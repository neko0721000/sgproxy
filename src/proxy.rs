use anyhow::Result;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use url::Url;
use worker::{Fetch, Headers, Request, RequestInit, Response};

use crate::config::{
    CLAUDE_CODE_BILLING_CCH, CLAUDE_CODE_BILLING_ENTRYPOINT, CLAUDE_CODE_BILLING_HEADER_PREFIX,
    CLAUDE_CODE_BILLING_SALT, CredentialConfig, DEFAULT_ANTHROPIC_VERSION, DEFAULT_BASE_URL,
    DEFAULT_CONTEXT_1M_BETA, DEFAULT_REQUIRED_BETA, DEFAULT_USER_AGENT, MAGIC_TRIGGER_1H_ID,
    MAGIC_TRIGGER_5M_ID, MAGIC_TRIGGER_AUTO_ID,
};

pub struct ProxyOutcome {
    pub response: Response,
    pub status_code: u16,
    pub disable_sonnet_1m: bool,
    pub disable_opus_1m: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClaudeCode1mTarget {
    Sonnet,
    Opus,
}

#[derive(Debug, Default)]
struct PreparedProxyRequest {
    body: Option<Vec<u8>>,
    context_1m_target: Option<ClaudeCode1mTarget>,
}

pub async fn proxy_request(
    mut req: Request,
    credential: &CredentialConfig,
) -> Result<ProxyOutcome> {
    let upstream_url = build_upstream_url(&req)?;
    let method = req.method();
    let prepared = maybe_prepare_request(&mut req, credential).await?;
    let context_1m_enabled =
        claudecode_1m_enabled_for_credential(credential, prepared.context_1m_target.as_ref());

    let mut headers = build_upstream_headers(
        req.headers(),
        credential.access_token.as_str(),
        context_1m_enabled,
    )?;
    let sent_with_context_1m = has_context_1m_beta(&headers);

    let mut upstream_resp = send_upstream_request(
        upstream_url.as_str(),
        &method,
        headers,
        prepared.body.as_deref(),
    )
    .await?;
    let mut status_code = upstream_resp.status_code();
    let mut disable_sonnet_1m = false;
    let mut disable_opus_1m = false;

    if sent_with_context_1m && context_1m_enabled && status_code >= 400 {
        headers = build_upstream_headers(req.headers(), credential.access_token.as_str(), false)?;
        let retry_resp = send_upstream_request(
            upstream_url.as_str(),
            &method,
            headers,
            prepared.body.as_deref(),
        )
        .await?;
        if retry_resp.status_code() < 400 {
            match prepared.context_1m_target.as_ref() {
                Some(ClaudeCode1mTarget::Sonnet) => disable_sonnet_1m = true,
                Some(ClaudeCode1mTarget::Opus) => disable_opus_1m = true,
                None => {}
            }
        }
        upstream_resp = retry_resp;
        status_code = upstream_resp.status_code();
    }

    let response_headers = filter_response_headers(upstream_resp.headers())?;
    let (_, body) = upstream_resp.into_parts();
    let response = Response::builder()
        .with_status(status_code)
        .with_headers(response_headers)
        .body(body);

    Ok(ProxyOutcome {
        response,
        status_code,
        disable_sonnet_1m,
        disable_opus_1m,
    })
}

fn build_upstream_url(req: &Request) -> Result<Url> {
    let source = req.url()?;
    let mut target = Url::parse(DEFAULT_BASE_URL)?;
    target.set_path(source.path());
    target.set_query(source.query());
    Ok(target)
}

fn build_upstream_headers(
    original: &Headers,
    access_token: &str,
    allow_context_1m: bool,
) -> Result<Headers> {
    let headers = Headers::new();
    let mut seen_user_agent = false;
    let mut seen_anthropic_version = false;
    let mut beta_values = Vec::new();

    for (name, value) in original.entries() {
        let lower = name.to_ascii_lowercase();
        if is_hop_by_hop(&lower)
            || matches!(
                lower.as_str(),
                "host" | "content-length" | "authorization" | "cookie" | "x-api-key"
            )
        {
            continue;
        }
        if lower == "anthropic-beta" {
            collect_beta_values(&value, &mut beta_values, allow_context_1m);
            continue;
        }
        if lower == "user-agent" {
            seen_user_agent = true;
        }
        if lower == "anthropic-version" {
            seen_anthropic_version = true;
        }
        headers.append(&name, &value)?;
    }

    collect_beta_values(DEFAULT_REQUIRED_BETA, &mut beta_values, allow_context_1m);
    if allow_context_1m {
        collect_beta_values(DEFAULT_CONTEXT_1M_BETA, &mut beta_values, allow_context_1m);
    }
    headers.set("authorization", &format!("Bearer {access_token}"))?;
    if !seen_user_agent {
        headers.set("user-agent", DEFAULT_USER_AGENT)?;
    }
    if !seen_anthropic_version {
        headers.set("anthropic-version", DEFAULT_ANTHROPIC_VERSION)?;
    }
    if !beta_values.is_empty() {
        headers.set("anthropic-beta", &beta_values.join(","))?;
    }
    Ok(headers)
}

async fn send_upstream_request(
    upstream_url: &str,
    method: &worker::Method,
    headers: Headers,
    body: Option<&[u8]>,
) -> Result<Response> {
    let mut init = RequestInit::new();
    init.with_method(method.clone()).with_headers(headers);
    if let Some(body) = body {
        init.with_body(Some(body.to_vec().into()));
    }

    let upstream_req = Request::new_with_init(upstream_url, &init)?;
    Ok(Fetch::Request(upstream_req).send().await?)
}

fn filter_response_headers(original: &Headers) -> Result<Headers> {
    let headers = Headers::new();
    for (name, value) in original.entries() {
        if is_hop_by_hop(&name) {
            continue;
        }
        headers.append(&name, &value)?;
    }
    Ok(headers)
}

fn collect_beta_values(raw: &str, target: &mut Vec<String>, allow_context_1m: bool) {
    for value in raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !allow_context_1m && is_context_1m_beta(value) {
            continue;
        }
        if !target.iter().any(|item| item == value) {
            target.push(value.to_string());
        }
    }
}

fn is_context_1m_beta(value: &str) -> bool {
    value.trim().to_ascii_lowercase().starts_with("context-1m")
}

fn has_context_1m_beta(headers: &Headers) -> bool {
    headers
        .get("anthropic-beta")
        .ok()
        .flatten()
        .map(|value| value.split(',').any(is_context_1m_beta))
        .unwrap_or(false)
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

async fn maybe_prepare_request(
    req: &mut Request,
    credential: &CredentialConfig,
) -> Result<PreparedProxyRequest> {
    if !request_body_should_be_rewritten(req) {
        let body = if request_can_have_body(req) {
            Some(req.bytes().await?)
        } else {
            None
        };
        return Ok(PreparedProxyRequest {
            body,
            context_1m_target: None,
        });
    }

    let bytes = req.bytes().await?;
    if bytes.is_empty() {
        return Ok(PreparedProxyRequest {
            body: Some(bytes),
            context_1m_target: None,
        });
    }

    let mut body = match serde_json::from_slice::<Value>(&bytes) {
        Ok(body) => body,
        Err(_) => {
            return Ok(PreparedProxyRequest {
                body: Some(bytes),
                context_1m_target: None,
            });
        }
    };
    let context_1m_target = body
        .get("model")
        .and_then(Value::as_str)
        .and_then(claude_1m_target_for_model);

    normalize_claudecode_sampling(&mut body);
    apply_magic_string_cache_control_triggers(&mut body);
    apply_claudecode_metadata_user_id(&mut body, credential);
    flatten_system_text_before_cache_control(&mut body);
    apply_claudecode_billing_header_system_block(&mut body, request_claudecode_version(req));
    Ok(PreparedProxyRequest {
        body: Some(serde_json::to_vec(&body)?),
        context_1m_target,
    })
}

fn request_body_should_be_rewritten(req: &Request) -> bool {
    request_can_have_body(req)
        && req
            .headers()
            .get("content-type")
            .ok()
            .flatten()
            .map(|value| value.to_ascii_lowercase().contains("application/json"))
            .unwrap_or(false)
        && req
            .url()
            .ok()
            .map(|url| url.path().starts_with("/v1/"))
            .unwrap_or(false)
}

fn request_can_have_body(req: &Request) -> bool {
    matches!(
        req.method(),
        worker::Method::Post | worker::Method::Put | worker::Method::Patch | worker::Method::Delete
    )
}

fn claude_1m_target_for_model(model: &str) -> Option<ClaudeCode1mTarget> {
    let lower = model.trim().to_ascii_lowercase();
    if lower.starts_with("claude-sonnet-4") {
        return Some(ClaudeCode1mTarget::Sonnet);
    }
    if lower.starts_with("claude-opus-4-6") {
        return Some(ClaudeCode1mTarget::Opus);
    }
    None
}

fn claudecode_1m_enabled_for_credential(
    credential: &CredentialConfig,
    target: Option<&ClaudeCode1mTarget>,
) -> bool {
    match target {
        Some(ClaudeCode1mTarget::Sonnet) => credential.enable_sonnet_1m,
        Some(ClaudeCode1mTarget::Opus) => credential.enable_opus_1m,
        None => false,
    }
}

fn request_claudecode_version(req: &Request) -> String {
    req.headers()
        .get("user-agent")
        .ok()
        .flatten()
        .and_then(|value| {
            value
                .trim()
                .strip_prefix("claude-code/")
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| {
            DEFAULT_USER_AGENT
                .strip_prefix("claude-code/")
                .unwrap_or(DEFAULT_USER_AGENT)
                .to_string()
        })
}

fn normalize_claudecode_sampling(body: &mut Value) {
    let Some(map) = body.as_object_mut() else {
        return;
    };

    let has_temperature = map.get("temperature").and_then(Value::as_f64).is_some();
    let has_top_p = map.get("top_p").and_then(Value::as_f64).is_some();
    if has_temperature && has_top_p {
        map.remove("top_p");
    }
}

fn apply_claudecode_metadata_user_id(body: &mut Value, credential: &CredentialConfig) {
    canonicalize_claude_body(body);
    let session_seed = session_seed_from_body(body)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| credential.id.clone());
    let Some(map) = body.as_object_mut() else {
        return;
    };

    if map
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("user_id"))
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
    {
        return;
    }

    let metadata = map
        .entry("metadata".to_string())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let Some(metadata_map) = metadata.as_object_mut() else {
        return;
    };

    let account_uuid = credential.account_uuid.clone().unwrap_or_default();
    let device_seed = credential
        .account_uuid
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            credential
                .organization_uuid
                .as_deref()
                .filter(|value| !value.trim().is_empty())
        })
        .or_else(|| {
            credential
                .user_email
                .as_deref()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or(credential.id.as_str());

    metadata_map.insert(
        "user_id".to_string(),
        Value::String(
            json!({
                "device_id": sha256_hex(format!("sgproxy.claudecode.device:{device_seed}").as_str()),
                "account_uuid": account_uuid,
                "session_id": stable_session_uuid(session_seed.as_str()),
            })
            .to_string(),
        ),
    );
}

fn session_seed_from_body(body: &Value) -> Option<String> {
    system_session_seed(body).or_else(|| first_message_session_seed(body))
}

fn system_session_seed(body: &Value) -> Option<String> {
    match body.get("system")? {
        Value::String(text) => non_empty_owned(text),
        Value::Array(blocks) => {
            let text = blocks
                .iter()
                .filter_map(first_text_from_claude_block)
                .collect::<Vec<_>>()
                .join("\n");
            non_empty_owned(text.as_str())
        }
        Value::Object(_) => first_text_from_claude_block(body.get("system")?),
        _ => None,
    }
}

fn first_message_session_seed(body: &Value) -> Option<String> {
    let messages = body.get("messages")?.as_array()?;
    let first = messages.first()?.as_object()?;
    first
        .get("content")
        .and_then(first_text_from_claude_content)
        .or_else(|| {
            first
                .get("role")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .and_then(|value| non_empty_owned(value.as_str()))
}

fn non_empty_owned(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn sha256_hex(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn stable_session_uuid(seed: &str) -> String {
    let digest = Sha256::digest(format!("sgproxy.claudecode.session:{seed}").as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn apply_claudecode_billing_header_system_block(body: &mut Value, version: String) {
    canonicalize_claude_body(body);
    if system_has_claudecode_billing_header(body.get("system")) {
        return;
    }
    let header_text = build_claudecode_billing_header_text(body, &version);
    let Some(map) = body.as_object_mut() else {
        return;
    };

    let header_block = json_text_block(header_text.as_str());
    match map.remove("system") {
        Some(Value::Array(mut blocks)) => {
            blocks.retain(|block| !is_claudecode_billing_header_block(block));
            blocks.insert(0, header_block);
            map.insert("system".to_string(), Value::Array(blocks));
        }
        Some(value) => {
            let mut blocks = vec![header_block];
            if !is_claudecode_billing_header_block(&value) {
                blocks.push(value);
            }
            map.insert("system".to_string(), Value::Array(blocks));
        }
        None => {
            map.insert("system".to_string(), Value::Array(vec![header_block]));
        }
    }
}

fn flatten_system_text_before_cache_control(body: &mut Value) {
    canonicalize_claude_body(body);
    let Some(blocks) = body.get_mut("system").and_then(Value::as_array_mut) else {
        return;
    };

    let mut merge_ranges = Vec::new();
    let mut run_start = None;
    let mut run_text = String::new();

    for (index, block) in blocks.iter().enumerate() {
        if is_claudecode_billing_header_block(block) {
            run_start = None;
            run_text.clear();
            continue;
        }

        if block_has_cache_control(block) {
            if let Some(start) = run_start.take()
                && index.saturating_sub(start) > 1
            {
                merge_ranges.push((start, index, std::mem::take(&mut run_text)));
            } else {
                run_text.clear();
            }
            continue;
        }

        if let Some(text) = block_text(block) {
            if run_start.is_none() {
                run_start = Some(index);
            }
            run_text.push_str(text);
            continue;
        }

        run_start = None;
        run_text.clear();
    }

    for (start, end, text) in merge_ranges.into_iter().rev() {
        blocks.splice(start..end, [json_text_block(text.as_str())]);
    }
}

fn build_claudecode_billing_header_text(body: &Value, version: &str) -> String {
    let user_text = first_claudecode_user_text(body);
    let version_hash = claudecode_billing_version_hash(user_text.as_str(), version);
    format!(
        "{} cc_version={}.{}; cc_entrypoint={}; cch={};",
        CLAUDE_CODE_BILLING_HEADER_PREFIX,
        version,
        version_hash,
        CLAUDE_CODE_BILLING_ENTRYPOINT,
        CLAUDE_CODE_BILLING_CCH,
    )
}

fn first_claudecode_user_text(body: &Value) -> String {
    body.get("messages")
        .and_then(Value::as_array)
        .and_then(|messages| {
            messages.iter().find_map(|message| {
                let message_map = message.as_object()?;
                if message_map.get("role").and_then(Value::as_str) != Some("user") {
                    return None;
                }
                message_map
                    .get("content")
                    .and_then(first_text_from_claude_content)
            })
        })
        .unwrap_or_default()
}

fn block_has_cache_control(block: &Value) -> bool {
    block
        .as_object()
        .is_some_and(|block_map| block_map.contains_key("cache_control"))
}

fn block_text(block: &Value) -> Option<&str> {
    let block_map = block.as_object()?;
    if block_map.get("type").and_then(Value::as_str) != Some("text") {
        return None;
    }
    block_map.get("text").and_then(Value::as_str)
}

fn first_text_from_claude_content(content: &Value) -> Option<String> {
    match content {
        Value::String(text) => Some(text.clone()),
        Value::Array(blocks) => blocks.iter().find_map(first_text_from_claude_block),
        Value::Object(_) => first_text_from_claude_block(content),
        _ => None,
    }
}

fn first_text_from_claude_block(block: &Value) -> Option<String> {
    let block_map = block.as_object()?;
    if block_map.get("type").and_then(Value::as_str) != Some("text") {
        return None;
    }
    block_map
        .get("text")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn claudecode_billing_version_hash(message_text: &str, version: &str) -> String {
    let sampled = sampled_js_utf16_positions(message_text, &[4, 7, 20]);
    sha256_hex_prefix(
        format!("{}{}{}", CLAUDE_CODE_BILLING_SALT, sampled, version).as_str(),
        3,
    )
}

fn sampled_js_utf16_positions(text: &str, indices: &[usize]) -> String {
    let utf16 = text.encode_utf16().collect::<Vec<_>>();
    let mut sampled = String::new();
    for index in indices {
        match utf16.get(*index).copied() {
            Some(unit) => sampled.push(js_utf16_unit_char(unit)),
            None => sampled.push('0'),
        }
    }
    sampled
}

fn js_utf16_unit_char(unit: u16) -> char {
    char::from_u32(unit as u32).unwrap_or(char::REPLACEMENT_CHARACTER)
}

fn sha256_hex_prefix(value: &str, len: usize) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let hex = format!("{digest:x}");
    hex[..len.min(hex.len())].to_string()
}

fn is_claudecode_billing_header_block(block: &Value) -> bool {
    block
        .as_object()
        .and_then(|block_map| block_map.get("text"))
        .and_then(Value::as_str)
        .map(str::trim_start)
        .is_some_and(|text| text.starts_with(CLAUDE_CODE_BILLING_HEADER_PREFIX))
}

fn system_has_claudecode_billing_header(system: Option<&Value>) -> bool {
    let Some(system) = system else {
        return false;
    };

    match system {
        Value::Array(blocks) => blocks.iter().any(is_claudecode_billing_header_block),
        value => is_claudecode_billing_header_block(value),
    }
}

fn canonicalize_claude_body(body: &mut Value) {
    let Some(root) = body.as_object_mut() else {
        return;
    };

    if let Some(system) = root.get_mut("system") {
        canonicalize_claude_system(system);
    }

    if let Some(messages) = root.get_mut("messages").and_then(Value::as_array_mut) {
        for message in messages {
            canonicalize_claude_message(message);
        }
    }
}

fn canonicalize_claude_system(system: &mut Value) {
    match system {
        Value::String(text) => {
            let text = std::mem::take(text);
            *system = Value::Array(vec![json_text_block(text.as_str())]);
        }
        Value::Array(blocks) => canonicalize_claude_blocks(blocks),
        _ => {}
    }
}

fn canonicalize_claude_message(message: &mut Value) {
    let Some(message_map) = message.as_object_mut() else {
        return;
    };
    let Some(content) = message_map.get_mut("content") else {
        return;
    };
    canonicalize_claude_content(content);
}

fn canonicalize_claude_content(content: &mut Value) {
    match content {
        Value::String(text) => {
            let text = std::mem::take(text);
            *content = Value::Array(vec![json_text_block(text.as_str())]);
        }
        Value::Object(_) => {
            let block = std::mem::take(content);
            *content = Value::Array(vec![block]);
        }
        Value::Array(blocks) => canonicalize_claude_blocks(blocks),
        _ => {}
    }
}

fn canonicalize_claude_blocks(blocks: &mut Vec<Value>) {
    for block in blocks {
        if let Value::String(text) = block {
            let text = std::mem::take(text);
            *block = json_text_block(text.as_str());
        }
    }
}

fn json_text_block(text: &str) -> Value {
    json!({
        "type": "text",
        "text": text,
    })
}

fn apply_magic_string_cache_control_triggers(body: &mut Value) {
    canonicalize_claude_body(body);
    let Some(root) = body.as_object_mut() else {
        return;
    };
    let existing_breakpoints = existing_cache_breakpoint_count(root);
    let mut remaining_slots = 4usize.saturating_sub(existing_breakpoints);

    if let Some(system) = root.get_mut("system") {
        apply_magic_trigger_to_content(system, &mut remaining_slots);
    }

    if let Some(messages) = root.get_mut("messages").and_then(Value::as_array_mut) {
        for message in messages {
            let Some(message_map) = message.as_object_mut() else {
                continue;
            };
            let Some(content) = message_map.get_mut("content") else {
                continue;
            };
            apply_magic_trigger_to_content(content, &mut remaining_slots);
        }
    }
}

fn apply_magic_trigger_to_content(content: &mut Value, remaining_slots: &mut usize) {
    match content {
        Value::Array(blocks) => {
            for block in blocks {
                let Some(block_map) = block.as_object_mut() else {
                    continue;
                };
                apply_magic_trigger_to_block(block_map, remaining_slots);
            }
        }
        Value::Object(block_map) => apply_magic_trigger_to_block(block_map, remaining_slots),
        _ => {}
    }
}

fn apply_magic_trigger_to_block(
    block_map: &mut serde_json::Map<String, Value>,
    remaining_slots: &mut usize,
) {
    let Some(Value::String(text)) = block_map.get_mut("text") else {
        return;
    };

    let ttl = remove_magic_trigger_tokens(text);
    let Some(ttl) = ttl else {
        return;
    };

    if *remaining_slots > 0 && !block_map.contains_key("cache_control") {
        block_map.insert("cache_control".to_string(), cache_control_ephemeral(ttl));
        *remaining_slots = remaining_slots.saturating_sub(1);
    }
}

fn remove_magic_trigger_tokens(text: &mut String) -> Option<Option<&'static str>> {
    let specs = [
        (MAGIC_TRIGGER_AUTO_ID, None),
        (MAGIC_TRIGGER_5M_ID, Some("5m")),
        (MAGIC_TRIGGER_1H_ID, Some("1h")),
    ];

    let mut matched_ttl = None;
    for (id, ttl) in specs {
        if text.contains(id) {
            *text = text.replace(id, "");
            if matched_ttl.is_none() {
                matched_ttl = Some(ttl);
            }
        }
    }

    matched_ttl
}

fn cache_control_ephemeral(ttl: Option<&'static str>) -> Value {
    let mut cache_control = json!({
        "type": "ephemeral",
    });
    if let Some(ttl) = ttl {
        cache_control["ttl"] = json!(ttl);
    }
    cache_control
}

fn existing_cache_breakpoint_count(root: &serde_json::Map<String, Value>) -> usize {
    let mut count = 0;

    if root.contains_key("cache_control") {
        count += 1;
    }

    if let Some(system) = root.get("system") {
        count += count_cache_controls_in_content(system);
    }

    if let Some(messages) = root.get("messages").and_then(Value::as_array) {
        for message in messages {
            let Some(content) = message.as_object().and_then(|item| item.get("content")) else {
                continue;
            };
            count += count_cache_controls_in_content(content);
        }
    }

    count
}

fn count_cache_controls_in_content(content: &Value) -> usize {
    match content {
        Value::Array(items) => items
            .iter()
            .filter(|item| {
                item.as_object()
                    .is_some_and(|map| map.contains_key("cache_control"))
            })
            .count(),
        Value::Object(map) => usize::from(map.contains_key("cache_control")),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_credential() -> CredentialConfig {
        CredentialConfig {
            id: "cred_test".to_string(),
            channel: crate::config::ChannelKind::ClaudeCode,
            enabled: true,
            order: 1,
            access_token: "token".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at_unix_ms: 0,
            enable_sonnet_1m: true,
            enable_opus_1m: true,
            user_email: Some("user@example.com".to_string()),
            account_uuid: Some("acct_123".to_string()),
            organization_uuid: Some("org_123".to_string()),
            subscription_type: None,
            rate_limit_tier: None,
            status: crate::config::CredentialStatus::Healthy,
            cooldown_until_unix_ms: None,
            last_error: None,
            last_used_at_unix_ms: None,
        }
    }

    #[test]
    fn injects_billing_header_when_missing() {
        let mut body = json!({
            "messages": [
                {"role":"user","content":"hello world"}
            ]
        });

        apply_claudecode_billing_header_system_block(&mut body, "2.1.81".to_string());

        let system = body["system"].as_array().unwrap();
        let text = system[0]["text"].as_str().unwrap();
        assert!(text.starts_with("x-anthropic-billing-header: cc_version=2.1.81."));
        assert!(text.contains("cc_entrypoint=cli; cch=00000;"));
    }

    #[test]
    fn preserves_existing_billing_header() {
        let mut body = json!({
            "system": [
                {
                    "type":"text",
                    "text":"x-anthropic-billing-header: cc_version=already.there; cc_entrypoint=cli; cch=99999;"
                }
            ],
            "messages": [
                {"role":"user","content":"hello world"}
            ]
        });

        apply_claudecode_billing_header_system_block(&mut body, "2.1.81".to_string());

        assert_eq!(
            body["system"][0]["text"].as_str().unwrap(),
            "x-anthropic-billing-header: cc_version=already.there; cc_entrypoint=cli; cch=99999;"
        );
    }

    #[test]
    fn flatten_system_text_before_cache_control_merges_text_blocks_before_cache_points() {
        let mut body = json!({
            "system": [
                {"type":"text","text":"a"},
                {"type":"text","text":"b"},
                {"type":"text","text":"c","cache_control":{"type":"ephemeral","ttl":"5m"}},
                {"type":"text","text":"d"},
                {"type":"text","text":"e"},
                {"type":"text","text":"f","cache_control":{"type":"ephemeral","ttl":"1h"}},
                {"type":"text","text":"g"}
            ]
        });

        flatten_system_text_before_cache_control(&mut body);

        assert_eq!(
            body["system"],
            json!([
                {"type":"text","text":"ab"},
                {"type":"text","text":"c","cache_control":{"type":"ephemeral","ttl":"5m"}},
                {"type":"text","text":"de"},
                {"type":"text","text":"f","cache_control":{"type":"ephemeral","ttl":"1h"}},
                {"type":"text","text":"g"}
            ])
        );
    }

    #[test]
    fn flatten_system_text_before_cache_control_preserves_leading_billing_header() {
        let mut body = json!({
            "system": [
                {
                    "type":"text",
                    "text":"x-anthropic-billing-header: cc_version=already.there; cc_entrypoint=cli; cch=99999;"
                },
                {"type":"text","text":"a"},
                {"type":"text","text":"b"},
                {"type":"text","text":"c","cache_control":{"type":"ephemeral","ttl":"5m"}}
            ]
        });

        flatten_system_text_before_cache_control(&mut body);

        assert_eq!(
            body["system"],
            json!([
                {
                    "type":"text",
                    "text":"x-anthropic-billing-header: cc_version=already.there; cc_entrypoint=cli; cch=99999;"
                },
                {"type":"text","text":"ab"},
                {"type":"text","text":"c","cache_control":{"type":"ephemeral","ttl":"5m"}}
            ])
        );
    }

    #[test]
    fn applies_magic_string_cache_control() {
        let mut body = json!({
            "messages": [
                {
                    "role":"user",
                    "content":[
                        {
                            "type":"text",
                            "text": format!("hello {} world", MAGIC_TRIGGER_5M_ID)
                        }
                    ]
                }
            ]
        });

        apply_magic_string_cache_control_triggers(&mut body);

        let block = &body["messages"][0]["content"][0];
        assert_eq!(block["cache_control"]["type"], json!("ephemeral"));
        assert_eq!(block["cache_control"]["ttl"], json!("5m"));
        assert!(
            !block["text"]
                .as_str()
                .unwrap()
                .contains(MAGIC_TRIGGER_5M_ID)
        );
    }

    #[test]
    fn injects_metadata_user_id_when_missing() {
        let mut body = json!({
            "system": "system prompt",
            "messages": [
                {"role":"user","content":"hello world"}
            ]
        });

        apply_claudecode_metadata_user_id(&mut body, &sample_credential());

        let user_id = body["metadata"]["user_id"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(user_id).unwrap();
        assert_eq!(parsed["account_uuid"], json!("acct_123"));
        assert_eq!(
            parsed["device_id"],
            json!(sha256_hex("sgproxy.claudecode.device:acct_123"))
        );
        assert_eq!(
            parsed["session_id"],
            json!(stable_session_uuid("system prompt"))
        );
    }

    #[test]
    fn preserves_existing_metadata_user_id() {
        let mut body = json!({
            "metadata": {
                "user_id": "{\"device_id\":\"x\",\"account_uuid\":\"y\",\"session_id\":\"z\"}"
            },
            "messages": [
                {"role":"user","content":"hello world"}
            ]
        });

        apply_claudecode_metadata_user_id(&mut body, &sample_credential());

        assert_eq!(
            body["metadata"]["user_id"].as_str().unwrap(),
            "{\"device_id\":\"x\",\"account_uuid\":\"y\",\"session_id\":\"z\"}"
        );
    }

    #[test]
    fn session_id_falls_back_to_first_message_text() {
        let mut body = json!({
            "messages": [
                {"role":"user","content":"hello world"}
            ]
        });

        apply_claudecode_metadata_user_id(&mut body, &sample_credential());

        let user_id = body["metadata"]["user_id"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(user_id).unwrap();
        assert_eq!(
            parsed["session_id"],
            json!(stable_session_uuid("hello world"))
        );
    }

    #[test]
    fn drops_top_p_when_temperature_is_present() {
        let mut body = json!({
            "temperature": 0.7,
            "top_p": 0.9,
            "messages": []
        });

        normalize_claudecode_sampling(&mut body);

        assert_eq!(body["temperature"], json!(0.7));
        assert!(body.get("top_p").is_none());
    }

    #[test]
    fn keeps_top_p_when_temperature_is_absent() {
        let mut body = json!({
            "top_p": 0.9,
            "messages": []
        });

        normalize_claudecode_sampling(&mut body);

        assert_eq!(body["top_p"], json!(0.9));
    }

    #[test]
    fn detects_1m_target_from_model() {
        assert_eq!(
            claude_1m_target_for_model("claude-sonnet-4-5"),
            Some(ClaudeCode1mTarget::Sonnet)
        );
        assert_eq!(
            claude_1m_target_for_model("claude-opus-4-6-thinking"),
            Some(ClaudeCode1mTarget::Opus)
        );
        assert_eq!(claude_1m_target_for_model("claude-3-7-sonnet"), None);
    }

    #[test]
    fn collect_beta_values_adds_context_1m_when_enabled() {
        let mut values = Vec::new();
        collect_beta_values(DEFAULT_REQUIRED_BETA, &mut values, true);
        collect_beta_values(DEFAULT_CONTEXT_1M_BETA, &mut values, true);

        assert!(values.iter().any(|item| item == DEFAULT_REQUIRED_BETA));
        assert!(values.iter().any(|item| item == DEFAULT_CONTEXT_1M_BETA));
    }

    #[test]
    fn collect_beta_values_strip_context_1m_when_disabled() {
        let mut values = Vec::new();
        collect_beta_values(
            "output-128k-2025-02-19, context-1m-2025-08-07, custom-beta",
            &mut values,
            false,
        );
        collect_beta_values(DEFAULT_REQUIRED_BETA, &mut values, false);

        assert!(values.iter().any(|item| item == DEFAULT_REQUIRED_BETA));
        assert!(values.iter().any(|item| item == "output-128k-2025-02-19"));
        assert!(values.iter().any(|item| item == "custom-beta"));
        assert!(!values.iter().any(|item| item == DEFAULT_CONTEXT_1M_BETA));
    }
}
