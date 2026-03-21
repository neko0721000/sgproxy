use std::sync::Arc;

use anyhow::{Result, anyhow};
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::header::{self, HeaderName, HeaderValue};
use axum::http::{HeaderMap, Response, StatusCode};
use reqwest::header::HeaderMap as ReqwestHeaderMap;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use tracing::{error, warn};

use crate::config::CredentialUpsertInput;
use crate::oauth::{RefreshError, maybe_refresh_access_token};
use crate::state::{AppState, SelectedCredential};

const CLAUDE_CODE_BILLING_HEADER_PREFIX: &str = "x-anthropic-billing-header:";
const CLAUDE_CODE_BILLING_ENTRYPOINT: &str = "cli";
const CLAUDE_CODE_BILLING_SALT: &str = "59cf53e54c78";
const CLAUDE_CODE_BILLING_CCH: &str = "00000";
const MAGIC_TRIGGER_AUTO_ID: &str =
    "GPROXY_MAGIC_STRING_TRIGGER_CACHING_CREATE_7D9ASD7A98SD7A9S8D79ASC98A7FNKJBVV80SCMSHDSIUCH";
const MAGIC_TRIGGER_5M_ID: &str =
    "GPROXY_MAGIC_STRING_TRIGGER_CACHING_CREATE_49VA1S5V19GR4G89W2V695G9W9GV52W95V198WV5W2FC9DF";
const MAGIC_TRIGGER_1H_ID: &str =
    "GPROXY_MAGIC_STRING_TRIGGER_CACHING_CREATE_1FAS5GV9R5H29T5Y2J9584K6O95M2NBVW52C95CX984FRJY";

pub async fn handle_proxy(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Response<Body>, ProxyError> {
    let (parts, body) = request.into_parts();
    let credential = resolve_proxy_credential(&state).await?;
    let upstream = state.upstream_snapshot().await;
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or(parts.uri.path());
    let url = format!(
        "{}{}",
        upstream.base_url.trim_end_matches('/'),
        path_and_query
    );
    let headers = build_upstream_headers(
        &parts.headers,
        &upstream.anthropic_version,
        &upstream.required_beta,
        &upstream.default_user_agent,
        credential.credential.access_token.as_str(),
    )
    .map_err(|err| ProxyError::bad_gateway(err.to_string()))?;

    let upstream_body = build_upstream_body(
        parts.uri.path(),
        &parts.headers,
        upstream.default_user_agent.as_str(),
        body,
        state.max_body_bytes().await,
    )
    .await?;
    let client = state.client().await;
    let response = client
        .request(parts.method.clone(), url)
        .headers(headers)
        .body(upstream_body)
        .send()
        .await
        .map_err(|err| ProxyError::bad_gateway(err.to_string()))?;

    let status_code = response.status().as_u16();
    let downstream_headers = filter_response_headers(response.headers());
    let body = Body::from_stream(response.bytes_stream());

    let persist_result = state
        .record_proxy_result(
            credential.credential.id.as_str(),
            credential.credential.access_token.as_str(),
            status_code,
        )
        .await;
    if let Err(err) = persist_result {
        warn!(error = %err, "failed to persist proxy result");
    }
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(status_code).unwrap_or(StatusCode::BAD_GATEWAY));
    for (name, value) in &downstream_headers {
        builder = builder.header(name, value);
    }
    builder
        .body(body)
        .map_err(|err| ProxyError::internal(err.to_string()))
}

async fn resolve_proxy_credential(state: &Arc<AppState>) -> Result<SelectedCredential, ProxyError> {
    let selected = state
        .select_credential_for_proxy()
        .await
        .map_err(|err| ProxyError::service_unavailable(err.to_string()))?;

    let upstream = state.upstream_snapshot().await;
    let client = state.client().await;
    match maybe_refresh_access_token(&client, &upstream, &selected.credential).await {
        Ok(Some(refreshed)) => {
            let updated = state
                .add_or_update_credential(
                    CredentialUpsertInput {
                        id: Some(selected.credential.id.clone()),
                        enabled: Some(selected.credential.enabled),
                        order: Some(selected.credential.order),
                        access_token: Some(refreshed.access_token),
                        refresh_token: Some(refreshed.refresh_token),
                        expires_at_unix_ms: Some(refreshed.expires_at_unix_ms),
                        user_email: selected.credential.user_email.clone(),
                        organization_uuid: selected.credential.organization_uuid.clone(),
                        subscription_type: refreshed
                            .subscription_type
                            .or_else(|| selected.credential.subscription_type.clone()),
                        rate_limit_tier: refreshed
                            .rate_limit_tier
                            .or_else(|| selected.credential.rate_limit_tier.clone()),
                    },
                    Some(selected.credential.id.clone()),
                )
                .await
                .map_err(|err| ProxyError::internal(err.to_string()))?;
            Ok(SelectedCredential {
                credential: updated,
            })
        }
        Ok(None) => Ok(selected),
        Err(RefreshError::InvalidCredential(message)) => {
            warn!(credential_id = %selected.credential.id, error = %message, "credential refresh failed with invalid credential");
            state
                .record_proxy_result(
                    selected.credential.id.as_str(),
                    selected.credential.access_token.as_str(),
                    401,
                )
                .await
                .map_err(|err| ProxyError::internal(err.to_string()))?;
            state
                .select_credential_for_proxy()
                .await
                .map_err(|err| ProxyError::service_unavailable(err.to_string()))
        }
        Err(RefreshError::Transient(message)) => {
            error!(credential_id = %selected.credential.id, error = %message, "credential refresh failed");
            Err(ProxyError::bad_gateway(message))
        }
    }
}

async fn build_upstream_body(
    path: &str,
    headers: &HeaderMap,
    default_user_agent: &str,
    body: Body,
    max_body_bytes: usize,
) -> Result<reqwest::Body, ProxyError> {
    if !should_attempt_claude_body_rewrite(path) {
        return Ok(reqwest::Body::wrap_stream(body.into_data_stream()));
    }

    let body_bytes = axum::body::to_bytes(body, max_body_bytes)
        .await
        .map_err(|err| ProxyError::payload_too_large(err.to_string()))?;
    Ok(reqwest::Body::from(maybe_rewrite_claude_body(
        headers,
        default_user_agent,
        body_bytes,
    )))
}

fn should_attempt_claude_body_rewrite(path: &str) -> bool {
    path == "/v1/messages"
}

fn maybe_rewrite_claude_body(
    headers: &HeaderMap,
    default_user_agent: &str,
    body_bytes: Bytes,
) -> Vec<u8> {
    if body_bytes.is_empty() || !looks_like_json(body_bytes.as_ref()) {
        return body_bytes.to_vec();
    }

    let mut body = match serde_json::from_slice::<Value>(body_bytes.as_ref()) {
        Ok(value) => value,
        Err(err) => {
            warn!(error = %err, "failed to parse claude request body, proxying original payload");
            return body_bytes.to_vec();
        }
    };

    if body.get("messages").and_then(Value::as_array).is_none() {
        return body_bytes.to_vec();
    }

    apply_magic_string_cache_control_triggers(&mut body);
    apply_claudecode_billing_header_system_block(
        &mut body,
        extract_claude_code_version(headers, default_user_agent),
    );

    serde_json::to_vec(&body).unwrap_or_else(|err| {
        warn!(error = %err, "failed to serialize rewritten claude request body");
        body_bytes.to_vec()
    })
}

fn build_upstream_headers(
    original: &HeaderMap,
    anthropic_version: &str,
    required_beta: &[String],
    default_user_agent: &str,
    access_token: &str,
) -> Result<ReqwestHeaderMap> {
    let mut headers = ReqwestHeaderMap::new();
    let mut seen_user_agent = false;
    let mut seen_anthropic_version = false;
    let mut beta_values = Vec::new();

    for (name, value) in original {
        let lower = name.as_str().to_ascii_lowercase();
        if is_hop_by_hop(lower.as_str())
            || matches!(
                lower.as_str(),
                "host" | "content-length" | "authorization" | "cookie"
            )
        {
            continue;
        }

        if lower == "anthropic-beta" {
            if let Ok(raw) = value.to_str() {
                collect_beta_values(raw, &mut beta_values);
            }
            continue;
        }
        if lower == "user-agent" {
            seen_user_agent = true;
        }
        if lower == "anthropic-version" {
            seen_anthropic_version = true;
        }
        headers.insert(name, value.clone());
    }

    for beta in required_beta {
        collect_beta_values(beta.as_str(), &mut beta_values);
    }

    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(format!("Bearer {access_token}").as_str())
            .map_err(|err| anyhow!("invalid authorization header: {err}"))?,
    );
    if !seen_user_agent && !default_user_agent.trim().is_empty() {
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_str(default_user_agent.trim())
                .map_err(|err| anyhow!("invalid user-agent header: {err}"))?,
        );
    }
    if !seen_anthropic_version {
        headers.insert(
            HeaderName::from_static("anthropic-version"),
            HeaderValue::from_str(anthropic_version.trim())
                .map_err(|err| anyhow!("invalid anthropic-version header: {err}"))?,
        );
    }
    if !beta_values.is_empty() {
        headers.insert(
            HeaderName::from_static("anthropic-beta"),
            HeaderValue::from_str(beta_values.join(",").as_str())
                .map_err(|err| anyhow!("invalid anthropic-beta header: {err}"))?,
        );
    }

    Ok(headers)
}

fn filter_response_headers(headers: &ReqwestHeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        out.append(name, value.clone());
    }
    out
}

fn looks_like_json(body: &[u8]) -> bool {
    body.iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| matches!(byte, b'{' | b'['))
}

fn extract_claude_code_version<'a>(headers: &'a HeaderMap, default_user_agent: &'a str) -> &'a str {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_claude_client_version)
        .or_else(|| parse_claude_client_version(default_user_agent))
        .unwrap_or("2.1.76")
}

fn parse_claude_client_version(user_agent: &str) -> Option<&str> {
    let tail = user_agent
        .split_once("claude-cli/")
        .map(|(_, tail)| tail)
        .or_else(|| user_agent.split_once("claude-code/").map(|(_, tail)| tail))?;
    let version_len = tail
        .char_indices()
        .find_map(|(idx, ch)| (!matches!(ch, '0'..='9' | '.' | '-')).then_some(idx))
        .unwrap_or(tail.len());
    let version = tail[..version_len].trim();
    (!version.is_empty()).then_some(version)
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
    serde_json::json!({
        "type": "text",
        "text": text,
    })
}

fn apply_magic_string_cache_control_triggers(body: &mut Value) {
    canonicalize_claude_body(body);
    let Some(root) = body.as_object_mut() else {
        return;
    };
    let mut remaining_slots = 4usize.saturating_sub(existing_cache_breakpoint_count(root));

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
    let mut cache_control = serde_json::json!({
        "type": "ephemeral",
    });
    if let Some(ttl) = ttl {
        cache_control["ttl"] = serde_json::json!(ttl);
    }
    cache_control
}

fn existing_cache_breakpoint_count(root: &serde_json::Map<String, Value>) -> usize {
    let mut count = 0usize;
    if root.contains_key("cache_control") {
        count += 1;
    }

    match root.get("system") {
        Some(Value::Array(blocks)) => {
            count += blocks
                .iter()
                .filter_map(Value::as_object)
                .filter(|item| item.contains_key("cache_control"))
                .count();
        }
        Some(Value::Object(item)) => {
            if item.contains_key("cache_control") {
                count += 1;
            }
        }
        _ => {}
    }

    if let Some(messages) = root.get("messages").and_then(Value::as_array) {
        for message in messages {
            let Some(message_map) = message.as_object() else {
                continue;
            };
            let Some(content) = message_map.get("content") else {
                continue;
            };
            match content {
                Value::Array(blocks) => {
                    count += blocks
                        .iter()
                        .filter_map(Value::as_object)
                        .filter(|item| item.contains_key("cache_control"))
                        .count();
                }
                Value::Object(item) => {
                    if item.contains_key("cache_control") {
                        count += 1;
                    }
                }
                _ => {}
            }
        }
    }

    count
}

fn apply_claudecode_billing_header_system_block(body: &mut Value, claude_code_version: &str) {
    canonicalize_claude_body(body);
    if system_has_claudecode_billing_header(body.get("system")) {
        return;
    }
    let header_text = build_claudecode_billing_header_text(body, claude_code_version);
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

fn system_has_claudecode_billing_header(system: Option<&Value>) -> bool {
    let Some(system) = system else {
        return false;
    };

    match system {
        Value::Array(blocks) => blocks.iter().any(is_claudecode_billing_header_block),
        value => is_claudecode_billing_header_block(value),
    }
}

fn is_claudecode_billing_header_block(block: &Value) -> bool {
    block
        .as_object()
        .and_then(|block_map| block_map.get("text"))
        .and_then(Value::as_str)
        .map(str::trim_start)
        .is_some_and(|text| text.starts_with(CLAUDE_CODE_BILLING_HEADER_PREFIX))
}

fn build_claudecode_billing_header_text(body: &Value, claude_code_version: &str) -> String {
    let user_text = first_claudecode_user_text(body);
    let version_hash = claudecode_billing_version_hash(user_text.as_str(), claude_code_version);
    format!(
        "{} cc_version={}.{}; cc_entrypoint={}; cch={};",
        CLAUDE_CODE_BILLING_HEADER_PREFIX,
        claude_code_version,
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

fn claudecode_billing_version_hash(message_text: &str, claude_code_version: &str) -> String {
    let sampled = sampled_js_utf16_positions(message_text, &[4, 7, 20]);
    sha256_hex_prefix(
        format!(
            "{}{}{}",
            CLAUDE_CODE_BILLING_SALT, sampled, claude_code_version
        )
        .as_str(),
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

fn collect_beta_values(raw: &str, out: &mut Vec<String>) {
    for item in raw.split(',') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !out
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(trimmed))
        {
            out.push(trimmed.to_string());
        }
    }
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
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

pub struct ProxyError {
    status: StatusCode,
    message: String,
}

impl ProxyError {
    fn service_unavailable(message: String) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message,
        }
    }

    fn bad_gateway(message: String) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message,
        }
    }

    fn payload_too_large(message: String) -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            message,
        }
    }

    fn internal(message: String) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message,
        }
    }
}

impl axum::response::IntoResponse for ProxyError {
    fn into_response(self) -> Response<Body> {
        let body = serde_json::json!({ "error": self.message }).to_string();
        Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap_or_else(|_| Response::new(Body::from("{\"error\":\"internal error\"}")))
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;

    use axum::Router;
    use axum::body::{Body, Bytes};
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::{any, get, post};
    use serde_json::json;
    use serial_test::serial;
    use tempfile::tempdir;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use crate::admin;
    use crate::config::{ConfigFile, CredentialConfig, CredentialStatus};
    use crate::state::AppState;

    async fn spawn_server(app: Router) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve app");
        });
        (addr, handle)
    }

    async fn build_state(upstream_base_url: String) -> Arc<AppState> {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("sgproxy.toml");
        let config = ConfigFile {
            server: crate::config::ServerConfig {
                admin_token: "admin-secret".to_string(),
                ..crate::config::ServerConfig::default()
            },
            upstream: crate::config::UpstreamConfig {
                base_url: upstream_base_url,
                ..crate::config::UpstreamConfig::default()
            },
            credentials: vec![
                CredentialConfig {
                    id: "cred-a".to_string(),
                    enabled: true,
                    order: 1,
                    access_token: "token-a".to_string(),
                    refresh_token: "refresh-a".to_string(),
                    expires_at_unix_ms: u64::MAX,
                    user_email: None,
                    organization_uuid: None,
                    subscription_type: None,
                    rate_limit_tier: None,
                    status: CredentialStatus::Healthy,
                    cooldown_until_unix_ms: None,
                    last_error: None,
                    last_used_at_unix_ms: None,
                },
                CredentialConfig {
                    id: "cred-b".to_string(),
                    enabled: true,
                    order: 2,
                    access_token: "token-b".to_string(),
                    refresh_token: "refresh-b".to_string(),
                    expires_at_unix_ms: u64::MAX,
                    user_email: None,
                    organization_uuid: None,
                    subscription_type: None,
                    rate_limit_tier: None,
                    status: CredentialStatus::Healthy,
                    cooldown_until_unix_ms: None,
                    last_error: None,
                    last_used_at_unix_ms: None,
                },
            ],
        };
        AppState::new(PathBuf::from(config_path), config).expect("state")
    }

    fn app(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/", get(admin::index))
            .route("/v1", any(super::handle_proxy))
            .route("/v1/{*tail}", any(super::handle_proxy))
            .with_state(state)
    }

    #[test]
    fn magic_string_rewrite_and_billing_header_use_json_shims() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::USER_AGENT,
            HeaderValue::from_static("claude-cli/2.1.76 (external, cli)"),
        );

        let rewritten = super::maybe_rewrite_claude_body(
            &headers,
            "claude-cli/2.1.76 (external, cli)",
            Bytes::from(
                serde_json::to_vec(&json!({
                    "system": "prefix GPROXY_MAGIC_STRING_TRIGGER_CACHING_CREATE_7D9ASD7A98SD7A9S8D79ASC98A7FNKJBVV80SCMSHDSIUCH suffix",
                    "messages": [{
                        "role": "user",
                        "content": "hello GPROXY_MAGIC_STRING_TRIGGER_CACHING_CREATE_49VA1S5V19GR4G89W2V695G9W9GV52W95V198WV5W2FC9DF world"
                    }]
                }))
                .expect("serialize body"),
            ),
        );

        let body: serde_json::Value = serde_json::from_slice(&rewritten).expect("valid json");
        assert_eq!(
            body["system"][0]["text"],
            json!(
                "x-anthropic-billing-header: cc_version=2.1.76.ae7; cc_entrypoint=cli; cch=00000;"
            )
        );
        assert_eq!(body["system"][1]["text"], json!("prefix  suffix"));
        assert_eq!(
            body["system"][1]["cache_control"],
            json!({
                "type": "ephemeral"
            })
        );
        assert_eq!(
            body["messages"][0]["content"][0]["text"],
            json!("hello  world")
        );
        assert_eq!(
            body["messages"][0]["content"][0]["cache_control"],
            json!({
                "type": "ephemeral",
                "ttl": "5m"
            })
        );
    }

    #[test]
    fn existing_billing_header_is_preserved() {
        let rewritten = super::maybe_rewrite_claude_body(
            &HeaderMap::new(),
            "claude-cli/2.1.76 (external, cli)",
            Bytes::from(
                serde_json::to_vec(&json!({
                    "system": [{
                        "type": "text",
                        "text": "x-anthropic-billing-header: cc_version=already.there; cc_entrypoint=cli; cch=99999;"
                    }],
                    "messages": [{
                        "role": "user",
                        "content": "hey"
                    }]
                }))
                .expect("serialize body"),
            ),
        );

        let body: serde_json::Value = serde_json::from_slice(&rewritten).expect("valid json");
        assert_eq!(
            body["system"][0]["text"],
            json!(
                "x-anthropic-billing-header: cc_version=already.there; cc_entrypoint=cli; cch=99999;"
            )
        );
        assert_eq!(body["messages"][0]["content"][0]["text"], json!("hey"));
    }

    #[tokio::test]
    #[serial]
    async fn proxy_preserves_body_and_overrides_headers() {
        async fn upstream(req: Request<Body>) -> impl IntoResponse {
            let headers = req.headers();
            let auth = headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let beta = headers
                .get("anthropic-beta")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let version = headers
                .get("anthropic-version")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let custom = headers
                .get("x-test-header")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let body = axum::body::to_bytes(req.into_body(), usize::MAX)
                .await
                .expect("body bytes");
            (
                StatusCode::OK,
                axum::Json(json!({
                    "authorization": auth,
                    "anthropic_beta": beta,
                    "anthropic_version": version,
                    "x_test_header": custom,
                    "body": String::from_utf8_lossy(&body),
                })),
            )
        }

        let (upstream_addr, _upstream_handle) =
            spawn_server(Router::new().route("/v1/messages", post(upstream))).await;
        let state = build_state(format!("http://{}", upstream_addr)).await;
        let (sg_addr, _sg_handle) = spawn_server(app(state)).await;

        let client = reqwest::Client::new();
        let response = client
            .post(format!("http://{}/v1/messages", sg_addr))
            .header("authorization", "Bearer should-be-overwritten")
            .header("x-test-header", "kept")
            .header("anthropic-beta", "custom-beta")
            .body("{\"hello\":\"world\"}")
            .send()
            .await
            .expect("send request");
        assert_eq!(response.status(), StatusCode::OK);
        let payload = response
            .json::<serde_json::Value>()
            .await
            .expect("json payload");
        assert_eq!(payload["authorization"], "Bearer token-a");
        assert_eq!(payload["anthropic_version"], "2023-06-01");
        assert_eq!(payload["x_test_header"], "kept");
        assert_eq!(payload["body"], "{\"hello\":\"world\"}");
        assert!(
            payload["anthropic_beta"]
                .as_str()
                .expect("beta string")
                .contains("oauth-2025-04-20")
        );
        assert!(
            payload["anthropic_beta"]
                .as_str()
                .expect("beta string")
                .contains("custom-beta")
        );
    }

    #[tokio::test]
    #[serial]
    async fn auth_failure_switches_credential_for_next_request() {
        async fn upstream(
            State(counter): State<Arc<tokio::sync::Mutex<u64>>>,
            req: Request<Body>,
        ) -> impl IntoResponse {
            let auth = req
                .headers()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let mut guard = counter.lock().await;
            *guard += 1;
            if *guard == 1 {
                return (StatusCode::UNAUTHORIZED, Body::from("nope")).into_response();
            }
            axum::Json(json!({ "authorization": auth })).into_response()
        }

        let counter = Arc::new(tokio::sync::Mutex::new(0));
        let upstream_app = Router::new()
            .route("/v1/messages", post(upstream))
            .with_state(counter);
        let (upstream_addr, _upstream_handle) = spawn_server(upstream_app).await;
        let state = build_state(format!("http://{}", upstream_addr)).await;
        let (sg_addr, _sg_handle) = spawn_server(app(state.clone())).await;
        let client = reqwest::Client::new();

        let first = client
            .post(format!("http://{}/v1/messages", sg_addr))
            .body("first")
            .send()
            .await
            .expect("first request");
        assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
        let _ = first.bytes().await.expect("first body");

        let second = reqwest::Client::new()
            .post(format!("http://{}/v1/messages", sg_addr))
            .body("second")
            .send()
            .await
            .expect("second request");
        assert_eq!(second.status(), StatusCode::OK);
        let payload = second
            .json::<serde_json::Value>()
            .await
            .expect("json payload");
        assert_eq!(payload["authorization"], "Bearer token-b");

        let credentials = state.credentials().await;
        let first_cred = credentials
            .iter()
            .find(|item| item.id == "cred-a")
            .expect("cred-a");
        let second_cred = credentials
            .iter()
            .find(|item| item.id == "cred-b")
            .expect("cred-b");
        assert_eq!(first_cred.status, CredentialStatus::Dead);
        assert_eq!(second_cred.status, CredentialStatus::Healthy);
    }
}
