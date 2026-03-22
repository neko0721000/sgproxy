use anyhow::{Result, anyhow};
use base64::Engine as _;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use url::form_urlencoded;
use wasm_bindgen::JsValue;
use worker::{Fetch, Headers, Method, Request, RequestInit};

use crate::config::{
    CLAUDE_CODE_OAUTH_CLIENT_ID, CLAUDE_CODE_OAUTH_SCOPE, ChannelKind, CredentialConfig,
    CredentialUsageBucket, CredentialUsageSnapshot, DEFAULT_ANTHROPIC_VERSION, DEFAULT_BASE_URL,
    DEFAULT_CLAUDE_AI_BASE_URL, DEFAULT_REDIRECT_URI, DEFAULT_REQUIRED_BETA,
    DEFAULT_TOKEN_USER_AGENT, DEFAULT_USER_AGENT, StoredOAuthState,
};
use crate::state::now_unix_ms;

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthStartInput {
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthCallbackInput {
    #[serde(default)]
    pub callback_url: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OAuthStartResponse {
    pub auth_url: String,
    pub state: String,
    pub redirect_uri: String,
}

#[derive(Debug, Clone)]
pub struct OAuthStartState {
    pub response: OAuthStartResponse,
    pub stored_state: StoredOAuthState,
}

#[derive(Debug, Clone)]
pub struct RefreshedCredential {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at_unix_ms: u64,
    pub user_email: Option<String>,
    pub account_uuid: Option<String>,
    pub organization_uuid: Option<String>,
    pub subscription_type: Option<String>,
    pub rate_limit_tier: Option<String>,
}

#[derive(Debug)]
pub enum RefreshError {
    InvalidCredential(String),
    Transient(String),
}

#[derive(Debug, Clone, Default)]
pub struct OAuthProfileParsed {
    pub email: Option<String>,
    pub account_uuid: Option<String>,
    pub subscription_type: Option<String>,
    pub rate_limit_tier: Option<String>,
    pub organization_uuid: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ClaudeTokenResponse {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
    #[serde(default, alias = "subscriptionType")]
    pub subscription_type: Option<String>,
    #[serde(default, alias = "rateLimitTier")]
    pub rate_limit_tier: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
    #[serde(default, alias = "organizationUuid")]
    pub organization_uuid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OAuthProfile {
    #[serde(default)]
    account: OAuthProfileAccount,
    #[serde(default)]
    organization: OAuthProfileOrg,
}

#[derive(Debug, Default, Deserialize)]
struct OAuthProfileAccount {
    uuid: Option<String>,
    email: Option<String>,
    #[serde(default)]
    has_claude_max: bool,
    #[serde(default)]
    has_claude_pro: bool,
}

#[derive(Debug, Default, Deserialize)]
struct OAuthProfileOrg {
    uuid: Option<String>,
    organization_type: Option<String>,
    rate_limit_tier: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UsagePayload {
    #[serde(default)]
    five_hour: UsageBucketPayload,
    #[serde(default)]
    seven_day: UsageBucketPayload,
    #[serde(default)]
    seven_day_sonnet: UsageBucketPayload,
}

#[derive(Debug, Default, Deserialize)]
struct UsageBucketPayload {
    utilization: Option<f64>,
    resets_at: Option<String>,
}

pub fn oauth_start_claudecode(input: OAuthStartInput) -> OAuthStartState {
    let redirect_uri = input
        .redirect_uri
        .and_then(clean_string)
        .unwrap_or_else(|| DEFAULT_REDIRECT_URI.to_string());
    let scope = input
        .scope
        .and_then(clean_string)
        .unwrap_or_else(|| CLAUDE_CODE_OAUTH_SCOPE.to_string());
    let state_id = generate_oauth_state();
    let code_verifier = generate_code_verifier(32);
    let code_challenge = generate_code_challenge(&code_verifier);
    let auth_url = build_claude_authorize_url(&redirect_uri, &scope, &code_challenge, &state_id);

    OAuthStartState {
        response: OAuthStartResponse {
            auth_url,
            state: state_id.clone(),
            redirect_uri: redirect_uri.clone(),
        },
        stored_state: StoredOAuthState {
            channel: ChannelKind::ClaudeCode,
            state_id,
            code_verifier,
            redirect_uri,
            created_at_unix_ms: now_unix_ms(),
        },
    }
}

pub fn resolve_code_and_state(payload: &OAuthCallbackInput) -> Result<(String, Option<String>)> {
    let mut code = payload.code.clone().and_then(clean_string);
    let mut state = payload.state.clone().and_then(clean_string);

    if let Some(callback_url) = payload
        .callback_url
        .as_ref()
        .and_then(|value| clean_opt_str(value))
    {
        let callback_code = extract_value_from_text(&callback_url, "code");
        let callback_state = extract_value_from_text(&callback_url, "state");
        if code.is_none() {
            code = callback_code;
        }
        if state.is_none() {
            state = callback_state;
        }
        if code.is_none() {
            code = extract_manual_code(&callback_url);
        }
    }

    let code = code.ok_or_else(|| anyhow!("missing code"))?;
    Ok((code, state))
}

pub async fn exchange_claudecode_code_for_tokens(
    stored_state: &StoredOAuthState,
    code: &str,
) -> Result<ClaudeTokenResponse> {
    let cleaned_code = sanitize_oauth_code(code);
    let body = format!(
        "grant_type=authorization_code&client_id={}&code={}&redirect_uri={}&code_verifier={}&state={}",
        url_encode(CLAUDE_CODE_OAUTH_CLIENT_ID),
        url_encode(&cleaned_code),
        url_encode(&stored_state.redirect_uri),
        url_encode(&stored_state.code_verifier),
        url_encode(&stored_state.state_id),
    );

    let headers = default_claude_headers()?;
    headers.set("content-type", "application/x-www-form-urlencoded")?;
    headers.set("accept", "application/json, text/plain, */*")?;
    headers.set("origin", DEFAULT_CLAUDE_AI_BASE_URL)?;
    headers.set("referer", "https://claude.ai/")?;
    headers.set("user-agent", DEFAULT_TOKEN_USER_AGENT)?;

    let mut response = send_request(
        Method::Post,
        &format!("{}/v1/oauth/token", DEFAULT_BASE_URL),
        headers,
        Some(JsValue::from_str(&body)),
    )
    .await?;

    let status = response.status_code();
    let bytes = response.bytes().await?;
    if !(200..=299).contains(&status) {
        return Err(anyhow!(
            "oauth_token_failed: status={} body={}",
            status,
            String::from_utf8_lossy(&bytes)
        ));
    }
    Ok(serde_json::from_slice::<ClaudeTokenResponse>(&bytes)?)
}

pub async fn maybe_refresh_access_token(
    credential: &CredentialConfig,
) -> Result<Option<RefreshedCredential>, RefreshError> {
    maybe_refresh_claudecode_access_token(credential).await
}

pub async fn fetch_oauth_profile(access_token: &str) -> Result<OAuthProfileParsed> {
    let headers = Headers::new();
    headers.set("authorization", &format!("Bearer {access_token}"))?;
    headers.set("accept", "application/json")?;
    headers.set("anthropic-beta", DEFAULT_REQUIRED_BETA)?;
    headers.set("user-agent", DEFAULT_USER_AGENT)?;

    let mut response = send_request(
        Method::Get,
        &format!("{}/api/oauth/profile", DEFAULT_BASE_URL),
        headers,
        None,
    )
    .await?;
    let status = response.status_code();
    let bytes = response.bytes().await?;
    if !(200..=299).contains(&status) {
        return Err(anyhow!(
            "oauth_profile_failed: status={} body={}",
            status,
            String::from_utf8_lossy(&bytes)
        ));
    }
    let profile = serde_json::from_slice::<OAuthProfile>(&bytes)?;
    Ok(parse_profile(profile))
}

pub async fn fetch_claudecode_usage(access_token: &str) -> Result<CredentialUsageSnapshot> {
    let headers = Headers::new();
    headers.set("authorization", &format!("Bearer {access_token}"))?;
    headers.set("accept", "application/json")?;
    headers.set("anthropic-beta", DEFAULT_REQUIRED_BETA)?;
    headers.set("user-agent", DEFAULT_USER_AGENT)?;

    let mut response = send_request(
        Method::Get,
        &format!("{}/api/oauth/usage", DEFAULT_BASE_URL),
        headers,
        None,
    )
    .await?;
    let status = response.status_code();
    let bytes = response.bytes().await?;
    if !(200..=299).contains(&status) {
        return Err(anyhow!(
            "oauth_usage_failed: status={} body={}",
            status,
            String::from_utf8_lossy(&bytes)
        ));
    }

    let payload = serde_json::from_slice::<UsagePayload>(&bytes)?;
    Ok(CredentialUsageSnapshot {
        five_hour: parse_usage_bucket(payload.five_hour),
        seven_day: parse_usage_bucket(payload.seven_day),
        seven_day_sonnet: parse_usage_bucket(payload.seven_day_sonnet),
        last_error: None,
    })
}

async fn maybe_refresh_claudecode_access_token(
    credential: &CredentialConfig,
) -> Result<Option<RefreshedCredential>, RefreshError> {
    let now = now_unix_ms();
    if !credential.access_token.trim().is_empty()
        && credential.expires_at_unix_ms > now.saturating_add(60_000)
    {
        return Ok(None);
    }
    if credential.refresh_token.trim().is_empty() {
        return Err(RefreshError::InvalidCredential(
            "missing refresh_token".to_string(),
        ));
    }

    let body = format!(
        "grant_type=refresh_token&client_id={}&refresh_token={}",
        url_encode(CLAUDE_CODE_OAUTH_CLIENT_ID),
        url_encode(&credential.refresh_token),
    );

    let headers =
        default_claude_headers().map_err(|err| RefreshError::Transient(err.to_string()))?;
    headers
        .set("content-type", "application/x-www-form-urlencoded")
        .map_err(|err| RefreshError::Transient(err.to_string()))?;
    headers
        .set("accept", "application/json, text/plain, */*")
        .map_err(|err| RefreshError::Transient(err.to_string()))?;
    headers
        .set("user-agent", DEFAULT_TOKEN_USER_AGENT)
        .map_err(|err| RefreshError::Transient(err.to_string()))?;

    let mut response = send_request(
        Method::Post,
        &format!("{}/v1/oauth/token", DEFAULT_BASE_URL),
        headers,
        Some(JsValue::from_str(&body)),
    )
    .await
    .map_err(|err| RefreshError::Transient(err.to_string()))?;

    let status = response.status_code();
    let bytes = response
        .bytes()
        .await
        .map_err(|err| RefreshError::Transient(err.to_string()))?;
    let parsed = serde_json::from_slice::<ClaudeTokenResponse>(&bytes).ok();

    if (200..=299).contains(&status) {
        let access_token = parsed
            .as_ref()
            .and_then(|item| item.access_token.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| RefreshError::Transient("missing access_token".to_string()))?
            .to_string();
        let refresh_token = parsed
            .as_ref()
            .and_then(|item| item.refresh_token.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(credential.refresh_token.as_str())
            .to_string();
        let mut refreshed = RefreshedCredential {
            access_token,
            refresh_token,
            expires_at_unix_ms: now.saturating_add(
                parsed
                    .as_ref()
                    .and_then(|item| item.expires_in)
                    .unwrap_or(3600)
                    .saturating_mul(1000),
            ),
            user_email: credential.user_email.clone(),
            account_uuid: credential.account_uuid.clone(),
            organization_uuid: credential.organization_uuid.clone(),
            subscription_type: parsed
                .as_ref()
                .and_then(|item| item.subscription_type.clone()),
            rate_limit_tier: parsed
                .as_ref()
                .and_then(|item| item.rate_limit_tier.clone()),
        };
        if refreshed.user_email.is_none()
            || refreshed.account_uuid.is_none()
            || refreshed.organization_uuid.is_none()
            || refreshed.subscription_type.is_none()
            || refreshed.rate_limit_tier.is_none()
        {
            if let Ok(profile) = fetch_oauth_profile(&refreshed.access_token).await {
                if refreshed.user_email.is_none() {
                    refreshed.user_email = profile.email;
                }
                if refreshed.account_uuid.is_none() {
                    refreshed.account_uuid = profile.account_uuid;
                }
                if refreshed.organization_uuid.is_none() {
                    refreshed.organization_uuid = profile.organization_uuid;
                }
                if refreshed.subscription_type.is_none() {
                    refreshed.subscription_type = profile.subscription_type;
                }
                if refreshed.rate_limit_tier.is_none() {
                    refreshed.rate_limit_tier = profile.rate_limit_tier;
                }
            }
        }
        return Ok(Some(refreshed));
    }

    let error = parsed
        .as_ref()
        .and_then(|item| item.error.as_deref())
        .unwrap_or_default();
    let description = parsed
        .as_ref()
        .and_then(|item| item.error_description.as_deref())
        .unwrap_or_default();
    let text = String::from_utf8_lossy(&bytes).to_string();
    let message = if error.is_empty() && description.is_empty() {
        format!("oauth token refresh failed: status={} body={text}", status)
    } else {
        format!(
            "oauth token refresh failed: status={} error={} description={}",
            status, error, description
        )
    };

    if status == 400 || status == 401 || status == 403 {
        Err(RefreshError::InvalidCredential(message))
    } else {
        Err(RefreshError::Transient(message))
    }
}

fn parse_profile(profile: OAuthProfile) -> OAuthProfileParsed {
    let subscription_type = profile
        .organization
        .organization_type
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            if profile.account.has_claude_max {
                Some("claude_max".to_string())
            } else if profile.account.has_claude_pro {
                Some("claude_pro".to_string())
            } else {
                None
            }
        });

    OAuthProfileParsed {
        email: profile.account.email,
        account_uuid: profile.account.uuid,
        subscription_type,
        rate_limit_tier: profile.organization.rate_limit_tier,
        organization_uuid: profile.organization.uuid,
    }
}

fn parse_usage_bucket(bucket: UsageBucketPayload) -> CredentialUsageBucket {
    CredentialUsageBucket {
        utilization_pct: bucket
            .utilization
            .map(|value| value.round().clamp(0.0, 100.0) as u32),
        resets_at: bucket.resets_at.and_then(clean_string),
    }
}

fn default_claude_headers() -> Result<Headers> {
    let headers = Headers::new();
    headers.set("anthropic-version", DEFAULT_ANTHROPIC_VERSION)?;
    headers.set("anthropic-beta", DEFAULT_REQUIRED_BETA)?;
    Ok(headers)
}

async fn send_request(
    method: Method,
    url: &str,
    headers: Headers,
    body: Option<JsValue>,
) -> worker::Result<worker::Response> {
    let mut init = RequestInit::new();
    init.with_method(method)
        .with_headers(headers)
        .with_body(body);
    let request = Request::new_with_init(url, &init)?;
    Fetch::Request(request).send().await
}

fn build_claude_authorize_url(
    redirect_uri: &str,
    scope: &str,
    code_challenge: &str,
    state: &str,
) -> String {
    let query = vec![
        ("code".to_string(), "true".to_string()),
        (
            "client_id".to_string(),
            CLAUDE_CODE_OAUTH_CLIENT_ID.to_string(),
        ),
        ("response_type".to_string(), "code".to_string()),
        ("redirect_uri".to_string(), redirect_uri.to_string()),
        ("scope".to_string(), scope.to_string()),
        ("code_challenge".to_string(), code_challenge.to_string()),
        ("code_challenge_method".to_string(), "S256".to_string()),
        ("state".to_string(), state.to_string()),
    ]
    .into_iter()
    .map(|(key, value)| format!("{key}={}", url_encode(&value)))
    .collect::<Vec<_>>()
    .join("&");
    format!(
        "{}/oauth/authorize?{}",
        DEFAULT_CLAUDE_AI_BASE_URL.trim_end_matches('/'),
        query
    )
}

fn clean_opt_str(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn clean_string(value: String) -> Option<String> {
    clean_opt_str(&value)
}

fn generate_oauth_state() -> String {
    let mut bytes = [0u8; 24];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_code_verifier(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_code_challenge(code_verifier: &str) -> String {
    let digest = Sha256::digest(code_verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn parse_query_value(raw: Option<&str>, key: &str) -> Option<String> {
    let raw = raw?.trim();
    let query = raw
        .split_once('?')
        .map(|(_, query)| query)
        .unwrap_or(raw)
        .trim_start_matches('?');
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        if name == key {
            return Some(value.into_owned());
        }
    }
    None
}

fn extract_value_from_text(raw: &str, key: &str) -> Option<String> {
    parse_query_value(Some(raw), key)
        .or_else(|| parse_query_value(raw.split_once('#').map(|(_, fragment)| fragment), key))
        .or_else(|| extract_inline_query_value(raw, key))
        .or_else(|| {
            let decoded = percent_decode_lossy(raw);
            if decoded == raw {
                None
            } else {
                parse_query_value(Some(&decoded), key)
                    .or_else(|| extract_inline_query_value(&decoded, key))
            }
        })
}

fn extract_inline_query_value(raw: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let index = raw.find(&needle)?;
    let start = index + needle.len();
    let rest = &raw[start..];
    let end = rest
        .find(['&', '#', '"', '\'', ' ', '\n', '\r', '\t'])
        .unwrap_or(rest.len());
    let value = rest[..end].trim();
    if value.is_empty() {
        return None;
    }
    Some(percent_decode_lossy(value))
}

fn extract_labeled_value(raw: &str, key: &str) -> Option<String> {
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        for separator in [":", "="] {
            let prefix = format!("{key}{separator}");
            if lower.starts_with(&prefix) {
                let value = trimmed[prefix.len()..].trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

fn extract_manual_code(raw: &str) -> Option<String> {
    if let Some(code) = extract_labeled_value(raw, "code") {
        return Some(code);
    }

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let looks_structured = trimmed.contains("://")
        || trimmed.contains('?')
        || trimmed.contains('&')
        || trimmed.contains("code=")
        || trimmed.contains("state=");
    if looks_structured {
        return None;
    }
    (!trimmed.contains(char::is_whitespace)).then(|| trimmed.to_string())
}

fn percent_decode_lossy(value: &str) -> String {
    form_urlencoded::parse(format!("x={value}").as_bytes())
        .next()
        .map(|(_, decoded)| decoded.into_owned())
        .unwrap_or_else(|| value.to_string())
}

fn url_encode(value: &str) -> String {
    form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
}

fn sanitize_oauth_code(code: &str) -> String {
    let code = code.split('#').next().unwrap_or(code);
    let code = code.split('&').next().unwrap_or(code);
    code.trim().to_string()
}
