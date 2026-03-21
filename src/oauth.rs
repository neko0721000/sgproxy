use anyhow::{Result, anyhow};
use axum::Json;
use base64::Engine as _;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use url::form_urlencoded;

use crate::config::{
    CLAUDE_CODE_OAUTH_CLIENT_ID, CLAUDE_CODE_OAUTH_SCOPE, DEFAULT_REDIRECT_URI,
    DEFAULT_REQUIRED_BETA, DEFAULT_USER_AGENT,
};
use crate::state::{AppState, OAuthState, now_unix_ms};

#[derive(Debug, Deserialize)]
pub struct OAuthStartInput {
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OAuthCallbackInput {
    pub callback_url: Option<String>,
    pub code: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
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

#[derive(Debug, Serialize)]
pub struct OAuthStartResponse {
    pub auth_url: String,
    pub state: String,
    pub redirect_uri: String,
}

pub async fn oauth_start(
    state: &AppState,
    payload: OAuthStartInput,
) -> Result<Json<OAuthStartResponse>> {
    let config = state.config_snapshot().await;
    let redirect_uri = payload
        .redirect_uri
        .and_then(clean_opt)
        .unwrap_or_else(|| DEFAULT_REDIRECT_URI.to_string());
    let scope = payload
        .scope
        .and_then(clean_opt)
        .unwrap_or_else(|| CLAUDE_CODE_OAUTH_SCOPE.to_string());
    let state_id = generate_oauth_state();
    let code_verifier = generate_code_verifier();
    let code_challenge = generate_code_challenge(code_verifier.as_str());
    let auth_url = build_authorize_url(
        config.upstream.claude_ai_base_url.as_str(),
        redirect_uri.as_str(),
        scope.as_str(),
        code_challenge.as_str(),
        state_id.as_str(),
    );

    state
        .insert_oauth_state(
            state_id.clone(),
            OAuthState {
                code_verifier,
                redirect_uri: redirect_uri.clone(),
                api_base_url: config.upstream.base_url.clone(),
                claude_ai_base_url: config.upstream.claude_ai_base_url.clone(),
                created_at_unix_ms: now_unix_ms(),
            },
        )
        .await;

    Ok(Json(OAuthStartResponse {
        auth_url,
        state: state_id,
        redirect_uri,
    }))
}

pub async fn oauth_callback(
    state: &AppState,
    payload: OAuthCallbackInput,
) -> Result<Json<serde_json::Value>> {
    let (code, requested_state) = resolve_code_and_state(&payload)?;
    let (resolved_state, oauth_state) = state
        .take_oauth_state_with_id(requested_state.as_deref())
        .await?;
    let client = state.client().await;
    let token = exchange_code_for_tokens(
        &client,
        oauth_state.api_base_url.as_str(),
        oauth_state.claude_ai_base_url.as_str(),
        oauth_state.redirect_uri.as_str(),
        oauth_state.code_verifier.as_str(),
        code.as_str(),
        Some(resolved_state.as_str()),
    )
    .await?;

    let access_token = token
        .access_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("missing_access_token"))?
        .to_string();
    let refresh_token = token
        .refresh_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("missing_refresh_token"))?
        .to_string();

    let profile = fetch_oauth_profile(
        &client,
        oauth_state.api_base_url.as_str(),
        access_token.as_str(),
    )
    .await
    .ok();
    let expires_at_unix_ms =
        now_unix_ms().saturating_add(token.expires_in.unwrap_or(3600).saturating_mul(1000));
    let credential = state
        .add_or_create_credential(
            crate::config::CredentialUpsertInput {
                id: None,
                enabled: Some(true),
                order: None,
                access_token: Some(access_token.clone()),
                refresh_token: Some(refresh_token.clone()),
                expires_at_unix_ms: Some(expires_at_unix_ms),
                user_email: profile.as_ref().and_then(|item| item.email.clone()),
                organization_uuid: profile
                    .as_ref()
                    .and_then(|item| item.organization_uuid.clone()),
                subscription_type: token.subscription_type.clone().or_else(|| {
                    profile
                        .as_ref()
                        .and_then(|item| item.subscription_type.clone())
                }),
                rate_limit_tier: token.rate_limit_tier.clone().or_else(|| {
                    profile
                        .as_ref()
                        .and_then(|item| item.rate_limit_tier.clone())
                }),
            },
            None,
        )
        .await?;

    Ok(Json(serde_json::json!({
        "credential": credential,
        "upstream": {
            "expires_in": token.expires_in,
            "subscription_type": token.subscription_type,
            "rate_limit_tier": token.rate_limit_tier,
        }
    })))
}

#[derive(Debug, Clone)]
pub struct RefreshedCredential {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at_unix_ms: u64,
    pub subscription_type: Option<String>,
    pub rate_limit_tier: Option<String>,
}

#[derive(Debug)]
pub enum RefreshError {
    InvalidCredential(String),
    Transient(String),
}

pub async fn maybe_refresh_access_token(
    client: &reqwest::Client,
    upstream: &crate::config::UpstreamConfig,
    credential: &crate::config::CredentialConfig,
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
        url_encode(credential.refresh_token.as_str()),
    );
    let url = format!("{}/v1/oauth/token", upstream.base_url.trim_end_matches('/'));
    let response = client
        .post(url)
        .header("anthropic-version", upstream.anthropic_version.as_str())
        .header("anthropic-beta", DEFAULT_REQUIRED_BETA)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json, text/plain, */*")
        .header("connection", "close")
        .header("user-agent", DEFAULT_USER_AGENT)
        .body(body)
        .send()
        .await
        .map_err(|err| RefreshError::Transient(err.to_string()))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|err| RefreshError::Transient(err.to_string()))?;
    let parsed = serde_json::from_slice::<TokenResponse>(&bytes).ok();
    if status.is_success() {
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
        return Ok(Some(RefreshedCredential {
            access_token,
            refresh_token,
            expires_at_unix_ms: now.saturating_add(
                parsed
                    .as_ref()
                    .and_then(|item| item.expires_in)
                    .unwrap_or(3600)
                    .saturating_mul(1000),
            ),
            subscription_type: parsed
                .as_ref()
                .and_then(|item| item.subscription_type.clone()),
            rate_limit_tier: parsed
                .as_ref()
                .and_then(|item| item.rate_limit_tier.clone()),
        }));
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
        format!(
            "oauth token refresh failed: status={} body={text}",
            status.as_u16()
        )
    } else {
        format!(
            "oauth token refresh failed: status={} error={} description={}",
            status.as_u16(),
            error,
            description
        )
    };
    if is_invalid_oauth_credential_failure(status.as_u16(), error, description) {
        Err(RefreshError::InvalidCredential(message))
    } else {
        Err(RefreshError::Transient(message))
    }
}

#[derive(Debug, Default)]
pub(crate) struct OAuthProfileParsed {
    pub(crate) email: Option<String>,
    pub(crate) subscription_type: Option<String>,
    pub(crate) rate_limit_tier: Option<String>,
    pub(crate) organization_uuid: Option<String>,
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
        subscription_type,
        rate_limit_tier: profile.organization.rate_limit_tier,
        organization_uuid: profile.organization.uuid,
    }
}

fn resolve_code_and_state(payload: &OAuthCallbackInput) -> Result<(String, Option<String>)> {
    let mut code = payload.code.clone().and_then(clean_opt);
    let mut state = payload.state.clone().and_then(clean_opt);
    if let Some(callback_url) = payload
        .callback_url
        .as_ref()
        .and_then(|value| clean_opt_str(value.as_str()))
    {
        let callback_code = extract_value_from_text(callback_url.as_str(), "code");
        let callback_state = extract_value_from_text(callback_url.as_str(), "state");
        if code.is_none() {
            code = callback_code;
        }
        if state.is_none() {
            state = callback_state;
        }
        if code.is_none() {
            code = extract_manual_code(callback_url.as_str());
        }
        if state.is_none() {
            state = extract_labeled_value(callback_url.as_str(), "state");
        }
    }
    let code = code.ok_or_else(|| anyhow!("missing code"))?;
    Ok((code, state))
}

async fn exchange_code_for_tokens(
    client: &reqwest::Client,
    api_base_url: &str,
    claude_ai_base_url: &str,
    redirect_uri: &str,
    code_verifier: &str,
    code: &str,
    state: Option<&str>,
) -> Result<TokenResponse> {
    let cleaned_code = code.split('#').next().unwrap_or(code);
    let cleaned_code = cleaned_code.split('&').next().unwrap_or(cleaned_code);
    let mut body = format!(
        "grant_type=authorization_code&client_id={}&code={}&redirect_uri={}&code_verifier={}",
        url_encode(CLAUDE_CODE_OAUTH_CLIENT_ID),
        url_encode(cleaned_code),
        url_encode(redirect_uri),
        url_encode(code_verifier),
    );
    if let Some(state) = state {
        body.push_str("&state=");
        body.push_str(url_encode(state).as_str());
    }
    let origin = claude_ai_base_url.trim_end_matches('/');
    let url = format!("{}/v1/oauth/token", api_base_url.trim_end_matches('/'));
    let response = client
        .post(url)
        .header("anthropic-version", "2023-06-01")
        .header("anthropic-beta", DEFAULT_REQUIRED_BETA)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json, text/plain, */*")
        .header("user-agent", DEFAULT_USER_AGENT)
        .header("origin", origin)
        .header("referer", format!("{origin}/"))
        .body(body)
        .send()
        .await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    if !status.is_success() {
        return Err(anyhow!(
            "oauth_token_failed: status={} body={}",
            status.as_u16(),
            String::from_utf8_lossy(&bytes)
        ));
    }
    Ok(serde_json::from_slice::<TokenResponse>(&bytes)?)
}

pub(crate) async fn fetch_oauth_profile(
    client: &reqwest::Client,
    api_base_url: &str,
    access_token: &str,
) -> Result<OAuthProfileParsed> {
    let url = format!("{}/api/oauth/profile", api_base_url.trim_end_matches('/'));
    let mut last_err = None;
    let response = loop {
        match client
            .get(url.as_str())
            .header("authorization", format!("Bearer {access_token}"))
            .header("user-agent", DEFAULT_USER_AGENT)
            .header("accept", "application/json")
            .header("connection", "close")
            .header("anthropic-beta", DEFAULT_REQUIRED_BETA)
            .send()
            .await
        {
            Ok(response) => break response,
            Err(err) if last_err.is_none() => {
                last_err = Some(err);
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(err) => return Err(err.into()),
        }
    };
    let status = response.status();
    let bytes = response.bytes().await?;
    if !status.is_success() {
        return Err(anyhow!(
            "oauth_profile_failed: status={} body={}",
            status.as_u16(),
            String::from_utf8_lossy(&bytes)
        ));
    }
    let payload = serde_json::from_slice::<OAuthProfile>(&bytes)?;
    Ok(parse_profile(payload))
}

fn build_authorize_url(
    claude_ai_base_url: &str,
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
    .map(|(key, value)| format!("{key}={}", url_encode(value.as_str())))
    .collect::<Vec<_>>()
    .join("&");
    format!(
        "{}/oauth/authorize?{}",
        claude_ai_base_url.trim_end_matches('/'),
        query
    )
}

fn clean_opt(value: String) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn clean_opt_str(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn generate_oauth_state() -> String {
    let mut bytes = [0u8; 24];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_code_verifier() -> String {
    let mut bytes = [0u8; 32];
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
                parse_query_value(Some(decoded.as_str()), key)
                    .or_else(|| extract_inline_query_value(decoded.as_str(), key))
            }
        })
}

fn extract_inline_query_value(raw: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let index = raw.find(needle.as_str())?;
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
            if lower.starts_with(prefix.as_str()) {
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
    url::form_urlencoded::parse(format!("x={value}").as_bytes())
        .next()
        .map(|(_, decoded)| decoded.into_owned())
        .unwrap_or_else(|| value.to_string())
}

fn url_encode(value: &str) -> String {
    form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
}

fn is_invalid_oauth_credential_failure(status: u16, error: &str, description: &str) -> bool {
    if !matches!(status, 400 | 401 | 403) {
        return false;
    }
    let joined = format!(
        "{} {}",
        error.to_ascii_lowercase(),
        description.to_ascii_lowercase()
    );
    joined.contains("invalid_grant")
        || joined.contains("invalid_client")
        || joined.contains("unauthorized_client")
        || joined.contains("invalid_scope")
        || joined.contains("invalid_token")
}

#[cfg(test)]
mod tests {
    use super::{
        OAuthCallbackInput, extract_labeled_value, extract_manual_code, extract_value_from_text,
        resolve_code_and_state,
    };

    #[test]
    fn resolve_code_and_state_accepts_full_callback_url() {
        let payload = OAuthCallbackInput {
            callback_url: Some(
                "https://platform.claude.com/oauth/code/callback?code=abc123&state=state456"
                    .to_string(),
            ),
            code: None,
            state: None,
        };
        let (code, state) = resolve_code_and_state(&payload).expect("resolve code/state");
        assert_eq!(code, "abc123");
        assert_eq!(state.as_deref(), Some("state456"));
    }

    #[test]
    fn extract_value_from_text_accepts_pasted_text_with_embedded_url() {
        let pasted = "paste this callback: https://platform.claude.com/oauth/code/callback?code=abc123&state=state456";
        assert_eq!(
            extract_value_from_text(pasted, "code").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            extract_value_from_text(pasted, "state").as_deref(),
            Some("state456")
        );
    }

    #[test]
    fn resolve_code_and_state_accepts_manual_code_only() {
        let payload = OAuthCallbackInput {
            callback_url: Some("abc123".to_string()),
            code: None,
            state: None,
        };
        let (code, state) = resolve_code_and_state(&payload).expect("resolve code/state");
        assert_eq!(code, "abc123");
        assert_eq!(state, None);
    }

    #[test]
    fn extract_manual_code_accepts_labeled_lines() {
        assert_eq!(
            extract_manual_code("code: abc123").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            extract_labeled_value("state: state456", "state").as_deref(),
            Some("state456")
        );
    }
}
