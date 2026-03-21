use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use chrono::DateTime;
use tokio::sync::RwLock;

use crate::config::{
    AdminConfigView, ConfigFile, CredentialConfig, CredentialStatus, CredentialUpsertInput,
    CredentialUsageBucket, CredentialUsageSnapshot, OAUTH_STATE_TTL_MS, UpdateConfigInput,
    UpstreamConfig, UsageCredentialView, clean_opt_owned,
};
use crate::oauth::{RefreshError, fetch_oauth_profile, maybe_refresh_access_token};
use crate::persist::save_config;

const FIVE_HOUR_WINDOW_MS: u64 = 5 * 60 * 60 * 1000;

#[derive(Debug, Clone)]
pub struct OAuthState {
    pub code_verifier: String,
    pub redirect_uri: String,
    pub api_base_url: String,
    pub claude_ai_base_url: String,
    pub created_at_unix_ms: u64,
}

#[derive(Debug, Clone)]
pub struct SelectedCredential {
    pub credential: CredentialConfig,
}

pub struct AppState {
    config_path: PathBuf,
    config: RwLock<ConfigFile>,
    client: RwLock<reqwest::Client>,
    oauth_states: RwLock<HashMap<String, OAuthState>>,
}

impl AppState {
    pub fn new(config_path: PathBuf, mut config: ConfigFile) -> Result<Arc<Self>> {
        config.normalize();
        let client = build_http_client(&config.upstream)?;
        Ok(Arc::new(Self {
            config_path,
            config: RwLock::new(config),
            client: RwLock::new(client),
            oauth_states: RwLock::new(HashMap::new()),
        }))
    }

    pub async fn client(&self) -> reqwest::Client {
        self.client.read().await.clone()
    }

    pub async fn admin_token(&self) -> String {
        self.config.read().await.server.admin_token.clone()
    }

    pub async fn verify_admin_token(&self, token: &str) -> bool {
        self.admin_token().await == token
    }

    pub async fn config_view(&self) -> AdminConfigView {
        let config = self.config.read().await;
        AdminConfigView {
            host: config.server.host.clone(),
            port: config.server.port,
            proxy: config.upstream.proxy.clone(),
        }
    }

    pub async fn update_config(&self, input: UpdateConfigInput) -> Result<AdminConfigView> {
        let mut config = self.config.write().await;
        config.server.host = input.host.trim().to_string();
        config.server.port = input.port;
        config.upstream.proxy = clean_opt_owned(input.proxy);
        config.normalize();
        let client = build_http_client(&config.upstream)?;
        let view = AdminConfigView {
            host: config.server.host.clone(),
            port: config.server.port,
            proxy: config.upstream.proxy.clone(),
        };
        let snapshot = config.clone();
        drop(config);
        *self.client.write().await = client;
        save_config(&self.config_path, &snapshot).await?;
        Ok(view)
    }

    pub async fn credentials(&self) -> Vec<CredentialConfig> {
        let mut config = self.config.write().await;
        normalize_runtime_credentials(&mut config.credentials, now_unix_ms());
        let credentials = config.credentials.clone();
        drop(config);
        credentials
    }

    pub async fn credential_usage_views(&self) -> Result<Vec<UsageCredentialView>> {
        let credentials = self.credentials().await;
        self.build_usage_views(credentials).await
    }

    pub async fn credential_usage_view(&self, id: &str) -> Result<UsageCredentialView> {
        let credential = self
            .credentials()
            .await
            .into_iter()
            .find(|item| item.id == id)
            .ok_or_else(|| anyhow!("credential not found: {id}"))?;
        let mut views = self.build_usage_views(vec![credential]).await?;
        views.pop()
            .ok_or_else(|| anyhow!("credential usage not found: {id}"))
    }

    pub async fn public_usage_credentials(&self) -> Result<Vec<UsageCredentialView>> {
        self.build_usage_views(self.credentials().await).await
    }

    async fn build_usage_views(
        &self,
        credentials: Vec<CredentialConfig>,
    ) -> Result<Vec<UsageCredentialView>> {
        let mut views = Vec::with_capacity(credentials.len());
        for credential in credentials {
            let usage = self.fetch_live_usage(credential.id.as_str(), credential.access_token.as_str()).await;
            let (status, cooldown_until_unix_ms, last_error) = merge_status_for_view(&credential, &usage);
            views.push(UsageCredentialView {
                id: credential.id,
                user_email: credential.user_email,
                enabled: credential.enabled,
                order: credential.order,
                status,
                cooldown_until_unix_ms,
                last_error,
                last_used_at_unix_ms: credential.last_used_at_unix_ms,
                usage,
            });
        }
        Ok(views)
    }

    pub async fn config_snapshot(&self) -> ConfigFile {
        self.config.read().await.clone()
    }

    pub async fn max_body_bytes(&self) -> usize {
        self.config.read().await.server.max_body_bytes
    }

    pub async fn add_or_create_credential(
        &self,
        input: CredentialUpsertInput,
        forced_id: Option<String>,
    ) -> Result<CredentialConfig> {
        let existing = if let Some(id) = forced_id.as_deref().or(input.id.as_deref()) {
            self.config
                .read()
                .await
                .credentials
                .iter()
                .find(|item| item.id == id)
                .cloned()
        } else {
            None
        };
        let resolved = self
            .resolve_credential_input(input, existing.as_ref())
            .await?;
        self.store_credential(resolved, forced_id).await
    }

    pub async fn add_or_update_credential(
        &self,
        input: CredentialUpsertInput,
        forced_id: Option<String>,
    ) -> Result<CredentialConfig> {
        let existing = if let Some(id) = forced_id.as_deref().or(input.id.as_deref()) {
            self.config
                .read()
                .await
                .credentials
                .iter()
                .find(|item| item.id == id)
                .cloned()
        } else {
            None
        };
        let resolved = self
            .resolve_credential_input(input, existing.as_ref())
            .await?;
        self.store_credential(resolved, forced_id).await
    }

    async fn store_credential(
        &self,
        input: CredentialUpsertInput,
        forced_id: Option<String>,
    ) -> Result<CredentialConfig> {
        let mut config = self.config.write().await;
        normalize_runtime_credentials(&mut config.credentials, now_unix_ms());
        let id = forced_id
            .or_else(|| input.id.clone())
            .unwrap_or_else(generate_credential_id);
        let default_order = input
            .order
            .unwrap_or_else(|| next_order(&config.credentials));
        let existing = config.credentials.iter_mut().find(|item| item.id == id);

        let credential = CredentialConfig {
            id: id.clone(),
            enabled: input.enabled.unwrap_or(true),
            order: default_order,
            access_token: input.access_token.unwrap_or_default(),
            refresh_token: input.refresh_token.unwrap_or_default(),
            expires_at_unix_ms: input.expires_at_unix_ms.unwrap_or(0),
            user_email: clean_opt_owned(input.user_email),
            organization_uuid: clean_opt_owned(input.organization_uuid),
            subscription_type: clean_opt_owned(input.subscription_type),
            rate_limit_tier: clean_opt_owned(input.rate_limit_tier),
            status: CredentialStatus::Healthy,
            cooldown_until_unix_ms: None,
            last_error: None,
            last_used_at_unix_ms: None,
        };

        if let Some(item) = existing {
            let current_status = item.status;
            let current_cooldown = item.cooldown_until_unix_ms;
            let current_last_error = item.last_error.clone();
            let current_last_used = item.last_used_at_unix_ms;
            *item = credential;
            item.status = current_status;
            item.cooldown_until_unix_ms = current_cooldown;
            item.last_error = current_last_error;
            item.last_used_at_unix_ms = current_last_used;
        } else {
            config.credentials.push(credential);
        }

        config.normalize();
        let stored = config
            .credentials
            .iter()
            .find(|item| item.id == id)
            .cloned()
            .expect("stored credential exists after normalize");
        let snapshot = config.clone();
        drop(config);
        save_config(&self.config_path, &snapshot).await?;
        Ok(stored)
    }

    async fn resolve_credential_input(
        &self,
        input: CredentialUpsertInput,
        existing: Option<&CredentialConfig>,
    ) -> Result<CredentialUpsertInput> {
        let mut access_token = clean_opt_owned(input.access_token).or_else(|| {
            existing.and_then(|item| clean_opt_owned(Some(item.access_token.clone())))
        });
        let mut refresh_token = clean_opt_owned(input.refresh_token).or_else(|| {
            existing.and_then(|item| clean_opt_owned(Some(item.refresh_token.clone())))
        });
        let mut expires_at_unix_ms = input
            .expires_at_unix_ms
            .or_else(|| existing.map(|item| item.expires_at_unix_ms));
        let mut user_email = clean_opt_owned(input.user_email)
            .or_else(|| existing.and_then(|item| item.user_email.clone()));
        let mut organization_uuid = clean_opt_owned(input.organization_uuid)
            .or_else(|| existing.and_then(|item| item.organization_uuid.clone()));
        let mut subscription_type = clean_opt_owned(input.subscription_type)
            .or_else(|| existing.and_then(|item| item.subscription_type.clone()));
        let mut rate_limit_tier = clean_opt_owned(input.rate_limit_tier)
            .or_else(|| existing.and_then(|item| item.rate_limit_tier.clone()));

        if access_token.is_none() && refresh_token.is_none() {
            return Err(anyhow!("missing access_token or refresh_token"));
        }

        let config = self.config_snapshot().await;
        let client = self.client().await;
        if let Some(refresh) = refresh_token.as_deref().filter(|value| !value.trim().is_empty()) {
            if access_token.is_none() || expires_at_unix_ms.unwrap_or(0) <= now_unix_ms() {
                let refreshed = maybe_refresh_access_token(
                    &client,
                    &config.upstream,
                    &CredentialConfig {
                        id: existing
                            .map(|item| item.id.clone())
                            .unwrap_or_else(|| "import".to_string()),
                        enabled: existing.map(|item| item.enabled).unwrap_or(true),
                        order: existing.map(|item| item.order).unwrap_or(0),
                        access_token: access_token.clone().unwrap_or_default(),
                        refresh_token: refresh.to_string(),
                        expires_at_unix_ms: expires_at_unix_ms.unwrap_or(0),
                        user_email: None,
                        organization_uuid: None,
                        subscription_type: None,
                        rate_limit_tier: None,
                        status: CredentialStatus::Healthy,
                        cooldown_until_unix_ms: None,
                        last_error: None,
                        last_used_at_unix_ms: None,
                    },
                )
                .await
                .map_err(|err| match err {
                    RefreshError::InvalidCredential(message)
                    | RefreshError::Transient(message) => anyhow!(message),
                })?;
                if let Some(refreshed) = refreshed {
                    access_token = Some(refreshed.access_token);
                    refresh_token = Some(refreshed.refresh_token);
                    expires_at_unix_ms = Some(refreshed.expires_at_unix_ms);
                    if subscription_type.is_none() {
                        subscription_type = refreshed.subscription_type;
                    }
                    if rate_limit_tier.is_none() {
                        rate_limit_tier = refreshed.rate_limit_tier;
                    }
                }
            }
        }

        let access_token = access_token.ok_or_else(|| anyhow!("missing access_token"))?;
        if user_email.is_none()
            || organization_uuid.is_none()
            || subscription_type.is_none()
            || rate_limit_tier.is_none()
        {
            let profile = fetch_oauth_profile(&client, config.upstream.base_url.as_str(), &access_token)
                .await?;
            if user_email.is_none() {
                user_email = profile.email;
            }
            if organization_uuid.is_none() {
                organization_uuid = profile.organization_uuid;
            }
            if subscription_type.is_none() {
                subscription_type = profile.subscription_type;
            }
            if rate_limit_tier.is_none() {
                rate_limit_tier = profile.rate_limit_tier;
            }
        }

        Ok(CredentialUpsertInput {
            id: input.id.or_else(|| existing.map(|item| item.id.clone())),
            enabled: input
                .enabled
                .or_else(|| existing.map(|item| item.enabled)),
            order: input.order.or_else(|| existing.map(|item| item.order)),
            access_token: Some(access_token),
            refresh_token,
            expires_at_unix_ms: Some(expires_at_unix_ms.unwrap_or(0)),
            user_email,
            organization_uuid,
            subscription_type,
            rate_limit_tier,
        })
    }

    pub async fn delete_credential(&self, id: &str) -> Result<()> {
        let mut config = self.config.write().await;
        let before = config.credentials.len();
        config.credentials.retain(|item| item.id != id);
        if before == config.credentials.len() {
            return Err(anyhow!("credential not found: {id}"));
        }
        let snapshot = config.clone();
        drop(config);
        save_config(&self.config_path, &snapshot).await?;
        Ok(())
    }

    pub async fn set_enabled(&self, id: &str, enabled: bool) -> Result<CredentialConfig> {
        let mut config = self.config.write().await;
        let now = now_unix_ms();
        normalize_runtime_credentials(&mut config.credentials, now);
        let item = config
            .credentials
            .iter_mut()
            .find(|item| item.id == id)
            .ok_or_else(|| anyhow!("credential not found: {id}"))?;
        item.enabled = enabled;
        let stored = item.clone();
        let snapshot = config.clone();
        drop(config);
        save_config(&self.config_path, &snapshot).await?;
        Ok(stored)
    }

    pub async fn select_credential_for_proxy(&self) -> Result<SelectedCredential> {
        let mut config = self.config.write().await;
        let now = now_unix_ms();
        normalize_runtime_credentials(&mut config.credentials, now);
        let selected = first_usable(&config.credentials, now)
            .cloned()
            .ok_or_else(|| anyhow!("no usable credential configured"))?;
        Ok(SelectedCredential {
            credential: selected,
        })
    }

    pub async fn record_proxy_result(
        &self,
        credential_id: &str,
        access_token: &str,
        status_code: u16,
    ) -> Result<()> {
        let usage_result = match status_code {
            429 => {
                let client = self.client().await;
                let credential = CredentialConfig {
                    id: credential_id.to_string(),
                    enabled: true,
                    order: 0,
                    access_token: access_token.to_string(),
                    refresh_token: String::new(),
                    expires_at_unix_ms: 0,
                    user_email: None,
                    organization_uuid: None,
                    subscription_type: None,
                    rate_limit_tier: None,
                    status: CredentialStatus::Healthy,
                    cooldown_until_unix_ms: None,
                    last_error: None,
                    last_used_at_unix_ms: None,
                };
                Some(fetch_usage_payload(&client, &credential).await)
            }
            _ => None,
        };

        let mut config = self.config.write().await;
        let now = now_unix_ms();
        normalize_runtime_credentials(&mut config.credentials, now);

        if let Some(item) = config
            .credentials
            .iter_mut()
            .find(|item| item.id == credential_id)
        {
            item.last_used_at_unix_ms = Some(now);
            item.last_error = None;
            match status_code {
                200..=299 => {
                    if item.status != CredentialStatus::Dead {
                        item.status = CredentialStatus::Healthy;
                        item.cooldown_until_unix_ms = None;
                    }
                }
                401 | 403 => {
                    item.status = CredentialStatus::Dead;
                    item.cooldown_until_unix_ms = None;
                    item.last_error = Some(format!("upstream returned status {status_code}"));
                }
                429 => match usage_result.expect("usage result exists for 429") {
                    Ok(payload) => {
                        let (status, cooldown_until_unix_ms) =
                            derive_rate_limited_status_from_payload(&payload, now).unwrap_or((
                                CredentialStatus::Cooldown5h,
                                Some(now.saturating_add(FIVE_HOUR_WINDOW_MS)),
                            ));
                        item.status = status;
                        item.cooldown_until_unix_ms = cooldown_until_unix_ms;
                        item.last_error = Some("upstream returned status 429".to_string());
                    }
                    Err(UsageRefreshFailure::Dead(message)) => {
                        item.status = CredentialStatus::Dead;
                        item.cooldown_until_unix_ms = None;
                        item.last_error = Some(message);
                    }
                    Err(UsageRefreshFailure::Transient(message)) => {
                        item.status = CredentialStatus::Cooldown5h;
                        item.cooldown_until_unix_ms =
                            Some(now.saturating_add(FIVE_HOUR_WINDOW_MS));
                        item.last_error = Some(format!(
                            "upstream returned status 429; usage fetch failed: {message}"
                        ));
                    }
                },
                _ => {
                    item.last_error = Some(format!("upstream returned status {status_code}"));
                }
            }
        }

        let snapshot = config.clone();
        drop(config);
        save_config(&self.config_path, &snapshot).await?;
        Ok(())
    }

    pub async fn upstream_snapshot(&self) -> crate::config::UpstreamConfig {
        self.config.read().await.upstream.clone()
    }

    pub async fn insert_oauth_state(&self, state_id: String, state: OAuthState) {
        self.oauth_states.write().await.insert(state_id, state);
    }

    pub async fn take_oauth_state(&self, requested_state: Option<&str>) -> Result<OAuthState> {
        let (_, state) = self.take_oauth_state_with_id(requested_state).await?;
        Ok(state)
    }

    pub async fn take_oauth_state_with_id(
        &self,
        requested_state: Option<&str>,
    ) -> Result<(String, OAuthState)> {
        let now = now_unix_ms();
        let mut states = self.oauth_states.write().await;
        states.retain(|_, value| now.saturating_sub(value.created_at_unix_ms) <= OAUTH_STATE_TTL_MS);

        if let Some(state_id) = requested_state {
            let state = states
                .remove(state_id)
                .ok_or_else(|| anyhow!("missing state"))?;
            return Ok((state_id.to_string(), state));
        }

        if states.is_empty() {
            return Err(anyhow!("missing state"));
        }
        if states.len() > 1 {
            return Err(anyhow!("ambiguous_state"));
        }
        let key = states
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| anyhow!("missing state"))?;
        let state = states.remove(&key).ok_or_else(|| anyhow!("missing state"))?;
        Ok((key, state))
    }

    async fn mark_dead(&self, credential_id: &str, message: String) -> Result<()> {
        let mut config = self.config.write().await;
        let item = config
            .credentials
            .iter_mut()
            .find(|item| item.id == credential_id)
            .ok_or_else(|| anyhow!("credential not found: {credential_id}"))?;
        item.status = CredentialStatus::Dead;
        item.cooldown_until_unix_ms = None;
        item.last_error = Some(message.clone());
        let snapshot = config.clone();
        drop(config);
        save_config(&self.config_path, &snapshot).await?;
        Ok(())
    }

    async fn fetch_live_usage(&self, credential_id: &str, access_token: &str) -> CredentialUsageSnapshot {
        let client = self.client().await;
        let credential = CredentialConfig {
            id: credential_id.to_string(),
            enabled: true,
            order: 0,
            access_token: access_token.to_string(),
            refresh_token: String::new(),
            expires_at_unix_ms: 0,
            user_email: None,
            organization_uuid: None,
            subscription_type: None,
            rate_limit_tier: None,
            status: CredentialStatus::Healthy,
            cooldown_until_unix_ms: None,
            last_error: None,
            last_used_at_unix_ms: None,
        };
        match fetch_usage_response(&client, &credential).await {
            Ok(snapshot) => snapshot,
            Err(UsageRefreshFailure::Dead(message)) => {
                let _ = self.mark_dead(credential_id, message.clone()).await;
                CredentialUsageSnapshot {
                    last_error: Some(message),
                    ..CredentialUsageSnapshot::default()
                }
            }
            Err(UsageRefreshFailure::Transient(message)) => CredentialUsageSnapshot {
                last_error: Some(message),
                ..CredentialUsageSnapshot::default()
            },
        }
    }
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as u64)
        .unwrap_or(0)
}

fn normalize_runtime_credentials(credentials: &mut [CredentialConfig], now: u64) {
    for item in credentials {
        if matches!(
            item.status,
            CredentialStatus::Cooldown5h
                | CredentialStatus::CooldownSonnet7d
                | CredentialStatus::Cooldown7d
        ) && item
            .cooldown_until_unix_ms
            .is_some_and(|until| until <= now)
        {
            item.status = CredentialStatus::Healthy;
            item.cooldown_until_unix_ms = None;
            item.last_error = None;
        }
    }
}

fn first_usable<'a>(credentials: &'a [CredentialConfig], now: u64) -> Option<&'a CredentialConfig> {
    credentials.iter().find(|item| is_usable(item, now))
}

fn is_usable(item: &CredentialConfig, now: u64) -> bool {
    item.enabled
        && item.status != CredentialStatus::Dead
        && !item.access_token.trim().is_empty()
        && item
            .cooldown_until_unix_ms
            .map(|until| until <= now)
            .unwrap_or(true)
}

#[derive(Debug)]
enum UsageRefreshFailure {
    Dead(String),
    Transient(String),
}

async fn fetch_usage_response(
    client: &reqwest::Client,
    credential: &CredentialConfig,
) -> Result<CredentialUsageSnapshot, UsageRefreshFailure> {
    let payload = fetch_usage_payload(client, credential).await?;
    Ok(parse_usage_snapshot(&payload))
}

async fn fetch_usage_payload(
    client: &reqwest::Client,
    credential: &CredentialConfig,
) -> Result<serde_json::Value, UsageRefreshFailure> {
    let response = client
        .get(format!(
            "{}/api/oauth/usage",
            crate::config::DEFAULT_BASE_URL.trim_end_matches('/')
        ))
        .header(
            "authorization",
            format!("Bearer {}", credential.access_token.trim()),
        )
        .header("accept", "application/json")
        .header("anthropic-beta", crate::config::DEFAULT_REQUIRED_BETA)
        .header("user-agent", crate::config::DEFAULT_USER_AGENT)
        .send()
        .await
        .map_err(|err| UsageRefreshFailure::Transient(err.to_string()))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|err| UsageRefreshFailure::Transient(err.to_string()))?;
    if matches!(status.as_u16(), 401 | 403) {
        return Err(UsageRefreshFailure::Dead(format!(
            "usage fetch returned status {}",
            status.as_u16()
        )));
    }
    if !status.is_success() {
        return Err(UsageRefreshFailure::Transient(format!(
            "usage fetch returned status {} body={}",
            status.as_u16(),
            String::from_utf8_lossy(&bytes)
        )));
    }

    serde_json::from_slice::<serde_json::Value>(&bytes)
        .map_err(|err| UsageRefreshFailure::Transient(err.to_string()))
}

fn parse_usage_snapshot(payload: &serde_json::Value) -> CredentialUsageSnapshot {
    CredentialUsageSnapshot {
        five_hour: parse_usage_bucket(payload, "five_hour"),
        seven_day: parse_usage_bucket(payload, "seven_day"),
        seven_day_sonnet: parse_usage_bucket(payload, "seven_day_sonnet"),
        last_error: None,
    }
}

fn parse_usage_bucket(payload: &serde_json::Value, key: &str) -> CredentialUsageBucket {
    let section = payload.get(key).and_then(|value| value.as_object());
    CredentialUsageBucket {
        utilization_pct: section
            .and_then(|value| value.get("utilization"))
            .and_then(|value| value.as_f64())
            .filter(|value| value.is_finite())
            .map(|value| value.round().clamp(0.0, 100.0) as u32),
        resets_at: section
            .and_then(|value| value.get("resets_at"))
            .and_then(|value| value.as_str())
            .map(|value| value.to_string()),
    }
}

fn derive_status_from_usage(
    snapshot: &CredentialUsageSnapshot,
    now_unix_ms: u64,
) -> (CredentialStatus, Option<u64>) {
    let five_hour_reset = parse_rfc3339_to_unix_ms(snapshot.five_hour.resets_at.as_deref());
    let all_reset = parse_rfc3339_to_unix_ms(snapshot.seven_day.resets_at.as_deref());
    let sonnet_reset = parse_rfc3339_to_unix_ms(snapshot.seven_day_sonnet.resets_at.as_deref());
    let five_hour_exhausted = snapshot.five_hour.utilization_pct.unwrap_or(0) >= 100;
    let all_exhausted = snapshot.seven_day.utilization_pct.unwrap_or(0) >= 100;
    let sonnet_exhausted = snapshot.seven_day_sonnet.utilization_pct.unwrap_or(0) >= 100;

    if all_exhausted && all_reset.is_some_and(|value| value > now_unix_ms) {
        return (CredentialStatus::Cooldown7d, all_reset);
    }
    if sonnet_exhausted && sonnet_reset.is_some_and(|value| value > now_unix_ms) {
        return (CredentialStatus::CooldownSonnet7d, sonnet_reset);
    }
    if five_hour_exhausted && five_hour_reset.is_some_and(|value| value > now_unix_ms) {
        return (CredentialStatus::Cooldown5h, five_hour_reset);
    }
    (CredentialStatus::Healthy, None)
}

fn merge_status_for_view(
    credential: &CredentialConfig,
    usage: &CredentialUsageSnapshot,
) -> (CredentialStatus, Option<u64>, Option<String>) {
    if credential.status == CredentialStatus::Dead {
        return (
            CredentialStatus::Dead,
            None,
            credential
                .last_error
                .clone()
                .or_else(|| usage.last_error.clone()),
        );
    }

    let (usage_status, usage_cooldown_until_unix_ms) = derive_status_from_usage(usage, now_unix_ms());
    let status = if matches!(
        usage_status,
        CredentialStatus::Cooldown5h | CredentialStatus::Cooldown7d | CredentialStatus::CooldownSonnet7d
    ) {
        usage_status
    } else {
        credential.status
    };
    let cooldown_until_unix_ms = usage_cooldown_until_unix_ms.or(credential.cooldown_until_unix_ms);
    let last_error = credential
        .last_error
        .clone()
        .or_else(|| usage.last_error.clone());
    (status, cooldown_until_unix_ms, last_error)
}

fn parse_rfc3339_to_unix_ms(value: Option<&str>) -> Option<u64> {
    value
        .and_then(|item| DateTime::parse_from_rfc3339(item).ok())
        .and_then(|item| u64::try_from(item.timestamp_millis()).ok())
}

fn derive_rate_limited_status_from_payload(
    payload: &serde_json::Value,
    now_unix_ms: u64,
) -> Option<(CredentialStatus, Option<u64>)> {
    let candidates = [
        ("seven_day", CredentialStatus::Cooldown7d),
        ("seven_day_sonnet", CredentialStatus::CooldownSonnet7d),
        ("five_hour", CredentialStatus::Cooldown5h),
    ];

    for (key, status) in candidates {
        let section = match payload.get(key).and_then(|value| value.as_object()) {
            Some(section) => section,
            None => continue,
        };
        let utilization = match section.get("utilization").and_then(|value| value.as_f64()) {
            Some(utilization) if utilization.is_finite() => utilization,
            _ => continue,
        };
        if utilization < 100.0 {
            continue;
        }
        let reset = parse_rfc3339_to_unix_ms(
            section.get("resets_at").and_then(|value| value.as_str()),
        );
        if reset.is_some_and(|value| value > now_unix_ms) {
            return Some((status, reset));
        }
    }
    None
}

fn generate_credential_id() -> String {
    let mut bytes = [0u8; 10];
    rand::fill(&mut bytes);
    let mut out = String::with_capacity(bytes.len() * 2 + 7);
    out.push_str("cred_");
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn next_order(credentials: &[CredentialConfig]) -> u32 {
    credentials
        .iter()
        .map(|item| item.order)
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

fn build_http_client(upstream: &UpstreamConfig) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().http1_only();

    if let Some(proxy) = upstream.proxy.as_deref() {
        let proxy = proxy.trim();
        if !proxy.is_empty() {
            builder = builder.proxy(
                reqwest::Proxy::all(proxy)
                    .map_err(|err| anyhow!("invalid proxy `{proxy}`: {err}"))?,
            );
        }
    }

    builder
        .build()
        .map_err(|err| anyhow!("build reqwest client: {err}"))
}

#[cfg(test)]
mod tests {
    use super::{build_http_client, derive_rate_limited_status_from_payload, derive_status_from_usage};
    use crate::config::{CredentialStatus, CredentialUsageBucket, CredentialUsageSnapshot, UpstreamConfig};
    use serde_json::json;

    #[test]
    fn build_http_client_accepts_http_proxy() {
        let upstream = UpstreamConfig {
            proxy: Some("http://127.0.0.1:8080".to_string()),
            ..UpstreamConfig::default()
        };
        build_http_client(&upstream).expect("http proxy client");
    }

    #[test]
    fn build_http_client_accepts_socks_proxy() {
        let upstream = UpstreamConfig {
            proxy: Some("socks5h://127.0.0.1:1080".to_string()),
            ..UpstreamConfig::default()
        };
        build_http_client(&upstream).expect("socks proxy client");
    }

    #[test]
    fn derive_status_from_usage_marks_sonnet_cooldown() {
        let usage = CredentialUsageSnapshot {
            seven_day_sonnet: CredentialUsageBucket {
                utilization_pct: Some(100),
                resets_at: Some("2099-01-01T00:00:00Z".to_string()),
            },
            ..CredentialUsageSnapshot::default()
        };
        let (status, _) = derive_status_from_usage(&usage, 0);
        assert_eq!(status, CredentialStatus::CooldownSonnet7d);
    }

    #[test]
    fn derive_status_from_usage_marks_full_cooldown() {
        let usage = CredentialUsageSnapshot {
            seven_day: CredentialUsageBucket {
                utilization_pct: Some(100),
                resets_at: Some("2099-01-01T00:00:00Z".to_string()),
            },
            ..CredentialUsageSnapshot::default()
        };
        let (status, _) = derive_status_from_usage(&usage, 0);
        assert_eq!(status, CredentialStatus::Cooldown7d);
    }

    #[test]
    fn derive_status_from_usage_marks_five_hour_cooldown() {
        let usage = CredentialUsageSnapshot {
            five_hour: CredentialUsageBucket {
                utilization_pct: Some(100),
                resets_at: Some("2099-01-01T00:00:00Z".to_string()),
            },
            ..CredentialUsageSnapshot::default()
        };
        let (status, _) = derive_status_from_usage(&usage, 0);
        assert_eq!(status, CredentialStatus::Cooldown5h);
    }

    #[test]
    fn derive_rate_limited_status_prefers_seven_day_then_sonnet_then_five_hour() {
        let payload = json!({
            "five_hour": { "utilization": 100.0, "resets_at": "2099-01-01T00:00:00Z" },
            "seven_day": { "utilization": 100.0, "resets_at": "2099-01-01T00:00:00Z" },
            "seven_day_sonnet": { "utilization": 100.0, "resets_at": "2099-01-01T00:00:00Z" }
        });
        let (status, _) = derive_rate_limited_status_from_payload(&payload, 0).expect("status");
        assert_eq!(status, CredentialStatus::Cooldown7d);
    }
}
