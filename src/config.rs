use serde::{Deserialize, Serialize};

pub const STORAGE_KEY: &str = "state";
pub const DEFAULT_REQUIRED_BETA: &str = "oauth-2025-04-20";
pub const DEFAULT_CONTEXT_1M_BETA: &str = "context-1m-2025-08-07";
pub const DEFAULT_ANTHROPIC_VERSION: &str = "2023-06-01";
pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
pub const DEFAULT_CLAUDE_AI_BASE_URL: &str = "https://claude.ai";
pub const DEFAULT_REDIRECT_URI: &str = "https://platform.claude.com/oauth/code/callback";
pub const DEFAULT_USER_AGENT: &str = "claude-code/2.1.76";
pub const DEFAULT_TOKEN_USER_AGENT: &str = "claude-cli/2.1.76 (external, cli)";
pub const CLAUDE_CODE_BILLING_HEADER_PREFIX: &str = "x-anthropic-billing-header:";
pub const CLAUDE_CODE_BILLING_ENTRYPOINT: &str = "cli";
pub const CLAUDE_CODE_BILLING_SALT: &str = "59cf53e54c78";
pub const CLAUDE_CODE_BILLING_CCH: &str = "00000";
pub const MAGIC_TRIGGER_AUTO_ID: &str =
    "GPROXY_MAGIC_STRING_TRIGGER_CACHING_CREATE_7D9ASD7A98SD7A9S8D79ASC98A7FNKJBVV80SCMSHDSIUCH";
pub const MAGIC_TRIGGER_5M_ID: &str =
    "GPROXY_MAGIC_STRING_TRIGGER_CACHING_CREATE_49VA1S5V19GR4G89W2V695G9W9GV52W95V198WV5W2FC9DF";
pub const MAGIC_TRIGGER_1H_ID: &str =
    "GPROXY_MAGIC_STRING_TRIGGER_CACHING_CREATE_1FAS5GV9R5H29T5Y2J9584K6O95M2NBVW52C95CX984FRJY";
pub const CLAUDE_CODE_OAUTH_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
pub const CLAUDE_CODE_OAUTH_SCOPE: &str = "user:profile user:inference user:sessions:claude_code";
pub const OAUTH_STATE_TTL_MS: u64 = 10 * 60 * 1000;
pub const FIVE_HOUR_WINDOW_MS: u64 = 5 * 60 * 60 * 1000;
pub const SEVEN_DAY_WINDOW_MS: u64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DurableStateDoc {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub credentials: Vec<CredentialConfig>,
    #[serde(default)]
    pub oauth_states: Vec<StoredOAuthState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredOAuthState {
    #[serde(default)]
    pub channel: ChannelKind,
    pub state_id: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub created_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfig {
    pub id: String,
    #[serde(default)]
    pub channel: ChannelKind,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub order: u32,
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub expires_at_unix_ms: u64,
    #[serde(default = "default_enabled")]
    pub enable_sonnet_1m: bool,
    #[serde(default = "default_enabled")]
    pub enable_opus_1m: bool,
    #[serde(default)]
    pub user_email: Option<String>,
    #[serde(default)]
    pub account_uuid: Option<String>,
    #[serde(default)]
    pub organization_uuid: Option<String>,
    #[serde(default)]
    pub subscription_type: Option<String>,
    #[serde(default)]
    pub rate_limit_tier: Option<String>,
    #[serde(default)]
    pub status: CredentialStatus,
    #[serde(default)]
    pub cooldown_until_unix_ms: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_used_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    #[default]
    ClaudeCode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    #[default]
    Healthy,
    Cooldown5h,
    Cooldown7d,
    Dead,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialUsageSnapshot {
    #[serde(default)]
    pub five_hour: CredentialUsageBucket,
    #[serde(default)]
    pub seven_day: CredentialUsageBucket,
    #[serde(default)]
    pub seven_day_sonnet: CredentialUsageBucket,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialUsageBucket {
    #[serde(default)]
    pub utilization_pct: Option<u32>,
    #[serde(default)]
    pub resets_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageCredentialView {
    pub id: String,
    pub user_email: Option<String>,
    pub enabled: bool,
    pub order: u32,
    pub status: CredentialStatus,
    pub cooldown_until_unix_ms: Option<u64>,
    pub last_error: Option<String>,
    pub last_used_at_unix_ms: Option<u64>,
    pub usage: CredentialUsageSnapshot,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CredentialUpsertInput {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub order: Option<u32>,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub enable_sonnet_1m: Option<bool>,
    #[serde(default)]
    pub enable_opus_1m: Option<bool>,
    #[serde(default)]
    pub user_email: Option<String>,
    #[serde(default)]
    pub account_uuid: Option<String>,
    #[serde(default)]
    pub organization_uuid: Option<String>,
    #[serde(default)]
    pub subscription_type: Option<String>,
    #[serde(default)]
    pub rate_limit_tier: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialJsonView {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at_unix_ms: u64,
    pub enable_sonnet_1m: bool,
    pub enable_opus_1m: bool,
    pub user_email: Option<String>,
    pub account_uuid: Option<String>,
    pub organization_uuid: Option<String>,
    pub subscription_type: Option<String>,
    pub rate_limit_tier: Option<String>,
    pub status: CredentialStatus,
}

pub fn default_schema_version() -> u32 {
    1
}

pub fn default_enabled() -> bool {
    true
}

pub fn clean_opt_owned(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

impl DurableStateDoc {
    pub fn normalize(&mut self, now: u64) {
        self.credentials.sort_by_key(|item| item.order);
        for credential in &mut self.credentials {
            credential.access_token = credential.access_token.trim().to_string();
            credential.refresh_token = credential.refresh_token.trim().to_string();
            credential.user_email = clean_opt_owned(credential.user_email.take());
            credential.account_uuid = clean_opt_owned(credential.account_uuid.take());
            credential.organization_uuid = clean_opt_owned(credential.organization_uuid.take());
            credential.subscription_type = clean_opt_owned(credential.subscription_type.take());
            credential.rate_limit_tier = clean_opt_owned(credential.rate_limit_tier.take());
            credential.last_error = clean_opt_owned(credential.last_error.take());
            if matches!(
                credential.status,
                CredentialStatus::Cooldown5h | CredentialStatus::Cooldown7d
            ) && credential
                .cooldown_until_unix_ms
                .is_some_and(|until| until <= now)
            {
                credential.status = CredentialStatus::Healthy;
                credential.cooldown_until_unix_ms = None;
            }
        }
        self.oauth_states
            .retain(|item| now.saturating_sub(item.created_at_unix_ms) <= OAUTH_STATE_TTL_MS);
    }
}

impl CredentialConfig {
    pub fn json_view(&self) -> CredentialJsonView {
        CredentialJsonView {
            access_token: self.access_token.clone(),
            refresh_token: self.refresh_token.clone(),
            expires_at_unix_ms: self.expires_at_unix_ms,
            enable_sonnet_1m: self.enable_sonnet_1m,
            enable_opus_1m: self.enable_opus_1m,
            user_email: self.user_email.clone(),
            account_uuid: self.account_uuid.clone(),
            organization_uuid: self.organization_uuid.clone(),
            subscription_type: self.subscription_type.clone(),
            rate_limit_tier: self.rate_limit_tier.clone(),
            status: self.status,
        }
    }
}
