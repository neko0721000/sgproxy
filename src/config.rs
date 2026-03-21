use serde::{Deserialize, Serialize};

pub const DEFAULT_CONFIG_PATH: &str = "./sgproxy.toml";
pub const DEFAULT_REQUIRED_BETA: &str = "oauth-2025-04-20";
pub const DEFAULT_ANTHROPIC_VERSION: &str = "2023-06-01";
pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
pub const DEFAULT_CLAUDE_AI_BASE_URL: &str = "https://claude.ai";
pub const DEFAULT_REDIRECT_URI: &str = "https://platform.claude.com/oauth/code/callback";
pub const DEFAULT_USER_AGENT: &str = "claude-code/2.1.76";
pub const CLAUDE_CODE_OAUTH_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
pub const CLAUDE_CODE_OAUTH_SCOPE: &str = "user:profile user:inference user:sessions:claude_code";
pub const OAUTH_STATE_TTL_MS: u64 = 600_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFile {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub credentials: Vec<CredentialConfig>,
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            upstream: UpstreamConfig::default(),
            credentials: Vec::new(),
        }
    }
}

impl ConfigFile {
    pub fn normalize(&mut self) {
        self.upstream.proxy = clean_opt_owned(self.upstream.proxy.take());
        self.credentials.sort_by_key(|item| item.order);
        for credential in &mut self.credentials {
            credential.access_token = credential.access_token.trim().to_string();
            credential.refresh_token = credential.refresh_token.trim().to_string();
            credential.user_email = clean_opt_owned(credential.user_email.take());
            credential.organization_uuid = clean_opt_owned(credential.organization_uuid.take());
            credential.subscription_type = clean_opt_owned(credential.subscription_type.take());
            credential.rate_limit_tier = clean_opt_owned(credential.rate_limit_tier.take());
            credential.last_error = clean_opt_owned(credential.last_error.take());
        }
        if self.upstream.required_beta.is_empty() {
            self.upstream.required_beta = vec![DEFAULT_REQUIRED_BETA.to_string()];
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub admin_token: String,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            admin_token: String::new(),
            max_body_bytes: default_max_body_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default = "default_claude_ai_base_url")]
    pub claude_ai_base_url: String,
    #[serde(default, alias = "http_proxy", alias = "socks_proxy")]
    pub proxy: Option<String>,
    #[serde(default = "default_anthropic_version")]
    pub anthropic_version: String,
    #[serde(default = "default_required_beta")]
    pub required_beta: Vec<String>,
    #[serde(default = "default_user_agent")]
    pub default_user_agent: String,
    #[serde(default = "default_rate_limit_cooldown_secs")]
    pub rate_limit_cooldown_secs: u64,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            base_url: default_base_url(),
            claude_ai_base_url: default_claude_ai_base_url(),
            proxy: None,
            anthropic_version: default_anthropic_version(),
            required_beta: default_required_beta(),
            default_user_agent: default_user_agent(),
            rate_limit_cooldown_secs: default_rate_limit_cooldown_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfig {
    pub id: String,
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
    #[serde(default)]
    pub user_email: Option<String>,
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
pub enum CredentialStatus {
    #[default]
    Healthy,
    Cooldown5h,
    CooldownSonnet7d,
    #[serde(alias = "cooldown_all_7d")]
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

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
pub struct AdminConfigView {
    pub host: String,
    pub port: u16,
    pub proxy: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateConfigInput {
    pub host: String,
    pub port: u16,
    pub proxy: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CredentialUpsertInput {
    pub id: Option<String>,
    pub enabled: Option<bool>,
    pub order: Option<u32>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at_unix_ms: Option<u64>,
    pub user_email: Option<String>,
    pub organization_uuid: Option<String>,
    pub subscription_type: Option<String>,
    pub rate_limit_tier: Option<String>,
}

pub fn default_host() -> String {
    "127.0.0.1".to_string()
}

pub const fn default_port() -> u16 {
    8787
}

pub const fn default_max_body_bytes() -> usize {
    50 * 1024 * 1024
}

pub fn default_base_url() -> String {
    DEFAULT_BASE_URL.to_string()
}

pub fn default_claude_ai_base_url() -> String {
    DEFAULT_CLAUDE_AI_BASE_URL.to_string()
}

pub fn default_anthropic_version() -> String {
    DEFAULT_ANTHROPIC_VERSION.to_string()
}

pub fn default_required_beta() -> Vec<String> {
    vec![DEFAULT_REQUIRED_BETA.to_string()]
}

pub fn default_user_agent() -> String {
    DEFAULT_USER_AGENT.to_string()
}

pub const fn default_rate_limit_cooldown_secs() -> u64 {
    300
}

pub const fn default_enabled() -> bool {
    true
}

pub fn clean_opt_owned(value: Option<String>) -> Option<String> {
    value.and_then(|item| {
        let trimmed = item.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}
