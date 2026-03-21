use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::fs;

use crate::config::{ConfigFile, CredentialConfig};

pub async fn load_or_create_config(path: &Path, admin_token: String) -> Result<ConfigFile> {
    if path.exists() {
        let text = fs::read_to_string(path)
            .await
            .with_context(|| format!("read config {}", path.display()))?;
        let mut config = toml::from_str::<ConfigFile>(&text)
            .with_context(|| format!("parse config {}", path.display()))?;
        let mut should_save = false;
        let should_strip_runtime_usage = text.contains("[credentials.usage");
        if config.server.admin_token.trim().is_empty() {
            config.server.admin_token = admin_token;
            should_save = true;
        }
        config.normalize();
        if should_save || should_strip_runtime_usage {
            save_config(path, &config).await?;
        }
        return Ok(config);
    }

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create config directory {}", parent.display()))?;
    }

    let mut config = ConfigFile::default();
    config.server.admin_token = admin_token;
    config.normalize();
    save_config(path, &config).await?;
    Ok(config)
}

pub async fn save_config(path: &Path, config: &ConfigFile) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create config directory {}", parent.display()))?;
    }

    let tmp_path = path.with_extension("toml.tmp");
    let text = toml::to_string_pretty(&PersistedConfigFile::from_config(config))
        .context("serialize config")?;
    fs::write(&tmp_path, text)
        .await
        .with_context(|| format!("write temp config {}", tmp_path.display()))?;
    fs::rename(&tmp_path, path)
        .await
        .with_context(|| format!("rename temp config to {}", path.display()))?;
    Ok(())
}

#[derive(Serialize)]
struct PersistedConfigFile {
    server: PersistedServerConfig,
    #[serde(skip_serializing_if = "PersistedUpstreamConfig::is_empty")]
    upstream: PersistedUpstreamConfig,
    credentials: Vec<PersistedCredentialConfig>,
}

impl PersistedConfigFile {
    fn from_config(config: &ConfigFile) -> Self {
        Self {
            server: PersistedServerConfig {
                host: config.server.host.clone(),
                port: config.server.port,
                admin_token: config.server.admin_token.clone(),
            },
            upstream: PersistedUpstreamConfig {
                proxy: config.upstream.proxy.clone(),
            },
            credentials: config
                .credentials
                .iter()
                .cloned()
                .map(PersistedCredentialConfig::from)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct PersistedCredentialConfig {
    id: String,
    enabled: bool,
    order: u32,
    access_token: String,
    refresh_token: String,
    expires_at_unix_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subscription_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_limit_tier: Option<String>,
    status: crate::config::CredentialStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    cooldown_until_unix_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_used_at_unix_ms: Option<u64>,
}

impl From<CredentialConfig> for PersistedCredentialConfig {
    fn from(value: CredentialConfig) -> Self {
        Self {
            id: value.id,
            enabled: value.enabled,
            order: value.order,
            access_token: value.access_token,
            refresh_token: value.refresh_token,
            expires_at_unix_ms: value.expires_at_unix_ms,
            user_email: value.user_email,
            organization_uuid: value.organization_uuid,
            subscription_type: value.subscription_type,
            rate_limit_tier: value.rate_limit_tier,
            status: value.status,
            cooldown_until_unix_ms: value.cooldown_until_unix_ms,
            last_error: value.last_error,
            last_used_at_unix_ms: value.last_used_at_unix_ms,
        }
    }
}

#[derive(Serialize)]
struct PersistedServerConfig {
    host: String,
    port: u16,
    admin_token: String,
}

#[derive(Serialize)]
struct PersistedUpstreamConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    proxy: Option<String>,
}

impl PersistedUpstreamConfig {
    fn is_empty(&self) -> bool {
        self.proxy.is_none()
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::save_config;
    use crate::config::{
        ConfigFile, CredentialConfig, CredentialStatus, ServerConfig, UpstreamConfig,
    };

    #[tokio::test]
    async fn save_config_does_not_persist_usage() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("sgproxy.toml");
        let config = ConfigFile {
            server: ServerConfig {
                admin_token: "admin".to_string(),
                ..ServerConfig::default()
            },
            upstream: UpstreamConfig::default(),
            credentials: vec![CredentialConfig {
                id: "cred_1".to_string(),
                enabled: true,
                order: 0,
                access_token: "access".to_string(),
                refresh_token: "refresh".to_string(),
                expires_at_unix_ms: 1,
                user_email: Some("dev@example.com".to_string()),
                organization_uuid: None,
                subscription_type: None,
                rate_limit_tier: None,
                status: CredentialStatus::Healthy,
                cooldown_until_unix_ms: None,
                last_error: None,
                last_used_at_unix_ms: None,
            }],
        };

        save_config(&path, &config).await.expect("save config");
        let text = tokio::fs::read_to_string(path).await.expect("read config");

        assert!(!text.contains("[credentials.usage]"));
        assert!(!text.contains("raw_json"));
        assert!(!text.contains("utilization_pct"));
    }
}
