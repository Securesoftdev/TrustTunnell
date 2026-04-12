use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const DEFAULT_SYNC_PATH_TEMPLATE: &str = "/internal/trusttunnel/v1/nodes/{externalNodeId}/sync";
pub const DEFAULT_SYNC_REPORT_PATH: &str = "/internal/trusttunnel/v1/nodes/sync-report";
pub const DEFAULT_HEARTBEAT_PATH: &str = "/internal/trusttunnel/v1/nodes/heartbeat";
pub const DEFAULT_REGISTER_PATH: &str = "/internal/trusttunnel/v1/nodes/register";

#[derive(Clone)]
pub struct LkApiClient {
    client: reqwest::Client,
    base_url: String,
    service_token: String,
    register_path: String,
    heartbeat_path: String,
    sync_report_path: String,
    sync_path_template: String,
}

impl LkApiClient {
    pub fn new(
        client: reqwest::Client,
        base_url: String,
        service_token: String,
        register_path: String,
        heartbeat_path: String,
        sync_report_path: String,
        sync_path_template: String,
    ) -> Self {
        Self {
            client,
            base_url,
            service_token,
            register_path,
            heartbeat_path,
            sync_report_path,
            sync_path_template,
        }
    }

    pub async fn register(
        &self,
        payload: &OnboardingPayload<'_>,
    ) -> Result<reqwest::Response, String> {
        self.client
            .post(self.endpoint(&self.register_path))
            .header("Authorization", format!("Bearer {}", self.service_token))
            .header("X-Internal-Agent-Token", &self.service_token)
            .json(payload)
            .send()
            .await
            .map_err(|e| format!("register request failed: {e}"))
    }

    pub async fn heartbeat(&self, payload: &HeartbeatPayload<'_>) -> Result<(), HeartbeatError> {
        let response = self
            .client
            .post(self.endpoint(&self.heartbeat_path))
            .header("Authorization", format!("Bearer {}", self.service_token))
            .header("X-Internal-Agent-Token", &self.service_token)
            .json(payload)
            .send()
            .await
            .map_err(|e| HeartbeatError::Network(format!("heartbeat push failed: {e}")))?;

        if response.status().is_success() {
            return Ok(());
        }

        let status = response.status();
        if status.is_server_error() {
            return Err(HeartbeatError::ServerHttp(status));
        }
        if status.is_client_error() {
            return Err(HeartbeatError::ClientHttp(status));
        }

        Err(HeartbeatError::UnexpectedStatus(status))
    }

    pub async fn sync(&self, external_node_id: &str) -> Result<(SyncPayload, Vec<u8>), String> {
        let path = self
            .sync_path_template
            .replace("{externalNodeId}", external_node_id);
        let response = self
            .client
            .get(self.endpoint(&path))
            .header("Authorization", format!("Bearer {}", self.service_token))
            .header("X-Internal-Agent-Token", &self.service_token)
            .send()
            .await
            .map_err(|e| format!("LK snapshot request failed: {e}"))?;

        if response.status() != StatusCode::OK {
            return Err(format!(
                "LK snapshot request returned HTTP {}",
                response.status()
            ));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| format!("failed to read LK snapshot response: {e}"))?;
        let parsed = serde_json::from_slice::<SyncPayload>(&bytes)
            .map_err(|e| format!("failed to parse LK snapshot JSON: {e}"))?;
        parsed.validate_compatibility()?;

        Ok((parsed, bytes.to_vec()))
    }

    pub async fn sync_report(&self, payload: &SyncReportPayload<'_>) -> Result<(), String> {
        let response = self
            .client
            .post(self.endpoint(&self.sync_report_path))
            .header("Authorization", format!("Bearer {}", self.service_token))
            .header("X-Internal-Agent-Token", &self.service_token)
            .json(payload)
            .send()
            .await
            .map_err(|e| format!("sync-report push failed: {e}"))?;

        if response.status().is_success() {
            return Ok(());
        }

        Err(format!(
            "sync-report push failed with HTTP {}",
            response.status()
        ))
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.base_url.trim_end_matches('/'), path)
    }
}

#[derive(Clone)]
pub struct NodeMetadata {
    pub node_external_id: String,
    pub node_hostname: String,
    pub node_stage: String,
    pub node_cluster: String,
    pub node_namespace: String,
    pub node_rollout_group: String,
    pub node_public_host: Option<String>,
    pub node_public_port: Option<u16>,
    pub node_display_name: Option<String>,
    pub trusttunnel_runtime_dir: String,
    pub trusttunnel_credentials_file: String,
    pub trusttunnel_config_file: String,
    pub trusttunnel_hosts_file: String,
}

#[derive(Debug, Deserialize)]
pub struct SyncPayload {
    #[serde(alias = "snapshotVersion")]
    pub version: String,
    pub checksum: String,
    #[serde(default, alias = "onboardingState")]
    pub onboarding_state: String,
    #[serde(default = "default_sync_required", alias = "syncRequired")]
    pub sync_required: bool,
    #[serde(default, alias = "users")]
    pub accounts: Vec<Account>,
}

impl SyncPayload {
    pub fn validate_compatibility(&self) -> Result<(), String> {
        if self.version.trim().is_empty() {
            return Err("sync payload compatibility check failed: version is empty".to_string());
        }
        if self.checksum.trim().is_empty() {
            return Err("sync payload compatibility check failed: checksum is empty".to_string());
        }
        for account in &self.accounts {
            if account.username.trim().is_empty() {
                return Err(
                    "sync payload compatibility check failed: account username is empty"
                        .to_string(),
                );
            }
            if account.password.trim().is_empty() {
                return Err(
                    "sync payload compatibility check failed: account password is empty"
                        .to_string(),
                );
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Account {
    #[serde(alias = "user", alias = "login", alias = "name")]
    pub username: String,
    #[serde(alias = "token", alias = "credentials", alias = "secret")]
    pub password: String,
    #[serde(default = "default_enabled", alias = "isEnabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

fn default_sync_required() -> bool {
    true
}

#[derive(Serialize, Deserialize)]
pub struct OnboardingPayload<'a> {
    #[serde(rename = "node_external_id", alias = "externalNodeId")]
    pub node_external_id: &'a str,
    #[serde(rename = "node_hostname", alias = "nodeHostname")]
    pub node_hostname: &'a str,
    #[serde(rename = "node_stage", alias = "nodeStage")]
    pub node_stage: &'a str,
    #[serde(rename = "node_cluster", alias = "nodeCluster")]
    pub node_cluster: &'a str,
    #[serde(rename = "node_namespace", alias = "nodeNamespace")]
    pub node_namespace: &'a str,
    #[serde(rename = "node_rollout_group", alias = "nodeRolloutGroup")]
    pub node_rollout_group: &'a str,
    #[serde(rename = "node_public_host", alias = "publicHost")]
    pub node_public_host: Option<&'a str>,
    #[serde(rename = "node_public_port", alias = "publicPort")]
    pub node_public_port: Option<u16>,
    #[serde(rename = "node_display_name", alias = "displayName")]
    pub node_display_name: Option<&'a str>,
    pub trusttunnel_runtime_dir: &'a str,
    pub trusttunnel_credentials_file: &'a str,
    pub trusttunnel_config_file: &'a str,
    pub trusttunnel_hosts_file: &'a str,
    pub active_path: &'static str,
    pub modified_enabled: bool,
}

#[derive(Serialize)]
pub struct HeartbeatPayload<'a> {
    #[serde(flatten)]
    pub onboarding: OnboardingPayload<'a>,
    pub external_node_id: &'a str,
    pub current_revision: &'a str,
    pub health_status: &'a str,
    pub agent_version: &'a str,
    pub runtime_version: &'a str,
    pub active_clients: u64,
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub last_apply_status: &'a str,
    pub timestamp: String,
}

impl<'a> OnboardingPayload<'a> {
    pub fn from_metadata(metadata: &'a NodeMetadata) -> Self {
        Self {
            node_external_id: &metadata.node_external_id,
            node_hostname: &metadata.node_hostname,
            node_stage: &metadata.node_stage,
            node_cluster: &metadata.node_cluster,
            node_namespace: &metadata.node_namespace,
            node_rollout_group: &metadata.node_rollout_group,
            node_public_host: metadata.node_public_host.as_deref(),
            node_public_port: metadata.node_public_port,
            node_display_name: metadata.node_display_name.as_deref(),
            trusttunnel_runtime_dir: &metadata.trusttunnel_runtime_dir,
            trusttunnel_credentials_file: &metadata.trusttunnel_credentials_file,
            trusttunnel_config_file: &metadata.trusttunnel_config_file,
            trusttunnel_hosts_file: &metadata.trusttunnel_hosts_file,
            active_path: "classic",
            modified_enabled: false,
        }
    }

    pub fn validate_compatibility(&self) -> Result<(), String> {
        if self.node_external_id.trim().is_empty() {
            return Err(
                "onboarding payload compatibility check failed: node_external_id is empty"
                    .to_string(),
            );
        }
        if self.node_hostname.trim().is_empty() {
            return Err(
                "onboarding payload compatibility check failed: node_hostname is empty"
                    .to_string(),
            );
        }
        if self.node_stage.trim().is_empty() {
            return Err(
                "onboarding payload compatibility check failed: node_stage is empty".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum HeartbeatError {
    Network(String),
    ClientHttp(StatusCode),
    ServerHttp(StatusCode),
    UnexpectedStatus(StatusCode),
}

impl HeartbeatError {
    pub fn kind(&self) -> &'static str {
        match self {
            HeartbeatError::Network(_) => "network",
            HeartbeatError::ClientHttp(_) => "http_client",
            HeartbeatError::ServerHttp(_) => "http_server",
            HeartbeatError::UnexpectedStatus(_) => "http_unexpected",
        }
    }
}

impl fmt::Display for HeartbeatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeartbeatError::Network(msg) => write!(f, "{msg}"),
            HeartbeatError::ClientHttp(status) => {
                write!(f, "heartbeat push failed with client HTTP {status}")
            }
            HeartbeatError::ServerHttp(status) => {
                write!(f, "heartbeat push failed with server HTTP {status}")
            }
            HeartbeatError::UnexpectedStatus(status) => {
                write!(f, "heartbeat push failed with unexpected HTTP {status}")
            }
        }
    }
}

#[derive(Serialize)]
pub struct SyncReportPayload<'a> {
    #[serde(flatten)]
    pub onboarding: OnboardingPayload<'a>,
    pub version: &'a str,
    pub checksum: &'a str,
    pub applied: bool,
    pub details: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_deserializes_legacy_fields() {
        let raw = r#"{"user":"alice","token":"pwd"}"#;
        let account = serde_json::from_str::<Account>(raw).unwrap();

        assert_eq!(account.username, "alice");
        assert_eq!(account.password, "pwd");
        assert!(account.enabled);
    }

    #[test]
    fn sync_payload_rejects_empty_compat_fields() {
        let payload = SyncPayload {
            version: "".to_string(),
            checksum: "abc".to_string(),
            onboarding_state: "active".to_string(),
            sync_required: true,
            accounts: vec![],
        };

        assert!(payload.validate_compatibility().is_err());
    }

    #[test]
    fn sync_payload_deserializes_sync_branching_fields() {
        let raw = r#"{
            "version":"v1",
            "checksum":"abc",
            "onboardingState":"paused",
            "syncRequired":false,
            "accounts":[]
        }"#;
        let payload = serde_json::from_str::<SyncPayload>(raw).unwrap();

        assert_eq!(payload.onboarding_state, "paused");
        assert!(!payload.sync_required);
    }

    #[test]
    fn onboarding_payload_rejects_empty_compat_fields() {
        let metadata = NodeMetadata {
            node_external_id: "".to_string(),
            node_hostname: "node-1".to_string(),
            node_stage: "prod".to_string(),
            node_cluster: "c1".to_string(),
            node_namespace: "ns".to_string(),
            node_rollout_group: "r1".to_string(),
            node_public_host: None,
            node_public_port: None,
            node_display_name: None,
            trusttunnel_runtime_dir: "/tmp".to_string(),
            trusttunnel_credentials_file: "credentials.toml".to_string(),
            trusttunnel_config_file: "vpn.toml".to_string(),
            trusttunnel_hosts_file: "hosts.toml".to_string(),
        };

        let payload = OnboardingPayload::from_metadata(&metadata);
        assert!(payload.validate_compatibility().is_err());
    }
}
