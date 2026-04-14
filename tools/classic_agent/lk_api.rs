use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
    ) -> Result<reqwest::Response, RegisterRequestError> {
        let endpoint = self.endpoint(&self.register_path);
        let payload_value = serde_json::to_value(payload)
            .map_err(|e| RegisterRequestError::Network(format!("register payload serialization failed: {e}")))?;
        self.client
            .post(endpoint)
            .header("Authorization", format!("Bearer {}", self.service_token))
            .header("X-Internal-Agent-Token", &self.service_token)
            .json(payload)
            .send()
            .await
            .map_err(|e| {
                RegisterRequestError::Network(format!(
                    "register request failed: {e}; payload_keys={}",
                    payload_top_level_keys(&payload_value)
                ))
            })
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
    pub node_public_ip: Option<String>,
    pub node_public_port: Option<u16>,
    pub node_sni: Option<String>,
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

#[derive(Serialize)]
pub struct OnboardingPayload<'a> {
    pub contract_version: &'static str,
    pub hostname: &'a str,
    pub agent_version: &'a str,
    pub runtime_version: &'a str,
    pub node_identity: NodeIdentityPayload<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusttunnel_runtime_dir: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusttunnel_credentials_file: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusttunnel_config_file: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusttunnel_hosts_file: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_path: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_enabled: Option<bool>,
}

#[derive(Serialize)]
pub struct NodeIdentityPayload<'a> {
    pub external_id: &'a str,
    pub stage: &'a str,
    pub cluster: &'a str,
    pub namespace: &'a str,
    pub rollout_group: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<&'a str>,
}

#[derive(Serialize)]
pub struct HeartbeatPayload<'a> {
    #[serde(flatten)]
    pub onboarding: OnboardingPayload<'a>,
    pub external_node_id: &'a str,
    pub current_revision: &'a str,
    pub health_status: &'a str,
    pub active_clients: u64,
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub last_apply_status: &'a str,
    pub timestamp: String,
}

impl<'a> OnboardingPayload<'a> {
    pub fn from_metadata(
        metadata: &'a NodeMetadata,
        agent_version: &'a str,
        runtime_version: &'a str,
    ) -> Self {
        Self {
            contract_version: "v1",
            hostname: &metadata.node_hostname,
            agent_version,
            runtime_version,
            node_identity: NodeIdentityPayload {
                external_id: &metadata.node_external_id,
                stage: &metadata.node_stage,
                cluster: &metadata.node_cluster,
                namespace: &metadata.node_namespace,
                rollout_group: &metadata.node_rollout_group,
                public_ip: metadata.node_public_ip.as_deref(),
                public_port: metadata.node_public_port,
                sni: metadata.node_sni.as_deref(),
            },
            trusttunnel_runtime_dir: Some(&metadata.trusttunnel_runtime_dir),
            trusttunnel_credentials_file: Some(&metadata.trusttunnel_credentials_file),
            trusttunnel_config_file: Some(&metadata.trusttunnel_config_file),
            trusttunnel_hosts_file: Some(&metadata.trusttunnel_hosts_file),
            active_path: Some("classic"),
            modified_enabled: Some(false),
        }
    }

    pub fn validate_compatibility(&self) -> Result<(), String> {
        if self.contract_version != "v1" {
            return Err(
                "onboarding payload compatibility check failed: contract_version must be v1"
                    .to_string(),
            );
        }
        if self.node_identity.external_id.trim().is_empty() {
            return Err(
                "onboarding payload compatibility check failed: node_external_id is empty"
                    .to_string(),
            );
        }
        if self.hostname.trim().is_empty() {
            return Err(
                "onboarding payload compatibility check failed: hostname is empty"
                    .to_string(),
            );
        }
        if self.agent_version.trim().is_empty() {
            return Err(
                "onboarding payload compatibility check failed: agent_version is empty"
                    .to_string(),
            );
        }
        if self.runtime_version.trim().is_empty() {
            return Err(
                "onboarding payload compatibility check failed: runtime_version is empty"
                    .to_string(),
            );
        }
        if self.node_identity.stage.trim().is_empty() {
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

#[derive(Debug)]
pub enum RegisterRequestError {
    Network(String),
}

impl fmt::Display for RegisterRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegisterRequestError::Network(msg) => write!(f, "{msg}"),
        }
    }
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

pub fn payload_top_level_keys(payload: &Value) -> String {
    let mut keys = payload
        .as_object()
        .map(|obj| obj.keys().cloned().collect::<Vec<String>>())
        .unwrap_or_default();
    keys.sort();
    keys.join(",")
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
            node_public_ip: None,
            node_public_port: None,
            node_sni: None,
            trusttunnel_runtime_dir: "/tmp".to_string(),
            trusttunnel_credentials_file: "credentials.toml".to_string(),
            trusttunnel_config_file: "vpn.toml".to_string(),
            trusttunnel_hosts_file: "hosts.toml".to_string(),
        };

        let payload = OnboardingPayload::from_metadata(&metadata, "1.2.3", "runtime-1");
        assert!(payload.validate_compatibility().is_err());
    }

    #[test]
    fn onboarding_payload_serializes_canonical_v1_shape() {
        let metadata = NodeMetadata {
            node_external_id: "ext-1".to_string(),
            node_hostname: "node-1".to_string(),
            node_stage: "prod".to_string(),
            node_cluster: "cluster-a".to_string(),
            node_namespace: "edge".to_string(),
            node_rollout_group: "blue".to_string(),
            node_public_ip: Some("203.0.113.10".to_string()),
            node_public_port: Some(443),
            node_sni: Some("vpn.example.com".to_string()),
            trusttunnel_runtime_dir: "/var/lib/trusttunnel".to_string(),
            trusttunnel_credentials_file: "credentials.toml".to_string(),
            trusttunnel_config_file: "vpn.toml".to_string(),
            trusttunnel_hosts_file: "hosts.toml".to_string(),
        };

        let payload = OnboardingPayload::from_metadata(&metadata, "2.0.0", "runtime-2");
        let value = serde_json::to_value(payload).unwrap();

        assert_eq!(value["contract_version"], "v1");
        assert_eq!(value["hostname"], "node-1");
        assert_eq!(value["agent_version"], "2.0.0");
        assert_eq!(value["runtime_version"], "runtime-2");
        assert_eq!(value["node_identity"]["external_id"], "ext-1");
        assert_eq!(value["node_identity"]["public_ip"], "203.0.113.10");
        assert!(value.get("node_external_id").is_none());
    }
}
