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

    pub async fn sync(&self, external_node_id: &str) -> Result<SyncResponse, String> {
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

        if response.status() == StatusCode::CONFLICT {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unavailable>".to_string());
            return Ok(SyncResponse::Conflict { details: body });
        }

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

        Ok(SyncResponse::Snapshot((parsed, bytes.to_vec())))
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
    pub node_stage: Option<String>,
    pub node_cluster: Option<String>,
    pub node_namespace: Option<String>,
    pub node_rollout_group: Option<String>,
}

#[derive(Debug)]
pub enum SyncResponse {
    Snapshot((SyncPayload, Vec<u8>)),
    Conflict { details: String },
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
    #[serde(default, alias = "accountId", alias = "credentialId")]
    pub external_account_id: Option<String>,
    #[serde(default, alias = "accessBundleId", alias = "bundleId")]
    pub access_bundle_id: Option<String>,
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
    pub external_node_id: &'a str,
    pub hostname: &'a str,
    pub agent_version: &'a str,
    pub runtime_version: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollout_group: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_revision: Option<&'a str>,
}

#[derive(Serialize)]
pub struct HeartbeatPayload<'a> {
    pub contract_version: &'static str,
    pub external_node_id: &'a str,
    pub current_revision: Option<&'a str>,
    pub health_status: &'a str,
    pub stats: HeartbeatStats<'a>,
}

#[derive(Serialize)]
pub struct HeartbeatStats<'a> {
    pub active_clients: u64,
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub sync_lag_sec: u64,
    pub last_apply_status: &'a str,
}

impl<'a> OnboardingPayload<'a> {
    pub fn from_metadata(
        metadata: &'a NodeMetadata,
        agent_version: &'a str,
        runtime_version: &'a str,
    ) -> Self {
        Self {
            contract_version: "v1",
            external_node_id: &metadata.node_external_id,
            hostname: &metadata.node_hostname,
            agent_version,
            runtime_version,
            stage: metadata.node_stage.as_deref(),
            cluster: metadata.node_cluster.as_deref(),
            namespace: metadata.node_namespace.as_deref(),
            rollout_group: metadata.node_rollout_group.as_deref(),
            current_revision: None,
        }
    }

    pub fn validate_compatibility(&self) -> Result<(), String> {
        if self.contract_version != "v1" {
            return Err(
                "onboarding payload compatibility check failed: contract_version must be v1"
                    .to_string(),
            );
        }
        if self.external_node_id.trim().is_empty() {
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
    pub contract_version: &'static str,
    pub external_node_id: &'a str,
    pub applied_revision: &'a str,
    pub last_sync_status: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sync_error: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_exports: Option<&'a [AccountExportPayload<'a>]>,
}

#[derive(Serialize)]
pub struct AccountExportPayload<'a> {
    pub external_node_id: &'a str,
    pub username: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_bundle_id: Option<&'a str>,
    pub active: bool,
    pub tt_link: &'a str,
    pub endpoint_host: &'a str,
    pub endpoint_port: u16,
    pub protocol: &'a str,
    pub applied_revision: &'a str,
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
            node_stage: Some("prod".to_string()),
            node_cluster: Some("c1".to_string()),
            node_namespace: Some("ns".to_string()),
            node_rollout_group: Some("r1".to_string()),
        };

        let payload = OnboardingPayload::from_metadata(&metadata, "1.2.3", "runtime-1");
        assert!(payload.validate_compatibility().is_err());
    }

    #[test]
    fn onboarding_payload_serializes_canonical_v1_shape() {
        let metadata = NodeMetadata {
            node_external_id: "ext-1".to_string(),
            node_hostname: "node-1".to_string(),
            node_stage: Some("prod".to_string()),
            node_cluster: Some("cluster-a".to_string()),
            node_namespace: Some("edge".to_string()),
            node_rollout_group: Some("blue".to_string()),
        };

        let payload = OnboardingPayload::from_metadata(&metadata, "2.0.0", "runtime-2");
        let value = serde_json::to_value(payload).unwrap();

        assert_eq!(value["contract_version"], "v1");
        assert_eq!(value["external_node_id"], "ext-1");
        assert_eq!(value["hostname"], "node-1");
        assert_eq!(value["agent_version"], "2.0.0");
        assert_eq!(value["runtime_version"], "runtime-2");
        assert_eq!(value["stage"], "prod");
        assert_eq!(value["cluster"], "cluster-a");
        assert_eq!(value["namespace"], "edge");
        assert_eq!(value["rollout_group"], "blue");
        assert!(value.get("node_identity").is_none());
        assert!(value.get("trusttunnel_runtime_dir").is_none());
    }

    #[test]
    fn heartbeat_payload_uses_nested_stats_and_nullable_revision() {
        let payload = HeartbeatPayload {
            contract_version: "v1",
            external_node_id: "n-1",
            current_revision: None,
            health_status: "ok",
            stats: HeartbeatStats {
                active_clients: 1,
                cpu_percent: 0.3,
                memory_percent: 1.4,
                sync_lag_sec: 0,
                last_apply_status: "pending",
            },
        };

        let value = serde_json::to_value(payload).unwrap();
        assert!(value.get("stats").is_some());
        assert!(value.get("active_clients").is_none());
        assert!(value["current_revision"].is_null());
    }

    #[test]
    fn sync_report_payload_uses_v1_fields() {
        let payload = SyncReportPayload {
            contract_version: "v1",
            external_node_id: "n-1",
            applied_revision: "rev-1",
            last_sync_status: "ok",
            last_sync_error: None,
            account_exports: None,
        };

        let value = serde_json::to_value(payload).unwrap();
        assert!(value.get("version").is_none());
        assert!(value.get("checksum").is_none());
        assert!(value.get("applied").is_none());
        assert!(value.get("details").is_none());
        assert_eq!(value["last_sync_status"], "ok");
    }
}
