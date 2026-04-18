mod legacy;
mod exporter;
mod link_config;
mod credentials_format;
mod credentials_inventory;
mod lk_bulk_writer;
mod runtime_workspace;

use legacy::lk_api::{
    Account, AccountExportPayload, HeartbeatPayload, HeartbeatStats, LkApiClient, NodeMetadata,
    OnboardingPayload, SyncPayload, SyncReportPayload, SyncResponse, DEFAULT_SYNC_PATH_TEMPLATE,
    DEFAULT_SYNC_REPORT_PATH, DEFAULT_HEARTBEAT_PATH, DEFAULT_REGISTER_PATH,
};
use credentials_inventory::{
    ExportConfig as InventoryExportConfig, InventoryAccount, compute_delta as compute_inventory_delta,
    load_inventory_snapshot, load_state as load_inventory_state, persist_state as persist_inventory_state,
    resolve_credentials_path_from_settings,
};
use credentials_format::parse_client_credentials;
use exporter::{EndpointExportOptions, EndpointLinkExporter};
use lk_bulk_writer::{LkArtifactRecord, LkBulkWriter, LkWriteContract};
use link_config::LinkGenerationConfig;
use runtime_workspace::{ArtifactKind, RuntimeWorkspace};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::read_dir;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::{Instant, MissedTickBehavior, interval};
use toml_edit::value;
use prometheus::{Encoder, IntCounterVec, IntGaugeVec, Opts, Registry, TextEncoder};

const SYNC_REPORT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const SYNC_REPORT_MAX_BACKOFF: Duration = Duration::from_secs(300);
const REGISTER_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const REGISTER_MAX_BACKOFF: Duration = Duration::from_secs(60);
const HEARTBEAT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const HEARTBEAT_MAX_BACKOFF: Duration = Duration::from_secs(30);
const HEARTBEAT_MAX_ATTEMPTS: usize = 3;
const DEFAULT_DB_WORKER_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const INVENTORY_INGEST_ATTEMPTS: usize = 3;
const INVENTORY_INGEST_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const SYNC_REPORT_OUTBOX_FILE: &str = "pending_sync_reports.jsonl";
const RUNTIME_PRIMARY_MARKER_FILE: &str = ".runtime_credentials_primary";
const DEFAULT_RUNTIME_VALIDATION_MIN_USERS: usize = 1;
const DEFAULT_RUNTIME_VALIDATION_MAX_USERS: usize = 100;
const DEFAULT_ENDPOINT_BINARY_PATH: &str = "/usr/local/bin/trusttunnel_endpoint";

mod sidecar_sync {
    use super::sha256_hex;
    use std::collections::BTreeMap;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct AccessArtifact {
        pub(crate) username: String,
        pub(crate) password: String,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum PassKind {
        Bootstrap,
        Reconcile,
    }

    impl PassKind {
        pub(crate) fn as_str(self) -> &'static str {
            match self {
                Self::Bootstrap => "bootstrap",
                Self::Reconcile => "reconcile",
            }
        }
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub(crate) struct PassStats {
        pub(crate) found: usize,
        pub(crate) generated: usize,
        pub(crate) updated: usize,
        pub(crate) skipped: usize,
        pub(crate) errors: usize,
        pub(crate) new_credentials: usize,
        pub(crate) missing_credentials: usize,
        pub(crate) stale_credentials: usize,
        pub(crate) deleted_credentials: usize,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub(crate) struct ReconcilePlan {
        pub(crate) stats: PassStats,
        pub(crate) rendered_credentials: String,
        pub(crate) rendered_sha256: String,
        pub(crate) changed: bool,
    }

    pub(crate) fn reconcile_plan(
        desired_artifacts: &[AccessArtifact],
        runtime_credentials: &[AccessArtifact],
    ) -> ReconcilePlan {
        let mut desired = reconcile_unique_artifacts(desired_artifacts, "desired");
        let runtime = reconcile_unique_artifacts(runtime_credentials, "runtime");

        let mut stats = PassStats {
            found: desired.len(),
            ..PassStats::default()
        };

        for (username, password) in &desired {
            match runtime.get(username) {
                None => {
                    stats.generated += 1;
                    stats.new_credentials += 1;
                }
                Some(existing_password) if existing_password == password => {
                    stats.skipped += 1;
                }
                Some(_) => {
                    stats.updated += 1;
                    stats.stale_credentials += 1;
                }
            }
        }

        for username in runtime.keys() {
            if !desired.contains_key(username) {
                stats.missing_credentials += 1;
                stats.deleted_credentials += 1;
            }
        }

        let rendered_credentials = render_credentials_from_map(&desired);
        let rendered_sha256 = sha256_hex(rendered_credentials.as_bytes());
        let changed = stats.generated > 0 || stats.updated > 0 || stats.deleted_credentials > 0;
        desired.clear();

        ReconcilePlan {
            stats,
            rendered_credentials,
            rendered_sha256,
            changed,
        }
    }

    fn render_credentials_from_map(accounts: &BTreeMap<String, String>) -> String {
        let mut out = String::new();
        for (username, password) in accounts {
            out.push_str("[[client]]\n");
            out.push_str(&format!("username = {:?}\n", username));
            out.push_str(&format!("password = {:?}\n\n", password));
        }
        out
    }

    fn reconcile_unique_artifacts(
        artifacts: &[AccessArtifact],
        source: &str,
    ) -> BTreeMap<String, String> {
        let mut unique = BTreeMap::<String, String>::new();
        for item in artifacts {
            if let Some(previous_password) = unique.get(&item.username) {
                if previous_password != &item.password {
                    println!(
                        "phase=credentials_reconcile_conflict source={} username={} resolution=last_wins",
                        source, item.username
                    );
                }
            }
            unique.insert(item.username.clone(), item.password.clone());
        }
        unique
    }
}

#[derive(Clone)]
struct Config {
    runtime_mode: RuntimeMode,
    lk_write_contract: LkWriteContract,
    lk_db_dsn: String,
    lk_base_url: Option<String>,
    lk_service_token: Option<String>,
    node_external_id: String,
    node_hostname: String,
    node_stage: Option<String>,
    node_cluster: Option<String>,
    node_namespace: Option<String>,
    node_rollout_group: Option<String>,
    trusttunnel_runtime_dir: PathBuf,
    trusttunnel_config_file: PathBuf,
    trusttunnel_hosts_file: PathBuf,
    bootstrap_credentials_source_path: Option<PathBuf>,
    trusttunnel_link_config_file: PathBuf,
    runtime_credentials_path: PathBuf,
    runtime_primary_marker_path: PathBuf,
    agent_state_path: PathBuf,
    reconcile_interval: Duration,
    apply_interval: Duration,
    heartbeat_interval: Duration,
    sync_path_template: Option<String>,
    sync_report_path: Option<String>,
    apply_cmd: Option<String>,
    runtime_pid_path: Option<PathBuf>,
    runtime_process_name: Option<String>,
    endpoint_binary: String,
    agent_version: String,
    runtime_version: String,
    pending_sync_reports_path: Option<PathBuf>,
    metrics_address: SocketAddr,
    debug_preserve_temp_files: bool,
    validation_strict_mode: bool,
    syntax_validation_diagnostic_only: bool,
    runtime_validation_min_users: usize,
    runtime_validation_max_users: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DbWorkerPhaseSchedule {
    reconcile_plan_interval: Duration,
    apply_interval: Duration,
    export_write_interval: Duration,
}

impl DbWorkerPhaseSchedule {
    fn from_config(cfg: &Config) -> Self {
        Self {
            reconcile_plan_interval: cfg.reconcile_interval,
            apply_interval: cfg.apply_interval,
            export_write_interval: cfg.apply_interval,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DbWorkerTickKind {
    Reconcile,
    Apply,
}

impl DbWorkerTickKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Reconcile => "reconcile",
            Self::Apply => "apply",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeMode {
    DbWorker,
    LegacyHttp,
}

impl RuntimeMode {
    fn from_env() -> Result<Self, String> {
        match optional_env_nonempty("CLASSIC_AGENT_MODE")
            .unwrap_or_else(|| "db_worker".to_string())
            .to_ascii_lowercase()
            .as_str()
        {
            "db_worker" => Ok(Self::DbWorker),
            "legacy_http" => {
                if cfg!(feature = "legacy-lk-http") {
                    Ok(Self::LegacyHttp)
                } else {
                    Err(
                        "CLASSIC_AGENT_MODE=legacy_http requires build feature `legacy-lk-http`"
                            .to_string(),
                    )
                }
            }
            other => Err(format!(
                "CLASSIC_AGENT_MODE must be one of: db_worker, legacy_http; got {other}"
            )),
        }
    }

    fn supports_lifecycle_writes(self) -> bool {
        matches!(self, Self::DbWorker | Self::LegacyHttp)
    }
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let runtime_mode = RuntimeMode::from_env()?;
        let lk_write_contract = optional_env_nonempty("LK_WRITE_CONTRACT")
            .ok_or_else(|| {
                "LK_WRITE_CONTRACT is required and must be one of: api, pg_function, legacy_table"
                    .to_string()
            })
            .and_then(|raw| LkWriteContract::from_env(&raw))?;
        let lk_db_dsn = required_env("LK_DB_DSN")?;
        let node_external_id = required_env("NODE_EXTERNAL_ID")?;
        let node_hostname = required_env("NODE_HOSTNAME")?;
        let trusttunnel_runtime_dir: PathBuf = required_env("TRUSTTUNNEL_RUNTIME_DIR")?.into();
        let trusttunnel_runtime_credentials_file: PathBuf =
            required_env("TRUSTTUNNEL_RUNTIME_CREDENTIALS_FILE")?.into();
        let trusttunnel_link_config_file: PathBuf = optional_env_nonempty("TRUSTTUNNEL_LINK_CONFIG_FILE")
            .unwrap_or_else(|| "tt-link.toml".to_string())
            .into();
        let trusttunnel_config_file: PathBuf = required_env("TRUSTTUNNEL_CONFIG_FILE")?.into();
        let trusttunnel_hosts_file: PathBuf = required_env("TRUSTTUNNEL_HOSTS_FILE")?.into();
        let bootstrap_credentials_source_path =
            optional_env("TRUSTTUNNEL_BOOTSTRAP_CREDENTIALS_FILE").map(PathBuf::from);
        let runtime_credentials_path =
            resolve_runtime_path(&trusttunnel_runtime_dir, &trusttunnel_runtime_credentials_file);
        let runtime_primary_marker_path = trusttunnel_runtime_dir.join(RUNTIME_PRIMARY_MARKER_FILE);
        let agent_state_path = std::env::var("AGENT_STATE_PATH")
            .unwrap_or_else(|_| "agent_state.json".to_string())
            .into();

        let reconcile_interval = duration_required_from_env("AGENT_RECONCILE_INTERVAL_SEC")?;
        let apply_interval = duration_required_from_env("AGENT_APPLY_INTERVAL_SEC")?;

        let (lk_base_url, lk_service_token, node_stage, node_cluster, node_namespace, node_rollout_group, heartbeat_interval, sync_path_template, sync_report_path) =
            if runtime_mode == RuntimeMode::LegacyHttp {
                (
                    Some(required_env("LK_BASE_URL")?),
                    Some(required_env("LK_SERVICE_TOKEN")?),
                    optional_env_nonempty("NODE_STAGE"),
                    optional_env_nonempty("NODE_CLUSTER"),
                    optional_env_nonempty("NODE_NAMESPACE"),
                    optional_env_nonempty("NODE_ROLLOUT_GROUP"),
                    duration_required_from_env("AGENT_HEARTBEAT_INTERVAL_SEC")?,
                    Some(
                        std::env::var("LK_SYNC_PATH_TEMPLATE")
                            .unwrap_or_else(|_| DEFAULT_SYNC_PATH_TEMPLATE.to_string()),
                    ),
                    Some(
                        std::env::var("LK_SYNC_REPORT_PATH")
                            .unwrap_or_else(|_| DEFAULT_SYNC_REPORT_PATH.to_string()),
                    ),
                )
            } else {
                let lifecycle_base_url = optional_env_nonempty("LK_LIFECYCLE_BASE_URL")
                    .or_else(|| optional_env_nonempty("LK_BASE_URL"))
                    .or_else(|| derive_lifecycle_base_url_from_artifacts_endpoint(&lk_db_dsn));
                let service_token = optional_env_nonempty("LK_SERVICE_TOKEN");
                let heartbeat_interval = optional_env_nonempty("AGENT_HEARTBEAT_INTERVAL_SEC")
                    .map(|raw| {
                        let secs = raw
                            .parse::<u64>()
                            .map_err(|e| format!("AGENT_HEARTBEAT_INTERVAL_SEC must be u64 seconds: {e}"))?;
                        Ok::<Duration, String>(Duration::from_secs(secs))
                    })
                    .transpose()?
                    .unwrap_or(DEFAULT_DB_WORKER_HEARTBEAT_INTERVAL);
                (
                    lifecycle_base_url,
                    service_token,
                    None,
                    None,
                    None,
                    None,
                    heartbeat_interval,
                    None,
                    None,
                )
            };

        let apply_cmd = std::env::var("TRUSTTUNNEL_APPLY_CMD")
            .ok()
            .and_then(|x| if x.trim().is_empty() { None } else { Some(x) });
        let runtime_pid_path = if runtime_mode == RuntimeMode::LegacyHttp {
            Some(
                std::env::var("TRUSTTUNNEL_RUNTIME_PID_FILE")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| trusttunnel_runtime_dir.join("trusttunnel.pid")),
            )
        } else {
            None
        };
        let runtime_process_name = if runtime_mode == RuntimeMode::LegacyHttp {
            Some(
                std::env::var("TRUSTTUNNEL_RUNTIME_PROCESS_NAME")
                    .unwrap_or_else(|_| "trusttunnel_endpoint".to_string()),
            )
        } else {
            None
        };
        let agent_version = optional_env_nonempty("TRUSTTUNNEL_AGENT_VERSION")
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
        let runtime_version =
            optional_env_nonempty("TRUSTTUNNEL_RUNTIME_VERSION").unwrap_or_else(|| "unknown".to_string());
        let endpoint_binary = resolve_endpoint_binary_from_env();
        let pending_sync_reports_path = if runtime_mode == RuntimeMode::LegacyHttp {
            Some(trusttunnel_runtime_dir.join(SYNC_REPORT_OUTBOX_FILE))
        } else {
            None
        };
        let metrics_address = std::env::var("AGENT_METRICS_ADDRESS")
            .unwrap_or_else(|_| "127.0.0.1:9901".to_string())
            .parse::<SocketAddr>()
            .map_err(|e| format!("AGENT_METRICS_ADDRESS must be socket address host:port: {e}"))?;
        let debug_preserve_temp_files = optional_env_nonempty("TRUSTTUNNEL_DEBUG_KEEP_TEMP_FILES")
            .map(|raw| {
                matches!(
                    raw.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        let validation_strict_mode = optional_env_nonempty("TRUSTTUNNEL_VALIDATION_STRICT")
            .map(|raw| {
                matches!(
                    raw.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        let syntax_validation_diagnostic_only = optional_env_nonempty(
            "TRUSTTUNNEL_CANDIDATE_SYNTAX_DIAGNOSTIC_ONLY",
        )
        .map(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
        let runtime_validation_min_users = optional_env_nonempty(
            "TRUSTTUNNEL_RUNTIME_VALIDATION_MIN_USERS",
        )
        .map(|raw| {
            raw.parse::<usize>().map_err(|e| {
                format!(
                    "TRUSTTUNNEL_RUNTIME_VALIDATION_MIN_USERS must be a positive integer: {e}"
                )
            })
        })
        .transpose()?
        .unwrap_or(DEFAULT_RUNTIME_VALIDATION_MIN_USERS);
        if runtime_validation_min_users == 0 {
            return Err(
                "TRUSTTUNNEL_RUNTIME_VALIDATION_MIN_USERS must be greater than zero".to_string(),
            );
        }
        let runtime_validation_max_users = optional_env_nonempty(
            "TRUSTTUNNEL_RUNTIME_VALIDATION_MAX_USERS",
        )
        .map(|raw| {
            raw.parse::<usize>().map_err(|e| {
                format!(
                    "TRUSTTUNNEL_RUNTIME_VALIDATION_MAX_USERS must be a positive integer: {e}"
                )
            })
        })
        .transpose()?
        .unwrap_or(DEFAULT_RUNTIME_VALIDATION_MAX_USERS);
        if runtime_validation_max_users == 0 {
            return Err(
                "TRUSTTUNNEL_RUNTIME_VALIDATION_MAX_USERS must be greater than zero".to_string(),
            );
        }
        if runtime_validation_min_users > runtime_validation_max_users {
            return Err(format!(
                "TRUSTTUNNEL_RUNTIME_VALIDATION_MIN_USERS ({runtime_validation_min_users}) must be <= TRUSTTUNNEL_RUNTIME_VALIDATION_MAX_USERS ({runtime_validation_max_users})"
            ));
        }

        let cfg = Self {
            lk_base_url,
            runtime_mode,
            lk_write_contract,
            lk_db_dsn,
            lk_service_token,
            node_external_id,
            node_hostname,
            node_stage,
            node_cluster,
            node_namespace,
            node_rollout_group,
            trusttunnel_runtime_dir,
            trusttunnel_config_file,
            trusttunnel_hosts_file,
            bootstrap_credentials_source_path,
            trusttunnel_link_config_file,
            runtime_credentials_path,
            runtime_primary_marker_path,
            agent_state_path,
            reconcile_interval,
            apply_interval,
            heartbeat_interval,
            sync_path_template,
            sync_report_path,
            apply_cmd,
            runtime_pid_path,
            runtime_process_name,
            endpoint_binary,
            agent_version,
            runtime_version,
            pending_sync_reports_path,
            metrics_address,
            debug_preserve_temp_files,
            validation_strict_mode,
            syntax_validation_diagnostic_only,
            runtime_validation_min_users,
            runtime_validation_max_users,
        };
        cfg.validate_lifecycle_config()?;
        cfg.validate_paths()?;
        Ok(cfg)
    }

    fn validate_lifecycle_config(&self) -> Result<(), String> {
        if !self.runtime_mode.supports_lifecycle_writes() {
            return Ok(());
        }
        let Some(base_url) = self.lk_base_url.as_ref().map(|raw| raw.trim()) else {
            return Err(
                "lifecycle writes are enabled but lifecycle base URL is missing; set LK_LIFECYCLE_BASE_URL (preferred), LK_BASE_URL, or provide LK_DB_DSN as an artifacts endpoint URL".to_string(),
            );
        };
        if base_url.is_empty() {
            return Err(
                "lifecycle writes are enabled but lifecycle base URL is empty; set LK_LIFECYCLE_BASE_URL (preferred) or LK_BASE_URL".to_string(),
            );
        }
        let parsed = reqwest::Url::parse(base_url)
            .map_err(|e| format!("lifecycle writes are enabled but lifecycle base URL is invalid ({base_url}): {e}"))?;
        if parsed.host_str().is_none() {
            return Err(format!(
                "lifecycle writes are enabled but lifecycle base URL has no host: {base_url}"
            ));
        }
        if self
            .lk_service_token
            .as_ref()
            .map(|raw| raw.trim().is_empty())
            .unwrap_or(true)
        {
            return Err(
                "lifecycle writes are enabled but LK_SERVICE_TOKEN is missing or empty".to_string(),
            );
        }
        Ok(())
    }

    fn validate_paths(&self) -> Result<(), String> {
        if !self.trusttunnel_runtime_dir.exists() {
            return Err(format!(
                "TRUSTTUNNEL_RUNTIME_DIR path not found: {}",
                self.trusttunnel_runtime_dir.display()
            ));
        }
        if !self.trusttunnel_runtime_dir.is_dir() {
            return Err(format!(
                "TRUSTTUNNEL_RUNTIME_DIR is not a directory: {}",
                self.trusttunnel_runtime_dir.display()
            ));
        }

        let config_path = resolve_runtime_path(&self.trusttunnel_runtime_dir, &self.trusttunnel_config_file);
        if !config_path.exists() {
            return Err(format!(
                "TRUSTTUNNEL_CONFIG_FILE path not found: {}",
                config_path.display()
            ));
        }

        let hosts_path = resolve_runtime_path(&self.trusttunnel_runtime_dir, &self.trusttunnel_hosts_file);
        if !hosts_path.exists() {
            return Err(format!(
                "TRUSTTUNNEL_HOSTS_FILE path not found: {}",
                hosts_path.display()
            ));
        }

        let credentials_parent = self
            .runtime_credentials_path
            .parent()
            .ok_or_else(|| {
                format!(
                    "TRUSTTUNNEL_RUNTIME_CREDENTIALS_FILE has no parent directory: {}",
                    self.runtime_credentials_path.display()
                )
            })?;
        if !credentials_parent.exists() {
            return Err(format!(
                "TRUSTTUNNEL_RUNTIME_CREDENTIALS_FILE parent path not found: {}",
                credentials_parent.display()
            ));
        }

        let link_config_path =
            resolve_runtime_path(&self.trusttunnel_runtime_dir, &self.trusttunnel_link_config_file);
        let link_config_parent = link_config_path.parent().ok_or_else(|| {
            format!(
                "TRUSTTUNNEL_LINK_CONFIG_FILE has no parent directory: {}",
                link_config_path.display()
            )
        })?;
        if !link_config_parent.exists() {
            return Err(format!(
                "TRUSTTUNNEL_LINK_CONFIG_FILE parent path not found: {}",
                link_config_parent.display()
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
struct AgentState {
    #[serde(alias = "version")]
    applied_revision: Option<String>,
    last_target_revision: Option<String>,
    #[serde(default)]
    credentials_sha256: String,
}

struct Agent {
    cfg: Config,
    workspace: RuntimeWorkspace,
    lk_api: LkApiClient,
    state: AgentState,
    node_metadata: NodeMetadata,
    last_apply_status: String,
    db_worker_health: DbWorkerHealthState,
    metrics: Arc<AgentMetrics>,
    sync_report_backoff: Duration,
    sync_report_next_retry_at: Instant,
}

#[derive(Debug)]
struct CandidateValidationFiles {
    candidate_credentials_path: PathBuf,
    temp_config_path: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
struct InventoryIngestCredential {
    username: String,
    password: String,
}

#[derive(Clone, Debug, Serialize)]
struct InventoryIngestPayload {
    contract_version: &'static str,
    snapshot_version: &'static str,
    external_node_id: String,
    source: String,
    revision: i64,
    exported_at: String,
    idempotency_key: String,
    request_id: String,
    credentials: Vec<InventoryIngestCredential>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct InventoryIngestAttempt {
    had_retry: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InventoryIngestSource {
    Bootstrap,
    Imported,
}

impl InventoryIngestSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Imported => "imported",
        }
    }
}

impl Agent {
    async fn new(cfg: Config) -> Result<Self, String> {
        cfg.validate_lifecycle_config()?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .no_proxy()
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;

        let state = load_state(&cfg.agent_state_path).await.unwrap_or_default();
        let node_metadata = NodeMetadata {
            node_external_id: cfg.node_external_id.clone(),
            node_hostname: cfg.node_hostname.clone(),
            node_stage: cfg.node_stage.clone(),
            node_cluster: cfg.node_cluster.clone(),
            node_namespace: cfg.node_namespace.clone(),
            node_rollout_group: cfg.node_rollout_group.clone(),
        };
        let lk_base_url = cfg
            .lk_base_url
            .clone()
            .unwrap_or_default();
        if cfg.runtime_mode.supports_lifecycle_writes() && lk_base_url.trim().is_empty() {
            return Err(
                "failed to initialize lifecycle API client: empty lifecycle base URL".to_string(),
            );
        }
        let lk_api = LkApiClient::new(
            client,
            lk_base_url,
            cfg.lk_service_token.clone().unwrap_or_default(),
            DEFAULT_REGISTER_PATH.to_string(),
            DEFAULT_HEARTBEAT_PATH.to_string(),
            cfg.sync_report_path.clone().unwrap_or_default(),
            cfg.sync_path_template.clone().unwrap_or_default(),
        );

        let metrics = Arc::new(AgentMetrics::new(&node_metadata.node_external_id)?);

        let workspace = RuntimeWorkspace::new(
            cfg.trusttunnel_runtime_dir.clone(),
            cfg.debug_preserve_temp_files,
        );
        Ok(Self {
            cfg,
            workspace,
            lk_api,
            state,
            node_metadata,
            last_apply_status: "pending".to_string(),
            db_worker_health: DbWorkerHealthState::default(),
            metrics,
            sync_report_backoff: SYNC_REPORT_INITIAL_BACKOFF,
            sync_report_next_retry_at: Instant::now(),
        })
    }

    async fn run(&mut self) {
        let metrics = Arc::clone(&self.metrics);
        let metrics_address = self.cfg.metrics_address;
        tokio::spawn(async move {
            if let Err(err) = serve_metrics(metrics, metrics_address).await {
                log_error(
                    "metrics_server_failed",
                    "classic_agent",
                    "metrics_server",
                    "unknown",
                    &err,
                );
            }
        });

        if let Err(err) = self.resolve_and_validate_endpoint_binary().await {
            log_error(
                "unknown",
                &self.cfg.node_external_id,
                "endpoint_binary_check_failed",
                "failed",
                &err,
            );
            std::process::exit(2);
        }

        if let Err(err) = self.bootstrap_runtime_credentials().await {
            log_error(
                "bootstrap_import_failed",
                &self.cfg.node_external_id,
                "bootstrap_import",
                "failed",
                &err,
            );
            std::process::exit(2);
        }

        match self.cfg.runtime_mode {
            RuntimeMode::DbWorker => self.run_db_worker_loop().await,
            RuntimeMode::LegacyHttp => self.run_legacy_http_loop().await,
        }
    }

    async fn resolve_and_validate_endpoint_binary(&mut self) -> Result<(), String> {
        println!(
            "phase=endpoint_binary_check_begin node={} endpoint_bin_path={}",
            self.cfg.node_external_id, self.cfg.endpoint_binary
        );
        let resolved = if self.cfg.endpoint_binary == DEFAULT_ENDPOINT_BINARY_PATH {
            if is_executable_file(Path::new(DEFAULT_ENDPOINT_BINARY_PATH)) {
                DEFAULT_ENDPOINT_BINARY_PATH.to_string()
            } else {
                let path_fallback = "trusttunnel_endpoint";
                if is_command_available_in_path(path_fallback).await {
                    path_fallback.to_string()
                } else {
                    DEFAULT_ENDPOINT_BINARY_PATH.to_string()
                }
            }
        } else {
            self.cfg.endpoint_binary.clone()
        };
        self.cfg.endpoint_binary = resolved;

        if !is_executable_file(Path::new(&self.cfg.endpoint_binary))
            && !is_command_available_in_path(&self.cfg.endpoint_binary).await
        {
            self.db_worker_health.runtime_prerequisites_valid = false;
            println!(
                "phase=endpoint_binary_check_failed node={} endpoint_bin_path={} found=false executable=false",
                self.cfg.node_external_id, self.cfg.endpoint_binary
            );
            return Err(format!(
                "trusttunnel_endpoint binary not found at {}; set TRUSTTUNNEL_ENDPOINT_BIN or rebuild classic-agent image with endpoint binary included",
                self.cfg.endpoint_binary
            ));
        }

        let executable = if Path::new(&self.cfg.endpoint_binary).components().count() > 1 {
            is_executable_file(Path::new(&self.cfg.endpoint_binary))
        } else {
            true
        };
        println!(
            "phase=endpoint_binary_check_ok node={} endpoint_bin_path={} found=true executable={}",
            self.cfg.node_external_id, self.cfg.endpoint_binary, executable
        );
        self.db_worker_health.runtime_prerequisites_valid = true;
        Ok(())
    }

    async fn run_db_worker_loop(&mut self) {
        let lifecycle_writes_supported = self.cfg.runtime_mode.supports_lifecycle_writes();
        let schedule = DbWorkerPhaseSchedule::from_config(&self.cfg);
        let heartbeat_interval = self.cfg.heartbeat_interval;
        println!(
            "db_worker mode enabled for node_external_id={} (dsn_len={}, reconcile_interval_sec={}, apply_interval_sec={}, export_write_interval_sec={}, heartbeat_interval_sec={}, lifecycle_writes_supported={})",
            self.cfg.node_external_id,
            self.cfg.lk_db_dsn.len(),
            schedule.reconcile_plan_interval.as_secs(),
            schedule.apply_interval.as_secs(),
            schedule.export_write_interval.as_secs(),
            heartbeat_interval.as_secs(),
            lifecycle_writes_supported
        );
        println!(
            "phase=startup mode=db_worker lifecycle_writes=enabled level=minimal details=\"register+heartbeat enabled; metadata/status/revision writes remain disabled\""
        );
        println!(
            "phase=lifecycle_writes_enabled_for_db_worker mode=db_worker node={} lifecycle_writes_supported={} reconcile_interval_sec={} apply_interval_sec={} export_write_interval_sec={} heartbeat_interval_sec={}",
            self.cfg.node_external_id,
            lifecycle_writes_supported,
            schedule.reconcile_plan_interval.as_secs(),
            schedule.apply_interval.as_secs(),
            schedule.export_write_interval.as_secs(),
            heartbeat_interval.as_secs()
        );
        self.bootstrap_register().await;
        if let Err(err) = self
            .run_sidecar_sync_pass(sidecar_sync::PassKind::Bootstrap)
            .await
        {
            log_error(
                "unknown",
                &self.cfg.node_external_id,
                "sidecar_sync_bootstrap_failed",
                "failed",
                &err,
            );
        }
        let mut reconcile_tick = interval(schedule.reconcile_plan_interval);
        reconcile_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut apply_tick = interval(schedule.apply_interval);
        apply_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut heartbeat_tick = interval(heartbeat_interval);
        heartbeat_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut backoff = Duration::from_secs(1);
        let mut pending_plan: Option<sidecar_sync::ReconcilePlan> = None;
        loop {
            let tick_kind = tokio::select! {
                _ = reconcile_tick.tick() => DbWorkerTickKind::Reconcile,
                _ = apply_tick.tick() => DbWorkerTickKind::Apply,
                _ = heartbeat_tick.tick() => {
                    self.send_heartbeat_with_retry().await;
                    continue;
                }
            };
            match tick_kind {
                DbWorkerTickKind::Reconcile => {
                    println!(
                        "phase=scheduler_tick mode=db_worker tick={} trigger=reconcile_plan",
                        tick_kind.as_str()
                    );
                    match self.run_sidecar_reconcile_plan_phase().await {
                        Ok(plan) => {
                            pending_plan = Some(plan);
                            backoff = Duration::from_secs(1);
                        }
                        Err(err) => {
                            log_error(
                                self.state.applied_revision.as_deref().unwrap_or("none"),
                                &self.cfg.node_external_id,
                                "sidecar_sync_reconcile_plan_failed",
                                "failed",
                                &err,
                            );
                            tokio::time::sleep(backoff).await;
                            backoff =
                                std::cmp::min(backoff.saturating_mul(2), Duration::from_secs(300));
                        }
                    }
                }
                DbWorkerTickKind::Apply => {
                    println!(
                        "phase=scheduler_tick mode=db_worker tick={} trigger=apply_export_write",
                        tick_kind.as_str()
                    );
                    if let Err(err) = self
                        .run_sidecar_apply_export_write_phase(
                            sidecar_sync::PassKind::Reconcile,
                            pending_plan.take(),
                        )
                        .await
                    {
                        log_error(
                            self.state.applied_revision.as_deref().unwrap_or("none"),
                            &self.cfg.node_external_id,
                            "sidecar_sync_apply_export_write_failed",
                            "failed",
                            &err,
                        );
                        tokio::time::sleep(backoff).await;
                        backoff =
                            std::cmp::min(backoff.saturating_mul(2), Duration::from_secs(300));
                    } else {
                        backoff = Duration::from_secs(1);
                    }
                }
            }
        }
    }

    async fn run_sidecar_reconcile_plan_phase(
        &mut self,
    ) -> Result<sidecar_sync::ReconcilePlan, String> {
        let desired_artifacts = self.load_desired_access_artifacts().await?;
        let runtime_credentials = self.load_runtime_credentials_artifacts().await?;
        println!(
            "phase=source_inventory_summary node={} source_inventory_count={} runtime_inventory_count={}",
            self.cfg.node_external_id,
            desired_artifacts.len(),
            runtime_credentials.len()
        );
        let plan = sidecar_sync::reconcile_plan(&desired_artifacts, &runtime_credentials);
        println!(
            "phase=reconcile_plan found={} generated={} updated={} missing={} skipped={} new={} stale={} deleted={} changed={}",
            plan.stats.found,
            plan.stats.generated,
            plan.stats.updated,
            plan.stats.missing_credentials,
            plan.stats.skipped,
            plan.stats.new_credentials,
            plan.stats.stale_credentials,
            plan.stats.deleted_credentials,
            plan.changed
        );
        println!(
            "phase=reconcile_invariants node={} source_inventory_count={} reconcile_found_count={}",
            self.cfg.node_external_id,
            desired_artifacts.len(),
            plan.stats.found
        );
        Ok(plan)
    }

    async fn run_sidecar_apply_export_write_phase(
        &mut self,
        pass_kind: sidecar_sync::PassKind,
        plan: Option<sidecar_sync::ReconcilePlan>,
    ) -> Result<(), String> {
        let mut plan = plan.unwrap_or_default();
        let node = self.cfg.node_external_id.clone();
        let pass = pass_kind.as_str();
        println!(
            "phase=apply_start pass={} changed={} source={}",
            pass,
            plan.changed,
            if plan.changed { "reconcile_tick" } else { "no_pending_plan" }
        );

        if plan.changed {
            println!(
                "phase=apply_plan_summary node={} planned_credentials_count={}",
                self.cfg.node_external_id,
                plan.stats.found
            );
            let previous_runtime_credentials = fs::read(&self.cfg.runtime_credentials_path).await.ok();
            let tmp_credentials_path = self
                .write_runtime_credentials_tmp(plan.rendered_credentials.as_bytes())
                .await?;
            let validation_files = match self
                .validate_candidate_credentials_pipeline(tmp_credentials_path)
                .await
            {
                Ok(files) => {
                    self.db_worker_health.candidate_validation_valid = true;
                    files
                }
                Err(err) => {
                    self.db_worker_health.candidate_validation_valid = false;
                    plan.stats.errors += 1;
                    self.update_sidecar_sync_metrics(pass, &plan.stats);
                    return Err(err);
                }
            };
            if let Err(err) = self
                .cleanup_validation_files(
                    &validation_files,
                    self.cfg.debug_preserve_temp_files,
                    false,
                )
                .await
            {
                plan.stats.errors += 1;
                self.update_sidecar_sync_metrics(pass, &plan.stats);
                return Err(err);
            }
            self.promote_runtime_credentials(&validation_files.candidate_credentials_path)
                .await?;
            let apply_result = self.apply_runtime().await;
            let apply_result = match apply_result {
                Ok(()) => self.verify_runtime_post_apply(&plan.rendered_sha256).await,
                Err(err) => Err(err),
            };
            if let Err(apply_err) = apply_result {
                self.db_worker_health.candidate_validation_valid = false;
                let rollback_result = self.rollback_runtime(previous_runtime_credentials).await;
                plan.stats.errors += 1;
                self.update_sidecar_sync_metrics(pass, &plan.stats);
                return match rollback_result {
                    Ok(()) => Err(format!("sidecar sync apply failed and rollback completed: {apply_err}")),
                    Err(rollback_err) => Err(format!(
                        "sidecar sync apply failed: {apply_err}; rollback failed: {rollback_err}"
                    )),
                };
            }
            self.state.credentials_sha256 = plan.rendered_sha256.clone();
            self.mark_runtime_as_primary().await?;
            persist_state(&self.cfg.agent_state_path, &self.state).await?;
            self.db_worker_health.candidate_validation_valid = true;
        }

        println!("phase=export_write_start pass={}", pass);
        let inventory_source = match pass_kind {
            sidecar_sync::PassKind::Bootstrap => InventoryIngestSource::Bootstrap,
            sidecar_sync::PassKind::Reconcile => InventoryIngestSource::Imported,
        };
        self.sync_local_inventory_export_sidecar(inventory_source).await?;

        if !plan.changed {
            plan.stats.skipped += plan.stats.missing_credentials;
        }

        self.update_sidecar_sync_metrics(pass, &plan.stats);
        println!(
            "sidecar sync pass={} found={} generated={} updated={} skipped={} errors={} new={} missing={} stale={} deleted={}",
            pass,
            plan.stats.found,
            plan.stats.generated,
            plan.stats.updated,
            plan.stats.skipped,
            plan.stats.errors,
            plan.stats.new_credentials,
            plan.stats.missing_credentials,
            plan.stats.stale_credentials,
            plan.stats.deleted_credentials
        );
        log_event(
            if plan.stats.errors == 0 { "info" } else { "error" },
            self.state.applied_revision.as_deref().unwrap_or("none"),
            &node,
            "sidecar_sync_pass",
            pass,
        );
        Ok(())
    }

    async fn run_sidecar_sync_pass(
        &mut self,
        pass_kind: sidecar_sync::PassKind,
    ) -> Result<sidecar_sync::PassStats, String> {
        let plan = self.run_sidecar_reconcile_plan_phase().await?;
        let stats = plan.stats.clone();
        self.run_sidecar_apply_export_write_phase(pass_kind, Some(plan))
            .await?;
        Ok(stats)
    }

    async fn load_desired_access_artifacts(&self) -> Result<Vec<sidecar_sync::AccessArtifact>, String> {
        if let Some(source_path) = self.cfg.bootstrap_credentials_source_path.as_ref() {
            let raw = fs::read_to_string(source_path).await.map_err(|e| {
                format!(
                    "failed to read desired access artifacts {}: {e}",
                    source_path.display()
                )
            })?;
            let parsed = parse_access_artifacts(&raw)?;
            println!(
                "phase=source_inventory_loaded node={} source=bootstrap_credentials path={} source_inventory_count={}",
                self.cfg.node_external_id,
                source_path.display(),
                parsed.len()
            );
            return Ok(parsed);
        }

        if !fs::try_exists(&self.cfg.runtime_credentials_path)
            .await
            .map_err(|e| {
                format!(
                    "failed to check runtime credentials {}: {e}",
                    self.cfg.runtime_credentials_path.display()
                )
            })?
        {
            println!(
                "phase=source_inventory_loaded node={} source=none source_inventory_count=0",
                self.cfg.node_external_id
            );
            return Ok(Vec::new());
        }

        let raw = fs::read_to_string(&self.cfg.runtime_credentials_path)
            .await
            .map_err(|e| {
                format!(
                    "failed to read runtime credentials for desired inventory {}: {e}",
                    self.cfg.runtime_credentials_path.display()
                )
            })?;
        let parsed = parse_access_artifacts(&raw)?;
        println!(
            "phase=source_inventory_loaded node={} source=runtime_credentials_fallback path={} source_inventory_count={}",
            self.cfg.node_external_id,
            self.cfg.runtime_credentials_path.display(),
            parsed.len()
        );
        Ok(parsed)
    }

    async fn load_runtime_credentials_artifacts(
        &self,
    ) -> Result<Vec<sidecar_sync::AccessArtifact>, String> {
        if !fs::try_exists(&self.cfg.runtime_credentials_path)
            .await
            .map_err(|e| {
                format!(
                    "failed to check runtime credentials {}: {e}",
                    self.cfg.runtime_credentials_path.display()
                )
            })?
        {
            return Ok(Vec::new());
        }
        let raw = fs::read_to_string(&self.cfg.runtime_credentials_path)
            .await
            .map_err(|e| {
                format!(
                    "failed to read runtime credentials {}: {e}",
                    self.cfg.runtime_credentials_path.display()
                )
            })?;
        parse_access_artifacts(&raw)
    }

    fn update_sidecar_sync_metrics(&self, pass: &str, stats: &sidecar_sync::PassStats) {
        let node = self.cfg.node_external_id.as_str();
        self.metrics
            .sidecar_sync_pass_total
            .with_label_values(&[node, pass, if stats.errors == 0 { "ok" } else { "error" }])
            .inc();
        for (outcome, value) in [
            ("found", stats.found),
            ("generated", stats.generated),
            ("updated", stats.updated),
            ("skipped", stats.skipped),
            ("errors", stats.errors),
            ("new", stats.new_credentials),
            ("missing", stats.missing_credentials),
            ("stale", stats.stale_credentials),
            ("deleted", stats.deleted_credentials),
        ] {
            if value > 0 {
                self.metrics
                    .sidecar_sync_item_total
                    .with_label_values(&[node, pass, outcome])
                    .inc_by(value as u64);
            }
        }
    }

    async fn sync_local_inventory_export_sidecar(
        &mut self,
        inventory_source: InventoryIngestSource,
    ) -> Result<(), String> {
        let settings_path = resolve_runtime_path(&self.cfg.trusttunnel_runtime_dir, &self.cfg.trusttunnel_config_file);
        let credentials_path = resolve_credentials_path_from_settings(
            &self.cfg.trusttunnel_runtime_dir,
            &settings_path,
        )?;

        let link_config_path =
            resolve_runtime_path(&self.cfg.trusttunnel_runtime_dir, &self.cfg.trusttunnel_link_config_file);
        let (link_cfg, link_diag) = LinkGenerationConfig::load_with_diagnostics(
            &link_config_path,
            &self.cfg.node_external_id,
        )?;
        println!(
            "phase=link_config_diagnostics node={} path={} exists={} parsed={} fallback_used={} contract_mode={} hash={} protocol={} server_address={}",
            self.cfg.node_external_id,
            link_diag.path,
            link_diag.file_exists,
            link_diag.file_parsed,
            link_diag.fallback_used,
            link_diag.contract_mode,
            link_diag.hash.as_deref().unwrap_or("none"),
            link_diag.recognized_protocol.as_deref().unwrap_or("unknown"),
            link_diag.recognized_server_address.as_deref().unwrap_or("unknown")
        );

        let (address, port) = split_host_port(link_cfg.server_address())?;
        let export_config_hash = InventoryExportConfig {
            address,
            domain: link_cfg.cert_domain().to_string(),
            port,
            sni: link_cfg.custom_sni(),
            dns: link_cfg.dns_servers(),
            protocol: link_cfg.protocol().to_string(),
        }
        .config_hash();

        let snapshot = load_inventory_snapshot(
            &credentials_path,
            export_config_hash,
            chrono::Utc::now().timestamp(),
        )?;
        let state_path = self.workspace.inventory_state_path();
        let previous = load_inventory_state(&state_path)?;
        let delta = compute_inventory_delta(&snapshot, previous.as_ref());

        let mut upsert_accounts = Vec::new();
        upsert_accounts.extend(delta.missing.iter().cloned());
        upsert_accounts.extend(delta.stale.iter().cloned());
        let unchanged_count = snapshot
            .credentials
            .len()
            .saturating_sub(upsert_accounts.len());
        let removed_count = delta.removed.len();

        let writer = LkBulkWriter::from_contract(
            self.cfg.lk_write_contract,
            &self.cfg.lk_db_dsn,
            &self.cfg.node_external_id,
            self.cfg.lk_service_token.clone(),
        )?;
        if writer.active_contract() == "api" {
            let inventory_payload = build_inventory_ingest_payload(
                &self.cfg.node_external_id,
                &snapshot,
                inventory_source,
            )?;
            println!(
                "phase=inventory_payload_sent node={} endpoint={} snapshot_version={} revision={} credentials={} idempotency_key={} request_id={}",
                self.cfg.node_external_id,
                derive_inventory_endpoint(&self.cfg.lk_db_dsn, &self.cfg.node_external_id)?,
                inventory_payload.snapshot_version,
                inventory_payload.revision,
                inventory_payload.credentials.len(),
                inventory_payload.idempotency_key,
                inventory_payload.request_id
            );
            let inventory_attempt = match self.post_inventory_with_retry(&inventory_payload).await {
                Ok(attempt) => attempt,
                Err(err) => {
                    self.db_worker_health.inventory_status = DbWorkerSignalStatus::Degraded;
                    return Err(err);
                }
            };
            self.db_worker_health.inventory_status = if inventory_attempt.had_retry {
                DbWorkerSignalStatus::Degraded
            } else {
                DbWorkerSignalStatus::Ok
            };
            println!(
                "phase=inventory_payload_accepted node={} snapshot_version={} revision={} credentials={} idempotency_key={} request_id={} reconcile_ready=true",
                self.cfg.node_external_id,
                inventory_payload.snapshot_version,
                inventory_payload.revision,
                inventory_payload.credentials.len(),
                inventory_payload.idempotency_key,
                inventory_payload.request_id
            );
        } else {
            self.db_worker_health.inventory_status = DbWorkerSignalStatus::Disabled;
            println!(
                "phase=inventory_payload_skipped node={} contract={} reconcile_ready=false reason=inventory_requires_api_contract",
                self.cfg.node_external_id,
                writer.active_contract()
            );
        }
        let use_full_snapshot_for_export = writer.active_contract() == "api";
        let accounts_for_export = if use_full_snapshot_for_export {
            snapshot.credentials.clone()
        } else {
            upsert_accounts.clone()
        };

        let mut generated_links = BTreeMap::new();
        let mut export_failed = 0usize;
        let mut export_failures = Vec::new();
        if !accounts_for_export.is_empty() {
            let usernames = accounts_for_export
                .iter()
                .map(|account: &InventoryAccount| account.username.clone())
                .collect::<Vec<_>>();
            println!(
                "phase=link_generation_started node={} contract_mode={} endpoint_bin_path={} accounts_for_export={} removed_accounts={}",
                self.cfg.node_external_id,
                if link_diag.fallback_used {
                    "legacy_fallback"
                } else {
                    "file_required"
                },
                self.cfg.endpoint_binary,
                usernames.len(),
                removed_count
            );
            let settings_path =
                resolve_runtime_path(&self.cfg.trusttunnel_runtime_dir, &self.cfg.trusttunnel_config_file);
            let hosts_path =
                resolve_runtime_path(&self.cfg.trusttunnel_runtime_dir, &self.cfg.trusttunnel_hosts_file);
            let exporter = EndpointLinkExporter::new(
                self.cfg.endpoint_binary.clone(),
                settings_path,
                hosts_path,
                EndpointExportOptions::new(
                    link_cfg.server_address().to_string(),
                    link_cfg.custom_sni(),
                    link_cfg.display_name(),
                    link_cfg.dns_servers(),
                ),
            );
            let export_summary = exporter.export_usernames(usernames).await?;
            generated_links = export_summary.links;
            export_failed = export_summary.failed;
            export_failures = export_summary.failures;
            let export_binary_invocation_failed = export_failures
                .iter()
                .filter(|x| x.contains("failed to execute endpoint command"))
                .count();
            println!(
                "phase=link_generation_complete node={} endpoint_bin_path={} generated_links={} export_failed={} export_failed_binary_invocation={}",
                self.cfg.node_external_id,
                self.cfg.endpoint_binary,
                generated_links.len(),
                export_failed,
                export_binary_invocation_failed
            );
            for (username, _) in &generated_links {
                println!(
                    "phase=link_generation_exported node={} endpoint_bin_path={} username={}",
                    self.cfg.node_external_id, self.cfg.endpoint_binary, username
                );
            }
        }

        let mut records = accounts_for_export
            .iter()
            .filter(|account| generated_links.contains_key(&account.username))
            .map(|account| LkArtifactRecord {
                username: account.username.clone(),
                external_node_id: self.cfg.node_external_id.clone(),
                external_account_id: None,
                access_bundle_id: None,
                tt_link: generated_links.get(&account.username).cloned(),
                config_hash: Some(snapshot.export_config_hash.clone()),
                active: true,
                credential_external_id: None,
                generated_at: Some(
                    chrono::DateTime::from_timestamp(snapshot.generated_at_unix_sec, 0)
                        .unwrap_or_else(chrono::Utc::now)
                        .to_rfc3339(),
                ),
                source: Some("classic_agent".to_string()),
                display_name: link_cfg.display_name(),
                source_key: Some(account.username.clone()),
                link_hash: generated_links
                    .get(&account.username)
                    .map(|item| sha256_hex(item.as_bytes())),
            })
            .collect::<Vec<_>>();
        if !use_full_snapshot_for_export {
            records.extend(delta.removed.iter().map(|username| LkArtifactRecord {
                username: username.clone(),
                external_node_id: self.cfg.node_external_id.clone(),
                external_account_id: None,
                access_bundle_id: None,
                tt_link: None,
                config_hash: Some(snapshot.export_config_hash.clone()),
                active: false,
                credential_external_id: None,
                generated_at: Some(
                    chrono::DateTime::from_timestamp(snapshot.generated_at_unix_sec, 0)
                        .unwrap_or_else(chrono::Utc::now)
                        .to_rfc3339(),
                ),
                source: Some("classic_agent".to_string()),
                display_name: link_cfg.display_name(),
                source_key: Some(username.clone()),
                link_hash: None,
            }));
        }
        let records_count = records.len();
        let endpoint = writer.selected_endpoint().unwrap_or("n/a");
        println!(
            "phase=lk_api_write_begin contract={} endpoint={} external_node_id={} records_count={}",
            writer.active_contract(),
            endpoint,
            self.cfg.node_external_id,
            records_count
        );
        println!(
            "phase=artifacts_payload_sent node={} contract={} endpoint={} records_count={} reconcile_ready=true",
            self.cfg.node_external_id,
            writer.active_contract(),
            endpoint,
            records_count
        );
        let mut write_result = match writer.write_batch(records).await {
            Ok(result) => {
                println!(
                    "phase=lk_api_write_ok contract={} endpoint={} external_node_id={} records_count={} response_summary={{created:{},updated:{},unchanged:{},deactivated:{},failed:{}}}",
                    writer.active_contract(),
                    endpoint,
                    self.cfg.node_external_id,
                    records_count,
                    result.created,
                    result.updated,
                    result.unchanged,
                    result.deactivated,
                    result.failed
                );
                println!(
                    "phase=artifacts_payload_accepted node={} contract={} endpoint={} records_count={} reconcile_ready={}",
                    self.cfg.node_external_id,
                    writer.active_contract(),
                    endpoint,
                    records_count,
                    result.failed == 0
                );
                result
            }
            Err(err) => {
                self.db_worker_health.artifacts_status = DbWorkerSignalStatus::Degraded;
                eprintln!(
                    "phase=lk_api_write_failed contract={} endpoint={} external_node_id={} records_count={} error={}",
                    writer.active_contract(),
                    endpoint,
                    self.cfg.node_external_id,
                    records_count,
                    err
                );
                return Err(err);
            }
        };
        if export_failed > 0 {
            write_result.failed += export_failed;
            write_result.failures.extend(export_failures.clone());
        }
        if !use_full_snapshot_for_export {
            write_result.unchanged += unchanged_count;
            write_result.deactivated += removed_count;
        }

        if write_result.failed == 0 {
            persist_inventory_state(&state_path, &snapshot)?;
        }
        self.db_worker_health.artifacts_status = if write_result.failed == 0 {
            DbWorkerSignalStatus::Ok
        } else {
            DbWorkerSignalStatus::Degraded
        };
        println!(
            "phase=inventory_sync node={} inventory_counts={{credentials:{},missing:{},stale:{},removed:{}}} export_counts={{generated:{},failed:{}}} write_counts={{created:{},updated:{},unchanged:{},deactivated:{},failed:{}}}",
            self.cfg.node_external_id,
            snapshot.credentials.len(),
            delta.missing.len(),
            delta.stale.len(),
            delta.removed.len(),
            generated_links.len(),
            export_failed,
            write_result.created,
            write_result.updated,
            write_result.unchanged,
            write_result.deactivated,
            write_result.failed
        );
        if !write_result.failures.is_empty() {
            eprintln!(
                "inventory LK writer failures: {}",
                write_result.failures.join(" | ")
            );
        }

        Ok(())
    }

    async fn post_inventory_with_retry(
        &self,
        payload: &InventoryIngestPayload,
    ) -> Result<InventoryIngestAttempt, String> {
        let endpoint = derive_inventory_endpoint(&self.cfg.lk_db_dsn, &self.cfg.node_external_id)?;
        let mut backoff = INVENTORY_INGEST_INITIAL_BACKOFF;
        let mut had_retry = false;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .no_proxy()
            .build()
            .map_err(|e| format!("failed to build inventory ingest HTTP client: {e}"))?;

        for attempt in 1..=INVENTORY_INGEST_ATTEMPTS {
            let mut request = client.post(&endpoint).json(payload);
            if let Some(token) = self
                .cfg
                .lk_service_token
                .as_deref()
                .map(str::trim)
                .filter(|item| !item.is_empty())
            {
                request = request.bearer_auth(token).header("X-Internal-Agent-Token", token);
            }
            let response = request.send().await;
            match response {
                Ok(resp) if resp.status().is_success() => {
                    return Ok(InventoryIngestAttempt { had_retry });
                }
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    let field_mismatch_details = extract_contract_mismatch_detail(body.trim())
                        .unwrap_or_else(|| "none".to_string());
                    println!(
                        "phase=inventory_payload_rejected node={} status={} request_id={} idempotency_key={} field_level_errors={}",
                        self.cfg.node_external_id,
                        status.as_u16(),
                        payload.request_id,
                        payload.idempotency_key,
                        field_mismatch_details
                    );
                    let detail = format!(
                        "inventory ingest returned HTTP {} on attempt {attempt}/{INVENTORY_INGEST_ATTEMPTS}: {}",
                        status.as_u16(),
                        inventory_error_details(body.trim())
                    );
                    if status.is_server_error() && attempt < INVENTORY_INGEST_ATTEMPTS {
                        had_retry = true;
                        println!(
                            "phase=inventory_payload_retry node={} endpoint={} attempt={} backoff_sec={} reason=server_error status={}",
                            self.cfg.node_external_id,
                            endpoint,
                            attempt,
                            backoff.as_secs(),
                            status.as_u16()
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = std::cmp::min(backoff.saturating_mul(2), Duration::from_secs(30));
                        continue;
                    }
                    println!(
                        "phase=reconcile_not_ready node={} reason=inventory_delivery_failed request_id={} idempotency_key={} field_level_errors={}",
                        self.cfg.node_external_id,
                        payload.request_id,
                        payload.idempotency_key,
                        field_mismatch_details
                    );
                    return Err(detail);
                }
                Err(err) => {
                    if attempt < INVENTORY_INGEST_ATTEMPTS {
                        had_retry = true;
                        println!(
                            "phase=inventory_payload_retry node={} endpoint={} attempt={} backoff_sec={} reason=network_error error={}",
                            self.cfg.node_external_id,
                            endpoint,
                            attempt,
                            backoff.as_secs(),
                            err
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = std::cmp::min(backoff.saturating_mul(2), Duration::from_secs(30));
                        continue;
                    }
                    println!(
                        "phase=reconcile_not_ready node={} reason=inventory_delivery_failed request_id={} idempotency_key={} field_level_errors=none",
                        self.cfg.node_external_id,
                        payload.request_id,
                        payload.idempotency_key
                    );
                    return Err(format!(
                        "inventory ingest request failed after {INVENTORY_INGEST_ATTEMPTS} attempts: {err}"
                    ));
                }
            }
        }
        Err("inventory ingest retry loop exhausted".to_string())
    }


    async fn run_legacy_http_loop(&mut self) {
        self.bootstrap_register().await;
        let heartbeat_interval = self.cfg.heartbeat_interval;

        let mut poll_tick = interval(self.cfg.reconcile_interval);
        poll_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut heartbeat_tick = interval(heartbeat_interval);
        heartbeat_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut sync_report_tick = interval(Duration::from_secs(1));
        sync_report_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut backoff = Duration::from_secs(1);

        loop {
            tokio::select! {
                _ = poll_tick.tick() => {
                    match self.reconcile_once().await {
                        Ok(()) => backoff = Duration::from_secs(1),
                        Err(err) => {
                            log_error(
                                "snapshot_reconcile_failed",
                                &self.cfg.node_external_id,
                                "reconcile",
                                "failed",
                                &err,
                            );
                            tokio::time::sleep(backoff).await;
                            backoff = std::cmp::min(backoff.saturating_mul(2), Duration::from_secs(300));
                        }
                    }
                }
                _ = heartbeat_tick.tick() => {
                    self.send_heartbeat_with_retry().await;
                }
                _ = sync_report_tick.tick() => {
                    self.flush_pending_sync_reports().await;
                }
            }
        }
    }

    async fn bootstrap_register(&self) {
        let mut backoff = REGISTER_INITIAL_BACKOFF;

        loop {
            match self.send_register_once().await {
                Ok(RegisterAttemptOutcome::Registered) => {
                    println!(
                        "register succeeded for node_external_id={}",
                        self.cfg.node_external_id
                    );
                    return;
                }
                Ok(RegisterAttemptOutcome::AlreadyRegistered) => {
                    println!(
                        "register skipped: node already registered, node_external_id={}",
                        self.cfg.node_external_id
                    );
                    return;
                }
                Err(RegisterError::Temporary(detail)) => {
                    eprintln!(
                        "{}; retry in {}s",
                        BootstrapError::RegisterFailed(detail),
                        backoff.as_secs()
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff.saturating_mul(2), REGISTER_MAX_BACKOFF);
                }
                Err(RegisterError::Permanent(detail)) => {
                    eprintln!("{}", BootstrapError::RegisterFailed(detail));
                    std::process::exit(2);
                }
            }
        }
    }

    async fn reconcile_once(&mut self) -> Result<(), String> {
        let Some((snapshot, raw_body)) = self.fetch_accounts_by_node().await? else {
            return Ok(());
        };
        let node = self.cfg.node_external_id.clone();
        self.state.last_target_revision = Some(snapshot.version.clone());

        if snapshot.onboarding_state != "active" {
            let details = format!(
                "reconcile skipped: onboarding_state={}, expected=active",
                snapshot.onboarding_state
            );
            log_sync_skip(&snapshot, &details);
            self.last_apply_status = "skipped".to_string();
            self.send_sync_report(&snapshot.version, "skipped", Some(&details), None)
                .await?;
            self.metrics
                .reconcile_total
                .with_label_values(&[&node, &snapshot.version, "skipped", "onboarding_state"])
                .inc();
            log_event(
                "info",
                &snapshot.version,
                &node,
                "reconcile_skipped",
                "onboarding_state",
            );
            return Ok(());
        }

        if !snapshot.sync_required {
            let details = "reconcile skipped: sync_required=false".to_string();
            log_sync_skip(&snapshot, &details);
            self.last_apply_status = "skipped".to_string();
            self.send_sync_report(&snapshot.version, "skipped", Some(&details), None)
                .await?;
            self.metrics
                .reconcile_total
                .with_label_values(&[&node, &snapshot.version, "skipped", "reconcile_not_required"])
                .inc();
            log_event(
                "info",
                &snapshot.version,
                &node,
                "reconcile_skipped",
                "reconcile_not_required",
            );
            return Ok(());
        }

        if !validate_checksum(&snapshot, &raw_body) {
            let detail = "invalid checksum returned by LK";
            eprintln!("snapshot rejected: {detail}, version={}", snapshot.version);
            self.send_sync_report(&snapshot.version, "error", Some(detail), None)
                .await?;
            self.metrics
                .reconcile_total
                .with_label_values(&[&node, &snapshot.version, "failed", "invalid_checksum"])
                .inc();
            self.metrics
                .last_failed_reconcile
                .with_label_values(&[&node])
                .set(chrono::Utc::now().timestamp());
            log_event(
                "error",
                &snapshot.version,
                &node,
                "reconcile_failed",
                "invalid_checksum",
            );
            return Err(detail.to_string());
        }

        let runtime_accounts = fetch_active_accounts_for_runtime(&snapshot.accounts);
        let rendered = render_credentials(&runtime_accounts);
        let rendered_sha = sha256_hex(rendered.as_bytes());

        if self
            .state
            .applied_revision
            .as_deref()
            .is_some_and(|x| x == snapshot.version)
            && self.state.credentials_sha256 == rendered_sha
        {
            println!(
                "reconcile unchanged, skip rewrite/apply: version={}, checksum={}",
                snapshot.version, snapshot.checksum
            );
            self.metrics
                .reconcile_total
                .with_label_values(&[&node, &snapshot.version, "unchanged", "none"])
                .inc();
            log_event("info", &snapshot.version, &node, "reconcile_unchanged", "none");
            return Ok(());
        }

        println!(
            "reconcile changed: version={} checksum={} accounts={} enabled={}",
            snapshot.version,
            snapshot.checksum,
            snapshot.accounts.len(),
            runtime_accounts.len()
        );
        self.metrics
            .credentials_count
            .with_label_values(&[&node])
            .set(runtime_accounts.len() as i64);

        let previous_runtime_credentials = fs::read(&self.cfg.runtime_credentials_path).await.ok();
        let tmp_credentials_path = self
            .write_runtime_credentials_tmp(rendered.as_bytes())
            .await?;
        let validation_files = match self
            .validate_candidate_credentials_pipeline(tmp_credentials_path)
            .await
        {
            Ok(files) => files,
            Err(err) => return Err(err),
        };
        if let Err(err) = self
            .cleanup_validation_files(&validation_files, self.cfg.debug_preserve_temp_files, false)
            .await
        {
            return Err(err);
        }
        self.promote_runtime_credentials(&validation_files.candidate_credentials_path)
            .await?;
        println!(
            "credentials updated atomically at {}",
            self.cfg.runtime_credentials_path.display()
        );

        let apply_started = Instant::now();
        let apply_result = self.apply_runtime().await;
        let apply_result = match apply_result {
            Ok(()) => self.verify_runtime_post_apply(&rendered_sha).await,
            Err(err) => Err(err),
        };
        self.metrics
            .apply_duration_ms
            .with_label_values(&[&node])
            .set(apply_started.elapsed().as_millis() as i64);
        let apply_ok = apply_result.is_ok();
        let apply_details = match apply_result {
            Ok(_) => "runtime apply succeeded".to_string(),
            Err(e) => {
                let rollback_result = self.rollback_runtime(previous_runtime_credentials).await;
                match rollback_result {
                    Ok(()) => format!("runtime apply failed and rollback completed: {e}"),
                    Err(rollback_err) => format!(
                        "runtime apply failed: {e}; rollback failed: {rollback_err}"
                    ),
                }
            }
        };
        self.last_apply_status = if apply_ok { "ok" } else { "error" }.to_string();
        self.metrics.apply_total.with_label_values(&[
            &node,
            &snapshot.version,
            if apply_ok { "success" } else { "failed" },
            if apply_ok { "none" } else { "apply_or_verify" },
        ]).inc();
        log_event(
            if apply_ok { "info" } else { "error" },
            &snapshot.version,
            &node,
            if apply_ok { "apply_success" } else { "apply_failed" },
            if apply_ok { "none" } else { "apply_or_verify" },
        );

        if !apply_ok {
            self.metrics
                .reconcile_total
                .with_label_values(&[&node, &snapshot.version, "failed", "apply"])
                .inc();
            self.metrics
                .last_failed_reconcile
                .with_label_values(&[&node])
                .set(chrono::Utc::now().timestamp());
            log_event("error", &snapshot.version, &node, "reconcile_failed", "apply");
            self.send_sync_report(&snapshot.version, "error", Some(&apply_details), None)
                .await?;
            return Err(apply_details);
        }

        self.state = AgentState {
            applied_revision: Some(snapshot.version.clone()),
            last_target_revision: Some(snapshot.version.clone()),
            credentials_sha256: rendered_sha,
        };
        self.mark_runtime_as_primary().await?;
        persist_state(&self.cfg.agent_state_path, &self.state).await?;
        let (account_exports, link_stats) = self.batch_tt_link_reconcile(&snapshot).await?;
        println!(
            "tt-link reconcile: updated_total={} skipped_up_to_date={} skipped_disabled={} updated_reasons(empty_link={}, hash_mismatch={}, stale={})",
            link_stats.updated_total,
            link_stats.skipped_up_to_date,
            link_stats.skipped_disabled,
            link_stats.updated_empty_link,
            link_stats.updated_hash_mismatch,
            link_stats.updated_stale
        );
        for export in &account_exports {
            let error_class = if export.access_bundle_id.is_some() {
                "bundle_id_present"
            } else {
                "bundle_id_missing"
            };
            self.metrics
                .tt_link_generation_total
                .with_label_values(&[&node, &snapshot.version, "success", error_class])
                .inc();
            log_event(
                "info",
                &snapshot.version,
                &node,
                "tt_link_generated",
                error_class,
            );
        }
        self.send_sync_report(&snapshot.version, "ok", None, Some(&account_exports))
            .await?;
        self.metrics
            .reconcile_total
            .with_label_values(&[&node, &snapshot.version, "success", "none"])
            .inc();
        self.metrics
            .last_successful_reconcile
            .with_label_values(&[&node])
            .set(chrono::Utc::now().timestamp());
        log_event("info", &snapshot.version, &node, "reconcile_success", "none");

        Ok(())
    }

    async fn bootstrap_runtime_credentials(&self) -> Result<(), String> {
        let should_import = should_import_bootstrap_credentials(
            self.cfg.bootstrap_credentials_source_path.is_some(),
            fs::try_exists(&self.cfg.runtime_primary_marker_path)
                .await
                .map_err(|e| {
                    format!(
                        "failed to check runtime marker {}: {e}",
                        self.cfg.runtime_primary_marker_path.display()
                    )
                })?,
            fs::try_exists(&self.cfg.runtime_credentials_path)
                .await
                .map_err(|e| {
                    format!(
                        "failed to check runtime credentials {}: {e}",
                        self.cfg.runtime_credentials_path.display()
                    )
                })?,
        );
        if !should_import {
            if fs::try_exists(&self.cfg.runtime_primary_marker_path)
                .await
                .unwrap_or(false)
            {
                println!(
                    "runtime credentials already marked as primary, bootstrap source ignored"
                );
            }
            return Ok(());
        }

        let source_path = self
            .cfg
            .bootstrap_credentials_source_path
            .as_ref()
            .ok_or_else(|| "bootstrap source path is missing".to_string())?;
        let bootstrap_credentials = fs::read(source_path).await.map_err(|e| {
            format!(
                "failed to read bootstrap credentials {}: {e}",
                source_path.display()
            )
        })?;
        let tmp_credentials_path = self
            .write_runtime_credentials_tmp(&bootstrap_credentials)
            .await?;
        let validation_files = self
            .validate_candidate_credentials_pipeline(tmp_credentials_path)
            .await?;
        self.cleanup_validation_files(&validation_files, self.cfg.debug_preserve_temp_files, false)
            .await?;
        self.promote_runtime_credentials(&validation_files.candidate_credentials_path)
            .await?;
        self.apply_runtime().await?;
        println!(
            "bootstrap credentials imported: {} -> {}",
            source_path.display(),
            self.cfg.runtime_credentials_path.display()
        );
        Ok(())
    }

    async fn mark_runtime_as_primary(&self) -> Result<(), String> {
        if fs::try_exists(&self.cfg.runtime_primary_marker_path)
            .await
            .map_err(|e| {
                format!(
                    "failed to check runtime marker {}: {e}",
                    self.cfg.runtime_primary_marker_path.display()
                )
            })?
        {
            return Ok(());
        }

        atomic_write(&self.cfg.runtime_primary_marker_path, b"runtime_credentials_primary\n").await
    }

    async fn fetch_accounts_by_node(&self) -> Result<Option<(SyncPayload, Vec<u8>)>, String> {
        match self.lk_api.sync(&self.cfg.node_external_id).await? {
            SyncResponse::Snapshot(payload) => Ok(Some(payload)),
            SyncResponse::Conflict { details } => {
                let detail = details.trim();
                let reason = if detail.is_empty() {
                    "no details"
                } else {
                    detail
                };
                log_error(
                    "reconcile_conflict",
                    &self.cfg.node_external_id,
                    "reconcile",
                    "http_409_conflict",
                    &format!("account fetch conflict: {reason}"),
                );
                Ok(None)
            }
        }
    }

    async fn batch_tt_link_reconcile(
        &self,
        snapshot: &SyncPayload,
    ) -> Result<(Vec<AccountExportOwned>, TtLinkReconcileStats), String> {
        build_account_exports(&self.cfg, snapshot).await
    }

    async fn send_sync_report(
        &mut self,
        applied_revision: &str,
        status: &'static str,
        error: Option<&str>,
        account_exports: Option<&[AccountExportOwned]>,
    ) -> Result<(), String> {
        let report = PendingSyncReport {
            applied_revision,
            status,
            error,
            account_exports,
        };
        if let Err(err) = self.send_sync_report_payload(&report).await {
            eprintln!("sync-report failed: {err}; queued for retry");
            append_pending_sync_report(
                self.cfg
                    .pending_sync_reports_path
                    .as_ref()
                    .ok_or_else(|| "sync-report outbox is disabled in db_worker mode".to_string())?,
                &report.to_owned_payload(),
            )
            .await?;
            self.increase_sync_report_backoff();
            return Ok(());
        }

        Ok(())
    }

    async fn send_sync_report_payload(&self, report: &PendingSyncReport<'_>) -> Result<(), String> {
        let account_exports = report.account_exports.map(|items| {
            items
                .iter()
                .map(|item| AccountExportPayload {
                    external_node_id: &self.cfg.node_external_id,
                    username: &item.username,
                    external_account_id: item.external_account_id.as_deref(),
                    access_bundle_id: item.access_bundle_id.as_deref(),
                    active: item.active,
                    tt_link: &item.tt_link,
                    server_address: &item.server_address,
                    cert_domain: &item.cert_domain,
                    custom_sni: item.custom_sni.as_deref(),
                    display_name: item.display_name.as_deref(),
                    dns_servers: item.dns_servers.iter().map(String::as_str).collect(),
                    protocol: &item.protocol,
                    config_hash: &item.config_hash,
                    applied_revision: &item.applied_revision,
                })
                .collect::<Vec<_>>()
        });
        let payload = SyncReportPayload {
            contract_version: "v1",
            external_node_id: &self.cfg.node_external_id,
            applied_revision: report.applied_revision,
            last_sync_status: report.status,
            last_sync_error: report.error,
            account_exports: account_exports.as_deref(),
        };
        self.lk_api.sync_report(&payload).await?;

        println!(
            "sync-report sent: applied_revision={} status={} error={} account_exports={}",
            report.applied_revision,
            report.status,
            report.error.unwrap_or("<none>"),
            report.account_exports.map_or(0, |x| x.len())
        );
        Ok(())
    }

    async fn flush_pending_sync_reports(&mut self) {
        if Instant::now() < self.sync_report_next_retry_at {
            return;
        }

        let Some(outbox_path) = self.cfg.pending_sync_reports_path.as_ref() else {
            return;
        };
        let pending = match load_pending_sync_reports(outbox_path).await {
            Ok(items) => items,
            Err(err) => {
                eprintln!("failed to load sync-report outbox: {err}");
                self.increase_sync_report_backoff();
                return;
            }
        };
        if pending.is_empty() {
            self.reset_sync_report_backoff();
            return;
        }

        for (idx, item) in pending.iter().enumerate() {
            let report = item.as_payload();
            if let Err(err) = self.send_sync_report_payload(&report).await {
                eprintln!("sync-report retry failed: {err}");
                if let Err(persist_err) = persist_pending_sync_reports(
                    outbox_path,
                    &pending[idx..],
                )
                .await
                {
                    eprintln!("failed to persist sync-report outbox: {persist_err}");
                }
                self.increase_sync_report_backoff();
                return;
            }
        }

        if let Err(err) = persist_pending_sync_reports(outbox_path, &[]).await {
            eprintln!("failed to clear sync-report outbox: {err}");
            self.increase_sync_report_backoff();
            return;
        }
        self.reset_sync_report_backoff();
    }

    fn increase_sync_report_backoff(&mut self) {
        self.sync_report_next_retry_at = Instant::now() + self.sync_report_backoff;
        self.sync_report_backoff =
            std::cmp::min(self.sync_report_backoff.saturating_mul(2), SYNC_REPORT_MAX_BACKOFF);
    }

    fn reset_sync_report_backoff(&mut self) {
        self.sync_report_backoff = SYNC_REPORT_INITIAL_BACKOFF;
        self.sync_report_next_retry_at = Instant::now();
    }

    async fn send_heartbeat_with_retry(&self) {
        let mut backoff = HEARTBEAT_INITIAL_BACKOFF;
        for attempt in 1..=HEARTBEAT_MAX_ATTEMPTS {
            match self.send_heartbeat().await {
                Ok(()) => {
                    if let Some(metric) = &self.metrics.runtime_health_status {
                        metric
                            .with_label_values(&[&self.cfg.node_external_id])
                            .set(1);
                    }
                    return;
                }
                Err(err) => {
                    let is_last = attempt == HEARTBEAT_MAX_ATTEMPTS;
                    log_event(
                        "error",
                        self.state.applied_revision.as_deref().unwrap_or("none"),
                        &self.cfg.node_external_id,
                        "runtime_health_failed",
                        err.kind(),
                    );
                    eprintln!(
                        "heartbeat failed: kind={} attempt={}/{} detail={}",
                        err.kind(),
                        attempt,
                        HEARTBEAT_MAX_ATTEMPTS,
                        err
                    );
                    if is_last {
                        if let Some(metric) = &self.metrics.runtime_health_status {
                            metric
                                .with_label_values(&[&self.cfg.node_external_id])
                                .set(0);
                        }
                        return;
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff.saturating_mul(2), HEARTBEAT_MAX_BACKOFF);
                }
            }
        }
    }

    async fn send_heartbeat(&self) -> Result<(), HeartbeatFailure> {
        let runtime_status = match self.cfg.runtime_mode {
            RuntimeMode::DbWorker => RuntimeStatus::collect_db_worker(&self.cfg.runtime_credentials_path),
            RuntimeMode::LegacyHttp => RuntimeStatus::collect(
                self.cfg
                    .runtime_pid_path
                    .as_deref()
                    .unwrap_or_else(|| Path::new("trusttunnel.pid")),
                self.cfg
                    .runtime_process_name
                    .as_deref()
                    .unwrap_or("trusttunnel_endpoint"),
                &self.cfg.runtime_credentials_path,
            ),
        };
        let raw_health_status = match self.cfg.runtime_mode {
            RuntimeMode::DbWorker => self.db_worker_health.health_status(),
            RuntimeMode::LegacyHttp => runtime_status.health_status(),
        };
        let current_revision = self.state.applied_revision.as_deref().unwrap_or("");
        let normalized_payload = normalize_heartbeat_payload(
            current_revision,
            raw_health_status,
            &self.last_apply_status,
            &self.cfg.agent_version,
            &self.cfg.runtime_version,
            self.cfg.runtime_mode,
        );
        if let Some(metric) = &self.metrics.endpoint_process_status {
            metric
                .with_label_values(&[&self.cfg.node_external_id])
                .set(if runtime_status.alive { 1 } else { 0 });
        }
        let payload = HeartbeatPayload {
            contract_version: "v1",
            external_node_id: &self.cfg.node_external_id,
            current_revision: normalized_payload.current_revision.as_deref(),
            health_status: normalized_payload.health_status,
            stats: HeartbeatStats {
                active_clients: runtime_status.active_clients,
                cpu_percent: runtime_status.cpu_percent,
                memory_percent: runtime_status.memory_percent,
                sync_lag_sec: 0,
                last_apply_status: normalized_payload.last_apply_status,
            },
        };
        println!(
            "phase=heartbeat_sent node={} revision={} health={}",
            self.cfg.node_external_id,
            normalized_payload.current_revision.as_deref().unwrap_or("none"),
            normalized_payload.health_status
        );
        self.lk_api
            .heartbeat(&payload)
            .await
            .map_err(|err| {
                if let Some(metric) = &self.metrics.runtime_health_total {
                    metric
                        .with_label_values(&[
                            &self.cfg.node_external_id,
                            self.state.applied_revision.as_deref().unwrap_or("none"),
                            "failed",
                            err.kind(),
                        ])
                        .inc();
                }
                HeartbeatFailure::Api(err)
            })?;
        println!(
            "phase=heartbeat_accepted node={} revision={} health={}",
            self.cfg.node_external_id,
            normalized_payload.current_revision.as_deref().unwrap_or("none"),
            normalized_payload.health_status
        );
        if let Some(metric) = &self.metrics.runtime_health_total {
            metric
                .with_label_values(&[
                    &self.cfg.node_external_id,
                    self.state.applied_revision.as_deref().unwrap_or("none"),
                    "success",
                    "none",
                ])
                .inc();
        }
        log_event(
            "info",
            self.state.applied_revision.as_deref().unwrap_or("none"),
            &self.cfg.node_external_id,
            "runtime_health_success",
            "none",
        );

        println!(
            "heartbeat sent for node_external_id={}",
            self.cfg.node_external_id
        );
        Ok(())
    }

    async fn send_register_once(&self) -> Result<RegisterAttemptOutcome, RegisterError> {
        let payload = OnboardingPayload::from_metadata(
            &self.node_metadata,
            &self.cfg.agent_version,
            &self.cfg.runtime_version,
        );
        payload
            .validate_compatibility()
            .map_err(RegisterError::Permanent)?;
        let response = self
            .lk_api
            .register(&payload)
            .await
            .map_err(|err| RegisterError::Temporary(err.to_string()))?;

        let status = response.status();
        if status.is_success() {
            return Ok(RegisterAttemptOutcome::Registered);
        }

        if is_idempotent_register_status(status) {
            return Ok(RegisterAttemptOutcome::AlreadyRegistered);
        }

        let response_body = response
            .text()
            .await
            .unwrap_or_else(|err| format!("failed to read response body: {err}"));
        let endpoint = format!(
            "{}{}",
            self.cfg
                .lk_base_url
                .as_deref()
                .unwrap_or_default()
                .trim_end_matches('/'),
            DEFAULT_REGISTER_PATH
        );
        let payload_keys = payload_key_list(&payload);
        let reason_summary = summarize_register_reason(status, &response_body);
        let details = format!(
            "register failure: status={status} endpoint={endpoint} payload_keys={payload_keys} reason={reason_summary} response_body={response_body}"
        );

        if is_temporary_http_status(status) {
            return Err(RegisterError::Temporary(format!(
                "register request returned temporary HTTP {status}; {details}"
            )));
        }

        Err(RegisterError::Permanent(format!(
            "register request returned HTTP {status}; {details}"
        )))
    }

    async fn apply_runtime(&self) -> Result<(), String> {
        let Some(cmd) = &self.cfg.apply_cmd else {
            println!("runtime apply command is not set, skip runtime apply");
            return Ok(());
        };

        let status = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .status()
            .await
            .map_err(|e| format!("failed to execute TRUSTTUNNEL_APPLY_CMD: {e}"))?;

        if !status.success() {
            return Err(format!("TRUSTTUNNEL_APPLY_CMD exited with status {status}"));
        }

        println!("runtime apply finished successfully");
        Ok(())
    }

    async fn write_runtime_credentials_tmp(&self, data: &[u8]) -> Result<PathBuf, String> {
        let parent = self.workspace.root();
        fs::create_dir_all(parent).await.map_err(|e| {
            format!(
                "failed to create runtime directory {}: {e}",
                parent.display()
            )
        })?;
        let tmp_path = self.workspace.make_temp_path(
            ArtifactKind::CandidateCredentials,
            self.cfg
                .runtime_credentials_path
                .file_name()
                .and_then(|x| x.to_str())
                .unwrap_or("credentials"),
        );
        fs::write(&tmp_path, data)
            .await
            .map_err(|e| format!("failed to write candidate credentials {}: {e}", tmp_path.display()))?;
        let candidate_raw = String::from_utf8_lossy(data);
        let candidate_written_count = parse_access_artifacts(&candidate_raw)
            .map(|artifacts| artifacts.len())
            .unwrap_or_default();
        println!(
            "phase=candidate_credentials_written node={} candidate_path={} candidate_written_count={} candidate_has_client_entries={}",
            self.cfg.node_external_id,
            tmp_path.display(),
            candidate_written_count,
            candidate_written_count > 0
        );

        Ok(tmp_path)
    }

    async fn write_temp_endpoint_config_for_candidate(
        &self,
        candidate_path: &Path,
    ) -> Result<PathBuf, String> {
        let settings_path = self.resolve_runtime_path(&self.cfg.trusttunnel_config_file);
        let settings_content = std::fs::read_to_string(&settings_path).map_err(|e| {
            format!(
                "failed to read endpoint settings {}: {e}",
                settings_path.display()
            )
        })?;
        let mut settings_doc = settings_content.parse::<toml_edit::Document>().map_err(|e| {
            format!(
                "failed to parse endpoint settings {}: {e}",
                settings_path.display()
            )
        })?;
        let candidate_path_str = path_to_string(candidate_path)?.to_string();
        settings_doc["credentials_file"] = value(candidate_path_str);

        let parent = self.workspace.root();
        fs::create_dir_all(parent).await.map_err(|e| {
            format!(
                "failed to create runtime directory {}: {e}",
                parent.display()
            )
        })?;
        let temp_config_path = self.workspace.make_temp_path(
            ArtifactKind::CandidateConfig,
            settings_path
                .file_name()
                .and_then(|x| x.to_str())
                .unwrap_or("vpn"),
        );
        fs::write(&temp_config_path, settings_doc.to_string())
            .await
            .map_err(|e| {
                format!(
                    "failed to write temp endpoint settings {}: {e}",
                    temp_config_path.display()
                )
            })?;
        Ok(temp_config_path)
    }

    fn validate_candidate_credentials_syntax(&self, candidate_path: &Path) -> Result<(), String> {
        let raw = std::fs::read_to_string(candidate_path).map_err(|e| {
            format!(
                "failed to read candidate credentials {}: {e}",
                candidate_path.display()
            )
        })?;
        parse_candidate_credentials_for_validation(&raw).map(|_| ())
    }

    fn validate_endpoint_settings_reference(
        &self,
        temp_config_path: &Path,
        candidate_path: &Path,
    ) -> Result<(), String> {
        let settings_content = std::fs::read_to_string(temp_config_path).map_err(|e| {
            format!(
                "failed to read temp endpoint settings {}: {e}",
                temp_config_path.display()
            )
        })?;
        let parsed_doc = settings_content.parse::<toml_edit::Document>().map_err(|e| {
            format!(
                "failed to parse temp endpoint settings document {}: {e}",
                temp_config_path.display()
            )
        })?;
        let configured_credentials = parsed_doc
            .get("credentials_file")
            .and_then(toml_edit::Item::as_str)
            .ok_or_else(|| {
                format!(
                    "temp endpoint settings {} does not contain string field credentials_file",
                    temp_config_path.display()
                )
            })?;
        let candidate_path_str = path_to_string(candidate_path)?;
        if configured_credentials != candidate_path_str {
            return Err(format!(
                "temp endpoint settings {} points credentials_file={} instead of candidate_path={}",
                temp_config_path.display(),
                configured_credentials,
                candidate_path.display()
            ));
        }
        Ok(())
    }

    async fn validate_endpoint_runtime_entrypoint(
        &self,
        temp_config_path: &Path,
        candidate_path: &Path,
    ) -> Result<(), String> {
        let raw_candidate = std::fs::read_to_string(candidate_path).map_err(|e| {
            format!(
                "failed to read candidate credentials {}: {e}",
                candidate_path.display()
            )
        })?;
        let usernames = runtime_validation_usernames_from_raw_toml(&raw_candidate).map_err(|e| {
            format!(
                "validation_path=runtime_entrypoint failed to derive usernames from candidate {}: {e}",
                candidate_path.display()
            )
        })?;
        println!(
            "phase=candidate_credentials_format_detected node={} format=[[client]] parser_path=shared_credentials_parser candidate_path={} usernames_detected={}",
            self.cfg.node_external_id,
            candidate_path.display(),
            usernames.len()
        );
        let selected_usernames = select_runtime_validation_usernames(
            usernames,
            self.cfg.runtime_validation_min_users,
            self.cfg.runtime_validation_max_users,
        )
        .map_err(|e| {
            format!(
                "validation_path=runtime_entrypoint failed to choose validation usernames for candidate {}: {e}",
                candidate_path.display()
            )
        })?;
        let hosts_path =
            resolve_runtime_path(&self.cfg.trusttunnel_runtime_dir, &self.cfg.trusttunnel_hosts_file);
        if selected_usernames.limited {
            println!(
                "phase=runtime_validation_user_limit_applied node={} strategy=sorted_take_first total_usernames={} selected_usernames={} min_users={} max_users={} candidate_path={}",
                self.cfg.node_external_id,
                selected_usernames.total,
                selected_usernames.selected.len(),
                self.cfg.runtime_validation_min_users,
                self.cfg.runtime_validation_max_users,
                candidate_path.display()
            );
        }

        let mut failures = Vec::new();
        for username in &selected_usernames.selected {
            if let Err(error) = self
                .validate_endpoint_runtime_entrypoint_for_username(
                    temp_config_path,
                    candidate_path,
                    &hosts_path,
                    username,
                )
                .await
            {
                failures.push(format!("username={username}: {error}"));
            }
        }
        if !failures.is_empty() {
            return Err(format!(
                "endpoint runtime validation failed for {}/{} selected usernames: {}",
                failures.len(),
                selected_usernames.selected.len(),
                failures.join(" | ")
            ));
        }

        Ok(())
    }

    async fn validate_endpoint_runtime_entrypoint_for_username(
        &self,
        temp_config_path: &Path,
        candidate_path: &Path,
        hosts_path: &Path,
        username: &str,
    ) -> Result<(), String> {
        let mut command = Command::new(&self.cfg.endpoint_binary);
        command
            .arg(temp_config_path)
            .arg(hosts_path)
            .arg("--client_config")
            .arg(username)
            .arg("--format")
            .arg("deeplink")
            .arg("--address")
            .arg("127.0.0.1:443");

        let output = tokio::time::timeout(Duration::from_secs(5), command.output())
            .await
            .map_err(|_| {
                format!(
                    "endpoint runtime validation timed out for binary={} settings={} hosts={} username={}",
                    self.cfg.endpoint_binary,
                    temp_config_path.display(),
                    hosts_path.display(),
                    username,
                )
            })?
            .map_err(|e| {
                format!(
                    "failed to execute endpoint runtime validation binary={} settings={} hosts={} username={}: {e}",
                    self.cfg.endpoint_binary,
                    temp_config_path.display(),
                    hosts_path.display(),
                    username,
                )
            })?;
        let stdout = String::from_utf8(output.stdout)
            .map_err(|e| format!("endpoint runtime validation stdout is not valid UTF-8: {e}"))?;
        let stderr = String::from_utf8(output.stderr)
            .map_err(|e| format!("endpoint runtime validation stderr is not valid UTF-8: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "status={} settings={} hosts={} candidate={} stdout={} stderr={}",
                output.status,
                temp_config_path.display(),
                hosts_path.display(),
                candidate_path.display(),
                stdout.trim(),
                stderr.trim()
            ));
        }
        if !stdout.trim().starts_with("tt://") {
            return Err(format!(
                "invalid client config output for candidate={}: stdout={} stderr={}",
                candidate_path.display(),
                stdout.trim(),
                stderr.trim()
            ));
        }
        Ok(())
    }

    async fn cleanup_validation_files(
        &self,
        files: &CandidateValidationFiles,
        keep_files: bool,
        remove_candidate: bool,
    ) -> Result<(), String> {
        if keep_files {
            println!(
                "phase=validation_debug_preserved node={} candidate_credentials={} temp_config={}",
                self.cfg.node_external_id,
                files.candidate_credentials_path.display(),
                files.temp_config_path.display()
            );
            return Ok(());
        }
        if fs::try_exists(&files.temp_config_path)
            .await
            .map_err(|e| {
                format!(
                    "failed to check temp endpoint settings {}: {e}",
                    files.temp_config_path.display()
                )
            })?
        {
            fs::remove_file(&files.temp_config_path).await.map_err(|e| {
                format!(
                    "failed to remove temp endpoint settings {}: {e}",
                    files.temp_config_path.display()
                )
            })?;
        }
        if remove_candidate {
            if fs::try_exists(&files.candidate_credentials_path)
                .await
                .map_err(|e| {
                    format!(
                        "failed to check candidate credentials {}: {e}",
                        files.candidate_credentials_path.display()
                    )
                })?
            {
                fs::remove_file(&files.candidate_credentials_path)
                    .await
                    .map_err(|e| {
                        format!(
                            "failed to remove candidate credentials {}: {e}",
                            files.candidate_credentials_path.display()
                        )
                    })?;
            }
        }
        Ok(())
    }

    async fn validate_candidate_credentials_pipeline(
        &self,
        candidate_path: PathBuf,
    ) -> Result<CandidateValidationFiles, String> {
        println!(
            "phase=candidate_credentials_write node={} candidate_path={}",
            self.cfg.node_external_id,
            candidate_path.display()
        );
        println!(
            "phase=credentials_validation_begin node={} parser=parse_access_artifacts stage=candidate_credentials_syntax file={}",
            self.cfg.node_external_id,
            candidate_path.display()
        );
        println!(
            "phase=credentials_validation_mode node={} validation_mode={}",
            self.cfg.node_external_id,
            if self.cfg.syntax_validation_diagnostic_only {
                "diagnostic_only"
            } else {
                "fail_fast"
            }
        );
        let syntax_precheck_result = self.validate_candidate_credentials_syntax(&candidate_path);
        if let Err(err) = &syntax_precheck_result {
            println!(
                "phase=credentials_validation_failed node={} parser=parse_access_artifacts stage=candidate_credentials_syntax validation_path=syntax_precheck file={} diagnostic_only={} error={}",
                self.cfg.node_external_id,
                candidate_path.display(),
                self.cfg.syntax_validation_diagnostic_only,
                err
            );
            if !self.cfg.syntax_validation_diagnostic_only {
                return Err(format!(
                    "phase=credentials_validation_failed node={} parser=parse_access_artifacts stage=candidate_credentials_syntax validation_path=syntax_precheck file={}: {err}",
                    self.cfg.node_external_id,
                    candidate_path.display()
                ));
            }
        } else {
            println!(
                "phase=credentials_validation_ok node={} parser=parse_access_artifacts stage=candidate_credentials_syntax validation_path=syntax_precheck file={}",
                self.cfg.node_external_id,
                candidate_path.display()
            );
            println!(
                "phase=candidate_toml_valid node={} candidate_path={} validation_path=syntax_precheck",
                self.cfg.node_external_id,
                candidate_path.display()
            );
        }

        let temp_config_path = self
            .write_temp_endpoint_config_for_candidate(&candidate_path)
            .await
            .map_err(|e| format!("phase=temp_config_invalid node={} candidate_path={}: {e}", self.cfg.node_external_id, candidate_path.display()))?;
        println!(
            "phase=temp_config_rendered node={} temp_config_path={} candidate_path={}",
            self.cfg.node_external_id,
            temp_config_path.display(),
            candidate_path.display()
        );

        println!(
            "phase=settings_reference_check_begin node={} parser=toml_edit::Document stage=settings_reference_check file={}",
            self.cfg.node_external_id,
            temp_config_path.display()
        );
        self.validate_endpoint_settings_reference(&temp_config_path, &candidate_path)
            .map_err(|e| {
                format!(
                    "phase=settings_reference_check_failed node={} parser=toml_edit::Document stage=settings_reference_check temp_config_path={} candidate_path={}: {e}",
                    self.cfg.node_external_id,
                    temp_config_path.display(),
                    candidate_path.display()
                )
            })?;
        println!(
            "phase=settings_reference_check_ok node={} parser=toml_edit::Document stage=settings_reference_check file={}",
            self.cfg.node_external_id,
            temp_config_path.display()
        );

        println!(
            "phase=runtime_startup_validation_begin node={} parser=trusttunnel_endpoint --client_config stage=runtime_startup_validation temp_config_path={} hosts_path={}",
            self.cfg.node_external_id,
            temp_config_path.display(),
            resolve_runtime_path(&self.cfg.trusttunnel_runtime_dir, &self.cfg.trusttunnel_hosts_file).display()
        );
        let runtime_result = self
            .validate_endpoint_runtime_entrypoint(&temp_config_path, &candidate_path)
            .await;
        if self.cfg.validation_strict_mode {
            let parser_ok = syntax_precheck_result.is_ok();
            let runtime_ok = runtime_result.is_ok();
            if parser_ok != runtime_ok {
                let parser_outcome = syntax_precheck_result
                    .as_ref()
                    .map(|_| "ok".to_string())
                    .unwrap_or_else(|e| format!("failed: {e}"));
                let runtime_outcome = runtime_result
                    .as_ref()
                    .map(|_| "ok".to_string())
                    .unwrap_or_else(|e| format!("failed: {e}"));
                log_error(
                    self.state.applied_revision.as_deref().unwrap_or("none"),
                    &self.cfg.node_external_id,
                    "credentials_validation_mismatch",
                    "parser_runtime_mismatch_strict",
                    &format!(
                        "strict mode mismatch detected: syntax_precheck={} runtime_entrypoint={} candidate_path={} temp_config_path={}",
                        parser_outcome,
                        runtime_outcome,
                        candidate_path.display(),
                        temp_config_path.display()
                    ),
                );
            }
        }
        runtime_result.map_err(|e| {
            format!(
                "phase=runtime_startup_validation_failed node={} parser=trusttunnel_endpoint --client_config stage=runtime_startup_validation validation_path=runtime_entrypoint temp_config_path={} candidate_path={}: {e}",
                self.cfg.node_external_id,
                temp_config_path.display(),
                candidate_path.display()
            )
        })?;
        println!(
            "phase=runtime_startup_validation_ok node={} parser=trusttunnel_endpoint --client_config stage=runtime_startup_validation temp_config_path={} candidate_path={}",
            self.cfg.node_external_id,
            temp_config_path.display(),
            candidate_path.display()
        );

        println!(
            "phase=endpoint_runtime_validation_ok node={} temp_config_path={} candidate_path={}",
            self.cfg.node_external_id,
            temp_config_path.display(),
            candidate_path.display()
        );
        println!(
            "phase=export_readiness_ok node={} candidate_path={} temp_config_path={}",
            self.cfg.node_external_id,
            candidate_path.display(),
            temp_config_path.display()
        );

        Ok(CandidateValidationFiles {
            candidate_credentials_path: candidate_path,
            temp_config_path,
        })
    }

    async fn promote_runtime_credentials(&self, candidate_path: &Path) -> Result<(), String> {
        fs::rename(candidate_path, &self.cfg.runtime_credentials_path)
            .await
            .map_err(|e| {
                format!(
                    "failed to atomically rename {} -> {}: {e}",
                    candidate_path.display(),
                    self.cfg.runtime_credentials_path.display()
                )
            })
    }

    async fn verify_runtime_post_apply(&self, expected_revision: &str) -> Result<(), String> {
        let actual_credentials = fs::read(&self.cfg.runtime_credentials_path)
            .await
            .map_err(|e| {
                format!(
                    "failed to read runtime credentials {}: {e}",
                    self.cfg.runtime_credentials_path.display()
                )
            })?;
        let actual_revision = sha256_hex(&actual_credentials);
        if actual_revision != expected_revision {
            return Err(format!(
                "runtime revision mismatch: expected={expected_revision}, actual={actual_revision}"
            ));
        }

        Ok(())
    }

    async fn rollback_runtime(&self, previous_runtime_credentials: Option<Vec<u8>>) -> Result<(), String> {
        match previous_runtime_credentials {
            Some(data) => {
                atomic_write(&self.cfg.runtime_credentials_path, &data).await?;
            }
            None => {
                if fs::try_exists(&self.cfg.runtime_credentials_path)
                    .await
                    .map_err(|e| {
                        format!(
                            "failed to check runtime credentials presence {}: {e}",
                            self.cfg.runtime_credentials_path.display()
                        )
                    })?
                {
                    fs::remove_file(&self.cfg.runtime_credentials_path)
                        .await
                        .map_err(|e| {
                            format!(
                                "failed to remove runtime credentials {} during rollback: {e}",
                                self.cfg.runtime_credentials_path.display()
                            )
                        })?;
                }
            }
        }

        self.apply_runtime()
            .await
            .map_err(|e| format!("failed to re-apply runtime after rollback: {e}"))?;
        Ok(())
    }

    fn resolve_runtime_path(&self, path: &Path) -> PathBuf {
        resolve_runtime_path(&self.cfg.trusttunnel_runtime_dir, path)
    }
}

#[derive(Debug)]
enum HeartbeatFailure {
    Api(legacy::lk_api::HeartbeatError),
}

impl HeartbeatFailure {
    fn kind(&self) -> &'static str {
        match self {
            HeartbeatFailure::Api(err) => err.kind(),
        }
    }
}

impl std::fmt::Display for HeartbeatFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeartbeatFailure::Api(err) => write!(f, "{err}"),
        }
    }
}

struct RuntimeStatus {
    alive: bool,
    metrics_available: bool,
    active_clients: u64,
    cpu_percent: f64,
    memory_percent: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DbWorkerSignalStatus {
    Unknown,
    Ok,
    Degraded,
    Disabled,
}

impl DbWorkerSignalStatus {
    fn is_disabled(self) -> bool {
        matches!(self, Self::Disabled)
    }
}

#[derive(Clone, Debug)]
struct DbWorkerHealthState {
    inventory_status: DbWorkerSignalStatus,
    artifacts_status: DbWorkerSignalStatus,
    candidate_validation_valid: bool,
    runtime_prerequisites_valid: bool,
}

impl Default for DbWorkerHealthState {
    fn default() -> Self {
        Self {
            inventory_status: DbWorkerSignalStatus::Unknown,
            artifacts_status: DbWorkerSignalStatus::Unknown,
            candidate_validation_valid: true,
            runtime_prerequisites_valid: true,
        }
    }
}

impl DbWorkerHealthState {
    fn health_status(&self) -> &'static str {
        if !self.runtime_prerequisites_valid
            || !self.candidate_validation_valid
            || self.inventory_status.is_disabled()
            || self.artifacts_status.is_disabled()
        {
            return "disabled";
        }
        if matches!(self.inventory_status, DbWorkerSignalStatus::Ok)
            && matches!(self.artifacts_status, DbWorkerSignalStatus::Ok)
        {
            return "ok";
        }
        "degraded"
    }
}

struct AgentMetrics {
    registry: Registry,
    reconcile_total: IntCounterVec,
    sidecar_sync_pass_total: IntCounterVec,
    sidecar_sync_item_total: IntCounterVec,
    tt_link_generation_total: IntCounterVec,
    runtime_health_total: Option<IntCounterVec>,
    apply_total: IntCounterVec,
    last_successful_reconcile: IntGaugeVec,
    last_failed_reconcile: IntGaugeVec,
    apply_duration_ms: IntGaugeVec,
    credentials_count: IntGaugeVec,
    runtime_health_status: Option<IntGaugeVec>,
    endpoint_process_status: Option<IntGaugeVec>,
}

impl AgentMetrics {
    fn new(node: &str) -> Result<Self, String> {
        let registry = Registry::new();
        let reconcile_total = IntCounterVec::new(
            Opts::new("classic_agent_reconcile_total", "Total sync attempts by status"),
            &["node", "revision", "status", "error_class"],
        )
        .map_err(|e| format!("failed to create reconcile_total metric: {e}"))?;
        let sidecar_sync_pass_total = IntCounterVec::new(
            Opts::new(
                "classic_agent_sidecar_sync_pass_total",
                "Total sidecar sync passes by status",
            ),
            &["node", "pass", "status"],
        )
        .map_err(|e| format!("failed to create sidecar_sync_pass_total metric: {e}"))?;
        let sidecar_sync_item_total = IntCounterVec::new(
            Opts::new(
                "classic_agent_sidecar_sync_item_total",
                "Total sidecar sync item outcomes",
            ),
            &["node", "pass", "outcome"],
        )
        .map_err(|e| format!("failed to create sidecar_sync_item_total metric: {e}"))?;
        let runtime_health_total = IntCounterVec::new(
            Opts::new(
                "classic_agent_runtime_health_total",
                "Total heartbeat delivery attempts by status",
            ),
            &["node", "revision", "status", "error_class"],
        )
        .map_err(|e| format!("failed to create runtime_health_total metric: {e}"))?;
        let tt_link_generation_total = IntCounterVec::new(
            Opts::new(
                "classic_agent_tt_link_generation_total",
                "Total TT-link generation events by status",
            ),
            &["node", "revision", "status", "error_class"],
        )
        .map_err(|e| format!("failed to create tt_link_generation_total metric: {e}"))?;
        let apply_total = IntCounterVec::new(
            Opts::new("classic_agent_apply_total", "Total apply attempts by status"),
            &["node", "revision", "status", "error_class"],
        )
        .map_err(|e| format!("failed to create apply_total metric: {e}"))?;
        let last_successful_reconcile = IntGaugeVec::new(
            Opts::new(
                "classic_agent_last_successful_reconcile_timestamp_seconds",
                "Unix timestamp of the latest successful reconcile",
            ),
            &["node"],
        )
        .map_err(|e| format!("failed to create last_successful_reconcile metric: {e}"))?;
        let last_failed_reconcile = IntGaugeVec::new(
            Opts::new(
                "classic_agent_last_failed_reconcile_timestamp_seconds",
                "Unix timestamp of the latest failed reconcile",
            ),
            &["node"],
        )
        .map_err(|e| format!("failed to create last_failed_reconcile metric: {e}"))?;
        let apply_duration_ms = IntGaugeVec::new(
            Opts::new(
                "classic_agent_apply_duration_milliseconds",
                "Duration of the latest apply attempt in milliseconds",
            ),
            &["node"],
        )
        .map_err(|e| format!("failed to create apply_duration metric: {e}"))?;
        let credentials_count = IntGaugeVec::new(
            Opts::new(
                "classic_agent_credentials_count",
                "Number of active credentials currently rendered",
            ),
            &["node"],
        )
        .map_err(|e| format!("failed to create credentials_count metric: {e}"))?;
        let runtime_health_status = IntGaugeVec::new(
            Opts::new(
                "classic_agent_runtime_health_status",
                "Runtime heartbeat health status (1=accepted, 0=degraded)",
            ),
            &["node"],
        )
        .map_err(|e| format!("failed to create runtime_health_status metric: {e}"))?;
        let endpoint_process_status = IntGaugeVec::new(
            Opts::new(
                "classic_agent_endpoint_process_status",
                "Endpoint process liveness status (1=alive, 0=not_alive)",
            ),
            &["node"],
        )
        .map_err(|e| format!("failed to create endpoint_process_status metric: {e}"))?;

        registry
            .register(Box::new(reconcile_total.clone()))
            .map_err(|e| format!("failed to register reconcile_total metric: {e}"))?;
        registry
            .register(Box::new(sidecar_sync_pass_total.clone()))
            .map_err(|e| format!("failed to register sidecar_sync_pass_total metric: {e}"))?;
        registry
            .register(Box::new(sidecar_sync_item_total.clone()))
            .map_err(|e| format!("failed to register sidecar_sync_item_total metric: {e}"))?;
        registry
            .register(Box::new(tt_link_generation_total.clone()))
            .map_err(|e| format!("failed to register tt_link_generation_total metric: {e}"))?;
        registry
            .register(Box::new(runtime_health_total.clone()))
            .map_err(|e| format!("failed to register runtime_health_total metric: {e}"))?;
        registry
            .register(Box::new(apply_total.clone()))
            .map_err(|e| format!("failed to register apply_total metric: {e}"))?;
        registry
            .register(Box::new(last_successful_reconcile.clone()))
            .map_err(|e| format!("failed to register last_successful_reconcile metric: {e}"))?;
        registry
            .register(Box::new(last_failed_reconcile.clone()))
            .map_err(|e| format!("failed to register last_failed_reconcile metric: {e}"))?;
        registry
            .register(Box::new(apply_duration_ms.clone()))
            .map_err(|e| format!("failed to register apply_duration metric: {e}"))?;
        registry
            .register(Box::new(credentials_count.clone()))
            .map_err(|e| format!("failed to register credentials_count metric: {e}"))?;
        registry
            .register(Box::new(runtime_health_status.clone()))
            .map_err(|e| format!("failed to register runtime_health_status metric: {e}"))?;
        registry
            .register(Box::new(endpoint_process_status.clone()))
            .map_err(|e| format!("failed to register endpoint_process_status metric: {e}"))?;

        let labels = &[node];
        last_successful_reconcile.with_label_values(labels).set(0);
        last_failed_reconcile.with_label_values(labels).set(0);
        apply_duration_ms.with_label_values(labels).set(0);
        credentials_count.with_label_values(labels).set(0);
        runtime_health_status.with_label_values(labels).set(0);
        endpoint_process_status.with_label_values(labels).set(0);
        for pass in ["bootstrap", "reconcile"] {
            sidecar_sync_pass_total
                .with_label_values(&[node, pass, "ok"])
                .inc_by(0);
            sidecar_sync_item_total
                .with_label_values(&[node, pass, "found"])
                .inc_by(0);
        }

        Ok(Self {
            registry,
            reconcile_total,
            sidecar_sync_pass_total,
            sidecar_sync_item_total,
            tt_link_generation_total,
            runtime_health_total: Some(runtime_health_total),
            apply_total,
            last_successful_reconcile,
            last_failed_reconcile,
            apply_duration_ms,
            credentials_count,
            runtime_health_status: Some(runtime_health_status),
            endpoint_process_status: Some(endpoint_process_status),
        })
    }
}

#[derive(Clone, Debug)]
struct PendingSyncReport<'a> {
    applied_revision: &'a str,
    status: &'a str,
    error: Option<&'a str>,
    account_exports: Option<&'a [AccountExportOwned]>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct PendingSyncReportOwned {
    applied_revision: String,
    status: String,
    error: Option<String>,
    #[serde(default)]
    account_exports: Vec<AccountExportOwned>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct AccountExportOwned {
    username: String,
    external_account_id: Option<String>,
    access_bundle_id: Option<String>,
    active: bool,
    tt_link: String,
    server_address: String,
    cert_domain: String,
    custom_sni: Option<String>,
    display_name: Option<String>,
    dns_servers: Vec<String>,
    protocol: String,
    config_hash: String,
    applied_revision: String,
}

#[derive(Default)]
struct TtLinkReconcileStats {
    updated_total: usize,
    updated_empty_link: usize,
    updated_hash_mismatch: usize,
    updated_stale: usize,
    skipped_up_to_date: usize,
    skipped_disabled: usize,
}

impl PendingSyncReport<'_> {
    fn to_owned_payload(&self) -> PendingSyncReportOwned {
        PendingSyncReportOwned {
            applied_revision: self.applied_revision.to_string(),
            status: self.status.to_string(),
            error: self.error.map(ToString::to_string),
            account_exports: self.account_exports.unwrap_or_default().to_vec(),
        }
    }
}

impl PendingSyncReportOwned {
    fn as_payload(&self) -> PendingSyncReport<'_> {
        PendingSyncReport {
            applied_revision: &self.applied_revision,
            status: &self.status,
            error: self.error.as_deref(),
            account_exports: (!self.account_exports.is_empty()).then_some(&self.account_exports),
        }
    }
}

struct NormalizedHeartbeatPayload {
    current_revision: Option<String>,
    health_status: &'static str,
    last_apply_status: &'static str,
}

fn normalize_heartbeat_payload(
    current_revision: &str,
    health_status: &str,
    last_apply_status: &str,
    agent_version: &str,
    runtime_version: &str,
    runtime_mode: RuntimeMode,
) -> NormalizedHeartbeatPayload {
    let _ = normalize_required_string(agent_version, "unknown");
    let _ = normalize_required_string(runtime_version, "unknown");
    NormalizedHeartbeatPayload {
        current_revision: normalize_optional_revision(current_revision),
        health_status: normalize_health_status(health_status, runtime_mode),
        last_apply_status: normalize_last_apply_status(last_apply_status),
    }
}

fn normalize_optional_revision(value: &str) -> Option<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return None;
    }
    Some(normalized.to_string())
}

fn normalize_last_apply_status(value: &str) -> &'static str {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "ok" | "success" | "runtime apply succeeded" => "ok",
        "pending" | "unknown" => "pending",
        "skipped" => "skipped",
        "" => "pending",
        _ => "error",
    }
}

fn normalize_required_string(value: &str, fallback: &str) -> String {
    let normalized = value.trim();
    if normalized.is_empty() {
        return fallback.to_string();
    }
    normalized.to_string()
}

fn normalize_health_status(raw_status: &str, runtime_mode: RuntimeMode) -> &'static str {
    let status = raw_status.trim().to_ascii_lowercase();
    match runtime_mode {
        RuntimeMode::LegacyHttp => match status.as_str() {
            "healthy" | "alive" | "ready" | "ok" => "ok",
            "warning" | "degraded" | "limited" => "degraded",
            "dead" | "stopped" | "offline" | "fatal" | "failed" | "disabled" => "disabled",
            _ => "degraded",
        },
        RuntimeMode::DbWorker => match status.as_str() {
            "healthy" | "alive" | "ready" | "ok" | "success" => "ok",
            "warning" | "degraded" | "limited" | "dead" | "stopped" | "offline" | "failed" => {
                "degraded"
            }
            "fatal" | "disabled" => "disabled",
            _ => "degraded",
        },
    }
}

impl RuntimeStatus {
    fn collect(runtime_pid_path: &Path, process_name: &str, credentials_file: &Path) -> Self {
        let pid = read_pid(runtime_pid_path).or_else(|| find_pid_by_name(process_name));
        let alive = pid.is_some_and(is_pid_alive);
        let active_clients = count_active_clients(credentials_file).unwrap_or(0);

        if let Some(pid) = pid {
            if let (Some(cpu_percent), Some(memory_percent)) =
                (read_cpu_percent(pid), read_memory_percent(pid))
            {
                return Self {
                    alive,
                    metrics_available: true,
                    active_clients,
                    cpu_percent,
                    memory_percent,
                };
            }
        }

        Self {
            alive,
            metrics_available: false,
            active_clients,
            cpu_percent: 0.0,
            memory_percent: 0.0,
        }
    }

    fn health_status(&self) -> &'static str {
        if !self.alive {
            return "dead";
        }
        if self.metrics_available {
            return "healthy";
        }
        "degraded"
    }

    fn collect_db_worker(credentials_file: &Path) -> Self {
        Self {
            alive: true,
            metrics_available: false,
            active_clients: count_active_clients(credentials_file).unwrap_or(0),
            cpu_percent: 0.0,
            memory_percent: 0.0,
        }
    }
}

async fn serve_metrics(metrics: Arc<AgentMetrics>, address: SocketAddr) -> Result<(), String> {
    let listener = TcpListener::bind(address)
        .await
        .map_err(|e| format!("failed to bind metrics listener {address}: {e}"))?;
    log_event("info", "metrics_listener_started", "unknown", "started", "none");
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|e| format!("failed to accept metrics connection: {e}"))?;
        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            let mut buf = [0_u8; 1024];
            let read = match stream.read(&mut buf).await {
                Ok(size) => size,
                Err(_) => return,
            };
            if read == 0 {
                return;
            }

            let request = String::from_utf8_lossy(&buf[..read]);
            let first_line = request.lines().next().unwrap_or_default();
            let response = if first_line.starts_with("GET /metrics") {
                let encoder = TextEncoder::new();
                let metric_families = metrics.registry.gather();
                let mut body = Vec::new();
                match encoder.encode(&metric_families, &mut body) {
                    Ok(()) => format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        String::from_utf8_lossy(&body)
                    ),
                    Err(_) => "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n".to_string(),
                }
            } else {
                "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n".to_string()
            };
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

fn log_event(level: &str, revision: &str, node: &str, status: &str, error_class: &str) {
    let payload = serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "level": level,
        "revision": revision,
        "node": node,
        "status": status,
        "error_class": error_class,
    });
    println!("{payload}");
}

fn log_error(revision: &str, node: &str, status: &str, error_class: &str, error: &str) {
    let payload = serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "level": "error",
        "revision": revision,
        "node": node,
        "status": status,
        "error_class": error_class,
        "message": error,
    });
    eprintln!("{payload}");
}

#[tokio::main]
async fn main() {
    let cfg = match Config::from_env() {
        Ok(cfg) => cfg,
        Err(err) => {
            log_error("unknown", "classic_agent", "config", "invalid_env", &err);
            std::process::exit(2);
        }
    };

    log_event(
        "info",
        "unknown",
        &cfg.node_external_id,
        "classic_agent_started",
        "none",
    );

    let mut agent = match Agent::new(cfg).await {
        Ok(agent) => agent,
        Err(err) => {
            log_error("unknown", "classic_agent", "bootstrap", "init_failed", &err);
            std::process::exit(2);
        }
    };

    agent.run().await;
}

fn fetch_active_accounts_for_runtime(accounts: &[Account]) -> Vec<&Account> {
    let mut active = accounts
        .iter()
        .filter(|x| x.enabled && x.assigned && !x.free && !x.revoked && !x.frozen)
        .collect::<Vec<_>>();
    active.sort_by(|a, b| a.username.cmp(&b.username));
    active
}

fn render_credentials(accounts: &[&Account]) -> String {
    let mut out = String::new();
    for a in accounts {
        out.push_str("[[client]]\n");
        out.push_str(&format!("username = {:?}\n", a.username));
        out.push_str(&format!("password = {:?}\n\n", a.password));
    }
    out
}

fn parse_access_artifacts(raw: &str) -> Result<Vec<sidecar_sync::AccessArtifact>, String> {
    let parsed = parse_client_credentials(raw, "credentials")?;
    Ok(parsed
        .into_iter()
        .map(|item| sidecar_sync::AccessArtifact {
            username: item.username,
            password: item.password,
        })
        .collect())
}

fn parse_candidate_credentials_for_validation(
    raw: &str,
) -> Result<Vec<sidecar_sync::AccessArtifact>, String> {
    let parsed = parse_access_artifacts(raw)?;
    if parsed.is_empty() {
        return Err("credentials TOML does not contain [[client]] entries".to_string());
    }
    Ok(parsed)
}

fn runtime_validation_sample_username(
    credentials: &[sidecar_sync::AccessArtifact],
) -> Option<&str> {
    credentials
        .iter()
        .map(|item| item.username.as_str())
        .min()
}

fn runtime_validation_usernames_from_raw_toml(raw_credentials: &str) -> Result<Vec<String>, String> {
    let parsed = parse_candidate_credentials_for_validation(raw_credentials)?;
    Ok(parsed.into_iter().map(|item| item.username).collect())
}

#[derive(Debug)]
struct RuntimeValidationSelection {
    selected: Vec<String>,
    total: usize,
    limited: bool,
}

fn select_runtime_validation_usernames(
    usernames: Vec<String>,
    min_users: usize,
    max_users: usize,
) -> Result<RuntimeValidationSelection, String> {
    if min_users == 0 {
        return Err("min_users must be greater than zero".to_string());
    }
    if max_users == 0 {
        return Err("max_users must be greater than zero".to_string());
    }
    if min_users > max_users {
        return Err(format!(
            "min_users ({min_users}) must be <= max_users ({max_users})"
        ));
    }
    if usernames.is_empty() {
        return Err("credentials TOML does not contain any usernames".to_string());
    }
    let mut sorted_unique = usernames;
    sorted_unique.sort();
    sorted_unique.dedup();
    if sorted_unique.len() < min_users {
        return Err(format!(
            "credentials TOML contains {} unique usernames, below required minimum {}",
            sorted_unique.len(),
            min_users
        ));
    }
    let total = sorted_unique.len();
    let limited = total > max_users;
    let selected = if limited {
        sorted_unique.into_iter().take(max_users).collect()
    } else {
        sorted_unique
    };
    Ok(RuntimeValidationSelection {
        selected,
        total,
        limited,
    })
}

fn validate_checksum(snapshot: &SyncPayload, raw_body: &[u8]) -> bool {
    let expected = snapshot.checksum.to_ascii_lowercase();
    if expected.len() != 64 || !expected.chars().all(|x| x.is_ascii_hexdigit()) {
        return false;
    }

    let candidates = checksum_candidates(snapshot, raw_body);
    candidates.iter().any(|x| x == &expected)
}

fn checksum_candidates(snapshot: &SyncPayload, raw_body: &[u8]) -> Vec<String> {
    let mut stable_accounts = snapshot
        .accounts
        .iter()
        .map(|x| serde_json::json!({
            "enabled": x.enabled,
            "password": x.password,
            "username": x.username,
        }))
        .collect::<Vec<_>>();
    stable_accounts.sort_by(|a, b| a["username"].as_str().cmp(&b["username"].as_str()));

    let canonical_accounts = serde_json::to_vec(&stable_accounts).unwrap_or_default();
    let mut with_version = snapshot.version.as_bytes().to_vec();
    with_version.push(b'\n');
    with_version.extend_from_slice(&canonical_accounts);

    vec![
        sha256_hex(raw_body),
        sha256_hex(&canonical_accounts),
        sha256_hex(&with_version),
    ]
}

async fn load_state(path: &Path) -> Option<AgentState> {
    let bytes = fs::read(path).await.ok()?;
    serde_json::from_slice::<AgentState>(&bytes).ok()
}

async fn persist_state(path: &Path, state: &AgentState) -> Result<(), String> {
    let encoded = serde_json::to_vec_pretty(state)
        .map_err(|e| format!("failed to serialize state JSON: {e}"))?;
    atomic_write(path, &encoded).await
}

async fn atomic_write(path: &Path, data: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)
        .await
        .map_err(|e| format!("failed to create directory {}: {e}", parent.display()))?;

    let tmp_path = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|x| x.to_str())
            .unwrap_or("credentials")
    ));

    fs::write(&tmp_path, data)
        .await
        .map_err(|e| format!("failed to write tmp file {}: {e}", tmp_path.display()))?;
    fs::rename(&tmp_path, path)
        .await
        .map_err(|e| format!("failed to atomically rename {} -> {}: {e}", tmp_path.display(), path.display()))?;

    Ok(())
}

async fn append_pending_sync_report(
    outbox_path: &Path,
    report: &PendingSyncReportOwned,
) -> Result<(), String> {
    let parent = outbox_path
        .parent()
        .ok_or_else(|| format!("path has no parent: {}", outbox_path.display()))?;
    fs::create_dir_all(parent)
        .await
        .map_err(|e| format!("failed to create directory {}: {e}", parent.display()))?;

    let mut outbox = OpenOptions::new()
        .create(true)
        .append(true)
        .open(outbox_path)
        .await
        .map_err(|e| format!("failed to open sync-report outbox {}: {e}", outbox_path.display()))?;
    let encoded = serde_json::to_vec(report)
        .map_err(|e| format!("failed to serialize sync-report outbox row: {e}"))?;
    outbox
        .write_all(&encoded)
        .await
        .map_err(|e| format!("failed to append sync-report outbox row: {e}"))?;
    outbox
        .write_all(b"\n")
        .await
        .map_err(|e| format!("failed to append sync-report outbox newline: {e}"))?;
    outbox
        .flush()
        .await
        .map_err(|e| format!("failed to flush sync-report outbox: {e}"))?;
    Ok(())
}

async fn load_pending_sync_reports(path: &Path) -> Result<Vec<PendingSyncReportOwned>, String> {
    let raw = match fs::read(path).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(err) => {
            return Err(format!(
                "failed to read sync-report outbox {}: {err}",
                path.display()
            ));
        }
    };
    let content = std::str::from_utf8(&raw)
        .map_err(|e| format!("sync-report outbox is not valid UTF-8 {}: {e}", path.display()))?;

    let mut reports = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let report = serde_json::from_str::<PendingSyncReportOwned>(line).map_err(|e| {
            format!(
                "failed to parse sync-report outbox line {} in {}: {e}",
                idx + 1,
                path.display()
            )
        })?;
        reports.push(report);
    }
    Ok(reports)
}

async fn persist_pending_sync_reports(
    path: &Path,
    reports: &[PendingSyncReportOwned],
) -> Result<(), String> {
    if reports.is_empty() {
        match fs::remove_file(path).await {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(format!(
                    "failed to remove empty sync-report outbox {}: {err}",
                    path.display()
                ));
            }
        }
    }

    let mut encoded = Vec::new();
    for report in reports {
        let line = serde_json::to_vec(report)
            .map_err(|e| format!("failed to serialize sync-report outbox row: {e}"))?;
        encoded.extend_from_slice(&line);
        encoded.push(b'\n');
    }
    atomic_write(path, &encoded).await
}

fn needs_tt_link_regeneration(account: &Account, current_config_hash: &str) -> bool {
    account.tt_link.trim().is_empty()
        || account.tt_link_config_hash != current_config_hash
        || account.tt_link_stale
}

async fn build_account_exports(
    cfg: &Config,
    snapshot: &SyncPayload,
) -> Result<(Vec<AccountExportOwned>, TtLinkReconcileStats), String> {
    let link_config_path =
        resolve_runtime_path(&cfg.trusttunnel_runtime_dir, &cfg.trusttunnel_link_config_file);
    let link_cfg = LinkGenerationConfig::load_from_file_or_legacy_env(
        &link_config_path,
        &cfg.node_external_id,
    )?;
    if link_cfg.node_external_id() != cfg.node_external_id {
        return Err(format!(
            "link generation config node_external_id mismatch: expected {}, got {}",
            cfg.node_external_id,
            link_cfg.node_external_id()
        ));
    }
    let server_address = link_cfg.server_address().to_string();
    let cert_domain = link_cfg.cert_domain().to_string();
    let custom_sni = link_cfg.custom_sni();
    let display_name = link_cfg.display_name();
    let dns_servers = link_cfg.dns_servers();
    let protocol = link_cfg.protocol().to_string();
    let config_hash = link_cfg.config_hash();

    let mut stats = TtLinkReconcileStats::default();
    let mut exports = Vec::new();
    let settings_path = resolve_runtime_path(&cfg.trusttunnel_runtime_dir, &cfg.trusttunnel_config_file);
    let hosts_path = resolve_runtime_path(&cfg.trusttunnel_runtime_dir, &cfg.trusttunnel_hosts_file);
    let exporter = EndpointLinkExporter::new(
        cfg.endpoint_binary.clone(),
        settings_path,
        hosts_path,
        EndpointExportOptions::new(
            server_address.clone(),
            custom_sni.clone(),
            display_name.clone(),
            dns_servers.clone(),
        ),
    );

    let regenerate_accounts = snapshot
        .accounts
        .iter()
        .filter(|account| account.enabled && needs_tt_link_regeneration(account, &config_hash))
        .collect::<Vec<_>>();
    for account in &snapshot.accounts {
        if !account.enabled {
            stats.skipped_disabled += 1;
        }
    }
    let regenerated_links = exporter.export_links(regenerate_accounts).await?;

    for account in &snapshot.accounts {
        if !account.enabled {
            continue;
        }
        let must_regenerate = needs_tt_link_regeneration(account, &config_hash);
        let (tt_link, account_config_hash) = if must_regenerate {
            let tt_link = regenerated_links
                .links
                .get(account.username.as_str())
                .ok_or_else(|| format!("missing generated TT link for account {}", account.username))?
                .clone();
            stats.updated_total += 1;
            if account.tt_link.trim().is_empty() {
                stats.updated_empty_link += 1;
            }
            if account.tt_link_config_hash != config_hash {
                stats.updated_hash_mismatch += 1;
            }
            if account.tt_link_stale {
                stats.updated_stale += 1;
            }
            (tt_link, config_hash.clone())
        } else {
            stats.skipped_up_to_date += 1;
            (account.tt_link.clone(), account.tt_link_config_hash.clone())
        };

        exports.push(AccountExportOwned {
            username: account.username.clone(),
            external_account_id: account.external_account_id.clone(),
            access_bundle_id: account.access_bundle_id.clone(),
            active: true,
            tt_link,
            server_address: server_address.clone(),
            cert_domain: cert_domain.clone(),
            custom_sni: custom_sni.clone(),
            display_name: display_name.clone(),
            dns_servers: dns_servers.clone(),
            protocol: protocol.clone(),
            config_hash: account_config_hash,
            applied_revision: snapshot.version.clone(),
        });
    }

    Ok((exports, stats))
}

fn required_env(name: &str) -> Result<String, String> {
    let raw = std::env::var(name).map_err(|_| format!("required env var {name} is missing"))?;
    non_empty_value(name, raw)
}

fn read_pid(pid_path: &Path) -> Option<u32> {
    let raw = std::fs::read_to_string(pid_path).ok()?;
    raw.trim().parse::<u32>().ok()
}

fn find_pid_by_name(process_name: &str) -> Option<u32> {
    let candidates = process_name_candidates(process_name);
    let entries = read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let pid = file_name.to_str()?.parse::<u32>().ok()?;
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
        if candidates.iter().any(|item| comm.trim() == item) {
            return Some(pid);
        }
    }
    None
}

fn process_name_candidates(process_name: &str) -> Vec<String> {
    let normalized = process_name.trim();
    if normalized.is_empty() {
        return vec!["trusttunnel_endpoint".to_string()];
    }
    let mut candidates = vec![normalized.to_string()];
    let hyphen = normalized.replace('_', "-");
    if hyphen != normalized {
        candidates.push(hyphen);
    }
    let underscore = normalized.replace('-', "_");
    if underscore != normalized && !candidates.iter().any(|item| item == &underscore) {
        candidates.push(underscore);
    }
    candidates
}

fn is_pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn read_cpu_percent(pid: u32) -> Option<f64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let parts = stat.split_whitespace().collect::<Vec<_>>();
    if parts.len() <= 21 {
        return None;
    }
    let utime = parts[13].parse::<f64>().ok()?;
    let stime = parts[14].parse::<f64>().ok()?;
    let start_time = parts[21].parse::<f64>().ok()?;
    let uptime = std::fs::read_to_string("/proc/uptime").ok()?;
    let uptime_secs = uptime.split_whitespace().next()?.parse::<f64>().ok()?;
    let ticks_per_sec = 100.0;
    let total_time_secs = (utime + stime) / ticks_per_sec;
    let running_secs = uptime_secs - (start_time / ticks_per_sec);
    if running_secs <= 0.0 {
        return None;
    }
    Some((total_time_secs / running_secs * 100.0 * 100.0).round() / 100.0)
}

fn read_memory_percent(pid: u32) -> Option<f64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let rss_kb = status
        .lines()
        .find(|line| line.starts_with("VmRSS:"))?
        .split_whitespace()
        .nth(1)?
        .parse::<f64>()
        .ok()?;
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let total_kb = meminfo
        .lines()
        .find(|line| line.starts_with("MemTotal:"))?
        .split_whitespace()
        .nth(1)?
        .parse::<f64>()
        .ok()?;
    if total_kb <= 0.0 {
        return None;
    }
    Some((rss_kb / total_kb * 100.0 * 100.0).round() / 100.0)
}

fn count_active_clients(credentials_file: &Path) -> Option<u64> {
    let raw = std::fs::read_to_string(credentials_file).ok()?;
    Some(raw.matches("[[client]]").count() as u64)
}

#[cfg(test)]
mod runtime_status_tests {
    use super::*;

    #[test]
    fn runtime_health_status_dead_when_process_unavailable() {
        let status = RuntimeStatus {
            alive: false,
            metrics_available: false,
            active_clients: 0,
            cpu_percent: 0.0,
            memory_percent: 0.0,
        };

        assert_eq!(status.health_status(), "dead");
    }

    #[test]
    fn runtime_health_status_degraded_on_metrics_fallback() {
        let status = RuntimeStatus {
            alive: true,
            metrics_available: false,
            active_clients: 0,
            cpu_percent: 0.0,
            memory_percent: 0.0,
        };

        assert_eq!(status.health_status(), "degraded");
    }

    #[test]
    fn runtime_health_status_healthy_when_metrics_ready() {
        let status = RuntimeStatus {
            alive: true,
            metrics_available: true,
            active_clients: 3,
            cpu_percent: 2.4,
            memory_percent: 1.7,
        };

        assert_eq!(status.health_status(), "healthy");
    }

    #[test]
    fn normalize_heartbeat_payload_falls_back_to_non_empty_contract_fields() {
        let payload = normalize_heartbeat_payload("", "dead", "", "", "", RuntimeMode::LegacyHttp);

        assert_eq!(payload.current_revision, None);
        assert_eq!(payload.health_status, "disabled");
        assert_eq!(payload.last_apply_status, "pending");
    }

    #[test]
    fn normalize_health_status_maps_legacy_values_to_lk_contract() {
        assert_eq!(normalize_health_status("healthy", RuntimeMode::LegacyHttp), "ok");
        assert_eq!(normalize_health_status("alive", RuntimeMode::LegacyHttp), "ok");
        assert_eq!(normalize_health_status("ready", RuntimeMode::LegacyHttp), "ok");
        assert_eq!(normalize_health_status("warning", RuntimeMode::LegacyHttp), "degraded");
        assert_eq!(normalize_health_status("limited", RuntimeMode::LegacyHttp), "degraded");
        assert_eq!(normalize_health_status("offline", RuntimeMode::LegacyHttp), "disabled");
        assert_eq!(normalize_health_status("failed", RuntimeMode::LegacyHttp), "disabled");
    }

    #[test]
    fn normalize_health_status_uses_safe_default_for_unknown_values() {
        assert_eq!(
            normalize_health_status("something-new", RuntimeMode::LegacyHttp),
            "degraded"
        );
    }

    #[test]
    fn normalize_health_status_in_db_worker_does_not_force_disabled_for_dead_process_checks() {
        assert_eq!(normalize_health_status("dead", RuntimeMode::DbWorker), "degraded");
        assert_eq!(normalize_health_status("offline", RuntimeMode::DbWorker), "degraded");
        assert_eq!(normalize_health_status("failed", RuntimeMode::DbWorker), "degraded");
        assert_eq!(normalize_health_status("disabled", RuntimeMode::DbWorker), "disabled");
    }

    #[test]
    fn db_worker_health_state_maps_pipeline_signals_to_contract_status() {
        let mut state = DbWorkerHealthState::default();
        state.inventory_status = DbWorkerSignalStatus::Ok;
        state.artifacts_status = DbWorkerSignalStatus::Ok;
        assert_eq!(state.health_status(), "ok");

        state.artifacts_status = DbWorkerSignalStatus::Degraded;
        assert_eq!(state.health_status(), "degraded");

        state.runtime_prerequisites_valid = false;
        assert_eq!(state.health_status(), "disabled");
    }

    #[test]
    fn process_name_candidates_accept_hyphen_and_underscore_variants() {
        let from_underscore = process_name_candidates("trusttunnel_endpoint");
        assert!(from_underscore.contains(&"trusttunnel_endpoint".to_string()));
        assert!(from_underscore.contains(&"trusttunnel-endpoint".to_string()));

        let from_hyphen = process_name_candidates("trusttunnel-endpoint");
        assert!(from_hyphen.contains(&"trusttunnel-endpoint".to_string()));
        assert!(from_hyphen.contains(&"trusttunnel_endpoint".to_string()));
    }
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .and_then(|raw| non_empty_value(name, raw).ok())
}

fn optional_env_nonempty(name: &str) -> Option<String> {
    optional_env(name).filter(|value| !value.trim().is_empty())
}

fn resolve_endpoint_binary_from_env() -> String {
    if let Some(path) = optional_env_nonempty("TRUSTTUNNEL_ENDPOINT_BIN") {
        return path;
    }
    if let Some(path) = optional_env_nonempty("TRUSTTUNNEL_ENDPOINT_BINARY") {
        return path;
    }
    DEFAULT_ENDPOINT_BINARY_PATH.to_string()
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|meta| meta.is_file() && (meta.permissions().mode() & 0o111 != 0))
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path).map(|meta| meta.is_file()).unwrap_or(false)
}

async fn is_command_available_in_path(command: &str) -> bool {
    if command.trim().is_empty() {
        return false;
    }
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {command} >/dev/null 2>&1"))
        .status()
        .await;
    matches!(status, Ok(exit) if exit.success())
}

fn non_empty_value(name: &str, raw: String) -> Result<String, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(format!("required env var {name} must not be empty"));
    }

    Ok(value.to_string())
}

fn duration_required_from_env(name: &str) -> Result<Duration, String> {
    let raw = required_env(name)?;
    let secs = raw
        .parse::<u64>()
        .map_err(|e| format!("{name} must be u64 seconds: {e}"))?;
    Ok(Duration::from_secs(secs))
}

fn path_to_string(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path must be valid UTF-8: {}", path.display()))
}

fn resolve_runtime_path(runtime_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    runtime_dir.join(path)
}

fn split_host_port(raw: &str) -> Result<(String, u16), String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("server address is empty".to_string());
    }
    if let Some(stripped) = value.strip_prefix('[') {
        let Some(close_idx) = stripped.find(']') else {
            return Err(format!("invalid bracketed IPv6 server address: {value}"));
        };
        let host = stripped[..close_idx].trim();
        let rest = stripped[close_idx + 1..].trim();
        if host.is_empty() {
            return Err(format!("server address host is empty: {value}"));
        }
        let Some(port_raw) = rest.strip_prefix(':') else {
            return Err(format!("server address must include :port, got: {value}"));
        };
        let port = port_raw
            .trim()
            .parse::<u16>()
            .map_err(|e| format!("invalid server address port in {value}: {e}"))?;
        return Ok((host.to_string(), port));
    }

    let colon_count = value.matches(':').count();
    if colon_count == 1 {
        let idx = value
            .rfind(':')
            .ok_or_else(|| format!("server address must contain host:port, got: {value}"))?;
        let host = value[..idx].trim();
        let port_raw = value[idx + 1..].trim();
        if host.is_empty() {
            return Err(format!("server address host is empty: {value}"));
        }
        let port = port_raw
            .parse::<u16>()
            .map_err(|e| format!("invalid server address port in {value}: {e}"))?;
        return Ok((host.to_string(), port));
    }

    Err(format!(
        "invalid server address {value}: use host:port or [ipv6]:port"
    ))
}

fn should_import_bootstrap_credentials(
    has_bootstrap_source: bool,
    runtime_primary_marker_exists: bool,
    runtime_credentials_exists: bool,
) -> bool {
    has_bootstrap_source && !runtime_primary_marker_exists && !runtime_credentials_exists
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    hex::encode(digest.as_ref())
}

fn derive_lifecycle_base_url_from_artifacts_endpoint(artifacts_endpoint: &str) -> Option<String> {
    let endpoint = artifacts_endpoint.trim();
    if endpoint.is_empty() {
        return None;
    }
    let parsed = reqwest::Url::parse(endpoint).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed.host_str()?;
    let mut base_url = format!("{}://{host}", parsed.scheme());
    if let Some(port) = parsed.port() {
        base_url.push(':');
        base_url.push_str(port.to_string().as_str());
    }
    Some(base_url)
}

fn derive_inventory_endpoint(artifacts_endpoint: &str, external_node_id: &str) -> Result<String, String> {
    let resolved = artifacts_endpoint.replace("{externalNodeId}", external_node_id);
    if resolved.trim().is_empty() {
        return Err("inventory endpoint resolution failed: artifacts endpoint is empty".to_string());
    }
    if let Some(prefix) = resolved.strip_suffix("/artifacts") {
        return Ok(format!("{prefix}/inventory"));
    }
    Ok(format!("{}/inventory", resolved.trim_end_matches('/')))
}

fn build_inventory_ingest_payload(
    external_node_id: &str,
    snapshot: &credentials_inventory::InventorySnapshot,
    source: InventoryIngestSource,
) -> Result<InventoryIngestPayload, String> {
    let mut credentials = snapshot
        .credentials
        .iter()
        .map(|item| InventoryIngestCredential {
            username: item.username.clone(),
            password: item.password.clone(),
        })
        .collect::<Vec<_>>();
    credentials.sort_by(|left, right| left.username.cmp(&right.username));

    let mut seed = external_node_id.trim().to_string();
    seed.push('|');
    seed.push_str(snapshot.export_config_hash.as_str());
    for item in &credentials {
        seed.push('|');
        seed.push_str(item.username.as_str());
        seed.push('|');
        seed.push_str(sha256_hex(item.password.as_bytes()).as_str());
    }
    let logical_hash = sha256_hex(seed.as_bytes());
    let idempotency_key = trim_id(format!("inventory-v1-{logical_hash}"), 128);
    let request_id = trim_id(format!("inventory-req-{logical_hash}"), 128);
    let exported_at = chrono::DateTime::from_timestamp(snapshot.generated_at_unix_sec, 0)
        .ok_or_else(|| {
            format!(
                "inventory payload has invalid generated_at_unix_sec={}",
                snapshot.generated_at_unix_sec
            )
        })?
        .to_rfc3339();

    Ok(InventoryIngestPayload {
        contract_version: "v1",
        snapshot_version: "v1",
        external_node_id: external_node_id.to_string(),
        source: source.as_str().to_string(),
        revision: snapshot.generated_at_unix_sec,
        exported_at,
        idempotency_key,
        request_id,
        credentials,
    })
}

fn inventory_error_details(raw_body: &str) -> String {
    let trimmed = raw_body.trim();
    if trimmed.is_empty() {
        return "<empty response body>".to_string();
    }
    if let Some(detail) = extract_contract_mismatch_detail(trimmed) {
        return format!("{trimmed} (contract_mismatch={detail})");
    }
    trimmed.to_string()
}

fn extract_contract_mismatch_detail(raw_body: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(raw_body).ok()?;
    if let Some(field) = value
        .pointer("/field")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let message = value
            .pointer("/message")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .unwrap_or("invalid field value");
        return Some(format!("{field}: {message}"));
    }
    if let Some(errors) = value.get("errors").and_then(serde_json::Value::as_array) {
        let detailed = errors
            .iter()
            .filter_map(|item| {
                let field = item
                    .get("field")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|x| !x.is_empty())?;
                let message = item
                    .get("message")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|x| !x.is_empty())
                    .unwrap_or("invalid field value");
                Some(format!("{field}: {message}"))
            })
            .collect::<Vec<_>>();
        if !detailed.is_empty() {
            return Some(detailed.join(", "));
        }
    }
    None
}

fn trim_id(value: String, limit: usize) -> String {
    value.chars().take(limit).collect()
}

fn log_sync_skip(snapshot: &SyncPayload, reason: &str) {
    println!(
        "reconcile skip: reason={} version={} checksum={} onboarding_state={} sync_required={}",
        reason,
        snapshot.version,
        snapshot.checksum,
        snapshot.onboarding_state,
        snapshot.sync_required
    );
}


#[derive(Debug)]
enum RegisterAttemptOutcome {
    Registered,
    AlreadyRegistered,
}

#[derive(Debug)]
enum RegisterError {
    Temporary(String),
    Permanent(String),
}

enum BootstrapError {
    RegisterFailed(String),
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegisterFailed(detail) => write!(f, "register failed: {detail}"),
        }
    }
}

fn is_idempotent_register_status(status: StatusCode) -> bool {
    status == StatusCode::CONFLICT
}

fn is_temporary_http_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn payload_key_list(payload: &OnboardingPayload<'_>) -> String {
    serde_json::to_value(payload)
        .ok()
        .and_then(|v| {
            v.as_object().map(|obj| {
                let mut keys = obj.keys().cloned().collect::<Vec<String>>();
                keys.sort();
                keys.join(",")
            })
        })
        .unwrap_or_else(|| "unavailable".to_string())
}

fn summarize_register_reason(status: StatusCode, body: &str) -> &'static str {
    if status == StatusCode::BAD_REQUEST {
        let normalized = body.to_ascii_lowercase();
        if normalized.contains("missing") {
            return "missing_field";
        }
        if normalized.contains("contract_version") {
            return "invalid_contract_version";
        }
        if normalized.contains("identity") || normalized.contains("external_id") {
            return "invalid_node_identity";
        }
        return "validation_mismatch";
    }
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return "auth_failed";
    }
    if status.is_server_error() {
        return "server_error";
    }
    "unexpected_http_status"
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "legacy-lk-http")]
    use http_body_util::{BodyExt, Full};
    #[cfg(feature = "legacy-lk-http")]
    use hyper::body::{Bytes, Incoming};
    #[cfg(feature = "legacy-lk-http")]
    use hyper::server::conn::http1;
    #[cfg(feature = "legacy-lk-http")]
    use hyper::service::service_fn;
    #[cfg(feature = "legacy-lk-http")]
    use hyper::{Method, Request, Response, StatusCode as HyperStatusCode};
    #[cfg(feature = "legacy-lk-http")]
    use hyper_util::rt::TokioIo;
    #[cfg(feature = "legacy-lk-http")]
    use std::collections::{HashMap, VecDeque};
    #[cfg(feature = "legacy-lk-http")]
    use std::convert::Infallible;
    #[cfg(feature = "legacy-lk-http")]
    use std::sync::Arc;
    use tempfile::TempDir;
    #[cfg(feature = "legacy-lk-http")]
    use tokio::net::TcpListener;
    #[cfg(feature = "legacy-lk-http")]
    use tokio::sync::Mutex;

    fn make_fake_endpoint_script(temp_dir: &TempDir, args_log_path: &Path) -> String {
        let script_path = temp_dir.path().join("fake_endpoint.sh");
        std::fs::write(
            &script_path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{}\"\nuser=\"\"\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = \"--client_config\" ]; then shift; user=\"$1\"; fi\n  shift\ndone\necho \"tt://$user\"\n",
                args_log_path.display()
            ),
        )
        .unwrap();
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&script_path, perms).unwrap();
        script_path.display().to_string()
    }

    async fn run_multi_request_server(
        responses: Vec<(u16, String)>,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut captured = Vec::new();
            for (status, response_body) in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = vec![0_u8; 65536];
                let size = stream.read(&mut buffer).await.unwrap();
                let request = String::from_utf8_lossy(&buffer[..size]).to_string();
                captured.push(request);
                let response = format!(
                    "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            captured
        });
        (
            format!("http://{address}/internal/trusttunnel/v1/nodes/{{externalNodeId}}/artifacts"),
            handle,
        )
    }

    #[cfg(feature = "legacy-lk-http")]
    #[derive(Clone)]
    struct MockResponse {
        status: HyperStatusCode,
        body: String,
    }

    #[cfg(feature = "legacy-lk-http")]
    #[derive(Clone)]
    struct CapturedRequest {
        method: Method,
        path: String,
        body: String,
    }

    #[cfg(feature = "legacy-lk-http")]
    #[derive(Default)]
    struct MockState {
        routes: HashMap<(Method, String), VecDeque<MockResponse>>,
        captured: Vec<CapturedRequest>,
    }

    #[cfg(feature = "legacy-lk-http")]
    struct MockHttpServer {
        base_url: String,
        state: Arc<Mutex<MockState>>,
    }

    #[cfg(feature = "legacy-lk-http")]
    impl MockHttpServer {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let state = Arc::new(Mutex::new(MockState::default()));
            let state_for_task = Arc::clone(&state);

            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let io = TokioIo::new(stream);
                    let state_for_conn = Arc::clone(&state_for_task);
                    tokio::spawn(async move {
                        let service = service_fn(move |req: Request<Incoming>| {
                            let state_for_req = Arc::clone(&state_for_conn);
                            async move {
                                let method = req.method().clone();
                                let path = req.uri().path().to_string();
                                let body = req
                                    .into_body()
                                    .collect()
                                    .await
                                    .map(|x| x.to_bytes())
                                    .unwrap_or_else(|_| Bytes::new());
                                let body = String::from_utf8_lossy(&body).to_string();

                                let mut guard = state_for_req.lock().await;
                                guard.captured.push(CapturedRequest {
                                    method: method.clone(),
                                    path: path.clone(),
                                    body,
                                });
                                let response = guard
                                    .routes
                                    .get_mut(&(method, path))
                                    .and_then(|queue| queue.pop_front())
                                    .unwrap_or(MockResponse {
                                        status: HyperStatusCode::NOT_FOUND,
                                        body: String::new(),
                                    });

                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(response.status)
                                        .body(Full::new(Bytes::from(response.body)))
                                        .unwrap(),
                                )
                            }
                        });

                        let _ = http1::Builder::new().serve_connection(io, service).await;
                    });
                }
            });

            Self {
                base_url: format!("http://{addr}"),
                state,
            }
        }

        async fn enqueue(
            &self,
            method: Method,
            path: &str,
            status: HyperStatusCode,
            body: impl Into<String>,
        ) {
            let mut guard = self.state.lock().await;
            guard
                .routes
                .entry((method, path.to_string()))
                .or_default()
                .push_back(MockResponse {
                    status,
                    body: body.into(),
                });
        }

        async fn captured(&self) -> Vec<CapturedRequest> {
            self.state.lock().await.captured.clone()
        }
    }

    #[cfg(feature = "legacy-lk-http")]
    async fn wait_for_captured_requests(
        server: &MockHttpServer,
        min_count: usize,
        timeout: Duration,
    ) -> Vec<CapturedRequest> {
        let deadline = Instant::now() + timeout;
        loop {
            let captured = server.captured().await;
            if captured.len() >= min_count {
                return captured;
            }
            if Instant::now() >= deadline {
                return captured;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[cfg(feature = "legacy-lk-http")]
    async fn make_agent(
        temp_dir: &TempDir,
        base_url: &str,
        apply_cmd: Option<&str>,
    ) -> Agent {
        let runtime_dir = temp_dir.path().join("runtime");
        fs::create_dir_all(&runtime_dir).await.unwrap();
        let config_file = runtime_dir.join("vpn.toml");
        let credentials_file_rel = PathBuf::from("credentials.toml");
        let credentials_file_abs = runtime_dir.join(&credentials_file_rel);
        let hosts_file = runtime_dir.join("hosts.toml");
        let rules_file = runtime_dir.join("rules.toml");
        let cert_file = runtime_dir.join("cert.pem");
        let key_file = runtime_dir.join("key.pem");
        fs::write(&credentials_file_abs, b"").await.unwrap();
        fs::write(&cert_file, b"placeholder").await.unwrap();
        fs::write(&key_file, b"placeholder").await.unwrap();
        fs::write(
            &hosts_file,
            format!(
                r#"
[[main_hosts]]
hostname = "node-1.example"
cert_chain_path = "{}"
private_key_path = "{}"
"#,
                cert_file.display(),
                key_file.display()
            ),
        )
        .await
        .unwrap();
        fs::write(&rules_file, b"").await.unwrap();

        let settings = format!(
            r#"
listen_address = "127.0.0.1:443"
credentials_file = "{}"
rules_file = "{}"

[listen_protocols]

[listen_protocols.http1]
upload_buffer_size = 32768

[listen_protocols.http2]
initial_connection_window_size = 8388608
initial_stream_window_size = 131072
max_concurrent_streams = 1000
max_frame_size = 16384
header_table_size = 65536

[listen_protocols.quic]
recv_udp_payload_size = 1350
send_udp_payload_size = 1350
initial_max_data = 104857600
initial_max_stream_data_bidi_local = 1048576
initial_max_stream_data_bidi_remote = 1048576
initial_max_stream_data_uni = 1048576
initial_max_streams_bidi = 4096
initial_max_streams_uni = 4096
max_connection_window = 25165824
max_stream_window = 16777216
disable_active_migration = true
enable_early_data = true
message_queue_capacity = 4096
"#,
            credentials_file_abs.display(),
            rules_file.display()
        );
        fs::write(&config_file, settings).await.unwrap();
        fs::write(
            runtime_dir.join("tt-link.toml"),
            "node_external_id = \"node-1\"\nserver_address = \"node-1.example:8443\"\ncert_domain = \"node-1.example\"\nprotocol = \"http2\"\ndns_servers = [\"8.8.8.8\"]\n",
        )
        .await
        .unwrap();
        let endpoint_args_log_path = runtime_dir.join("agent-endpoint-args.log");
        let endpoint_binary = make_fake_endpoint_script(temp_dir, &endpoint_args_log_path);

        let cfg = Config {
            lk_base_url: Some(base_url.to_string()),
            runtime_mode: RuntimeMode::DbWorker,
            lk_write_contract: LkWriteContract::PgFunction,
            lk_db_dsn: "postgres://localhost/lk".to_string(),
            lk_service_token: Some("token".to_string()),
            node_external_id: "node-1".to_string(),
            node_hostname: "node-1.example".to_string(),
            node_stage: Some("prod".to_string()),
            node_cluster: Some("cluster-a".to_string()),
            node_namespace: Some("default".to_string()),
            node_rollout_group: Some("g1".to_string()),
            trusttunnel_runtime_dir: runtime_dir.clone(),
            trusttunnel_config_file: config_file.clone(),
            trusttunnel_hosts_file: hosts_file,
            bootstrap_credentials_source_path: None,
            trusttunnel_link_config_file: runtime_dir.join("tt-link.toml"),
            runtime_credentials_path: credentials_file_abs,
            runtime_primary_marker_path: runtime_dir.join(RUNTIME_PRIMARY_MARKER_FILE),
            agent_state_path: runtime_dir.join("agent_state.json"),
            reconcile_interval: Duration::from_secs(60),
            apply_interval: Duration::from_secs(60),
            heartbeat_interval: Duration::from_secs(30),
            sync_path_template: Some("/sync/{externalNodeId}".to_string()),
            sync_report_path: Some("/sync-report".to_string()),
            apply_cmd: apply_cmd.map(ToString::to_string),
            runtime_pid_path: Some(runtime_dir.join("trusttunnel.pid")),
            runtime_process_name: Some("trusttunnel_endpoint".to_string()),
            endpoint_binary,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            runtime_version: "test".to_string(),
            pending_sync_reports_path: Some(runtime_dir.join(SYNC_REPORT_OUTBOX_FILE)),
            metrics_address: "127.0.0.1:9901".parse().unwrap(),
            debug_preserve_temp_files: false,
            validation_strict_mode: false,
            syntax_validation_diagnostic_only: false,
            runtime_validation_min_users: DEFAULT_RUNTIME_VALIDATION_MIN_USERS,
            runtime_validation_max_users: DEFAULT_RUNTIME_VALIDATION_MAX_USERS,
        };

        Agent::new(cfg).await.unwrap()
    }

    async fn make_db_worker_agent_for_validation_tests(
        temp_dir: &TempDir,
        debug_preserve_temp_files: bool,
    ) -> Agent {
        make_db_worker_agent_for_validation_tests_with_strict(
            temp_dir,
            debug_preserve_temp_files,
            false,
        )
        .await
    }

    async fn make_db_worker_agent_for_validation_tests_with_strict(
        temp_dir: &TempDir,
        debug_preserve_temp_files: bool,
        validation_strict_mode: bool,
    ) -> Agent {
        let runtime_dir = temp_dir.path().join("runtime");
        fs::create_dir_all(&runtime_dir).await.unwrap();
        let config_file = runtime_dir.join("vpn.toml");
        let credentials_file = runtime_dir.join("credentials.toml");
        let hosts_file = runtime_dir.join("hosts.toml");
        let rules_file = runtime_dir.join("rules.toml");
        let cert_file = runtime_dir.join("cert.pem");
        let key_file = runtime_dir.join("key.pem");
        fs::write(&credentials_file, b"").await.unwrap();
        fs::write(&cert_file, b"placeholder").await.unwrap();
        fs::write(&key_file, b"placeholder").await.unwrap();
        fs::write(
            &hosts_file,
            format!(
                r#"
[[main_hosts]]
hostname = "node-1.example"
cert_chain_path = "{}"
private_key_path = "{}"
"#,
                cert_file.display(),
                key_file.display()
            ),
        )
        .await
        .unwrap();
        fs::write(&rules_file, b"").await.unwrap();
        fs::write(
            &config_file,
            format!(
                r#"
listen_address = "127.0.0.1:443"
credentials_file = "{}"
rules_file = "{}"

[listen_protocols]

[listen_protocols.http1]
upload_buffer_size = 32768
"#,
                credentials_file.display(),
                rules_file.display()
            ),
        )
        .await
        .unwrap();
        fs::write(
            runtime_dir.join("tt-link.toml"),
            "node_external_id = \"node-1\"\nserver_address = \"node-1.example:8443\"\ncert_domain = \"node-1.example\"\nprotocol = \"http2\"\n",
        )
        .await
        .unwrap();

        let endpoint_args_log_path = runtime_dir.join("validation-endpoint-args.log");
        let endpoint_binary = make_fake_endpoint_script(temp_dir, &endpoint_args_log_path);

        let cfg = Config {
            lk_base_url: Some("http://localhost".to_string()),
            runtime_mode: RuntimeMode::DbWorker,
            lk_write_contract: LkWriteContract::PgFunction,
            lk_db_dsn: "postgres://localhost/lk".to_string(),
            lk_service_token: Some("token".to_string()),
            node_external_id: "node-1".to_string(),
            node_hostname: "node-1.example".to_string(),
            node_stage: None,
            node_cluster: None,
            node_namespace: None,
            node_rollout_group: None,
            trusttunnel_runtime_dir: runtime_dir.clone(),
            trusttunnel_config_file: config_file,
            trusttunnel_hosts_file: hosts_file,
            bootstrap_credentials_source_path: None,
            trusttunnel_link_config_file: runtime_dir.join("tt-link.toml"),
            runtime_credentials_path: credentials_file,
            runtime_primary_marker_path: runtime_dir.join(RUNTIME_PRIMARY_MARKER_FILE),
            agent_state_path: runtime_dir.join("agent_state.json"),
            reconcile_interval: Duration::from_secs(10),
            apply_interval: Duration::from_secs(10),
            heartbeat_interval: DEFAULT_DB_WORKER_HEARTBEAT_INTERVAL,
            sync_path_template: None,
            sync_report_path: None,
            apply_cmd: None,
            runtime_pid_path: None,
            runtime_process_name: None,
            endpoint_binary,
            agent_version: "test".to_string(),
            runtime_version: "test".to_string(),
            pending_sync_reports_path: None,
            metrics_address: "127.0.0.1:9901".parse().unwrap(),
            debug_preserve_temp_files,
            validation_strict_mode,
            syntax_validation_diagnostic_only: false,
            runtime_validation_min_users: DEFAULT_RUNTIME_VALIDATION_MIN_USERS,
            runtime_validation_max_users: DEFAULT_RUNTIME_VALIDATION_MAX_USERS,
        };

        Agent::new(cfg).await.unwrap()
    }

    #[cfg(feature = "legacy-lk-http")]
    fn snapshot_json(
        version: &str,
        onboarding_state: &str,
        sync_required: bool,
        accounts: Vec<Account>,
    ) -> String {
        let snapshot = SyncPayload {
            version: version.to_string(),
            checksum: "placeholder".to_string(),
            onboarding_state: onboarding_state.to_string(),
            sync_required,
            accounts,
        };
        let checksum = checksum_candidates(&snapshot, b"{}")[2].clone();
        serde_json::json!({
            "version": snapshot.version,
            "checksum": checksum,
            "onboardingState": snapshot.onboarding_state,
            "syncRequired": snapshot.sync_required,
            "users": snapshot.accounts,
        })
        .to_string()
    }

    #[test]
    fn credentials_include_only_enabled_accounts() {
        let accounts = vec![
            Account {
                username: "b".to_string(),
                password: "p2".to_string(),
                enabled: false,
                assigned: true,
                free: false,
                revoked: false,
                frozen: false,
                external_account_id: None,
                access_bundle_id: None,
                tt_link: String::new(),
                tt_link_config_hash: String::new(),
                tt_link_stale: false,
            },
            Account {
                username: "a".to_string(),
                password: "p1".to_string(),
                enabled: true,
                assigned: true,
                free: false,
                revoked: false,
                frozen: false,
                external_account_id: None,
                access_bundle_id: None,
                tt_link: String::new(),
                tt_link_config_hash: String::new(),
                tt_link_stale: false,
            },
        ];

        let runtime_accounts = fetch_active_accounts_for_runtime(&accounts);
        let rendered = render_credentials(&runtime_accounts);
        assert!(rendered.contains("username = \"a\""));
        assert!(!rendered.contains("username = \"b\""));
    }

    #[test]
    fn runtime_filters_exclude_frozen_and_revoked_accounts() {
        let accounts = vec![
            Account {
                username: "active".to_string(),
                password: "p1".to_string(),
                enabled: true,
                assigned: true,
                free: false,
                revoked: false,
                frozen: false,
                external_account_id: None,
                access_bundle_id: None,
                tt_link: "tt://active".to_string(),
                tt_link_config_hash: "hash".to_string(),
                tt_link_stale: false,
            },
            Account {
                username: "frozen".to_string(),
                password: "p2".to_string(),
                enabled: true,
                assigned: true,
                free: false,
                revoked: false,
                frozen: true,
                external_account_id: None,
                access_bundle_id: None,
                tt_link: "tt://frozen".to_string(),
                tt_link_config_hash: "hash".to_string(),
                tt_link_stale: false,
            },
            Account {
                username: "revoked".to_string(),
                password: "p3".to_string(),
                enabled: true,
                assigned: true,
                free: false,
                revoked: true,
                frozen: false,
                external_account_id: None,
                access_bundle_id: None,
                tt_link: "tt://revoked".to_string(),
                tt_link_config_hash: "hash".to_string(),
                tt_link_stale: false,
            },
        ];

        let runtime_accounts = fetch_active_accounts_for_runtime(&accounts);
        assert_eq!(runtime_accounts.len(), 1);
        assert_eq!(runtime_accounts[0].username, "active");

        let rendered = render_credentials(&runtime_accounts);
        assert!(rendered.contains("username = \"active\""));
        assert!(!rendered.contains("username = \"frozen\""));
        assert!(!rendered.contains("username = \"revoked\""));
    }

    #[test]
    fn runtime_filters_keep_only_active_accounts() {
        let accounts = vec![
            Account {
                username: "active".to_string(),
                password: "p1".to_string(),
                enabled: true,
                assigned: true,
                free: false,
                revoked: false,
                frozen: false,
                external_account_id: None,
                access_bundle_id: None,
                tt_link: "tt://active".to_string(),
                tt_link_config_hash: "hash".to_string(),
                tt_link_stale: false,
            },
            Account {
                username: "unassigned".to_string(),
                password: "p2".to_string(),
                enabled: true,
                assigned: false,
                free: false,
                revoked: false,
                frozen: false,
                external_account_id: None,
                access_bundle_id: None,
                tt_link: "tt://u".to_string(),
                tt_link_config_hash: "hash".to_string(),
                tt_link_stale: false,
            },
            Account {
                username: "free".to_string(),
                password: "p3".to_string(),
                enabled: true,
                assigned: true,
                free: true,
                revoked: false,
                frozen: false,
                external_account_id: None,
                access_bundle_id: None,
                tt_link: "tt://f".to_string(),
                tt_link_config_hash: "hash".to_string(),
                tt_link_stale: false,
            },
        ];

        let runtime_accounts = fetch_active_accounts_for_runtime(&accounts);
        assert_eq!(runtime_accounts.len(), 1);
        assert_eq!(runtime_accounts[0].username, "active");
    }

    #[tokio::test]
    async fn account_exports_generate_valid_tt_links() {
        let temp_dir = TempDir::new().unwrap();
        let runtime_dir = temp_dir.path();
        let args_log_path = runtime_dir.join("args.log");
        let endpoint_binary = make_fake_endpoint_script(&temp_dir, &args_log_path);
        std::fs::write(
            runtime_dir.join("tt-link.toml"),
            "node_external_id = \"node-1\"\nserver_address = \"89.110.100.165:443\"\ncert_domain = \"cdn.securesoft.dev\"\ncustom_sni = \"sni.example.com\"\nprotocol = \"http2\"\ndisplay_name = \"Primary\"\ndns_servers = [\"8.8.8.8\"]\n",
        )
        .unwrap();
        let snapshot = SyncPayload {
            version: "rev-1".to_string(),
            checksum: "0".repeat(64),
            onboarding_state: "active".to_string(),
            sync_required: true,
            accounts: vec![Account {
                username: "alice".to_string(),
                password: "secret".to_string(),
                enabled: true,
                assigned: true,
                free: false,
                revoked: false,
                frozen: false,
                external_account_id: Some("acc-1".to_string()),
                access_bundle_id: Some("bundle-1".to_string()),
                tt_link: String::new(),
                tt_link_config_hash: String::new(),
                tt_link_stale: false,
            }],
        };
        let cfg = Config {
            lk_base_url: None,
            runtime_mode: RuntimeMode::DbWorker,
            lk_write_contract: LkWriteContract::PgFunction,
            lk_db_dsn: "postgres://localhost/lk".to_string(),
            lk_service_token: None,
            node_external_id: "node-1".to_string(),
            node_hostname: "node-1.example".to_string(),
            node_stage: None,
            node_cluster: None,
            node_namespace: None,
            node_rollout_group: None,
            trusttunnel_runtime_dir: runtime_dir.to_path_buf(),
            trusttunnel_config_file: PathBuf::from("vpn.toml"),
            trusttunnel_hosts_file: PathBuf::from("hosts.toml"),
            bootstrap_credentials_source_path: None,
            trusttunnel_link_config_file: PathBuf::from("tt-link.toml"),
            runtime_credentials_path: PathBuf::from("credentials.toml"),
            runtime_primary_marker_path: PathBuf::from(".runtime_primary_marker"),
            agent_state_path: PathBuf::from("agent_state.json"),
            reconcile_interval: Duration::from_secs(10),
            apply_interval: Duration::from_secs(10),
            heartbeat_interval: Duration::from_secs(30),
            sync_path_template: Some("/sync/{externalNodeId}".to_string()),
            sync_report_path: Some("/sync-report".to_string()),
            apply_cmd: None,
            runtime_pid_path: Some(PathBuf::from("trusttunnel.pid")),
            runtime_process_name: Some("trusttunnel_endpoint".to_string()),
            endpoint_binary,
            agent_version: "test".to_string(),
            runtime_version: "test".to_string(),
            pending_sync_reports_path: Some(PathBuf::from("pending_sync_reports.jsonl")),
            metrics_address: "127.0.0.1:9901".parse().unwrap(),
            debug_preserve_temp_files: false,
            validation_strict_mode: false,
            syntax_validation_diagnostic_only: false,
            runtime_validation_min_users: DEFAULT_RUNTIME_VALIDATION_MIN_USERS,
            runtime_validation_max_users: DEFAULT_RUNTIME_VALIDATION_MAX_USERS,
        };

        let (exports, stats) = build_account_exports(&cfg, &snapshot).await.unwrap();
        assert_eq!(exports.len(), 1);
        assert_eq!(stats.updated_total, 1);
        assert_eq!(exports[0].tt_link, "tt://alice");
        assert_eq!(exports[0].server_address, "89.110.100.165:443");
        assert_eq!(exports[0].cert_domain, "cdn.securesoft.dev");
        assert_eq!(exports[0].config_hash.len(), 64);
        let args_log = std::fs::read_to_string(args_log_path).unwrap();
        assert!(args_log.contains("--format deeplink"));
        assert!(args_log.contains("--address 89.110.100.165:443"));
        assert!(args_log.contains("--custom-sni sni.example.com"));
        assert!(args_log.contains("--name Primary"));
        assert!(args_log.contains("--dns-upstream 8.8.8.8"));
    }

    #[test]
    fn needs_tt_link_regeneration_predicate_works() {
        let account = Account {
            username: "alice".to_string(),
            password: "secret".to_string(),
            enabled: true,
            assigned: true,
            free: false,
            revoked: false,
            frozen: false,
            external_account_id: None,
            access_bundle_id: None,
            tt_link: "tt://existing".to_string(),
            tt_link_config_hash: "hash-1".to_string(),
            tt_link_stale: false,
        };
        assert!(!needs_tt_link_regeneration(&account, "hash-1"));
        assert!(needs_tt_link_regeneration(&account, "hash-2"));
        assert!(needs_tt_link_regeneration(
            &Account {
                tt_link: String::new(),
                ..account.clone()
            },
            "hash-1"
        ));
        assert!(needs_tt_link_regeneration(
            &Account {
                tt_link_stale: true,
                ..account
            },
            "hash-1"
        ));
    }

    #[tokio::test]
    async fn account_exports_reuse_current_tt_link_when_up_to_date() {
        let temp_dir = TempDir::new().unwrap();
        let runtime_dir = temp_dir.path();
        std::fs::write(
            runtime_dir.join("tt-link.toml"),
            "node_external_id = \"node-1\"\nserver_address = \"89.110.100.165:443\"\ncert_domain = \"cdn.securesoft.dev\"\nprotocol = \"http2\"\ndns_servers = []\n",
        )
        .unwrap();

        let cfg = Config {
            lk_base_url: None,
            runtime_mode: RuntimeMode::DbWorker,
            lk_write_contract: LkWriteContract::PgFunction,
            lk_db_dsn: "postgres://localhost/lk".to_string(),
            lk_service_token: None,
            node_external_id: "node-1".to_string(),
            node_hostname: "node-1.example".to_string(),
            node_stage: None,
            node_cluster: None,
            node_namespace: None,
            node_rollout_group: None,
            trusttunnel_runtime_dir: runtime_dir.to_path_buf(),
            trusttunnel_config_file: PathBuf::from("vpn.toml"),
            trusttunnel_hosts_file: PathBuf::from("hosts.toml"),
            bootstrap_credentials_source_path: None,
            trusttunnel_link_config_file: PathBuf::from("tt-link.toml"),
            runtime_credentials_path: PathBuf::from("credentials.toml"),
            runtime_primary_marker_path: PathBuf::from(".runtime_primary_marker"),
            agent_state_path: PathBuf::from("agent_state.json"),
            reconcile_interval: Duration::from_secs(10),
            apply_interval: Duration::from_secs(10),
            heartbeat_interval: Duration::from_secs(30),
            sync_path_template: Some("/sync/{externalNodeId}".to_string()),
            sync_report_path: Some("/sync-report".to_string()),
            apply_cmd: None,
            runtime_pid_path: Some(PathBuf::from("trusttunnel.pid")),
            runtime_process_name: Some("trusttunnel_endpoint".to_string()),
            endpoint_binary: "trusttunnel_endpoint".to_string(),
            agent_version: "test".to_string(),
            runtime_version: "test".to_string(),
            pending_sync_reports_path: Some(PathBuf::from("pending_sync_reports.jsonl")),
            metrics_address: "127.0.0.1:9901".parse().unwrap(),
            debug_preserve_temp_files: false,
            validation_strict_mode: false,
            syntax_validation_diagnostic_only: false,
            runtime_validation_min_users: DEFAULT_RUNTIME_VALIDATION_MIN_USERS,
            runtime_validation_max_users: DEFAULT_RUNTIME_VALIDATION_MAX_USERS,
        };
        let config_hash = LinkGenerationConfig::load_from_file(&runtime_dir.join("tt-link.toml"))
            .unwrap()
            .config_hash();
        let snapshot = SyncPayload {
            version: "rev-1".to_string(),
            checksum: "0".repeat(64),
            onboarding_state: "active".to_string(),
            sync_required: true,
            accounts: vec![Account {
                username: "alice".to_string(),
                password: "secret".to_string(),
                enabled: true,
                assigned: true,
                free: false,
                revoked: false,
                frozen: false,
                external_account_id: Some("acc-1".to_string()),
                access_bundle_id: Some("bundle-1".to_string()),
                tt_link: "tt://existing".to_string(),
                tt_link_config_hash: config_hash.clone(),
                tt_link_stale: false,
            }],
        };

        let (exports, stats) = build_account_exports(&cfg, &snapshot).await.unwrap();
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].tt_link, "tt://existing");
        assert_eq!(exports[0].config_hash, config_hash);
        assert_eq!(stats.updated_total, 0);
        assert_eq!(stats.skipped_up_to_date, 1);
    }

    #[tokio::test]
    async fn tt_link_generation_is_stable_for_same_account_and_config() {
        let temp_dir = TempDir::new().unwrap();
        let runtime_dir = temp_dir.path();
        let args_log_path = runtime_dir.join("args.log");
        let endpoint_binary = make_fake_endpoint_script(&temp_dir, &args_log_path);
        std::fs::write(
            runtime_dir.join("tt-link.toml"),
            "node_external_id = \"node-1\"\nserver_address = \"89.110.100.165:443\"\ncert_domain = \"cdn.securesoft.dev\"\ncustom_sni = \"cdn.securesoft.dev\"\nprotocol = \"http2\"\ndns_servers = [\"8.8.8.8\"]\n",
        )
        .unwrap();

        let cfg = Config {
            lk_base_url: Some("http://localhost".to_string()),
            runtime_mode: RuntimeMode::DbWorker,
            lk_write_contract: LkWriteContract::PgFunction,
            lk_db_dsn: "postgres://localhost/lk".to_string(),
            lk_service_token: Some("token".to_string()),
            node_external_id: "node-1".to_string(),
            node_hostname: "node-1.example".to_string(),
            node_stage: None,
            node_cluster: None,
            node_namespace: None,
            node_rollout_group: None,
            trusttunnel_runtime_dir: runtime_dir.to_path_buf(),
            trusttunnel_config_file: PathBuf::from("vpn.toml"),
            trusttunnel_hosts_file: PathBuf::from("hosts.toml"),
            bootstrap_credentials_source_path: None,
            trusttunnel_link_config_file: PathBuf::from("tt-link.toml"),
            runtime_credentials_path: PathBuf::from("credentials.toml"),
            runtime_primary_marker_path: PathBuf::from(".runtime_primary_marker"),
            agent_state_path: PathBuf::from("agent_state.json"),
            reconcile_interval: Duration::from_secs(10),
            apply_interval: Duration::from_secs(10),
            heartbeat_interval: Duration::from_secs(30),
            sync_path_template: Some("/sync/{externalNodeId}".to_string()),
            sync_report_path: Some("/sync-report".to_string()),
            apply_cmd: None,
            runtime_pid_path: Some(PathBuf::from("trusttunnel.pid")),
            runtime_process_name: Some("trusttunnel_endpoint".to_string()),
            endpoint_binary,
            agent_version: "test".to_string(),
            runtime_version: "test".to_string(),
            pending_sync_reports_path: Some(PathBuf::from("pending_sync_reports.jsonl")),
            metrics_address: "127.0.0.1:9901".parse().unwrap(),
            debug_preserve_temp_files: false,
            validation_strict_mode: false,
            syntax_validation_diagnostic_only: false,
            runtime_validation_min_users: DEFAULT_RUNTIME_VALIDATION_MIN_USERS,
            runtime_validation_max_users: DEFAULT_RUNTIME_VALIDATION_MAX_USERS,
        };
        let snapshot = SyncPayload {
            version: "rev-1".to_string(),
            checksum: "0".repeat(64),
            onboarding_state: "active".to_string(),
            sync_required: true,
            accounts: vec![Account {
                username: "alice".to_string(),
                password: "secret".to_string(),
                enabled: true,
                assigned: true,
                free: false,
                revoked: false,
                frozen: false,
                external_account_id: None,
                access_bundle_id: None,
                tt_link: String::new(),
                tt_link_config_hash: String::new(),
                tt_link_stale: false,
            }],
        };

        let (first, _) = build_account_exports(&cfg, &snapshot).await.unwrap();
        let (second, _) = build_account_exports(&cfg, &snapshot).await.unwrap();
        assert_eq!(first[0].tt_link, second[0].tt_link);
    }

    #[test]
    fn checksum_accepts_sha_of_raw_body() {
        let raw = br#"{"version":"1","checksum":"","accounts":[]}"#;
        let snapshot = SyncPayload {
            version: "1".to_string(),
            checksum: sha256_hex(raw),
            onboarding_state: "active".to_string(),
            sync_required: true,
            accounts: vec![],
        };

        assert!(validate_checksum(&snapshot, raw));
    }

    #[test]
    fn checksum_rejects_unknown_hash() {
        let snapshot = SyncPayload {
            version: "1".to_string(),
            checksum: "deadbeef".to_string(),
            onboarding_state: "active".to_string(),
            sync_required: true,
            accounts: vec![],
        };

        assert!(!validate_checksum(&snapshot, b"{}"));
    }

    #[test]
    fn non_empty_value_rejects_whitespace_only() {
        let err = non_empty_value("ANY_KEY", "   ".to_string()).unwrap_err();

        assert_eq!(err, "required env var ANY_KEY must not be empty");
    }

    #[test]
    fn register_conflict_is_treated_as_idempotent_success() {
        assert!(is_idempotent_register_status(StatusCode::CONFLICT));
    }

    #[test]
    fn temporary_http_statuses_include_retryable_codes() {
        assert!(is_temporary_http_status(StatusCode::REQUEST_TIMEOUT));
        assert!(is_temporary_http_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(is_temporary_http_status(StatusCode::BAD_GATEWAY));
        assert!(!is_temporary_http_status(StatusCode::BAD_REQUEST));
    }

    #[test]
    fn resolve_runtime_path_keeps_absolute_paths() {
        let runtime_dir = Path::new("/var/lib/trusttunnel");
        let path = Path::new("/etc/trusttunnel/vpn.toml");

        assert_eq!(resolve_runtime_path(runtime_dir, path), path);
    }

    #[test]
    fn resolve_runtime_path_joins_relative_paths() {
        let runtime_dir = Path::new("/var/lib/trusttunnel");
        let path = Path::new("vpn.toml");

        assert_eq!(
            resolve_runtime_path(runtime_dir, path),
            Path::new("/var/lib/trusttunnel/vpn.toml")
        );
    }

    #[test]
    fn import_bootstrap_credentials_only_before_runtime_becomes_primary() {
        assert!(should_import_bootstrap_credentials(true, false, false));
        assert!(!should_import_bootstrap_credentials(true, true, false));
        assert!(!should_import_bootstrap_credentials(true, false, true));
        assert!(!should_import_bootstrap_credentials(false, false, false));
    }

    #[test]
    fn lifecycle_writes_support_depends_on_runtime_mode() {
        assert!(RuntimeMode::DbWorker.supports_lifecycle_writes());
        assert!(RuntimeMode::LegacyHttp.supports_lifecycle_writes());
    }

    #[tokio::test]
    async fn db_worker_mode_requires_lifecycle_configuration() {
        let temp_dir = TempDir::new().unwrap();
        let runtime_dir = temp_dir.path().join("runtime");
        fs::create_dir_all(&runtime_dir).await.unwrap();
        let config_file = runtime_dir.join("vpn.toml");
        let hosts_file = runtime_dir.join("hosts.toml");
        let rules_file = runtime_dir.join("rules.toml");
        let credentials_file = runtime_dir.join("credentials.toml");

        fs::write(&hosts_file, "").await.unwrap();
        fs::write(&rules_file, "").await.unwrap();
        fs::write(&credentials_file, "").await.unwrap();
        fs::write(
            runtime_dir.join("tt-link.toml"),
            "server = \"node-1.example\"\nport = 8443\nprotocol = \"http2\"\n",
        )
        .await
        .unwrap();
        fs::write(
            &config_file,
            format!(
                "listen_address = \"127.0.0.1:443\"\ncredentials_file = \"{}\"\nrules_file = \"{}\"\n",
                credentials_file.display(),
                rules_file.display()
            ),
        )
        .await
        .unwrap();

        let cfg = Config {
            lk_base_url: None,
            runtime_mode: RuntimeMode::DbWorker,
            lk_write_contract: LkWriteContract::PgFunction,
            lk_db_dsn: "postgres://localhost/lk".to_string(),
            lk_service_token: None,
            node_external_id: "node-1".to_string(),
            node_hostname: "node-1.example".to_string(),
            node_stage: None,
            node_cluster: None,
            node_namespace: None,
            node_rollout_group: None,
            trusttunnel_runtime_dir: runtime_dir.clone(),
            trusttunnel_config_file: config_file,
            trusttunnel_hosts_file: hosts_file,
            bootstrap_credentials_source_path: None,
            trusttunnel_link_config_file: runtime_dir.join("tt-link.toml"),
            runtime_credentials_path: credentials_file,
            runtime_primary_marker_path: runtime_dir.join(RUNTIME_PRIMARY_MARKER_FILE),
            agent_state_path: runtime_dir.join("agent_state.json"),
            reconcile_interval: Duration::from_secs(60),
            apply_interval: Duration::from_secs(60),
            heartbeat_interval: DEFAULT_DB_WORKER_HEARTBEAT_INTERVAL,
            sync_path_template: None,
            sync_report_path: None,
            apply_cmd: None,
            runtime_pid_path: None,
            runtime_process_name: None,
            endpoint_binary: "trusttunnel_endpoint".to_string(),
            agent_version: "test".to_string(),
            runtime_version: "test".to_string(),
            pending_sync_reports_path: None,
            metrics_address: "127.0.0.1:9901".parse().unwrap(),
            debug_preserve_temp_files: false,
            validation_strict_mode: false,
            syntax_validation_diagnostic_only: false,
            runtime_validation_min_users: DEFAULT_RUNTIME_VALIDATION_MIN_USERS,
            runtime_validation_max_users: DEFAULT_RUNTIME_VALIDATION_MAX_USERS,
        };

        let err = Agent::new(cfg).await.err().unwrap();
        assert!(err.contains("lifecycle writes are enabled"));
    }

    #[tokio::test]
    async fn pending_sync_report_outbox_roundtrip() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.path().join("pending_sync_reports.jsonl");
        let first = PendingSyncReportOwned {
            applied_revision: "1".to_string(),
            status: "ok".to_string(),
            error: None,
            account_exports: vec![],
        };
        let second = PendingSyncReportOwned {
            applied_revision: "2".to_string(),
            status: "error".to_string(),
            error: Some("failed".to_string()),
            account_exports: vec![],
        };

        append_pending_sync_report(&path, &first).await.unwrap();
        append_pending_sync_report(&path, &second).await.unwrap();

        let loaded = load_pending_sync_reports(&path).await.unwrap();
        assert_eq!(loaded, vec![first, second]);
    }

    #[tokio::test]
    async fn persist_pending_sync_report_outbox_clears_file_on_empty_batch() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.path().join("pending_sync_reports.jsonl");
        fs::write(&path, b"{\"applied_revision\":\"1\",\"status\":\"ok\",\"error\":null}\n")
            .await
            .unwrap();

        persist_pending_sync_reports(&path, &[]).await.unwrap();
        assert!(!fs::try_exists(&path).await.unwrap());
    }

    #[test]
    fn agent_metrics_registry_contains_required_metric_families() {
        let metrics = AgentMetrics::new("node-1").unwrap();
        let names = metrics
            .registry
            .gather()
            .iter()
            .map(|family| family.get_name().to_string())
            .collect::<Vec<_>>();

        assert!(!names.is_empty());
        assert!(names.contains(
            &"classic_agent_last_successful_reconcile_timestamp_seconds".to_string()
        ));
        assert!(names.contains(
            &"classic_agent_last_failed_reconcile_timestamp_seconds".to_string()
        ));
        assert!(names.contains(&"classic_agent_apply_duration_milliseconds".to_string()));
        assert!(names.contains(&"classic_agent_credentials_count".to_string()));
        assert!(
            names
                .iter()
                .any(|name| name.starts_with("classic_agent_runtime_health"))
        );
        assert!(names.contains(&"classic_agent_runtime_health_status".to_string()));
        assert!(names.contains(&"classic_agent_endpoint_process_status".to_string()));
        assert!(
            names
                .iter()
                .any(|name| name.starts_with("classic_agent_sidecar_sync_pass"))
        );
        assert!(
            names
                .iter()
                .any(|name| name.starts_with("classic_agent_sidecar_sync_item"))
        );
    }

    #[test]
    fn parse_access_artifacts_reads_clients() {
        let raw = r#"
[[client]]
username = "alice"
password = "secret-1"

[[client]]
username = "bob"
password = "secret-2"
"#;
        let parsed = parse_access_artifacts(raw).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].username, "alice");
        assert_eq!(parsed[1].username, "bob");
    }

    #[test]
    fn parse_access_artifacts_rejects_invalid_toml() {
        let raw = r#"
[[client]]
username = "alice"
password = "secret
"#;
        let err = parse_access_artifacts(raw).unwrap_err();
        assert!(err.contains("failed to parse credentials TOML"));
    }

    #[test]
    fn candidate_validation_parser_rejects_empty_candidate() {
        let err = parse_candidate_credentials_for_validation("").unwrap_err();
        assert!(err.contains("does not contain [[client]] entries"));
    }

    #[test]
    fn unified_parser_is_equivalent_for_candidate_inventory_and_runtime_precheck() {
        let raw = r#"
[[client]]
username = "alice"
password = "secret-1"
max_http2_conns = 100

[[client]]
username = "bob"
password = "secret-2"
max_http3_conns = 3
"#;

        let candidate = parse_access_artifacts(raw).unwrap();
        let inventory = crate::credentials_inventory::parse_inventory_accounts(raw).unwrap();
        let runtime_sample = runtime_validation_sample_username(&candidate);

        assert_eq!(candidate.len(), inventory.len());
        for (candidate_item, inventory_item) in candidate.iter().zip(inventory.iter()) {
            assert_eq!(candidate_item.username, inventory_item.username);
            assert_eq!(candidate_item.password, inventory_item.password);
        }
        assert_eq!(runtime_sample, Some("alice"));
    }

    #[test]
    fn parser_keeps_duplicate_usernames_until_reconcile_step() {
        let raw = r#"
[[client]]
username = "alice"
password = "first"

[[client]]
username = "alice"
password = "second"
"#;

        let parsed = parse_access_artifacts(raw).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].password, "first");
        assert_eq!(parsed[1].password, "second");
    }

    #[test]
    fn runtime_username_derivation_matches_syntax_parser_for_invalid_candidate() {
        let raw = "";
        let syntax_err = parse_candidate_credentials_for_validation(raw).unwrap_err();
        let runtime_err = runtime_validation_usernames_from_raw_toml(raw).unwrap_err();
        assert_eq!(syntax_err, runtime_err);
    }

    #[test]
    fn runtime_validation_selection_is_deterministic_and_limited() {
        let selection = select_runtime_validation_usernames(
            vec![
                "carol".to_string(),
                "alice".to_string(),
                "bob".to_string(),
                "alice".to_string(),
            ],
            1,
            2,
        )
        .unwrap();
        assert_eq!(selection.total, 3);
        assert!(selection.limited);
        assert_eq!(selection.selected, vec!["alice".to_string(), "bob".to_string()]);
    }

    #[test]
    fn runtime_validation_selection_enforces_minimum_users() {
        let err = select_runtime_validation_usernames(vec!["alice".to_string()], 2, 10).unwrap_err();
        assert!(err.contains("below required minimum"));
    }

    #[tokio::test]
    async fn candidate_validation_rewrites_temp_config_with_candidate_credentials_path() {
        let tmp_dir = TempDir::new().unwrap();
        let agent = make_db_worker_agent_for_validation_tests(&tmp_dir, false).await;
        let runtime_dir = agent.cfg.trusttunnel_runtime_dir.clone();
        let candidate = agent
            .write_runtime_credentials_tmp(b"[[client]]\nusername=\"alice\"\npassword=\"secret\"\n")
            .await
            .unwrap();

        let files = agent
            .validate_candidate_credentials_pipeline(candidate.clone())
            .await
            .unwrap();

        let temp_config = std::fs::read_to_string(&files.temp_config_path).unwrap();
        let parsed = temp_config.parse::<toml_edit::Document>().unwrap();
        assert_eq!(
            parsed
                .get("credentials_file")
                .and_then(|item| item.as_str())
                .unwrap(),
            candidate.display().to_string()
        );
        assert_eq!(candidate.parent().unwrap(), runtime_dir.as_path());
        assert_eq!(files.temp_config_path.parent().unwrap(), runtime_dir.as_path());
        assert!(!temp_config.contains("[[client]]"));
        agent
            .cleanup_validation_files(&files, false, false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn runtime_validation_uses_settings_entrypoint_for_temp_config() {
        let tmp_dir = TempDir::new().unwrap();
        let agent = make_db_worker_agent_for_validation_tests(&tmp_dir, false).await;
        let candidate = agent
            .write_runtime_credentials_tmp(b"[[client]]\nusername=\"alice\"\npassword=\"secret\"\n")
            .await
            .unwrap();
        let temp_config_path = agent
            .write_temp_endpoint_config_for_candidate(&candidate)
            .await
            .unwrap();

        let syntax_err = agent
            .validate_candidate_credentials_syntax(&temp_config_path)
            .unwrap_err();
        assert!(syntax_err.contains("credentials TOML does not contain [[client]] entries"));

        agent
            .validate_endpoint_runtime_entrypoint(&temp_config_path, &candidate)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn endpoint_binary_startup_check_detects_present_binary() {
        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_db_worker_agent_for_validation_tests(&tmp_dir, false).await;
        let args_log_path = agent.cfg.trusttunnel_runtime_dir.join("endpoint_args.log");
        let endpoint_binary = make_fake_endpoint_script(&tmp_dir, &args_log_path);
        agent.cfg.endpoint_binary = endpoint_binary;

        agent.resolve_and_validate_endpoint_binary().await.unwrap();
    }

    #[tokio::test]
    async fn endpoint_binary_startup_check_fails_when_binary_missing() {
        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_db_worker_agent_for_validation_tests(&tmp_dir, false).await;
        agent.cfg.endpoint_binary = tmp_dir
            .path()
            .join("missing_trusttunnel_endpoint")
            .display()
            .to_string();

        let err = agent.resolve_and_validate_endpoint_binary().await.unwrap_err();
        assert!(err.contains("trusttunnel_endpoint binary not found at"));
        assert!(err.contains("set TRUSTTUNNEL_ENDPOINT_BIN"));
    }

    #[tokio::test]
    async fn runtime_validation_fails_when_non_first_username_is_invalid() {
        let tmp_dir = TempDir::new().unwrap();
        let agent = make_db_worker_agent_for_validation_tests(&tmp_dir, false).await;
        let runtime_dir = agent.cfg.trusttunnel_runtime_dir.clone();
        let failing_endpoint = runtime_dir.join("fake_endpoint_fail_for_bob.sh");
        std::fs::write(
            &failing_endpoint,
            "#!/bin/sh\nuser=\"\"\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = \"--client_config\" ]; then shift; user=\"$1\"; fi\n  shift\ndone\nif [ \"$user\" = \"bob\" ]; then\n  echo \"broken user\" 1>&2\n  exit 1\nfi\necho \"tt://$user\"\n",
        )
        .unwrap();
        let mut perms = std::fs::metadata(&failing_endpoint).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&failing_endpoint, perms).unwrap();

        let mut validation_agent = agent;
        validation_agent.cfg.endpoint_binary = failing_endpoint.display().to_string();
        let candidate = validation_agent
            .write_runtime_credentials_tmp(
                b"[[client]]\nusername=\"alice\"\npassword=\"secret\"\n\n[[client]]\nusername=\"bob\"\npassword=\"secret2\"\n",
            )
            .await
            .unwrap();

        let err = validation_agent
            .validate_candidate_credentials_pipeline(candidate)
            .await
            .unwrap_err();

        assert!(err.contains("phase=runtime_startup_validation_failed"));
        assert!(err.contains("username=bob"));
        assert!(err.contains("selected usernames"));
    }

    #[tokio::test]
    async fn candidate_validation_failure_keeps_debug_artifacts() {
        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_db_worker_agent_for_validation_tests(&tmp_dir, true).await;
        agent.cfg.syntax_validation_diagnostic_only = true;
        let candidate = agent
            .write_runtime_credentials_tmp(b"credentials_file = \"not-credentials\"")
            .await
            .unwrap();

        let err = agent
            .validate_candidate_credentials_pipeline(candidate.clone())
            .await
            .unwrap_err();
        assert!(err.contains("phase=runtime_startup_validation_failed"));
        assert!(err.contains("validation_path=runtime_entrypoint"));
        assert!(candidate.exists());
    }

    #[tokio::test]
    async fn candidate_validation_fails_fast_on_syntax_error_by_default() {
        let tmp_dir = TempDir::new().unwrap();
        let agent = make_db_worker_agent_for_validation_tests(&tmp_dir, false).await;
        let candidate = agent
            .write_runtime_credentials_tmp(b"credentials_file = \"not-credentials\"")
            .await
            .unwrap();

        let err = agent
            .validate_candidate_credentials_pipeline(candidate)
            .await
            .unwrap_err();

        assert!(err.contains("phase=credentials_validation_failed"));
        assert!(!err.contains("runtime_startup_validation_failed"));
    }

    #[tokio::test]
    async fn candidate_validation_fails_consistently_when_candidate_has_invalid_password_shape() {
        let tmp_dir = TempDir::new().unwrap();
        let agent = make_db_worker_agent_for_validation_tests(&tmp_dir, false).await;
        let candidate = agent
            .write_runtime_credentials_tmp(b"[[client]]\nusername=\"alice\"\npassword=123\n")
            .await
            .unwrap();

        let err = agent
            .validate_candidate_credentials_pipeline(candidate.clone())
            .await
            .unwrap_err();

        assert!(err.contains("phase=credentials_validation_failed"));
        assert!(err.contains("password cannot be empty"));
    }

    #[tokio::test]
    async fn candidate_validation_runtime_failure_marks_runtime_entrypoint_path_in_strict_mode() {
        let tmp_dir = TempDir::new().unwrap();
        let agent =
            make_db_worker_agent_for_validation_tests_with_strict(&tmp_dir, false, true).await;
        let runtime_dir = agent.cfg.trusttunnel_runtime_dir.clone();
        let failing_endpoint = runtime_dir.join("fake_endpoint_fail.sh");
        std::fs::write(&failing_endpoint, "#!/bin/sh\necho \"runtime failed\" 1>&2\nexit 1\n").unwrap();
        let mut perms = std::fs::metadata(&failing_endpoint).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&failing_endpoint, perms).unwrap();

        let mut strict_agent = agent;
        strict_agent.cfg.endpoint_binary = failing_endpoint.display().to_string();
        let candidate = strict_agent
            .write_runtime_credentials_tmp(b"[[client]]\nusername=\"alice\"\npassword=\"secret\"\n")
            .await
            .unwrap();

        let err = strict_agent
            .validate_candidate_credentials_pipeline(candidate)
            .await
            .unwrap_err();

        assert!(err.contains("phase=runtime_startup_validation_failed"));
        assert!(err.contains("validation_path=runtime_entrypoint"));
    }

    #[tokio::test]
    async fn candidate_validation_writes_temp_files_to_runtime_dir_for_absolute_source_config() {
        let tmp_dir = TempDir::new().unwrap();
        let runtime_dir = tmp_dir.path().join("runtime");
        let source_dir = tmp_dir.path().join("source");
        fs::create_dir_all(&runtime_dir).await.unwrap();
        fs::create_dir_all(&source_dir).await.unwrap();

        let source_credentials_file = source_dir.join("credentials.toml");
        let source_rules_file = source_dir.join("rules.toml");
        let source_config_file = source_dir.join("vpn.toml");
        let source_hosts_file = source_dir.join("hosts.toml");
        let source_cert_file = source_dir.join("cert.pem");
        let source_key_file = source_dir.join("key.pem");
        let runtime_credentials_file = runtime_dir.join("credentials.runtime.toml");
        fs::write(&source_credentials_file, b"").await.unwrap();
        fs::write(&source_rules_file, b"").await.unwrap();
        fs::write(&source_cert_file, b"placeholder").await.unwrap();
        fs::write(&source_key_file, b"placeholder").await.unwrap();
        fs::write(
            &source_hosts_file,
            format!(
                r#"
[[main_hosts]]
hostname = "node-1.example"
cert_chain_path = "{}"
private_key_path = "{}"
"#,
                source_cert_file.display(),
                source_key_file.display()
            ),
        )
        .await
        .unwrap();
        fs::write(&runtime_credentials_file, b"").await.unwrap();
        fs::write(
            &source_config_file,
            format!(
                r#"
listen_address = "127.0.0.1:443"
credentials_file = "{}"
rules_file = "{}"

[listen_protocols]

[listen_protocols.http1]
upload_buffer_size = 32768
"#,
                source_credentials_file.display(),
                source_rules_file.display()
            ),
        )
        .await
        .unwrap();
        fs::write(
            runtime_dir.join("tt-link.toml"),
            "node_external_id = \"node-1\"\nserver_address = \"node-1.example:8443\"\ncert_domain = \"node-1.example\"\nprotocol = \"http2\"\n",
        )
        .await
        .unwrap();
        let endpoint_args_log_path = runtime_dir.join("validation-endpoint-args.log");
        let endpoint_binary = make_fake_endpoint_script(&tmp_dir, &endpoint_args_log_path);

        let cfg = Config {
            lk_base_url: Some("http://localhost".to_string()),
            runtime_mode: RuntimeMode::DbWorker,
            lk_write_contract: LkWriteContract::PgFunction,
            lk_db_dsn: "postgres://localhost/lk".to_string(),
            lk_service_token: Some("token".to_string()),
            node_external_id: "node-1".to_string(),
            node_hostname: "node-1.example".to_string(),
            node_stage: None,
            node_cluster: None,
            node_namespace: None,
            node_rollout_group: None,
            trusttunnel_runtime_dir: runtime_dir.clone(),
            trusttunnel_config_file: source_config_file,
            trusttunnel_hosts_file: source_hosts_file,
            bootstrap_credentials_source_path: None,
            trusttunnel_link_config_file: runtime_dir.join("tt-link.toml"),
            runtime_credentials_path: runtime_credentials_file,
            runtime_primary_marker_path: runtime_dir.join(RUNTIME_PRIMARY_MARKER_FILE),
            agent_state_path: runtime_dir.join("agent_state.json"),
            reconcile_interval: Duration::from_secs(10),
            apply_interval: Duration::from_secs(10),
            heartbeat_interval: DEFAULT_DB_WORKER_HEARTBEAT_INTERVAL,
            sync_path_template: None,
            sync_report_path: None,
            apply_cmd: None,
            runtime_pid_path: None,
            runtime_process_name: None,
            endpoint_binary,
            agent_version: "test".to_string(),
            runtime_version: "test".to_string(),
            pending_sync_reports_path: None,
            metrics_address: "127.0.0.1:9901".parse().unwrap(),
            debug_preserve_temp_files: false,
            validation_strict_mode: false,
            syntax_validation_diagnostic_only: false,
            runtime_validation_min_users: DEFAULT_RUNTIME_VALIDATION_MIN_USERS,
            runtime_validation_max_users: DEFAULT_RUNTIME_VALIDATION_MAX_USERS,
        };
        let agent = Agent::new(cfg).await.unwrap();

        let candidate = agent
            .write_runtime_credentials_tmp(b"[[client]]\nusername=\"alice\"\npassword=\"secret\"\n")
            .await
            .unwrap();
        let files = agent
            .validate_candidate_credentials_pipeline(candidate.clone())
            .await
            .unwrap();

        assert_eq!(candidate.parent().unwrap(), runtime_dir.as_path());
        assert_eq!(files.temp_config_path.parent().unwrap(), runtime_dir.as_path());
        agent
            .cleanup_validation_files(&files, false, false)
            .await
            .unwrap();
    }

    #[test]
    fn sidecar_sync_reconcile_plan_detects_new_missing_and_stale() {
        let desired = vec![
            sidecar_sync::AccessArtifact {
                username: "alice".to_string(),
                password: "new".to_string(),
            },
            sidecar_sync::AccessArtifact {
                username: "charlie".to_string(),
                password: "fresh".to_string(),
            },
        ];
        let runtime = vec![
            sidecar_sync::AccessArtifact {
                username: "alice".to_string(),
                password: "old".to_string(),
            },
            sidecar_sync::AccessArtifact {
                username: "bob".to_string(),
                password: "legacy".to_string(),
            },
        ];

        let plan = sidecar_sync::reconcile_plan(&desired, &runtime);
        assert_eq!(plan.stats.found, 2);
        assert_eq!(plan.stats.generated, 1);
        assert_eq!(plan.stats.updated, 1);
        assert_eq!(plan.stats.new_credentials, 1);
        assert_eq!(plan.stats.stale_credentials, 1);
        assert_eq!(plan.stats.missing_credentials, 1);
        assert_eq!(plan.stats.deleted_credentials, 1);
        assert!(plan.changed);
    }

    #[tokio::test]
    async fn sidecar_reconcile_uses_runtime_source_when_bootstrap_is_missing() {
        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_db_worker_agent_for_validation_tests(&tmp_dir, false).await;
        fs::write(
            &agent.cfg.runtime_credentials_path,
            b"[[client]]\nusername=\"alice\"\npassword=\"one\"\n\n[[client]]\nusername=\"bob\"\npassword=\"two\"\n",
        )
        .await
        .unwrap();
        agent.cfg.bootstrap_credentials_source_path = None;

        let plan = agent.run_sidecar_reconcile_plan_phase().await.unwrap();
        assert_eq!(plan.stats.found, 2);
        assert_eq!(plan.stats.missing_credentials, 0);
        assert_eq!(plan.stats.deleted_credentials, 0);
        assert!(!plan.changed);
        assert!(plan.rendered_credentials.contains("[[client]]"));
    }

    #[tokio::test]
    async fn sidecar_export_api_contract_uses_full_snapshot_without_inactive_artifacts() {
        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_db_worker_agent_for_validation_tests(&tmp_dir, false).await;
        fs::write(
            &agent.cfg.runtime_credentials_path,
            b"[[client]]\nusername=\"alice\"\npassword=\"one\"\n",
        )
        .await
        .unwrap();

        let prior_snapshot = credentials_inventory::InventorySnapshot {
            generated_at_unix_sec: chrono::Utc::now().timestamp(),
            export_config_hash: "legacy-hash".to_string(),
            credentials: vec![
                credentials_inventory::InventoryAccount {
                    username: "alice".to_string(),
                    password: "one".to_string(),
                },
                credentials_inventory::InventoryAccount {
                    username: "bob".to_string(),
                    password: "two".to_string(),
                },
            ],
        };
        persist_inventory_state(&agent.workspace.inventory_state_path(), &prior_snapshot).unwrap();

        let (endpoint, request_handle) = run_multi_request_server(vec![
            (
                200,
                r#"{"accepted":true}"#.to_string(),
            ),
            (
                200,
                r#"{"summary":{"created":1,"updated":0,"unchanged":0,"deactivated":1,"failed":0}}"#
                    .to_string(),
            ),
        ])
        .await;
        agent.cfg.lk_write_contract = LkWriteContract::Api;
        agent.cfg.lk_db_dsn = endpoint;
        agent.cfg.lk_service_token = Some("token".to_string());

        agent
            .sync_local_inventory_export_sidecar(InventoryIngestSource::Imported)
            .await
            .unwrap();
        let requests = request_handle.await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("POST /internal/trusttunnel/v1/nodes/node-1/inventory"));
        assert!(requests[0].contains("\"contract_version\":\"v1\""));
        assert!(requests[0].contains("\"credentials\":["));
        assert!(requests[1].contains("POST /internal/trusttunnel/v1/nodes/node-1/artifacts"));
        assert!(requests[1].contains("\"contract_version\":\"v1\""));
        assert!(requests[1].contains("\"artifacts\":["));
        assert!(requests[1].contains("\"username\":\"alice\""));
        assert!(!requests[1].contains("\"username\":\"bob\""));
        assert!(!requests[1].contains("\"is_current\":false"));
    }

    #[tokio::test]
    async fn sidecar_export_does_not_persist_inventory_state_on_lk_write_failure() {
        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_db_worker_agent_for_validation_tests(&tmp_dir, false).await;
        fs::write(
            &agent.cfg.runtime_credentials_path,
            b"[[client]]\nusername=\"alice\"\npassword=\"one\"\n",
        )
        .await
        .unwrap();
        let state_path = agent.workspace.inventory_state_path();
        if fs::try_exists(&state_path).await.unwrap() {
            fs::remove_file(&state_path).await.unwrap();
        }

        let (endpoint, _request_handle) = run_multi_request_server(vec![
            (
                200,
                r#"{"accepted":true}"#.to_string(),
            ),
            (
                500,
                r#"{"error":"downstream unavailable"}"#.to_string(),
            ),
        ])
        .await;
        agent.cfg.lk_write_contract = LkWriteContract::Api;
        agent.cfg.lk_db_dsn = endpoint;
        agent.cfg.lk_service_token = Some("token".to_string());

        let err = agent
            .sync_local_inventory_export_sidecar(InventoryIngestSource::Imported)
            .await
            .unwrap_err();
        assert!(err.contains("HTTP 500"));
        assert!(!fs::try_exists(&state_path).await.unwrap());
    }

    #[tokio::test]
    async fn sidecar_export_fails_when_inventory_delivery_fails() {
        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_db_worker_agent_for_validation_tests(&tmp_dir, false).await;
        fs::write(
            &agent.cfg.runtime_credentials_path,
            b"[[client]]\nusername=\"alice\"\npassword=\"one\"\n",
        )
        .await
        .unwrap();
        let state_path = agent.workspace.inventory_state_path();

        let (endpoint, _request_handle) = run_multi_request_server(vec![
            (500, r#"{"error":"inventory unavailable"}"#.to_string()),
            (500, r#"{"error":"inventory unavailable"}"#.to_string()),
            (500, r#"{"error":"inventory unavailable"}"#.to_string()),
        ])
        .await;
        agent.cfg.lk_write_contract = LkWriteContract::Api;
        agent.cfg.lk_db_dsn = endpoint;
        agent.cfg.lk_service_token = Some("token".to_string());

        let err = agent
            .sync_local_inventory_export_sidecar(InventoryIngestSource::Imported)
            .await
            .unwrap_err();
        assert!(err.contains("inventory ingest returned HTTP 500"));
        assert!(!fs::try_exists(&state_path).await.unwrap());
    }

    #[cfg(feature = "legacy-lk-http")]
    #[tokio::test]
    async fn reconcile_once_valid_config_applies_and_reports_success() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_agent(&tmp_dir, &server.base_url, Some("true")).await;
        fs::write(&agent.cfg.runtime_credentials_path, b"[[client]]\nusername=\"old\"\npassword=\"old\"\n")
            .await
            .unwrap();
        let body = snapshot_json(
            "v1",
            "active",
            true,
            vec![Account {
                username: "alice".to_string(),
                password: "secret".to_string(),
                enabled: true,
                assigned: true,
                free: false,
                revoked: false,
                frozen: false,
                external_account_id: Some("acc-1".to_string()),
                access_bundle_id: Some("bundle-1".to_string()),
                tt_link: String::new(),
                tt_link_config_hash: String::new(),
                tt_link_stale: false,
            }],
        );
        server
            .enqueue(
                Method::GET,
                "/sync/node-1",
                HyperStatusCode::OK,
                body.clone(),
            )
            .await;
        server
            .enqueue(Method::POST, "/sync-report", HyperStatusCode::OK, "")
            .await;

        agent.reconcile_once().await.unwrap();
        let creds = fs::read_to_string(&agent.cfg.runtime_credentials_path)
            .await
            .unwrap();
        assert!(creds.contains("username = \"alice\""));
        assert_eq!(agent.state.applied_revision.as_deref(), Some("v1"));
        assert!(
            !fs::try_exists(agent.cfg.pending_sync_reports_path.as_ref().unwrap())
                .await
                .unwrap()
        );

        let requests = server.captured().await;
        let report = requests
            .iter()
            .find(|x| x.method == Method::POST && x.path == "/sync-report")
            .unwrap();
        assert!(report.body.contains("\"last_sync_status\":\"ok\""));
        assert!(report.body.contains("\"applied_revision\":\"v1\""));
        assert!(report.body.contains("\"external_node_id\":\"node-1\""));
        assert!(report.body.contains("\"tt_link\":\"tt://"));
        assert!(report.body.contains("\"config_hash\":\""));
    }

    #[cfg(feature = "legacy-lk-http")]
    #[tokio::test]
    async fn reconcile_once_onboarding_not_active_skips_apply() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_agent(&tmp_dir, &server.base_url, Some("true")).await;
        let body = snapshot_json("v1", "pending", true, vec![]);
        server
            .enqueue(Method::GET, "/sync/node-1", HyperStatusCode::OK, body)
            .await;
        server
            .enqueue(Method::POST, "/sync-report", HyperStatusCode::OK, "")
            .await;

        agent.reconcile_once().await.unwrap();
        assert_eq!(agent.last_apply_status, "skipped");
        let requests = server.captured().await;
        let report = requests
            .iter()
            .find(|x| x.method == Method::POST && x.path == "/sync-report")
            .unwrap();
        assert!(report.body.contains("\"last_sync_status\":\"skipped\""));
    }

    #[cfg(feature = "legacy-lk-http")]
    #[tokio::test]
    async fn reconcile_once_sync_required_false_skips_apply() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_agent(&tmp_dir, &server.base_url, Some("true")).await;
        let body = snapshot_json("v1", "active", false, vec![]);
        server
            .enqueue(Method::GET, "/sync/node-1", HyperStatusCode::OK, body)
            .await;
        server
            .enqueue(Method::POST, "/sync-report", HyperStatusCode::OK, "")
            .await;

        agent.reconcile_once().await.unwrap();
        assert_eq!(agent.last_apply_status, "skipped");
        let requests = server.captured().await;
        let report = requests
            .iter()
            .find(|x| x.method == Method::POST && x.path == "/sync-report")
            .unwrap();
        assert!(report.body.contains("\"last_sync_status\":\"skipped\""));
    }

    #[cfg(feature = "legacy-lk-http")]
    #[tokio::test]
    async fn reconcile_once_apply_failure_rolls_back_runtime_credentials() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_agent(&tmp_dir, &server.base_url, Some("false")).await;
        let original = b"[[client]]\nusername=\"before\"\npassword=\"before\"\n";
        fs::write(&agent.cfg.runtime_credentials_path, original)
            .await
            .unwrap();
        let body = snapshot_json(
            "v2",
            "active",
            true,
            vec![Account {
                username: "alice".to_string(),
                password: "new".to_string(),
                enabled: true,
                assigned: true,
                free: false,
                revoked: false,
                frozen: false,
                external_account_id: None,
                access_bundle_id: None,
                tt_link: String::new(),
                tt_link_config_hash: String::new(),
                tt_link_stale: false,
            }],
        );
        server
            .enqueue(Method::GET, "/sync/node-1", HyperStatusCode::OK, body)
            .await;
        server
            .enqueue(Method::POST, "/sync-report", HyperStatusCode::OK, "")
            .await;

        let err = agent.reconcile_once().await.unwrap_err();
        assert!(err.contains("rollback"));
        let creds = fs::read(&agent.cfg.runtime_credentials_path).await.unwrap();
        assert_eq!(creds, original);
    }

    #[cfg(feature = "legacy-lk-http")]
    #[tokio::test]
    async fn failed_apply_with_sync_report_error_is_queued_for_retry() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_agent(&tmp_dir, &server.base_url, Some("false")).await;
        fs::write(
            &agent.cfg.runtime_credentials_path,
            b"[[client]]\nusername=\"old\"\npassword=\"old\"\n",
        )
        .await
        .unwrap();
        let body = snapshot_json(
            "v3",
            "active",
            true,
            vec![Account {
                username: "alice".to_string(),
                password: "new".to_string(),
                enabled: true,
                assigned: true,
                free: false,
                revoked: false,
                frozen: false,
                external_account_id: None,
                access_bundle_id: None,
                tt_link: String::new(),
                tt_link_config_hash: String::new(),
                tt_link_stale: false,
            }],
        );
        server
            .enqueue(Method::GET, "/sync/node-1", HyperStatusCode::OK, body)
            .await;
        server
            .enqueue(
                Method::POST,
                "/sync-report",
                HyperStatusCode::INTERNAL_SERVER_ERROR,
                "",
            )
            .await;

        let _ = agent.reconcile_once().await.unwrap_err();
        assert!(
            fs::try_exists(agent.cfg.pending_sync_reports_path.as_ref().unwrap())
                .await
                .unwrap()
        );
        let queued = load_pending_sync_reports(agent.cfg.pending_sync_reports_path.as_ref().unwrap())
            .await
            .unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].status, "error");
    }

    #[cfg(feature = "legacy-lk-http")]
    #[tokio::test]
    async fn db_worker_registers_on_startup_with_contract_v1_payload() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_agent(&tmp_dir, &server.base_url, None).await;
        agent.cfg.heartbeat_interval = Duration::from_millis(40);
        agent.cfg.reconcile_interval = Duration::from_secs(3600);
        agent.cfg.apply_interval = Duration::from_secs(3600);
        server
            .enqueue(
                Method::POST,
                DEFAULT_REGISTER_PATH,
                HyperStatusCode::OK,
                r#"{"accepted":true}"#,
            )
            .await;
        for _ in 0..4 {
            server
                .enqueue(
                    Method::POST,
                    DEFAULT_HEARTBEAT_PATH,
                    HyperStatusCode::OK,
                    r#"{"accepted":true}"#,
                )
                .await;
        }

        let worker = tokio::spawn(async move {
            agent.run_db_worker_loop().await;
        });
        let requests =
            wait_for_captured_requests(&server, 2, Duration::from_secs(2)).await;
        worker.abort();

        let register = requests
            .iter()
            .find(|x| x.method == Method::POST && x.path == DEFAULT_REGISTER_PATH)
            .unwrap();
        let payload: serde_json::Value = serde_json::from_str(&register.body).unwrap();
        assert_eq!(payload["contract_version"], "v1");
        assert_eq!(payload["external_node_id"], "node-1");
        assert_eq!(payload["hostname"], "node-1.example");
        assert_eq!(payload["agent_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(payload["runtime_version"], "test");
        assert_eq!(payload["cluster"], "cluster-a");
        assert_eq!(payload["stage"], "prod");
    }

    #[cfg(feature = "legacy-lk-http")]
    #[tokio::test]
    async fn db_worker_sends_periodic_heartbeat_and_observes_accepted_responses() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_agent(&tmp_dir, &server.base_url, None).await;
        agent.cfg.heartbeat_interval = Duration::from_millis(40);
        agent.cfg.reconcile_interval = Duration::from_secs(3600);
        agent.cfg.apply_interval = Duration::from_secs(3600);
        agent.db_worker_health.inventory_status = DbWorkerSignalStatus::Ok;
        agent.db_worker_health.artifacts_status = DbWorkerSignalStatus::Ok;
        server
            .enqueue(
                Method::POST,
                DEFAULT_REGISTER_PATH,
                HyperStatusCode::OK,
                r#"{"accepted":true}"#,
            )
            .await;
        for _ in 0..8 {
            server
                .enqueue(
                    Method::POST,
                    DEFAULT_HEARTBEAT_PATH,
                    HyperStatusCode::OK,
                    r#"{"accepted":true}"#,
                )
                .await;
        }

        let worker = tokio::spawn(async move {
            agent.run_db_worker_loop().await;
        });
        let requests =
            wait_for_captured_requests(&server, 4, Duration::from_secs(2)).await;
        worker.abort();

        let heartbeats: Vec<&CapturedRequest> = requests
            .iter()
            .filter(|x| x.method == Method::POST && x.path == DEFAULT_HEARTBEAT_PATH)
            .collect();
        assert!(heartbeats.len() >= 2);
        let first_payload: serde_json::Value = serde_json::from_str(&heartbeats[0].body).unwrap();
        assert_eq!(first_payload["contract_version"], "v1");
        let health_status = first_payload["health_status"].as_str().unwrap();
        assert!(matches!(health_status, "ok" | "degraded" | "disabled"));
        assert_eq!(first_payload["stats"]["last_apply_status"], "pending");
    }

    #[cfg(feature = "legacy-lk-http")]
    #[tokio::test]
    async fn db_worker_heartbeat_does_not_disable_live_node_without_legacy_pid() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_agent(&tmp_dir, &server.base_url, None).await;
        agent.cfg.runtime_pid_path = None;
        agent.db_worker_health.inventory_status = DbWorkerSignalStatus::Ok;
        agent.db_worker_health.artifacts_status = DbWorkerSignalStatus::Ok;
        server
            .enqueue(
                Method::POST,
                DEFAULT_HEARTBEAT_PATH,
                HyperStatusCode::OK,
                r#"{"accepted":true}"#,
            )
            .await;

        agent.send_heartbeat().await.unwrap();
        let requests = server.captured().await;
        let heartbeat = requests
            .iter()
            .find(|x| x.method == Method::POST && x.path == DEFAULT_HEARTBEAT_PATH)
            .unwrap();
        let payload: serde_json::Value = serde_json::from_str(&heartbeat.body).unwrap();
        assert_eq!(payload["health_status"], "ok");
        assert_ne!(payload["health_status"], "disabled");
    }

    #[cfg(feature = "legacy-lk-http")]
    #[tokio::test]
    async fn lk_happy_path_register_heartbeat_inventory_artifacts_keeps_order_and_contract() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_agent(&tmp_dir, &server.base_url, None).await;
        fs::write(
            &agent.cfg.runtime_credentials_path,
            b"[[client]]\nusername=\"alice\"\npassword=\"one\"\n",
        )
        .await
        .unwrap();
        agent.cfg.lk_write_contract = LkWriteContract::Api;
        agent.cfg.lk_db_dsn = format!(
            "{}/internal/trusttunnel/v1/nodes/{{externalNodeId}}/artifacts",
            server.base_url
        );
        server
            .enqueue(
                Method::POST,
                DEFAULT_REGISTER_PATH,
                HyperStatusCode::OK,
                r#"{"accepted":true}"#,
            )
            .await;
        server
            .enqueue(
                Method::POST,
                DEFAULT_HEARTBEAT_PATH,
                HyperStatusCode::OK,
                r#"{"accepted":true}"#,
            )
            .await;
        server
            .enqueue(
                Method::POST,
                "/internal/trusttunnel/v1/nodes/node-1/inventory",
                HyperStatusCode::OK,
                r#"{"accepted":true}"#,
            )
            .await;
        server
            .enqueue(
                Method::POST,
                "/internal/trusttunnel/v1/nodes/node-1/artifacts",
                HyperStatusCode::OK,
                r#"{"summary":{"created":1,"updated":0,"unchanged":0,"deactivated":0,"failed":0}}"#,
            )
            .await;

        agent.bootstrap_register().await;
        agent.send_heartbeat().await.unwrap();
        agent
            .sync_local_inventory_export_sidecar(InventoryIngestSource::Imported)
            .await
            .unwrap();

        let requests = server.captured().await;
        let sequence: Vec<&str> = requests.iter().map(|x| x.path.as_str()).collect();
        assert_eq!(
            sequence,
            vec![
                DEFAULT_REGISTER_PATH,
                DEFAULT_HEARTBEAT_PATH,
                "/internal/trusttunnel/v1/nodes/node-1/inventory",
                "/internal/trusttunnel/v1/nodes/node-1/artifacts",
            ]
        );
        let register: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
        let heartbeat: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
        let inventory: serde_json::Value = serde_json::from_str(&requests[2].body).unwrap();
        let artifacts: serde_json::Value = serde_json::from_str(&requests[3].body).unwrap();
        assert_eq!(register["contract_version"], "v1");
        assert_eq!(heartbeat["contract_version"], "v1");
        assert_eq!(inventory["contract_version"], "v1");
        assert_eq!(artifacts["contract_version"], "v1");
        assert_eq!(inventory["external_node_id"], "node-1");
        assert_eq!(artifacts["external_node_id"], "node-1");
    }

    #[cfg(feature = "legacy-lk-http")]
    #[tokio::test]
    async fn canonical_inventory_payload_is_accepted_without_invalid_input() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let request_handle = tokio::spawn(async move {
            let mut captured = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = vec![0_u8; 65536];
                let size = stream.read(&mut buffer).await.unwrap();
                let request = String::from_utf8_lossy(&buffer[..size]).to_string();
                let is_inventory = request.contains("/inventory");
                let (status, body) = if is_inventory
                    && request.contains("\"contract_version\":\"v1\"")
                    && request.contains("\"snapshot_version\":\"v1\"")
                    && request.contains("\"external_node_id\":\"node-1\"")
                    && request.contains("\"credentials\":[")
                {
                    (200, r#"{"accepted":true}"#)
                } else if is_inventory {
                    (
                        400,
                        r#"{"error":"invalid_input","details":"inventory shape mismatch"}"#,
                    )
                } else {
                    (
                        200,
                        r#"{"summary":{"created":1,"updated":0,"unchanged":0,"deactivated":0,"failed":0}}"#,
                    )
                };
                let response = format!(
                    "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                captured.push(request);
            }
            captured
        });

        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_db_worker_agent_for_validation_tests(&tmp_dir, false).await;
        fs::write(
            &agent.cfg.runtime_credentials_path,
            b"[[client]]\nusername=\"alice\"\npassword=\"one\"\n",
        )
        .await
        .unwrap();
        agent.cfg.lk_write_contract = LkWriteContract::Api;
        agent.cfg.lk_db_dsn = format!(
            "http://{address}/internal/trusttunnel/v1/nodes/{{externalNodeId}}/artifacts"
        );
        agent.cfg.lk_service_token = Some("token".to_string());

        agent
            .sync_local_inventory_export_sidecar(InventoryIngestSource::Imported)
            .await
            .unwrap();
        let requests = request_handle.await.unwrap();
        assert!(requests[0].contains("/inventory"));
        assert!(requests[0].contains("\"contract_version\":\"v1\""));
        assert!(!requests[0].contains("\"error\":\"invalid_input\""));
    }

    #[cfg(feature = "legacy-lk-http")]
    #[tokio::test]
    async fn register_retries_on_temporary_lk_unavailability() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let agent = make_agent(&tmp_dir, &server.base_url, None).await;
        server
            .enqueue(
                Method::POST,
                DEFAULT_REGISTER_PATH,
                HyperStatusCode::SERVICE_UNAVAILABLE,
                "",
            )
            .await;
        server
            .enqueue(Method::POST, DEFAULT_REGISTER_PATH, HyperStatusCode::OK, "")
            .await;

        let started = std::time::Instant::now();
        agent.bootstrap_register().await;
        assert!(started.elapsed() >= REGISTER_INITIAL_BACKOFF);
    }

    #[cfg(feature = "legacy-lk-http")]
    #[tokio::test]
    async fn register_payload_uses_canonical_v1_contract() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let agent = make_agent(&tmp_dir, &server.base_url, None).await;
        server
            .enqueue(Method::POST, DEFAULT_REGISTER_PATH, HyperStatusCode::OK, "")
            .await;

        let outcome = agent.send_register_once().await.unwrap();
        assert!(matches!(outcome, RegisterAttemptOutcome::Registered));

        let requests = server.captured().await;
        let register = requests
            .iter()
            .find(|x| x.method == Method::POST && x.path == DEFAULT_REGISTER_PATH)
            .unwrap();
        let body: serde_json::Value = serde_json::from_str(&register.body).unwrap();
        assert_eq!(body["contract_version"], "v1");
        assert_eq!(body["external_node_id"], "node-1");
        assert_eq!(body["hostname"], "node-1.example");
        assert_eq!(body["agent_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(body["runtime_version"], "test");
        assert_eq!(body["stage"], "prod");
        assert_eq!(body["cluster"], "cluster-a");
        assert!(body.get("node_identity").is_none());
        assert!(body.get("trusttunnel_runtime_dir").is_none());
    }

    #[cfg(feature = "legacy-lk-http")]
    #[tokio::test]
    async fn register_bad_request_returns_diagnostic_without_secret_token() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let agent = make_agent(&tmp_dir, &server.base_url, None).await;
        server
            .enqueue(
                Method::POST,
                DEFAULT_REGISTER_PATH,
                HyperStatusCode::BAD_REQUEST,
                r#"{"error":"missing field: contract_version"}"#,
            )
            .await;

        let err = agent.send_register_once().await.unwrap_err();
        let rendered = match err {
            RegisterError::Permanent(detail) => detail,
            RegisterError::Temporary(detail) => detail,
        };
        assert!(rendered.contains("status=400 Bad Request"));
        assert!(rendered.contains("missing_field"));
        assert!(rendered.contains("response_body={\"error\":\"missing field: contract_version\"}"));
        assert!(!rendered.contains("test-token"));
    }

    #[test]
    fn register_reason_summary_detects_invalid_node_identity() {
        let reason = summarize_register_reason(
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid node identity"}"#,
        );
        assert_eq!(reason, "invalid_node_identity");
    }

    #[cfg(feature = "legacy-lk-http")]
    #[tokio::test]
    async fn heartbeat_loop_is_resilient_to_temporary_lk_errors() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let agent = make_agent(&tmp_dir, &server.base_url, None).await;
        server
            .enqueue(
                Method::POST,
                DEFAULT_HEARTBEAT_PATH,
                HyperStatusCode::INTERNAL_SERVER_ERROR,
                "",
            )
            .await;
        server
            .enqueue(
                Method::POST,
                DEFAULT_HEARTBEAT_PATH,
                HyperStatusCode::BAD_GATEWAY,
                "",
            )
            .await;
        server
            .enqueue(Method::POST, DEFAULT_HEARTBEAT_PATH, HyperStatusCode::OK, "")
            .await;

        agent.send_heartbeat_with_retry().await;
        let requests = server.captured().await;
        let heartbeat_count = requests
            .iter()
            .filter(|x| x.method == Method::POST && x.path == DEFAULT_HEARTBEAT_PATH)
            .count();
        assert_eq!(heartbeat_count, 3);
    }

    #[cfg(feature = "legacy-lk-http")]
    #[tokio::test]
    async fn heartbeat_payload_uses_lk_v1_normalized_fields() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_agent(&tmp_dir, &server.base_url, None).await;
        agent.state.applied_revision = None;
        agent.last_apply_status = "".to_string();
        server
            .enqueue(Method::POST, DEFAULT_HEARTBEAT_PATH, HyperStatusCode::OK, "")
            .await;

        agent.send_heartbeat().await.unwrap();

        let requests = server.captured().await;
        let heartbeat = requests
            .iter()
            .find(|x| x.method == Method::POST && x.path == DEFAULT_HEARTBEAT_PATH)
            .unwrap();
        let body: serde_json::Value = serde_json::from_str(&heartbeat.body).unwrap();
        assert_eq!(body["contract_version"], "v1");
        assert!(body["current_revision"].is_null());
        assert_eq!(body["health_status"], "disabled");
        assert_eq!(body["stats"]["last_apply_status"], "pending");
        assert!(body.get("active_clients").is_none());
        assert!(body.get("timestamp").is_none());
    }

    #[cfg(feature = "legacy-lk-http")]
    #[tokio::test]
    async fn temporary_lk_sync_failure_does_not_break_subsequent_sync() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_agent(&tmp_dir, &server.base_url, Some("true")).await;
        let valid_body = snapshot_json(
            "v4",
            "active",
            true,
            vec![Account {
                username: "ok".to_string(),
                password: "ok".to_string(),
                enabled: true,
                assigned: true,
                free: false,
                revoked: false,
                frozen: false,
                external_account_id: None,
                access_bundle_id: None,
                tt_link: String::new(),
                tt_link_config_hash: String::new(),
                tt_link_stale: false,
            }],
        );
        server
            .enqueue(
                Method::GET,
                "/sync/node-1",
                HyperStatusCode::SERVICE_UNAVAILABLE,
                "",
            )
            .await;
        server
            .enqueue(Method::GET, "/sync/node-1", HyperStatusCode::OK, valid_body)
            .await;
        server
            .enqueue(Method::POST, "/sync-report", HyperStatusCode::OK, "")
            .await;

        assert!(agent.reconcile_once().await.is_err());
        assert!(agent.reconcile_once().await.is_ok());
    }

    #[cfg(feature = "legacy-lk-http")]
    #[tokio::test]
    async fn sync_http_409_is_handled_without_crash() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let mut agent = make_agent(&tmp_dir, &server.base_url, Some("true")).await;
        server
            .enqueue(Method::GET, "/sync/node-1", HyperStatusCode::CONFLICT, "onboarding_not_ready")
            .await;

        assert!(agent.reconcile_once().await.is_ok());
        let requests = server.captured().await;
        let sync_report_count = requests
            .iter()
            .filter(|x| x.method == Method::POST && x.path == "/sync-report")
            .count();
        assert_eq!(sync_report_count, 0);
    }

    #[cfg(feature = "legacy-lk-http")]
    #[tokio::test]
    async fn fetch_accounts_uses_current_node_external_id_in_sync_path() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let agent = make_agent(&tmp_dir, &server.base_url, None).await;
        let body = snapshot_json("v5", "active", true, vec![]);
        server
            .enqueue(Method::GET, "/sync/node-1", HyperStatusCode::OK, body)
            .await;

        let response = agent.fetch_accounts_by_node().await.unwrap();
        assert!(response.is_some());

        let requests = server.captured().await;
        let sync_paths = requests
            .iter()
            .filter(|x| x.method == Method::GET)
            .map(|x| x.path.clone())
            .collect::<Vec<_>>();
        assert_eq!(sync_paths, vec!["/sync/node-1".to_string()]);
    }

    #[tokio::test]
    async fn state_persistence_keeps_applied_revision() {
        let tmp_dir = TempDir::new().unwrap();
        let state_path = tmp_dir.path().join("agent_state.json");
        let state = AgentState {
            applied_revision: Some("rev-123".to_string()),
            last_target_revision: Some("rev-124".to_string()),
            credentials_sha256: "abc".to_string(),
        };
        persist_state(&state_path, &state).await.unwrap();

        let loaded = load_state(&state_path).await.unwrap();
        assert_eq!(loaded.applied_revision.as_deref(), Some("rev-123"));
        assert_eq!(loaded.last_target_revision.as_deref(), Some("rev-124"));
    }

    #[test]
    fn split_host_port_accepts_domain_and_bracketed_ipv6() {
        let domain = split_host_port("edge.example.com:443").unwrap();
        let ipv6 = split_host_port("[2001:db8::1]:8443").unwrap();

        assert_eq!(domain, ("edge.example.com".to_string(), 443));
        assert_eq!(ipv6, ("2001:db8::1".to_string(), 8443));
    }

    #[test]
    fn split_host_port_rejects_unbracketed_ipv6() {
        let err = split_host_port("2001:db8::1:443").unwrap_err();
        assert!(err.contains("host:port or [ipv6]:port"));
    }

    #[test]
    fn derive_inventory_endpoint_replaces_artifacts_path() {
        let endpoint = derive_inventory_endpoint(
            "https://lk.example/internal/trusttunnel/v1/nodes/{externalNodeId}/artifacts",
            "node-1",
        )
        .unwrap();
        assert_eq!(
            endpoint,
            "https://lk.example/internal/trusttunnel/v1/nodes/node-1/inventory"
        );
    }

    #[test]
    fn derive_lifecycle_base_url_uses_scheme_and_host_from_artifacts_endpoint() {
        let base_url = derive_lifecycle_base_url_from_artifacts_endpoint(
            "https://lk.example:8443/internal/trusttunnel/v1/nodes/{externalNodeId}/artifacts",
        )
        .unwrap();
        assert_eq!(base_url, "https://lk.example:8443");
    }

    #[test]
    fn derive_lifecycle_base_url_returns_none_for_non_url_dsn() {
        let postgres = derive_lifecycle_base_url_from_artifacts_endpoint("postgres://localhost/lk");
        assert!(postgres.is_none());
        let invalid = derive_lifecycle_base_url_from_artifacts_endpoint("not-a-url");
        assert!(invalid.is_none());
    }

    #[test]
    fn inventory_payload_ids_are_stable_for_same_snapshot() {
        let snapshot = credentials_inventory::InventorySnapshot {
            generated_at_unix_sec: 1_710_000_000,
            export_config_hash: "cfg-hash".to_string(),
            credentials: vec![credentials_inventory::InventoryAccount {
                username: "alice".to_string(),
                password: "secret".to_string(),
            }],
        };
        let first =
            build_inventory_ingest_payload("node-1", &snapshot, InventoryIngestSource::Imported)
                .unwrap();
        let second =
            build_inventory_ingest_payload("node-1", &snapshot, InventoryIngestSource::Imported)
                .unwrap();
        assert_eq!(first.idempotency_key, second.idempotency_key);
        assert_eq!(first.request_id, second.request_id);
        assert_eq!(first.snapshot_version, "v1");
    }

    #[test]
    fn inventory_payload_matches_lk_contract_v1_shape() {
        let snapshot = credentials_inventory::InventorySnapshot {
            generated_at_unix_sec: 1_710_000_000,
            export_config_hash: "cfg-hash".to_string(),
            credentials: vec![credentials_inventory::InventoryAccount {
                username: "alice".to_string(),
                password: "secret".to_string(),
            }],
        };
        let payload =
            build_inventory_ingest_payload("node-1", &snapshot, InventoryIngestSource::Bootstrap)
                .unwrap();
        let value = serde_json::to_value(&payload).unwrap();

        assert_eq!(value["contract_version"], "v1");
        assert_eq!(value["snapshot_version"], "v1");
        assert_eq!(value["external_node_id"], "node-1");
        assert_eq!(value["source"], "bootstrap");
        assert!(value["revision"].is_i64());
        assert_eq!(value["revision"], 1_710_000_000_i64);
        assert!(value["exported_at"].as_str().unwrap().contains('T'));
        assert!(value["idempotency_key"].as_str().unwrap().starts_with("inventory-v1-"));
        assert!(value["request_id"].as_str().unwrap().starts_with("inventory-req-"));
        assert_eq!(value["credentials"][0]["username"], "alice");
        assert_eq!(value["credentials"][0]["password"], "secret");
    }

    #[test]
    fn inventory_source_uses_only_contract_values() {
        assert_eq!(InventoryIngestSource::Bootstrap.as_str(), "bootstrap");
        assert_eq!(InventoryIngestSource::Imported.as_str(), "imported");
    }

    #[test]
    fn inventory_error_details_include_field_level_mismatch() {
        let body = r#"{"error":"invalid_input","errors":[{"field":"snapshot_version","message":"must be equal to v1"}]}"#;
        let rendered = inventory_error_details(body);
        assert!(rendered.contains("snapshot_version"));
        assert!(rendered.contains("must be equal to v1"));
    }

    #[test]
    fn extract_contract_mismatch_detail_reads_top_level_field_message() {
        let body = r#"{"field":"credentials","message":"must not be empty"}"#;
        assert_eq!(
            extract_contract_mismatch_detail(body).as_deref(),
            Some("credentials: must not be empty")
        );
    }

    #[test]
    fn db_worker_phase_schedule_uses_distinct_reconcile_and_apply_intervals() {
        let cfg = Config {
            lk_base_url: None,
            runtime_mode: RuntimeMode::DbWorker,
            lk_write_contract: LkWriteContract::PgFunction,
            lk_db_dsn: "postgres://localhost/lk".to_string(),
            lk_service_token: None,
            node_external_id: "node-1".to_string(),
            node_hostname: "node-1.example".to_string(),
            node_stage: None,
            node_cluster: None,
            node_namespace: None,
            node_rollout_group: None,
            trusttunnel_runtime_dir: PathBuf::from("/tmp/runtime"),
            trusttunnel_config_file: PathBuf::from("vpn.toml"),
            trusttunnel_hosts_file: PathBuf::from("hosts.toml"),
            bootstrap_credentials_source_path: None,
            trusttunnel_link_config_file: PathBuf::from("tt-link.toml"),
            runtime_credentials_path: PathBuf::from("/tmp/runtime/credentials.toml"),
            runtime_primary_marker_path: PathBuf::from("/tmp/runtime/.runtime_credentials_primary"),
            agent_state_path: PathBuf::from("/tmp/runtime/agent_state.json"),
            reconcile_interval: Duration::from_secs(17),
            apply_interval: Duration::from_secs(43),
            heartbeat_interval: DEFAULT_DB_WORKER_HEARTBEAT_INTERVAL,
            sync_path_template: None,
            sync_report_path: None,
            apply_cmd: None,
            runtime_pid_path: None,
            runtime_process_name: None,
            endpoint_binary: "trusttunnel_endpoint".to_string(),
            agent_version: "test".to_string(),
            runtime_version: "test".to_string(),
            pending_sync_reports_path: None,
            metrics_address: "127.0.0.1:9901".parse().unwrap(),
            debug_preserve_temp_files: false,
            validation_strict_mode: false,
            syntax_validation_diagnostic_only: false,
            runtime_validation_min_users: DEFAULT_RUNTIME_VALIDATION_MIN_USERS,
            runtime_validation_max_users: DEFAULT_RUNTIME_VALIDATION_MAX_USERS,
        };

        let schedule = DbWorkerPhaseSchedule::from_config(&cfg);
        assert_eq!(schedule.reconcile_plan_interval, Duration::from_secs(17));
        assert_eq!(schedule.apply_interval, Duration::from_secs(43));
        assert_eq!(schedule.export_write_interval, Duration::from_secs(43));
    }

    #[test]
    fn db_worker_tick_kind_has_stable_log_labels() {
        assert_eq!(DbWorkerTickKind::Reconcile.as_str(), "reconcile");
        assert_eq!(DbWorkerTickKind::Apply.as_str(), "apply");
    }
}
