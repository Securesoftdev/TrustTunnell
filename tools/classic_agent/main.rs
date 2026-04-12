mod lk_api;

use lk_api::{
    Account, HeartbeatPayload, LkApiClient, NodeMetadata, OnboardingPayload, SyncPayload,
    SyncReportPayload,
    DEFAULT_HEARTBEAT_PATH, DEFAULT_REGISTER_PATH, DEFAULT_SYNC_PATH_TEMPLATE,
    DEFAULT_SYNC_REPORT_PATH,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::read_dir;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs;
use tokio::process::Command;
use tokio::time::{interval, MissedTickBehavior};

const REGISTER_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const REGISTER_MAX_BACKOFF: Duration = Duration::from_secs(60);
const HEARTBEAT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const HEARTBEAT_MAX_BACKOFF: Duration = Duration::from_secs(30);
const HEARTBEAT_MAX_ATTEMPTS: usize = 3;

#[derive(Clone)]
struct Config {
    lk_base_url: String,
    lk_service_token: String,
    node_external_id: String,
    node_hostname: String,
    node_stage: String,
    node_cluster: String,
    node_namespace: String,
    node_rollout_group: String,
    node_public_host: Option<String>,
    node_public_port: Option<u16>,
    node_display_name: Option<String>,
    trusttunnel_runtime_dir: PathBuf,
    trusttunnel_credentials_file: PathBuf,
    trusttunnel_config_file: PathBuf,
    trusttunnel_hosts_file: PathBuf,
    runtime_credentials_path: PathBuf,
    agent_state_path: PathBuf,
    poll_interval: Duration,
    heartbeat_interval: Duration,
    sync_path_template: String,
    sync_report_path: String,
    heartbeat_path: String,
    register_path: String,
    apply_cmd: Option<String>,
    runtime_pid_path: PathBuf,
    runtime_process_name: String,
    runtime_version: String,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let lk_base_url = required_env("LK_BASE_URL")?;
        let lk_service_token = required_env("LK_SERVICE_TOKEN")?;
        let node_external_id = required_env("NODE_EXTERNAL_ID")?;
        let node_hostname = required_env("NODE_HOSTNAME")?;
        let node_stage = required_env("NODE_STAGE")?;
        let node_cluster = required_env("NODE_CLUSTER")?;
        let node_namespace = required_env("NODE_NAMESPACE")?;
        let node_rollout_group = required_env("NODE_ROLLOUT_GROUP")?;
        let trusttunnel_runtime_dir: PathBuf = required_env("TRUSTTUNNEL_RUNTIME_DIR")?.into();
        let trusttunnel_credentials_file: PathBuf =
            required_env("TRUSTTUNNEL_CREDENTIALS_FILE")?.into();
        let trusttunnel_config_file: PathBuf = required_env("TRUSTTUNNEL_CONFIG_FILE")?.into();
        let trusttunnel_hosts_file: PathBuf = required_env("TRUSTTUNNEL_HOSTS_FILE")?.into();
        let node_public_host = optional_env("NODE_PUBLIC_HOST");
        let node_public_port = optional_env("NODE_PUBLIC_PORT")
            .map(|raw| {
                raw.parse::<u16>()
                    .map_err(|e| format!("NODE_PUBLIC_PORT must be u16: {e}"))
            })
            .transpose()?;
        let node_display_name = optional_env("NODE_DISPLAY_NAME");

        let runtime_credentials_path = trusttunnel_runtime_dir.join(&trusttunnel_credentials_file);
        let agent_state_path = std::env::var("AGENT_STATE_PATH")
            .unwrap_or_else(|_| "agent_state.json".to_string())
            .into();

        let poll_interval = duration_required_from_env("AGENT_POLL_INTERVAL_SEC")?;
        let heartbeat_interval = duration_required_from_env("AGENT_HEARTBEAT_INTERVAL_SEC")?;

        let sync_path_template = std::env::var("LK_SYNC_PATH_TEMPLATE")
            .unwrap_or_else(|_| DEFAULT_SYNC_PATH_TEMPLATE.to_string());
        let sync_report_path = std::env::var("LK_SYNC_REPORT_PATH")
            .unwrap_or_else(|_| DEFAULT_SYNC_REPORT_PATH.to_string());
        let heartbeat_path = std::env::var("LK_HEARTBEAT_PATH")
            .unwrap_or_else(|_| DEFAULT_HEARTBEAT_PATH.to_string());
        let register_path =
            std::env::var("LK_REGISTER_PATH").unwrap_or_else(|_| DEFAULT_REGISTER_PATH.to_string());

        let apply_cmd = std::env::var("TRUSTTUNNEL_APPLY_CMD")
            .ok()
            .and_then(|x| if x.trim().is_empty() { None } else { Some(x) });
        let runtime_pid_path = std::env::var("TRUSTTUNNEL_RUNTIME_PID_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| trusttunnel_runtime_dir.join("trusttunnel.pid"));
        let runtime_process_name = std::env::var("TRUSTTUNNEL_RUNTIME_PROCESS_NAME")
            .unwrap_or_else(|_| "trusttunnel_endpoint".to_string());
        let runtime_version = std::env::var("TRUSTTUNNEL_RUNTIME_VERSION")
            .unwrap_or_else(|_| "unknown".to_string());

        Ok(Self {
            lk_base_url,
            lk_service_token,
            node_external_id,
            node_hostname,
            node_stage,
            node_cluster,
            node_namespace,
            node_rollout_group,
            node_public_host,
            node_public_port,
            node_display_name,
            trusttunnel_runtime_dir,
            trusttunnel_credentials_file,
            trusttunnel_config_file,
            trusttunnel_hosts_file,
            runtime_credentials_path,
            agent_state_path,
            poll_interval,
            heartbeat_interval,
            sync_path_template,
            sync_report_path,
            heartbeat_path,
            register_path,
            apply_cmd,
            runtime_pid_path,
            runtime_process_name,
            runtime_version,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
struct AgentState {
    version: String,
    checksum: String,
    credentials_sha256: String,
}

struct Agent {
    cfg: Config,
    lk_api: LkApiClient,
    state: AgentState,
    node_metadata: NodeMetadata,
    last_apply_status: String,
}

impl Agent {
    async fn new(cfg: Config) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
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
            node_public_host: cfg.node_public_host.clone(),
            node_public_port: cfg.node_public_port,
            node_display_name: cfg.node_display_name.clone(),
            trusttunnel_runtime_dir: path_to_string(&cfg.trusttunnel_runtime_dir)?.to_string(),
            trusttunnel_credentials_file: path_to_string(&cfg.trusttunnel_credentials_file)?
                .to_string(),
            trusttunnel_config_file: path_to_string(&cfg.trusttunnel_config_file)?.to_string(),
            trusttunnel_hosts_file: path_to_string(&cfg.trusttunnel_hosts_file)?.to_string(),
        };
        let lk_api = LkApiClient::new(
            client,
            cfg.lk_base_url.clone(),
            cfg.lk_service_token.clone(),
            cfg.register_path.clone(),
            cfg.heartbeat_path.clone(),
            cfg.sync_report_path.clone(),
            cfg.sync_path_template.clone(),
        );

        Ok(Self {
            cfg,
            lk_api,
            state,
            node_metadata,
            last_apply_status: "unknown".to_string(),
        })
    }

    async fn run(&mut self) {
        self.bootstrap_register().await;

        let mut poll_tick = interval(self.cfg.poll_interval);
        poll_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut heartbeat_tick = interval(self.cfg.heartbeat_interval);
        heartbeat_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut backoff = Duration::from_secs(1);

        loop {
            tokio::select! {
                _ = poll_tick.tick() => {
                    match self.sync_once().await {
                        Ok(()) => backoff = Duration::from_secs(1),
                        Err(err) => {
                            eprintln!("snapshot sync failed: {err}");
                            tokio::time::sleep(backoff).await;
                            backoff = std::cmp::min(backoff.saturating_mul(2), Duration::from_secs(300));
                        }
                    }
                }
                _ = heartbeat_tick.tick() => {
                    self.send_heartbeat_with_retry().await;
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

    async fn sync_once(&mut self) -> Result<(), String> {
        let (snapshot, raw_body) = self.pull_snapshot().await?;

        if !validate_checksum(&snapshot, &raw_body) {
            let detail = "invalid checksum returned by LK";
            eprintln!("snapshot rejected: {detail}, version={}", snapshot.version);
            self.send_sync_report(&snapshot, false, detail).await?;
            return Err(detail.to_string());
        }

        let rendered = render_credentials(&snapshot.accounts);
        let rendered_sha = sha256_hex(rendered.as_bytes());

        if self.state.version == snapshot.version
            && self.state.checksum == snapshot.checksum
            && self.state.credentials_sha256 == rendered_sha
        {
            println!(
                "snapshot unchanged, skip rewrite/apply: version={}, checksum={}",
                snapshot.version, snapshot.checksum
            );
            return Ok(());
        }

        println!(
            "snapshot changed: version={} checksum={} accounts={} enabled={}",
            snapshot.version,
            snapshot.checksum,
            snapshot.accounts.len(),
            snapshot.accounts.iter().filter(|a| a.enabled).count()
        );

        atomic_write(&self.cfg.runtime_credentials_path, rendered.as_bytes()).await?;
        println!(
            "credentials updated atomically at {}",
            self.cfg.runtime_credentials_path.display()
        );

        let apply_result = self.apply_runtime().await;
        let apply_ok = apply_result.is_ok();
        let apply_details = match apply_result {
            Ok(_) => "runtime apply succeeded".to_string(),
            Err(e) => format!("runtime apply failed: {e}"),
        };
        self.last_apply_status = apply_details.clone();

        self.state = AgentState {
            version: snapshot.version.clone(),
            checksum: snapshot.checksum.clone(),
            credentials_sha256: rendered_sha,
        };
        persist_state(&self.cfg.agent_state_path, &self.state).await?;

        self.send_sync_report(&snapshot, apply_ok, &apply_details).await?;

        if !apply_ok {
            return Err(apply_details);
        }

        Ok(())
    }

    async fn pull_snapshot(&self) -> Result<(SyncPayload, Vec<u8>), String> {
        self.lk_api.sync(&self.cfg.node_external_id).await
    }

    async fn send_sync_report(
        &self,
        snapshot: &SyncPayload,
        applied: bool,
        details: &str,
    ) -> Result<(), String> {
        let onboarding = OnboardingPayload::from_metadata(&self.node_metadata);
        onboarding.validate_compatibility()?;
        let payload = SyncReportPayload {
            onboarding,
            version: &snapshot.version,
            checksum: &snapshot.checksum,
            applied,
            details,
        };
        self.lk_api.sync_report(&payload).await?;

        println!(
            "sync-report sent: version={} checksum={} applied={} details={}",
            snapshot.version, snapshot.checksum, applied, details
        );

        Ok(())
    }

    async fn send_heartbeat_with_retry(&self) {
        let mut backoff = HEARTBEAT_INITIAL_BACKOFF;
        for attempt in 1..=HEARTBEAT_MAX_ATTEMPTS {
            match self.send_heartbeat().await {
                Ok(()) => return,
                Err(err) => {
                    let is_last = attempt == HEARTBEAT_MAX_ATTEMPTS;
                    eprintln!(
                        "heartbeat failed: kind={} attempt={}/{} detail={}",
                        err.kind(),
                        attempt,
                        HEARTBEAT_MAX_ATTEMPTS,
                        err
                    );
                    if is_last {
                        return;
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff.saturating_mul(2), HEARTBEAT_MAX_BACKOFF);
                }
            }
        }
    }

    async fn send_heartbeat(&self) -> Result<(), HeartbeatFailure> {
        let onboarding = OnboardingPayload::from_metadata(&self.node_metadata);
        onboarding
            .validate_compatibility()
            .map_err(HeartbeatFailure::PayloadValidation)?;
        let runtime_status = RuntimeStatus::collect(
            &self.cfg.runtime_pid_path,
            &self.cfg.runtime_process_name,
            &self.cfg.runtime_credentials_path,
        );
        let health_status = runtime_status.health_status();
        let payload = HeartbeatPayload {
            onboarding,
            external_node_id: &self.cfg.node_external_id,
            current_revision: &self.state.version,
            health_status,
            agent_version: env!("CARGO_PKG_VERSION"),
            runtime_version: &self.cfg.runtime_version,
            active_clients: runtime_status.active_clients,
            cpu_percent: runtime_status.cpu_percent,
            memory_percent: runtime_status.memory_percent,
            last_apply_status: &self.last_apply_status,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        self.lk_api
            .heartbeat(&payload)
            .await
            .map_err(HeartbeatFailure::Api)?;

        println!(
            "heartbeat sent for node_external_id={}",
            self.cfg.node_external_id
        );
        Ok(())
    }

    async fn send_register_once(&self) -> Result<RegisterAttemptOutcome, RegisterError> {
        let payload = OnboardingPayload::from_metadata(&self.node_metadata);
        payload
            .validate_compatibility()
            .map_err(RegisterError::Permanent)?;
        let response = self
            .lk_api
            .register(&payload)
            .await
            .map_err(RegisterError::Temporary)?;

        let status = response.status();
        if status.is_success() {
            return Ok(RegisterAttemptOutcome::Registered);
        }

        if is_idempotent_register_status(status) {
            return Ok(RegisterAttemptOutcome::AlreadyRegistered);
        }

        if is_temporary_http_status(status) {
            return Err(RegisterError::Temporary(format!(
                "register request returned temporary HTTP {status}"
            )));
        }

        Err(RegisterError::Permanent(format!(
            "register request returned HTTP {status}"
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
}

#[derive(Debug)]
enum HeartbeatFailure {
    PayloadValidation(String),
    Api(lk_api::HeartbeatError),
}

impl HeartbeatFailure {
    fn kind(&self) -> &'static str {
        match self {
            HeartbeatFailure::PayloadValidation(_) => "payload_validation",
            HeartbeatFailure::Api(err) => err.kind(),
        }
    }
}

impl std::fmt::Display for HeartbeatFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeartbeatFailure::PayloadValidation(msg) => write!(f, "{msg}"),
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
}

#[tokio::main]
async fn main() {
    let cfg = match Config::from_env() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("configuration error: {err}");
            std::process::exit(2);
        }
    };

    println!(
        "classic-agent started: node_external_id={} active_path=classic modified_enabled=false",
        cfg.node_external_id
    );

    let mut agent = match Agent::new(cfg).await {
        Ok(agent) => agent,
        Err(err) => {
            eprintln!("agent bootstrap failed: {err}");
            std::process::exit(2);
        }
    };

    agent.run().await;
}

fn render_credentials(accounts: &[Account]) -> String {
    let mut enabled = accounts
        .iter()
        .filter(|x| x.enabled)
        .collect::<Vec<&Account>>();
    enabled.sort_by(|a, b| a.username.cmp(&b.username));

    let mut out = String::new();
    for a in enabled {
        out.push_str("[[client]]\n");
        out.push_str(&format!("username = {:?}\n", a.username));
        out.push_str(&format!("password = {:?}\n\n", a.password));
    }
    out
}

fn validate_checksum(snapshot: &SyncPayload, raw_body: &[u8]) -> bool {
    let expected = snapshot.checksum.to_ascii_lowercase();
    if expected.is_empty() {
        return false;
    }

    let candidates = checksum_candidates(snapshot, raw_body);
    candidates.iter().any(|x| x == &expected)
}

fn checksum_candidates(snapshot: &SyncPayload, raw_body: &[u8]) -> Vec<String> {
    let mut stable_accounts = snapshot
        .accounts
        .iter()
        .map(|x| {
            let mut m = HashMap::new();
            m.insert("username", x.username.clone());
            m.insert("password", x.password.clone());
            m.insert(
                "enabled",
                if x.enabled { "true" } else { "false" }.to_string(),
            );
            m
        })
        .collect::<Vec<_>>();
    stable_accounts.sort_by(|a, b| a["username"].cmp(&b["username"]));

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

fn required_env(name: &str) -> Result<String, String> {
    let raw = std::env::var(name).map_err(|_| format!("required env var {name} is missing"))?;
    non_empty_value(name, raw)
}

fn read_pid(pid_path: &Path) -> Option<u32> {
    let raw = std::fs::read_to_string(pid_path).ok()?;
    raw.trim().parse::<u32>().ok()
}

fn find_pid_by_name(process_name: &str) -> Option<u32> {
    let entries = read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let pid = file_name.to_str()?.parse::<u32>().ok()?;
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
        if comm.trim() == process_name {
            return Some(pid);
        }
    }
    None
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
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .and_then(|raw| non_empty_value(name, raw).ok())
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

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    hex::encode(digest.as_ref())
}


enum RegisterAttemptOutcome {
    Registered,
    AlreadyRegistered,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_include_only_enabled_accounts() {
        let accounts = vec![
            Account {
                username: "b".to_string(),
                password: "p2".to_string(),
                enabled: false,
            },
            Account {
                username: "a".to_string(),
                password: "p1".to_string(),
                enabled: true,
            },
        ];

        let rendered = render_credentials(&accounts);
        assert!(rendered.contains("username = \"a\""));
        assert!(!rendered.contains("username = \"b\""));
    }

    #[test]
    fn checksum_accepts_sha_of_raw_body() {
        let raw = br#"{"version":"1","checksum":"","accounts":[]}"#;
        let snapshot = SyncPayload {
            version: "1".to_string(),
            checksum: sha256_hex(raw),
            accounts: vec![],
        };

        assert!(validate_checksum(&snapshot, raw));
    }

    #[test]
    fn checksum_rejects_unknown_hash() {
        let snapshot = SyncPayload {
            version: "1".to_string(),
            checksum: "deadbeef".to_string(),
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
}
