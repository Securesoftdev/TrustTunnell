use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs;
use tokio::process::Command;
use tokio::time::{interval, MissedTickBehavior};

const DEFAULT_SNAPSHOT_PATH: &str = "/internal/vpn/classic/accounts";
const DEFAULT_SYNC_REPORT_PATH: &str = "/internal/vpn/classic/sync-report";
const DEFAULT_HEARTBEAT_PATH: &str = "/internal/vpn/classic/heartbeat";

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
    snapshot_path: String,
    sync_report_path: String,
    heartbeat_path: String,
    apply_cmd: Option<String>,
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

        let snapshot_path = std::env::var("LK_SNAPSHOT_PATH")
            .unwrap_or_else(|_| DEFAULT_SNAPSHOT_PATH.to_string());
        let sync_report_path = std::env::var("LK_SYNC_REPORT_PATH")
            .unwrap_or_else(|_| DEFAULT_SYNC_REPORT_PATH.to_string());
        let heartbeat_path = std::env::var("LK_HEARTBEAT_PATH")
            .unwrap_or_else(|_| DEFAULT_HEARTBEAT_PATH.to_string());

        let apply_cmd = std::env::var("TRUSTTUNNEL_APPLY_CMD")
            .ok()
            .and_then(|x| if x.trim().is_empty() { None } else { Some(x) });

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
            snapshot_path,
            sync_report_path,
            heartbeat_path,
            apply_cmd,
        })
    }
}

#[derive(Debug, Deserialize)]
struct SnapshotResponse {
    version: String,
    checksum: String,
    #[serde(default)]
    accounts: Vec<Account>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Account {
    #[serde(alias = "user", alias = "login", alias = "name")]
    username: String,
    #[serde(alias = "token", alias = "credentials", alias = "secret")]
    password: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
struct AgentState {
    version: String,
    checksum: String,
    credentials_sha256: String,
}

#[derive(Serialize)]
struct HeartbeatPayload<'a> {
    node_external_id: &'a str,
    node_hostname: &'a str,
    node_stage: &'a str,
    node_cluster: &'a str,
    node_namespace: &'a str,
    node_rollout_group: &'a str,
    node_public_host: Option<&'a str>,
    node_public_port: Option<u16>,
    node_display_name: Option<&'a str>,
    trusttunnel_runtime_dir: &'a str,
    trusttunnel_credentials_file: &'a str,
    trusttunnel_config_file: &'a str,
    trusttunnel_hosts_file: &'a str,
    active_path: &'static str,
    modified_enabled: bool,
}

#[derive(Serialize)]
struct SyncReportPayload<'a> {
    node_external_id: &'a str,
    node_hostname: &'a str,
    node_stage: &'a str,
    node_cluster: &'a str,
    node_namespace: &'a str,
    node_rollout_group: &'a str,
    node_public_host: Option<&'a str>,
    node_public_port: Option<u16>,
    node_display_name: Option<&'a str>,
    trusttunnel_runtime_dir: &'a str,
    trusttunnel_credentials_file: &'a str,
    trusttunnel_config_file: &'a str,
    trusttunnel_hosts_file: &'a str,
    active_path: &'static str,
    modified_enabled: bool,
    version: &'a str,
    checksum: &'a str,
    applied: bool,
    details: &'a str,
}

struct Agent {
    cfg: Config,
    client: reqwest::Client,
    state: AgentState,
}

impl Agent {
    async fn new(cfg: Config) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;

        let state = load_state(&cfg.agent_state_path).await.unwrap_or_default();

        Ok(Self { cfg, client, state })
    }

    async fn run(&mut self) {
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
                    if let Err(err) = self.send_heartbeat().await {
                        eprintln!("heartbeat push failed: {err}");
                    }
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

    async fn pull_snapshot(&self) -> Result<(SnapshotResponse, Vec<u8>), String> {
        let endpoint = format_url(&self.cfg.lk_base_url, &self.cfg.snapshot_path);
        let response = self
            .client
            .get(endpoint)
            .header("Authorization", format!("Bearer {}", self.cfg.lk_service_token))
            .header("X-Internal-Agent-Token", &self.cfg.lk_service_token)
            .query(&[("node_external_id", self.cfg.node_external_id.as_str())])
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
        let parsed = serde_json::from_slice::<SnapshotResponse>(&bytes)
            .map_err(|e| format!("failed to parse LK snapshot JSON: {e}"))?;

        Ok((parsed, bytes.to_vec()))
    }

    async fn send_sync_report(
        &self,
        snapshot: &SnapshotResponse,
        applied: bool,
        details: &str,
    ) -> Result<(), String> {
        let endpoint = format_url(&self.cfg.lk_base_url, &self.cfg.sync_report_path);
        let payload = SyncReportPayload {
            node_external_id: &self.cfg.node_external_id,
            node_hostname: &self.cfg.node_hostname,
            node_stage: &self.cfg.node_stage,
            node_cluster: &self.cfg.node_cluster,
            node_namespace: &self.cfg.node_namespace,
            node_rollout_group: &self.cfg.node_rollout_group,
            node_public_host: self.cfg.node_public_host.as_deref(),
            node_public_port: self.cfg.node_public_port,
            node_display_name: self.cfg.node_display_name.as_deref(),
            trusttunnel_runtime_dir: path_to_string(&self.cfg.trusttunnel_runtime_dir)?,
            trusttunnel_credentials_file: path_to_string(&self.cfg.trusttunnel_credentials_file)?,
            trusttunnel_config_file: path_to_string(&self.cfg.trusttunnel_config_file)?,
            trusttunnel_hosts_file: path_to_string(&self.cfg.trusttunnel_hosts_file)?,
            active_path: "classic",
            modified_enabled: false,
            version: &snapshot.version,
            checksum: &snapshot.checksum,
            applied,
            details,
        };

        let response = self
            .client
            .post(endpoint)
            .header("Authorization", format!("Bearer {}", self.cfg.lk_service_token))
            .header("X-Internal-Agent-Token", &self.cfg.lk_service_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("sync-report push failed: {e}"))?;

        if !response.status().is_success() {
            return Err(format!(
                "sync-report push failed with HTTP {}",
                response.status()
            ));
        }

        println!(
            "sync-report sent: version={} checksum={} applied={} details={}",
            snapshot.version, snapshot.checksum, applied, details
        );

        Ok(())
    }

    async fn send_heartbeat(&self) -> Result<(), String> {
        let endpoint = format_url(&self.cfg.lk_base_url, &self.cfg.heartbeat_path);
        let payload = HeartbeatPayload {
            node_external_id: &self.cfg.node_external_id,
            node_hostname: &self.cfg.node_hostname,
            node_stage: &self.cfg.node_stage,
            node_cluster: &self.cfg.node_cluster,
            node_namespace: &self.cfg.node_namespace,
            node_rollout_group: &self.cfg.node_rollout_group,
            node_public_host: self.cfg.node_public_host.as_deref(),
            node_public_port: self.cfg.node_public_port,
            node_display_name: self.cfg.node_display_name.as_deref(),
            trusttunnel_runtime_dir: path_to_string(&self.cfg.trusttunnel_runtime_dir)?,
            trusttunnel_credentials_file: path_to_string(&self.cfg.trusttunnel_credentials_file)?,
            trusttunnel_config_file: path_to_string(&self.cfg.trusttunnel_config_file)?,
            trusttunnel_hosts_file: path_to_string(&self.cfg.trusttunnel_hosts_file)?,
            active_path: "classic",
            modified_enabled: false,
        };

        let response = self
            .client
            .post(endpoint)
            .header("Authorization", format!("Bearer {}", self.cfg.lk_service_token))
            .header("X-Internal-Agent-Token", &self.cfg.lk_service_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("heartbeat push failed: {e}"))?;

        if !response.status().is_success() {
            return Err(format!("heartbeat push failed with HTTP {}", response.status()));
        }

        println!(
            "heartbeat sent for node_external_id={}",
            self.cfg.node_external_id
        );
        Ok(())
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

fn validate_checksum(snapshot: &SnapshotResponse, raw_body: &[u8]) -> bool {
    let expected = snapshot.checksum.to_ascii_lowercase();
    if expected.is_empty() {
        return false;
    }

    let candidates = checksum_candidates(snapshot, raw_body);
    candidates.iter().any(|x| x == &expected)
}

fn checksum_candidates(snapshot: &SnapshotResponse, raw_body: &[u8]) -> Vec<String> {
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

fn format_url(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

fn required_env(name: &str) -> Result<String, String> {
    let raw = std::env::var(name).map_err(|_| format!("required env var {name} is missing"))?;
    non_empty_value(name, raw)
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
        let snapshot = SnapshotResponse {
            version: "1".to_string(),
            checksum: sha256_hex(raw),
            accounts: vec![],
        };

        assert!(validate_checksum(&snapshot, raw));
    }

    #[test]
    fn checksum_rejects_unknown_hash() {
        let snapshot = SnapshotResponse {
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
}
