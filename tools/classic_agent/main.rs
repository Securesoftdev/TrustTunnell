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
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::{Instant, MissedTickBehavior, interval};
use toml_edit::value;
use trusttunnel::settings::Settings;
use prometheus::{Encoder, IntCounterVec, IntGaugeVec, Opts, Registry, TextEncoder};

const REGISTER_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const REGISTER_MAX_BACKOFF: Duration = Duration::from_secs(60);
const HEARTBEAT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const HEARTBEAT_MAX_BACKOFF: Duration = Duration::from_secs(30);
const HEARTBEAT_MAX_ATTEMPTS: usize = 3;
const SYNC_REPORT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const SYNC_REPORT_MAX_BACKOFF: Duration = Duration::from_secs(300);
const SYNC_REPORT_OUTBOX_FILE: &str = "pending_sync_reports.jsonl";
const RUNTIME_PRIMARY_MARKER_FILE: &str = ".runtime_credentials_primary";

#[derive(Clone)]
struct Config {
    lk_base_url: String,
    lk_service_token: String,
    node_external_id: String,
    node_hostname: String,
    node_stage: Option<String>,
    node_cluster: Option<String>,
    node_namespace: Option<String>,
    node_rollout_group: Option<String>,
    trusttunnel_runtime_dir: PathBuf,
    trusttunnel_config_file: PathBuf,
    bootstrap_credentials_source_path: Option<PathBuf>,
    runtime_credentials_path: PathBuf,
    runtime_primary_marker_path: PathBuf,
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
    agent_version: String,
    runtime_version: String,
    pending_sync_reports_path: PathBuf,
    metrics_address: SocketAddr,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let lk_base_url = required_env("LK_BASE_URL")?;
        let lk_service_token = required_env("LK_SERVICE_TOKEN")?;
        let node_external_id = required_env("NODE_EXTERNAL_ID")?;
        let node_hostname = required_env("NODE_HOSTNAME")?;
        let node_stage = optional_env_nonempty("NODE_STAGE");
        let node_cluster = optional_env_nonempty("NODE_CLUSTER");
        let node_namespace = optional_env_nonempty("NODE_NAMESPACE");
        let node_rollout_group = optional_env_nonempty("NODE_ROLLOUT_GROUP");
        let trusttunnel_runtime_dir: PathBuf = required_env("TRUSTTUNNEL_RUNTIME_DIR")?.into();
        let trusttunnel_credentials_file: PathBuf =
            required_env("TRUSTTUNNEL_CREDENTIALS_FILE")?.into();
        let trusttunnel_config_file: PathBuf = required_env("TRUSTTUNNEL_CONFIG_FILE")?.into();
        let _trusttunnel_hosts_file: PathBuf = required_env("TRUSTTUNNEL_HOSTS_FILE")?.into();
        let bootstrap_credentials_source_path =
            optional_env("TRUSTTUNNEL_BOOTSTRAP_CREDENTIALS_FILE").map(PathBuf::from);
        let runtime_credentials_path = trusttunnel_runtime_dir.join(&trusttunnel_credentials_file);
        let runtime_primary_marker_path = trusttunnel_runtime_dir.join(RUNTIME_PRIMARY_MARKER_FILE);
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
        let agent_version = optional_env_nonempty("TRUSTTUNNEL_AGENT_VERSION")
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
        let runtime_version =
            optional_env_nonempty("TRUSTTUNNEL_RUNTIME_VERSION").unwrap_or_else(|| "unknown".to_string());
        let pending_sync_reports_path = trusttunnel_runtime_dir.join(SYNC_REPORT_OUTBOX_FILE);
        let metrics_address = std::env::var("AGENT_METRICS_ADDRESS")
            .unwrap_or_else(|_| "127.0.0.1:9901".to_string())
            .parse::<SocketAddr>()
            .map_err(|e| format!("AGENT_METRICS_ADDRESS must be socket address host:port: {e}"))?;

        Ok(Self {
            lk_base_url,
            lk_service_token,
            node_external_id,
            node_hostname,
            node_stage,
            node_cluster,
            node_namespace,
            node_rollout_group,
            trusttunnel_runtime_dir,
            trusttunnel_config_file,
            bootstrap_credentials_source_path,
            runtime_credentials_path,
            runtime_primary_marker_path,
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
            agent_version,
            runtime_version,
            pending_sync_reports_path,
            metrics_address,
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
    metrics: Arc<AgentMetrics>,
    sync_report_backoff: Duration,
    sync_report_next_retry_at: Instant,
}

impl Agent {
    async fn new(cfg: Config) -> Result<Self, String> {
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
        let lk_api = LkApiClient::new(
            client,
            cfg.lk_base_url.clone(),
            cfg.lk_service_token.clone(),
            cfg.register_path.clone(),
            cfg.heartbeat_path.clone(),
            cfg.sync_report_path.clone(),
            cfg.sync_path_template.clone(),
        );

        let metrics = Arc::new(AgentMetrics::new(&node_metadata.node_external_id)?);

        Ok(Self {
            cfg,
            lk_api,
            state,
            node_metadata,
            last_apply_status: "unknown".to_string(),
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

        self.bootstrap_register().await;

        let mut poll_tick = interval(self.cfg.poll_interval);
        poll_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut heartbeat_tick = interval(self.cfg.heartbeat_interval);
        heartbeat_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut sync_report_tick = interval(Duration::from_secs(1));
        sync_report_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut backoff = Duration::from_secs(1);

        loop {
            tokio::select! {
                _ = poll_tick.tick() => {
                    match self.sync_once().await {
                        Ok(()) => backoff = Duration::from_secs(1),
                        Err(err) => {
                            log_error(
                                "snapshot_sync_failed",
                                &self.cfg.node_external_id,
                                "sync",
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

    async fn sync_once(&mut self) -> Result<(), String> {
        let (snapshot, raw_body) = self.pull_snapshot().await?;
        let node = self.cfg.node_external_id.clone();

        if snapshot.onboarding_state != "active" {
            let details = format!(
                "sync apply skipped: onboarding_state={}, expected=active",
                snapshot.onboarding_state
            );
            log_sync_skip(&snapshot, &details);
            self.last_apply_status = details.clone();
            self.send_sync_report(&snapshot, false, &details).await?;
            self.metrics
                .sync_total
                .with_label_values(&[&node, &snapshot.version, "skipped", "onboarding_state"])
                .inc();
            log_event(
                "info",
                &snapshot.version,
                &node,
                "sync_skipped",
                "onboarding_state",
            );
            return Ok(());
        }

        if !snapshot.sync_required {
            let details = "sync apply skipped: sync_required=false".to_string();
            log_sync_skip(&snapshot, &details);
            self.last_apply_status = details.clone();
            self.send_sync_report(&snapshot, false, &details).await?;
            self.metrics
                .sync_total
                .with_label_values(&[&node, &snapshot.version, "skipped", "sync_not_required"])
                .inc();
            log_event(
                "info",
                &snapshot.version,
                &node,
                "sync_skipped",
                "sync_not_required",
            );
            return Ok(());
        }

        if !validate_checksum(&snapshot, &raw_body) {
            let detail = "invalid checksum returned by LK";
            eprintln!("snapshot rejected: {detail}, version={}", snapshot.version);
            self.send_sync_report(&snapshot, false, detail).await?;
            self.metrics
                .sync_total
                .with_label_values(&[&node, &snapshot.version, "failed", "invalid_checksum"])
                .inc();
            self.metrics
                .last_failed_sync
                .with_label_values(&[&node])
                .set(chrono::Utc::now().timestamp());
            log_event(
                "error",
                &snapshot.version,
                &node,
                "sync_failed",
                "invalid_checksum",
            );
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
            self.metrics
                .sync_total
                .with_label_values(&[&node, &snapshot.version, "unchanged", "none"])
                .inc();
            log_event("info", &snapshot.version, &node, "sync_unchanged", "none");
            return Ok(());
        }

        println!(
            "snapshot changed: version={} checksum={} accounts={} enabled={}",
            snapshot.version,
            snapshot.checksum,
            snapshot.accounts.len(),
            snapshot.accounts.iter().filter(|a| a.enabled).count()
        );
        self.metrics
            .credentials_count
            .with_label_values(&[&node])
            .set(snapshot.accounts.iter().filter(|a| a.enabled).count() as i64);

        let previous_runtime_credentials = fs::read(&self.cfg.runtime_credentials_path).await.ok();
        let tmp_credentials_path = self
            .write_runtime_credentials_tmp(rendered.as_bytes())
            .await?;
        if let Err(err) = self.validate_credentials_with_endpoint_parser(&tmp_credentials_path) {
            let _ = fs::remove_file(&tmp_credentials_path).await;
            return Err(err);
        }
        self.promote_runtime_credentials(&tmp_credentials_path).await?;
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
        self.last_apply_status = apply_details.clone();
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
                .sync_total
                .with_label_values(&[&node, &snapshot.version, "failed", "apply"])
                .inc();
            self.metrics
                .last_failed_sync
                .with_label_values(&[&node])
                .set(chrono::Utc::now().timestamp());
            log_event("error", &snapshot.version, &node, "sync_failed", "apply");
            self.send_sync_report(&snapshot, false, &apply_details).await?;
            return Err(apply_details);
        }

        self.state = AgentState {
            version: snapshot.version.clone(),
            checksum: snapshot.checksum.clone(),
            credentials_sha256: rendered_sha,
        };
        self.mark_runtime_as_primary().await?;
        persist_state(&self.cfg.agent_state_path, &self.state).await?;
        self.send_sync_report(&snapshot, true, &apply_details).await?;
        self.metrics
            .sync_total
            .with_label_values(&[&node, &snapshot.version, "success", "none"])
            .inc();
        self.metrics
            .last_successful_sync
            .with_label_values(&[&node])
            .set(chrono::Utc::now().timestamp());
        log_event("info", &snapshot.version, &node, "sync_success", "none");

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
        if let Err(err) = self.validate_credentials_with_endpoint_parser(&tmp_credentials_path) {
            let _ = fs::remove_file(&tmp_credentials_path).await;
            return Err(err);
        }
        self.promote_runtime_credentials(&tmp_credentials_path).await?;
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

    async fn pull_snapshot(&self) -> Result<(SyncPayload, Vec<u8>), String> {
        self.lk_api.sync(&self.cfg.node_external_id).await
    }

    async fn send_sync_report(
        &mut self,
        snapshot: &SyncPayload,
        applied: bool,
        details: &str,
    ) -> Result<(), String> {
        let report = PendingSyncReport {
            version: &snapshot.version,
            checksum: &snapshot.checksum,
            applied,
            details,
        };
        if let Err(err) = self.send_sync_report_payload(&report).await {
            eprintln!("sync-report failed: {err}; queued for retry");
            append_pending_sync_report(
                &self.cfg.pending_sync_reports_path,
                &report.to_owned_payload(),
            )
            .await?;
            self.increase_sync_report_backoff();
            return Ok(());
        }

        Ok(())
    }

    async fn send_sync_report_payload(&self, report: &PendingSyncReport<'_>) -> Result<(), String> {
        let onboarding = OnboardingPayload::from_metadata(
            &self.node_metadata,
            &self.cfg.agent_version,
            &self.cfg.runtime_version,
        );
        onboarding.validate_compatibility()?;
        let payload = SyncReportPayload {
            onboarding,
            version: report.version,
            checksum: report.checksum,
            applied: report.applied,
            details: report.details,
        };
        self.lk_api.sync_report(&payload).await?;

        println!(
            "sync-report sent: version={} checksum={} applied={} details={}",
            report.version, report.checksum, report.applied, report.details
        );
        Ok(())
    }

    async fn flush_pending_sync_reports(&mut self) {
        if Instant::now() < self.sync_report_next_retry_at {
            return;
        }

        let pending = match load_pending_sync_reports(&self.cfg.pending_sync_reports_path).await {
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
                    &self.cfg.pending_sync_reports_path,
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

        if let Err(err) = persist_pending_sync_reports(&self.cfg.pending_sync_reports_path, &[]).await {
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
                    self.metrics
                        .heartbeat_status
                        .with_label_values(&[&self.cfg.node_external_id])
                        .set(1);
                    return;
                }
                Err(err) => {
                    let is_last = attempt == HEARTBEAT_MAX_ATTEMPTS;
                    log_event(
                        "error",
                        &self.state.version,
                        &self.cfg.node_external_id,
                        "heartbeat_failed",
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
                        self.metrics
                            .heartbeat_status
                            .with_label_values(&[&self.cfg.node_external_id])
                            .set(0);
                        return;
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff.saturating_mul(2), HEARTBEAT_MAX_BACKOFF);
                }
            }
        }
    }

    async fn send_heartbeat(&self) -> Result<(), HeartbeatFailure> {
        let onboarding = OnboardingPayload::from_metadata(
            &self.node_metadata,
            &self.cfg.agent_version,
            &self.cfg.runtime_version,
        );
        onboarding
            .validate_compatibility()
            .map_err(HeartbeatFailure::PayloadValidation)?;
        let runtime_status = RuntimeStatus::collect(
            &self.cfg.runtime_pid_path,
            &self.cfg.runtime_process_name,
            &self.cfg.runtime_credentials_path,
        );
        let health_status = runtime_status.health_status();
        self.metrics
            .endpoint_process_status
            .with_label_values(&[&self.cfg.node_external_id])
            .set(if runtime_status.alive { 1 } else { 0 });
        let payload = HeartbeatPayload {
            onboarding,
            external_node_id: &self.cfg.node_external_id,
            current_revision: &self.state.version,
            health_status,
            active_clients: runtime_status.active_clients,
            cpu_percent: runtime_status.cpu_percent,
            memory_percent: runtime_status.memory_percent,
            last_apply_status: &self.last_apply_status,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        self.lk_api
            .heartbeat(&payload)
            .await
            .map_err(|err| {
                self.metrics
                    .heartbeat_total
                    .with_label_values(&[
                        &self.cfg.node_external_id,
                        &self.state.version,
                        "failed",
                        err.kind(),
                    ])
                    .inc();
                HeartbeatFailure::Api(err)
            })?;
        self.metrics
            .heartbeat_total
            .with_label_values(&[
                &self.cfg.node_external_id,
                &self.state.version,
                "success",
                "none",
            ])
            .inc();
        log_event(
            "info",
            &self.state.version,
            &self.cfg.node_external_id,
            "heartbeat_success",
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
            self.cfg.lk_base_url.trim_end_matches('/'),
            self.cfg.register_path
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
        let parent = self
            .cfg
            .runtime_credentials_path
            .parent()
            .ok_or_else(|| {
                format!(
                    "runtime credentials path has no parent: {}",
                    self.cfg.runtime_credentials_path.display()
                )
            })?;
        fs::create_dir_all(parent)
            .await
            .map_err(|e| format!("failed to create runtime directory {}: {e}", parent.display()))?;

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|x| x.as_nanos())
            .unwrap_or_default();
        let tmp_path = parent.join(format!(
            ".{}.candidate.{}.{nonce}.tmp",
            self.cfg
                .runtime_credentials_path
                .file_name()
                .and_then(|x| x.to_str())
                .unwrap_or("credentials"),
            std::process::id()
        ));
        fs::write(&tmp_path, data)
            .await
            .map_err(|e| format!("failed to write candidate credentials {}: {e}", tmp_path.display()))?;

        Ok(tmp_path)
    }

    fn validate_credentials_with_endpoint_parser(&self, candidate_path: &Path) -> Result<(), String> {
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

        toml::from_str::<Settings>(&settings_doc.to_string())
            .map(|_| ())
            .map_err(|e| format!("failed to validate candidate credentials via endpoint parser: {e}"))
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
        let runtime_status = RuntimeStatus::collect(
            &self.cfg.runtime_pid_path,
            &self.cfg.runtime_process_name,
            &self.cfg.runtime_credentials_path,
        );
        if runtime_status.health_status() == "dead" {
            return Err("runtime health check failed: dead".to_string());
        }

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

struct AgentMetrics {
    registry: Registry,
    sync_total: IntCounterVec,
    heartbeat_total: IntCounterVec,
    apply_total: IntCounterVec,
    last_successful_sync: IntGaugeVec,
    last_failed_sync: IntGaugeVec,
    apply_duration_ms: IntGaugeVec,
    credentials_count: IntGaugeVec,
    heartbeat_status: IntGaugeVec,
    endpoint_process_status: IntGaugeVec,
}

impl AgentMetrics {
    fn new(node: &str) -> Result<Self, String> {
        let registry = Registry::new();
        let sync_total = IntCounterVec::new(
            Opts::new("classic_agent_sync_total", "Total sync attempts by status"),
            &["node", "revision", "status", "error_class"],
        )
        .map_err(|e| format!("failed to create sync_total metric: {e}"))?;
        let heartbeat_total = IntCounterVec::new(
            Opts::new(
                "classic_agent_heartbeat_total",
                "Total heartbeat attempts by status",
            ),
            &["node", "revision", "status", "error_class"],
        )
        .map_err(|e| format!("failed to create heartbeat_total metric: {e}"))?;
        let apply_total = IntCounterVec::new(
            Opts::new("classic_agent_apply_total", "Total apply attempts by status"),
            &["node", "revision", "status", "error_class"],
        )
        .map_err(|e| format!("failed to create apply_total metric: {e}"))?;
        let last_successful_sync = IntGaugeVec::new(
            Opts::new(
                "classic_agent_last_successful_sync_timestamp_seconds",
                "Unix timestamp of the latest successful sync",
            ),
            &["node"],
        )
        .map_err(|e| format!("failed to create last_successful_sync metric: {e}"))?;
        let last_failed_sync = IntGaugeVec::new(
            Opts::new(
                "classic_agent_last_failed_sync_timestamp_seconds",
                "Unix timestamp of the latest failed sync",
            ),
            &["node"],
        )
        .map_err(|e| format!("failed to create last_failed_sync metric: {e}"))?;
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
        let heartbeat_status = IntGaugeVec::new(
            Opts::new(
                "classic_agent_heartbeat_status",
                "Current heartbeat status, 1 for success and 0 for failure",
            ),
            &["node"],
        )
        .map_err(|e| format!("failed to create heartbeat_status metric: {e}"))?;
        let endpoint_process_status = IntGaugeVec::new(
            Opts::new(
                "classic_agent_endpoint_process_status",
                "Current endpoint process status, 1 for running and 0 for dead",
            ),
            &["node"],
        )
        .map_err(|e| format!("failed to create endpoint_process_status metric: {e}"))?;

        registry
            .register(Box::new(sync_total.clone()))
            .map_err(|e| format!("failed to register sync_total metric: {e}"))?;
        registry
            .register(Box::new(heartbeat_total.clone()))
            .map_err(|e| format!("failed to register heartbeat_total metric: {e}"))?;
        registry
            .register(Box::new(apply_total.clone()))
            .map_err(|e| format!("failed to register apply_total metric: {e}"))?;
        registry
            .register(Box::new(last_successful_sync.clone()))
            .map_err(|e| format!("failed to register last_successful_sync metric: {e}"))?;
        registry
            .register(Box::new(last_failed_sync.clone()))
            .map_err(|e| format!("failed to register last_failed_sync metric: {e}"))?;
        registry
            .register(Box::new(apply_duration_ms.clone()))
            .map_err(|e| format!("failed to register apply_duration metric: {e}"))?;
        registry
            .register(Box::new(credentials_count.clone()))
            .map_err(|e| format!("failed to register credentials_count metric: {e}"))?;
        registry
            .register(Box::new(heartbeat_status.clone()))
            .map_err(|e| format!("failed to register heartbeat_status metric: {e}"))?;
        registry
            .register(Box::new(endpoint_process_status.clone()))
            .map_err(|e| format!("failed to register endpoint_process_status metric: {e}"))?;

        let labels = &[node];
        last_successful_sync.with_label_values(labels).set(0);
        last_failed_sync.with_label_values(labels).set(0);
        apply_duration_ms.with_label_values(labels).set(0);
        credentials_count.with_label_values(labels).set(0);
        heartbeat_status.with_label_values(labels).set(0);
        endpoint_process_status.with_label_values(labels).set(0);

        Ok(Self {
            registry,
            sync_total,
            heartbeat_total,
            apply_total,
            last_successful_sync,
            last_failed_sync,
            apply_duration_ms,
            credentials_count,
            heartbeat_status,
            endpoint_process_status,
        })
    }
}

#[derive(Clone, Debug)]
struct PendingSyncReport<'a> {
    version: &'a str,
    checksum: &'a str,
    applied: bool,
    details: &'a str,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct PendingSyncReportOwned {
    version: String,
    checksum: String,
    applied: bool,
    details: String,
}

impl PendingSyncReport<'_> {
    fn to_owned_payload(&self) -> PendingSyncReportOwned {
        PendingSyncReportOwned {
            version: self.version.to_string(),
            checksum: self.checksum.to_string(),
            applied: self.applied,
            details: self.details.to_string(),
        }
    }
}

impl PendingSyncReportOwned {
    fn as_payload(&self) -> PendingSyncReport<'_> {
        PendingSyncReport {
            version: &self.version,
            checksum: &self.checksum,
            applied: self.applied,
            details: &self.details,
        }
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

fn optional_env_nonempty(name: &str) -> Option<String> {
    optional_env(name).filter(|value| !value.trim().is_empty())
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

fn log_sync_skip(snapshot: &SyncPayload, reason: &str) {
    println!(
        "sync skip: reason={} version={} checksum={} onboarding_state={} sync_required={}",
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
    use http_body_util::{BodyExt, Full};
    use hyper::body::{Bytes, Incoming};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Method, Request, Response, StatusCode as HyperStatusCode};
    use hyper_util::rt::TokioIo;
    use std::collections::VecDeque;
    use std::convert::Infallible;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    #[derive(Clone)]
    struct MockResponse {
        status: HyperStatusCode,
        body: String,
    }

    #[derive(Clone)]
    struct CapturedRequest {
        method: Method,
        path: String,
        body: String,
    }

    #[derive(Default)]
    struct MockState {
        routes: HashMap<(Method, String), VecDeque<MockResponse>>,
        captured: Vec<CapturedRequest>,
    }

    struct MockHttpServer {
        base_url: String,
        state: Arc<Mutex<MockState>>,
    }

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
        fs::write(&credentials_file_abs, b"").await.unwrap();
        fs::write(&hosts_file, b"").await.unwrap();
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

        let cfg = Config {
            lk_base_url: base_url.to_string(),
            lk_service_token: "token".to_string(),
            node_external_id: "node-1".to_string(),
            node_hostname: "node-1.example".to_string(),
            node_stage: Some("prod".to_string()),
            node_cluster: Some("cluster-a".to_string()),
            node_namespace: Some("default".to_string()),
            node_rollout_group: Some("g1".to_string()),
            trusttunnel_runtime_dir: runtime_dir.clone(),
            trusttunnel_config_file: config_file.clone(),
            bootstrap_credentials_source_path: None,
            runtime_credentials_path: credentials_file_abs,
            runtime_primary_marker_path: runtime_dir.join(RUNTIME_PRIMARY_MARKER_FILE),
            agent_state_path: runtime_dir.join("agent_state.json"),
            poll_interval: Duration::from_secs(60),
            heartbeat_interval: Duration::from_secs(60),
            sync_path_template: "/sync/{externalNodeId}".to_string(),
            sync_report_path: "/sync-report".to_string(),
            heartbeat_path: "/heartbeat".to_string(),
            register_path: "/register".to_string(),
            apply_cmd: apply_cmd.map(ToString::to_string),
            runtime_pid_path: runtime_dir.join("trusttunnel.pid"),
            runtime_process_name: "trusttunnel_endpoint".to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            runtime_version: "test".to_string(),
            pending_sync_reports_path: runtime_dir.join(SYNC_REPORT_OUTBOX_FILE),
            metrics_address: "127.0.0.1:9901".parse().unwrap(),
        };

        Agent::new(cfg).await.unwrap()
    }

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
        let checksum = checksum_candidates(&snapshot, b"{}")[1].clone();
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

    #[tokio::test]
    async fn pending_sync_report_outbox_roundtrip() {
        let tmp_dir = TempDir::new().unwrap();
        let path = tmp_dir.path().join("pending_sync_reports.jsonl");
        let first = PendingSyncReportOwned {
            version: "1".to_string(),
            checksum: "a".to_string(),
            applied: true,
            details: "ok".to_string(),
        };
        let second = PendingSyncReportOwned {
            version: "2".to_string(),
            checksum: "b".to_string(),
            applied: false,
            details: "failed".to_string(),
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
        fs::write(&path, b"{\"version\":\"1\",\"checksum\":\"x\",\"applied\":true,\"details\":\"ok\"}\n")
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

        assert!(names.contains(&"classic_agent_sync_total".to_string()));
        assert!(names.contains(&"classic_agent_heartbeat_total".to_string()));
        assert!(names.contains(&"classic_agent_apply_total".to_string()));
        assert!(names.contains(
            &"classic_agent_last_successful_sync_timestamp_seconds".to_string()
        ));
        assert!(names.contains(
            &"classic_agent_last_failed_sync_timestamp_seconds".to_string()
        ));
        assert!(names.contains(&"classic_agent_apply_duration_milliseconds".to_string()));
        assert!(names.contains(&"classic_agent_credentials_count".to_string()));
        assert!(names.contains(&"classic_agent_heartbeat_status".to_string()));
        assert!(names.contains(&"classic_agent_endpoint_process_status".to_string()));
    }

    #[tokio::test]
    async fn sync_once_valid_config_applies_and_reports_success() {
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

        agent.sync_once().await.unwrap();
        let creds = fs::read_to_string(&agent.cfg.runtime_credentials_path)
            .await
            .unwrap();
        assert!(creds.contains("username = \"alice\""));
        assert_eq!(agent.state.version, "v1");
        assert!(!fs::try_exists(&agent.cfg.pending_sync_reports_path).await.unwrap());

        let requests = server.captured().await;
        let report = requests
            .iter()
            .find(|x| x.method == Method::POST && x.path == "/sync-report")
            .unwrap();
        assert!(report.body.contains("\"applied\":true"));
    }

    #[tokio::test]
    async fn sync_once_onboarding_not_active_skips_apply() {
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

        agent.sync_once().await.unwrap();
        assert!(agent.last_apply_status.contains("onboarding_state=pending"));
        let requests = server.captured().await;
        let report = requests
            .iter()
            .find(|x| x.method == Method::POST && x.path == "/sync-report")
            .unwrap();
        assert!(report.body.contains("\"applied\":false"));
    }

    #[tokio::test]
    async fn sync_once_sync_required_false_skips_apply() {
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

        agent.sync_once().await.unwrap();
        assert_eq!(agent.last_apply_status, "sync apply skipped: sync_required=false");
        let requests = server.captured().await;
        let report = requests
            .iter()
            .find(|x| x.method == Method::POST && x.path == "/sync-report")
            .unwrap();
        assert!(report.body.contains("\"applied\":false"));
    }

    #[tokio::test]
    async fn sync_once_apply_failure_rolls_back_runtime_credentials() {
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
            }],
        );
        server
            .enqueue(Method::GET, "/sync/node-1", HyperStatusCode::OK, body)
            .await;
        server
            .enqueue(Method::POST, "/sync-report", HyperStatusCode::OK, "")
            .await;

        let err = agent.sync_once().await.unwrap_err();
        assert!(err.contains("rollback completed"));
        let creds = fs::read(&agent.cfg.runtime_credentials_path).await.unwrap();
        assert_eq!(creds, original);
    }

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

        let _ = agent.sync_once().await.unwrap_err();
        assert!(fs::try_exists(&agent.cfg.pending_sync_reports_path).await.unwrap());
        let queued = load_pending_sync_reports(&agent.cfg.pending_sync_reports_path)
            .await
            .unwrap();
        assert_eq!(queued.len(), 1);
        assert!(!queued[0].applied);
    }

    #[tokio::test]
    async fn register_retries_on_temporary_lk_unavailability() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let agent = make_agent(&tmp_dir, &server.base_url, None).await;
        server
            .enqueue(
                Method::POST,
                "/register",
                HyperStatusCode::SERVICE_UNAVAILABLE,
                "",
            )
            .await;
        server
            .enqueue(Method::POST, "/register", HyperStatusCode::OK, "")
            .await;

        let started = std::time::Instant::now();
        agent.bootstrap_register().await;
        assert!(started.elapsed() >= REGISTER_INITIAL_BACKOFF);
    }

    #[tokio::test]
    async fn register_payload_uses_canonical_v1_contract() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let agent = make_agent(&tmp_dir, &server.base_url, None).await;
        server
            .enqueue(Method::POST, "/register", HyperStatusCode::OK, "")
            .await;

        let outcome = agent.send_register_once().await.unwrap();
        assert!(matches!(outcome, RegisterAttemptOutcome::Registered));

        let requests = server.captured().await;
        let register = requests
            .iter()
            .find(|x| x.method == Method::POST && x.path == "/register")
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

    #[tokio::test]
    async fn register_bad_request_returns_diagnostic_without_secret_token() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let agent = make_agent(&tmp_dir, &server.base_url, None).await;
        server
            .enqueue(
                Method::POST,
                "/register",
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

    #[tokio::test]
    async fn heartbeat_loop_is_resilient_to_temporary_lk_errors() {
        let server = MockHttpServer::start().await;
        let tmp_dir = TempDir::new().unwrap();
        let agent = make_agent(&tmp_dir, &server.base_url, None).await;
        server
            .enqueue(
                Method::POST,
                "/heartbeat",
                HyperStatusCode::INTERNAL_SERVER_ERROR,
                "",
            )
            .await;
        server
            .enqueue(
                Method::POST,
                "/heartbeat",
                HyperStatusCode::BAD_GATEWAY,
                "",
            )
            .await;
        server
            .enqueue(Method::POST, "/heartbeat", HyperStatusCode::OK, "")
            .await;

        agent.send_heartbeat_with_retry().await;
        let requests = server.captured().await;
        let heartbeat_count = requests
            .iter()
            .filter(|x| x.method == Method::POST && x.path == "/heartbeat")
            .count();
        assert_eq!(heartbeat_count, 3);
    }

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

        assert!(agent.sync_once().await.is_err());
        assert!(agent.sync_once().await.is_ok());
    }
}
