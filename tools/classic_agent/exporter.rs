use crate::legacy::lk_api::Account;
use std::collections::BTreeMap;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

const EXPORT_MAX_PARALLELISM: usize = 4;
const EXPORT_ATTEMPTS: usize = 3;
const EXPORT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(crate) struct EndpointExportOptions {
    address: String,
    custom_sni: Option<String>,
    display_name: Option<String>,
    dns_servers: Vec<String>,
}

impl EndpointExportOptions {
    pub(crate) fn new(
        address: String,
        custom_sni: Option<String>,
        display_name: Option<String>,
        dns_servers: Vec<String>,
    ) -> Self {
        Self {
            address,
            custom_sni,
            display_name,
            dns_servers,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ExportSummary {
    pub(crate) links: BTreeMap<String, String>,
    pub(crate) failed: usize,
    pub(crate) failures: Vec<String>,
}

#[cfg(test)]
impl ExportSummary {
    pub(crate) fn exported(&self) -> usize {
        self.links.len()
    }
}

pub(crate) struct EndpointLinkExporter {
    endpoint_binary: String,
    settings_path: PathBuf,
    hosts_path: PathBuf,
    options: EndpointExportOptions,
    max_parallelism: usize,
    attempts: usize,
    timeout: Duration,
}

impl EndpointLinkExporter {
    pub(crate) fn new(
        endpoint_binary: String,
        settings_path: PathBuf,
        hosts_path: PathBuf,
        options: EndpointExportOptions,
    ) -> Self {
        Self {
            endpoint_binary,
            settings_path,
            hosts_path,
            options,
            max_parallelism: EXPORT_MAX_PARALLELISM,
            attempts: EXPORT_ATTEMPTS,
            timeout: EXPORT_TIMEOUT,
        }
    }

    pub(crate) async fn export_links(
        &self,
        accounts: Vec<&Account>,
    ) -> Result<ExportSummary, String> {
        let usernames = accounts
            .into_iter()
            .map(|account| account.username.clone())
            .collect::<Vec<_>>();
        self.export_usernames(usernames).await
    }

    pub(crate) async fn export_usernames(
        &self,
        usernames: Vec<String>,
    ) -> Result<ExportSummary, String> {
        if usernames.is_empty() {
            return Ok(ExportSummary::default());
        }

        let mut join_set = JoinSet::new();
        let semaphore = Arc::new(Semaphore::new(self.max_parallelism));

        for username in usernames {
            let semaphore = Arc::clone(&semaphore);
            let endpoint_binary = self.endpoint_binary.clone();
            let settings_path = self.settings_path.clone();
            let hosts_path = self.hosts_path.clone();
            let options = self.options.clone();
            let attempts = self.attempts;
            let timeout = self.timeout;
            join_set.spawn(async move {
                let _permit = semaphore.acquire_owned().await.map_err(|_| {
                    format!("semaphore closed while exporting TT link for {username}")
                })?;
                let tt_link = export_single_link(
                    &endpoint_binary,
                    &settings_path,
                    &hosts_path,
                    &options,
                    &username,
                    attempts,
                    timeout,
                )
                .await?;
                Ok::<(String, String), String>((username, tt_link))
            });
        }

        let mut summary = ExportSummary::default();
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok((username, tt_link))) => {
                    summary.links.insert(username, tt_link);
                }
                Ok(Err(err)) => {
                    summary.failed += 1;
                    summary.failures.push(err);
                }
                Err(err) => {
                    summary.failed += 1;
                    summary
                        .failures
                        .push(format!("TT link export task failed: {err}"));
                }
            }
        }

        Ok(summary)
    }
}

async fn export_single_link(
    endpoint_binary: &str,
    settings_path: &Path,
    hosts_path: &Path,
    options: &EndpointExportOptions,
    username: &str,
    attempts: usize,
    timeout: Duration,
) -> Result<String, String> {
    let mut last_error = String::new();

    for attempt in 1..=attempts {
        match run_export_command(
            endpoint_binary,
            settings_path,
            hosts_path,
            options,
            username,
            timeout,
        )
        .await
        {
            Ok(link) => return Ok(link),
            Err(err) => {
                last_error = format!("attempt {attempt}/{attempts}: {err}");
                if attempt < attempts {
                    tokio::time::sleep(Duration::from_millis(200 * attempt as u64)).await;
                }
            }
        }
    }

    Err(format!(
        "failed to export TT link for {username} after {attempts} attempts: {last_error}"
    ))
}

async fn run_export_command(
    endpoint_binary: &str,
    settings_path: &Path,
    hosts_path: &Path,
    options: &EndpointExportOptions,
    username: &str,
    timeout: Duration,
) -> Result<String, String> {
    let mut command = Command::new(endpoint_binary);
    command.arg(settings_path);
    command.arg(hosts_path);
    command.arg("--client_config");
    command.arg(username);
    command.arg("--format");
    command.arg("deeplink");
    command.arg("--address");
    command.arg(&options.address);
    if let Some(custom_sni) = &options.custom_sni {
        command.arg("--custom-sni");
        command.arg(custom_sni);
    }
    if let Some(display_name) = &options.display_name {
        command.arg("--name");
        command.arg(display_name);
    }
    for dns_server in &options.dns_servers {
        command.arg("--dns-upstream");
        command.arg(dns_server);
    }

    let output = tokio::time::timeout(timeout, command.output())
        .await
        .map_err(|_| {
            format!(
                "endpoint command timed out after {}s",
                timeout.as_secs_f64()
            )
        })?
        .map_err(|e| format!("failed to execute endpoint command: {e}"))?;

    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| format!("endpoint stdout is not valid UTF-8: {e}"))?;
    let stderr = String::from_utf8(output.stderr)
        .map_err(|e| format!("endpoint stderr is not valid UTF-8: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "endpoint exited with status {} for {username}; stderr={}",
            output.status,
            stderr.trim()
        ));
    }

    let (tt_link, normalized_stdout) =
        extract_canonical_tt_link(&stdout, username).map_err(|reason| {
            format!(
                "endpoint returned invalid deeplink for {username}: {reason}; stderr={}",
                stderr.trim()
            )
        })?;
    if normalized_stdout {
        let non_empty_lines = stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();
        println!(
            "phase=export_tt_link_stdout_normalized username={username} non_empty_lines={non_empty_lines}"
        );
    }

    Ok(tt_link)
}

fn extract_canonical_tt_link(stdout: &str, username: &str) -> Result<(String, bool), String> {
    let mut canonical_link = None;
    let mut canonical_line_index = 0usize;
    let mut non_empty_lines = Vec::new();

    for (index, line) in stdout.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        non_empty_lines.push((index, trimmed));
        if canonical_link.is_none() && trimmed.starts_with("tt://") {
            canonical_link = Some(trimmed.to_string());
            canonical_line_index = index;
        }
    }

    let tt_link = canonical_link.ok_or_else(|| {
        format!(
            "missing canonical tt:// line in stdout for {username}; stdout={}",
            stdout.trim()
        )
    })?;

    let normalized_stdout =
        non_empty_lines.len() != 1 || non_empty_lines[0].0 != canonical_line_index;
    Ok((tt_link, normalized_stdout))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command as StdCommand;
    use std::sync::OnceLock;
    use tempfile::TempDir;

    fn set_executable(path: &Path) {
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }

    fn endpoint_binary_path() -> PathBuf {
        static ENDPOINT_BINARY: OnceLock<PathBuf> = OnceLock::new();
        ENDPOINT_BINARY
            .get_or_init(|| {
                if let Some(path) = std::env::var_os("TRUSTTUNNEL_TEST_ENDPOINT_BINARY") {
                    return PathBuf::from(path);
                }

                let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap()
                    .to_path_buf();
                let bin_path = repo_root.join("target/debug/trusttunnel_endpoint");
                if !bin_path.exists() {
                    let status = StdCommand::new("cargo")
                        .current_dir(&repo_root)
                        .args([
                            "build",
                            "--package",
                            "trusttunnel_endpoint",
                            "--bin",
                            "trusttunnel_endpoint",
                        ])
                        .status()
                        .expect("failed to invoke cargo build for trusttunnel_endpoint");
                    assert!(
                        status.success(),
                        "failed to build trusttunnel_endpoint binary"
                    );
                }

                bin_path
            })
            .clone()
    }

    fn write_endpoint_files(temp_dir: &TempDir, users: &[&str]) -> (PathBuf, PathBuf) {
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        let credentials_path = temp_dir.path().join("credentials.toml");
        let settings_path = temp_dir.path().join("vpn.toml");
        let hosts_path = temp_dir.path().join("hosts.toml");

        let cert = rcgen::generate_simple_self_signed(vec!["vpn.example.com".to_string()]).unwrap();
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        let credentials = users
            .iter()
            .map(|username| format!("[[client]]\nusername = \"{username}\"\npassword = \"pass\"\n"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&credentials_path, credentials).unwrap();
        std::fs::write(
            &settings_path,
            format!(
                "listen_address = \"127.0.0.1:443\"\ncredentials_file = \"{}\"\n\n[listen_protocols]\n\n[listen_protocols.http1]\nupload_buffer_size = 32768\n",
                credentials_path.display(),
            ),
        )
        .unwrap();
        std::fs::write(
            &hosts_path,
            format!(
                "[[main_hosts]]\nhostname = \"vpn.example.com\"\ncert_chain_path = \"{}\"\nprivate_key_path = \"{}\"\nallowed_sni = [\"sni.example.com\"]\n",
                cert_path.display(),
                key_path.display()
            ),
        )
        .unwrap();

        (settings_path, hosts_path)
    }

    #[tokio::test]
    async fn exporter_retries_on_failure_and_parses_tt_link() {
        let temp_dir = TempDir::new().unwrap();
        let counter_path = temp_dir.path().join("counter");
        let script_path = temp_dir.path().join("fake_endpoint.sh");
        std::fs::write(
            &script_path,
            format!(
                "#!/bin/sh\ncount=$(cat {counter} 2>/dev/null || echo 0)\ncount=$((count+1))\necho $count > {counter}\nif [ \"$count\" -lt 2 ]; then echo fail >&2; exit 1; fi\nuser=\"\"\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = \"--client_config\" ]; then shift; user=\"$1\"; fi\n  shift\ndone\necho \"tt://$user\"\n",
                counter = counter_path.display(),
            ),
        )
        .unwrap();
        set_executable(&script_path);

        let exporter = EndpointLinkExporter::new(
            script_path.display().to_string(),
            temp_dir.path().join("vpn.toml"),
            temp_dir.path().join("hosts.toml"),
            EndpointExportOptions::new("1.1.1.1:443".to_string(), None, None, vec![]),
        );

        let link = export_single_link(
            &exporter.endpoint_binary,
            &exporter.settings_path,
            &exporter.hosts_path,
            &exporter.options,
            "alice",
            3,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(link, "tt://alice");
    }

    #[tokio::test]
    async fn exporter_calls_endpoint_binary_and_returns_tt_links() {
        let temp_dir = TempDir::new().unwrap();
        let args_log_path = temp_dir.path().join("args.log");
        let script_path = temp_dir.path().join("fake_endpoint.sh");
        std::fs::write(
            &script_path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{}\"\nuser=\"\"\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = \"--client_config\" ]; then shift; user=\"$1\"; fi\n  shift\ndone\necho \"tt://$user\"\n",
                args_log_path.display()
            ),
        )
        .unwrap();
        set_executable(&script_path);

        let exporter = EndpointLinkExporter::new(
            script_path.display().to_string(),
            temp_dir.path().join("vpn.toml"),
            temp_dir.path().join("hosts.toml"),
            EndpointExportOptions::new(
                "89.110.100.165:443".to_string(),
                Some("sni.example.com".to_string()),
                Some("Primary".to_string()),
                vec!["8.8.8.8".to_string()],
            ),
        );

        let links = exporter
            .export_usernames(vec!["alice".to_string()])
            .await
            .unwrap();

        assert_eq!(links.links.get("alice"), Some(&"tt://alice".to_string()));
        let args_log = std::fs::read_to_string(args_log_path).unwrap();
        assert!(args_log.contains("--format deeplink"));
        assert!(args_log.contains("--address 89.110.100.165:443"));
        assert!(args_log.contains("--custom-sni sni.example.com"));
        assert!(args_log.contains("--name Primary"));
        assert!(args_log.contains("--dns-upstream 8.8.8.8"));
    }

    #[tokio::test]
    async fn exporter_collects_partial_failures() {
        let temp_dir = TempDir::new().unwrap();
        let script_path = temp_dir.path().join("fake_endpoint_partial.sh");
        std::fs::write(
            &script_path,
            "#!/bin/sh\nuser=\"\"\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = \"--client_config\" ]; then shift; user=\"$1\"; fi\n  shift\ndone\nif [ \"$user\" = \"broken\" ]; then echo fail >&2; exit 1; fi\necho \"tt://$user\"\n",
        )
        .unwrap();
        set_executable(&script_path);

        let exporter = EndpointLinkExporter::new(
            script_path.display().to_string(),
            temp_dir.path().join("vpn.toml"),
            temp_dir.path().join("hosts.toml"),
            EndpointExportOptions::new("1.1.1.1:443".to_string(), None, None, vec![]),
        );

        let summary = exporter
            .export_usernames(vec!["alice".to_string(), "broken".to_string()])
            .await
            .unwrap();

        assert_eq!(summary.exported(), 1);
        assert_eq!(summary.failed, 1);
        assert_eq!(
            summary.links.get("alice").cloned(),
            Some("tt://alice".to_string())
        );
        assert_eq!(summary.failures.len(), 1);
    }

    #[tokio::test]
    async fn exporter_with_real_endpoint_handles_cli_flags_and_outputs_deeplinks() {
        let temp_dir = TempDir::new().unwrap();
        let endpoint_binary = endpoint_binary_path();
        let (settings_path, hosts_path) = write_endpoint_files(&temp_dir, &["alice"]);
        let exporter = EndpointLinkExporter::new(
            endpoint_binary.display().to_string(),
            settings_path,
            hosts_path,
            EndpointExportOptions::new(
                "89.110.100.165:443".to_string(),
                Some("sni.example.com".to_string()),
                Some("Primary".to_string()),
                vec!["8.8.8.8".to_string()],
            ),
        );

        let summary = exporter
            .export_usernames(vec!["alice".to_string(), "missing".to_string()])
            .await
            .unwrap();

        assert_eq!(summary.exported(), 1);
        assert_eq!(summary.failed, 1);
        let alice_link = summary.links.get("alice").unwrap();
        assert!(alice_link.starts_with("tt://"));
        assert!(summary
            .failures
            .iter()
            .any(|failure| failure.contains("endpoint exited with status")));
    }

    #[tokio::test]
    async fn exporter_timeout_is_reported() {
        let temp_dir = TempDir::new().unwrap();
        let script_path = temp_dir.path().join("slow_endpoint.sh");
        std::fs::write(&script_path, "#!/bin/sh\nsleep 1\necho \"tt://late\"\n").unwrap();
        set_executable(&script_path);

        let err = run_export_command(
            &script_path.display().to_string(),
            &temp_dir.path().join("vpn.toml"),
            &temp_dir.path().join("hosts.toml"),
            &EndpointExportOptions::new("1.1.1.1:443".to_string(), None, None, vec![]),
            "alice",
            Duration::from_millis(100),
        )
        .await
        .unwrap_err();

        assert!(err.contains("timed out"));
    }

    #[test]
    fn extract_canonical_tt_link_returns_single_line_unchanged() {
        let stdout = "tt://alice";
        let (tt_link, normalized_stdout) = extract_canonical_tt_link(stdout, "alice").unwrap();
        assert_eq!(tt_link, "tt://alice");
        assert!(!normalized_stdout);
    }

    #[test]
    fn extract_canonical_tt_link_discards_helper_text_and_urls() {
        let stdout =
            "tt://alice\n\nTo connect on mobile...\nhttps://trusttunnel.org/qr.html#tt=abc";
        let (tt_link, normalized_stdout) = extract_canonical_tt_link(stdout, "alice").unwrap();
        assert_eq!(tt_link, "tt://alice");
        assert!(normalized_stdout);
    }

    #[test]
    fn extract_canonical_tt_link_fails_without_tt_scheme() {
        let stdout = "To connect on mobile...\nhttps://trusttunnel.org/qr.html#tt=abc";
        let err = extract_canonical_tt_link(stdout, "alice").unwrap_err();
        assert!(err.contains("missing canonical tt:// line"));
    }

    #[test]
    fn extract_canonical_tt_link_accepts_tt_scheme_after_helper_text() {
        let stdout = "To connect on mobile...\ntt://alice\nhttps://trusttunnel.org/qr.html#tt=abc";
        let (tt_link, normalized_stdout) = extract_canonical_tt_link(stdout, "alice").unwrap();
        assert_eq!(tt_link, "tt://alice");
        assert!(normalized_stdout);
    }

    #[tokio::test]
    async fn exporter_reports_clear_error_when_binary_path_is_invalid() {
        let temp_dir = TempDir::new().unwrap();
        let err = run_export_command(
            "/missing/trusttunnel_endpoint",
            &temp_dir.path().join("vpn.toml"),
            &temp_dir.path().join("hosts.toml"),
            &EndpointExportOptions::new("1.1.1.1:443".to_string(), None, None, vec![]),
            "alice",
            Duration::from_millis(100),
        )
        .await
        .unwrap_err();

        assert!(err.contains("failed to execute endpoint command"));
        assert!(err.contains("No such file or directory"));
    }
}
