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
    ) -> Result<BTreeMap<String, String>, String> {
        let usernames = accounts
            .into_iter()
            .map(|account| account.username.clone())
            .collect::<Vec<_>>();
        self.export_usernames(usernames).await
    }

    pub(crate) async fn export_usernames(
        &self,
        usernames: Vec<String>,
    ) -> Result<BTreeMap<String, String>, String> {
        if usernames.is_empty() {
            return Ok(BTreeMap::new());
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
                let _permit = semaphore
                    .acquire_owned()
                    .await
                    .map_err(|_| format!("semaphore closed while exporting TT link for {username}"))?;
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

        let mut links = BTreeMap::new();
        while let Some(result) = join_set.join_next().await {
            let (username, tt_link) = result
                .map_err(|err| format!("TT link export task failed: {err}"))??;
            links.insert(username, tt_link);
        }

        Ok(links)
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
    let tt_link = stdout.trim();

    if !output.status.success() {
        return Err(format!(
            "endpoint exited with status {} for {username}; stderr={}",
            output.status,
            stderr.trim()
        ));
    }
    if !tt_link.starts_with("tt://") {
        return Err(format!(
            "endpoint returned invalid deeplink for {username}: stdout={} stderr={}",
            stdout.trim(),
            stderr.trim()
        ));
    }

    Ok(tt_link.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&script_path, perms).unwrap();

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
}
