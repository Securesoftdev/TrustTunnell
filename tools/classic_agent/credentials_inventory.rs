use crate::sha256_hex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const INVENTORY_STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExportConfig {
    pub(crate) address: String,
    pub(crate) domain: String,
    pub(crate) port: u16,
    pub(crate) sni: Option<String>,
    pub(crate) dns: Vec<String>,
    pub(crate) protocol: String,
}

impl ExportConfig {
    pub(crate) fn config_hash(&self) -> String {
        let mut canonical_dns = self
            .dns
            .iter()
            .map(|item| item.trim())
            .filter(|item| !item.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        canonical_dns.sort();
        canonical_dns.dedup();

        let canonical = CanonicalExportConfig {
            address: self.address.trim().to_string(),
            domain: self.domain.trim().to_string(),
            port: self.port,
            sni: self
                .sni
                .as_deref()
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToString::to_string),
            dns: canonical_dns,
            protocol: self.protocol.trim().to_ascii_lowercase(),
        };
        let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
        sha256_hex(&bytes)
    }
}

#[derive(Clone, Debug, Serialize)]
struct CanonicalExportConfig {
    address: String,
    domain: String,
    port: u16,
    sni: Option<String>,
    dns: Vec<String>,
    protocol: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InventoryAccount {
    pub(crate) username: String,
    pub(crate) password: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InventorySnapshot {
    pub(crate) generated_at_unix_sec: i64,
    pub(crate) export_config_hash: String,
    pub(crate) credentials: Vec<InventoryAccount>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct InventoryDelta {
    pub(crate) missing: Vec<InventoryAccount>,
    pub(crate) stale: Vec<InventoryAccount>,
    pub(crate) removed: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct InventoryState {
    pub(crate) schema_version: u32,
    pub(crate) generated_at_unix_sec: i64,
    pub(crate) export_config_hash: String,
    pub(crate) credentials: Vec<InventoryStateCredential>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct InventoryStateCredential {
    pub(crate) username: String,
    pub(crate) password_sha256: String,
}

pub(crate) fn resolve_credentials_path_from_settings(
    runtime_dir: &Path,
    settings_path: &Path,
) -> Result<PathBuf, String> {
    let settings_raw = std::fs::read_to_string(settings_path).map_err(|e| {
        format!(
            "failed to read endpoint settings {}: {e}",
            settings_path.display()
        )
    })?;
    let settings = settings_raw.parse::<toml_edit::Document>().map_err(|e| {
        format!(
            "failed to parse endpoint settings {} as TOML: {e}",
            settings_path.display()
        )
    })?;
    let credentials_raw = settings
        .get("credentials_file")
        .and_then(|item| item.as_str())
        .ok_or_else(|| {
            format!(
                "endpoint settings {} does not contain string field credentials_file",
                settings_path.display()
            )
        })?;
    let credentials_path = PathBuf::from(credentials_raw.trim());
    if credentials_path.is_absolute() {
        return Ok(credentials_path);
    }
    Ok(runtime_dir.join(credentials_path))
}

pub(crate) fn load_inventory_snapshot(
    credentials_path: &Path,
    export_config_hash: String,
    generated_at_unix_sec: i64,
) -> Result<InventorySnapshot, String> {
    let raw = std::fs::read_to_string(credentials_path).map_err(|e| {
        format!(
            "failed to read credentials inventory {}: {e}",
            credentials_path.display()
        )
    })?;
    let credentials = parse_credentials_toml(&raw)?;
    Ok(InventorySnapshot {
        generated_at_unix_sec,
        export_config_hash,
        credentials,
    })
}

pub(crate) fn load_state(state_path: &Path) -> Result<Option<InventoryState>, String> {
    match std::fs::read_to_string(state_path) {
        Ok(raw) => {
            let state = serde_json::from_str::<InventoryState>(&raw).map_err(|e| {
                format!(
                    "failed to parse credentials inventory state {}: {e}",
                    state_path.display()
                )
            })?;
            Ok(Some(state))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!(
            "failed to read credentials inventory state {}: {err}",
            state_path.display()
        )),
    }
}

pub(crate) fn persist_state(state_path: &Path, snapshot: &InventorySnapshot) -> Result<(), String> {
    let state = InventoryState {
        schema_version: INVENTORY_STATE_SCHEMA_VERSION,
        generated_at_unix_sec: snapshot.generated_at_unix_sec,
        export_config_hash: snapshot.export_config_hash.clone(),
        credentials: snapshot
            .credentials
            .iter()
            .map(|credential| InventoryStateCredential {
                username: credential.username.clone(),
                password_sha256: sha256_hex(credential.password.as_bytes()),
            })
            .collect(),
    };
    let parent = state_path.parent().ok_or_else(|| {
        format!(
            "inventory state file has no parent directory: {}",
            state_path.display()
        )
    })?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("failed to create inventory state directory {}: {e}", parent.display()))?;
    let encoded = serde_json::to_vec_pretty(&state)
        .map_err(|e| format!("failed to serialize inventory state: {e}"))?;
    std::fs::write(state_path, encoded).map_err(|e| {
        format!(
            "failed to write credentials inventory state {}: {e}",
            state_path.display()
        )
    })
}

pub(crate) fn compute_delta(snapshot: &InventorySnapshot, previous: Option<&InventoryState>) -> InventoryDelta {
    let mut delta = InventoryDelta::default();
    let previous_credentials = previous
        .map(|state| {
            state
                .credentials
                .iter()
                .map(|item| (item.username.clone(), item.password_sha256.clone()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();

    let mut seen = BTreeSet::new();
    for credential in &snapshot.credentials {
        let password_sha256 = sha256_hex(credential.password.as_bytes());
        match previous_credentials.get(&credential.username) {
            None => delta.missing.push(credential.clone()),
            Some(previous_hash)
                if previous_hash != &password_sha256
                    || previous
                        .map(|state| state.export_config_hash != snapshot.export_config_hash)
                        .unwrap_or(false) =>
            {
                delta.stale.push(credential.clone());
            }
            Some(_) => {}
        }
        seen.insert(credential.username.clone());
    }

    for username in previous_credentials.keys() {
        if !seen.contains(username) {
            delta.removed.push(username.clone());
        }
    }

    delta
}

fn parse_credentials_toml(raw: &str) -> Result<Vec<InventoryAccount>, String> {
    let parsed = raw
        .parse::<toml_edit::Document>()
        .map_err(|e| format!("failed to parse credentials inventory TOML: {e}"))?;
    let clients = parsed
        .get("client")
        .and_then(toml_edit::Item::as_array_of_tables)
        .ok_or_else(|| "credentials inventory TOML does not contain [[client]] section".to_string())?;

    let mut entries = Vec::new();
    for (index, client) in clients.iter().enumerate() {
        let username = client
            .get("username")
            .and_then(|item| item.as_str())
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .ok_or_else(|| format!("credentials inventory: client #{} has empty username", index + 1))?;
        let password = client
            .get("password")
            .and_then(|item| item.as_str())
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .ok_or_else(|| format!("credentials inventory: client #{} has empty password", index + 1))?;

        entries.push(InventoryAccount {
            username: username.to_string(),
            password: password.to_string(),
        });
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn resolves_relative_credentials_path_with_runtime_dir() {
        let temp_dir = TempDir::new().unwrap();
        let settings_path = temp_dir.path().join("vpn.toml");
        std::fs::write(&settings_path, "credentials_file = \"credentials.toml\"\n").unwrap();

        let resolved =
            resolve_credentials_path_from_settings(temp_dir.path(), &settings_path).unwrap();
        assert_eq!(resolved, temp_dir.path().join("credentials.toml"));
    }

    #[test]
    fn computes_missing_stale_and_removed_credentials() {
        let snapshot = InventorySnapshot {
            generated_at_unix_sec: 1,
            export_config_hash: "new_hash".to_string(),
            credentials: vec![
                InventoryAccount {
                    username: "alice".to_string(),
                    password: "new_password".to_string(),
                },
                InventoryAccount {
                    username: "carol".to_string(),
                    password: "carol_password".to_string(),
                },
            ],
        };
        let previous = InventoryState {
            schema_version: INVENTORY_STATE_SCHEMA_VERSION,
            generated_at_unix_sec: 0,
            export_config_hash: "old_hash".to_string(),
            credentials: vec![
                InventoryStateCredential {
                    username: "alice".to_string(),
                    password_sha256: sha256_hex("old_password".as_bytes()),
                },
                InventoryStateCredential {
                    username: "bob".to_string(),
                    password_sha256: sha256_hex("bob_password".as_bytes()),
                },
            ],
        };

        let delta = compute_delta(&snapshot, Some(&previous));
        assert_eq!(delta.missing.len(), 1);
        assert_eq!(delta.missing[0].username, "carol");
        assert_eq!(delta.stale.len(), 1);
        assert_eq!(delta.stale[0].username, "alice");
        assert_eq!(delta.removed, vec!["bob".to_string()]);
    }

    #[test]
    fn export_config_hash_uses_expected_fields() {
        let first = ExportConfig {
            address: "89.110.100.165".to_string(),
            domain: "cdn.securesoft.dev".to_string(),
            port: 443,
            sni: Some("sni.securesoft.dev".to_string()),
            dns: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            protocol: "http2".to_string(),
        };
        let second = ExportConfig {
            address: "89.110.100.165".to_string(),
            domain: "cdn.securesoft.dev".to_string(),
            port: 443,
            sni: Some("sni.securesoft.dev".to_string()),
            dns: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
            protocol: "HTTP2".to_string(),
        };

        assert_eq!(first.config_hash(), second.config_hash());
    }

    #[test]
    fn loads_existing_credentials_into_inventory_snapshot() {
        let temp_dir = TempDir::new().unwrap();
        let credentials_path = temp_dir.path().join("credentials.toml");
        std::fs::write(
            &credentials_path,
            "[[client]]\nusername = \"alice\"\npassword = \"one\"\n\n[[client]]\nusername = \"bob\"\npassword = \"two\"\n",
        )
        .unwrap();

        let snapshot =
            load_inventory_snapshot(&credentials_path, "cfg-hash".to_string(), 10).unwrap();

        assert_eq!(snapshot.export_config_hash, "cfg-hash");
        assert_eq!(snapshot.credentials.len(), 2);
        assert_eq!(snapshot.credentials[0].username, "alice");
        assert_eq!(snapshot.credentials[1].username, "bob");
    }

    #[test]
    fn startup_bootstrap_with_empty_state_loads_all_credentials_as_missing() {
        let snapshot = InventorySnapshot {
            generated_at_unix_sec: 1,
            export_config_hash: "hash-v1".to_string(),
            credentials: vec![
                InventoryAccount {
                    username: "alice".to_string(),
                    password: "one".to_string(),
                },
                InventoryAccount {
                    username: "bob".to_string(),
                    password: "two".to_string(),
                },
            ],
        };

        let delta = compute_delta(&snapshot, None);

        assert_eq!(delta.missing.len(), 2);
        assert_eq!(delta.stale.len(), 0);
        assert_eq!(delta.removed.len(), 0);
    }

    #[test]
    fn periodic_reconcile_detects_added_changed_and_removed_credentials() {
        let snapshot = InventorySnapshot {
            generated_at_unix_sec: 2,
            export_config_hash: "hash-v2".to_string(),
            credentials: vec![
                InventoryAccount {
                    username: "alice".to_string(),
                    password: "one".to_string(),
                },
                InventoryAccount {
                    username: "carol".to_string(),
                    password: "three".to_string(),
                },
            ],
        };
        let previous = InventoryState {
            schema_version: INVENTORY_STATE_SCHEMA_VERSION,
            generated_at_unix_sec: 1,
            export_config_hash: "hash-v1".to_string(),
            credentials: vec![
                InventoryStateCredential {
                    username: "alice".to_string(),
                    password_sha256: sha256_hex("one".as_bytes()),
                },
                InventoryStateCredential {
                    username: "bob".to_string(),
                    password_sha256: sha256_hex("two".as_bytes()),
                },
            ],
        };

        let delta = compute_delta(&snapshot, Some(&previous));

        assert_eq!(delta.missing.len(), 1);
        assert_eq!(delta.missing[0].username, "carol");
        assert_eq!(delta.stale.len(), 1);
        assert_eq!(delta.stale[0].username, "alice");
        assert_eq!(delta.removed, vec!["bob".to_string()]);
    }

    #[test]
    fn idempotent_second_run_reports_no_changes() {
        let temp_dir = TempDir::new().unwrap();
        let state_path = temp_dir.path().join("credentials_inventory_state.json");
        let snapshot = InventorySnapshot {
            generated_at_unix_sec: 5,
            export_config_hash: "hash-v1".to_string(),
            credentials: vec![InventoryAccount {
                username: "alice".to_string(),
                password: "one".to_string(),
            }],
        };

        persist_state(&state_path, &snapshot).unwrap();
        let previous = load_state(&state_path).unwrap().unwrap();
        let second_delta = compute_delta(&snapshot, Some(&previous));

        assert!(second_delta.missing.is_empty());
        assert!(second_delta.stale.is_empty());
        assert!(second_delta.removed.is_empty());
    }
}
