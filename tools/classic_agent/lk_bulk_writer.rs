use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use tokio::process::Command;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct LkArtifactRecord {
    pub(crate) username: String,
    pub(crate) external_node_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) external_account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) access_bundle_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tt_link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) config_hash: Option<String>,
    pub(crate) active: bool,
}

impl LkArtifactRecord {
    pub(crate) fn dedupe_key(&self) -> String {
        if let Some(bundle_id) = self
            .access_bundle_id
            .as_deref()
            .map(str::trim)
            .filter(|item| !item.is_empty())
        {
            return format!("bundle:{bundle_id}");
        }
        format!("node_user:{}:{}", self.external_node_id, self.username)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct LkBatchWriteResult {
    pub(crate) created: usize,
    pub(crate) updated: usize,
    pub(crate) unchanged: usize,
    pub(crate) deactivated: usize,
    pub(crate) failed: usize,
    pub(crate) failures: Vec<String>,
}

pub(crate) struct LkBulkWriter {
    sink: LkBulkSink,
}

enum LkBulkSink {
    Api {
        client: Client,
        endpoint: String,
        service_token: Option<String>,
    },
    Postgres {
        dsn: String,
        table_name: String,
    },
}

#[derive(Serialize)]
struct LkBulkApiRequest {
    records: Vec<LkArtifactRecord>,
}

#[derive(Deserialize)]
struct LkBulkApiResponse {
    created: usize,
    updated: usize,
    unchanged: usize,
    deactivated: usize,
    #[serde(default)]
    failed: usize,
    #[serde(default)]
    failures: Vec<String>,
}

impl LkBulkWriter {
    pub(crate) fn from_contract(
        lk_db_dsn: &str,
        lk_service_token: Option<String>,
    ) -> Result<Self, String> {
        let dsn = lk_db_dsn.trim();
        if dsn.is_empty() {
            return Err("LK_DB_DSN must not be empty".to_string());
        }

        if is_http_url(dsn) {
            return Ok(Self {
                sink: LkBulkSink::Api {
                    client: Client::new(),
                    endpoint: dsn.to_string(),
                    service_token: lk_service_token,
                },
            });
        }

        if dsn.starts_with("postgres://") || dsn.starts_with("postgresql://") {
            let table_name = std::env::var("LK_DB_TABLE")
                .ok()
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty())
                .unwrap_or_else(|| "access_artifacts".to_string());
            return Ok(Self {
                sink: LkBulkSink::Postgres {
                    dsn: dsn.to_string(),
                    table_name,
                },
            });
        }

        Err(format!(
            "LK_DB_DSN must be HTTP(S) bulk endpoint or Postgres DSN, got: {dsn}"
        ))
    }

    pub(crate) async fn write_batch(
        &self,
        records: Vec<LkArtifactRecord>,
    ) -> Result<LkBatchWriteResult, String> {
        validate_records(&records)?;
        if records.is_empty() {
            return Ok(LkBatchWriteResult::default());
        }
        match &self.sink {
            LkBulkSink::Api {
                client,
                endpoint,
                service_token,
            } => write_via_api(client, endpoint, service_token.as_deref(), records).await,
            LkBulkSink::Postgres { dsn, table_name } => {
                write_via_postgres(dsn, table_name, records).await
            }
        }
    }
}

fn validate_records(records: &[LkArtifactRecord]) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for record in records {
        if record.username.trim().is_empty() {
            return Err("LK artifact record has empty username".to_string());
        }
        if record.external_node_id.trim().is_empty() {
            return Err(format!(
                "LK artifact record for {} has empty external_node_id",
                record.username
            ));
        }
        let key = record.dedupe_key();
        if !seen.insert(key.clone()) {
            return Err(format!("duplicate LK artifact record dedupe key: {key}"));
        }
    }
    Ok(())
}

async fn write_via_api(
    client: &Client,
    endpoint: &str,
    service_token: Option<&str>,
    records: Vec<LkArtifactRecord>,
) -> Result<LkBatchWriteResult, String> {
    let mut request = client
        .post(endpoint)
        .json(&LkBulkApiRequest { records });
    if let Some(token) = service_token.map(str::trim).filter(|item| !item.is_empty()) {
        request = request.bearer_auth(token);
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("LK bulk API request failed: {e}"))?;
    let status = response.status();
    if status == StatusCode::NOT_FOUND {
        return Err(format!(
            "LK bulk API endpoint not found: {endpoint} (HTTP {})",
            status.as_u16()
        ));
    }
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "LK bulk API returned HTTP {}: {}",
            status.as_u16(),
            body.trim()
        ));
    }

    let payload = response
        .json::<LkBulkApiResponse>()
        .await
        .map_err(|e| format!("failed to parse LK bulk API response: {e}"))?;

    Ok(LkBatchWriteResult {
        created: payload.created,
        updated: payload.updated,
        unchanged: payload.unchanged,
        deactivated: payload.deactivated,
        failed: payload.failed,
        failures: payload.failures,
    })
}

async fn write_via_postgres(
    dsn: &str,
    table_name: &str,
    records: Vec<LkArtifactRecord>,
) -> Result<LkBatchWriteResult, String> {
    let mut summary = LkBatchWriteResult::default();

    for record in &records {
        let existing_status_query = format!(
            "SELECT active, COALESCE(tt_link, ''), COALESCE(config_hash, '') \
             FROM {table_name} \
             WHERE dedupe_key = '{}' \
             LIMIT 1",
            sql_quote(&record.dedupe_key())
        );
        let existing_raw = exec_psql(dsn, &existing_status_query)
            .await
            .map_err(|e| format!("failed to query existing LK artifact for {}: {e}", record.username))?;
        let existing = parse_existing_row(&existing_raw);

        let changed = existing
            .as_ref()
            .map(|(existing_active, existing_tt_link, existing_config_hash)| {
                *existing_active != record.active
                    || existing_tt_link.as_str() != record.tt_link.as_deref().unwrap_or_default()
                    || existing_config_hash.as_str()
                        != record.config_hash.as_deref().unwrap_or_default()
            })
            .unwrap_or(true);

        let upsert_query = format!(
            "INSERT INTO {table_name} \
            (dedupe_key, external_node_id, username, external_account_id, access_bundle_id, tt_link, config_hash, active, updated_at) \
            VALUES ('{}', '{}', '{}', {}, {}, {}, {}, {}, NOW()) \
            ON CONFLICT (dedupe_key) DO UPDATE SET \
                external_node_id = EXCLUDED.external_node_id, \
                username = EXCLUDED.username, \
                external_account_id = EXCLUDED.external_account_id, \
                access_bundle_id = EXCLUDED.access_bundle_id, \
                tt_link = EXCLUDED.tt_link, \
                config_hash = EXCLUDED.config_hash, \
                active = EXCLUDED.active, \
                updated_at = NOW()"
            ,
            sql_quote(&record.dedupe_key()),
            sql_quote(&record.external_node_id),
            sql_quote(&record.username),
            sql_nullable(&record.external_account_id),
            sql_nullable(&record.access_bundle_id),
            sql_nullable(&record.tt_link),
            sql_nullable(&record.config_hash),
            if record.active { "TRUE" } else { "FALSE" },
        );
        exec_psql(dsn, &upsert_query)
            .await
            .map_err(|e| format!("failed to upsert LK artifact for {}: {e}", record.username))?;

        if existing.is_none() {
            if record.active {
                summary.created += 1;
            } else {
                summary.deactivated += 1;
            }
        } else if changed {
            if record.active {
                summary.updated += 1;
            } else {
                summary.deactivated += 1;
            }
        } else {
            summary.unchanged += 1;
        }
    }

    Ok(summary)
}

fn is_http_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

async fn exec_psql(dsn: &str, sql: &str) -> Result<String, String> {
    let output = Command::new("psql")
        .arg(dsn)
        .arg("-v")
        .arg("ON_ERROR_STOP=1")
        .arg("-t")
        .arg("-A")
        .arg("-c")
        .arg(sql)
        .output()
        .await
        .map_err(|e| format!("failed to spawn psql: {e}"))?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| format!("psql stdout is not valid UTF-8: {e}"))?;
    if output.status.success() {
        return Ok(stdout.trim().to_string());
    }
    let stderr = String::from_utf8(output.stderr)
        .map_err(|e| format!("psql stderr is not valid UTF-8: {e}"))?;
    Err(stderr.trim().to_string())
}

fn parse_existing_row(raw: &str) -> Option<(bool, String, String)> {
    if raw.trim().is_empty() {
        return None;
    }
    let mut parts = raw.split('|');
    let active = parts.next()?.trim().eq_ignore_ascii_case("t");
    let tt_link = parts.next()?.trim().to_string();
    let config_hash = parts.next()?.trim().to_string();
    Some((active, tt_link, config_hash))
}

fn sql_nullable(value: &Option<String>) -> String {
    value
        .as_deref()
        .filter(|item| !item.trim().is_empty())
        .map(|item| format!("'{}'", sql_quote(item)))
        .unwrap_or_else(|| "NULL".to_string())
}

fn sql_quote(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupe_key_prefers_access_bundle() {
        let record = LkArtifactRecord {
            username: "alice".to_string(),
            external_node_id: "node-1".to_string(),
            external_account_id: None,
            access_bundle_id: Some("bundle-1".to_string()),
            tt_link: Some("tt://alice".to_string()),
            config_hash: Some("hash-1".to_string()),
            active: true,
        };

        assert_eq!(record.dedupe_key(), "bundle:bundle-1");
    }

    #[test]
    fn dedupe_key_falls_back_to_node_and_username() {
        let record = LkArtifactRecord {
            username: "alice".to_string(),
            external_node_id: "node-1".to_string(),
            external_account_id: None,
            access_bundle_id: None,
            tt_link: Some("tt://alice".to_string()),
            config_hash: Some("hash-1".to_string()),
            active: true,
        };

        assert_eq!(record.dedupe_key(), "node_user:node-1:alice");
    }

    #[test]
    fn validate_rejects_duplicate_dedupe_keys() {
        let first = LkArtifactRecord {
            username: "alice".to_string(),
            external_node_id: "node-1".to_string(),
            external_account_id: None,
            access_bundle_id: None,
            tt_link: Some("tt://alice".to_string()),
            config_hash: Some("hash-1".to_string()),
            active: true,
        };
        let second = LkArtifactRecord {
            username: "alice".to_string(),
            external_node_id: "node-1".to_string(),
            external_account_id: None,
            access_bundle_id: None,
            tt_link: Some("tt://alice-changed".to_string()),
            config_hash: Some("hash-2".to_string()),
            active: true,
        };

        let error = validate_records(&[first, second]).unwrap_err();
        assert!(error.contains("duplicate LK artifact record dedupe key"));
    }

    #[test]
    fn writer_selects_api_sink_for_http_dsn() {
        let writer = LkBulkWriter::from_contract("https://lk.example.com/api/v1/bulk", None)
            .expect("writer");

        assert!(matches!(writer.sink, LkBulkSink::Api { .. }));
    }

    #[test]
    fn writer_selects_postgres_sink_for_postgres_dsn() {
        let writer =
            LkBulkWriter::from_contract("postgres://localhost/lk", None).expect("writer");

        assert!(matches!(writer.sink, LkBulkSink::Postgres { .. }));
    }
}
