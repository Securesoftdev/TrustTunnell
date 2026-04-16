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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LkBatchWriteResult {
    pub(crate) created: usize,
    pub(crate) updated: usize,
    pub(crate) unchanged: usize,
    pub(crate) deactivated: usize,
    pub(crate) failed: usize,
    #[serde(default)]
    pub(crate) failures: Vec<String>,
}

pub(crate) struct LkBulkWriter {
    sink: LkBulkSink,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LkWriteContract {
    Api,
    PgFunction,
    LegacyTable,
}

impl LkWriteContract {
    pub(crate) fn from_env(raw: &str) -> Result<Self, String> {
        match raw.trim() {
            "api" => Ok(Self::Api),
            "pg_function" => Ok(Self::PgFunction),
            "legacy_table" => Ok(Self::LegacyTable),
            other => Err(format!(
                "LK_WRITE_CONTRACT must be one of: api, pg_function, legacy_table; got {other}"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::PgFunction => "pg_function",
            Self::LegacyTable => "legacy_table",
        }
    }
}

enum LkBulkSink {
    Api {
        client: Client,
        endpoint: String,
        service_token: Option<String>,
    },
    PostgresFunction {
        dsn: String,
        function_name: String,
    },
    LegacyPostgresTable {
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
    failed: usize,
    failures: Vec<String>,
}

impl LkBulkWriter {
    pub(crate) fn from_contract(
        write_contract: LkWriteContract,
        lk_db_dsn: &str,
        lk_service_token: Option<String>,
    ) -> Result<Self, String> {
        let dsn = lk_db_dsn.trim();
        if dsn.is_empty() {
            return Err("LK_DB_DSN must not be empty".to_string());
        }

        let detected = detect_contract_from_dsn(dsn)?;
        if detected != write_contract {
            return Err(format!(
                "LK_WRITE_CONTRACT expects {expected}, but LK_DB_DSN points to {detected}. dsn={dsn}",
                expected = write_contract.as_str(),
                detected = detected.as_str(),
            ));
        }

        match write_contract {
            LkWriteContract::Api => Ok(Self {
                sink: LkBulkSink::Api {
                    client: Client::new(),
                    endpoint: dsn.to_string(),
                    service_token: lk_service_token,
                },
            }),
            LkWriteContract::PgFunction => {
                let function_name = std::env::var("LK_DB_WRITE_FUNCTION")
                    .ok()
                    .map(|item| item.trim().to_string())
                    .filter(|item| !item.is_empty())
                    .unwrap_or_else(|| "trusttunnel_apply_access_artifacts".to_string());
                Ok(Self {
                    sink: LkBulkSink::PostgresFunction {
                        dsn: dsn.to_string(),
                        function_name,
                    },
                })
            }
            LkWriteContract::LegacyTable => {
                if std::env::var("LK_DB_LEGACY_RAW_TABLE")
                    .ok()
                    .as_deref()
                    .map(str::trim)
                    != Some("1")
                {
                    return Err(
                        "legacy table contract requires LK_DB_LEGACY_RAW_TABLE=1".to_string(),
                    );
                }
                if std::env::var("LK_ALLOW_DEPRECATED_LEGACY_TABLE")
                    .ok()
                    .as_deref()
                    .map(str::trim)
                    != Some("1")
                {
                    return Err(
                        "legacy table contract is deprecated; set LK_ALLOW_DEPRECATED_LEGACY_TABLE=1 to acknowledge and enable it".to_string(),
                    );
                }
                eprintln!(
                    "warning: LK_WRITE_CONTRACT=legacy_table is deprecated and should be replaced with pg_function or api"
                );
                let table_name = std::env::var("LK_DB_TABLE")
                    .ok()
                    .map(|item| item.trim().to_string())
                    .filter(|item| !item.is_empty())
                    .unwrap_or_else(|| "access_artifacts".to_string());
                Ok(Self {
                    sink: LkBulkSink::LegacyPostgresTable {
                        dsn: dsn.to_string(),
                        table_name,
                    },
                })
            }
        }
    }

    pub(crate) async fn write_batch(
        &self,
        records: Vec<LkArtifactRecord>,
    ) -> Result<LkBatchWriteResult, String> {
        validate_records(&records)?;
        if records.is_empty() {
            return Ok(LkBatchWriteResult::default());
        }
        self.ensure_contract_compatibility().await?;
        match &self.sink {
            LkBulkSink::Api {
                client,
                endpoint,
                service_token,
            } => write_via_api(client, endpoint, service_token.as_deref(), records).await,
            LkBulkSink::PostgresFunction { dsn, function_name } => {
                write_via_postgres_function(dsn, function_name, records).await
            }
            LkBulkSink::LegacyPostgresTable { dsn, table_name } => {
                write_via_legacy_postgres_table(dsn, table_name, records).await
            }
        }
    }

    async fn ensure_contract_compatibility(&self) -> Result<(), String> {
        match &self.sink {
            LkBulkSink::Api { endpoint, .. } => ensure_api_contract_compatibility(endpoint),
            LkBulkSink::PostgresFunction { dsn, function_name } => {
                ensure_postgres_function_contract_compatibility(dsn, function_name).await
            }
            LkBulkSink::LegacyPostgresTable { table_name, .. } => {
                ensure_legacy_table_contract_compatibility(table_name)
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
    let mut request = client.post(endpoint).json(&LkBulkApiRequest { records });
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

    let raw_payload = response
        .text()
        .await
        .map_err(|e| format!("failed to read LK bulk API response body: {e}"))?;
    validate_contract_response_shape(&raw_payload, "api", endpoint)?;
    let payload = serde_json::from_str::<LkBulkApiResponse>(&raw_payload)
        .map_err(|e| format!("failed to parse LK bulk API response: {e}; raw={raw_payload}"))?;

    Ok(LkBatchWriteResult {
        created: payload.created,
        updated: payload.updated,
        unchanged: payload.unchanged,
        deactivated: payload.deactivated,
        failed: payload.failed,
        failures: payload.failures,
    })
}

async fn write_via_postgres_function(
    dsn: &str,
    function_name: &str,
    records: Vec<LkArtifactRecord>,
) -> Result<LkBatchWriteResult, String> {
    let payload = serde_json::to_string(&records)
        .map_err(|e| format!("failed to serialize LK artifact payload: {e}"))?;
    let query = format!(
        "SELECT {function_name}($${payload}$$::jsonb)::text"
    );
    let raw = exec_psql(dsn, &query).await.map_err(|e| {
        format!(
            "failed to execute LK write function {function_name}: {e}. \
If your LK still uses legacy raw table writes, set LK_DB_LEGACY_RAW_TABLE=1"
        )
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "LK write function {function_name} returned empty response"
        ));
    }
    serde_json::from_str::<LkBatchWriteResult>(trimmed).map_err(|e| {
        format!(
            "failed to parse LK write function {function_name} response as JSON: {e}; raw={trimmed}"
        )
    })
}

async fn write_via_legacy_postgres_table(
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
        let existing_raw = match exec_psql(dsn, &existing_status_query).await {
            Ok(raw) => raw,
            Err(e) => {
                summary.failed += 1;
                summary
                    .failures
                    .push(format!("{}: failed to query existing artifact: {e}", record.username));
                continue;
            }
        };
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
                updated_at = NOW()",
            sql_quote(&record.dedupe_key()),
            sql_quote(&record.external_node_id),
            sql_quote(&record.username),
            sql_nullable(&record.external_account_id),
            sql_nullable(&record.access_bundle_id),
            sql_nullable(&record.tt_link),
            sql_nullable(&record.config_hash),
            if record.active { "TRUE" } else { "FALSE" },
        );
        if let Err(e) = exec_psql(dsn, &upsert_query).await {
            summary.failed += 1;
            summary
                .failures
                .push(format!("{}: failed to upsert artifact: {e}", record.username));
            continue;
        }

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

fn detect_contract_from_dsn(dsn: &str) -> Result<LkWriteContract, String> {
    if is_http_url(dsn) {
        return Ok(LkWriteContract::Api);
    }
    if dsn.starts_with("postgres://") || dsn.starts_with("postgresql://") {
        return Ok(LkWriteContract::PgFunction);
    }
    Err(format!(
        "LK_DB_DSN must be HTTP(S) bulk endpoint or Postgres DSN, got: {dsn}"
    ))
}

fn ensure_api_contract_compatibility(endpoint: &str) -> Result<(), String> {
    if !is_http_url(endpoint) {
        return Err(format!(
            "API contract compatibility check failed: endpoint must be http:// or https://, got {endpoint}"
        ));
    }
    Ok(())
}

async fn ensure_postgres_function_contract_compatibility(
    dsn: &str,
    function_name: &str,
) -> Result<(), String> {
    let function_exists_query = format!(
        "SELECT EXISTS (SELECT 1 FROM pg_proc p INNER JOIN pg_namespace n ON n.oid = p.pronamespace WHERE p.proname = '{}' AND pg_get_function_identity_arguments(p.oid) = 'jsonb')::text",
        sql_quote(function_name)
    );
    let exists_raw = exec_psql(dsn, &function_exists_query)
        .await
        .map_err(|e| format!("failed to check LK write function {function_name}: {e}"))?;
    if !exists_raw.trim().eq_ignore_ascii_case("t") {
        return Err(format!(
            "PG function contract compatibility check failed: expected write function {function_name}(jsonb), but it was not found"
        ));
    }

    let version_function_name = std::env::var("LK_DB_WRITE_FUNCTION_VERSION_FUNCTION")
        .ok()
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .unwrap_or_else(|| format!("{function_name}_contract_version"));
    let expected_version = std::env::var("LK_DB_WRITE_CONTRACT_VERSION")
        .ok()
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .unwrap_or_else(|| "v1".to_string());
    let version_query = format!("SELECT {version_function_name}()::text");
    let detected_version = exec_psql(dsn, &version_query).await.map_err(|e| {
        format!(
            "PG function contract compatibility check failed: expected metadata function {version_function_name}() returning version {expected_version}; {e}"
        )
    })?;
    let detected_version = detected_version.trim();
    if detected_version != expected_version {
        return Err(format!(
            "PG function contract compatibility check failed: expected contract version {expected_version}, detected {detected_version} (source: {version_function_name}())"
        ));
    }

    let handshake_query = format!("SELECT {function_name}($$[]$$::jsonb)::text");
    let handshake_raw = exec_psql(dsn, &handshake_query).await.map_err(|e| {
        format!(
            "PG function contract compatibility check failed while probing {function_name}(jsonb): {e}"
        )
    })?;
    validate_contract_response_shape(&handshake_raw, "pg_function", function_name)?;

    Ok(())
}

fn ensure_legacy_table_contract_compatibility(table_name: &str) -> Result<(), String> {
    if table_name.trim().is_empty() {
        return Err("legacy table contract compatibility check failed: table name is empty".to_string());
    }
    Ok(())
}

fn validate_contract_response_shape(raw: &str, contract: &str, source: &str) -> Result<(), String> {
    let parsed: serde_json::Value = serde_json::from_str(raw.trim()).map_err(|e| {
        format!(
            "contract compatibility check failed for {contract} ({source}): response is not JSON: {e}; raw={}",
            raw.trim()
        )
    })?;
    let object = parsed.as_object().ok_or_else(|| {
        format!(
            "contract compatibility check failed for {contract} ({source}): expected JSON object response"
        )
    })?;
    for field in ["created", "updated", "unchanged", "deactivated", "failed", "failures"] {
        if !object.contains_key(field) {
            return Err(format!(
                "contract compatibility check failed for {contract} ({source}): missing required field `{field}`"
            ));
        }
    }
    Ok(())
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
        let writer = LkBulkWriter::from_contract(
            LkWriteContract::Api,
            "https://lk.example.com/api/v1/bulk",
            None,
        )
        .expect("writer");

        assert!(matches!(writer.sink, LkBulkSink::Api { .. }));
    }

    #[test]
    fn write_contract_mode_must_match_dsn_type() {
        let result = LkBulkWriter::from_contract(
            LkWriteContract::Api,
            "postgres://localhost/lk",
            None,
        );
        let err = match result {
            Ok(_) => panic!("expected contract mismatch error"),
            Err(err) => err,
        };

        assert!(err.contains("LK_WRITE_CONTRACT expects api"));
        assert!(err.contains("points to pg_function"));
    }

    #[test]
    fn write_contract_env_parser_rejects_unknown_values() {
        let err = LkWriteContract::from_env("unknown").unwrap_err();
        assert!(err.contains("LK_WRITE_CONTRACT must be one of"));
    }

    #[test]
    fn response_shape_validation_reports_missing_field() {
        let err = validate_contract_response_shape(
            r#"{"created":1,"updated":0,"unchanged":2,"deactivated":0,"failed":0}"#,
            "pg_function",
            "trusttunnel_apply_access_artifacts",
        )
        .unwrap_err();
        assert!(err.contains("missing required field `failures`"));
    }

    #[test]
    fn bulk_upsert_tracks_created_updated_unchanged_deactivated_and_partial_errors() {
        let payload: LkBulkApiResponse = serde_json::from_str(
            r#"{"created":1,"updated":2,"unchanged":3,"deactivated":4,"failed":1,"failures":["alice: timeout"]}"#,
        )
        .unwrap();
        let result = LkBatchWriteResult {
            created: payload.created,
            updated: payload.updated,
            unchanged: payload.unchanged,
            deactivated: payload.deactivated,
            failed: payload.failed,
            failures: payload.failures,
        };

        assert_eq!(result.created, 1);
        assert_eq!(result.updated, 2);
        assert_eq!(result.unchanged, 3);
        assert_eq!(result.deactivated, 4);
        assert_eq!(result.failed, 1);
        assert_eq!(result.failures, vec!["alice: timeout".to_string()]);
    }

    #[test]
    fn postgres_function_response_is_parsed_from_json() {
        let parsed: LkBatchWriteResult = serde_json::from_str(
            r#"{"created":1,"updated":0,"unchanged":2,"deactivated":0,"failed":0,"failures":[]}"#,
        )
        .unwrap();

        assert_eq!(parsed.created, 1);
        assert_eq!(parsed.unchanged, 2);
        assert_eq!(parsed.failed, 0);
    }
}
