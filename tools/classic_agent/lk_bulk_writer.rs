use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) credential_external_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) generated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) source_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) link_hash: Option<String>,
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
        if let Some(credential_external_id) = self
            .credential_external_id
            .as_deref()
            .map(str::trim)
            .filter(|item| !item.is_empty())
        {
            return format!(
                "node_credential:{}:{credential_external_id}",
                self.external_node_id
            );
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

#[derive(Debug, Serialize)]
struct LkBulkApiRequest {
    contract_version: &'static str,
    snapshot_version: &'static str,
    external_node_id: String,
    import_batch_id: String,
    idempotency_key: String,
    request_id: String,
    artifacts: Vec<LkBulkApiArtifactRequest>,
}

#[derive(Debug, Serialize)]
struct LkBulkApiArtifactRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_external_id: Option<String>,
    link: String,
    link_revision: String,
    is_current: bool,
    generated_at: String,
    source: String,
    display_name: String,
    source_key: String,
    link_hash: String,
}

const BATCH_ID_FORMAT_RUNTIME_REASON: &str = "unexpected_batch_id_format_runtime";

impl LkBulkWriter {
    pub(crate) fn from_contract(
        write_contract: LkWriteContract,
        lk_db_dsn: &str,
        node_external_id: &str,
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
                    client: Client::builder()
                        .no_proxy()
                        .build()
                        .map_err(|e| format!("failed to initialize LK API HTTP client: {e}"))?,
                    endpoint: resolve_api_endpoint(dsn, node_external_id)?,
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
                        "legacy table contract requires LK_DB_LEGACY_RAW_TABLE=1".to_string()
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

    pub(crate) fn active_contract(&self) -> &'static str {
        match &self.sink {
            LkBulkSink::Api { .. } => "api",
            LkBulkSink::PostgresFunction { .. } => "pg_function",
            LkBulkSink::LegacyPostgresTable { .. } => "legacy_table",
        }
    }

    pub(crate) fn selected_endpoint(&self) -> Option<&str> {
        match &self.sink {
            LkBulkSink::Api { endpoint, .. } => Some(endpoint),
            _ => None,
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
    let request_payload = build_api_request(records)?;
    validate_api_payload_contract(&request_payload)?;
    log_api_payload_shape(endpoint, &request_payload)?;
    let mut request = client.post(endpoint).json(&request_payload);
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
        let diagnostics = render_payload_diagnostics(&request_payload)?;
        return Err(format!(
            "LK bulk API returned HTTP {}: {}. request_id={} import_batch_id={} idempotency_key={}. {}",
            status.as_u16(),
            body.trim(),
            request_payload.request_id,
            request_payload.import_batch_id,
            request_payload.idempotency_key,
            diagnostics
        ));
    }

    let raw_payload = response
        .text()
        .await
        .map_err(|e| format!("failed to read LK bulk API response body: {e}"))?;
    parse_api_response_contract(&raw_payload).map_err(|e| {
        format!("failed to parse LK artifacts API response contract: {e}; raw={raw_payload}")
    })
}

async fn write_via_postgres_function(
    dsn: &str,
    function_name: &str,
    records: Vec<LkArtifactRecord>,
) -> Result<LkBatchWriteResult, String> {
    let payload = serde_json::to_string(&records)
        .map_err(|e| format!("failed to serialize LK artifact payload: {e}"))?;
    let query = format!("SELECT {function_name}($${payload}$$::jsonb)::text");
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
                summary.failures.push(format!(
                    "{}: failed to query existing artifact: {e}",
                    record.username
                ));
                continue;
            }
        };
        let existing = parse_existing_row(&existing_raw);

        let changed = existing
            .as_ref()
            .map(
                |(existing_active, existing_tt_link, existing_config_hash)| {
                    *existing_active != record.active
                        || existing_tt_link.as_str()
                            != record.tt_link.as_deref().unwrap_or_default()
                        || existing_config_hash.as_str()
                            != record.config_hash.as_deref().unwrap_or_default()
                },
            )
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
            summary.failures.push(format!(
                "{}: failed to upsert artifact: {e}",
                record.username
            ));
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

fn resolve_api_endpoint(dsn: &str, node_external_id: &str) -> Result<String, String> {
    let external_node_id = node_external_id.trim();
    if external_node_id.is_empty() {
        return Err("NODE_EXTERNAL_ID must not be empty".to_string());
    }
    let mut endpoint = dsn
        .replace("{externalNodeId}", external_node_id)
        .replace(":externalNodeId", external_node_id);
    if endpoint.ends_with('/') {
        endpoint.pop();
    }
    Ok(endpoint)
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
        return Err(
            "legacy table contract compatibility check failed: table name is empty".to_string(),
        );
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
    for field in [
        "created",
        "updated",
        "unchanged",
        "deactivated",
        "failed",
        "failures",
    ] {
        if !object.contains_key(field) {
            return Err(format!(
                "contract compatibility check failed for {contract} ({source}): missing required field `{field}`"
            ));
        }
    }
    Ok(())
}

fn build_api_request(records: Vec<LkArtifactRecord>) -> Result<LkBulkApiRequest, String> {
    static REQUEST_SEQ: AtomicU64 = AtomicU64::new(1);
    let external_node_id = records
        .first()
        .map(|item| item.external_node_id.clone())
        .ok_or_else(|| "LK artifacts API payload is empty".to_string())?;
    if records
        .iter()
        .any(|item| item.external_node_id != external_node_id)
    {
        return Err(
            "LK artifacts API payload must contain exactly one external_node_id".to_string(),
        );
    }
    let mut validation_errors = Vec::new();
    let mut artifacts = records
        .into_iter()
        .filter_map(|record| {
            let username = Some(record.username.trim().to_string()).filter(|item| !item.is_empty());
            let credential_external_id = record
                .credential_external_id
                .as_deref()
                .map(str::trim)
                .map(ToString::to_string)
                .filter(|item| !item.is_empty());
            if username.is_none() && credential_external_id.is_none() {
                validation_errors.push(format!(
                    "artifact source_key={} is missing both username and credential_external_id",
                    record.source_key.as_deref().unwrap_or("-"),
                ));
                return None;
            }
            let Some(link) = record
                .tt_link
                .as_deref()
                .map(str::trim)
                .map(ToString::to_string)
                .filter(|item| !item.is_empty())
            else {
                validation_errors.push(format!(
                    "artifact source_key={} is missing required non-empty link",
                    record.source_key.as_deref().unwrap_or("-")
                ));
                return None;
            };
            let Some(link_revision) = record
                .config_hash
                .as_deref()
                .map(str::trim)
                .map(ToString::to_string)
                .filter(|item| !item.is_empty())
            else {
                validation_errors.push(format!(
                    "artifact source_key={} is missing required non-empty link_revision",
                    record.source_key.as_deref().unwrap_or("-")
                ));
                return None;
            };
            let Some(source_key) = record
                .source_key
                .as_deref()
                .map(str::trim)
                .map(ToString::to_string)
                .filter(|item| !item.is_empty())
                .or_else(|| username.clone())
                .or_else(|| credential_external_id.clone())
            else {
                validation_errors.push(format!(
                    "artifact username={} has no source_key/username/credential_external_id",
                    record.username
                ));
                return None;
            };
            let Some(link_hash) = record
                .link_hash
                .as_deref()
                .map(str::trim)
                .map(ToString::to_string)
                .filter(|item| !item.is_empty())
                .or_else(|| Some(link_revision.clone()))
            else {
                validation_errors.push(format!(
                    "artifact source_key={} is missing required link_hash",
                    source_key
                ));
                return None;
            };
            let Some(display_name) = record
                .display_name
                .as_deref()
                .map(str::trim)
                .map(ToString::to_string)
                .filter(|item| !item.is_empty())
                .or_else(|| username.clone())
                .or_else(|| credential_external_id.clone())
            else {
                validation_errors.push(format!(
                    "artifact source_key={} is missing required display_name",
                    source_key
                ));
                return None;
            };
            Some(LkBulkApiArtifactRequest {
                username,
                credential_external_id,
                link,
                link_revision,
                is_current: record.active,
                generated_at: record
                    .generated_at
                    .unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
                source: record
                    .source
                    .unwrap_or_else(|| "trusttunnel_classic_agent".to_string()),
                display_name,
                source_key,
                link_hash,
            })
        })
        .collect::<Vec<_>>();
    artifacts.sort_by(|left, right| left.source_key.cmp(&right.source_key));
    if !validation_errors.is_empty() {
        return Err(format!(
            "LK artifacts API payload validation failed before POST: {} invalid artifact(s): {}",
            validation_errors.len(),
            validation_errors.join("; ")
        ));
    }
    if artifacts.is_empty() {
        return Err(
            "LK artifacts API payload validation failed: empty artifacts array".to_string(),
        );
    }
    let request_id = format!(
        "req-{}-{}",
        chrono::Utc::now().timestamp_millis(),
        REQUEST_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let idempotency_key = build_logical_batch_id(&external_node_id, &artifacts);
    let import_batch_id = format!("{external_node_id}:{idempotency_key}:{request_id}");
    let import_batch_id = trim_id(import_batch_id, 128);
    let idempotency_key = trim_id(idempotency_key, 128);
    let request_id = trim_id(request_id, 128);
    Ok(LkBulkApiRequest {
        contract_version: "v1",
        snapshot_version: "v1",
        external_node_id,
        import_batch_id,
        idempotency_key,
        request_id,
        artifacts,
    })
}

fn log_api_payload_shape(endpoint: &str, payload: &LkBulkApiRequest) -> Result<(), String> {
    let import_batch_id_contains_request_id = validate_import_batch_id_format(payload).is_ok();
    let diagnostics = render_payload_diagnostics(payload)?;
    let sample_artifact = render_redacted_sample_artifact(payload)?;
    let payload_revision = summarize_payload_revision(payload);
    let force_regenerate = false;
    eprintln!(
        "phase=lk_artifacts_post_diagnostics endpoint={} external_node_id={} request_id={} idempotency_key={} import_batch_id={} import_batch_id_contains_request_id={} payload_revision={} artifacts_count={}",
        endpoint,
        payload.external_node_id,
        payload.request_id,
        payload.idempotency_key,
        payload.import_batch_id,
        import_batch_id_contains_request_id,
        payload_revision,
        payload.artifacts.len()
    );
    eprintln!(
        "phase=lk_api_payload_debug endpoint={} external_node_id={} artifacts_count={} import_batch_id={} request_id={} idempotency_key={} payload_revision={} force_regenerate={} diagnostics={} sample_artifact={}",
        endpoint,
        payload.external_node_id,
        payload.artifacts.len(),
        payload.import_batch_id,
        payload.request_id,
        payload.idempotency_key,
        payload_revision,
        force_regenerate,
        diagnostics,
        sample_artifact
    );
    Ok(())
}

fn summarize_payload_revision(payload: &LkBulkApiRequest) -> String {
    let mut revisions = payload
        .artifacts
        .iter()
        .map(|item| item.link_revision.as_str())
        .collect::<Vec<_>>();
    revisions.sort_unstable();
    revisions.dedup();
    if revisions.is_empty() {
        return "none".to_string();
    }
    if revisions.len() == 1 {
        return revisions[0].to_string();
    }
    format!("multi:{}", revisions.join("|"))
}

fn render_payload_diagnostics(payload: &LkBulkApiRequest) -> Result<String, String> {
    let value = serde_json::to_value(payload)
        .map_err(|e| format!("failed to render payload diagnostics: {e}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "failed to render payload diagnostics: root is not object".to_string())?;
    let top_level_keys: Vec<&str> = object.keys().map(String::as_str).collect();
    let first_artifact_keys = object
        .get("artifacts")
        .and_then(|item| item.as_array())
        .and_then(|items| items.first())
        .and_then(|item| item.as_object())
        .map(|item| item.keys().map(String::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    Ok(format!(
        "payload_top_level_keys={top_level_keys:?} payload_artifacts_count={} first_artifact_keys={first_artifact_keys:?}",
        payload.artifacts.len()
    ))
}

fn validate_api_payload_contract(payload: &LkBulkApiRequest) -> Result<(), String> {
    if payload.import_batch_id.trim().is_empty() {
        return Err("missing import_batch_id".to_string());
    }
    if payload.idempotency_key.trim().is_empty() {
        return Err("missing idempotency_key".to_string());
    }
    if payload.request_id.trim().is_empty() {
        return Err("missing request_id".to_string());
    }
    validate_import_batch_id_format(payload)?;
    if payload.artifacts.is_empty() {
        return Err("empty artifacts array when write was expected".to_string());
    }
    for item in &payload.artifacts {
        if item
            .username
            .as_deref()
            .map(str::trim)
            .is_none_or(|value| value.is_empty())
            && item
                .credential_external_id
                .as_deref()
                .map(str::trim)
                .is_none_or(|value| value.is_empty())
        {
            return Err("artifact without username/credential_external_id".to_string());
        }
        if chrono::DateTime::parse_from_rfc3339(item.generated_at.as_str()).is_err() {
            return Err("invalid generated_at format".to_string());
        }
        if item.link_revision.trim().is_empty() {
            return Err("invalid link_revision type".to_string());
        }
    }
    Ok(())
}

fn validate_import_batch_id_format(payload: &LkBulkApiRequest) -> Result<(), String> {
    let expected_suffix = format!(":{}", payload.request_id);
    let expected_full = format!(
        "{}:{}:{}",
        payload.external_node_id, payload.idempotency_key, payload.request_id
    );
    let contains_request_id = payload.import_batch_id.ends_with(&expected_suffix);
    if contains_request_id {
        return Ok(());
    }
    let message = format!(
        "reason={} external_node_id={} request_id={} idempotency_key={} import_batch_id={} expected_format={} import_batch_id_contains_request_id={}",
        BATCH_ID_FORMAT_RUNTIME_REASON,
        payload.external_node_id,
        payload.request_id,
        payload.idempotency_key,
        payload.import_batch_id,
        expected_full,
        contains_request_id
    );
    eprintln!("phase=lk_api_payload_invalid {message}");
    Err(message)
}

fn build_logical_batch_id(
    external_node_id: &str,
    artifacts: &[LkBulkApiArtifactRequest],
) -> String {
    let mut seed = external_node_id.to_string();
    for artifact in artifacts {
        seed.push('|');
        seed.push_str(artifact.source_key.as_str());
        seed.push('|');
        seed.push_str(artifact.link_revision.as_str());
        seed.push('|');
        seed.push_str(if artifact.is_current { "1" } else { "0" });
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, seed.as_bytes());
    let hash = hex::encode(digest.as_ref());
    format!("batch-v1-{hash}")
}

fn trim_id(value: String, limit: usize) -> String {
    value.chars().take(limit).collect()
}

fn render_redacted_sample_artifact(payload: &LkBulkApiRequest) -> Result<String, String> {
    let mut sample = serde_json::to_value(payload.artifacts.first())
        .map_err(|e| format!("failed to render payload sample artifact: {e}"))?;
    if let Some(obj) = sample.as_object_mut() {
        for (key, value) in obj {
            if key == "is_current" {
                continue;
            }
            *value = serde_json::Value::String("[redacted]".to_string());
        }
    }
    serde_json::to_string(&sample)
        .map_err(|e| format!("failed to stringify payload sample artifact: {e}"))
}

fn parse_api_response_contract(raw: &str) -> Result<LkBatchWriteResult, String> {
    let parsed: serde_json::Value =
        serde_json::from_str(raw.trim()).map_err(|e| format!("response is not valid JSON: {e}"))?;
    let object = parsed
        .as_object()
        .ok_or_else(|| "response is not a JSON object".to_string())?;

    let created = resolve_counter(object, &["created", "inserted"]).unwrap_or(0);
    let updated = resolve_counter(object, &["updated", "upserted"]).unwrap_or(0);
    let unchanged = resolve_counter(object, &["unchanged", "skipped"]).unwrap_or(0);
    let deactivated = resolve_counter(object, &["deactivated", "deleted"]).unwrap_or(0);
    let failed = resolve_counter(object, &["failed", "errors", "invalid"]).unwrap_or(0);
    let failures = resolve_failures(object);

    Ok(LkBatchWriteResult {
        created,
        updated,
        unchanged,
        deactivated,
        failed: failed.max(failures.len()),
        failures,
    })
}

fn resolve_counter(
    root: &serde_json::Map<String, serde_json::Value>,
    aliases: &[&str],
) -> Option<usize> {
    for alias in aliases {
        if let Some(value) = root.get(*alias).and_then(|item| item.as_u64()) {
            return Some(value as usize);
        }
    }
    for container in ["summary", "result", "stats", "data"] {
        if let Some(object) = root.get(container).and_then(|item| item.as_object()) {
            for alias in aliases {
                if let Some(value) = object.get(*alias).and_then(|item| item.as_u64()) {
                    return Some(value as usize);
                }
            }
        }
    }
    None
}

fn resolve_failures(root: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let mut failures = Vec::new();
    for key in ["failures", "errors"] {
        if let Some(values) = root.get(key).and_then(|item| item.as_array()) {
            for value in values {
                if let Some(detail) = value.as_str() {
                    failures.push(detail.to_string());
                } else if let Some(object) = value.as_object() {
                    if let Some(detail) = object.get("message").and_then(|item| item.as_str()) {
                        failures.push(detail.to_string());
                    }
                }
            }
        }
    }
    failures
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn test_record(username: &str) -> LkArtifactRecord {
        LkArtifactRecord {
            username: username.to_string(),
            external_node_id: "node-1".to_string(),
            external_account_id: None,
            access_bundle_id: None,
            tt_link: Some(format!("tt://{username}")),
            config_hash: Some("hash-1".to_string()),
            active: true,
            credential_external_id: None,
            generated_at: Some("2026-04-16T00:00:00Z".to_string()),
            source: Some("classic_agent".to_string()),
            display_name: Some("Primary".to_string()),
            source_key: Some(username.to_string()),
            link_hash: Some("abc".to_string()),
        }
    }

    #[test]
    fn dedupe_key_prefers_access_bundle() {
        let mut record = test_record("alice");
        record.access_bundle_id = Some("bundle-1".to_string());

        assert_eq!(record.dedupe_key(), "bundle:bundle-1");
    }

    #[test]
    fn dedupe_key_falls_back_to_node_and_username() {
        let record = test_record("alice");

        assert_eq!(record.dedupe_key(), "node_user:node-1:alice");
    }

    #[test]
    fn validate_rejects_duplicate_dedupe_keys() {
        let first = test_record("alice");
        let mut second = test_record("alice");
        second.tt_link = Some("tt://alice-changed".to_string());
        second.config_hash = Some("hash-2".to_string());

        let error = validate_records(&[first, second]).unwrap_err();
        assert!(error.contains("duplicate LK artifact record dedupe key"));
    }

    #[test]
    fn writer_selects_api_sink_for_http_dsn() {
        let writer = LkBulkWriter::from_contract(
            LkWriteContract::Api,
            "https://lk.example.com/api/v1/bulk",
            "node-1",
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
            "node-1",
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
    fn api_response_parser_accepts_nested_summary_shape() {
        let result = parse_api_response_contract(
            r#"{"summary":{"created":1,"updated":2,"unchanged":3,"deactivated":4,"failed":1},"errors":[{"message":"alice: timeout"}]}"#,
        )
        .unwrap();

        assert_eq!(result.created, 1);
        assert_eq!(result.updated, 2);
        assert_eq!(result.unchanged, 3);
        assert_eq!(result.deactivated, 4);
        assert_eq!(result.failed, 1);
        assert_eq!(result.failures, vec!["alice: timeout".to_string()]);
    }

    #[test]
    fn api_request_payload_uses_external_node_and_artifacts_shape() {
        let payload = build_api_request(vec![test_record("alice")]).unwrap();
        let encoded = serde_json::to_value(payload).unwrap();
        assert_eq!(encoded["contract_version"], "v1");
        assert_eq!(encoded["snapshot_version"], "v1");
        assert_eq!(encoded["external_node_id"], "node-1");
        assert!(encoded["import_batch_id"].is_string());
        assert!(encoded["request_id"].is_string());
        assert!(encoded["idempotency_key"].is_string());
        assert_eq!(encoded["artifacts"][0]["username"], "alice");
        assert_eq!(encoded["artifacts"][0]["link"], "tt://alice");
        assert_eq!(encoded["artifacts"][0]["link_revision"], "hash-1");
        assert_eq!(encoded["artifacts"][0]["link_hash"], "abc");
        assert_eq!(encoded["artifacts"][0]["source_key"], "alice");
        assert_eq!(encoded["artifacts"][0]["display_name"], "Primary");
        assert_eq!(encoded["artifacts"][0]["is_current"], true);
        assert_eq!(encoded["artifacts"][0]["source"], "classic_agent");
    }

    #[test]
    fn api_request_payload_requires_canonical_field_types() {
        let payload = build_api_request(vec![test_record("alice")]).unwrap();
        let encoded = serde_json::to_value(payload).unwrap();
        assert!(encoded["contract_version"].is_string());
        assert!(encoded["snapshot_version"].is_string());
        assert!(encoded["external_node_id"].is_string());
        assert!(encoded["import_batch_id"].is_string());
        assert!(encoded["request_id"].is_string());
        assert!(encoded["idempotency_key"].is_string());
        assert!(encoded["artifacts"].is_array());
        assert!(encoded["artifacts"][0]["username"].is_string());
        assert!(encoded["artifacts"][0]["link"].is_string());
        assert!(encoded["artifacts"][0]["link_revision"].is_string());
        assert!(encoded["artifacts"][0]["link_hash"].is_string());
        assert!(encoded["artifacts"][0]["source_key"].is_string());
        assert!(encoded["artifacts"][0]["is_current"].is_boolean());
        assert!(encoded["artifacts"][0]["generated_at"].is_string());
        assert!(encoded["artifacts"][0]["source"].is_string());
        assert!(encoded["artifacts"][0]["display_name"].is_string());
    }

    #[test]
    fn api_request_payload_supports_credential_external_id_without_username() {
        let mut record = test_record("alice");
        record.username = String::new();
        record.credential_external_id = Some("cred-1".to_string());
        record.display_name = None;
        record.source_key = None;

        let payload = build_api_request(vec![record]).unwrap();
        let encoded = serde_json::to_value(payload).unwrap();
        assert_eq!(encoded["artifacts"][0]["credential_external_id"], "cred-1");
        assert_eq!(encoded["artifacts"][0]["source_key"], "cred-1");
        assert_eq!(encoded["artifacts"][0]["display_name"], "cred-1");
        assert!(encoded["artifacts"][0].get("username").is_none());
    }

    #[test]
    fn api_request_reuses_idempotency_key_for_same_logical_payload() {
        let first = build_api_request(vec![test_record("alice")]).unwrap();
        let second = build_api_request(vec![test_record("alice")]).unwrap();
        assert_ne!(first.import_batch_id, second.import_batch_id);
        assert_eq!(first.idempotency_key, second.idempotency_key);
        assert_ne!(first.request_id, second.request_id);
    }

    #[test]
    fn api_request_import_batch_id_contains_request_id_suffix() {
        let payload = build_api_request(vec![test_record("alice")]).unwrap();
        assert!(payload
            .import_batch_id
            .ends_with(format!(":{}", payload.request_id).as_str()));
    }

    #[test]
    fn api_request_validation_fails_for_legacy_import_batch_id_format() {
        let mut payload = build_api_request(vec![test_record("alice")]).unwrap();
        payload.import_batch_id =
            format!("{}:{}", payload.external_node_id, payload.idempotency_key);
        let err = validate_api_payload_contract(&payload).unwrap_err();
        assert!(err.contains(BATCH_ID_FORMAT_RUNTIME_REASON));
        assert!(err.contains("import_batch_id_contains_request_id=false"));
    }

    #[test]
    fn api_request_new_batch_gets_new_import_batch_id() {
        let first = build_api_request(vec![test_record("alice")]).unwrap();
        let mut changed = test_record("alice");
        changed.config_hash = Some("hash-2".to_string());
        let second = build_api_request(vec![changed]).unwrap();
        assert_ne!(first.import_batch_id, second.import_batch_id);
    }

    #[test]
    fn api_request_rejects_artifact_without_matchers() {
        let mut invalid = test_record("alice");
        invalid.username.clear();
        invalid.credential_external_id = None;
        let err = build_api_request(vec![invalid]).unwrap_err();
        assert!(err.contains("missing both username and credential_external_id"));
    }

    #[test]
    fn api_request_rejects_artifact_without_link() {
        let mut invalid = test_record("alice");
        invalid.tt_link = None;
        let err = build_api_request(vec![invalid]).unwrap_err();
        assert!(err.contains("missing required non-empty link"));
    }

    #[test]
    fn api_request_idempotency_key_is_stable_when_generated_at_differs() {
        let mut first_record = test_record("alice");
        first_record.generated_at = Some("2026-04-16T00:00:00Z".to_string());
        let first = build_api_request(vec![first_record]).unwrap();
        let mut second_record = test_record("alice");
        second_record.generated_at = Some("2026-04-16T01:23:45Z".to_string());
        let second = build_api_request(vec![second_record]).unwrap();
        assert_ne!(first.import_batch_id, second.import_batch_id);
        assert_eq!(first.idempotency_key, second.idempotency_key);
    }

    #[test]
    fn api_endpoint_template_replaces_external_node_id() {
        let endpoint = resolve_api_endpoint(
            "https://lk.example.com/internal/trusttunnel/v1/nodes/{externalNodeId}/artifacts",
            "node-1",
        )
        .unwrap();
        assert_eq!(
            endpoint,
            "https://lk.example.com/internal/trusttunnel/v1/nodes/node-1/artifacts"
        );
    }

    async fn run_single_request_server(
        status: u16,
        body: &str,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.to_string();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0_u8; 8192];
            let size = stream.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..size]).to_string();
            let response = format!(
                "HTTP/1.1 {} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                status,
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            request
        });
        (
            format!("http://{addr}/internal/trusttunnel/v1/nodes/node-1/artifacts"),
            handle,
        )
    }

    #[tokio::test]
    async fn api_write_route_accepts_valid_payload() {
        let (endpoint, request_handle) = run_single_request_server(
            200,
            r#"{"summary":{"created":1,"updated":0,"unchanged":0,"deactivated":0,"failed":0}}"#,
        )
        .await;
        let writer =
            LkBulkWriter::from_contract(LkWriteContract::Api, &endpoint, "node-1", None).unwrap();
        let result = writer
            .write_batch(vec![test_record("alice")])
            .await
            .unwrap();
        assert_eq!(result.created, 1);

        let request = request_handle.await.unwrap();
        assert!(request.contains("POST /internal/trusttunnel/v1/nodes/node-1/artifacts"));
        assert!(request.contains("\"contract_version\":\"v1\""));
        assert!(request.contains("\"external_node_id\":\"node-1\""));
        assert!(request.contains("\"import_batch_id\":\""));
        assert!(request.contains("\"request_id\":\""));
        assert!(request.contains("\"idempotency_key\":\""));
        assert!(request.contains("\"artifacts\":["));
    }

    #[tokio::test]
    async fn api_write_route_returns_contract_error_without_import_batch_id() {
        let (endpoint, request_handle) = run_single_request_server(
            400,
            r#"{"error":"invalid_input","details":"missing import_batch_id"}"#,
        )
        .await;
        let writer =
            LkBulkWriter::from_contract(LkWriteContract::Api, &endpoint, "node-1", None).unwrap();
        let err = writer
            .write_batch(vec![test_record("alice")])
            .await
            .unwrap_err();
        assert!(err.contains("HTTP 400"));
        assert!(err.contains("invalid_input"));
        assert!(err.contains("request_id="));
        assert!(err.contains("import_batch_id="));
        assert!(err.contains("idempotency_key="));
        let request = request_handle.await.unwrap();
        assert!(request.contains("\"import_batch_id\":\""));
    }

    #[tokio::test]
    async fn api_write_route_is_idempotent_for_repeated_payload() {
        let (endpoint_first, request_first) = run_single_request_server(
            200,
            r#"{"summary":{"created":1,"updated":0,"unchanged":0,"deactivated":0,"failed":0}}"#,
        )
        .await;
        let first =
            LkBulkWriter::from_contract(LkWriteContract::Api, &endpoint_first, "node-1", None)
                .unwrap();
        let first_result = first.write_batch(vec![test_record("alice")]).await.unwrap();
        assert_eq!(first_result.created, 1);
        let _ = request_first.await.unwrap();

        let (endpoint_second, request_second) = run_single_request_server(
            200,
            r#"{"summary":{"created":0,"updated":0,"unchanged":1,"deactivated":0,"failed":0}}"#,
        )
        .await;
        let second =
            LkBulkWriter::from_contract(LkWriteContract::Api, &endpoint_second, "node-1", None)
                .unwrap();
        let second_result = second
            .write_batch(vec![test_record("alice")])
            .await
            .unwrap();
        assert_eq!(second_result.unchanged, 1);
        let _ = request_second.await.unwrap();
    }

    #[tokio::test]
    async fn api_write_route_reports_predictable_errors() {
        let (invalid_endpoint, _) = run_single_request_server(
            422,
            r#"{"errors":[{"message":"artifact[0].link must be tt://"}]}"#,
        )
        .await;
        let invalid_writer =
            LkBulkWriter::from_contract(LkWriteContract::Api, &invalid_endpoint, "node-1", None)
                .unwrap();
        let invalid_error = invalid_writer
            .write_batch(vec![test_record("alice")])
            .await
            .unwrap_err();
        assert!(invalid_error.contains("HTTP 422"));
        assert!(invalid_error.contains("payload_top_level_keys="));
        assert!(invalid_error.contains("first_artifact_keys="));

        let (not_found_endpoint, _) =
            run_single_request_server(404, r#"{"error":"node not found or credential not found"}"#)
                .await;
        let not_found_writer =
            LkBulkWriter::from_contract(LkWriteContract::Api, &not_found_endpoint, "node-1", None)
                .unwrap();
        let not_found_error = not_found_writer
            .write_batch(vec![test_record("alice")])
            .await
            .unwrap_err();
        assert!(not_found_error.contains("endpoint not found"));
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
