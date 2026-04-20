# Classic Agent modes and sidecar responsibilities

`classic_agent` treats LK HTTP orchestration as legacy behavior and defaults to
inventory-driven sidecar synchronization.

## Architecture rule

- Endpoint (`trusttunnel_endpoint`) is the data plane.
- Sidecar (`classic_agent`) is responsible for link inventory and sync.
- `tt://` links are generated only via the endpoint export command
  (`trusttunnel_endpoint ... --format deeplink`), never by sidecar-side URI construction.

## Sidecar modes

## Classic sidecar pipeline phases

`classic_agent` executes these stages in strict order for each sync cycle:

1. `bootstrap_credentials_import` (startup-only, guarded by runtime primary marker)
2. `reconcile_plan_runtime_state` (every `AGENT_RECONCILE_INTERVAL_SEC`)
3. `candidate_credentials_write` (on apply tick, only for changed plan)
4. `candidate_credentials_syntax_validation` (on apply tick, only for changed plan)
5. `temp_endpoint_config_render` (on apply tick, only for changed plan)
6. `endpoint_runtime_validation` (on apply tick, only for changed plan)
7. `apply_runtime_state` (on apply tick, only for changed plan)
8. `export_readiness_check` (every `AGENT_APPLY_INTERVAL_SEC`)
9. `inventory_snapshot_load_and_state_load` (every `AGENT_APPLY_INTERVAL_SEC`)
10. `inventory_delta_missing_stale_removed` (every `AGENT_APPLY_INTERVAL_SEC`)
11. `tt_link_export` (every `AGENT_APPLY_INTERVAL_SEC`)
12. `lk_bulk_write` (every `AGENT_APPLY_INTERVAL_SEC`)
13. `post_write_state_persist` (every `AGENT_APPLY_INTERVAL_SEC`)

All candidate/debug/state artifacts are written under `TRUSTTUNNEL_RUNTIME_DIR` via runtime workspace helpers.

Validation policy for candidate credentials:

- `candidate_credentials_syntax_validation` is fail-fast by default and blocks
  apply/export/write if candidate TOML is invalid.
- Optional debug mode:
  `TRUSTTUNNEL_CANDIDATE_SYNTAX_DIAGNOSTIC_ONLY=true` keeps syntax validation
  diagnostic-only and allows runtime validation to continue.
- Canonical credentials shape is `[[client]]` array-of-tables with string
  `username` and `password` in every entry.
- Canonical validation route is `endpoint_runtime_validation`, which executes the
  endpoint-compatible startup path (`trusttunnel_endpoint ... --client_config ...`).
- Candidate acceptance is determined by successful `runtime_entrypoint` validation.

### 1) Startup bootstrap pass

Executed once on startup:

- imports bootstrap credentials from `TRUSTTUNNEL_BOOTSTRAP_CREDENTIALS_FILE` only when
  runtime credentials do not exist and runtime has not been marked primary;
- runs sidecar sync with pass label `bootstrap`;
- validates/promotes credentials atomically, applies runtime, and marks runtime primary.

### 2) Periodic reconcile plan phase

Executed every `AGENT_RECONCILE_INTERVAL_SEC`:

- compares desired and runtime credentials;
- computes counters (`found/generated/updated/missing/skipped/errors` and
  `new/stale/deleted`).

### 3) Periodic apply and export/write phase

Executed every `AGENT_APPLY_INTERVAL_SEC`:

- applies the latest prepared reconcile plan when changes were detected;
- runs inventory export and LK bulk upsert/deactivate.

## Runtime modes

### Default mode (`db_worker`)

Default mode is selected when `CLASSIC_AGENT_MODE` is unset or set to `db_worker`.
In this mode sidecar sync and LK bulk writer run without legacy LK HTTP orchestration loops.
`db_worker` writes only access artifacts (TT-link payloads and active/deactivated records) through
`lk_bulk_write` contracts. Lifecycle writes (`register` + periodic `heartbeat`) are enabled in
`db_worker` and use lifecycle base URL derivation:

1. `LK_LIFECYCLE_BASE_URL` (preferred)
2. `LK_BASE_URL`
3. Derived from `LK_DB_DSN` when it is an HTTP(S) artifacts endpoint URL

`sync-report` remains part of the `legacy_http` flow only.

### Legacy mode (`legacy_http`)

The following functionality is temporarily kept under `tools/classic_agent/legacy/`:

- LK API client (`legacy/lk_api.rs`)
- register bootstrap flow
- heartbeat loop
- sync-report sending with outbox retry

To enable it explicitly:

1. Build with legacy feature:
   - `cargo build -p trusttunnel_endpoint_tools --bin classic_agent --features legacy-lk-http`
2. Run with legacy mode enabled:
   - `CLASSIC_AGENT_MODE=legacy_http`

Without `legacy-lk-http`, `CLASSIC_AGENT_MODE=legacy_http` is rejected at startup.

## Environment variables (`Config::from_env()`)

Required in all modes:

- `LK_DB_DSN`
- `LK_WRITE_CONTRACT` (`api`, `pg_function`, or `legacy_table`)
- `NODE_EXTERNAL_ID`
- `NODE_HOSTNAME`
- `AGENT_RECONCILE_INTERVAL_SEC`
- `AGENT_APPLY_INTERVAL_SEC`
- `TRUSTTUNNEL_RUNTIME_DIR`
- `TRUSTTUNNEL_RUNTIME_CREDENTIALS_FILE`
- `TRUSTTUNNEL_LINK_CONFIG_FILE`
- `TRUSTTUNNEL_CONFIG_FILE`
- `TRUSTTUNNEL_HOSTS_FILE`

Required for lifecycle writes (`register` + `heartbeat`) in both `db_worker` and `legacy_http`:

- `LK_SERVICE_TOKEN`
- one of:
  - `LK_LIFECYCLE_BASE_URL` (preferred)
  - `LK_BASE_URL`
  - derivation from `LK_DB_DSN` when it is an HTTP(S) artifacts endpoint URL

Required only in `legacy_http`:

- `AGENT_HEARTBEAT_INTERVAL_SEC`

Optional:

- `CLASSIC_AGENT_MODE` (`db_worker` default)
- `AGENT_STATE_PATH`
- `AGENT_METRICS_ADDRESS`
- `AGENT_METRICS_PUSH_ENABLED` (default `true`)
- `AGENT_METRICS_PUSH_INTERVAL_SEC` (default `30`)
- `AGENT_TELEMETRY_PUSH_ENABLED` (default `true`)
- `AGENT_TELEMETRY_PUSH_INTERVAL_SEC` (default `60`)
- `LK_METRICS_PATH` (default `/internal/trusttunnel/metrics`)
- `LK_TELEMETRY_SNAPSHOTS_PATH` (default `/internal/telemetry/snapshots`)
- `TRUSTTUNNEL_ENDPOINT_METRICS_URL` (optional override for scraping endpoint Prometheus metrics)
- `TRUSTTUNNEL_BOOTSTRAP_CREDENTIALS_FILE`
- `TRUSTTUNNEL_APPLY_CMD`
- `TRUSTTUNNEL_ENDPOINT_BINARY`
- `TRUSTTUNNEL_AGENT_VERSION`
- `TRUSTTUNNEL_RUNTIME_VERSION`
- `TRUSTTUNNEL_VALIDATION_STRICT` (default `false`; logs
  `error_class=parser_runtime_mismatch_strict` when `syntax_precheck` and
  `runtime_entrypoint` results diverge)
- `TRUSTTUNNEL_DEBUG_VERBOSE_EXPORT_LOGS` (default `false`; when enabled,
  emits per-username `phase=link_generation_exported` lines for TT-link export debugging)
- `TRUSTTUNNEL_LINK_CONFIG_ALLOW_LEGACY_FALLBACK` (`true|false`; when `true`,
  allows TT-link export to use legacy env variables if `tt-link.toml` is
  missing/invalid)
- `LK_DB_TABLE` (Postgres sink table name, default `access_artifacts`)
- `LK_DB_WRITE_FUNCTION` (Postgres function contract, default `trusttunnel_apply_access_artifacts`)
- `LK_LIFECYCLE_BASE_URL` (preferred explicit lifecycle API base URL)
- `LK_DB_WRITE_FUNCTION_VERSION_FUNCTION` (Postgres function contract metadata/version function, default `<LK_DB_WRITE_FUNCTION>_contract_version`)
- `LK_DB_WRITE_CONTRACT_VERSION` (expected Postgres function contract version, default `v1`)
- `LK_DB_LEGACY_RAW_TABLE` (must be `1` when `LK_WRITE_CONTRACT=legacy_table`)
- `LK_ALLOW_DEPRECATED_LEGACY_TABLE` (must be `1` to allow deprecated `legacy_table` contract)
- Legacy-only metadata/paths: `NODE_STAGE`, `NODE_CLUSTER`, `NODE_NAMESPACE`,
  `NODE_ROLLOUT_GROUP`, `LK_SYNC_PATH_TEMPLATE`, `LK_SYNC_REPORT_PATH`,
  `TRUSTTUNNEL_RUNTIME_PID_FILE`, `TRUSTTUNNEL_RUNTIME_PROCESS_NAME`

Legacy TT-link env fallback (used only when link config file cannot be loaded):

- `TRUSTTUNNEL_TT_LINK_HOST`
- `TRUSTTUNNEL_TT_LINK_PORT`
- `TRUSTTUNNEL_TT_LINK_PROTOCOL`
- `TRUSTTUNNEL_TT_LINK_CUSTOM_SNI`
- `TRUSTTUNNEL_TT_LINK_DISPLAY_NAME`
- `TRUSTTUNNEL_TT_LINK_CERT_DOMAIN`
- `TRUSTTUNNEL_TT_LINK_DNS_SERVERS`

## `tt-link.toml` contract (file mode)

Canonical exporter behavior is defined in
[`TT_LINK_EXPORT_CONTRACT.md`](TT_LINK_EXPORT_CONTRACT.md). The short form:
new configs should use normalized host/port fields and must produce links that
are both importable and connectable.

Canonical required fields:

- `node_external_id`
- `address_host`
- `port`
- `protocol` (`http2` or `http3`)

Conditional fields:

- `custom_sni`
- `cert_domain`

Optional fields:

- `display_name`
- `dns_servers` (string array)

Example:

```toml
node_external_id = "node-a"
address_host = "89.110.100.165"
port = 443
cert_domain = "edge.example.com"
protocol = "http2"
custom_sni = "edge.example.com"
display_name = "Main node"
dns_servers = ["1.1.1.1", "8.8.8.8"]
```

`server_address = "host:port"` is a legacy alias only. New configs and docs
must use `address_host + port`.

Kubernetes ConfigMap example:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: trusttunnel-link-config
data:
  tt-link.toml: |
    node_external_id = "tt-worker2"
    address_host = "89.110.100.165"
    port = 443
    cert_domain = "edge.example.com"
    protocol = "http2"
    custom_sni = "edge.example.com"
    display_name = "tt-worker2"
    dns_servers = ["1.1.1.1", "8.8.8.8"]
```

Mount the file into `TRUSTTUNNEL_RUNTIME_DIR` or set
`TRUSTTUNNEL_LINK_CONFIG_FILE` to the mounted absolute path.

Hard validation rule:

- if `address_host` is a public DNS name with a matching public TLS certificate,
  export with that DNS name;
- if `address_host` is an IP address, both `custom_sni` and `cert_domain` are
  required;
- an IP export without both TLS routing fields is invalid and must not be sent
  to LK as a successful link export.

Diagnostics include contract mode:

- `contract_mode=file_required` when file mode is enforced;
- `contract_mode=legacy_fallback` when fallback is enabled and env-based route is used.

## Observability

- Structured logs are JSON and include: `ts`, `level`, `revision`, `node`,
  `status`, `error_class` (and `message` for errors).
- Sidecar sync summary lines expose counters:
  `found/generated/updated/missing/skipped/errors` and `new/stale/deleted`.
- TT-link export always emits operational summaries:
  `phase=link_generation_started` and `phase=link_generation_complete`.
  Per-username `phase=link_generation_exported` lines are disabled by default
  and can be enabled with `TRUSTTUNNEL_DEBUG_VERBOSE_EXPORT_LOGS=1`. Export
  lines must include `username`, `exported_address_host`, `exported_port`,
  `exported_custom_sni`, `exported_cert_domain`, `used_fallback_config`, and
  `link_validation_result`.
- TT-link normalization silently discards helper text/URLs from endpoint stdout
  and keeps LK payloads limited to a clean single-line `tt://` deeplink.
- Prometheus endpoint: `GET /metrics` on `AGENT_METRICS_ADDRESS`.
- LK metric delivery: periodic `POST /internal/trusttunnel/metrics` and `POST /internal/telemetry/snapshots`, keyed by `external_node_id`, with optional endpoint Prometheus scraping for active sessions and bandwidth.
- Metrics:
  - `classic_agent_reconcile_total{node,revision,status,error_class}`
  - `classic_agent_apply_total{node,revision,status,error_class}`
  - `classic_agent_sidecar_sync_pass_total{node,pass,status}`
  - `classic_agent_sidecar_sync_item_total{node,pass,outcome}`
  - `classic_agent_tt_link_generation_total{node,revision,status,error_class}`
  - `classic_agent_runtime_health_total{node,revision,status,error_class}`
  - `classic_agent_runtime_health_status{node}`
  - `classic_agent_endpoint_process_status{node}`
  - `classic_agent_last_successful_reconcile_timestamp_seconds{node}`
  - `classic_agent_last_failed_reconcile_timestamp_seconds{node}`
  - `classic_agent_apply_duration_milliseconds{node}`
  - `classic_agent_credentials_count{node}`

## Sidecar development log bookkeeping

For incident reviews and future maintenance, keep a deterministic log trail in runtime output:

- Lifecycle events:
  - `phase=register_sent|register_accepted|heartbeat_sent|heartbeat_accepted`
- Inventory/artifact delivery:
  - `phase=inventory_payload_sent|inventory_payload_accepted|inventory_payload_rejected`
  - `phase=artifacts_payload_sent|artifacts_payload_accepted`
- Reconcile/apply pipeline:
  - `phase=reconcile_summary`
  - `phase=sidecar_sync_apply_success|sidecar_sync_apply_failed`
- Validation diagnostics:
  - `phase=credentials_validation_begin|credentials_validation_ok|credentials_validation_failed`

Use stable fields in each line (`node`, `revision`, `request_id`, `idempotency_key`,
`error_class`) so retries and rollback events can be correlated across runs.

For LK artifact imports, treat `import_batch_id` as an export-cycle identifier:

- A new export cycle must emit a new `import_batch_id` even when payload content is unchanged.
- Retries of the exact same HTTP request must keep the same `import_batch_id` and `idempotency_key`.
- Runtime logs for `phase=lk_api_payload_debug` must include:
  `import_batch_id`, `idempotency_key`, `payload_revision`, and `force_regenerate`.
- Operational actions that start a fresh cycle (`clear`, `hard reset`, `reissue`, forced regeneration)
  must never reuse a previous `import_batch_id`.

### Runtime build and export-cycle audit checklist

Use this checklist when runtime logs do not match current source code:

1. Verify startup build diagnostics from pod logs (`phase=classic_agent_build_diagnostics`):
   - `git_sha`
   - `build_timestamp`
   - `cargo_pkg_version`
   - `batch_id_format_version=v2_node_idempotency_request`
   - `binary_path`
   - `rust_target_triple`
2. Verify each LK artifacts POST diagnostics (`phase=lk_artifacts_post_diagnostics`):
   - `external_node_id`
   - `request_id`
   - `idempotency_key`
   - `import_batch_id`
   - `import_batch_id_contains_request_id`
   - `payload_revision`
   - `artifacts_count`
3. Treat `phase=lk_api_payload_invalid reason=unexpected_batch_id_format_runtime` as hard-fail:
   - request must not be considered successful;
   - investigate runtime image/build mismatch before retries.

Deployment pipeline requirements for deterministic runtime provenance:

- Every build must publish immutable tags (for example `sha-*` or `run-*-*`) in
  addition to optional `latest`.
- Deployment logs must include pushed image digest.
- Runtime deployment should pin image digest (`image@sha256:...`) instead of plain `latest`.
- After updating the deployment image, run explicit rollout restart.
- After rollout, check pod startup logs and confirm `git_sha` matches the expected commit.

## Bulk upsert idempotency and stale policy

- Primary deployment contract is `LK_WRITE_CONTRACT=api`.
- Recommended API settings for current sidecar-to-LK architecture:
  - `LK_WRITE_CONTRACT=api`
  - `LK_DB_DSN=https://<lk-host>/internal/trusttunnel/v1/nodes/{externalNodeId}/artifacts`
  - `LK_SERVICE_TOKEN=<service token>`
- `pg_function` and `legacy_table` are still supported for compatibility/migration only.

- Sidecar writes only delta: `missing + stale` as active upserts, `removed` as
  deactivations.
- Postgres writer uses conflict upsert by `dedupe_key`, making repeated equal
  batches idempotent.
- API writer relies on LK bulk endpoint contract for the same idempotent semantics.
- Stale detection includes password hash changes and export config hash changes.
- Export config hash includes `address`, `domain`, `port`, `sni`, `dns`, and
  `protocol`; changing address/domain/port marks links stale and forces
  regeneration/update.

Canonical LK API write contract (`LK_WRITE_CONTRACT=api`):

- Request payload:
  - top-level: `external_node_id`, `artifacts[]`
  - artifact item: `username` and/or `credential_external_id`, `link`,
    `link_revision`, `is_current`, `generated_at`, `source`, `display_name`,
    optional `source_key`, optional `link_hash`
- Response payload:
  - accepted canonical shape: `summary` object with counters
    (`created`, `updated`, `unchanged`, `deactivated`, `failed`)
  - plus `errors`/`failures` arrays for per-item diagnostics
  - sidecar also accepts legacy flat counter responses for backward compatibility
