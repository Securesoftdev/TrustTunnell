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

Current exporter contract expects a file with required fields:

- `node_external_id`
- `server_address`
- `cert_domain`
- `protocol` (`http2` or `http3`)

Optional fields:

- `custom_sni`
- `display_name`
- `dns_servers` (string array)

Example:

```toml
node_external_id = "node-a"
server_address = "edge.example.com:443"
cert_domain = "edge.example.com"
protocol = "http2"
custom_sni = "sni.example.com"
display_name = "Main node"
dns_servers = ["1.1.1.1", "8.8.8.8"]
```

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
  and can be enabled with `TRUSTTUNNEL_DEBUG_VERBOSE_EXPORT_LOGS=1`.
- TT-link normalization diagnostics:
  `phase=export_tt_link_stdout_normalized` is emitted when endpoint stdout
  includes extra non-empty lines in addition to the canonical `tt://` deeplink.
  This indicates helper text/URLs were discarded to keep LK payloads limited
  to a clean single-line deeplink.
- Prometheus endpoint: `GET /metrics` on `AGENT_METRICS_ADDRESS`.
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
