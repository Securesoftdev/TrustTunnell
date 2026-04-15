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
2. `reconcile_apply_runtime_state`
3. `candidate_credentials_write`
4. `candidate_credentials_syntax_validation`
5. `temp_endpoint_config_render`
6. `endpoint_runtime_validation`
7. `export_readiness_check`
8. `inventory_snapshot_load_and_state_load`
9. `inventory_delta_missing_stale_removed`
10. `tt_link_export`
11. `lk_bulk_write`
12. `post_write_state_persist`

All candidate/debug/state artifacts are written under `TRUSTTUNNEL_RUNTIME_DIR` via runtime workspace helpers.

Validation policy for candidate credentials:

- `candidate_credentials_syntax_validation` is a diagnostic precheck (`syntax_precheck`) and
  does not decide accept/reject on its own.
- Canonical validation route is `endpoint_runtime_validation`, which executes the
  endpoint-compatible startup path (`trusttunnel_endpoint ... --client_config ...`).
- Candidate acceptance is determined by successful `runtime_entrypoint` validation.

### 1) Startup bootstrap pass

Executed once on startup:

- imports bootstrap credentials from `TRUSTTUNNEL_BOOTSTRAP_CREDENTIALS_FILE` only when
  runtime credentials do not exist and runtime has not been marked primary;
- runs sidecar sync with pass label `bootstrap`;
- validates/promotes credentials atomically, applies runtime, and marks runtime primary.

### 2) Periodic reconcile pass

Executed every `AGENT_RECONCILE_INTERVAL_SEC`:

- compares desired and runtime credentials;
- computes counters (`found/generated/updated/missing/skipped/errors` and
  `new/stale/deleted`);
- applies only the detected delta;
- syncs inventory to LK via bulk upsert/deactivate.

## Runtime modes

### Default mode (`db_worker`)

Default mode is selected when `CLASSIC_AGENT_MODE` is unset or set to `db_worker`.
In this mode sidecar sync and LK bulk writer run without legacy LK HTTP orchestration loops.

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
- `NODE_EXTERNAL_ID`
- `NODE_HOSTNAME`
- `AGENT_RECONCILE_INTERVAL_SEC`
- `AGENT_APPLY_INTERVAL_SEC`
- `TRUSTTUNNEL_RUNTIME_DIR`
- `TRUSTTUNNEL_RUNTIME_CREDENTIALS_FILE`
- `TRUSTTUNNEL_LINK_CONFIG_FILE`
- `TRUSTTUNNEL_CONFIG_FILE`
- `TRUSTTUNNEL_HOSTS_FILE`

Required only in `legacy_http`:

- `LK_BASE_URL`
- `LK_SERVICE_TOKEN`
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
- `LK_DB_TABLE` (Postgres sink table name, default `access_artifacts`)
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

## Observability

- Structured logs are JSON and include: `ts`, `level`, `revision`, `node`,
  `status`, `error_class` (and `message` for errors).
- Sidecar sync summary lines expose counters:
  `found/generated/updated/missing/skipped/errors` and `new/stale/deleted`.
- Prometheus endpoint: `GET /metrics` on `AGENT_METRICS_ADDRESS`.
- Metrics:
  - `classic_agent_reconcile_total{node,revision,status,error_class}`
  - `classic_agent_apply_total{node,revision,status,error_class}`
  - `classic_agent_sidecar_sync_pass_total{node,pass,status}`
  - `classic_agent_sidecar_sync_item_total{node,pass,outcome}`
  - `classic_agent_tt_link_generation_total{node,revision,status,error_class}`
  - `classic_agent_last_successful_reconcile_timestamp_seconds{node}`
  - `classic_agent_last_failed_reconcile_timestamp_seconds{node}`
  - `classic_agent_apply_duration_milliseconds{node}`
  - `classic_agent_credentials_count{node}`

## Bulk upsert idempotency and stale policy

- Sidecar writes only delta: `missing + stale` as active upserts, `removed` as
  deactivations.
- Postgres writer uses conflict upsert by `dedupe_key`, making repeated equal
  batches idempotent.
- API writer relies on LK bulk endpoint contract for the same idempotent semantics.
- Stale detection includes password hash changes and export config hash changes.
- Export config hash includes `address`, `domain`, `port`, `sni`, `dns`, and
  `protocol`; changing address/domain/port marks links stale and forces
  regeneration/update.
