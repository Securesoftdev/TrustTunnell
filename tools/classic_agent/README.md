# Classic Agent modes

`classic_agent` now treats LK HTTP orchestration as legacy behavior.

## Default mode (`db_worker`)

Default mode is selected when `CLASSIC_AGENT_MODE` is unset or set to `db_worker`.
In this mode the agent does not run legacy LK orchestration loops and does not emit legacy runtime-health/sync-report outbox metrics.

## Legacy mode (`legacy_http`)

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
