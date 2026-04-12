# Development Log

## 2026-04-12

- Fixed a Rust borrow checker error (`E0502`) in `tools/classic_agent/main.rs` in
  `sync_once`.
- Root cause: `node` was borrowed as `&str` from `self.cfg.node_external_id` and
  then `self` was mutably borrowed across `await` calls (`send_sync_report`),
  while `node` was still used later in metrics/logging.
- Resolution: clone `self.cfg.node_external_id` into an owned `String` at the
  beginning of `sync_once` and pass `&node` where needed.
- Result: immutable borrow from `self` no longer spans mutable borrows across
  `await`, so the Docker build step that compiles `classic_agent` can proceed.
