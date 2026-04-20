# Development Log

## 2026-04-20

### Task

- Completed runtime audit hardening for `classic_agent` to eliminate ambiguity
  between source state and deployed binary behavior.

### Findings

- Runtime/source mismatch incidents are difficult to diagnose when startup logs
  do not include immutable build identity fields.
- LK artifacts POST diagnostics previously did not provide explicit
  `import_batch_id_contains_request_id` signal.
- CI image workflows produced `latest` in addition to immutable tags, but did
  not fail when immutable tags were missing and did not print digests
  consistently.

### Changes made

- Added startup runtime build diagnostics in `classic_agent`:
  - `git_sha`
  - `build_timestamp`
  - `cargo_pkg_version`
  - `batch_id_format_version=v2_node_idempotency_request`
  - `binary_path`
  - `rust_target_triple`
- Added build-time timestamp injection for tools crate via `tools/build.rs`.
- Added per-request LK artifacts POST diagnostics line
  `phase=lk_artifacts_post_diagnostics` with:
  `external_node_id`, `request_id`, `idempotency_key`, `import_batch_id`,
  `import_batch_id_contains_request_id`, `payload_revision`,
  `artifacts_count`.
- Added hard runtime format validation:
  if `import_batch_id` does not end with `:{request_id}`, writer emits
  `phase=lk_api_payload_invalid` with
  `reason=unexpected_batch_id_format_runtime` and fails before POST.
- Added unit tests for:
  - presence of request-id suffix in `import_batch_id`;
  - fail-fast behavior for legacy batch-id format.
- Updated Docker classic-agent build stage to pass build provenance values into
  compile-time env.
- Updated GitHub image workflows:
  - add run-unique immutable tag (`run-<run_id>-<run_attempt>`);
  - pass classic-agent build args (`BUILD_GIT_SHA`, `BUILD_TIMESTAMP`);
  - enforce immutable non-`latest` tag presence;
  - print pushed image digests in workflow logs.
- Expanded `tools/classic_agent/README.md` with runtime audit and deployment
  checklist (including digest pinning and rollout restart requirement).
- Added a changelog entry for runtime diagnostics and batch-id fail-fast.

### Validation notes

- Use pod startup logs (`phase=classic_agent_build_diagnostics`) to map running
  pod to exact Git commit and binary build metadata.
- Use per-POST diagnostics (`phase=lk_artifacts_post_diagnostics`) to confirm
  each export cycle has fresh request id and fresh import batch id.
- Treat `phase=lk_api_payload_invalid` as release blocker for deployment until
  image/provenance mismatch is resolved.

## 2026-04-12

### Task

- Verified and fixed container image build configuration for repository Docker targets.

### Findings

- `make docker/build-endpoint-image` currently fails in this environment because Docker CLI is not installed.
- In `Dockerfile`, the endpoint image stage used `COPY --chmod=755 /docker-entrypoint.sh /scripts/`.
- The source path used a leading slash, which is outside Docker build context semantics and can break image builds.

### Changes made

- Updated Dockerfile copy instruction to use a context-relative source path:
  `COPY --chmod=755 docker-entrypoint.sh /scripts/`.
- Added a changelog entry under `1.0.28` describing the Docker build fix.

### Validation notes

- Could not run Docker image builds locally due to missing Docker binary in the execution environment.
- Ran repository-required lint and test commands after the change to ensure workspace integrity.
