# Development Log

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
