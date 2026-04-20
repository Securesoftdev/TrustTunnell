<!-- markdownlint-disable MD012 MD013 -->

# TT-Link Export Contract

This document defines the TrustTunnell-side responsibilities for producing
`tt://` deep links that LK can store and clients can actually use.

The LK-side ingestion and UI responsibilities are documented in
`Securesoftdev/SecureLink-` under
`docs/15_TRUSTTUNNEL_LINK_EXPORT_AND_CAPACITY_CONTRACT.md`.

## Source Of Truth

- The endpoint binary is the only component allowed to generate the final
  `tt://` value.
- The classic agent owns link export orchestration, validation, logging, and
  delivery to LK.
- LK owns storage, admin visibility, user-facing delivery, and assignment
  capacity decisions.

## Canonical Link Config

New link configuration must use this normalized shape:

```toml
node_external_id = "node-a"
address_host = "edge.example.com"
port = 443
protocol = "http2"
custom_sni = ""
cert_domain = "edge.example.com"
display_name = "SecureSoft node A"
dns_servers = ["1.1.1.1", "8.8.8.8"]
```

IP endpoint with domain TLS routing:

```toml
node_external_id = "tt-worker2"
address_host = "89.110.100.165"
port = 443
protocol = "http2"
custom_sni = "edge.example.com"
cert_domain = "edge.example.com"
display_name = "tt-worker2"
dns_servers = ["1.1.1.1", "8.8.8.8"]
```

Field semantics:

| Field | Required | Meaning |
| --- | --- | --- |
| `node_external_id` | yes | LK external node id. |
| `address_host` | yes | Host placed into exported client config addresses. Prefer public domain when the endpoint has a public domain certificate. |
| `port` | yes | Public endpoint port. |
| `protocol` | yes | `http2` or `http3`. |
| `custom_sni` | conditional | TLS SNI override. Required when `address_host` is an IP. |
| `cert_domain` | conditional | Certificate verification domain. Required when `address_host` is an IP. |
| `display_name` | no | User-facing server name. |
| `dns_servers` | no | DNS upstreams embedded into the client config. |

Current `server_address = "host:port"` file configs are a legacy alias for
`address_host + port`. New configs and docs must use the normalized fields.

## Hard Export Rule

If the endpoint is reachable by a public domain and uses a TLS certificate for
that domain, export the deep-link with the domain as `address_host`.

IP exports are allowed only when both of these fields are explicitly present:

- `custom_sni`
- `cert_domain`

The exporter must reject an IP-based export when either field is empty. Such an
export is invalid because the client can import the link but fail TLS validation
or route/SNI selection during real connection.

## Runtime Validation Before LK Delivery

Before POSTing artifacts or sync-report account exports to LK, the agent must
validate every generated link metadata set.

Validation result values:

| Result | Meaning |
| --- | --- |
| `valid` | Link metadata can be sent to LK as successful export. |
| `invalid_ip_without_sni_or_cert_domain` | `address_host` is IP and at least one of `custom_sni` or `cert_domain` is empty. |
| `invalid_missing_address_host` | Export host is empty. |
| `invalid_missing_port` | Export port is missing or invalid. |
| `invalid_protocol` | Protocol is not `http2` or `http3`. |

Invalid exports must not be reported to LK as success. The agent should log the
validation failure and mark reconcile/export as failed or partial-failed instead
of sending an unusable `tt://` link.

## Export Logs

Every per-user export log must include:

| Field | Meaning |
| --- | --- |
| `username` | Credential username exported. |
| `exported_address_host` | Final host used in client addresses. |
| `exported_port` | Final port used in client addresses. |
| `exported_custom_sni` | Final SNI override, empty when absent. |
| `exported_cert_domain` | Final certificate domain, empty when absent. |
| `used_fallback_config` | `true` when legacy env fallback supplied link config. |
| `link_validation_result` | One validation result from this document. |

Recommended phase name:

```text
phase=link_generation_exported
```

## LK Payload Metadata

When an export is valid, delivery to LK must include metadata alongside the
`tt://` value:

| Field | Meaning |
| --- | --- |
| `host` | Same value as `address_host`. |
| `port` | Exported port. |
| `protocol` | Export protocol. |
| `custom_sni` | Exported custom SNI or empty/null. |
| `cert_domain` | Exported cert domain. |
| `generated_at` | Export timestamp. |
| `source` | `sidecar`, `sidecar_legacy_env`, or another explicit source. |
| `validation_result` | `valid` for accepted links. |
