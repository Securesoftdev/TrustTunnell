<!-- markdownlint-disable MD041 -->
<p align="center">
<picture>
<source media="(prefers-color-scheme: dark)" srcset="https://cdn.adguardcdn.com/website/github.com/TrustTunnel/logo_dark.svg" width="300px" alt="TrustTunnel" />
<img src="https://cdn.adguardcdn.com/website/github.com/TrustTunnel/logo_light.svg" width="300px" alt="TrustTunnel" />
</picture>
</p>

<p align="center"><a href="https://github.com/TrustTunnel/TrustTunnelClient">Console client</a>
  · <a href="https://github.com/TrustTunnel/TrustTunnelFlutterClient">Flutter-based app</a>
  · <a href="https://agrd.io/ios_trusttunnel">App store</a>
  · <a href="https://agrd.io/android_trusttunnel">Play store</a>
</p>

---

## Table of Contents

- [Introduction](#introduction)
- [Server Features](#server-features)
- [Client Features](#client-features)
- [Quick start](#quick-start)
    - [Endpoint setup](#endpoint-setup)
        - [Install the endpoint](#install-the-endpoint)
        - [Updating the endpoint](#updating-the-endpoint)
        - [TrustTunnel Flutter Client 1.0 Warning](#trusttunnel-flutter-client-10-warning)
        - [Endpoint configuration wizard](#endpoint-configuration-wizard)
        - [Let's Encrypt certificate lifecycle](#lets-encrypt-certificate-lifecycle)
        - [Running endpoint](#running-endpoint)
        - [Export client configuration](#export-client-configuration)
    - [Client setup](#client-setup)
        - [Install the client](#install-the-client)
        - [Updating the client](#updating-the-client)
        - [Client configuration wizard](#client-configuration-wizard)
        - [Running client](#running-client)
- [See also](#see-also)
- [Roadmap](#roadmap)
- [License](#license)

---

## Introduction

TrustTunnel is a modern, open-source VPN protocol originally developed by
[AdGuard VPN][adguard-vpn] and now available for anyone to use and audit.

It delivers fast, secure, and reliable VPN connections without the usual trade-offs.
By design, TrustTunnel traffic is indistinguishable from regular HTTPS traffic,
allowing it to bypass throttling and deep-packet inspection while maintaining
strong privacy protections.

The TrustTunnel project includes the VPN endpoint (this repository), the
[library and CLI for the client][trusttunnel-client],
and the [GUI application][trusttunnel-flutter-client].

[adguard-vpn]: https://adguard-vpn.com
[trusttunnel-client]: https://github.com/TrustTunnel/TrustTunnelClient
[trusttunnel-flutter-client]: https://github.com/TrustTunnel/TrustTunnelFlutterClient
[app-store]: https://agrd.io/ios_trusttunnel
[play-store]: https://agrd.io/android_trusttunnel

## Server Features

- **VPN Protocol**: The library implements the VPN protocol compatible
  with HTTP/1.1, HTTP/2, and QUIC. By mimicking regular network traffic, it
  becomes impossible to detect and block.

- **Flexible Traffic Tunneling**: TrustTunnel can tunnel TCP, UDP, and ICMP
  traffic to and from the client.

- **Platform Compatibility**: The server is compatible with Linux and macOS.
  The client is available for Android, Apple, Windows, and Linux.

---

## Client Features

- **Traffic Tunneling**: The library is capable of tunneling TCP, UDP, and ICMP
  traffic from the client to the endpoint and back.

- **Cross-Platform Support**: It supports Linux, macOS, and Windows platforms,
  providing a consistent experience across different operating systems.

- **System-Wide Tunnel and SOCKS5 Proxy**: It can be set up as a system-wide
  tunnel, utilizing a virtual network interface, as well as a SOCKS5 proxy.

- **Split Tunneling**: The library supports split tunneling, allowing users to
  exclude connections to certain domains or hosts from routing through the VPN
  endpoint, or vice versa, only routing connections to specific domains or hosts
  through the endpoint based on an exclusion list.

- **Custom DNS Upstream**: Users can specify a custom DNS upstream, which is
  used for DNS queries routed through the VPN endpoint.

---

## Quick start

### Endpoint setup

#### Install the endpoint

An installation script is available that can be run with the following command:

```bash
curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnel/refs/heads/master/scripts/install.sh | sh -s -
```

The installation script will download the prebuilt package from the latest
GitHub release for the appropriate system architecture and unpack it to
`/opt/trusttunnel`. The output directory could be overridden by specifying
`-o DIR` flag at the end of the command above.

If you want to install a specific version (instead of the latest), use `-V <version>`:

```bash
curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnel/refs/heads/master/scripts/install.sh | sh -s - -V <version>
```

> [!NOTE]
> Prebuilt packages are available for `linux-x86_64`, `linux-aarch64`, and
> `macos-universal` (Intel and Apple Silicon) architectures.

#### Updating the endpoint

The installation script always installs the latest available version.
So, to update your installation, run the install command again:

```bash
curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnel/refs/heads/master/scripts/install.sh | sh -s -
```

This re-runs the installer and replaces the binaries in the installation
directory (`/opt/trusttunnel` by default, or the directory you specified with `-o DIR`).

> [!NOTE]
> Don't forget to stop the endpoint before updating:
>
> ```bash
> sudo systemctl stop trusttunnel
> ```
>
> To start the endpoint again after updating:
>
> ```bash
> sudo systemctl start trusttunnel
> ```

#### TrustTunnel Flutter Client 1.0 Warning

> [!WARNING]
> TrustTunnel Flutter Client **doesn't support** self-signed certificates **yet**.
> If you want to use the TrustTunnel Flutter Client, you should have a valid
> certificate issued by a publicly trusted Certificate Authority (CA) associated
> with a registered domain for the IP address of the endpoint. Otherwise,
> the TrustTunnel Flutter Client will be unable to connect to the endpoint.

#### Endpoint configuration wizard

Please refer to the [CONFIGURATION.md](CONFIGURATION.md) for the more detailed
documentation on how to configure the endpoint.

The installation directory contains `setup_wizard` binary that helps generate
the config files required for the endpoint to run:

```bash
cd /opt/trusttunnel/
./setup_wizard -h
```

The setup wizard supports interactive mode, so you could run it and it will ask
for data required for endpoint configuration.

```bash
cd /opt/trusttunnel/
sudo ./setup_wizard
```

> [!NOTE]
> `sudo` is required to manage TLS certificates properly.

The wizard will ask for the following fields, some of them have the default
values you could safely use:

- **The address to listen on** - specify the address for the endpoint to listen
  on. Use `0.0.0.0:443` for native deployments (HTTPS on all interfaces).
  If you run with Docker port mapping `443:8443`, set it to `0.0.0.0:8443`.
- **Path to credentials file** - path where the user credentials for
  authorization will be stored.
- **Username** - the username the user will use for authorization.
- **Password** - the user's password.
- **Add one more user?** - select `yes` if you want to add more users, or `no`
  to continue the configuration process.
- **Path to the rules file** - path to store the filtering rules.
- **Connection filtering rules** - you can add rules that the endpoint will use
  to allow or disallow user's connections based on:
    - Client IP address
    - TLS random prefix
    - TLS random with mask

  Press `n` to allow all connections.
- **Path to a file to store the library settings** - path to store the main
  endpoint configuration file.
- **Certificate selection** - choose how to obtain a TLS certificate:
    - **Issue a Let's Encrypt certificate** (requires a public domain) - the
      setup wizard has built-in ACME support and can automatically obtain a free,
      publicly trusted certificate from Let's Encrypt. You'll need:
        - A registered domain pointing to your server's IP address
        - Port 80 accessible from the internet (for HTTP-01 challenge), or
        - Ability to add DNS TXT records (for DNS-01 challenge)
    - **Generate a self-signed certificate** - suitable for testing or when using
      the CLI client only. Note: The Flutter client does not support self-signed
      certificates **yet**.
    - **Provide path to existing certificate** - use your own certificate files
      obtained from another CA or tool like [certbot][certbot].
- **Path to a file to store the TLS hosts settings** - path to store the TLS host settings file.

At this point all required configuration files are created and saved on disk.

[certbot]: https://eff-certbot.readthedocs.io/en/stable/

#### Let's Encrypt certificate lifecycle

The setup wizard can obtain a Let's Encrypt certificate during initial setup, but you are responsible for ensuring it stays valid over time (renewal and service reload/restart).

If you're using Certbot to manage certificates and renew them automatically, follow the guide in [CERT_RENEWAL.md](CERT_RENEWAL.md).

#### Running endpoint

The installed package contains the systemd service template, named
`trusttunnel.service.template`.

This template can be used to set up the endpoint as a systemd service:

> [!NOTE]
> The template file assumes that the TrustTunnel Endpoint binary and all its
> configuration files are located in `/opt/trusttunnel` and have the default
> file names. Modify the template if you have used the different paths.

```bash
cd /opt/trusttunnel/
cp trusttunnel.service.template /etc/systemd/system/trusttunnel.service
sudo systemctl daemon-reload
sudo systemctl enable --now trusttunnel
```

#### Export client configuration

The endpoint binary can generate client configurations in two formats:

##### Deep-Link Format (Default)

Generate a compact `tt://?` URI suitable for QR codes and mobile apps:

```shell
# <client_name> - name of the client those credentials will be included in the configuration
# <address> - `ip`, `ip:port`, `domain`, or `domain:port` that the client will use to connect
#           If only `ip` or `domain` is specified, the port from the `listen_address` field will be used
cd /opt/trusttunnel/
./trusttunnel_endpoint vpn.toml hosts.toml -c <client_name> -a <address>

# Or explicitly specify the format:
./trusttunnel_endpoint vpn.toml hosts.toml -c <client_name> -a <address> --format deeplink
```

This outputs a `tt://?` deep-link URI that can be:

- Shared directly with mobile clients
- Used with the [CLI client][trusttunnel-client] or [TrustTunnel Flutter Client][trusttunnel-flutter-client]

You can also provide additional options:

- `--name <display_name>`: Set a custom display name for the server in the client app.
- `--dns-upstream <dns_upstream>`: Specify a DNS upstream for the client. Can be an IP address
  or a secure DNS URI (e.g., `tls://1.1.1.1`, `https://dns.google/dns-query`).
  This flag can be used multiple times to provide a list of DNS upstreams.
- `--output json`: Return machine-readable JSON payload (without QR hints
  or extra text). By default, the endpoint uses human-friendly output.

Example with custom name and DNS upstreams:

```shell
./trusttunnel_endpoint vpn.toml hosts.toml -c <client_name> -a <address> \
    --name "My Secure VPN" \
    --dns-upstream 1.1.1.1 --dns-upstream tls://8.8.8.8
```

When `--generate-client-random-prefix` is used, the endpoint also appends an
allow rule for the generated value to the `rules.toml` file referenced from
`vpn.toml`.

**Note**: If your certificate is signed by a trusted CA (e.g., Let's Encrypt), it will be
automatically omitted from the deep-link to keep it compact. Self-signed
certificates are included automatically.

##### TOML Format (For CLI Client)

Generate a traditional TOML configuration file:

```shell
cd /opt/trusttunnel/
./trusttunnel_endpoint vpn.toml hosts.toml -c <client_name> -a <public_ip> --format toml
```

This outputs a TOML configuration file suitable for the CLI client.

Both formats contain all necessary information to connect to the endpoint. See the
[TrustTunnel Flutter Client documentation][trusttunnel-flutter-configuration] for setup instructions.

##### JSON export schema (`--output json`)

Use `--output json` together with `-c/--client_config` to get a stable payload.

```shell
./trusttunnel_endpoint vpn.toml hosts.toml -c <client_name> -a <address> \
    --format deeplink --output json
```

JSON schema:

- `client_name` (`string`)
- `artifact_format` (`"deeplink"` | `"toml"`)
- `deeplink` (`string | null`) - present for `artifact_format = "deeplink"`
- `toml` (`string | null`) - present for `artifact_format = "toml"`
- `addresses` (`string[]`)
- `hostname` (`string`)
- `custom_sni` (`string | null`)
- `dns_upstreams` (`string[]`)
- `config_fingerprint` (`string`) - SHA-256 hash of generated TOML payload
- `generated_at` (`string`) - RFC3339 UTC timestamp

Example payload:

```json
{
  "client_name": "alice",
  "artifact_format": "deeplink",
  "deeplink": "tt://?...",
  "toml": null,
  "addresses": ["vpn.example.com:443"],
  "hostname": "vpn.example.com",
  "custom_sni": null,
  "dns_upstreams": ["1.1.1.1", "tls://8.8.8.8"],
  "config_fingerprint": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "generated_at": "2026-04-15T10:30:00+00:00"
}
```

Congratulations! You've done setting up the endpoint!

[trusttunnel-flutter-configuration]: https://github.com/TrustTunnel/TrustTunnelFlutterClient/blob/master/README.md#server-configuration

### Client setup

You have a choice to use a [CLI client][trusttunnel-client] or a
[GUI client][trusttunnel-flutter-client] (available on [App Store][app-store]
and [Play Store][play-store]).

#### Install the client

##### Linux / macOS

An installation script is available:

```bash
curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnelClient/refs/heads/master/scripts/install.sh | sh -s -
```

The installation script will download the prebuilt package from the latest GitHub release for the appropriate system architecture and unpack it to `/opt/trusttunnel_client`. The output directory could be overridden by specifying `-o DIR` flag at the end of the command above.

> [!NOTE]
> Install script supports x86_64, aarch64, armv7, mips and mipsel architectures
> for linux and arm64 and x86_64 for macos.

##### Windows

Download the latest release archive from the
[TrustTunnel Client releases page][trusttunnel-client-releases].

Extract the archive to a directory of your choice, for example `C:\TrustTunnel\`.

[trusttunnel-client-releases]: https://github.com/TrustTunnel/TrustTunnelClient/releases/latest

##### Router setup

For router deployments, please refer to router-specific client installation
guides.

- Keenetic routers: [TrustTunnel-Keenetic](https://github.com/artemevsevev/TrustTunnel-Keenetic)
  (guide in Russian)

#### Updating the client

##### Linux / macOS

The installation script always installs the latest available version.
So, to update your installation, run the install command again:

```bash
curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnelClient/refs/heads/master/scripts/install.sh | sh -s -
```

This re-runs the installer and replaces the binaries in the installation directory (`/opt/trusttunnel_client` by default, or the directory you specified with `-o DIR`).

> [!NOTE]
> Don't forget to stop the client before updating (for example, by stopping the running process).

##### Windows

Download the latest release from the
[releases page][trusttunnel-client-releases] and replace the files
in your installation directory.

#### Client configuration wizard

The installation directory contains `setup_wizard` binary that helps generate
the config files required for the client to run.

##### Linux / macOS

```bash
cd /opt/trusttunnel_client/
./setup_wizard -h
```

To configure the client to use the config that was generated by endpoint, run
the following command:

```bash
./setup_wizard --mode non-interactive \
     --endpoint_config <endpoint_config> \
     --settings trusttunnel_client.toml
```

##### Windows

```cmd
setup_wizard.exe --mode non-interactive ^
    --endpoint_config <endpoint_config> ^
    --settings trusttunnel_client.toml
```

In both cases, `<endpoint_config>` is the path to the configuration file
generated by the endpoint.

`trusttunnel_client.toml` will contain all required configuration for the
client.

> [!TIP]
> The generated configuration contains basic settings to connect to the endpoint.
> For advanced features, edit `trusttunnel_client.toml` directly. You can configure:
>
> - **VPN mode**: Route all traffic (`general`) or only specific destinations (`selective`)
> - **Kill switch**: Block traffic when VPN disconnects
> - **DNS upstreams**: Custom DNS resolvers (DoH, DoT, DoQ supported)
> - **Exclusions**: Domains/IPs to bypass or route through VPN
> - **Listener type**: TUN device or SOCKS5 proxy
>
> See the [TrustTunnel CLI Client README](https://github.com/TrustTunnel/TrustTunnelClient/blob/master/trusttunnel/README.md#configuration-reference) for all available options.

<!-- markdownlint-disable MD028 -->
> [!NOTE]
> After editing the config, restart the client for the changes to take effect.

#### Running client

##### Linux / macOS

```bash
cd /opt/trusttunnel_client/
sudo ./trusttunnel_client -c trusttunnel_client.toml
```

`sudo` is required to set up the routes and tun interface.

##### Windows

Open a terminal **as Administrator** and run:

```cmd
trusttunnel_client.exe -c trusttunnel_client.toml
```

Administrator privileges are required to set up routes and the TUN interface.

## See Also

- [CONFIGURATION.md](CONFIGURATION.md) - Configuration documentation
- [DEVELOPMENT.md](DEVELOPMENT.md) - Development documentation
- [PROTOCOL.md](PROTOCOL.md) - Protocol specification
- [CHANGELOG.md](CHANGELOG.md) - Changelog
- [VERIFY_RELEASES.md](VERIFY_RELEASES.md) - How to verify releases

## Roadmap

While our VPN currently supports tunneling TCP/UDP/ICMP traffic, we plan to add support for
peer-to-peer communication between clients.

Stay tuned for this feature in upcoming releases.

## License

This project is licensed under the Apache 2.0 License. See [LICENSE](LICENSE) for details.

## Production container image targets

Repository Docker build has two production targets:

- Endpoint image target: `trusttunnel-endpoint`
- Classic agent image target: `trusttunnel-classic-agent`

GitHub Actions image workflows:

- `.github/workflows/build-images.yml` builds and publishes both production images and is intentionally manual (`workflow_dispatch`). Use this workflow when endpoint-related changes must be built and published together with the sidecar image.
- `.github/workflows/build-classic-agent-image.yml` builds and publishes only the classic agent sidecar image. Use this workflow for sidecar-only changes and for regular pull request validation of sidecar image builds.

Build commands:

```sh
docker build --target trusttunnel-endpoint -t trusttunnel-endpoint:local .
docker build --target trusttunnel-classic-agent -t trusttunnel-classic-agent:local .
```

Example classic agent run:

```sh
docker run --rm \
  -e LK_BASE_URL="https://lk.example.com" \
  -e LK_SERVICE_TOKEN="<service-token>" \
  -e NODE_EXTERNAL_ID="node-1" \
  -e NODE_HOSTNAME="trusttunnel-node-1" \
  -e NODE_STAGE="prod" \
  -e NODE_CLUSTER="vpn" \
  -e NODE_NAMESPACE="default" \
  -e NODE_ROLLOUT_GROUP="stable" \
  -e AGENT_POLL_INTERVAL_SEC="15" \
  -e AGENT_HEARTBEAT_INTERVAL_SEC="30" \
  -e TRUSTTUNNEL_RUNTIME_DIR="/var/lib/trusttunnel" \
  -e TRUSTTUNNEL_CREDENTIALS_FILE="credentials.toml" \
  -e TRUSTTUNNEL_CONFIG_FILE="vpn.toml" \
  -e TRUSTTUNNEL_HOSTS_FILE="hosts.toml" \
  -v "$(pwd)/runtime:/var/lib/trusttunnel" \
  trusttunnel-classic-agent:local
```

Classic agent required environment variables:

- `LK_BASE_URL`
- `LK_SERVICE_TOKEN`
- `NODE_EXTERNAL_ID`
- `NODE_HOSTNAME`
- `NODE_STAGE`
- `NODE_CLUSTER`
- `NODE_NAMESPACE`
- `NODE_ROLLOUT_GROUP`
- `AGENT_POLL_INTERVAL_SEC`
- `AGENT_HEARTBEAT_INTERVAL_SEC`
- `TRUSTTUNNEL_RUNTIME_DIR`
- `TRUSTTUNNEL_CREDENTIALS_FILE`
- `TRUSTTUNNEL_CONFIG_FILE`
- `TRUSTTUNNEL_HOSTS_FILE`

Classic agent optional environment variables:

- `NODE_PUBLIC_HOST`
- `NODE_PUBLIC_PORT`
- `NODE_DISPLAY_NAME`
- `AGENT_STATE_PATH` (default `agent_state.json`)
- `TRUSTTUNNEL_APPLY_CMD` (command executed after runtime credentials update)
- `TRUSTTUNNEL_BOOTSTRAP_CREDENTIALS_FILE` (read-only bootstrap credentials source to import once into `TRUSTTUNNEL_RUNTIME_DIR/<TRUSTTUNNEL_CREDENTIALS_FILE>`)
- `LK_SNAPSHOT_PATH` (default `/internal/vpn/classic/accounts`)
- `LK_SYNC_REPORT_PATH` (default `/internal/vpn/classic/sync-report`)
- `LK_HEARTBEAT_PATH` (default `/internal/vpn/classic/heartbeat`)
- `AGENT_METRICS_ADDRESS` (default `127.0.0.1:9901`, Prometheus endpoint exposed as `GET /metrics`)

Classic agent runtime credentials migration and restart recovery:

- On startup, if `TRUSTTUNNEL_BOOTSTRAP_CREDENTIALS_FILE` is set, runtime credentials file is absent, and runtime has not yet been marked as primary, the agent imports bootstrap credentials once into `TRUSTTUNNEL_RUNTIME_DIR`.
- After the first successful `sync` + apply cycle, the agent creates a marker file `.runtime_credentials_primary` in `TRUSTTUNNEL_RUNTIME_DIR` and treats runtime credentials as the source of truth.
- After this marker exists, restarts do not re-import credentials from the bootstrap source (for example, from a read-only ConfigMap mount), so runtime no longer depends on that source as the primary store.
- If runtime credentials are lost after migration, restart does not restore them from bootstrap; the next successful LK sync recreates runtime credentials and reapplies runtime configuration.

Classic agent sidecar observability:

- Structured logs are emitted in JSON with normalized fields: `revision`, `node`, `status`, and `error_class`.
- Internal Prometheus endpoint is exposed on `AGENT_METRICS_ADDRESS` via `GET /metrics`.
- Sidecar metrics include:
  - `classic_agent_last_successful_sync_timestamp_seconds`
  - `classic_agent_last_failed_sync_timestamp_seconds`
  - `classic_agent_apply_duration_milliseconds`
  - `classic_agent_credentials_count`
  - `classic_agent_heartbeat_status`
  - `classic_agent_endpoint_process_status`
  - Operation counters with labels `revision/node/status/error_class`:
    - `classic_agent_sync_total`
    - `classic_agent_apply_total`
    - `classic_agent_heartbeat_total`
