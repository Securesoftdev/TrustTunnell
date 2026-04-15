use serde::Deserialize;
use std::path::Path;
use trusttunnel_deeplink::Protocol as DeepLinkProtocol;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LinkGenerationConfig {
    node_external_id: String,
    server_address: String,
    cert_domain: String,
    #[serde(default)]
    custom_sni: Option<String>,
    #[serde(default = "default_protocol", deserialize_with = "deserialize_protocol")]
    protocol: DeepLinkProtocol,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    dns_servers: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct LinkConfigDiagnostics {
    pub(crate) path: String,
    pub(crate) file_exists: bool,
    pub(crate) file_parsed: bool,
    pub(crate) hash: Option<String>,
    pub(crate) recognized_protocol: Option<String>,
    pub(crate) recognized_server_address: Option<String>,
    pub(crate) fallback_used: bool,
}

impl LinkGenerationConfig {
    pub(crate) fn load_from_file(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read link generation config {}: {e}", path.display()))?;
        let parsed = toml::from_str::<Self>(&raw).map_err(|e| {
            format!(
                "failed to parse link generation config {} as TOML: {e}",
                path.display()
            )
        })?;
        parsed.validate()?;
        Ok(parsed)
    }

    pub(crate) fn load_from_file_or_legacy_env(
        path: &Path,
        node_external_id: &str,
    ) -> Result<Self, String> {
        Self::load_with_diagnostics(path, node_external_id).map(|(cfg, _)| cfg)
    }

    pub(crate) fn load_with_diagnostics(
        path: &Path,
        node_external_id: &str,
    ) -> Result<(Self, LinkConfigDiagnostics), String> {
        let mut diagnostics = LinkConfigDiagnostics {
            path: path.display().to_string(),
            file_exists: path.exists(),
            ..LinkConfigDiagnostics::default()
        };
        match Self::load_from_file(path) {
            Ok(cfg) => {
                diagnostics.file_parsed = true;
                diagnostics.hash = Some(cfg.config_hash());
                diagnostics.recognized_protocol = Some(cfg.protocol().to_string());
                diagnostics.recognized_server_address = Some(cfg.server_address().to_string());
                Ok((cfg, diagnostics))
            }
            Err(file_err) => {
                let fallback_allowed = optional_env_nonempty("TRUSTTUNNEL_LINK_CONFIG_ALLOW_LEGACY_FALLBACK")
                    .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
                    .unwrap_or(false);
                if !fallback_allowed {
                    return Err(format!(
                        "{file_err}; file-based link config is required at {} (set TRUSTTUNNEL_LINK_CONFIG_ALLOW_LEGACY_FALLBACK=true to allow legacy env fallback)",
                        path.display()
                    ));
                }
                let Some(legacy) = Self::load_from_legacy_env(node_external_id)? else {
                    return Err(format!(
                        "{file_err}; expected TOML shape: node_external_id=\"...\", server_address=\"host:port\", cert_domain=\"...\", protocol=\"http2|http3\""
                    ));
                };
                println!(
                    "link generation config file unavailable, using legacy TT link env variables"
                );
                diagnostics.fallback_used = true;
                diagnostics.hash = Some(legacy.config_hash());
                diagnostics.recognized_protocol = Some(legacy.protocol().to_string());
                diagnostics.recognized_server_address = Some(legacy.server_address().to_string());
                Ok((legacy, diagnostics))
            }
        }
    }

    fn load_from_legacy_env(node_external_id: &str) -> Result<Option<Self>, String> {
        let Some(host) = optional_env_nonempty("TRUSTTUNNEL_TT_LINK_HOST") else {
            return Ok(None);
        };
        let port = optional_env_nonempty("TRUSTTUNNEL_TT_LINK_PORT")
            .and_then(|raw| raw.parse::<u16>().ok())
            .unwrap_or(443);
        let protocol = optional_env_nonempty("TRUSTTUNNEL_TT_LINK_PROTOCOL")
            .map(|raw| parse_protocol(&raw))
            .transpose()?
            .unwrap_or_else(default_protocol);
        let custom_sni = optional_env_nonempty("TRUSTTUNNEL_TT_LINK_CUSTOM_SNI");
        let display_name = optional_env_nonempty("TRUSTTUNNEL_TT_LINK_DISPLAY_NAME");
        let cert_domain = optional_env_nonempty("TRUSTTUNNEL_TT_LINK_CERT_DOMAIN")
            .unwrap_or_else(|| host.trim().to_string());
        let dns_servers = optional_env_nonempty("TRUSTTUNNEL_TT_LINK_DNS_SERVERS")
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let cfg = Self {
            node_external_id: node_external_id.trim().to_string(),
            server_address: format!("{}:{}", host.trim(), port),
            cert_domain,
            custom_sni,
            protocol,
            display_name,
            dns_servers,
        };
        cfg.validate()?;
        Ok(Some(cfg))
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.node_external_id.trim().is_empty() {
            return Err("link generation config validation failed: node_external_id is empty".to_string());
        }
        if self.server_address.trim().is_empty() {
            return Err("link generation config validation failed: server_address is empty".to_string());
        }
        if self.cert_domain.trim().is_empty() {
            return Err("link generation config validation failed: cert_domain is empty".to_string());
        }
        if self
            .dns_servers
            .iter()
            .any(|server| server.trim().is_empty())
        {
            return Err(
                "link generation config validation failed: dns_servers contains empty value"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub(crate) fn config_hash(&self) -> String {
        let canonical = CanonicalLinkGenerationConfig {
            node_external_id: self.node_external_id().to_string(),
            server_address: self.server_address().to_string(),
            cert_domain: self.cert_domain().to_string(),
            custom_sni: self.custom_sni(),
            protocol: self.protocol.to_string(),
            display_name: self.display_name(),
            dns_servers: self.dns_servers(),
        };
        let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
        let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
        hex::encode(digest.as_ref())
    }

    pub(crate) fn node_external_id(&self) -> &str {
        self.node_external_id.trim()
    }

    pub(crate) fn server_address(&self) -> &str {
        self.server_address.trim()
    }

    pub(crate) fn cert_domain(&self) -> &str {
        self.cert_domain.trim()
    }

    pub(crate) fn custom_sni(&self) -> Option<String> {
        self.custom_sni
            .as_deref()
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(ToString::to_string)
    }

    pub(crate) fn protocol(&self) -> DeepLinkProtocol {
        self.protocol
    }

    pub(crate) fn display_name(&self) -> Option<String> {
        self.display_name
            .as_deref()
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(ToString::to_string)
    }

    pub(crate) fn dns_servers(&self) -> Vec<String> {
        self.dns_servers
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect()
    }
}

#[derive(serde::Serialize)]
struct CanonicalLinkGenerationConfig {
    node_external_id: String,
    server_address: String,
    cert_domain: String,
    custom_sni: Option<String>,
    protocol: String,
    display_name: Option<String>,
    dns_servers: Vec<String>,
}

fn default_protocol() -> DeepLinkProtocol {
    DeepLinkProtocol::Http2
}

fn deserialize_protocol<'de, D>(deserializer: D) -> Result<DeepLinkProtocol, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    parse_protocol(&raw).map_err(serde::de::Error::custom)
}

fn parse_protocol(raw: &str) -> Result<DeepLinkProtocol, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "http2" => Ok(DeepLinkProtocol::Http2),
        "http3" => Ok(DeepLinkProtocol::Http3),
        other => Err(format!(
            "link generation config protocol must be either http2 or http3, got: {other}"
        )),
    }
}

fn optional_env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_validates_config_toml() {
        let raw = r#"
node_external_id = "node-a"
server_address = "89.110.100.165:443"
cert_domain = "cdn.securesoft.dev"
custom_sni = "sni.securesoft.dev"
protocol = "http3"
display_name = "My VPN"
dns_servers = ["8.8.8.8", "1.1.1.1"]
"#;
        let cfg = toml::from_str::<LinkGenerationConfig>(raw).unwrap();

        assert_eq!(cfg.node_external_id(), "node-a");
        assert_eq!(cfg.server_address(), "89.110.100.165:443");
        assert_eq!(cfg.cert_domain(), "cdn.securesoft.dev");
        assert_eq!(cfg.custom_sni(), Some("sni.securesoft.dev".to_string()));
        assert_eq!(cfg.protocol(), DeepLinkProtocol::Http3);
        assert_eq!(cfg.display_name(), Some("My VPN".to_string()));
        assert_eq!(cfg.dns_servers(), vec!["8.8.8.8", "1.1.1.1"]);
    }

    #[test]
    fn rejects_invalid_config_values() {
        let invalid_server_address = toml::from_str::<LinkGenerationConfig>(
            r#"
node_external_id = "node-a"
server_address = "   "
cert_domain = "cdn.securesoft.dev"
protocol = "http2"
"#,
        )
        .unwrap();
        let invalid_protocol = toml::from_str::<LinkGenerationConfig>(
            r#"
node_external_id = "node-a"
server_address = "edge.example.com:443"
cert_domain = "cdn.securesoft.dev"
protocol = "quic"
"#,
        );

        assert!(invalid_server_address.validate().is_err());
        assert!(invalid_protocol.is_err());
    }

    #[test]
    fn hash_is_stable_for_equivalent_configs() {
        let first = toml::from_str::<LinkGenerationConfig>(
            r#"
node_external_id = " node-a "
server_address = " 89.110.100.165:443 "
cert_domain = " cdn.securesoft.dev "
custom_sni = " sni.securesoft.dev "
protocol = "http2"
display_name = " Link Name "
dns_servers = [" 8.8.8.8 ", "1.1.1.1"]
"#,
        )
        .unwrap();
        let second = toml::from_str::<LinkGenerationConfig>(
            r#"
node_external_id = "node-a"
server_address = "89.110.100.165:443"
cert_domain = "cdn.securesoft.dev"
custom_sni = "sni.securesoft.dev"
protocol = "http2"
display_name = "Link Name"
dns_servers = ["8.8.8.8", "1.1.1.1"]
"#,
        )
        .unwrap();

        assert_eq!(first.config_hash(), second.config_hash());
    }

    #[test]
    fn loads_legacy_env_when_file_not_used() {
        std::env::set_var("TRUSTTUNNEL_TT_LINK_HOST", "legacy.example.com");
        std::env::set_var("TRUSTTUNNEL_TT_LINK_PORT", "8443");
        std::env::set_var("TRUSTTUNNEL_TT_LINK_PROTOCOL", "http3");
        std::env::set_var("TRUSTTUNNEL_TT_LINK_CUSTOM_SNI", "sni.example.com");
        std::env::set_var("TRUSTTUNNEL_TT_LINK_DNS_SERVERS", "8.8.8.8,1.1.1.1");

        let cfg = LinkGenerationConfig::load_from_legacy_env("node-a")
            .unwrap()
            .unwrap();

        assert_eq!(cfg.node_external_id(), "node-a");
        assert_eq!(cfg.server_address(), "legacy.example.com:8443");
        assert_eq!(cfg.cert_domain(), "legacy.example.com");
        assert_eq!(cfg.custom_sni(), Some("sni.example.com".to_string()));
        assert_eq!(cfg.protocol(), DeepLinkProtocol::Http3);
        assert_eq!(cfg.dns_servers(), vec!["8.8.8.8", "1.1.1.1"]);

        std::env::remove_var("TRUSTTUNNEL_TT_LINK_HOST");
        std::env::remove_var("TRUSTTUNNEL_TT_LINK_PORT");
        std::env::remove_var("TRUSTTUNNEL_TT_LINK_PROTOCOL");
        std::env::remove_var("TRUSTTUNNEL_TT_LINK_CUSTOM_SNI");
        std::env::remove_var("TRUSTTUNNEL_TT_LINK_DNS_SERVERS");
    }

    #[test]
    fn missing_file_error_describes_expected_shape() {
        std::env::remove_var("TRUSTTUNNEL_LINK_CONFIG_ALLOW_LEGACY_FALLBACK");
        std::env::remove_var("TRUSTTUNNEL_TT_LINK_HOST");
        let path = std::env::temp_dir().join("missing-link-config.toml");
        let err = LinkGenerationConfig::load_from_file_or_legacy_env(&path, "node-a").unwrap_err();
        assert!(err.contains("file-based link config is required"));
    }

    #[test]
    fn load_with_diagnostics_reports_parsed_file_and_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tt-link.toml");
        std::fs::write(
            &path,
            r#"
node_external_id = "node-a"
server_address = "edge.example.com:443"
cert_domain = "edge.example.com"
protocol = "http2"
"#,
        )
        .unwrap();

        let (cfg, diagnostics) =
            LinkGenerationConfig::load_with_diagnostics(&path, "node-a").unwrap();
        assert_eq!(cfg.server_address(), "edge.example.com:443");
        assert!(diagnostics.file_exists);
        assert!(diagnostics.file_parsed);
        assert!(!diagnostics.fallback_used);
        assert!(diagnostics.hash.is_some());
    }
}
