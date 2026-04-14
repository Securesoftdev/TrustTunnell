use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use trusttunnel_deeplink::Protocol as DeepLinkProtocol;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LinkGenerationConfig {
    #[serde(alias = "host")]
    server: String,
    port: Option<u16>,
    #[serde(default)]
    custom_sni: Option<String>,
    #[serde(default = "default_protocol", deserialize_with = "deserialize_protocol")]
    protocol: DeepLinkProtocol,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    additional_deeplink_params: BTreeMap<String, String>,
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

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.server.trim().is_empty() {
            return Err("link generation config validation failed: server/host is empty".to_string());
        }
        Ok(())
    }

    pub(crate) fn config_hash(&self) -> String {
        let canonical = CanonicalLinkGenerationConfig {
            server: self.server.trim(),
            port: self.port.unwrap_or(443),
            custom_sni: self.custom_sni.as_deref().map(str::trim).filter(|x| !x.is_empty()),
            protocol: self.protocol.to_string(),
            display_name: self
                .display_name
                .as_deref()
                .map(str::trim)
                .filter(|x| !x.is_empty()),
            additional_deeplink_params: self.additional_deeplink_params.clone(),
        };
        let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
        let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
        hex::encode(digest.as_ref())
    }

    pub(crate) fn server(&self) -> &str {
        self.server.trim()
    }

    pub(crate) fn port_or(&self, default_port: u16) -> u16 {
        self.port.unwrap_or(default_port)
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
}

#[derive(serde::Serialize)]
struct CanonicalLinkGenerationConfig<'a> {
    server: &'a str,
    port: u16,
    custom_sni: Option<&'a str>,
    protocol: String,
    display_name: Option<&'a str>,
    additional_deeplink_params: BTreeMap<String, String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_validates_config_toml() {
        let raw = r#"
host = "edge.example.com"
port = 8443
custom_sni = "sni.example.com"
protocol = "http3"
display_name = "My VPN"

[additional_deeplink_params]
region = "eu"
env = "prod"
"#;
        let cfg = toml::from_str::<LinkGenerationConfig>(raw).unwrap();

        assert_eq!(cfg.server(), "edge.example.com");
        assert_eq!(cfg.port_or(443), 8443);
        assert_eq!(cfg.custom_sni(), Some("sni.example.com".to_string()));
        assert_eq!(cfg.protocol(), DeepLinkProtocol::Http3);
        assert_eq!(cfg.display_name(), Some("My VPN".to_string()));
        assert_eq!(
            cfg.additional_deeplink_params.get("region"),
            Some(&"eu".to_string())
        );
    }

    #[test]
    fn rejects_invalid_config_values() {
        let invalid_host = toml::from_str::<LinkGenerationConfig>(
            r#"
server = "   "
protocol = "http2"
"#,
        )
        .unwrap();
        let invalid_protocol = toml::from_str::<LinkGenerationConfig>(
            r#"
server = "edge.example.com"
protocol = "quic"
"#,
        );

        assert!(invalid_host.validate().is_err());
        assert!(invalid_protocol.is_err());
    }

    #[test]
    fn hash_is_stable_for_equivalent_configs() {
        let first = toml::from_str::<LinkGenerationConfig>(
            r#"
host = " edge.example.com "
port = 443
custom_sni = " sni.example.com "
protocol = "http2"
display_name = " Link Name "

[additional_deeplink_params]
b = "2"
a = "1"
"#,
        )
        .unwrap();
        let second = toml::from_str::<LinkGenerationConfig>(
            r#"
server = "edge.example.com"
protocol = "http2"
display_name = "Link Name"
custom_sni = "sni.example.com"
port = 443

[additional_deeplink_params]
a = "1"
b = "2"
"#,
        )
        .unwrap();

        assert_eq!(first.config_hash(), second.config_hash());
    }
}
