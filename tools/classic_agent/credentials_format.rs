use toml_edit::{Document, Item};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ParsedCredential {
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) max_http2_conns: Option<u32>,
    pub(crate) max_http3_conns: Option<u32>,
}

pub(crate) fn parse_client_credentials(
    raw: &str,
    source_name: &str,
) -> Result<Vec<ParsedCredential>, String> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }

    let parsed = raw
        .parse::<Document>()
        .map_err(|e| format!("failed to parse {source_name} TOML: {e}"))?;
    let clients = parsed
        .get("client")
        .and_then(Item::as_array_of_tables)
        .ok_or_else(|| format!("{source_name} TOML does not contain [[client]] entries"))?;

    clients
        .iter()
        .enumerate()
        .map(|(index, client)| {
            let username = client
                .get("username")
                .and_then(Item::as_str)
                .map(str::trim)
                .unwrap_or("");
            let password = client
                .get("password")
                .and_then(Item::as_str)
                .map(str::trim)
                .unwrap_or("");
            if username.is_empty() {
                return Err(format!("Client #{}: username cannot be empty", index + 1));
            }
            if password.is_empty() {
                return Err(format!("Client #{}: password cannot be empty", index + 1));
            }

            let max_http2_conns = client
                .get("max_http2_conns")
                .and_then(Item::as_integer)
                .and_then(|v| u32::try_from(v).ok());
            let max_http3_conns = client
                .get("max_http3_conns")
                .and_then(Item::as_integer)
                .and_then(|v| u32::try_from(v).ok());

            Ok(ParsedCredential {
                username: username.to_string(),
                password: password.to_string(),
                max_http2_conns,
                max_http3_conns,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clients_and_optional_limits() {
        let raw = r#"
[[client]]
username = "alice"
password = "secret"
max_http2_conns = 42
max_http3_conns = 2
"#;

        let parsed = parse_client_credentials(raw, "credentials").unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].username, "alice");
        assert_eq!(parsed[0].password, "secret");
        assert_eq!(parsed[0].max_http2_conns, Some(42));
        assert_eq!(parsed[0].max_http3_conns, Some(2));
    }

    #[test]
    fn rejects_empty_required_fields() {
        let raw = r#"
[[client]]
username = ""
password = "secret"
"#;

        let err = parse_client_credentials(raw, "credentials").unwrap_err();
        assert!(err.contains("Client #1: username cannot be empty"));
    }
}
