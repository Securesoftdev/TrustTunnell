use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let build_timestamp = std::env::var("TRUSTTUNNEL_BUILD_TIMESTAMP").unwrap_or_else(|_| {
        let unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("unix:{unix_seconds}")
    });

    println!("cargo:rustc-env=TRUSTTUNNEL_BUILD_TIMESTAMP={build_timestamp}");
}
