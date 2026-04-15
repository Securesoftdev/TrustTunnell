use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub(crate) struct RuntimeWorkspace {
    root: PathBuf,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ArtifactKind {
    CandidateCredentials,
    CandidateConfig,
}

impl ArtifactKind {
    fn slug(self) -> &'static str {
        match self {
            Self::CandidateCredentials => "candidate",
            Self::CandidateConfig => "candidate-config",
        }
    }
}

impl RuntimeWorkspace {
    pub(crate) fn new(root: PathBuf, _debug_preserve_temp_files: bool) -> Self {
        Self { root }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn inventory_state_path(&self) -> PathBuf {
        self.root.join("credentials_inventory_state.json")
    }

    pub(crate) fn make_temp_path(&self, kind: ArtifactKind, stem_hint: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|x| x.as_nanos())
            .unwrap_or_default();
        let pid = std::process::id();
        self.root.join(format!(
            ".{stem}.{kind}.{pid}.{nonce}.tmp",
            stem = sanitize_hint(stem_hint),
            kind = kind.slug(),
        ))
    }
}

fn sanitize_hint(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "artifact".to_string();
    }
    trimmed
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_paths_are_in_runtime_workspace() {
        let workspace = RuntimeWorkspace::new(PathBuf::from("/tmp/runtime"), false);

        let path = workspace.make_temp_path(ArtifactKind::CandidateCredentials, "credentials.toml");
        let parent = path.parent().unwrap();

        assert_eq!(parent, Path::new("/tmp/runtime"));
        assert!(path
            .file_name()
            .and_then(|x| x.to_str())
            .unwrap()
            .contains("candidate"));
    }
}
