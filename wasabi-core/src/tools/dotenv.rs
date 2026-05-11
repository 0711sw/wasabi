//! `.env` file loading with detection of preset overrides.
//!
//! Loads variables from the nearest `.env` file without overriding values
//! already present in the process environment, and reports which keys were
//! silently ignored because they were preset elsewhere (typical culprit:
//! an IDE run configuration that injects its own values).
//!
//! Call [`load_dotenv`] before initializing the tracing subscriber so that
//! variables such as `RUST_LOG` from `.env` take effect, then call
//! [`DotenvLoadResult::report`] once tracing is up to emit the summary.

use std::io::Read;
use std::path::{Path, PathBuf};

/// Result of [`load_dotenv`], deferring tracing output until after the
/// subscriber has been initialized.
pub struct DotenvLoadResult {
    outcome: Result<PathBuf, dotenvy::Error>,
    overridden_keys: Vec<String>,
}

/// Loads variables from the nearest `.env` file (if present) without
/// overriding values already set in the process environment, and records
/// any keys whose `.env` value differs from the preset one.
pub fn load_dotenv() -> DotenvLoadResult {
    let outcome = dotenvy::dotenv();
    let overridden_keys = match &outcome {
        Ok(path) => collect_overridden_keys(path),
        Err(_) => Vec::new(),
    };
    DotenvLoadResult {
        outcome,
        overridden_keys,
    }
}

impl DotenvLoadResult {
    /// Emits an info line about the load outcome and one warning per
    /// preset key whose `.env` value was ignored. Call after the tracing
    /// subscriber has been initialized.
    pub fn report(&self) {
        match &self.outcome {
            Ok(path) => {
                tracing::info!("Loaded environment variables from: {}", path.display());
            }
            Err(err) => {
                tracing::info!("Skipped loading environment variables from .env: {err}");
            }
        }
        for key in &self.overridden_keys {
            tracing::warn!("Env var {key} was preset outside .env — .env value was ignored");
        }
    }

    /// Path of the loaded `.env` file, if any.
    pub fn loaded_from(&self) -> Option<&Path> {
        self.outcome.as_ref().ok().map(PathBuf::as_path)
    }

    /// Names of variables that were defined in `.env` but were already set
    /// in the process environment with a different value.
    pub fn overridden_keys(&self) -> &[String] {
        &self.overridden_keys
    }
}

fn collect_overridden_keys(path: &Path) -> Vec<String> {
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    overridden_keys_from(std::io::BufReader::new(file), |k| std::env::var(k).ok())
}

fn overridden_keys_from<R, F>(reader: R, env_lookup: F) -> Vec<String>
where
    R: Read,
    F: Fn(&str) -> Option<String>,
{
    let mut overridden = Vec::new();
    for item in dotenvy::Iter::new(reader) {
        let Ok((key, file_value)) = item else {
            continue;
        };
        if let Some(env_value) = env_lookup(&key)
            && env_value != file_value
        {
            overridden.push(key);
        }
    }
    overridden
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Cursor;

    #[test]
    fn detects_keys_with_different_values() {
        let env_file = "FOO=from_env_file\nBAR=also_from_file\nBAZ=match\n";
        let process_env = HashMap::from([
            ("FOO".to_string(), "from_process_env".to_string()),
            ("BAZ".to_string(), "match".to_string()),
        ]);

        let overridden =
            overridden_keys_from(Cursor::new(env_file), |k| process_env.get(k).cloned());

        assert_eq!(overridden, vec!["FOO".to_string()]);
    }

    #[test]
    fn ignores_keys_not_in_process_env() {
        let env_file = "ONLY_IN_FILE=value\n";

        let overridden = overridden_keys_from(Cursor::new(env_file), |_| None);

        assert!(overridden.is_empty());
    }

    #[test]
    fn handles_quoted_values_and_comments() {
        let env_file = "# a comment\nQUOTED=\"with spaces\"\nPLAIN=no_quotes\n";
        let process_env = HashMap::from([
            ("QUOTED".to_string(), "different".to_string()),
            ("PLAIN".to_string(), "no_quotes".to_string()),
        ]);

        let overridden =
            overridden_keys_from(Cursor::new(env_file), |k| process_env.get(k).cloned());

        assert_eq!(overridden, vec!["QUOTED".to_string()]);
    }
}
