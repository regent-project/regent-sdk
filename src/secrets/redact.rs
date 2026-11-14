//! Redaction of secret values in what a run shows (logs, live view, outcome details).
//!
//! Every secret resolved during a run goes through the host's [`SecretCache`]; a
//! [`Redactor`] built on that cache replaces each of those values by [`REDACTED`],
//! as well as each line of a multi-line secret (e.g. a private key), since output is
//! often handled line by line.
//!
//! Limit: a value the command transforms (e.g. the base64 of a secret) is not caught.

use crate::hosts::managed_host::InternalApiCallOutcome;
use crate::secrets::SecretCache;

/// What replaces a secret value.
pub const REDACTED: &str = "********";

/// Redacts the secrets of one run (cheap to clone: shares the run's cache).
#[derive(Clone, Default)]
pub(crate) struct Redactor {
    cache: Option<SecretCache>,
}

impl Redactor {
    pub(crate) fn new(cache: Option<SecretCache>) -> Self {
        Self { cache }
    }

    /// The secrets resolved so far. Take a new one after resolving more secrets.
    pub(crate) async fn snapshot(&self) -> Redaction {
        let Some(cache) = &self.cache else {
            return Redaction::default();
        };
        let mut values = Vec::new();
        for value in cache.values().await {
            if value.contains('\n') {
                for line in value.split('\n') {
                    let line = line.trim_end_matches('\r');
                    if !line.trim().is_empty() {
                        values.push(line.to_string());
                    }
                }
            }
            if !value.is_empty() {
                values.push(value);
            }
        }
        // longest first, so that a secret containing another one is fully hidden
        values.sort_by_key(|value| std::cmp::Reverse(value.len()));
        values.dedup();
        Redaction { values }
    }
}

/// A set of secret values to hide.
#[derive(Clone, Default, Debug)]
pub(crate) struct Redaction {
    values: Vec<String>,
}

impl Redaction {
    #[cfg(test)]
    pub(crate) fn of(values: &[&str]) -> Self {
        let mut values: Vec<String> = values.iter().map(|value| value.to_string()).collect();
        values.sort_by_key(|value| std::cmp::Reverse(value.len()));
        Self { values }
    }

    /// `text` with every secret value replaced by [`REDACTED`].
    pub(crate) fn apply(&self, text: &str) -> String {
        let mut text = text.to_string();
        for secret in &self.values {
            if text.contains(secret.as_str()) {
                text = text.replace(secret.as_str(), REDACTED);
            }
        }
        text
    }

    /// The `Debug` form of `value`, redacted (for logs).
    pub(crate) fn debug(&self, value: &impl std::fmt::Debug) -> String {
        self.apply(&format!("{value:?}"))
    }

    /// The outcome with its details (often the command's output) redacted.
    pub(crate) fn outcome(&self, outcome: InternalApiCallOutcome) -> InternalApiCallOutcome {
        match outcome {
            InternalApiCallOutcome::Success(details) => {
                InternalApiCallOutcome::Success(details.map(|details| self.apply(&details)))
            }
            InternalApiCallOutcome::Failure(details) => {
                InternalApiCallOutcome::Failure(self.apply(&details))
            }
            InternalApiCallOutcome::AllowedFailure(details) => {
                InternalApiCallOutcome::AllowedFailure(self.apply(&details))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_first() {
        let redaction = Redaction::of(&["abc", "abcdef"]);
        assert_eq!(redaction.apply("x abcdef abc"), "x ******** ********");
    }

    #[tokio::test]
    async fn multi_line_secrets_are_hidden_line_by_line() {
        let cache = SecretCache::new();
        cache
            .insert(
                "key".into(),
                "-----BEGIN-----\nAAAA\n-----END-----\n".into(),
            )
            .await;
        let redaction = Redactor::new(Some(cache)).snapshot().await;
        assert_eq!(redaction.apply("line: AAAA"), "line: ********");
    }

    #[test]
    fn outcome_details() {
        let redaction = Redaction::of(&["pw"]);
        assert!(matches!(
            redaction.outcome(InternalApiCallOutcome::Failure("pw rejected".into())),
            InternalApiCallOutcome::Failure(details) if details == "******** rejected"
        ));
    }
}
