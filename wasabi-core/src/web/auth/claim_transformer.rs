//! Claim transformation for JWT tokens.
//!
//! Allows adding or modifying claims after JWT validation, useful for
//! enriching tokens from external identity providers with application-specific claims.

use crate::web::auth::user::ClaimsSet;
use serde_json::Value;

/// Transforms JWT claims by applying a set of rules.
///
/// Rules can set string values, set arrays, or append to existing arrays.
#[derive(Clone, Debug)]
pub struct ClaimTransformer {
    rules: Vec<ClaimRule>,
}

#[derive(Clone, Debug)]
struct ClaimRule {
    claim_name: String,
    operation: ClaimOperation,
}

#[derive(Clone, Debug)]
enum ClaimOperation {
    SetString(String),
    SetArray(Vec<String>),
    AppendArray(Vec<String>),
}

impl ClaimTransformer {
    /// Parses a claim mapping configuration string.
    ///
    /// # Format
    ///
    /// Rules are comma-separated (commas inside brackets are preserved).
    /// Each rule has the format `name=value` or `name+=value`:
    ///
    /// - `tenant=github-ci` - Sets string value
    /// - `permissions=[deploy,read]` - Sets array value
    /// - `permissions+=[admin]` - Appends to existing array (creates if missing)
    ///
    /// # Example
    ///
    /// ```
    /// use wasabi_core::web::auth::claim_transformer::ClaimTransformer;
    ///
    /// let transformer = ClaimTransformer::parse("tenant=ci,permissions=[deploy,read]").unwrap();
    /// ```
    pub fn parse(config: &str) -> anyhow::Result<Self> {
        let config = config.trim();
        if config.is_empty() {
            return Ok(Self { rules: Vec::new() });
        }

        let mut rules = Vec::new();
        let rule_strings = Self::split_rules(config);

        for rule_str in rule_strings {
            let rule_str = rule_str.trim();
            if rule_str.is_empty() {
                continue;
            }

            let rule = Self::parse_rule(rule_str)?;
            rules.push(rule);
        }

        Ok(Self { rules })
    }

    /// Splits config string by commas, but ignores commas inside brackets.
    fn split_rules(config: &str) -> Vec<&str> {
        let mut result = Vec::new();
        let mut start = 0;
        let mut bracket_depth: u32 = 0;

        for (i, c) in config.char_indices() {
            match c {
                '[' => bracket_depth += 1,
                ']' => bracket_depth = bracket_depth.saturating_sub(1),
                ',' if bracket_depth == 0 => {
                    result.push(&config[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
        }

        // Add the last segment
        if start < config.len() {
            result.push(&config[start..]);
        }

        result
    }

    fn parse_rule(rule_str: &str) -> anyhow::Result<ClaimRule> {
        // Check for append operator first
        if let Some((name, value)) = rule_str.split_once("+=") {
            let name = name.trim();
            let value = value.trim();

            if name.is_empty() {
                anyhow::bail!("Invalid claim rule: empty claim name in '{}'", rule_str);
            }

            let array_values = Self::parse_array_value(value)?;
            return Ok(ClaimRule {
                claim_name: name.to_string(),
                operation: ClaimOperation::AppendArray(array_values),
            });
        }

        // Check for set operator
        if let Some((name, value)) = rule_str.split_once('=') {
            let name = name.trim();
            let value = value.trim();

            if name.is_empty() {
                anyhow::bail!("Invalid claim rule: empty claim name in '{}'", rule_str);
            }

            let operation = if value.starts_with('[') && value.ends_with(']') {
                ClaimOperation::SetArray(Self::parse_array_value(value)?)
            } else {
                ClaimOperation::SetString(value.to_string())
            };

            return Ok(ClaimRule {
                claim_name: name.to_string(),
                operation,
            });
        }

        anyhow::bail!(
            "Invalid claim rule format: '{}'. Expected 'name=value' or 'name+=value'",
            rule_str
        )
    }

    fn parse_array_value(value: &str) -> anyhow::Result<Vec<String>> {
        let value = value.trim();

        if !value.starts_with('[') || !value.ends_with(']') {
            anyhow::bail!(
                "Invalid array format: '{}'. Expected '[value1,value2,...]'",
                value
            );
        }

        let inner = &value[1..value.len() - 1];
        let values: Vec<String> = inner
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Ok(values)
    }

    /// Applies all transformation rules to the claims.
    pub fn apply(&self, claims: &mut ClaimsSet) {
        for rule in &self.rules {
            match &rule.operation {
                ClaimOperation::SetString(value) => {
                    let _ = claims.insert(rule.claim_name.clone(), Value::String(value.clone()));
                }
                ClaimOperation::SetArray(values) => {
                    let json_array: Vec<Value> =
                        values.iter().map(|s| Value::String(s.clone())).collect();
                    let _ = claims.insert(rule.claim_name.clone(), Value::Array(json_array));
                }
                ClaimOperation::AppendArray(values) => {
                    let existing = claims.get(&rule.claim_name);

                    let mut array = if let Some(Value::Array(arr)) = existing {
                        arr.clone()
                    } else {
                        Vec::new()
                    };

                    for value in values {
                        array.push(Value::String(value.clone()));
                    }

                    let _ = claims.insert(rule.claim_name.clone(), Value::Array(array));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_string_value() {
        let transformer = ClaimTransformer::parse("tenant=github-ci").unwrap();

        assert_eq!(transformer.rules.len(), 1);
        assert_eq!(transformer.rules[0].claim_name, "tenant");
        assert!(matches!(
            &transformer.rules[0].operation,
            ClaimOperation::SetString(s) if s == "github-ci"
        ));
    }

    #[test]
    fn parse_array_value() {
        let transformer = ClaimTransformer::parse("permissions=[deploy,read]").unwrap();

        assert_eq!(transformer.rules.len(), 1);
        assert_eq!(transformer.rules[0].claim_name, "permissions");
        assert!(matches!(
            &transformer.rules[0].operation,
            ClaimOperation::SetArray(arr) if arr == &vec!["deploy".to_string(), "read".to_string()]
        ));
    }

    #[test]
    fn parse_append_array() {
        let transformer = ClaimTransformer::parse("permissions+=[admin]").unwrap();

        assert_eq!(transformer.rules.len(), 1);
        assert_eq!(transformer.rules[0].claim_name, "permissions");
        assert!(matches!(
            &transformer.rules[0].operation,
            ClaimOperation::AppendArray(arr) if arr == &vec!["admin".to_string()]
        ));
    }

    #[test]
    fn parse_multiple_rules() {
        let transformer =
            ClaimTransformer::parse("tenant=ci,permissions=[deploy,read],roles+=[viewer]").unwrap();

        assert_eq!(transformer.rules.len(), 3);
        assert_eq!(transformer.rules[0].claim_name, "tenant");
        assert_eq!(transformer.rules[1].claim_name, "permissions");
        assert_eq!(transformer.rules[2].claim_name, "roles");
    }

    #[test]
    fn apply_sets_string() {
        let transformer = ClaimTransformer::parse("tenant=github-ci").unwrap();
        let mut claims = ClaimsSet::new();

        transformer.apply(&mut claims);

        assert_eq!(claims.get("tenant"), Some(&json!("github-ci")));
    }

    #[test]
    fn apply_sets_array() {
        let transformer = ClaimTransformer::parse("permissions=[deploy,read]").unwrap();
        let mut claims = ClaimsSet::new();

        transformer.apply(&mut claims);

        assert_eq!(claims.get("permissions"), Some(&json!(["deploy", "read"])));
    }

    #[test]
    fn apply_appends_to_existing_array() {
        let transformer = ClaimTransformer::parse("permissions+=[admin]").unwrap();
        let mut claims = ClaimsSet::new();
        claims.insert("permissions".to_string(), json!(["existing1", "existing2"]));

        transformer.apply(&mut claims);

        assert_eq!(
            claims.get("permissions"),
            Some(&json!(["existing1", "existing2", "admin"]))
        );
    }

    #[test]
    fn apply_appends_creates_array_if_missing() {
        let transformer = ClaimTransformer::parse("permissions+=[admin]").unwrap();
        let mut claims = ClaimsSet::new();

        transformer.apply(&mut claims);

        assert_eq!(claims.get("permissions"), Some(&json!(["admin"])));
    }

    #[test]
    fn parse_invalid_format_fails() {
        let result = ClaimTransformer::parse("invalid-no-equals");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid claim rule format")
        );
    }

    #[test]
    fn parse_empty_claim_name_fails() {
        let result = ClaimTransformer::parse("=value");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty claim name"));
    }

    #[test]
    fn parse_empty_config_succeeds() {
        let transformer = ClaimTransformer::parse("").unwrap();
        assert!(transformer.rules.is_empty());
    }

    #[test]
    fn parse_whitespace_handling() {
        let transformer =
            ClaimTransformer::parse("  tenant = ci , permissions = [a, b]  ").unwrap();

        assert_eq!(transformer.rules.len(), 2);
        assert_eq!(transformer.rules[0].claim_name, "tenant");
        assert_eq!(transformer.rules[1].claim_name, "permissions");
    }
}
