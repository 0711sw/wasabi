//! JWT validation with support for multiple issuers and key strategies.
//!
//! The [`Authenticator`] validates JWT tokens using either a shared secret (HMAC)
//! or JWKS endpoints, with per-issuer configuration. Custom claim prefixes can be
//! stripped to normalize claims from different identity providers.

use crate::status_bail;
use crate::web::auth::jwks::{JwksCache, UrlJwksFetcher};
use crate::web::auth::user::ClaimsSet;
use crate::web::auth::{CLAIM_ISS, CLAIM_LOCALE, DEFAULT_LOCALE};
use crate::web::error::ResultExt;
use anyhow::{bail, Context};
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Header, Validation};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use warp::http::StatusCode;

/// Trait for dynamically fetching authenticator config based on JWT claims.
///
/// Implement this to support multi-tenant scenarios where different tenants
/// use different identity providers.
#[async_trait]
pub trait ConfigFetcher: Send + Sync {
    async fn fetch(&self, claims: &ClaimsSet) -> Option<Arc<AuthenticatorConfig>>;
}

/// Validates JWTs and extracts claims.
pub struct Authenticator {
    config: AuthenticatorConfig,
    fetchers: Vec<Box<dyn ConfigFetcher>>,
}

impl Authenticator {
    /// Creates an authenticator with the given configuration.
    pub fn new(config: AuthenticatorConfig) -> Self {
        Authenticator {
            config,
            fetchers: Vec::new(),
        }
    }

    #[cfg(test)]
    pub fn with_simple_secret(secret: &str) -> Self {
        Self::new(
            AuthenticatorConfig::new(Some(secret), "", "", "", DEFAULT_LOCALE.to_string(), None)
                .unwrap(),
        )
    }

    /// Creates an authenticator from environment variables.
    ///
    /// # Environment Variables
    /// - `AUTH_SECRET` - Shared secret for HMAC validation
    /// - `AUTH_ALGORITHMS` - Comma-separated list of allowed algorithms
    /// - `AUTH_ISSUER` - Comma-separated issuers, optionally with config (e.g., `iss1,iss2=jwks:/url`)
    /// - `AUTH_AUDIENCE` - Expected audience claim
    /// - `DEFAULT_LOCALE` - Fallback locale if not in token
    /// - `AUTH_CUSTOM_CLAIM_PREFIX` - Prefix to strip from custom claims
    pub fn from_env() -> anyhow::Result<Self> {
        let config = AuthenticatorConfig::new(
            env::var("AUTH_SECRET").ok(),
            &env::var("AUTH_ALGORITHMS").ok().unwrap_or_default(),
            &env::var("AUTH_ISSUER").ok().unwrap_or_default(),
            &env::var("AUTH_AUDIENCE").ok().unwrap_or_default(),
            env::var("DEFAULT_LOCALE")
                .ok()
                .unwrap_or_else(|| DEFAULT_LOCALE.to_string()),
            env::var("AUTH_CUSTOM_CLAIM_PREFIX").ok(),
        )?;

        Ok(Self::new(config))
    }

    /// Adds a dynamic config fetcher for multi-tenant scenarios.
    pub fn add_fetcher(&mut self, fetcher: Box<dyn ConfigFetcher>) {
        self.fetchers.push(fetcher);
    }

    /// Validates the JWT and returns the extracted claims.
    pub async fn parse_jwt(&self, jwt_token: &str) -> anyhow::Result<ClaimsSet> {
        let claims = Self::decode_payload(jwt_token)
            .context("Invalid JWT present")
            .with_status(StatusCode::UNAUTHORIZED)?;

        if let Some(config) = self.try_fetch_config(&claims).await {
            Self::parse_validate_and_update(jwt_token, &claims, &config).await
        } else {
            Self::parse_validate_and_update(jwt_token, &claims, &self.config).await
        }
    }

    fn decode_payload(jwt_token: &str) -> anyhow::Result<ClaimsSet> {
        if let Some(payload) = jwt_token.split('.').nth(1) {
            let decoded = URL_SAFE_NO_PAD
                .decode(payload)
                .context("Cannot decode Base64 payload")
                .with_status(StatusCode::UNAUTHORIZED)?;
            serde_json::from_slice(&decoded)
                .context("Cannot parse payload as JSON")
                .with_status(StatusCode::UNAUTHORIZED)
        } else {
            bail!("Cannot extract payload part")
        }
    }

    async fn parse_validate_and_update(
        jwt_token: &str,
        claims: &ClaimsSet,
        config: &AuthenticatorConfig,
    ) -> anyhow::Result<ClaimsSet> {
        let mut claims = config.check_signature(claims, jwt_token).await?;

        if let Some(custom_claim_prefix) = &config.custom_claim_prefix {
            claims = Self::translate_claims(claims, custom_claim_prefix);
        }

        Self::inject_locale_if_missing(&mut claims, &config.default_locale);

        Ok(claims)
    }

    async fn try_fetch_config(&self, claims_set: &ClaimsSet) -> Option<Arc<AuthenticatorConfig>> {
        for fetcher in &self.fetchers {
            if let Some(config) = fetcher.fetch(claims_set).await {
                return Some(config);
            }
        }

        None
    }

    fn translate_claims(claims: ClaimsSet, custom_claim_prefix: &str) -> ClaimsSet {
        claims
            .into_iter()
            .map(|(key, value)| {
                if key.starts_with(custom_claim_prefix) {
                    let new_key = key.trim_start_matches(custom_claim_prefix).to_string();
                    (new_key, value)
                } else {
                    (key, value)
                }
            })
            .collect()
    }

    fn inject_locale_if_missing(claims: &mut ClaimsSet, default_locale: &str) {
        if claims.get(CLAIM_LOCALE).is_none() {
            claims.insert(
                CLAIM_LOCALE.to_string(),
                Value::String(default_locale.to_string()),
            );
        }
    }
}

/// Configuration for JWT validation.
pub struct AuthenticatorConfig {
    validation: Validation,
    default_locale: String,
    custom_claim_prefix: Option<String>,
    key_fetcher: KeyFetchStrategy,
}

/// Strategy for fetching decoding keys - either a single key for all issuers
/// or a different key source per issuer.
enum KeyFetchStrategy {
    Static(Arc<dyn KeyFetcher>),
    PerIssuer(HashMap<String, Arc<dyn KeyFetcher>>),
}

/// Trait for fetching JWT decoding keys.
#[async_trait]
pub trait KeyFetcher: Send + Sync {
    async fn fetch(&self, header: &Header) -> anyhow::Result<Arc<DecodingKey>>;
}

struct HmacKeyFetcher {
    hmac_key: Arc<DecodingKey>,
}

impl HmacKeyFetcher {
    pub fn new(hmac_key: Arc<DecodingKey>) -> Self {
        Self { hmac_key }
    }
}

#[async_trait]
impl KeyFetcher for HmacKeyFetcher {
    async fn fetch(&self, _header: &Header) -> anyhow::Result<Arc<DecodingKey>> {
        Ok(self.hmac_key.clone())
    }
}

struct JwksFetcher {
    jwks_cache: JwksCache,
}

impl JwksFetcher {
    pub fn new(jwks_url: String) -> Self {
        Self {
            jwks_cache: JwksCache::new(Box::new(UrlJwksFetcher::new(jwks_url))),
        }
    }
}

#[async_trait]
impl KeyFetcher for JwksFetcher {
    async fn fetch(&self, header: &Header) -> anyhow::Result<Arc<DecodingKey>> {
        if let Some(kid) = &header.kid {
            self.jwks_cache.fetch_key(kid).await
        } else {
            Err(anyhow::anyhow!("No kid present in JWT header"))
        }
    }
}

impl AuthenticatorConfig {
    /// Creates a new authenticator configuration.
    ///
    /// Issuers can include per-issuer config: `issuer=jwks:/path` or `issuer=secret`.
    pub fn new(
        shared_secret: Option<impl AsRef<str>>,
        algorithms: &str,
        issuer: &str,
        audience: &str,
        default_locale: String,
        custom_claim_prefix: Option<String>,
    ) -> anyhow::Result<Self> {
        let hmac_based_key =
            shared_secret.map(|str| Arc::new(DecodingKey::from_secret(str.as_ref().as_bytes())));
        let issuers = issuer
            .split(",")
            .map(|iss| iss.split_once('=').unwrap_or((iss, "")))
            .map(|(iss, config)| (iss.to_owned(), config.to_owned()))
            .collect();
        let validation = Self::build_validation(algorithms, &issuers, audience);
        let key_fetcher = Self::build_key_fetcher_strategy(issuers, hmac_based_key)?;

        Ok(AuthenticatorConfig {
            validation,
            default_locale,
            custom_claim_prefix,
            key_fetcher,
        })
    }

    fn build_validation(
        algorithms: &str,
        issuers: &HashMap<String, String>,
        audience: &str,
    ) -> Validation {
        let mut validation = Validation::default();

        #[cfg(test)]
        validation.required_spec_claims.clear();

        validation.validate_nbf = true;
        validation.algorithms = Self::parse_algorithms(algorithms);
        validation.iss = Some(issuers.keys().map(String::to_owned).collect());
        validation.aud = Self::parse_set(audience);

        // If we chose to leave the required audiences empty, we skip validation entirely as
        // otherwise, the JWT library will always report an error even if no audience is given and
        // none is requested.
        validation.validate_aud = validation
            .aud
            .as_ref()
            .map(|aud| !aud.is_empty())
            .unwrap_or(false);

        validation
    }

    fn parse_set(values: &str) -> Option<HashSet<String>> {
        Some(
            values
                .split(',')
                .flat_map(|part| part.split(';'))
                .map(str::trim)
                .map(String::from)
                .filter(|s| !s.is_empty())
                .collect::<HashSet<String>>(),
        )
        .filter(|set| !set.is_empty())
    }

    fn build_key_fetcher_strategy(
        issuers: HashMap<String, String>,
        hmac_key: Option<Arc<DecodingKey>>,
    ) -> anyhow::Result<KeyFetchStrategy> {
        if issuers.is_empty()
            || issuers
                .iter()
                .all(|(_, config)| config.is_empty() || *config == "secret")
        {
            if let Some(hmac_key) = hmac_key {
                Ok(KeyFetchStrategy::Static(Arc::new(HmacKeyFetcher::new(
                    hmac_key,
                ))))
            } else {
                Err(anyhow::anyhow!(
                    "All issuers rely on a shared secret to be present, but none was given"
                ))
            }
        } else {
            let mut config_per_issuer = HashMap::new();

            for (iss, config) in issuers {
                let fetcher = Self::create_key_fetcher_from_config(&iss, config, &hmac_key)?;
                config_per_issuer.insert(iss, fetcher);
            }

            Ok(KeyFetchStrategy::PerIssuer(config_per_issuer))
        }
    }

    fn create_key_fetcher_from_config(
        iss: &str,
        config: String,
        hmac_key: &Option<Arc<DecodingKey>>,
    ) -> anyhow::Result<Arc<dyn KeyFetcher>> {
        if config.is_empty() || config == "secret" {
            if let Some(hmac_key) = hmac_key {
                Ok(Arc::new(HmacKeyFetcher::new(hmac_key.clone())))
            } else {
                Err(anyhow::anyhow!(
                    "Issuer {} relies on a shared secret, but none was given",
                    iss
                ))
            }
        } else if let Some(jwks_url) = config.strip_prefix("jwks:") {
            let jwks_url = if jwks_url.starts_with('/') {
                format!("{}{}", iss.trim_matches('/'), jwks_url)
            } else {
                jwks_url.to_owned()
            };

            Ok(Arc::new(JwksFetcher::new(jwks_url)))
        } else {
            Err(anyhow::anyhow!(
                "Issuer {} has an invalid config: {}",
                iss,
                config
            ))
        }
    }

    fn parse_algorithms(algorithms: &str) -> Vec<Algorithm> {
        Self::parse_set(algorithms)
            .map(|set| {
                set.iter()
                    .filter_map(|alg| Algorithm::from_str(alg).ok())
                    .collect::<Vec<Algorithm>>()
            })
            .unwrap_or_default()
    }

    async fn check_signature(
        &self,
        claims: &ClaimsSet,
        jwt_token: &str,
    ) -> anyhow::Result<ClaimsSet> {
        let header = decode_header(jwt_token)
            .context("Invalid JWT present")
            .with_status(StatusCode::UNAUTHORIZED)?;

        if !self.validation.algorithms.is_empty()
            && !self.validation.algorithms.contains(&header.alg)
        {
            status_bail!(
                StatusCode::UNAUTHORIZED,
                "Invalid JWT present: Unsupported algorithm: {:?}",
                header.alg
            );
        }

        let key_fetcher = match &self.key_fetcher {
            KeyFetchStrategy::Static(fetcher) => fetcher.clone(),
            KeyFetchStrategy::PerIssuer(fetcher_per_issuer) => {
                if let Some(fetcher) = claims
                    .get(CLAIM_ISS)
                    .and_then(Value::as_str)
                    .and_then(|iss| fetcher_per_issuer.get(iss))
                {
                    fetcher.clone()
                } else {
                    status_bail!(
                        StatusCode::UNAUTHORIZED,
                        "Invalid issuer or missing configuration"
                    )
                }
            }
        };

        let decoding_key = key_fetcher
            .fetch(&header)
            .await
            .with_status(StatusCode::UNAUTHORIZED)?;
        self.validate_signature(&header, &decoding_key, jwt_token)
    }

    fn validate_signature(
        &self,
        header: &Header,
        decoding_key: &DecodingKey,
        jwt_token: &str,
    ) -> anyhow::Result<ClaimsSet> {
        let mut validation = self.validation.clone();
        validation.algorithms = vec![header.alg];

        let token = decode::<ClaimsSet>(jwt_token, decoding_key, &validation)
            .context("Invalid JWT present")
            .with_status(StatusCode::UNAUTHORIZED)?;

        Ok(token.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // translate_claims tests

    #[test]
    fn translate_claims_strips_prefix() {
        let mut claims = ClaimsSet::new();
        claims.insert("custom:tenant".to_string(), json!("abc"));
        claims.insert("custom:role".to_string(), json!("admin"));
        claims.insert("sub".to_string(), json!("user123"));

        let translated = Authenticator::translate_claims(claims, "custom:");

        assert_eq!(translated.get("tenant").unwrap(), &json!("abc"));
        assert_eq!(translated.get("role").unwrap(), &json!("admin"));
        assert_eq!(translated.get("sub").unwrap(), &json!("user123"));
        assert!(translated.get("custom:tenant").is_none());
    }

    #[test]
    fn translate_claims_leaves_non_matching_unchanged() {
        let mut claims = ClaimsSet::new();
        claims.insert("other:claim".to_string(), json!("value"));
        claims.insert("sub".to_string(), json!("user123"));

        let translated = Authenticator::translate_claims(claims, "custom:");

        assert_eq!(translated.get("other:claim").unwrap(), &json!("value"));
        assert_eq!(translated.get("sub").unwrap(), &json!("user123"));
    }

    // inject_locale_if_missing tests

    #[test]
    fn inject_locale_adds_default_when_missing() {
        let mut claims = ClaimsSet::new();
        claims.insert("sub".to_string(), json!("user123"));

        Authenticator::inject_locale_if_missing(&mut claims, "de-DE");

        assert_eq!(claims.get(CLAIM_LOCALE).unwrap(), &json!("de-DE"));
    }

    #[test]
    fn inject_locale_preserves_existing() {
        let mut claims = ClaimsSet::new();
        claims.insert(CLAIM_LOCALE.to_string(), json!("fr-FR"));

        Authenticator::inject_locale_if_missing(&mut claims, "de-DE");

        assert_eq!(claims.get(CLAIM_LOCALE).unwrap(), &json!("fr-FR"));
    }

    // decode_payload tests

    #[test]
    fn decode_payload_extracts_claims() {
        // JWT with payload: {"sub": "1234", "name": "Test"}
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0IiwibmFtZSI6IlRlc3QifQ.signature";

        let claims = Authenticator::decode_payload(jwt).unwrap();

        assert_eq!(claims.get("sub").unwrap(), &json!("1234"));
        assert_eq!(claims.get("name").unwrap(), &json!("Test"));
    }

    #[test]
    fn decode_payload_fails_on_invalid_jwt() {
        let result = Authenticator::decode_payload("not-a-jwt");
        assert!(result.is_err());
    }

    #[test]
    fn decode_payload_fails_on_invalid_base64() {
        let result = Authenticator::decode_payload("header.!!!invalid!!!.signature");
        assert!(result.is_err());
    }

    // parse_set tests

    #[test]
    fn parse_set_splits_by_comma() {
        let result = AuthenticatorConfig::parse_set("a,b,c").unwrap();
        assert!(result.contains("a"));
        assert!(result.contains("b"));
        assert!(result.contains("c"));
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn parse_set_splits_by_semicolon() {
        let result = AuthenticatorConfig::parse_set("a;b;c").unwrap();
        assert!(result.contains("a"));
        assert!(result.contains("b"));
        assert!(result.contains("c"));
    }

    #[test]
    fn parse_set_handles_mixed_separators() {
        let result = AuthenticatorConfig::parse_set("a,b;c").unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn parse_set_trims_whitespace() {
        let result = AuthenticatorConfig::parse_set(" a , b , c ").unwrap();
        assert!(result.contains("a"));
        assert!(result.contains("b"));
        assert!(result.contains("c"));
    }

    #[test]
    fn parse_set_returns_none_for_empty() {
        assert!(AuthenticatorConfig::parse_set("").is_none());
        assert!(AuthenticatorConfig::parse_set("  ").is_none());
    }

    // parse_algorithms tests

    #[test]
    fn parse_algorithms_parses_known_algorithms() {
        let algs = AuthenticatorConfig::parse_algorithms("HS256,RS256");
        assert!(algs.contains(&Algorithm::HS256));
        assert!(algs.contains(&Algorithm::RS256));
    }

    #[test]
    fn parse_algorithms_ignores_unknown() {
        let algs = AuthenticatorConfig::parse_algorithms("HS256,UNKNOWN,RS256");
        assert_eq!(algs.len(), 2);
        assert!(algs.contains(&Algorithm::HS256));
        assert!(algs.contains(&Algorithm::RS256));
    }

    #[test]
    fn parse_algorithms_returns_empty_for_empty_input() {
        let algs = AuthenticatorConfig::parse_algorithms("");
        assert!(algs.is_empty());
    }

    // AuthenticatorConfig::new tests

    #[test]
    fn config_new_requires_secret_when_no_jwks() {
        let result = AuthenticatorConfig::new(
            None::<&str>,
            "",
            "https://issuer.example.com",
            "",
            "en-US".to_string(),
            None,
        );
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("shared secret"));
    }

    #[test]
    fn config_new_succeeds_with_secret() {
        let result = AuthenticatorConfig::new(
            Some("my-secret"),
            "HS256",
            "https://issuer.example.com",
            "",
            "en-US".to_string(),
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn config_new_fails_on_invalid_issuer_config() {
        let result = AuthenticatorConfig::new(
            Some("my-secret"),
            "",
            "https://issuer.example.com=invalid:config",
            "",
            "en-US".to_string(),
            None,
        );
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("invalid config"));
    }

    #[test]
    fn config_new_accepts_jwks_config() {
        let result = AuthenticatorConfig::new(
            None::<&str>,
            "",
            "https://issuer.example.com=jwks:/.well-known/jwks.json",
            "",
            "en-US".to_string(),
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn config_new_accepts_mixed_issuer_configs() {
        let result = AuthenticatorConfig::new(
            Some("my-secret"),
            "",
            "https://iss1.example.com=secret,https://iss2.example.com=jwks:/jwks.json",
            "",
            "en-US".to_string(),
            None,
        );
        assert!(result.is_ok());
    }
}
