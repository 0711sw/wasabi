use crate::status_bail;
use crate::web::auth::jwks::{JwksCache, UrlJwksFetcher};
use crate::web::auth::user::ClaimsSet;
use crate::web::auth::{CLAIM_LOCALE, DEFAULT_LOCALE};
use crate::web::error::ResultExt;
use anyhow::{Context, bail};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode, decode_header};
use serde_json::Value;
use std::collections::HashSet;
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use warp::http::StatusCode;

#[async_trait]
pub trait ConfigFetcher: Send + Sync {
    async fn fetch(&self, claims: &ClaimsSet) -> Option<Arc<AuthenticatorConfig>>;
}

pub struct Authenticator {
    config: AuthenticatorConfig,
    fetchers: Vec<Box<dyn ConfigFetcher>>,
}

impl Authenticator {
    pub fn new(config: AuthenticatorConfig) -> Self {
        Authenticator {
            config,
            fetchers: Vec::new(),
        }
    }

    #[cfg(test)]
    pub fn with_simple_secret(secret: &str) -> Self {
        Self::new(AuthenticatorConfig::new(
            None::<&str>,
            Some(secret),
            "",
            "",
            "",
            DEFAULT_LOCALE.to_string(),
            None,
        ))
    }

    pub fn from_env() -> anyhow::Result<Self> {
        let jwks_url = env::var("AUTH_JWKS_URL").ok();
        let shared_secret = env::var("AUTH_SECRET").ok();

        if jwks_url.is_none() && shared_secret.is_none() {
            bail!("Either provide AUTH_JWKS_URL or AUTH_SECRET in the system environment");
        }

        let config = AuthenticatorConfig::new(
            jwks_url,
            shared_secret,
            &env::var("AUTH_ALGORITHMS").ok().unwrap_or_default(),
            &env::var("AUTH_ISSUER").ok().unwrap_or_default(),
            &env::var("AUTH_AUDIENCE").ok().unwrap_or_default(),
            env::var("DEFAULT_LOCALE")
                .ok()
                .unwrap_or_else(|| DEFAULT_LOCALE.to_string()),
            env::var("AUTH_CUSTOM_CLAIM_PREFIX").ok(),
        );

        Ok(Self::new(config))
    }

    pub fn add_fetcher(&mut self, fetcher: Box<dyn ConfigFetcher>) {
        self.fetchers.push(fetcher);
    }

    pub async fn parse_jwt(&self, jwt_token: &str) -> anyhow::Result<ClaimsSet> {
        let claims = Self::decode_payload(jwt_token)
            .context("Invalid JWT present")
            .with_status(StatusCode::UNAUTHORIZED)?;

        if let Some(config) = self.try_fetch_config(&claims).await {
            Self::parse_validate_and_update(jwt_token, &config).await
        } else {
            Self::parse_validate_and_update(jwt_token, &self.config).await
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
        config: &AuthenticatorConfig,
    ) -> anyhow::Result<ClaimsSet> {
        let mut claims = config.check_signature(jwt_token).await?;

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

pub struct AuthenticatorConfig {
    hmac_based_key: Option<DecodingKey>,
    validation: Validation,
    default_locale: String,
    custom_claim_prefix: Option<String>,
    jwks_cache: Option<JwksCache>,
}

impl AuthenticatorConfig {
    pub fn new(
        jwks_url: Option<impl ToString>,
        shared_secret: Option<impl AsRef<str>>,
        algorithms: &str,
        issuer: &str,
        audience: &str,
        default_locale: String,
        custom_claim_prefix: Option<String>,
    ) -> Self {
        AuthenticatorConfig {
            hmac_based_key: shared_secret
                .map(|str| DecodingKey::from_secret(str.as_ref().as_bytes())),
            jwks_cache: jwks_url
                .map(|url| JwksCache::new(Box::new(UrlJwksFetcher::new(url.to_string())))),
            default_locale,
            custom_claim_prefix,
            validation: Self::build_validation(algorithms, issuer, audience),
        }
    }

    fn build_validation(algorithms: &str, issuer: &str, audience: &str) -> Validation {
        let mut validation = Validation::default();

        #[cfg(test)]
        validation.required_spec_claims.clear();

        validation.validate_nbf = true;
        validation.algorithms = Self::parse_algorithms(algorithms);
        validation.iss = Self::parse_set(issuer);
        validation.aud = Self::parse_set(audience);

        validation
    }

    fn parse_set(values: &str) -> Option<HashSet<String>> {
        Some(
            values
                .split(',')
                .flat_map(|part| part.split(';'))
                .map(str::trim)
                .map(String::from)
                .collect::<HashSet<String>>(),
        )
        .filter(|set| !set.is_empty())
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

    async fn check_signature(&self, jwt_token: &str) -> anyhow::Result<ClaimsSet> {
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

        if let Some(jwks_cache) = &self.jwks_cache
            && let Some(kid) = &header.kid
        {
            let decoding_key = jwks_cache
                .fetch_key(kid)
                .await
                .with_status(StatusCode::UNAUTHORIZED)?;
            self.validate_signature(&header, &decoding_key, jwt_token)
        } else if let Some(hmac) = &self.hmac_based_key {
            self.validate_signature(&header, hmac, jwt_token)
        } else {
            status_bail!(
                StatusCode::UNAUTHORIZED,
                "Invalid JWT present: No matching authentication mechanism found"
            )
        }
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
