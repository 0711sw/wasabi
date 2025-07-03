use crate::status_bail;
use crate::tools::not;
use crate::web::auth::CLAIM_LOCALE;
use crate::web::auth::jwks::{JwksCache, UrlJwksFetcher};
use crate::web::error::ResultExt;
use anyhow::{Context, bail};
use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::sync::Arc;
use warp::http::StatusCode;

#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn parse_jwt(&self, jwt_token: &str) -> anyhow::Result<BTreeMap<String, Value>>;
}

#[derive(Clone)]
pub struct SimpleAuthenticator {
    key: Arc<DecodingKey>,
}

#[async_trait]
impl Authenticator for SimpleAuthenticator {
    async fn parse_jwt(&self, jwt_token: &str) -> anyhow::Result<BTreeMap<String, Value>> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();

        let claims: BTreeMap<String, Value> =
            match decode::<BTreeMap<String, Value>>(jwt_token, &self.key, &validation) {
                Ok(claims) => claims.claims,
                Err(err) => {
                    status_bail!(StatusCode::UNAUTHORIZED, "Invalid JWT present: {}", err);
                }
            };

        Ok(claims)
    }
}

impl SimpleAuthenticator {
    pub fn new(key: &str) -> SimpleAuthenticator {
        Self {
            key: Arc::new(DecodingKey::from_secret(key.as_bytes())),
        }
    }
}

#[derive(Clone)]
pub struct JwtsAuthenticator {
    data: Arc<JwtsAuthenticatorData>,
}

struct JwtsAuthenticatorData {
    cache: JwksCache,
    validation: Validation,
    default_locale: String,
    custom_claim_prefix: Option<String>,
}

#[async_trait]
impl Authenticator for JwtsAuthenticator {
    async fn parse_jwt(&self, jwt_token: &str) -> anyhow::Result<BTreeMap<String, Value>> {
        let header = decode_header(jwt_token)
            .context("Invalid JWT present")
            .with_status(StatusCode::UNAUTHORIZED)?;
        let kid = header
            .kid
            .as_ref()
            .context("JWT token header does not contain 'kid'")
            .with_status(StatusCode::UNAUTHORIZED)?;

        let key = self.data.cache.fetch_key(kid).await?;

        let mut claims = decode::<BTreeMap<String, Value>>(jwt_token, &key, &self.data.validation)
            .context("Failed to validate JWT token with JWKS key")
            .with_status(StatusCode::UNAUTHORIZED)?
            .claims;
        
        if let Some(custom_claim_prefix) = &self.data.custom_claim_prefix {
            claims = Self::translate_claims(claims, &custom_claim_prefix);
        }

        Self::inject_locale_if_missing(&mut claims, &self.data.default_locale);

        Ok(claims)
    }
}

impl JwtsAuthenticator {
    fn translate_claims(
        claims: BTreeMap<String, Value>,
        custom_claim_prefix: &str,
    ) -> BTreeMap<String, Value> {
        claims
            .into_iter()
            .map(|(key, value)| {
                if key.starts_with(&custom_claim_prefix) {
                    let new_key = key.trim_start_matches(&custom_claim_prefix).to_string();
                    (new_key, value)
                } else {
                    (key, value)
                }
            })
            .collect()
    }

    fn inject_locale_if_missing(claims: &mut BTreeMap<String, Value>, default_locale: &str) {
        if claims.get(CLAIM_LOCALE).is_none() {
            claims.insert(
                CLAIM_LOCALE.to_string(),
                Value::String(default_locale.to_string()),
            );
        }
    }
}

pub fn from_env() -> anyhow::Result<Arc<dyn Authenticator>> {
    if let Ok(url) = env::var("AUTH_JWKS_URL") {
        let authenticator = JwtsAuthenticator {
            data: Arc::new(JwtsAuthenticatorData {
                cache: JwksCache::new(Box::new(UrlJwksFetcher::new(url))),
                validation: load_validation_from_env()?,
                default_locale: env::var("DEFAULT_LOCALE")
                    .ok()
                    .unwrap_or_else(|| "en-US".to_string()),
                custom_claim_prefix: env::var("AUTH_CUSTOM_CLAIM_PREFIX").ok(),
            }),
        };
        Ok(Arc::new(authenticator))
    } else if let Ok(secret) = env::var("AUTH_SECRET") {
        Ok(Arc::new(SimpleAuthenticator::new(&secret)))
    } else {
        bail!(
            "No authentication method configured. Set either AUTH_JWKS_URL or AUTH_SECRET in the environment."
        );
    }
}

fn load_validation_from_env() -> anyhow::Result<Validation> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_nbf = true;

    let audiences = env::var("AUTH_AUDIENCE")
        .ok()
        .map(parse_set)
        .filter(not(HashSet::is_empty))
        .context("Please provider AUTH_AUDIENCE in the environment")?;
    validation.aud = Some(audiences);

    let issuers = env::var("AUTH_ISSUER")
        .ok()
        .map(parse_set)
        .filter(not(HashSet::is_empty))
        .context("Please provider AUTH_ISSUER in the environment")?;
    validation.iss = Some(issuers);

    Ok(validation)
}

fn parse_set(values: String) -> HashSet<String> {
    values
        .split(',')
        .map(str::trim)
        .map(String::from)
        .collect::<HashSet<String>>()
}
