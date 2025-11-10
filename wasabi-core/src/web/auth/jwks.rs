use anyhow::{Context, bail};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use jsonwebtoken::DecodingKey;
use jwks::Jwks;
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(test)]
use mock_instant::global::SystemTime;
#[cfg(not(test))]
use std::time::SystemTime;
use reqwest::Client;

pub(crate) type KeyCache = HashMap<String, Arc<DecodingKey>>;

#[async_trait]
pub(crate) trait JwksFetcher: Send + Sync {
    async fn fetch(&self) -> anyhow::Result<KeyCache>;
}

pub struct UrlJwksFetcher {
    url: String,
}

#[async_trait]
impl JwksFetcher for UrlJwksFetcher {
    async fn fetch(&self) -> anyhow::Result<KeyCache> {
        // Note that we pass a custom client in here, so that our dependency "reqwest"
        // is actually marked as used. We need this dependency to activate "rustls-tls" as
        // feature, as JWKS itself has all default features turned off...
        let jwks = Jwks::from_jwks_url_with_client(&Client::default(), &self.url)
            .await
            .with_context(|| format!("Failed to fetch JWKS from: {}", self.url))?;

        let keys = jwks
            .keys
            .into_iter()
            .map(|(kid, key)| (kid, Arc::new(key.decoding_key)))
            .collect();

        Ok(keys)
    }
}

impl UrlJwksFetcher {
    pub(crate) fn new(url: String) -> Self {
        Self { url }
    }
}

const MAX_CACHE_TTL_SECONDS: u64 = 5 * 60;
const MIN_WAIT_BETWEEN_LOADS_SECONDS: u64 = 10;
const NOT_YET_LOADED: u64 = 0;

pub(crate) struct JwksCache {
    fetcher: Box<dyn JwksFetcher>,
    last_load: ArcSwapOption<SystemTime>,
    cached_keys: ArcSwapOption<KeyCache>,
}
impl JwksCache {
    pub(crate) fn new(fetcher: Box<dyn JwksFetcher>) -> Self {
        Self {
            fetcher,
            last_load: ArcSwapOption::new(None),
            cached_keys: ArcSwapOption::new(None),
        }
    }

    pub(crate) async fn fetch_key(&self, key_id: &str) -> anyhow::Result<Arc<DecodingKey>> {
        let mut cached_keys = self.load_keys();
        let last_loaded_seconds = self.compute_seconds_since_last_load();

        if last_loaded_seconds > MAX_CACHE_TTL_SECONDS
            || cached_keys
                .as_ref()
                .and_then(|keys| keys.get(key_id))
                .is_none()
        {
            cached_keys = None;
        }

        if cached_keys.is_none()
            && (last_loaded_seconds == NOT_YET_LOADED
                || last_loaded_seconds > MIN_WAIT_BETWEEN_LOADS_SECONDS)
        {
            self.last_load.store(Some(Arc::new(SystemTime::now())));
            let keys = self.fetcher.fetch().await.map_err(|err| {
                self.cached_keys.store(None);
                err
            })?;
            cached_keys = Some(Arc::new(keys));
            self.cached_keys.store(cached_keys.clone());
        }

        if let Some(keys) = cached_keys {
            if let Some(key) = keys.get(key_id) {
                Ok(key.clone())
            } else {
                bail!("Unknown JWKS key: {}", key_id);
            }
        } else {
            bail!("JWKS not loaded or empty");
        }
    }

    fn load_keys(&self) -> Option<Arc<KeyCache>> {
        self.cached_keys.load_full()
    }

    fn compute_seconds_since_last_load(&self) -> u64 {
        self.last_load
            .load_full()
            .and_then(|last_load| SystemTime::now().duration_since(*last_load).ok())
            .map(|duration| duration.as_secs())
            .unwrap_or(NOT_YET_LOADED)
    }
}
