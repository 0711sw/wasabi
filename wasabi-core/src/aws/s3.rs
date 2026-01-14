//! S3 client with ETag-based caching and multipart uploads.
//!
//! Provides an ergonomic wrapper around the AWS S3 SDK with:
//!
//! - **Bucket naming**: Automatically appends `S3_BUCKET_SUFFIX` to bucket prefixes
//! - **Caching**: [`S3CachedObject`] uses ETags to avoid re-downloading unchanged files
//! - **Multipart uploads**: Streams large files in 16MB chunks
//!
//! # Environment Variables
//!
//! | Variable | Description |
//! |----------|-------------|
//! | `S3_BUCKET_SUFFIX` | Suffix appended to bucket prefixes (required) |
//!
//! # Bucket Naming
//!
//! Buckets can be specified in three ways:
//!
//! ```rust,ignore
//! // Full name (no suffix appended)
//! BucketName::FullyQualifiedName("my-bucket".to_string())
//!
//! // Prefix + suffix: "data" + "." + S3_BUCKET_SUFFIX
//! BucketName::ConstPrefix("data")
//! BucketName::Prefix("data".to_string())
//! ```

use crate::web::error::ResultExt;
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_s3::primitives::{AggregatedBytes, ByteStream};
use aws_sdk_s3::types::CompletedMultipartUpload;
use aws_sdk_s3::types::CompletedPart;
use aws_sdk_s3::types::{BucketLocationConstraint, CreateBucketConfiguration};
use aws_sdk_s3::{Client, config};
use bytes::{Buf, Bytes};
use bytesize::{KB, MB};
use futures_util::TryStreamExt;
use std::env;
use std::fmt::{Debug, Display};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use tokio::sync::Notify;
use tokio::sync::RwLock;
use tokio::time::Duration;
use tokio::time::Instant;

/// Ideal part size for multipart uploads (16 MB).
const MULTIPART_UPLOAD_IDEAL_PART_SIZE: usize = 16 * MB as usize;
/// Buffer size for multipart uploads (16 MB + 16 KB headroom).
const MULTIPART_UPLOAD_BUFFER_SIZE: usize = MULTIPART_UPLOAD_IDEAL_PART_SIZE + (16 * KB as usize);

/// S3 client wrapper with bucket suffix support.
///
/// Automatically appends `S3_BUCKET_SUFFIX` to bucket prefixes, enabling
/// environment-based bucket isolation (e.g., `data.prod.example.com` vs `data.dev.example.com`).
#[derive(Clone, Debug)]
pub struct S3Client {
    /// The underlying AWS SDK S3 client.
    pub client: Client,
    bucket_suffix: String,
}

/// Bucket name specification.
///
/// Use `ConstPrefix` or `Prefix` for automatic suffix appending,
/// or `FullyQualifiedName` for explicit bucket names.
#[derive(Debug)]
pub enum BucketName {
    /// Exact bucket name (no suffix appended).
    FullyQualifiedName(String),
    /// Static prefix + `S3_BUCKET_SUFFIX`.
    ConstPrefix(&'static str),
    /// Dynamic prefix + `S3_BUCKET_SUFFIX`.
    Prefix(String),
}

impl Display for BucketName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BucketName::FullyQualifiedName(name) => write!(f, "{}", name),
            BucketName::ConstPrefix(prefix) => write!(f, "{}...", prefix),
            BucketName::Prefix(prefix) => write!(f, "{}...", prefix),
        }
    }
}

/// Trait for objects that can be fetched with caching.
#[async_trait]
pub trait CachedObject: Send + Sync {
    /// Returns cached content if available and fresh, otherwise fetches.
    async fn fetch_cached(&self) -> anyhow::Result<Arc<Vec<u8>>>;

    /// Always fetches fresh content (ignoring cache).
    async fn fetch(&self) -> anyhow::Result<Arc<Vec<u8>>>;

    /// Fetches with optional cache bypass.
    async fn fetch_with_flush(&self, flush: bool) -> anyhow::Result<Arc<Vec<u8>>>;
}

/// In-memory cached object for testing or static content.
pub struct StaticCachedObject {
    content: Vec<u8>,
}

impl StaticCachedObject {
    /// Creates a new static cached object from raw bytes.
    pub fn new(content: Vec<u8>) -> Self {
        StaticCachedObject { content }
    }

    /// Creates a new static cached object from a string.
    pub fn from_string(content: &str) -> Self {
        StaticCachedObject {
            content: content.as_bytes().to_vec(),
        }
    }
}

#[async_trait]
impl CachedObject for StaticCachedObject {
    async fn fetch_cached(&self) -> anyhow::Result<Arc<Vec<u8>>> {
        self.fetch().await
    }

    async fn fetch(&self) -> anyhow::Result<Arc<Vec<u8>>> {
        Ok(Arc::new(self.content.clone()))
    }

    async fn fetch_with_flush(&self, _flush: bool) -> anyhow::Result<Arc<Vec<u8>>> {
        self.fetch().await
    }
}

/// S3 object with ETag-based caching.
///
/// Caches object content in memory and uses S3 ETags to detect changes.
/// When cache expires, checks ETag before re-downloading to save bandwidth.
///
/// Multiple concurrent fetches are coalesced - only one S3 request is made.
pub struct S3CachedObject {
    client: S3Client,
    minimum_cache_duration: Duration,
    bucket: BucketName,
    object_key: String,
    state: RwLock<S3CachedObjectState>,
    fetching: AtomicBool,
    notify: Notify,
}

/// Internal cache state.
struct S3CachedObjectState {
    content: Option<Arc<Vec<u8>>>,
    etag: String,
    last_fetched: Instant,
}

impl S3Client {
    /// Creates a new client from environment configuration.
    ///
    /// Loads AWS credentials from the default credential chain and reads
    /// `S3_BUCKET_SUFFIX` from the environment.
    ///
    /// # Errors
    ///
    /// Returns an error if `S3_BUCKET_SUFFIX` is not set.
    pub async fn from_env() -> anyhow::Result<S3Client> {
        tracing::info!("Setting up S3....");
        let config = aws_config::load_from_env().await;

        let s3_config = config::Builder::from(&config)
            .force_path_style(true)
            .build();

        let client = Client::from_conf(s3_config);
        let bucket_suffix =
            env::var("S3_BUCKET_SUFFIX").context("No S3_BUCKET_SUFFIX provided in environment")?;

        Ok(S3Client {
            client,
            bucket_suffix,
        })
    }

    /// Returns the effective bucket name with suffix applied.
    ///
    /// For `ConstPrefix("data")` with suffix `prod.example.com`, returns `data.prod.example.com`.
    pub fn effective_name(&self, bucket: &BucketName) -> String {
        match bucket {
            BucketName::FullyQualifiedName(name) => name.clone(),
            BucketName::ConstPrefix(prefix) => format!("{}.{}", prefix, self.bucket_suffix),
            BucketName::Prefix(prefix) => format!("{}.{}", prefix, self.bucket_suffix),
        }
    }

    /// Checks if a bucket exists in S3.
    ///
    /// Returns `true` if the bucket exists, `false` if not found.
    #[tracing::instrument(skip(self), ret, err(Display))]
    pub async fn does_bucket_exist(&self, bucket: &BucketName) -> anyhow::Result<bool> {
        let effective_name = self.effective_name(bucket);

        match self
            .client
            .head_bucket()
            .bucket(&effective_name)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(err)
                if err
                    .as_service_error()
                    .map(|e| e.is_not_found())
                    .unwrap_or(false) =>
            {
                Ok(false)
            }
            Err(e) => Err(e).context(format!("Cannot access bucket '{}'", effective_name)),
        }
    }
    /// Creates a bucket if it doesn't already exist.
    ///
    /// Uses the client's configured region for the bucket location.
    #[tracing::instrument(skip(self), err(Display))]
    pub async fn create_bucket(&self, name: &BucketName) -> anyhow::Result<()> {
        let effective_name = self.effective_name(name);

        if self.does_bucket_exist(name).await? {
            tracing::info!("Bucket '{}' already exists...", &self.effective_name(name));

            Ok(())
        } else {
            let region_str = self
                .client
                .config()
                .region()
                .context("Cannot determine default region")?
                .as_ref();
            let location_constraint = BucketLocationConstraint::from(region_str);

            tracing::info!(
                "Bucket '{}' does not exist. Creating in {:?}...",
                &self.effective_name(name),
                &location_constraint
            );

            let _ = self
                .client
                .create_bucket()
                .bucket(effective_name.clone())
                .create_bucket_configuration(
                    CreateBucketConfiguration::builder()
                        .location_constraint(location_constraint)
                        .build(),
                )
                .send()
                .await
                .with_context(|| format!("Failed to create bucket '{}'", effective_name))?;

            tracing::info!(
                "Bucket '{}' was successfully created",
                &self.effective_name(name)
            );

            Ok(())
        }
    }

    /// Deletes an object from S3.
    #[tracing::instrument(level = "debug", skip(self), ret(Debug), err(Display))]
    pub async fn delete_object(&self, bucket: &BucketName, key: &str) -> anyhow::Result<()> {
        let effective_bucket = self.effective_name(bucket);

        let _ = self
            .client
            .delete_object()
            .bucket(&effective_bucket)
            .key(key)
            .send()
            .await
            .with_context(|| {
                format!(
                    "Failed to delete '{}' from bucket '{}'",
                    key, &effective_bucket
                )
            })?;

        Ok(())
    }

    /// Uploads an object to S3.
    ///
    /// For large files, consider using [`multipart_upload`](Self::multipart_upload) instead.
    #[tracing::instrument(level = "debug", skip(self, body), err(Display))]
    pub async fn put_object(
        &self,
        bucket: &BucketName,
        object_key: &str,
        body: Vec<u8>,
    ) -> anyhow::Result<()> {
        let effective_bucket = self.effective_name(bucket);

        let _ = self
            .client
            .put_object()
            .bucket(effective_bucket)
            .key(object_key)
            .body(ByteStream::from(body))
            .send()
            .await
            .with_context(|| {
                format!(
                    "Failed to store object '{}' in bucket '{}'",
                    object_key, bucket
                )
            })?;

        Ok(())
    }

    /// Downloads an object from S3.
    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    pub async fn get_object(&self, bucket: &BucketName, object_key: &str) -> anyhow::Result<Bytes> {
        let effective_bucket = self.effective_name(bucket);

        let result = self
            .client
            .get_object()
            .bucket(effective_bucket)
            .key(object_key)
            .send()
            .await
            .with_context(|| {
                format!(
                    "Failed to fetch object '{}' from bucket '{}'",
                    object_key, bucket
                )
            })?;

        let data = result
            .body
            .collect()
            .await
            .with_context(|| {
                format!(
                    "Failed to read object '{}' from bucket '{}'",
                    object_key, bucket
                )
            })?
            .into_bytes();

        Ok(data)
    }

    /// Uploads a large object using S3 multipart upload.
    ///
    /// Streams data in 16MB chunks. Automatically aborts the upload on failure.
    #[tracing::instrument(level = "debug", skip(self, stream), err(Display))]
    pub async fn multipart_upload(
        &self,
        bucket: &BucketName,
        object_key: &str,
        stream: crate::tools::PinnedBytesStream,
    ) -> anyhow::Result<()> {
        let effective_bucket = self.effective_name(bucket);

        let upload_id = self
            .client
            .create_multipart_upload()
            .bucket(&effective_bucket)
            .key(object_key)
            .send()
            .await
            .with_context(|| {
                format!(
                    "Failed to create multipart upload for '{}' in bucket '{}'",
                    object_key, bucket
                )
            })?
            .upload_id()
            .with_context(|| {
                format!(
                    "Failed to receive upload id for a multipart upload of '{}' in bucket '{}'",
                    object_key, bucket
                )
            })?
            .to_owned();

        if let Err(err) = self
            .perform_multipart_upload(&effective_bucket, object_key, &upload_id, stream)
            .await
        {
            if let Err(abort_error) = self
                .client
                .abort_multipart_upload()
                .bucket(&effective_bucket)
                .key(object_key)
                .upload_id(upload_id)
                .send()
                .await
            {
                tracing::error!(
                    "Failed to abort multipart upload of '{}' in bucket '{}': {:#}",
                    object_key,
                    bucket,
                    abort_error
                );
            }

            Err(err)
        } else {
            Ok(())
        }
    }

    async fn perform_multipart_upload(
        &self,
        effective_bucket: &str,
        key: &str,
        upload_id: &str,
        mut stream: crate::tools::PinnedBytesStream,
    ) -> anyhow::Result<()> {
        let mut buffer = Vec::with_capacity(MULTIPART_UPLOAD_BUFFER_SIZE);
        let mut part_number = 1;
        let mut uploaded_parts = Vec::new();

        while let Some(chunk) = stream
            .try_next()
            .await
            .context("Failed to read body")
            .mark_client_error()?
        {
            buffer.extend_from_slice(chunk.chunk());

            if buffer.len() >= MULTIPART_UPLOAD_IDEAL_PART_SIZE {
                let upload_result = self
                    .client
                    .upload_part()
                    .bucket(effective_bucket)
                    .key(key)
                    .upload_id(upload_id)
                    .part_number(part_number)
                    .body(ByteStream::from(buffer.clone()))
                    .send()
                    .await?;

                uploaded_parts.push(
                    CompletedPart::builder()
                        .e_tag(upload_result.e_tag.unwrap_or_default())
                        .part_number(part_number)
                        .build(),
                );
                part_number += 1;
                buffer.clear();
            }
        }

        if !buffer.is_empty() {
            let upload_result = self
                .client
                .upload_part()
                .bucket(effective_bucket)
                .key(key)
                .upload_id(upload_id)
                .part_number(part_number)
                .body(ByteStream::from(buffer.clone()))
                .send()
                .await
                .with_context(|| {
                    format!(
                        "Failed to upload a part of a multipart upload of '{}' in bucket '{}'",
                        key, effective_bucket,
                    )
                })?;

            uploaded_parts.push(
                CompletedPart::builder()
                    .e_tag(upload_result.e_tag.unwrap_or_default())
                    .part_number(part_number)
                    .build(),
            );
        }

        let _ = self
            .client
            .complete_multipart_upload()
            .bucket(effective_bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(uploaded_parts))
                    .build(),
            )
            .send()
            .await
            .with_context(|| {
                format!(
                    "Failed to complete multipart upload of '{}' in bucket '{}'",
                    key, effective_bucket,
                )
            })?;

        Ok(())
    }

    /// Creates a cached object reference for repeated access.
    ///
    /// The returned [`S3CachedObject`] caches content in memory and uses ETags
    /// to avoid re-downloading unchanged files after the cache duration expires.
    #[tracing::instrument(level = "debug", skip(self), ret)]
    pub fn cached_object(
        &self,
        bucket: BucketName,
        object_key: &str,
        minimum_cache_duration: Duration,
    ) -> Arc<S3CachedObject> {
        Arc::new(S3CachedObject {
            client: self.clone(),
            bucket,
            object_key: object_key.to_owned(),
            state: RwLock::new(S3CachedObjectState {
                content: None,
                etag: "".to_owned(),
                last_fetched: Instant::now(),
            }),
            minimum_cache_duration,
            fetching: AtomicBool::new(false),
            notify: Notify::new(),
        })
    }
}

impl Debug for S3CachedObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} in {}", self.object_key, self.bucket)
    }
}

#[async_trait]
impl CachedObject for S3CachedObject {
    #[tracing::instrument(level = "debug", err(Display))]
    async fn fetch_cached(&self) -> anyhow::Result<Arc<Vec<u8>>> {
        if let Some(content) = self.fetch_from_inner_cache().await {
            return Ok(content);
        }

        self.fetch().await
    }

    #[tracing::instrument(level = "debug", err(Display))]
    async fn fetch(&self) -> anyhow::Result<Arc<Vec<u8>>> {
        if self.fetching.swap(true, Ordering::SeqCst) {
            self.notify.notified().await;

            let state = self.state.read().await;
            if let Some(content) = &state.content {
                return Ok(content.clone());
            } else {
                anyhow::bail!(
                    "Waited for another task to fetch {} from S3 bucket {}, but it failed",
                    self.object_key,
                    self.bucket
                );
            }
        }

        self.fetch_and_cache().await
    }

    async fn fetch_with_flush(&self, flush: bool) -> anyhow::Result<Arc<Vec<u8>>> {
        if flush {
            self.fetch().await
        } else {
            self.fetch_cached().await
        }
    }
}

impl S3CachedObject {
    async fn fetch_from_inner_cache(&self) -> Option<Arc<Vec<u8>>> {
        let state = self.state.read().await;

        match &state.content {
            Some(content) if state.last_fetched.elapsed() < self.minimum_cache_duration => {
                Some(content.clone())
            }
            _ => None,
        }
    }

    #[tracing::instrument(level = "debug", err(Display))]
    async fn fetch_and_cache(&self) -> anyhow::Result<Arc<Vec<u8>>> {
        let (content, next_etag) = self.perform_fetch().await;

        let mut state = self.state.write().await;
        state.etag = next_etag;
        state.content = content;
        state.last_fetched = Instant::now();

        self.fetching.store(false, Ordering::SeqCst);
        self.notify.notify_waiters();

        if let Some(content) = &state.content {
            Ok(content.clone())
        } else {
            Err(anyhow::anyhow!(
                "Failed to fetch {} from S3 bucket {}",
                self.object_key,
                self.bucket
            ))
        }
    }

    #[tracing::instrument(level = "debug")]
    async fn perform_fetch(&self) -> (Option<Arc<Vec<u8>>>, String) {
        if let Some((cached_content, cached_etag)) = self.load_from_cache().await {
            let new_etag = self.fetch_etag_from_s3().await;
            if new_etag == cached_etag {
                return (Some(cached_content), cached_etag);
            }
        }

        self.fetch_from_s3().await
    }

    #[tracing::instrument(level = "debug")]
    async fn load_from_cache(&self) -> Option<(Arc<Vec<u8>>, String)> {
        let state = self.state.read().await;
        match &state.content {
            Some(content) if !state.etag.is_empty() => Some((content.clone(), state.etag.clone())),
            _ => None,
        }
    }

    #[tracing::instrument(level = "debug", ret)]
    async fn fetch_etag_from_s3(&self) -> String {
        let effective_bucket = self.client.effective_name(&self.bucket);

        let result = self
            .client
            .client
            .head_object()
            .bucket(effective_bucket)
            .key(&self.object_key)
            .send()
            .await;

        match result {
            Ok(result) => result.e_tag.unwrap_or_default(),
            Err(err) => {
                tracing::error!(
                    "Failed to check the etag of object '{}' in bucket '{}': {:#}",
                    self.object_key,
                    self.bucket,
                    err
                );

                "".to_string()
            }
        }
    }

    #[tracing::instrument(level = "debug")]
    async fn fetch_from_s3(&self) -> (Option<Arc<Vec<u8>>>, String) {
        let effective_bucket = self.client.effective_name(&self.bucket);

        let result = self
            .client
            .client
            .get_object()
            .bucket(effective_bucket)
            .key(&self.object_key)
            .send()
            .await;

        match result {
            Ok(result) => {
                let etag = result.e_tag().unwrap_or_default().to_owned();
                let data = result
                    .body
                    .collect()
                    .await
                    .map(AggregatedBytes::to_vec)
                    .unwrap_or_default();

                (Some(Arc::new(data)), etag)
            }
            Err(err) => {
                tracing::error!(
                    "Failed to read object '{}' from bucket '{}': {:#}",
                    self.object_key,
                    self.bucket,
                    err
                );

                (None, "".to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aws::test::test_run_id;
    use std::env;

    #[test]
    fn bucket_name_display_shows_full_name() {
        let name = BucketName::FullyQualifiedName("my-bucket".to_string());
        assert_eq!(format!("{}", name), "my-bucket");
    }

    #[test]
    fn bucket_name_display_shows_prefix_with_ellipsis() {
        let name = BucketName::ConstPrefix("data");
        assert_eq!(format!("{}", name), "data...");

        let name = BucketName::Prefix("uploads".to_string());
        assert_eq!(format!("{}", name), "uploads...");
    }

    #[tokio::test]
    async fn static_cached_object_returns_content() {
        let obj = StaticCachedObject::new(vec![1, 2, 3]);
        let content = obj.fetch().await.unwrap();
        assert_eq!(*content, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn static_cached_object_from_string_returns_bytes() {
        let obj = StaticCachedObject::from_string("hello");
        let content = obj.fetch_cached().await.unwrap();
        assert_eq!(*content, b"hello".to_vec());
    }

    #[tokio::test]
    async fn static_cached_object_fetch_with_flush_ignores_flush() {
        let obj = StaticCachedObject::new(vec![42]);
        let content = obj.fetch_with_flush(true).await.unwrap();
        assert_eq!(*content, vec![42]);
    }

    #[tokio::test]
    #[ignore]
    async fn does_bucket_exist_detects_nonexistent_bucket() {
        unsafe {
            env::set_var("S3_BUCKET_SUFFIX", "wasabi-test.0711sw.net");
        }

        let s3_client = S3Client::from_env().await.unwrap();

        assert!(
            !s3_client
                .does_bucket_exist(&BucketName::ConstPrefix("non-existent-bucket"))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    #[ignore]
    async fn create_bucket_creates_bucket_if_non_existent() {
        unsafe {
            env::set_var("S3_BUCKET_SUFFIX", "wasabi-test.0711sw.net");
        }

        let s3_client = S3Client::from_env().await.unwrap();
        let bucket_name = BucketName::Prefix(format!("test-bucket-{}", test_run_id()));

        // Ensure the bucket does not exist before creating it...
        if s3_client.does_bucket_exist(&bucket_name).await.unwrap() {
            s3_client
                .client
                .delete_bucket()
                .bucket(s3_client.effective_name(&bucket_name))
                .send()
                .await
                .unwrap();
        }

        assert!(!s3_client.does_bucket_exist(&bucket_name).await.unwrap());
        s3_client.create_bucket(&bucket_name).await.unwrap();
        assert!(s3_client.does_bucket_exist(&bucket_name).await.unwrap());

        // Ensure creating it again doesn't fail...
        s3_client.create_bucket(&bucket_name).await.unwrap();

        // Clean up the bucket after the test...
        s3_client
            .client
            .delete_bucket()
            .bucket(s3_client.effective_name(&bucket_name))
            .send()
            .await
            .unwrap();
        assert!(!s3_client.does_bucket_exist(&bucket_name).await.unwrap());
    }
}
