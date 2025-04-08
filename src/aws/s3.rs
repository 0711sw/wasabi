use anyhow::Context;
use s3::creds::Credentials;
use s3::{Bucket, BucketConfiguration, Region};
use std::env;

#[derive(Clone, Debug)]
pub struct S3Client {
    region: Region,
    credentials: Credentials,
    bucket_suffix: Option<String>,
}

impl S3Client {
    pub fn from_env() -> anyhow::Result<S3Client> {
        tracing::info!("Setting up S3....");
        let region = Region::from_default_env().context("Failed to determine S3 region. Please provide AWS_ENDPOINT and or AWS_REGION in the environment!")?;
        let credentials = Credentials::default().context("Failed to determine S3 credentials. Please provide AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in the environment")?;

        Ok(S3Client {
            region,
            credentials,
            bucket_suffix: env::var("S3_BUCKET_SUFFIX").ok(),
        })
    }

    #[tracing::instrument(skip(self), err)]
    pub async fn open_or_create_bucket(&self, name: &str) -> anyhow::Result<Box<Bucket>> {
        let effective_name = match &self.bucket_suffix {
            Some(suffix) => format!("{}.{}", name, suffix),
            None => name.to_owned(),
        };

        let mut bucket = Bucket::new(
            &effective_name,
            self.region.clone(),
            self.credentials.clone(),
        )
        .with_context(|| format!("Failed accessing bucket '{}'", effective_name))?;

        bucket.set_path_style();

        if !bucket
            .exists()
            .await
            .with_context(|| format!("Failed to check if bucket '{}' exists", effective_name))?
        {
            tracing::info!("Bucket does not exist, creating...");
            Bucket::create_with_path_style(
                &effective_name,
                self.region.clone(),
                self.credentials.clone(),
                BucketConfiguration::private(),
            )
            .await
            .with_context(|| format!("Failed to create bucket '{}'", effective_name))?;
        } else {
            tracing::info!("Bucket '{}' does already exist", effective_name);
        }

        Ok(bucket)
    }
}
