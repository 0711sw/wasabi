use anyhow::Context;
use aws_sdk_s3::types::{BucketLocationConstraint, CreateBucketConfiguration};
use aws_sdk_s3::{Client, config};
use std::env;

#[derive(Clone, Debug)]
pub struct S3Client {
    pub client: Client,
    bucket_suffix: Option<String>,
}

impl S3Client {
    pub async fn from_env() -> anyhow::Result<S3Client> {
        tracing::info!("Setting up S3....");
        let config = aws_config::load_from_env().await;

        let s3_config = config::Builder::from(&config)
            .force_path_style(true)
            .build();

        let client = Client::from_conf(s3_config);

        Ok(S3Client {
            client,
            bucket_suffix: env::var("S3_BUCKET_SUFFIX").ok(),
        })
    }

    pub fn effective_name(&self, bucket: &str) -> String {
        match &self.bucket_suffix {
            Some(suffix) => format!("{}.{}", bucket, suffix),
            None => bucket.to_owned(),
        }
    }

    #[tracing::instrument(skip(self), err(Display))]
    pub async fn does_bucket_exist(&self, name: &str) -> anyhow::Result<bool> {
        let effective_name = self.effective_name(name);

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
    #[tracing::instrument(skip(self), err(Display))]
    pub async fn create_bucket(&self, name: &str) -> anyhow::Result<()> {
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

            self.client
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

    #[tracing::instrument(level = "debug", skip(self), ret(Debug), err(Display))]
    pub async fn delete_object(&self, bucket: &str, key: &str) -> anyhow::Result<()> {
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
}

#[cfg(test)]
mod tests {
    use crate::aws::s3::S3Client;
    use crate::aws::test::test_run_id;
    use std::env;

    #[tokio::test]
    #[ignore]
    async fn does_bucket_exist_detects_nonexistent_bucket() {
        unsafe {
            env::set_var("S3_BUCKET_SUFFIX", "wasabi-test.0711sw.net");
        }

        let s3_client = S3Client::from_env().await.unwrap();
        let bucket_name = "non-existent-bucket";

        assert!(!s3_client.does_bucket_exist(bucket_name).await.unwrap());
    }

    #[tokio::test]
    #[ignore]
    async fn create_bucket_creates_bucket_if_non_existent() {
        unsafe {
            env::set_var("S3_BUCKET_SUFFIX", "wasabi-test.0711sw.net");
        }

        let s3_client = S3Client::from_env().await.unwrap();
        let bucket_name = format!("test-bucket-{}", test_run_id());

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
