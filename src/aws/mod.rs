#[cfg(feature = "aws_dynamodb")]
pub mod dynamodb;
#[cfg(feature = "aws_s3")]
pub mod s3;

#[cfg(test)]
mod test {
    use rand::random;

    #[macro_export]
    macro_rules! aws_rdy {
        () => {
            if let Some(provider) = aws_config::load_from_env().await.credentials_provider() {
                use aws_sdk_s3::config::ProvideCredentials;
                if provider.provide_credentials().await.is_err() {
                    println!("Skipping test: No AWS credentials found");
                    return;
                }
            } else {
                println!("Skipping test: No AWS credentials provider found");
                return;
            }
        };
    }

    pub fn test_run_id() -> String {
        let unique_id = random::<u32>();
        if let Ok(run) = std::env::var("TEST_RUN_ID") {
            format!("{}-{}", run, unique_id)
        } else {
            format!("{}", unique_id)
        }
    }
}
