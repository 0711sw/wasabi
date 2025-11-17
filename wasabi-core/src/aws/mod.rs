#[cfg(feature = "aws_bedrock")]
pub mod bedrock;
#[cfg(feature = "aws_dynamodb")]
pub mod dynamodb;
#[cfg(feature = "aws_s3")]
pub mod s3;

#[cfg(test)]
pub mod test {
    use rand::random;

    pub fn test_run_id() -> String {
        let unique_id = random::<u32>();
        if let Ok(run) = std::env::var("TEST_RUN_ID") {
            format!("{}-{}", run, unique_id)
        } else {
            format!("{}", unique_id)
        }
    }
}
