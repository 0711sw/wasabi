# wasabi
A tiny rust-based framework to provide microservices in containerized environments

## Features

We split the framework into several features to minimize dependencies and thus 
compile time. The features are:

### pretty_logs

Renders colorful console outputs for opentelemetry spans.

### open_telemetry

Provides some tooling to set-up opentelemetry for tracing.

### aws_s3

Provide some helpers to interact with AWS S3.

### aws_dynamodb

Provides some tooling to interact with AWS DynamoDB.

### aws_firehose

Provides an EventRecorder which sends events to AWS Firehose.

### aws_bedrock

Provides some tooling to interact with AWS Bedrock.

### open_search

Provides some tooling to talk to AWS OpenSearch clusters.

---

## License

This project is licensed under the **MIT License**.