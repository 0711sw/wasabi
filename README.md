# wasabi
A tiny rust-based framework to provide microservices in containerized environments

## Features

We split the framework into several features to minimize dependencies and thus 
compile time. The features are:

### pretty_logs


= ["nu-ansi-term"]
open_telemetry = ["opentelemetry", "opentelemetry-otlp", "opentelemetry_sdk", "tracing-opentelemetry"]
aws_s3 = ["aws-config", "aws-sdk-s3"]
aws_dynamodb = ["aws-config", "aws-sdk-dynamodb"]