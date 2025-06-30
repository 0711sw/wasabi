use aws_sdk_dynamodb::error::BuildError;
use aws_sdk_dynamodb::operation::create_table::builders::CreateTableFluentBuilder;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
    ProjectionType, ScalarAttributeType,
};

pub fn str_attribute(name: &str) -> Result<AttributeDefinition, BuildError> {
    AttributeDefinition::builder()
        .attribute_name(name)
        .attribute_type(ScalarAttributeType::S)
        .build()
}
pub fn numeric_attribute(name: &str) -> Result<AttributeDefinition, BuildError> {
    AttributeDefinition::builder()
        .attribute_name(name)
        .attribute_type(ScalarAttributeType::N)
        .build()
}

pub fn with_hash_index(
    builder: CreateTableFluentBuilder,
    hash_attribute: &str,
) -> Result<CreateTableFluentBuilder, BuildError> {
    Ok(builder.key_schema(
        KeySchemaElement::builder()
            .attribute_name(hash_attribute)
            .key_type(KeyType::Hash)
            .build()?,
    ))
}

pub fn with_range_index(
    builder: CreateTableFluentBuilder,
    hash_attribute: &str,
    range_attribute: &str,
) -> Result<CreateTableFluentBuilder, BuildError> {
    Ok(builder
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name(hash_attribute)
                .key_type(KeyType::Hash)
                .build()?,
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name(range_attribute)
                .key_type(KeyType::Range)
                .build()?,
        ))
}

pub fn replicated_range_index(
    index_name: &str,
    hash_attribute: &str,
    range_attribute: &str,
) -> Result<GlobalSecondaryIndex, BuildError> {
    GlobalSecondaryIndex::builder()
        .index_name(index_name)
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name(hash_attribute)
                .key_type(KeyType::Hash)
                .build()?,
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name(range_attribute)
                .key_type(KeyType::Range)
                .build()?,
        )
        .projection(
            Projection::builder()
                .projection_type(ProjectionType::All)
                .build(),
        )
        .build()
}
