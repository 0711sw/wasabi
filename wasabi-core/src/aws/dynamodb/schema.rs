//! Schema builder helpers for DynamoDB table creation.
//!
//! Provides ergonomic functions for defining table schemas, key structures,
//! and global secondary indexes (GSIs).
//!
//! # Example
//!
//! ```rust,ignore
//! use wasabi_core::aws::dynamodb::schema::*;
//!
//! client.create_table("events", |builder| {
//!     let builder = builder
//!         .attribute_definitions(str_attribute("PK")?)
//!         .attribute_definitions(str_attribute("SK")?)
//!         .attribute_definitions(str_attribute("GSI1PK")?)
//!         .attribute_definitions(numeric_attribute("GSI1SK")?);
//!
//!     let builder = with_range_index(builder, "PK", "SK")?;
//!
//!     Ok(builder
//!         .global_secondary_indexes(replicated_range_index("GSI1", "GSI1PK", "GSI1SK")?)
//!         .billing_mode(BillingMode::PayPerRequest))
//! }).await?;
//! ```

use aws_sdk_dynamodb::error::BuildError;
use aws_sdk_dynamodb::operation::create_table::builders::CreateTableFluentBuilder;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
    ProjectionType, ScalarAttributeType,
};

/// Creates a string attribute definition.
pub fn str_attribute(name: &str) -> Result<AttributeDefinition, BuildError> {
    AttributeDefinition::builder()
        .attribute_name(name)
        .attribute_type(ScalarAttributeType::S)
        .build()
}
/// Creates a numeric attribute definition.
pub fn numeric_attribute(name: &str) -> Result<AttributeDefinition, BuildError> {
    AttributeDefinition::builder()
        .attribute_name(name)
        .attribute_type(ScalarAttributeType::N)
        .build()
}

/// Adds a hash-only primary key to the table.
///
/// Use this for tables where each item has a unique partition key with no sort key.
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

/// Adds a composite primary key (hash + range) to the table.
///
/// Use this for tables where items are grouped by partition key and ordered by sort key.
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

/// Creates a GSI with composite key and full item projection.
///
/// The index replicates all attributes (`ProjectionType::All`), enabling
/// queries on the GSI to return complete items without table lookups.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn str_attribute_creates_string_type() {
        let attr = str_attribute("PK").unwrap();
        assert_eq!(attr.attribute_name(), "PK");
        assert_eq!(attr.attribute_type(), &ScalarAttributeType::S);
    }

    #[test]
    fn numeric_attribute_creates_number_type() {
        let attr = numeric_attribute("timestamp").unwrap();
        assert_eq!(attr.attribute_name(), "timestamp");
        assert_eq!(attr.attribute_type(), &ScalarAttributeType::N);
    }

    #[test]
    fn replicated_range_index_creates_gsi_with_projection_all() {
        let gsi = replicated_range_index("GSI1", "GSI1PK", "GSI1SK").unwrap();

        assert_eq!(gsi.index_name(), "GSI1");

        let keys: Vec<_> = gsi.key_schema().iter().collect();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].attribute_name(), "GSI1PK");
        assert_eq!(keys[0].key_type(), &KeyType::Hash);
        assert_eq!(keys[1].attribute_name(), "GSI1SK");
        assert_eq!(keys[1].key_type(), &KeyType::Range);

        assert_eq!(
            gsi.projection().unwrap().projection_type(),
            Some(&ProjectionType::All)
        );
    }
}
