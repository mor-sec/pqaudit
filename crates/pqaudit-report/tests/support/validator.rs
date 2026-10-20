//! The CycloneDX 1.6 schema check. Several test crates share this file.

use serde_json::Value;

/// Read the schema files that the CycloneDX schema names with a URI.
struct LocalSchemas;

impl jsonschema::Retrieve for LocalSchemas {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let name = uri.path().as_str().rsplit('/').next().unwrap_or_default();
        let path = schema_dir().join(name);
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }
}

/// The vendored schema files. The path starts at the crate of the test, so it works from every crate.
fn schema_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../pqaudit-report/tests/schema")
}

/// Build a validator for CycloneDX 1.6.
pub fn validator() -> jsonschema::Validator {
    let text = std::fs::read_to_string(schema_dir().join("bom-1.6.schema.json")).unwrap();
    let schema: Value = serde_json::from_str(&text).unwrap();
    jsonschema::options()
        .with_retriever(LocalSchemas)
        .build(&schema)
        .expect("the schema is valid")
}
