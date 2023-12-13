use locator::Locator;
use non_empty_string::NonEmptyString;
use serde::{Deserialize, Serialize};
use typed_builder::TypedBuilder;

#[derive(Debug, Serialize, Deserialize, TypedBuilder)]
pub struct VulnComponentEntry {
    cve: NonEmptyString,
    dependency_revision_id: Locator,
    function: String,
    researcher: NonEmptyString,
    evidence_notes: Option<String>,
    file_path: Option<String>,
    line_start: Option<u32>,
}
