use locator::Locator;
use non_empty_string::NonEmptyString;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationVulnComponentEntry {
    pub cve: NonEmptyString,
    pub dependency_revision_id: Locator,
    pub function: String,
    pub researcher: NonEmptyString,
    pub evidence_notes: Option<String>,
    pub file_path: Option<String>,
    pub line_start: Option<u32>,
}
