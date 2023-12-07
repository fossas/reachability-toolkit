use anyhow::Result;
use locator::Locator;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Serialize, Deserialize)]
pub struct VulnComponentBatch {
    pub entries: Vec<VulnComponentEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VulnComponentEntry {
    #[serde(deserialize_with = "non_empty_string")]
    pub cve: String,
    pub dependency_revision_id: Locator,

    #[serde(serialize_with = "as_json_str")]
    pub function: SymbolTarget,

    #[serde(deserialize_with = "non_empty_string")]
    pub researcher: String,
    pub evidence_notes: Option<String>,
    pub file_path: Option<String>,
    pub line_start: Option<u32>,
}

// TODO: This should be using same type as reachability lib
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind")]
pub enum SymbolTarget {
    #[serde(rename = "java")]
    Java {
        #[serde(deserialize_with = "parse_java_symbols")]
        symbol: Vec<SymbolJava>,
    },
}

// TODO: This should be using same type as reachability lib
#[derive(Debug, Serialize, PartialEq)]
#[serde(tag = "kind")]
pub enum SymbolJava {
    #[serde(rename = "package")]
    Package { label: String },
    #[serde(rename = "class")]
    Class { label: String },
    #[serde(rename = "class_method")]
    ClassMethod { label: String },
    #[serde(rename = "constructor")]
    Constructor { label: String },
}

fn parse_symbol_java(input: &str) -> Option<SymbolJava> {
    let mut parts = input.split("::");
    let kind_label_pair = parts.next()?;
    let Some((kind, label)) = kind_label_pair.split_once('(') else {
        return None;
    };

    let kind = kind.trim();
    let label = label.trim_end_matches(')');

    match kind {
        "Package" => Some(SymbolJava::Package {
            label: label.to_string(),
        }),
        "Class" => Some(SymbolJava::Class {
            label: label.to_string(),
        }),
        "ClassMethod" => Some(SymbolJava::ClassMethod {
            label: label.to_string(),
        }),
        "Constructor" => Some(SymbolJava::Constructor {
            label: label.to_string(),
        }),
        _ => None,
    }
}

/// Deserialize non-empty string
/// Error when string is empty or only contains whitespace
fn non_empty_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.is_empty() {
        return Err(D::Error::custom(
            "Empty string is not allowed, provide non-empty string",
        ));
    }
    Ok(s)
}

/// Parses java symbol from non-empty string
fn parse_java_symbols<'de, D>(deserializer: D) -> Result<Vec<SymbolJava>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if !s.is_empty() {
        let symbols: Vec<SymbolJava> = s.split("::").filter_map(parse_symbol_java).collect();
        if !symbols.is_empty() {
            return Ok(symbols);
        }
    }

    Err(Error::invalid_value(
        serde::de::Unexpected::Str(s.as_str()),
        &"fully qualified symbol path: Class(SomeClassName)::ClassMethod(SomeClassMethod)",
    ))
}

/// Serializes `value` as into JSON string.
fn as_json_str<S>(value: impl Serialize, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&serde_json::to_string(&value).map_err(serde::ser::Error::custom)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[
        test_case("Class(Logger)::ClassMethod(log)", 
        vec![
            SymbolJava::Class {label: "Logger".to_string() }, 
            SymbolJava::ClassMethod { label: "log".to_string() }
        ]
    )]
    #[
        test_case("Class(Logger)", 
        vec![
            SymbolJava::Class {label: "Logger".to_string() }, 
        ]
    )]
    fn parse_java_symbols_works(arg: &str, expected: Vec<SymbolJava>) {
        let json_string = format!(
            r#"
            {{
                "kind": "java",
                "symbol": "{}"
            }}
        "#,
            arg
        );

        let symbol: SymbolTarget = serde_json::from_str(&json_string).unwrap();
        assert_eq!(symbol, SymbolTarget::Java { symbol: expected })
    }
}
