//! YAML-based taint configuration loader
//!
//! This module provides functionality to load taint analysis configurations
//! from YAML files, following the Models as Data (MaD) format inspired by CodeQL.

use serde::Deserialize;
use std::path::Path;
use std::collections::HashMap;

/// Root structure for a taint configuration YAML file
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TaintConfigYaml {
    #[serde(default)]
    pub sources: Vec<SourceConfig>,
    #[serde(default)]
    pub sinks: Vec<SinkConfig>,
    #[serde(default)]
    pub sanitizers: Vec<SanitizerConfig>,
    #[serde(default)]
    pub summaries: Vec<SummaryConfig>,
}

/// Configuration for a taint source
#[derive(Debug, Clone, Deserialize)]
pub struct SourceConfig {
    pub name: String,
    pub kind: SourceKind,
    #[serde(default)]
    pub package: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// Configuration for a taint sink
#[derive(Debug, Clone, Deserialize)]
pub struct SinkConfig {
    pub name: String,
    pub kind: SinkKind,
    #[serde(default)]
    pub package: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub argument: Option<usize>,
}

/// Configuration for a sanitizer
#[derive(Debug, Clone, Deserialize)]
pub struct SanitizerConfig {
    pub name: String,
    pub sanitizes: Vec<SanitizeKind>,
    #[serde(default)]
    pub package: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// Configuration for a flow summary (how taint propagates through functions)
#[derive(Debug, Clone, Deserialize)]
pub struct SummaryConfig {
    pub name: String,
    #[serde(default)]
    pub package: Option<String>,
    pub input: String,
    pub output: String,
    pub kind: SummaryKind,
}

/// Source kinds (where tainted data enters)
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
pub enum SourceKind {
    UserInput,
    Environment,
    Database,
    File,
    Network,
    Config,
}

/// Sink kinds (where tainted data becomes dangerous)
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
pub enum SinkKind {
    SqlQuery,
    CommandExecution,
    FileWrite,
    CodeEval,
    HtmlOutput,
    LogOutput,
    NetworkSend,
    PathTraversal,
    Deserialization,
    LdapQuery,
    XPathQuery,
    XmlParse,
    TrustBoundary,
    ReDoS,
}

/// What kinds of taint a sanitizer removes
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
pub enum SanitizeKind {
    Html,
    Sql,
    Shell,
    Path,
    All,
}

impl SanitizeKind {
    /// Convert to FlowState for integration with taint analysis
    pub fn to_flow_state(&self) -> Option<crate::taint::FlowState> {
        match self {
            SanitizeKind::Html => Some(crate::taint::FlowState::Html),
            SanitizeKind::Sql => Some(crate::taint::FlowState::Sql),
            SanitizeKind::Shell => Some(crate::taint::FlowState::Shell),
            SanitizeKind::Path => Some(crate::taint::FlowState::Path),
            SanitizeKind::All => None, // All means universal, represented by empty set
        }
    }
}

/// How taint flows through a function
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SummaryKind {
    /// Tainted input produces tainted output (data derived from input)
    Taint,
    /// Exact value copy
    Value,
}

/// Errors that can occur when loading YAML configs
#[derive(Debug, thiserror::Error)]
pub enum YamlConfigError {
    #[error("Failed to read config file: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Failed to parse YAML: {0}")]
    YamlError(#[from] serde_yaml::Error),
    #[error("Config file not found: {0}")]
    NotFound(String),
}

impl TaintConfigYaml {
    /// Load configuration from a YAML file
    pub fn from_file(path: &Path) -> Result<Self, YamlConfigError> {
        if !path.exists() {
            return Err(YamlConfigError::NotFound(path.display().to_string()));
        }
        let content = std::fs::read_to_string(path)?;
        let config: TaintConfigYaml = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Load configuration from a YAML string
    pub fn from_str(yaml: &str) -> Result<Self, YamlConfigError> {
        let config: TaintConfigYaml = serde_yaml::from_str(yaml)?;
        Ok(config)
    }

    /// Merge another config into this one
    pub fn merge(&mut self, other: TaintConfigYaml) {
        self.sources.extend(other.sources);
        self.sinks.extend(other.sinks);
        self.sanitizers.extend(other.sanitizers);
        self.summaries.extend(other.summaries);
    }

    /// Check if a function name matches a source pattern
    pub fn is_source(&self, name: &str) -> bool {
        self.sources.iter().any(|s| name.contains(&s.name) || name.ends_with(&s.name))
    }

    /// Check if a function name matches a sink pattern
    pub fn is_sink(&self, name: &str) -> bool {
        self.sinks.iter().any(|s| name.contains(&s.name) || name.ends_with(&s.name))
    }

    /// Check if a function name matches a sanitizer pattern
    pub fn is_sanitizer(&self, name: &str) -> bool {
        self.sanitizers.iter().any(|s| name.contains(&s.name) || name.ends_with(&s.name))
    }

    /// Get source config for a function name
    pub fn get_source(&self, name: &str) -> Option<&SourceConfig> {
        self.sources.iter().find(|s| name.contains(&s.name) || name.ends_with(&s.name))
    }

    /// Get sink config for a function name
    pub fn get_sink(&self, name: &str) -> Option<&SinkConfig> {
        self.sinks.iter().find(|s| name.contains(&s.name) || name.ends_with(&s.name))
    }

    /// Get sanitizer config for a function name
    pub fn get_sanitizer(&self, name: &str) -> Option<&SanitizerConfig> {
        self.sanitizers.iter().find(|s| name.contains(&s.name) || name.ends_with(&s.name))
    }

    /// Get flow summary for a function name
    pub fn get_summary(&self, name: &str) -> Option<&SummaryConfig> {
        self.summaries.iter().find(|s| name.contains(&s.name) || name.ends_with(&s.name))
    }

    /// Get the FlowStates that a sanitizer is effective for.
    /// Returns None if not a sanitizer, Some(empty HashSet) for universal sanitizers (All),
    /// or Some(states) for context-specific sanitizers.
    pub fn get_sanitizer_flow_states(&self, name: &str) -> Option<std::collections::HashSet<crate::taint::FlowState>> {
        let sanitizer = self.get_sanitizer(name)?;
        let mut states = std::collections::HashSet::new();

        for kind in &sanitizer.sanitizes {
            match kind.to_flow_state() {
                Some(state) => { states.insert(state); }
                None => {
                    // SanitizeKind::All - return empty set to indicate universal
                    return Some(std::collections::HashSet::new());
                }
            }
        }

        Some(states)
    }
}

/// Registry of taint configurations for all languages
#[derive(Debug, Default)]
pub struct TaintConfigRegistry {
    configs: HashMap<String, TaintConfigYaml>,
}

impl TaintConfigRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            configs: HashMap::new(),
        }
    }

    /// Load all configs from the models directory
    pub fn load_from_dir(models_dir: &Path) -> Result<Self, YamlConfigError> {
        let mut registry = Self::new();

        if !models_dir.exists() {
            return Ok(registry);
        }

        // Load language-specific configs
        for entry in std::fs::read_dir(models_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                let lang_name = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_string();

                // Load core.yaml for each language
                let core_path = path.join("core.yaml");
                if core_path.exists() {
                    let config = TaintConfigYaml::from_file(&core_path)?;
                    registry.configs.insert(lang_name.clone(), config);
                }

                // TODO: Load framework-specific configs and merge them
            }
        }

        Ok(registry)
    }

    /// Get config for a specific language
    pub fn get(&self, language: &str) -> Option<&TaintConfigYaml> {
        self.configs.get(language)
    }

    /// Get config for a specific language, with fallback to empty config
    pub fn get_or_default(&self, language: &str) -> TaintConfigYaml {
        self.configs.get(language).cloned().unwrap_or_default()
    }

    /// Get all registered language names
    pub fn languages(&self) -> impl Iterator<Item = &String> {
        self.configs.keys()
    }

    /// Register a config for a language
    pub fn register(&mut self, language: String, config: TaintConfigYaml) {
        self.configs.insert(language, config);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_source_config() {
        let yaml = r#"
sources:
  - name: "getParameter"
    kind: UserInput
    package: "javax.servlet.http.HttpServletRequest"
    description: "HTTP request parameter"
"#;
        let config = TaintConfigYaml::from_str(yaml).unwrap();
        assert_eq!(config.sources.len(), 1);
        assert_eq!(config.sources[0].name, "getParameter");
        assert_eq!(config.sources[0].kind, SourceKind::UserInput);
    }

    #[test]
    fn test_parse_sink_config() {
        let yaml = r#"
sinks:
  - name: "executeQuery"
    kind: SqlQuery
    description: "SQL query execution"
    argument: 0
"#;
        let config = TaintConfigYaml::from_str(yaml).unwrap();
        assert_eq!(config.sinks.len(), 1);
        assert_eq!(config.sinks[0].name, "executeQuery");
        assert_eq!(config.sinks[0].kind, SinkKind::SqlQuery);
        assert_eq!(config.sinks[0].argument, Some(0));
    }

    #[test]
    fn test_parse_sanitizer_config() {
        let yaml = r#"
sanitizers:
  - name: "escapeHtml"
    sanitizes: [Html]
    description: "HTML escape"
"#;
        let config = TaintConfigYaml::from_str(yaml).unwrap();
        assert_eq!(config.sanitizers.len(), 1);
        assert_eq!(config.sanitizers[0].name, "escapeHtml");
        assert_eq!(config.sanitizers[0].sanitizes, vec![SanitizeKind::Html]);
    }

    #[test]
    fn test_parse_summary_config() {
        let yaml = r#"
summaries:
  - name: "concat"
    package: "java.lang.String"
    input: "Argument[0]"
    output: "ReturnValue"
    kind: taint
"#;
        let config = TaintConfigYaml::from_str(yaml).unwrap();
        assert_eq!(config.summaries.len(), 1);
        assert_eq!(config.summaries[0].name, "concat");
        assert_eq!(config.summaries[0].kind, SummaryKind::Taint);
    }

    #[test]
    fn test_is_source() {
        let yaml = r#"
sources:
  - name: "getParameter"
    kind: UserInput
"#;
        let config = TaintConfigYaml::from_str(yaml).unwrap();
        assert!(config.is_source("request.getParameter"));
        assert!(config.is_source("getParameter"));
        assert!(!config.is_source("setParameter"));
    }

    #[test]
    fn test_merge_configs() {
        let yaml1 = r#"
sources:
  - name: "source1"
    kind: UserInput
"#;
        let yaml2 = r#"
sources:
  - name: "source2"
    kind: File
"#;
        let mut config1 = TaintConfigYaml::from_str(yaml1).unwrap();
        let config2 = TaintConfigYaml::from_str(yaml2).unwrap();
        config1.merge(config2);
        assert_eq!(config1.sources.len(), 2);
    }
}
