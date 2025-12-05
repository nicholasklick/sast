//! Language support and configuration

use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LanguageError {
    #[error("Unsupported language: {0}")]
    UnsupportedLanguage(String),
    #[error("Failed to detect language for file: {0}")]
    DetectionFailed(String),
}

/// Supported programming languages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Java,
    Go,
    C,
    Cpp,
    CSharp,
    Ruby,
    Php,
    Swift,
    Kotlin,
    Scala,
    Groovy,
    Lua,
    Perl,
}

impl Language {
    /// Detect language from file extension
    pub fn from_path(path: &Path) -> Result<Self, LanguageError> {
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .ok_or_else(|| LanguageError::DetectionFailed(path.display().to_string()))?;

        match extension {
            "rs" => Ok(Language::Rust),
            "py" | "pyw" => Ok(Language::Python),
            "js" | "mjs" | "cjs" => Ok(Language::JavaScript),
            "ts" => Ok(Language::TypeScript),
            "java" => Ok(Language::Java),
            "go" => Ok(Language::Go),
            "c" | "h" => Ok(Language::C),
            "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx" => Ok(Language::Cpp),
            "cs" => Ok(Language::CSharp),
            "rb" => Ok(Language::Ruby),
            "php" => Ok(Language::Php),
            "swift" => Ok(Language::Swift),
            "kt" | "kts" => Ok(Language::Kotlin),
            "scala" | "sc" => Ok(Language::Scala),
            "groovy" | "gradle" | "gvy" | "gy" | "gsh" => Ok(Language::Groovy),
            "lua" => Ok(Language::Lua),
            "pl" | "pm" | "t" | "cgi" => Ok(Language::Perl),
            _ => Err(LanguageError::UnsupportedLanguage(extension.to_string())),
        }
    }

    /// Get the tree-sitter language parser
    pub fn tree_sitter_language(&self) -> tree_sitter::Language {
        match self {
            Language::Rust => tree_sitter_rust::LANGUAGE.into(),
            Language::Python => tree_sitter_python::LANGUAGE.into(),
            Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Language::Java => tree_sitter_java::LANGUAGE.into(),
            Language::Go => tree_sitter_go::LANGUAGE.into(),
            Language::C => tree_sitter_c::LANGUAGE.into(),
            Language::Cpp => tree_sitter_cpp::LANGUAGE.into(),
            Language::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
            Language::Ruby => tree_sitter_ruby::LANGUAGE.into(),
            Language::Php => tree_sitter_php::LANGUAGE_PHP.into(),
            Language::Swift => tree_sitter_swift::LANGUAGE.into(),
            Language::Kotlin => tree_sitter_kotlin_ng::LANGUAGE.into(),
            Language::Scala => tree_sitter_scala::LANGUAGE.into(),
            Language::Groovy => tree_sitter_groovy::LANGUAGE.into(),
            Language::Lua => tree_sitter_lua::LANGUAGE.into(),
            Language::Perl => tree_sitter_perl::LANGUAGE.into(),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Language::Rust => "Rust",
            Language::Python => "Python",
            Language::JavaScript => "JavaScript",
            Language::TypeScript => "TypeScript",
            Language::Java => "Java",
            Language::Go => "Go",
            Language::C => "C",
            Language::Cpp => "C++",
            Language::CSharp => "C#",
            Language::Ruby => "Ruby",
            Language::Php => "PHP",
            Language::Swift => "Swift",
            Language::Kotlin => "Kotlin",
            Language::Scala => "Scala",
            Language::Groovy => "Groovy",
            Language::Lua => "Lua",
            Language::Perl => "Perl",
        }
    }

    pub fn file_extensions(&self) -> &[&str] {
        match self {
            Language::Rust => &["rs"],
            Language::Python => &["py", "pyw"],
            Language::JavaScript => &["js", "mjs", "cjs"],
            Language::TypeScript => &["ts"],
            Language::Java => &["java"],
            Language::Go => &["go"],
            Language::C => &["c", "h"],
            Language::Cpp => &["cpp", "cc", "cxx", "hpp", "hh", "hxx"],
            Language::CSharp => &["cs"],
            Language::Ruby => &["rb"],
            Language::Php => &["php"],
            Language::Swift => &["swift"],
            Language::Kotlin => &["kt", "kts"],
            Language::Scala => &["scala", "sc"],
            Language::Groovy => &["groovy", "gradle", "gvy", "gy", "gsh"],
            Language::Lua => &["lua"],
            Language::Perl => &["pl", "pm", "t", "cgi"],
        }
    }
}

/// Language-specific configuration
#[derive(Debug, Clone)]
pub struct LanguageConfig {
    pub language: Language,
    pub include_comments: bool,
    pub max_file_size: usize,
}

impl Default for LanguageConfig {
    fn default() -> Self {
        Self {
            language: Language::Rust,
            include_comments: false,
            max_file_size: 10 * 1024 * 1024, // 10 MB
        }
    }
}

impl LanguageConfig {
    pub fn new(language: Language) -> Self {
        Self {
            language,
            ..Default::default()
        }
    }

    pub fn with_comments(mut self, include: bool) -> Self {
        self.include_comments = include;
        self
    }

    pub fn with_max_file_size(mut self, size: usize) -> Self {
        self.max_file_size = size;
        self
    }
}
