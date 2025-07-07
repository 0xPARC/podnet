use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

#[derive(Debug, Clone, PartialEq)]
pub enum DocumentFormat {
    Markdown,
    Latex,
    Typst,
}

impl DocumentFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "markdown" | "md" => Some(Self::Markdown),
            "latex" | "tex" => Some(Self::Latex),
            "typst" | "typ" => Some(Self::Typst),
            _ => None,
        }
    }

    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "md" | "markdown" => Some(Self::Markdown),
            "tex" | "latex" => Some(Self::Latex),
            "typ" | "typst" => Some(Self::Typst),
            _ => None,
        }
    }
}

/// Auto-detect document format from content
pub fn detect_format(content: &str, file_path: Option<&str>) -> DocumentFormat {
    // First try to detect from file extension
    if let Some(path) = file_path {
        if let Some(ext) = std::path::Path::new(path).extension() {
            if let Some(format) = DocumentFormat::from_extension(&ext.to_string_lossy()) {
                return format;
            }
        }
    }

    // Fallback to content-based detection
    detect_format_from_content(content)
}

/// Detect format based on content patterns
fn detect_format_from_content(content: &str) -> DocumentFormat {
    let content = content.trim();

    // LaTeX indicators
    if content.contains("\\documentclass")
        || content.contains("\\begin{document}")
        || content.contains("\\section")
        || content.contains("\\subsection")
        || content.contains("\\usepackage")
    {
        return DocumentFormat::Latex;
    }

    // Typst indicators
    if content.contains("#let")
        || content.contains("#import")
        || content.contains("#show")
        || content.contains("#set")
        || content.starts_with("#")
    {
        return DocumentFormat::Typst;
    }

    // Default to Markdown
    DocumentFormat::Markdown
}

/// Convert document content to Markdown
pub fn convert_to_markdown(
    content: &str,
    format: &DocumentFormat,
) -> Result<String, Box<dyn std::error::Error>> {
    match format {
        DocumentFormat::Markdown => Ok(content.to_string()),
        DocumentFormat::Latex => latex_to_markdown(content),
        DocumentFormat::Typst => typst_to_markdown(content),
    }
}

/// Convert LaTeX to Markdown using pandoc
fn latex_to_markdown(latex_content: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Check if pandoc is available
    let pandoc_check = Command::new("pandoc").arg("--version").output();

    if pandoc_check.is_err() {
        return Err(
            "pandoc is not installed. Please install pandoc to convert LaTeX files.".into(),
        );
    }

    // Create temporary file for LaTeX content
    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(latex_content.as_bytes())?;
    let temp_path = temp_file.path();

    // Run pandoc conversion
    let output = Command::new("pandoc")
        .arg("-f")
        .arg("latex")
        .arg("-t")
        .arg("markdown")
        .arg("--wrap=none") // Don't wrap lines
        .arg("--standalone") // Include necessary headers
        .arg(temp_path)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("pandoc conversion failed: {stderr}").into());
    }

    let markdown = String::from_utf8(output.stdout)?;
    Ok(markdown)
}

/// Convert Typst to Markdown (placeholder for future LLM integration)
fn typst_to_markdown(typst_content: &str) -> Result<String, Box<dyn std::error::Error>> {
    // For now, return a placeholder indicating Typst conversion isn't fully supported
    let markdown = format!(
        "# Document converted from Typst\n\n> **Note**: This document was originally written in Typst. Full conversion to Markdown is not yet supported.\n\n```typst\n{typst_content}\n```"
    );
    Ok(markdown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_detection() {
        let latex_content = r"\documentclass{article}
\begin{document}
Hello world!
\end{document}";
        assert_eq!(
            detect_format_from_content(latex_content),
            DocumentFormat::Latex
        );

        let typst_content = r"#let title = [My Document]
#show heading: set text(blue)
= Introduction";
        assert_eq!(
            detect_format_from_content(typst_content),
            DocumentFormat::Typst
        );

        let markdown_content = r"# Hello World
This is **markdown**.";
        assert_eq!(
            detect_format_from_content(markdown_content),
            DocumentFormat::Markdown
        );
    }

    #[test]
    fn test_extension_detection() {
        assert_eq!(
            DocumentFormat::from_extension("tex"),
            Some(DocumentFormat::Latex)
        );
        assert_eq!(
            DocumentFormat::from_extension("typ"),
            Some(DocumentFormat::Typst)
        );
        assert_eq!(
            DocumentFormat::from_extension("md"),
            Some(DocumentFormat::Markdown)
        );
    }
}
