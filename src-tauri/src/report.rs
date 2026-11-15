//! Filesystem side of the audit report export.
//!
//! The UI renders the report from state it already holds (burst and fuzz reports, proxy and
//! lab status); the engine only names, bounds and writes the file. Keeping the write in Rust
//! means the webview needs neither an `fs` nor a `dialog` capability.

use std::path::Path;

use crate::engine::error::{EngineError, EngineResult};
use crate::engine::types::ReportFormat;
use crate::scanner::routes;

/// A report with 100 burst samples and a full fuzz finding list stays far below this; the
/// cap only stops a runaway payload from becoming a multi-gigabyte write.
pub const MAX_REPORT_BYTES: usize = 32 * 1024 * 1024;

const FALLBACK_STEM: &str = "z-proxy-audit";
/// Reserved on Windows, and never meaningful in a suggested name on any platform.
const FORBIDDEN: &str = r#"<>:"/\|?*"#;

impl ReportFormat {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Markdown => "md",
            Self::Json => "json",
        }
    }

    pub fn filter_label(self) -> &'static str {
        match self {
            Self::Markdown => "Markdown",
            Self::Json => "JSON",
        }
    }
}

/// Name pre-filled in the save dialog: the last component of `requested`, stripped of
/// characters a file name cannot hold, with the format's extension.
pub fn file_name(format: ReportFormat, requested: &str) -> String {
    let extension = format.extension();
    let last = requested.rsplit(['/', '\\']).next().unwrap_or_default();
    let clean: String = last
        .chars()
        .filter(|c| !c.is_control() && !FORBIDDEN.contains(*c))
        .collect();
    let suffix = format!(".{extension}");
    let stem = clean
        .strip_suffix(&suffix)
        .unwrap_or(&clean)
        .trim_matches(|c: char| c == '.' || c.is_whitespace());
    if stem.is_empty() {
        format!("{FALLBACK_STEM}{suffix}")
    } else {
        format!("{stem}{suffix}")
    }
}

pub fn check_size(contents: &str) -> EngineResult<()> {
    if contents.len() > MAX_REPORT_BYTES {
        return Err(EngineError::ReportExport {
            path: None,
            reason: format!(
                "{} bytes exceeds the {MAX_REPORT_BYTES} byte limit",
                contents.len()
            ),
        });
    }
    Ok(())
}

pub fn write(path: &Path, contents: &[u8]) -> EngineResult<()> {
    std::fs::write(path, contents).map_err(|err| EngineError::ReportExport {
        path: Some(routes::display_path(path)),
        reason: err.to_string(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn suggested_names_are_single_components_with_the_right_extension() {
        let md = ReportFormat::Markdown;
        let json = ReportFormat::Json;
        assert_eq!(
            file_name(md, "z-proxy-audit-20261115-183000.md"),
            "z-proxy-audit-20261115-183000.md"
        );
        assert_eq!(file_name(json, "run-42"), "run-42.json");
        assert_eq!(file_name(md, "..\\..\\Windows\\system32\\x.md"), "x.md");
        assert_eq!(file_name(md, "../../etc/passwd"), "passwd.md");
        assert_eq!(file_name(json, "a:b*c?.json"), "abc.json");
        assert_eq!(file_name(md, "  "), "z-proxy-audit.md");
        assert_eq!(file_name(md, "..."), "z-proxy-audit.md");
        assert_eq!(file_name(json, "line\nbreak"), "linebreak.json");
    }

    #[test]
    fn size_is_capped_and_writes_report_their_path() {
        assert!(check_size("# report").is_ok());
        let huge = "x".repeat(MAX_REPORT_BYTES + 1);
        let err = check_size(&huge).unwrap_err();
        assert_eq!(err.code(), "REPORT_EXPORT_FAILED");
        let json = serde_json::to_value(&err).unwrap();
        assert!(json["path"].is_null());

        let dir = std::env::temp_dir().join(format!("zproxy-report-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("audit.md");
        write(&file, b"# audit\n").unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "# audit\n");

        let missing = dir.join("no-such-dir").join("audit.md");
        let err = write(&missing, b"x").unwrap_err();
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "REPORT_EXPORT_FAILED");
        assert!(json["path"].as_str().unwrap().ends_with("audit.md"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
