#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn rust_source_files_do_not_contain_unsafe_tokens() {
    let workspace_root = workspace_root();
    let mut files = rust_files(&workspace_root.join("crates"));
    files.sort();
    let mut violations = Vec::new();
    for path in files {
        let source = fs::read_to_string(&path).expect("source file");
        for offset in unsafe_offsets(&source) {
            let (line, column) = line_column(&source, offset);
            violations.push(format!(
                "{}:{line}:{column}",
                path.strip_prefix(&workspace_root)
                    .expect("relative path")
                    .display()
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "unsafe tokens are forbidden:\n{}",
        violations.join("\n")
    );
}

#[test]
fn crate_manifests_inherit_workspace_lints() {
    let workspace_root = workspace_root();
    let mut manifests = crate_manifests(&workspace_root.join("crates"));
    manifests.sort();
    let mut missing = Vec::new();
    for path in manifests {
        let manifest = fs::read_to_string(&path).expect("crate manifest");
        if !manifest.contains("[lints]\nworkspace = true") {
            missing.push(
                path.strip_prefix(&workspace_root)
                    .expect("relative path")
                    .display()
                    .to_string(),
            );
        }
    }
    assert!(
        missing.is_empty(),
        "crate manifests must inherit workspace lints:\n{}",
        missing.join("\n")
    );
}

#[test]
fn scanner_detects_unsafe_keywords_without_matching_literals_or_identifiers() {
    let keyword = ["fn main() { ", "unsafe", " {} }"].concat();

    assert_eq!(unsafe_offsets(&keyword), vec![12]);
    assert_eq!(unsafe_offsets(r#"let text = "unsafe";"#), []);
    assert_eq!(unsafe_offsets(r##"let text = r#"unsafe"#;"##), []);
    assert_eq!(unsafe_offsets("let unsafe_code = true;"), []);
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_matching_files(root, "rs", &mut files);
    files
}

fn crate_manifests(root: &Path) -> Vec<PathBuf> {
    let mut manifests = Vec::new();
    for entry in fs::read_dir(root).expect("crates directory") {
        let path = entry.expect("crate entry").path().join("Cargo.toml");
        if path.exists() {
            manifests.push(path);
        }
    }
    manifests
}

fn collect_matching_files(path: &Path, extension: &str, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(path).expect("source directory") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            collect_matching_files(&path, extension, files);
        } else if path
            .extension()
            .is_some_and(|candidate| candidate == extension)
        {
            files.push(path);
        }
    }
}

fn unsafe_offsets(source: &str) -> Vec<usize> {
    let bytes = source.as_bytes();
    let mut offsets = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if let Some(end) = raw_string_end(bytes, index) {
            index = end;
            continue;
        }
        if let Some(end) = regular_string_end(bytes, index) {
            index = end;
            continue;
        }
        if let Some(end) = char_literal_end(bytes, index) {
            index = end;
            continue;
        }
        if source[index..].starts_with("unsafe")
            && !is_identifier_byte(bytes.get(index.wrapping_sub(1)).copied())
            && !is_identifier_byte(bytes.get(index + 6).copied())
        {
            offsets.push(index);
            index += 6;
            continue;
        }
        index += 1;
    }
    offsets
}

fn raw_string_end(bytes: &[u8], index: usize) -> Option<usize> {
    let mut cursor = index;
    if matches!(bytes.get(cursor), Some(b'b' | b'c')) {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'r') {
        return None;
    }
    cursor += 1;
    let mut hashes = 0;
    while bytes.get(cursor) == Some(&b'#') {
        hashes += 1;
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'"') {
        return None;
    }
    cursor += 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"'
            && bytes
                .get(cursor + 1..cursor + 1 + hashes)
                .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
        {
            return Some(cursor + 1 + hashes);
        }
        cursor += 1;
    }
    Some(bytes.len())
}

fn regular_string_end(bytes: &[u8], index: usize) -> Option<usize> {
    let quote = if matches!(bytes.get(index), Some(b'b' | b'c')) {
        index + 1
    } else {
        index
    };
    if bytes.get(quote) != Some(&b'"') {
        return None;
    }
    let mut cursor = quote + 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => cursor += 2,
            b'"' => return Some(cursor + 1),
            _ => cursor += 1,
        }
    }
    Some(bytes.len())
}

fn char_literal_end(bytes: &[u8], index: usize) -> Option<usize> {
    if bytes.get(index) != Some(&b'\'') {
        return None;
    }
    let mut cursor = index + 1;
    while cursor < bytes.len() && bytes[cursor] != b'\n' {
        match bytes[cursor] {
            b'\\' => cursor += 2,
            b'\'' => return Some(cursor + 1),
            _ => cursor += 1,
        }
    }
    None
}

fn is_identifier_byte(byte: Option<u8>) -> bool {
    byte.is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn line_column(source: &str, offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut column = 1;
    for (index, character) in source.char_indices() {
        if index == offset {
            return (line, column);
        }
        if character == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}
