#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn rust_source_files_do_not_contain_comments() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let mut files = rust_files(&workspace_root.join("crates"));
    files.sort();
    let mut violations = Vec::new();
    for path in files {
        let source = fs::read_to_string(&path).expect("source file");
        for offset in comment_offsets(&source) {
            let (line, column) = line_column(&source, offset);
            violations.push(format!(
                "{}:{line}:{column}",
                path.strip_prefix(workspace_root)
                    .expect("relative path")
                    .display()
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "source comments are forbidden:\n{}",
        violations.join("\n")
    );
}

#[test]
fn scanner_detects_comments_without_matching_string_content() {
    assert_eq!(
        comment_offsets(r#"let text = "https://relay.test/path";"#),
        []
    );
    assert_eq!(
        comment_offsets(r##"let text = r#"// not a comment"#;"##),
        []
    );
    assert_eq!(comment_offsets("let slash = '/';"), []);
    assert_eq!(comment_offsets("let value = 1; // comment"), vec![15]);
    assert_eq!(comment_offsets("let value = /* comment */ 1;"), vec![12]);
}

fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_rust_files(root, &mut files);
    files
}

fn collect_rust_files(path: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(path).expect("source directory") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            collect_rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

fn comment_offsets(source: &str) -> Vec<usize> {
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
        if bytes[index] == b'/' && index + 1 < bytes.len() {
            match bytes[index + 1] {
                b'/' => {
                    offsets.push(index);
                    index = line_comment_end(bytes, index + 2);
                    continue;
                }
                b'*' => {
                    offsets.push(index);
                    index = block_comment_end(bytes, index + 2);
                    continue;
                }
                _ => {}
            }
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

fn line_comment_end(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index] != b'\n' {
        index += 1;
    }
    index
}

fn block_comment_end(bytes: &[u8], mut index: usize) -> usize {
    while index + 1 < bytes.len() {
        if bytes[index] == b'*' && bytes[index + 1] == b'/' {
            return index + 2;
        }
        index += 1;
    }
    bytes.len()
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
