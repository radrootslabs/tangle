#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn production_runtime_and_group_source_keeps_pocket_native_boundary() {
    let workspace_root = workspace_root();
    let mut files = Vec::new();
    collect_rust_files(
        &workspace_root.join("crates/tangle_runtime/src"),
        &mut files,
    );
    collect_rust_files(&workspace_root.join("crates/tangle_groups/src"), &mut files);
    files.sort();
    let mut violations = Vec::new();
    for path in files {
        let source = fs::read_to_string(&path).expect("source file");
        let production = production_source(&source);
        collect_forbidden_imports(&workspace_root, &path, &production, &mut violations);
        collect_forbidden_paths(&workspace_root, &path, &production, &mut violations);
        collect_forbidden_identifiers(&workspace_root, &path, &production, &mut violations);
    }
    assert!(
        violations.is_empty(),
        "production Pocket-native source invariants failed:\n{}",
        violations.join("\n")
    );
}

#[test]
fn scanner_removes_test_gated_items_without_removing_production_items() {
    let source = [
        "#[cfg(test)]\n",
        "use tangle_protocol::{Event, Filter};\n",
        "fn production() {}\n",
        "#[cfg(test)]\n",
        "fn test_only() { let value = \"}\"; }\n",
        "fn production_two() {}\n",
    ]
    .concat();
    let production = production_source(&source);
    assert!(!production.contains("Event"));
    assert!(!production.contains("test_only"));
    assert!(production.contains("production()"));
    assert!(production.contains("production_two()"));
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
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

fn collect_forbidden_imports(
    workspace_root: &Path,
    path: &Path,
    source: &str,
    violations: &mut Vec<String>,
) {
    for block in protocol_use_blocks(source) {
        for ident in ["Event", "UnsignedEvent", "Tag", "Filter"] {
            if contains_identifier(block.text, ident) {
                violations.push(violation(workspace_root, path, source, block.offset, ident));
            }
        }
    }
}

fn collect_forbidden_paths(
    workspace_root: &Path,
    path: &Path,
    source: &str,
    violations: &mut Vec<String>,
) {
    for ident in ["Event", "UnsignedEvent", "Tag", "Filter"] {
        let needle = ["tangle_protocol::", ident].concat();
        for offset in identifier_occurrences(source, &needle) {
            violations.push(violation(workspace_root, path, source, offset, &needle));
        }
    }
}

fn collect_forbidden_identifiers(
    workspace_root: &Path,
    path: &Path,
    source: &str,
    violations: &mut Vec<String>,
) {
    for ident in [
        "pocket_event_to_tangle",
        "tangle_event_to_pocket",
        "RuntimeRelayMessage::into_protocol_message",
        "protocol_messages",
    ] {
        for offset in identifier_occurrences(source, ident) {
            violations.push(violation(workspace_root, path, source, offset, ident));
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct UseBlock<'a> {
    offset: usize,
    text: &'a str,
}

fn protocol_use_blocks(source: &str) -> Vec<UseBlock<'_>> {
    let mut output = Vec::new();
    let mut cursor = 0;
    while let Some(relative) = source[cursor..].find("use tangle_protocol::") {
        let start = cursor + relative;
        let Some(end) = statement_end(source, start) else {
            break;
        };
        output.push(UseBlock {
            offset: start,
            text: &source[start..end],
        });
        cursor = end;
    }
    output
}

fn production_source(source: &str) -> String {
    let mut output = String::new();
    let mut scan_cursor = 0;
    let mut copy_start = 0;
    while let Some((line_start, line_end, line)) = next_line(source, scan_cursor) {
        if line.trim() == "#[cfg(test)]" {
            output.push_str(&source[copy_start..line_start]);
            let item_start = next_item_start(source, line_end);
            let item_end = cfg_item_end(source, item_start).unwrap_or(source.len());
            for character in source[line_start..item_end].chars() {
                if character == '\n' {
                    output.push('\n');
                }
            }
            copy_start = item_end;
            scan_cursor = item_end;
        } else {
            scan_cursor = line_end;
        }
    }
    output.push_str(&source[copy_start..]);
    output
}

fn next_item_start(source: &str, mut cursor: usize) -> usize {
    while let Some((line_start, line_end, line)) = next_line(source, cursor) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("#[") {
            cursor = line_end;
        } else {
            return line_start;
        }
    }
    source.len()
}

fn cfg_item_end(source: &str, item_start: usize) -> Option<usize> {
    let mut cursor = item_start;
    while cursor < source.len() {
        if let Some(end) = raw_string_end(source.as_bytes(), cursor) {
            cursor = end;
            continue;
        }
        if let Some(end) = regular_string_end(source.as_bytes(), cursor) {
            cursor = end;
            continue;
        }
        if let Some(end) = char_literal_end(source.as_bytes(), cursor) {
            cursor = end;
            continue;
        }
        match source.as_bytes()[cursor] {
            b';' => return Some(include_trailing_newline(source, cursor + 1)),
            b'{' => {
                return Some(include_trailing_newline(
                    source,
                    matching_brace_end(source, cursor),
                ));
            }
            _ => cursor += 1,
        }
    }
    None
}

fn statement_end(source: &str, start: usize) -> Option<usize> {
    let mut cursor = start;
    while cursor < source.len() {
        if let Some(end) = raw_string_end(source.as_bytes(), cursor) {
            cursor = end;
            continue;
        }
        if let Some(end) = regular_string_end(source.as_bytes(), cursor) {
            cursor = end;
            continue;
        }
        if let Some(end) = char_literal_end(source.as_bytes(), cursor) {
            cursor = end;
            continue;
        }
        if source.as_bytes()[cursor] == b';' {
            return Some(cursor + 1);
        }
        cursor += 1;
    }
    None
}

fn matching_brace_end(source: &str, start: usize) -> usize {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut cursor = start;
    while cursor < bytes.len() {
        if let Some(end) = raw_string_end(bytes, cursor) {
            cursor = end;
            continue;
        }
        if let Some(end) = regular_string_end(bytes, cursor) {
            cursor = end;
            continue;
        }
        if let Some(end) = char_literal_end(bytes, cursor) {
            cursor = end;
            continue;
        }
        match bytes[cursor] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return cursor + 1;
                }
            }
            _ => {}
        }
        cursor += 1;
    }
    source.len()
}

fn include_trailing_newline(source: &str, cursor: usize) -> usize {
    if source.as_bytes().get(cursor) == Some(&b'\n') {
        cursor + 1
    } else {
        cursor
    }
}

fn next_line(source: &str, start: usize) -> Option<(usize, usize, &str)> {
    if start >= source.len() {
        return None;
    }
    let end = source[start..]
        .find('\n')
        .map(|relative| start + relative + 1)
        .unwrap_or(source.len());
    Some((start, end, &source[start..end]))
}

fn identifier_occurrences(source: &str, needle: &str) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut cursor = 0;
    while let Some(relative) = source[cursor..].find(needle) {
        let offset = cursor + relative;
        if !is_identifier_byte(source.as_bytes().get(offset.wrapping_sub(1)).copied())
            && !is_identifier_byte(source.as_bytes().get(offset + needle.len()).copied())
        {
            offsets.push(offset);
        }
        cursor = offset + needle.len();
    }
    offsets
}

fn contains_identifier(source: &str, needle: &str) -> bool {
    !identifier_occurrences(source, needle).is_empty()
}

fn violation(
    workspace_root: &Path,
    path: &Path,
    source: &str,
    offset: usize,
    needle: &str,
) -> String {
    let (line, column) = line_column(source, offset);
    format!(
        "{}:{line}:{column}: {needle}",
        path.strip_prefix(workspace_root)
            .expect("relative path")
            .display()
    )
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
