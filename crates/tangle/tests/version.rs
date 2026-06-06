#![forbid(unsafe_code)]

use std::process::Command;

#[test]
fn tangle_version_command_reports_package_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_tangle"))
        .arg("--version")
        .output()
        .expect("run tangle --version");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "tangle 0.1.0\n");
    assert!(output.stderr.is_empty());
}
