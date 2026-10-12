#[path = "../../reforge-core/tests/support/mod.rs"]
mod support;
use std::{fs, process::Command};

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_reforge"))
}

#[test]
fn json_analysis_and_resume_are_usable_from_the_executable() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("fixture.iso");
    let project = temp.path().join("analysis");
    fs::write(&input, support::iso(&support::pe())).unwrap();
    let result = cli()
        .arg("analyze")
        .arg(&input)
        .arg("--output")
        .arg(&project)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["analyzed_unique_binaries"], 1);
    let resumed = cli()
        .arg("resume")
        .arg(&project)
        .arg("--json")
        .output()
        .unwrap();
    assert!(resumed.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&resumed.stdout).unwrap(),
        report
    );
}

#[test]
fn partial_processing_and_fatal_failures_have_distinct_exit_codes() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("unsupported.iso");
    fs::write(&input, support::iso(b"MSWIM\0\0\0")).unwrap();
    let result = cli()
        .arg("analyze")
        .arg(&input)
        .arg("--output")
        .arg(temp.path().join("project"))
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(3));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&result.stdout).unwrap()["status"],
        "partial_with_blockers"
    );
    let result = cli()
        .arg("inspect")
        .arg(temp.path().join("missing"))
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&result.stdout).unwrap()["status"],
        "error"
    );
}

#[test]
fn unsupported_modes_are_not_advertised_as_working() {
    let result = cli()
        .args(["reconstruct", "input.iso", "--mode", "rewrite"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("recovery"));
}
