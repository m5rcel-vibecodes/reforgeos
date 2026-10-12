mod support;
use reforge_core::{
    binary,
    config::Config,
    image,
    project::{Project, Stage},
};
use std::{fs, io::Write};

#[test]
fn iso_pe_analysis_reports_resume_and_tamper_detection() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("input.dat");
    let root = temp.path().join("project");
    fs::write(&input, support::iso(&support::pe())).unwrap();
    assert_eq!(image::detect(&input).unwrap(), image::Format::Iso9660);
    let mut p = Project::create(&input, &root, &Config::default(), Stage::Analyze, None).unwrap();
    let report = p.run(None).unwrap();
    assert_eq!(report["analyzed_unique_binaries"], 1);
    assert_eq!(report["status"], "analysis_finished");
    assert!(
        Project::open(&root).is_err(),
        "concurrent writers must fail"
    );
    drop(p);
    let mut p = Project::open(&root).unwrap();
    assert_eq!(p.run(None).unwrap(), report);
    let parsed = binary::inspect(&root.join("extracted/ANSWER.EXE"), &Config::default()).unwrap();
    assert_eq!(parsed.format, "Pe");
    assert_eq!(parsed.entry, 0x140001000);
    assert!(root.join("reports/graph.dot").is_file());
    fs::write(root.join("extracted/ANSWER.EXE"), b"tampered").unwrap();
    assert!(p.run(None).unwrap_err().to_string().contains("changed"));
}

#[test]
fn corrupt_iso_and_missing_backend_preserve_truthful_state() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("image.iso");
    let mut data = support::iso(&support::pe());
    data[16 * 2048 + 84] ^= 1;
    fs::write(&input, data).unwrap();
    assert!(image::extract(&input, &temp.path().join("bad"), &Config::default()).is_err());
    fs::write(&input, support::iso(&support::pe())).unwrap();
    let root = temp.path().join("project");
    let absent = temp.path().join("empty-ghidra");
    fs::create_dir(&absent).unwrap();
    let mut p = Project::create(
        &input,
        &root,
        &Config::default(),
        Stage::Reconstruct,
        Some(&absent),
    )
    .unwrap();
    let r = p.run(None).unwrap();
    assert_eq!(r["status"], "partial_with_blockers");
    assert_eq!(r["decompilation_coverage"]["numerator"], 0);
    assert_eq!(r["analyzed_unique_binaries"], 1);
    assert!(p.build().is_err());
    assert_eq!(p.report().unwrap()["build"]["status"], "blocked_or_failed");
}

#[test]
fn nested_zip_gzip_tar_and_depth_limit() {
    let temp = tempfile::tempdir().unwrap();
    let mut tar = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(5);
    h.set_mode(0o644);
    h.set_cksum();
    tar.append_data(&mut h, "hello.txt", &b"hello"[..]).unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&tar.into_inner().unwrap()).unwrap();
    let zipped = temp.path().join("archive.bin");
    let mut zip = zip::ZipWriter::new(fs::File::create(&zipped).unwrap());
    zip.start_file("nested", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(&gzip.finish().unwrap()).unwrap();
    zip.finish().unwrap();
    let report = image::extract(&zipped, &temp.path().join("out"), &Config::default()).unwrap();
    assert!(report.files.iter().any(|f| f.path.ends_with("hello.txt")));
    let report = image::extract(
        &zipped,
        &temp.path().join("limited"),
        &Config {
            max_depth: 0,
            ..Config::default()
        },
    )
    .unwrap();
    assert_eq!(report.files.len(), 1);
    assert_eq!(report.warnings.len(), 1);
}

#[test]
fn resumes_before_extraction_and_rejects_input_changes() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("input.iso");
    let root = temp.path().join("project");
    fs::write(&input, support::iso(&support::pe())).unwrap();
    drop(Project::create(&input, &root, &Config::default(), Stage::Analyze, None).unwrap());
    let mut p = Project::open(&root).unwrap();
    assert_eq!(p.status().unwrap()["extraction_committed"], false);
    p.run(None).unwrap();
    fs::write(&input, b"changed").unwrap();
    assert!(p.run(None).is_err());
}

#[test]
fn configuration_rejects_unknown_keys_and_bad_limits() {
    assert!(Config {
        max_files: 0,
        ..Config::default()
    }
    .validate()
    .is_err());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("bad.toml");
    fs::write(&path, "jobs = 999").unwrap();
    assert!(Config::load(Some(&path)).is_err());
}

#[test]
fn timeout_child() {
    if std::env::var_os("REFORGE_TEST_SLEEP").is_some() {
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
}

#[test]
fn backend_process_timeout_and_launch_failure() {
    use reforge_core::decompiler::run_process;
    use std::process::Command;
    let temp = tempfile::tempdir().unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "timeout_child"])
        .env("REFORGE_TEST_SLEEP", "1");
    let result = run_process(&mut command, temp.path(), "sleep", 1);
    assert!(result.unwrap_err().to_string().contains("ANALYSIS_TIMEOUT"));
    assert!(temp.path().join("sleep.stdout.log").is_file());
    assert!(run_process(
        &mut Command::new(temp.path().join("missing")),
        temp.path(),
        "missing",
        1
    )
    .is_err());
}

#[test]
#[ignore = "requires GHIDRA_INSTALL_DIR, JAVA_HOME and CMake with a C compiler"]
fn real_ghidra_recovery_and_object_compilation() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("answer.iso");
    let root = temp.path().join("project");
    fs::write(&input, support::iso(&support::pe())).unwrap();
    let mut p =
        Project::create(&input, &root, &Config::default(), Stage::Reconstruct, None).unwrap();
    let report = p.run(None).unwrap();
    assert!(
        report["decompilation_coverage"]["numerator"]
            .as_u64()
            .unwrap()
            > 0,
        "{report}"
    );
    assert_eq!(p.build().unwrap()["status"], "object_compilation_succeeded");
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("reconstructed/provenance.json")).unwrap())
            .unwrap();
    assert_eq!(
        provenance[0]["compilation"],
        "containing_module_object_compiled"
    );
    let hash = provenance[0]["binary_sha256"].as_str().unwrap();
    let source = root.join("reconstructed").join(hash).join("module.c");
    let previous_report = p.report().unwrap();
    assert_eq!(
        p.run(None).unwrap(),
        previous_report,
        "resume must preserve successful compilation"
    );
    fs::write(&source, b"/* user edits */").unwrap();
    assert!(p.run(None).is_err());
    assert_eq!(fs::read(&source).unwrap(), b"/* user edits */");
}
