use std::process::Command;

fn report(command: &str, options: &[&str]) -> serde_json::Value {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/branch.exe"
    );
    let result = Command::new(env!("CARGO_BIN_EXE_disecta"))
        .arg(command)
        .arg(fixture)
        .args(options)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

#[test]
fn reports_functions_graph_and_references_using_virtual_addresses() {
    let functions = report("functions", &[]);
    assert_eq!(functions["functions"][1]["address"], "0x140001024");
    let graph = report("cfg", &["--function", "0x140001000"]);
    assert_eq!(graph["blocks"].as_array().unwrap().len(), 4);
    let xrefs = report("xrefs", &["--address", "0x140002000"]);
    assert_eq!(xrefs["references"]["incoming"][0]["kind"], "ip_relative");
    let calls = report("calls", &["--function", "0x140001024"]);
    assert_eq!(calls["calls"][0]["source"], "0x14000100A");
    let analysis = report("analyze", &[]);
    assert_eq!(analysis["schema"], 1);
}
