//! Documentation that must match the code.

// Test code: a panic is how a test reports failure (see clippy.toml and ADR 0004).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::Path;

use blindsight::detect::Detector;

fn read(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap()
}

#[test]
fn readme_detector_table_matches_the_code() {
    let readme = read("README.md");
    let rows: Vec<&str> = readme.lines().filter(|l| l.starts_with("| `BS-")).collect();
    let expected: Vec<String> = Detector::ALL
        .iter()
        .map(|d| format!("| `{}` | {} | {} |", d.id(), d.title(), d.severities()))
        .collect();
    assert_eq!(rows, expected);
}

#[test]
fn every_detector_has_a_page_listed_in_the_catalog() {
    let catalog = read("docs/detectors/CATALOG.md");
    for d in Detector::ALL {
        assert!(catalog.contains(&format!("`{}`", d.id())), "{}", d.id());
        assert!(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("docs/detectors/{}.md", d.id()))
                .exists()
        );
    }
}

#[test]
fn readme_states_independence() {
    let readme = read("README.md");
    assert!(readme.contains("not affiliated with"));
    assert!(readme.contains("Safe Ecosystem Foundation"));
    assert!(readme.contains("Chainlink Labs"));
}
