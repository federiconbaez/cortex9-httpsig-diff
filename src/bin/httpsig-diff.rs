//! Runs the corpus and writes the matrix.
//!
//! Usage: `httpsig-diff [--csv PATH] [--json PATH]`

use std::fs;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter()
        .position(|x| x == name)
        .and_then(|i| a.get(i + 1).cloned())
}

fn main() {
    let rows = httpsig_diff::matrix::run();
    let csv = httpsig_diff::matrix::to_csv(&rows);
    let summary = httpsig_diff::matrix::summary(&rows);
    let pretty = serde_json::to_string_pretty(&summary).expect("json");
    if let Some(p) = arg("--csv") {
        fs::write(p, &csv).expect("write csv");
    }
    if let Some(p) = arg("--json") {
        fs::write(p, &pretty).expect("write json");
    }
    println!("{pretty}");
}
