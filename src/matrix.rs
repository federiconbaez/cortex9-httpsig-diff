//! Runs the corpus through every implementation and summarizes.

use crate::adapters::{all, Implementation};
use crate::cases::{corpus, Case, Category, Expect};

#[derive(Debug, Clone)]
pub struct Row {
    pub id: &'static str,
    pub category: Category,
    pub expect: Expect,
    pub rfc: &'static str,
    pub what: &'static str,
    /// (implementation, accepted, error text)
    pub results: Vec<(&'static str, bool, String)>,
}

impl Row {
    /// True when the crates under test (reference excluded) disagree.
    pub fn divergent(&self) -> bool {
        let crates: Vec<bool> = self
            .results
            .iter()
            .filter(|(n, _, _)| *n != "reference")
            .map(|(_, a, _)| *a)
            .collect();
        crates.iter().any(|a| *a != crates[0])
    }
}

pub fn run_case(c: &Case, impls: &[Box<dyn Implementation>]) -> Row {
    let results = impls
        .iter()
        .map(|i| match i.verify(&c.request, c.label) {
            Ok(()) => (i.name(), true, String::new()),
            Err(e) => (i.name(), false, e),
        })
        .collect();
    Row {
        id: c.id,
        category: c.category,
        expect: c.expect,
        rfc: c.rfc,
        what: c.what,
        results,
    }
}

pub fn run() -> Vec<Row> {
    let impls = all();
    corpus().iter().map(|c| run_case(c, &impls)).collect()
}

fn csv_field(s: &str) -> String {
    let one_line = s.replace(['\n', '\r'], " ");
    format!("\"{}\"", one_line.replace('"', "\"\""))
}

/// Matrix as CSV: one row per case, accept/reject per implementation, then
/// the error text per implementation.
pub fn to_csv(rows: &[Row]) -> String {
    let names: Vec<&str> = rows[0].results.iter().map(|r| r.0).collect();
    let mut out = format!(
        "case,category,expected,rfc,{},divergent,what,{}\n",
        names.join(","),
        names
            .iter()
            .map(|n| format!("error_{n}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    for r in rows {
        let verdicts: Vec<&str> = r
            .results
            .iter()
            .map(|(_, a, _)| if *a { "accept" } else { "reject" })
            .collect();
        let errors: Vec<String> = r.results.iter().map(|(_, _, e)| csv_field(e)).collect();
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            r.id,
            r.category.as_str(),
            r.expect.as_str(),
            csv_field(r.rfc),
            verdicts.join(","),
            r.divergent(),
            csv_field(r.what),
            errors.join(",")
        ));
    }
    out
}

/// Per-implementation summary against the RFC expectation.
pub fn summary(rows: &[Row]) -> serde_json::Value {
    use serde_json::json;
    let names: Vec<&str> = rows[0].results.iter().map(|r| r.0).collect();
    let mut per = serde_json::Map::new();
    for (k, name) in names.iter().enumerate() {
        let mut app_b = Vec::new();
        let mut spurious = Vec::new();
        let mut undue = Vec::new();
        let mut agree = 0;
        let mut decided = 0;
        for r in rows {
            let accepted = r.results[k].1;
            if r.category == Category::AppendixB && accepted {
                app_b.push(r.id);
            }
            match r.expect {
                Expect::Accept => {
                    decided += 1;
                    if accepted {
                        agree += 1;
                    } else {
                        spurious.push(r.id);
                    }
                }
                Expect::Reject => {
                    decided += 1;
                    if accepted {
                        undue.push(r.id);
                    } else {
                        agree += 1;
                    }
                }
                Expect::Ambiguous => {}
            }
        }
        per.insert(
            (*name).to_string(),
            json!({
                "appendix_b_pass": app_b.len(),
                "appendix_b_passed": app_b,
                "agree_with_rfc": agree,
                "decided_cases": decided,
                "spurious_rejections": spurious.len(),
                "spurious_rejection_cases": spurious,
                "undue_acceptances": undue.len(),
                "undue_acceptance_cases": undue,
            }),
        );
    }
    let divergent: Vec<&str> = rows
        .iter()
        .filter(|r| r.divergent())
        .map(|r| r.id)
        .collect();
    let count = |c: Category| rows.iter().filter(|r| r.category == c).count();
    json!({
        "cases": rows.len(),
        "by_category": {
            "appendix_b": count(Category::AppendixB),
            "valid": count(Category::Valid),
            "tampered": count(Category::Tampered),
            "parser": count(Category::Parser),
        },
        "divergent_cases": divergent.len(),
        "divergent": divergent,
        "per_implementation": per,
    })
}
