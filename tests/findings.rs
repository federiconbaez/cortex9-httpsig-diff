//! Diagnostics that explain two aauth-httpsig rejections: the signature base
//! it builds for B.2.3 is the RFC's, so the rejection comes from its
//! Content-Digest re-check, which only computes SHA-256.

use std::collections::HashMap;

use httpsig_diff::cases::{appendix_b, test_request};

#[test]
fn aauth_builds_the_rfc_base_for_b23() {
    let (_, _, base, params) = appendix_b().into_iter().find(|c| c.0 == "B.2.3").unwrap();
    let req = test_request();
    let headers: HashMap<String, String> = req.headers.iter().cloned().collect();
    let uri = req.target_uri();
    let parts = aauth::RequestParts {
        method: &req.method,
        target_uri: &uri,
        headers: &headers,
        body: Some(&req.body),
    };
    let comps: Vec<String> = [
        "date",
        "@method",
        "@path",
        "@query",
        "@authority",
        "content-type",
        "content-digest",
        "content-length",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let got = aauth::build_signature_base(&parts, &comps, params).unwrap();
    assert_eq!(got, base);
}

#[test]
fn aauth_content_digest_is_sha256_only() {
    let d = aauth::calculate_content_digest(br#"{"hello": "world"}"#);
    assert!(d.starts_with("sha-256=:"), "{d}");
}
