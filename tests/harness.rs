//! Self-checks of the harness: the reference must reproduce the RFC, and the
//! controls must behave, otherwise the matrix means nothing.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier};
use httpsig_diff::adapters::all;
use httpsig_diff::cases::{
    appendix_b, corpus, test_request, Category, Expect, B26_SIGNATURE, DIGEST,
};
use httpsig_diff::matrix::{run, to_csv};
use httpsig_diff::reference::{inner_list, signature_base, test_key, TEST_KEY_ED25519_X};
use sha2::{Digest, Sha512};

fn params_of(base: &str) -> String {
    base.rsplit("\"@signature-params\": ")
        .next()
        .unwrap()
        .to_string()
}

#[test]
fn reference_rebuilds_every_appendix_b_base() {
    for (id, _, base, params) in appendix_b() {
        assert_eq!(params_of(&base), params, "{id}");
        // Split the Inner List back into component identifiers.
        let list = {
            let d = sfv::Parser::new(&format!("x={params}"))
                .parse_dictionary()
                .unwrap();
            match d.into_iter().next().unwrap().1 {
                sfv::ListEntry::InnerList(l) => l,
                _ => unreachable!(),
            }
        };
        let got = signature_base(&test_request(), &list).unwrap();
        assert_eq!(got, base, "{id}");
    }
}

#[test]
fn b26_signature_verifies_with_test_key() {
    let (_, _, base, _) = appendix_b().pop().unwrap();
    let b64 = B26_SIGNATURE
        .trim_start_matches("sig-b26=:")
        .trim_end_matches(':');
    let sig = Signature::from_slice(&STANDARD.decode(b64).unwrap()).unwrap();
    test_key()
        .verifying_key()
        .verify(base.as_bytes(), &sig)
        .unwrap();
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    assert_eq!(
        URL_SAFE_NO_PAD.encode(test_key().verifying_key().as_bytes()),
        TEST_KEY_ED25519_X
    );
}

#[test]
fn appendix_b_digest_matches_body() {
    let d = STANDARD.encode(Sha512::digest(br#"{"hello": "world"}"#));
    assert_eq!(DIGEST, format!("sha-512=:{d}:"));
}

#[test]
fn reference_matches_every_decided_expectation() {
    let rows = run();
    for r in &rows {
        let reference = r.results.iter().find(|x| x.0 == "reference").unwrap();
        match r.expect {
            Expect::Accept => assert!(reference.1, "{}: {}", r.id, reference.2),
            Expect::Reject => assert!(!reference.1, "{} accepted by reference", r.id),
            Expect::Ambiguous => {}
        }
    }
}

#[test]
fn negative_controls_rejected_by_everyone() {
    let rows = run();
    for id in ["T20-signature-bitflip", "T21-wrong-key"] {
        let r = rows.iter().find(|r| r.id == id).unwrap();
        for (name, accepted, _) in &r.results {
            assert!(!accepted, "{name} accepted {id}: harness or crate broken");
        }
    }
}

#[test]
fn corpus_size_and_matrix_shape() {
    let c = corpus();
    assert_eq!(
        c.iter()
            .filter(|c| c.category == Category::AppendixB)
            .count(),
        5
    );
    assert!(
        c.iter()
            .filter(|c| c.category != Category::AppendixB)
            .count()
            >= 30
    );
    let mut ids: Vec<&str> = c.iter().map(|c| c.id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), c.len(), "case ids must be unique");
    let rows = run();
    assert_eq!(rows.len(), c.len());
    for r in &rows {
        assert_eq!(r.results.len(), all().len());
    }
    assert_eq!(to_csv(&rows).lines().count(), c.len() + 1);
}

#[test]
fn reference_refuses_what_rfc_forbids() {
    let r = test_request();
    assert!(signature_base(&r, &inner_list(&["\"@method\"", "\"@method\""], "")).is_err());
    assert!(signature_base(&r, &inner_list(&["\"@signature-params\""], "")).is_err());
    assert!(signature_base(&r, &inner_list(&["\"date\";sf"], "")).is_err());
    assert!(signature_base(&r, &inner_list(&["\"x-missing\""], "")).is_err());
}
