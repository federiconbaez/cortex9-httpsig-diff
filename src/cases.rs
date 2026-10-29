//! Pre-registered corpus. Every case is a request as it reaches the
//! verifier, with its `Signature-Input` and `Signature` fields, plus the
//! verdict RFC 9421 expects.
//!
//! All signatures are made with the RFC 9421 Appendix B.1.4 test key. Unless
//! noted, the signer is [`crate::reference`] on the request as sent, and the
//! case then changes what the verifier receives.

use crate::model::Request;
use crate::reference::{self, inner_list, params_value, sign, sign_base, test_key, Signed};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// The RFC says the signature verifies.
    Accept,
    /// The RFC says verification fails.
    Reject,
    /// The RFC text read does not settle it; only divergence is reported.
    Ambiguous,
}

impl Expect {
    pub fn as_str(self) -> &'static str {
        match self {
            Expect::Accept => "accept",
            Expect::Reject => "reject",
            Expect::Ambiguous => "ambiguous",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// RFC 9421 Appendix B.2 request vectors (control: must pass everywhere).
    AppendixB,
    /// Valid edge cases; a rejection is a spurious rejection.
    Valid,
    /// Altered after signing; an acceptance is an undue acceptance.
    Tampered,
    /// Field-parsing edge cases.
    Parser,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::AppendixB => "appendix_b",
            Category::Valid => "valid",
            Category::Tampered => "tampered",
            Category::Parser => "parser",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Case {
    pub id: &'static str,
    pub category: Category,
    pub expect: Expect,
    /// RFC section that decides the expected verdict.
    pub rfc: &'static str,
    pub what: &'static str,
    pub label: &'static str,
    pub request: Request,
}

pub const CREATED: &str = ";created=1618884473;keyid=\"test-key-ed25519\"";
pub const DIGEST: &str =
    "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:";

/// RFC 9421 Appendix B.2 test-request.
pub fn test_request() -> Request {
    Request::new(
        "POST",
        "https",
        "example.com",
        "/foo",
        Some("param=Value&Pet=dog"),
    )
    .header("Host", "example.com")
    .header("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
    .header("Content-Type", "application/json")
    .header("Content-Digest", DIGEST)
    .header("Content-Length", "18")
    .body(br#"{"hello": "world"}"#)
}

fn simple(path: &str, query: Option<&str>) -> Request {
    Request::new("GET", "https", "example.com", path, query).header("Host", "example.com")
}

pub fn attach(req: Request, s: &Signed) -> Request {
    req.header("Signature-Input", &s.input)
        .header("Signature", &s.signature)
}

/// Sign `req` over `components` (serialized identifiers) with the reference.
pub fn signed(req: &Request, components: &[&str], params: &str) -> Signed {
    sign(req, &inner_list(components, params), "sig1", &test_key()).expect("reference signs")
}

/// Sign a hand-written base (for signers that do something the reference
/// refuses to do).
fn manual(lines: &[(&str, &str)], params: &str) -> Signed {
    let mut base = String::new();
    for (id, v) in lines {
        base.push_str(&format!("{id}: {v}\n"));
    }
    base.push_str(&format!("\"@signature-params\": {params}"));
    sign_base(&base, params, "sig1", &test_key())
}

/// Appendix B.2.x bases exactly as printed in the RFC (line wrapping undone).
pub fn appendix_b() -> Vec<(&'static str, &'static str, String, &'static str)> {
    vec![
        (
            "B.2.1",
            "sig-b21",
            "\"@signature-params\": ();created=1618884473;keyid=\"test-key-rsa-pss\";nonce=\"b3k2pp5k7z-50gnwp.yemd\"".to_string(),
            "();created=1618884473;keyid=\"test-key-rsa-pss\";nonce=\"b3k2pp5k7z-50gnwp.yemd\"",
        ),
        (
            "B.2.2",
            "sig-b22",
            format!("\"@authority\": example.com\n\"content-digest\": {DIGEST}\n\"@query-param\";name=\"Pet\": dog\n\"@signature-params\": (\"@authority\" \"content-digest\" \"@query-param\";name=\"Pet\");created=1618884473;keyid=\"test-key-rsa-pss\";tag=\"header-example\""),
            "(\"@authority\" \"content-digest\" \"@query-param\";name=\"Pet\");created=1618884473;keyid=\"test-key-rsa-pss\";tag=\"header-example\"",
        ),
        (
            "B.2.3",
            "sig-b23",
            format!("\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@method\": POST\n\"@path\": /foo\n\"@query\": ?param=Value&Pet=dog\n\"@authority\": example.com\n\"content-type\": application/json\n\"content-digest\": {DIGEST}\n\"content-length\": 18\n\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@query\" \"@authority\" \"content-type\" \"content-digest\" \"content-length\");created=1618884473;keyid=\"test-key-rsa-pss\""),
            "(\"date\" \"@method\" \"@path\" \"@query\" \"@authority\" \"content-type\" \"content-digest\" \"content-length\");created=1618884473;keyid=\"test-key-rsa-pss\"",
        ),
        (
            "B.2.5",
            "sig-b25",
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@authority\": example.com\n\"content-type\": application/json\n\"@signature-params\": (\"date\" \"@authority\" \"content-type\");created=1618884473;keyid=\"test-shared-secret\"".to_string(),
            "(\"date\" \"@authority\" \"content-type\");created=1618884473;keyid=\"test-shared-secret\"",
        ),
        (
            "B.2.6",
            "sig-b26",
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@method\": POST\n\"@path\": /foo\n\"@authority\": example.com\n\"content-type\": application/json\n\"content-length\": 18\n\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"".to_string(),
            "(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"",
        ),
    ]
}

/// The Ed25519 signature printed in Appendix B.2.6.
pub const B26_SIGNATURE: &str =
    "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:";

macro_rules! case {
    ($id:expr, $cat:ident, $exp:ident, $rfc:expr, $what:expr, $req:expr) => {
        Case {
            id: $id,
            category: Category::$cat,
            expect: Expect::$exp,
            rfc: $rfc,
            what: $what,
            label: "sig1",
            request: $req,
        }
    };
}

pub fn corpus() -> Vec<Case> {
    let mut v = Vec::new();

    // --- Appendix B -------------------------------------------------------
    for (id, label, base, params) in appendix_b() {
        let s = if id == "B.2.6" {
            Signed {
                input: format!("{label}={params}"),
                signature: B26_SIGNATURE.into(),
            }
        } else {
            // Re-signed with test-key-ed25519: acceptance means the crate
            // rebuilt exactly the base printed in the RFC.
            sign_base(&base, params, label, &test_key())
        };
        v.push(Case {
            id,
            category: Category::AppendixB,
            expect: Expect::Accept,
            rfc: "App. B.2",
            what: if id == "B.2.6" {
                "RFC vector with its original Ed25519 signature"
            } else {
                "RFC base re-signed with test-key-ed25519"
            },
            label,
            request: attach(test_request(), &s),
        });
    }

    // --- Valid edge cases --------------------------------------------------
    let r = simple("/", None)
        .header("Cache-Control", "max-age=60")
        .header("Cache-Control", "must-revalidate");
    v.push(case!(
        "V01-multi-line-field",
        Valid,
        Accept,
        "2.1",
        "two Cache-Control lines combined with \", \"",
        attach(r.clone(), &signed(&r, &["\"cache-control\""], CREATED))
    ));

    let r = simple("/", None).header("X-Empty", "");
    v.push(case!(
        "V02-empty-field",
        Valid,
        Accept,
        "2.1",
        "covered field with empty value",
        attach(r.clone(), &signed(&r, &["\"x-empty\""], CREATED))
    ));

    let r = simple("/", None).header("X-Ows", "   Leading and trailing whitespace.  ");
    v.push(case!(
        "V03-ows-trimmed",
        Valid,
        Accept,
        "2.1",
        "raw field line with leading/trailing whitespace (HTTP stacks normally strip it)",
        attach(r.clone(), &signed(&r, &["\"x-ows\""], CREATED))
    ));

    let r = simple("/foo", None);
    v.push(case!(
        "V04-query-absent",
        Valid,
        Accept,
        "2.2.7",
        "@query covered on a request without query: value is \"?\"",
        attach(r.clone(), &signed(&r, &["\"@query\""], CREATED))
    ));

    let r = simple("/foo", Some(""));
    v.push(case!(
        "V05-query-empty",
        Valid,
        Accept,
        "2.2.7",
        "request target ends in a bare ?",
        attach(r.clone(), &signed(&r, &["\"@query\""], CREATED))
    ));

    let r = simple("/a%2Fb%7Ec", None);
    v.push(case!(
        "V06-path-pct-raw",
        Valid,
        Accept,
        "2.2.6",
        "@path keeps percent-encoded octets undecoded",
        attach(r.clone(), &signed(&r, &["\"@path\""], CREATED))
    ));

    let mut r = simple("/", None);
    r.authority = "Example.COM".into();
    v.push(case!(
        "V07-authority-case",
        Valid,
        Accept,
        "2.2.3",
        "@authority host is lowercased",
        attach(r.clone(), &signed(&r, &["\"@authority\""], CREATED))
    ));

    let mut r = simple("/", None);
    r.authority = "example.com:443".into();
    v.push(case!(
        "V08-authority-default-port",
        Valid,
        Accept,
        "2.2.3",
        "@authority drops the default port :443 on https",
        attach(r.clone(), &signed(&r, &["\"@authority\""], CREATED))
    ));

    let mut r = simple("/", None);
    r.authority = "example.com:8443".into();
    v.push(case!(
        "V09-authority-port",
        Valid,
        Accept,
        "2.2.3",
        "@authority keeps a non-default port",
        attach(r.clone(), &signed(&r, &["\"@authority\""], CREATED))
    ));

    let r = simple("/path", Some("param=value"));
    v.push(case!(
        "V10-target-uri",
        Valid,
        Accept,
        "2.2.2",
        "@target-uri",
        attach(r.clone(), &signed(&r, &["\"@target-uri\""], CREATED))
    ));

    let r = simple("/path", Some("param=value"));
    v.push(case!(
        "V11-request-target",
        Valid,
        Accept,
        "2.2.5",
        "@request-target in origin form",
        attach(r.clone(), &signed(&r, &["\"@request-target\""], CREATED))
    ));

    let r = simple("/", None);
    v.push(case!(
        "V12-scheme",
        Valid,
        Accept,
        "2.2.4",
        "@scheme",
        attach(r.clone(), &signed(&r, &["\"@scheme\""], CREATED))
    ));

    let r = simple("/", Some("q=a+b&x=%41"));
    v.push(case!(
        "V13-query-param-encoding",
        Valid,
        Accept,
        "2.2.8",
        "@query-param decodes then re-encodes the value",
        attach(
            r.clone(),
            &signed(&r, &["\"@query-param\";name=\"q\""], CREATED)
        )
    ));

    let r = simple("/", Some("q=it's"));
    v.push(case!(
        "V14-query-subdelim",
        Valid,
        Accept,
        "2.2.7",
        "@query with a valid sub-delim (') kept as sent",
        attach(r.clone(), &signed(&r, &["\"@query\""], CREATED))
    ));

    let r = simple("/foo", None);
    let s = signed(&r, &["\"@method\"", "\"@path\""], CREATED);
    let reformatted = Signed {
        input: format!("sig1=( \"@method\"  \"@path\" ){CREATED}"),
        signature: s.signature.clone(),
    };
    v.push(case!(
        "V15-input-reformatted",
        Valid,
        Accept,
        "3.2 step 7; RFC 8941 4.2.1.2",
        "Signature-Input re-spaced by an intermediary (still valid SF); verifier must re-serialize",
        attach(r, &reformatted)
    ));

    let r = simple("/foo", None);
    let s1 = signed(&r, &["\"@method\"", "\"@path\""], CREATED);
    let s0 = sign(
        &r,
        &inner_list(&["\"@path\""], CREATED),
        "sig0",
        &test_key(),
    )
    .unwrap();
    let rr = r
        .clone()
        .header("Signature-Input", &s0.input)
        .header("Signature-Input", &s1.input)
        .header("Signature", &s0.signature)
        .header("Signature", &s1.signature);
    v.push(case!(
        "V16-two-signatures-two-lines",
        Valid,
        Accept,
        "4.1, 4.2",
        "two signatures sent as separate field lines; verify sig1",
        rr
    ));

    let r = simple("/foo", None);
    let rr = r
        .clone()
        .header("Signature-Input", &format!("{}, {}", s0.input, s1.input))
        .header("Signature", &format!("{}, {}", s0.signature, s1.signature));
    v.push(case!(
        "V17-two-signatures-one-line",
        Valid,
        Accept,
        "4.1, 4.2",
        "two signatures in one dictionary; verify the second",
        rr
    ));

    let r = simple("/", None).header("X-Custom", "v");
    v.push(case!(
        "V18-field-name-case",
        Valid,
        Accept,
        "2.1",
        "message field name in mixed case, component lowercase",
        attach(r.clone(), &signed(&r, &["\"x-custom\""], CREATED))
    ));

    let r = simple("/foo", None);
    let p = format!("{CREATED};alg=\"ed25519\"");
    v.push(case!(
        "V19-alg-matches",
        Valid,
        Accept,
        "3.2 step 6",
        "alg=\"ed25519\" present and matching the key",
        attach(r.clone(), &signed(&r, &["\"@method\""], &p))
    ));

    let r = simple("/", None).header("X-Obs-Fold", "Obsolete\r\n    line folding.");
    v.push(case!(
        "V20-obs-fold",
        Valid,
        Accept,
        "2.1",
        "HTTP/1.1 obsolete line folding replaced by one space",
        attach(r.clone(), &signed(&r, &["\"x-obs-fold\""], CREATED))
    ));

    let r = test_request();
    v.push(case!(
        "V21-digest-sha512",
        Valid,
        Accept,
        "2.1; App. B.2",
        "content-digest (sha-512, correct for the body) covered",
        attach(r.clone(), &signed(&r, &["\"content-digest\""], CREATED))
    ));

    // --- Tampered ----------------------------------------------------------
    let full = [
        "\"@method\"",
        "\"@path\"",
        "\"@query\"",
        "\"@authority\"",
        "\"x-amount\"",
    ];
    let base_req = Request::new(
        "POST",
        "https",
        "example.com",
        "/transfer",
        Some("to=alice&n=1"),
    )
    .header("Host", "example.com")
    .header("X-Amount", "10");
    let s = signed(&base_req, &full, CREATED);
    let t = |id, rfc, what, f: &dyn Fn(Request) -> Request| {
        case!(
            id,
            Tampered,
            Reject,
            rfc,
            what,
            attach(f(base_req.clone()), &s)
        )
    };
    v.push(t("T01-method", "2.2.1", "POST -> PUT", &|mut r| {
        r.method = "PUT".into();
        r
    }));
    v.push(t(
        "T02-method-case",
        "2.2.1",
        "POST -> post (case sensitive)",
        &|mut r| {
            r.method = "post".into();
            r
        },
    ));
    v.push(t(
        "T03-path",
        "2.2.6",
        "/transfer -> /transfer2",
        &|mut r| {
            r.path = "/transfer2".into();
            r
        },
    ));
    v.push(t(
        "T04-query-value",
        "2.2.7",
        "to=alice -> to=mallory",
        &|mut r| {
            r.query = Some("to=mallory&n=1".into());
            r
        },
    ));
    v.push(t(
        "T05-query-order",
        "2.2.7",
        "query parameters reordered",
        &|mut r| {
            r.query = Some("n=1&to=alice".into());
            r
        },
    ));
    v.push(t("T06-field-value", "2.1", "X-Amount 10 -> 1000", &|r| {
        r.set("X-Amount", "1000")
    }));
    v.push(t(
        "T07-field-removed",
        "2.5 step 2.5",
        "covered field removed",
        &|r| r.without("X-Amount"),
    ));
    v.push(t(
        "T08-field-duplicated",
        "2.1",
        "second X-Amount line appended",
        &|r| r.header("X-Amount", "1000"),
    ));
    v.push(t("T09-authority", "2.2.3", "host changed", &|mut r| {
        r.authority = "evil.example".into();
        r
    }));
    v.push(t(
        "T10-path-dotseg-prefix",
        "2.2.6",
        "/transfer -> /x/../transfer",
        &|mut r| {
            r.path = "/x/../transfer".into();
            r
        },
    ));

    let r = simple("/", Some("q=it%27s"));
    let s = signed(&r, &["\"@query\""], CREATED);
    let mut rr = r.clone();
    rr.query = Some("q=it's".into());
    v.push(case!(
        "T11-query-pct-collapse",
        Tampered,
        Reject,
        "2.2.7",
        "signed ?q=it%27s, received ?q=it's (no decoding allowed)",
        attach(rr, &s)
    ));

    let r = simple("/", Some("q=it's"));
    let s = signed(&r, &["\"@query\""], CREATED);
    let mut rr = r.clone();
    rr.query = Some("q=it%27s".into());
    v.push(case!(
        "T12-query-pct-expand",
        Tampered,
        Reject,
        "2.2.7",
        "signed ?q=it's, received ?q=it%27s",
        attach(rr, &s)
    ));

    let r = simple("/a%2fb", None);
    let s = signed(&r, &["\"@path\""], CREATED);
    let mut rr = r.clone();
    rr.path = "/a%2Fb".into();
    v.push(case!(
        "T13-path-pct-case",
        Tampered,
        Reject,
        "2.2.6",
        "signed /a%2fb, received /a%2Fb (simple string comparison)",
        attach(rr, &s)
    ));

    let mut r = simple("/", None);
    r.authority = "example.com:8443".into();
    let s = signed(&r, &["\"@authority\""], CREATED);
    let mut rr = r.clone();
    rr.authority = "example.com:9443".into();
    v.push(case!(
        "T14-authority-port",
        Tampered,
        Reject,
        "2.2.3",
        "port 8443 -> 9443",
        attach(rr, &s)
    ));

    let r = simple("/", Some("Pet=dog"));
    let s = signed(&r, &["\"@query-param\";name=\"Pet\""], CREATED);
    let mut rr = r.clone();
    rr.query = Some("Pet=cat".into());
    v.push(case!(
        "T15-query-param-value",
        Tampered,
        Reject,
        "2.2.8",
        "Pet=dog -> Pet=cat",
        attach(rr, &s)
    ));

    let r = simple("/foo", None);
    let p = format!("{CREATED};alg=\"rsa-pss-sha512\"");
    v.push(case!(
        "T16-alg-mismatch",
        Tampered,
        Reject,
        "3.2 step 6.5",
        "alg=\"rsa-pss-sha512\" declared, Ed25519 key used",
        attach(r.clone(), &signed_raw_alg(&r, &p))
    ));

    let r = simple("/foo", None);
    let p = format!("(\"@method\" \"@signature-params\"){CREATED}");
    v.push(case!(
        "T17-covers-signature-params",
        Tampered,
        Reject,
        "2.3",
        "@signature-params listed as a covered component",
        attach(
            r,
            &manual(
                &[("\"@method\"", "GET"), ("\"@signature-params\"", "x")],
                &p
            )
        )
    ));

    let r = simple("/foo", None);
    let p = format!("(\"@method\" \"@method\"){CREATED}");
    v.push(case!(
        "T18-duplicate-component",
        Tampered,
        Reject,
        "2.5 step 2.1",
        "same component covered twice",
        attach(
            r,
            &manual(&[("\"@method\"", "GET"), ("\"@method\"", "GET")], &p)
        )
    ));

    let r = simple("/foo", None);
    let s = signed(&r, &["\"@method\""], CREATED);
    let s2 = Signed {
        input: s.input.replacen("sig1=", "sig2=", 1),
        signature: s.signature,
    };
    v.push(case!(
        "T19-label-mismatch",
        Tampered,
        Reject,
        "3.2 step 1.2",
        "Signature labelled sig1, Signature-Input only has sig2",
        attach(r, &s2)
    ));

    let r = simple("/foo", None);
    let mut s = signed(&r, &["\"@method\""], CREATED);
    s.signature = flip_last_b64(&s.signature);
    v.push(case!(
        "T20-signature-bitflip",
        Tampered,
        Reject,
        "3.3",
        "one signature byte changed (negative control)",
        attach(r, &s)
    ));

    let r = simple("/foo", None);
    let other = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let s = sign(&r, &inner_list(&["\"@method\""], CREATED), "sig1", &other).unwrap();
    v.push(case!(
        "T21-wrong-key",
        Tampered,
        Reject,
        "3.2 step 5",
        "signed with a different key (negative control)",
        attach(r, &s)
    ));

    let r = simple("/foo", None);
    let p = format!("(\"@foo\"){CREATED}");
    v.push(case!(
        "T22-unknown-derived",
        Tampered,
        Reject,
        "2.5 step 2.5",
        "unknown derived component @foo",
        attach(r, &manual(&[("\"@foo\"", "bar")], &p))
    ));

    let r = test_request();
    let s = signed(&r, &["\"content-digest\""], CREATED);
    let rr = r.clone().body(br#"{"hello": "mallory"}"#);
    v.push(case!(
        "T23-body-swap-digest-kept",
        Tampered,
        Ambiguous,
        "2.1 (header text only); RFC 9530 is a separate check",
        "body changed, signed Content-Digest kept",
        attach(rr, &s)
    ));

    // --- Parser edge cases -------------------------------------------------
    let r = simple("/foo", None);
    let good = signed(&r, &["\"@method\"", "\"@path\""], CREATED);
    let rr = r
        .clone()
        .header(
            "Signature-Input",
            &format!("{}, sig1=(\"@method\"){CREATED}", good.input),
        )
        .header("Signature", &good.signature);
    v.push(case!(
        "P01-duplicate-label-last-wins",
        Parser,
        Reject,
        "RFC 8941 4.2.2",
        "Signature-Input repeats label sig1; the last member wins and does not match the signature",
        rr
    ));

    let r = simple("/foo", None);
    let s = signed(&r, &["\"@method\""], CREATED);
    let urlsafe = Signed {
        input: s.input.clone(),
        signature: s.signature.replace('+', "-").replace('/', "_"),
    };
    let has_alpha = urlsafe.signature != s.signature;
    v.push(Case {
        expect: if has_alpha {
            Expect::Reject
        } else {
            Expect::Accept
        },
        ..case!(
            "P02-signature-urlsafe-b64",
            Parser,
            Reject,
            "RFC 8941 4.2.7",
            "Signature byte sequence written in base64url alphabet",
            attach(r, &urlsafe)
        )
    });

    let r = simple("/foo", None);
    let noncanon = format!("( \"@method\"  \"@path\" ){CREATED}");
    let s = manual(&[("\"@method\"", "GET"), ("\"@path\"", "/foo")], &noncanon);
    v.push(case!(
        "P03-signer-noncanonical-params",
        Parser,
        Ambiguous,
        "2.3 vs 3.2 step 7",
        "signer signed its own non-canonical Signature-Input text verbatim",
        attach(r, &s)
    ));

    let r = simple("/a/./b", None);
    v.push(case!(
        "P04-path-dotseg-raw",
        Parser,
        Ambiguous,
        "2.2.6",
        "@path with a dot segment, unchanged in transit",
        attach(r.clone(), &signed(&r, &["\"@path\""], CREATED))
    ));

    let r = simple("/a/b", None);
    let s = signed(&r, &["\"@path\""], CREATED);
    let mut rr = r.clone();
    rr.path = "/a/./b".into();
    v.push(case!(
        "P05-path-dotseg-added",
        Parser,
        Ambiguous,
        "2.2.6",
        "signed /a/b, received /a/./b",
        attach(rr, &s)
    ));

    let r = simple("/", Some("Pet=dog&Pet=cat"));
    let p = format!("(\"@query-param\";name=\"Pet\"){CREATED}");
    let s = manual(&[("\"@query-param\";name=\"Pet\"", "dog")], &p);
    v.push(case!(
        "P06-query-param-repeated",
        Parser,
        Ambiguous,
        "2.2.8",
        "query parameter name repeated; signer used the first",
        attach(r, &s)
    ));

    let r = simple("/", None).header("X-Custom", "v");
    let p = format!("(\"X-Custom\"){CREATED}");
    let s = manual(&[("\"x-custom\"", "v")], &p);
    v.push(case!(
        "P07-uppercase-component",
        Parser,
        Ambiguous,
        "2.1",
        "Signature-Input names (\"X-Custom\"); signer lowercased the base line",
        attach(r, &s)
    ));

    v
}

/// Reference-sign with an `alg` that the reference verifier would refuse.
fn signed_raw_alg(req: &Request, params: &str) -> Signed {
    let list = inner_list(&["\"@method\""], params);
    let base = reference::signature_base(req, &list).unwrap();
    sign_base(&base, &params_value(&list).unwrap(), "sig1", &test_key())
}

fn flip_last_b64(sig: &str) -> String {
    // sig1=:....AAAA==: -> change the first base64 character after ':'.
    let start = sig.find(':').unwrap() + 1;
    let mut b: Vec<char> = sig.chars().collect();
    b[start] = if b[start] == 'A' { 'B' } else { 'A' };
    b.into_iter().collect()
}
