//! Reference RFC 9421 implementation, written from Sections 2, 3 and 4 of
//! the RFC. Ed25519 only. Supports the derived components of Section 2.2
//! for requests and plain HTTP fields; field parameters (`sf`, `key`, `bs`,
//! `tr`, `req`) are rejected as not understood (Section 2.5 step 2.5).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sfv::{BareItem, InnerList, Item, ListEntry, Parameters, Parser, SerializeValue};

use crate::model::Request;

/// Combined field value per Section 2.1: each line trimmed, obsolete line
/// folding replaced by one space, joined with ", ".
pub fn field_value(req: &Request, name: &str) -> Option<String> {
    let v = req.values(name);
    if v.is_empty() {
        return None;
    }
    Some(
        v.iter()
            .map(|s| unfold(s.trim_matches(|c| c == ' ' || c == '\t')))
            .collect::<Vec<_>>()
            .join(", "),
    )
}

fn unfold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' || c == '\n' {
            while matches!(chars.peek(), Some('\r' | '\n' | ' ' | '\t')) {
                chars.next();
            }
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

/// `@authority` per Section 2.2.3: host lowercased, default port removed.
pub fn authority(req: &Request) -> String {
    let a = req.authority.to_ascii_lowercase();
    let default = match req.scheme.to_ascii_lowercase().as_str() {
        "https" => Some(":443"),
        "http" => Some(":80"),
        _ => None,
    };
    match default {
        Some(p) if a.ends_with(p) => a[..a.len() - p.len()].to_owned(),
        _ => a,
    }
}

/// `@query-param` value per Section 2.2.8 (HTML URL form decoding, then
/// "percent-encode after encoding").
pub fn query_param(req: &Request, name: &str) -> Result<String, String> {
    let q = req.query.as_deref().unwrap_or("");
    let found: Vec<String> = form_urlencoded::parse(q.as_bytes())
        .filter(|(k, _)| k == name)
        .map(|(_, v)| form_urlencoded::byte_serialize(v.as_bytes()).collect())
        .collect();
    match found.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(format!("query parameter {name} absent")),
        _ => Err(format!("query parameter {name} repeated")),
    }
}

/// Value of one covered component (an sfv Item from the Inner List).
pub fn component_value(req: &Request, item: &Item) -> Result<String, String> {
    let name = item
        .bare_item
        .as_string()
        .ok_or("component identifier is not a string")?
        .as_str()
        .to_owned();
    let params: Vec<&str> = item.params.keys().map(|k| k.as_str()).collect();
    if name == "@query-param" {
        if params != ["name"] {
            return Err("@query-param needs exactly the name parameter".into());
        }
        let n = item.params[0]
            .as_string()
            .ok_or("name parameter is not a string")?
            .as_str();
        return query_param(req, n);
    }
    if !params.is_empty() {
        return Err(format!("parameter not understood on {name}: {params:?}"));
    }
    match name.as_str() {
        "@method" => Ok(req.method.clone()),
        "@target-uri" => Ok(req.target_uri()),
        "@authority" => Ok(authority(req)),
        "@scheme" => Ok(req.scheme.to_ascii_lowercase()),
        "@request-target" => Ok(req.request_target()),
        "@path" => Ok(if req.path.is_empty() {
            "/".into()
        } else {
            req.path.clone()
        }),
        "@query" => Ok(format!("?{}", req.query.as_deref().unwrap_or(""))),
        "@signature-params" => Err("@signature-params must not be covered".into()),
        n if n.starts_with('@') => Err(format!("unknown derived component {n}")),
        n if n.bytes().any(|b| b.is_ascii_uppercase()) => {
            Err(format!("field component names must be lowercase: {n}"))
        }
        n => field_value(req, n).ok_or_else(|| format!("field {n} absent")),
    }
}

/// Canonical `@signature-params` value (Section 2.3) for an Inner List.
pub fn params_value(list: &InnerList) -> Result<String, String> {
    vec![ListEntry::InnerList(list.clone())]
        .serialize_value()
        .ok_or_else(|| "cannot serialize signature params".to_string())
}

/// Signature base (Section 2.5) for `list` over `req`.
pub fn signature_base(req: &Request, list: &InnerList) -> Result<String, String> {
    let mut out = String::new();
    let mut seen: Vec<String> = Vec::new();
    for item in &list.items {
        let id = item.serialize_value();
        if seen.contains(&id) {
            return Err(format!("component {id} covered twice"));
        }
        let value = component_value(req, item)?;
        out.push_str(&format!("{id}: {value}\n"));
        seen.push(id);
    }
    out.push_str(&format!("\"@signature-params\": {}", params_value(list)?));
    if !out.is_ascii() {
        return Err("non-ASCII signature base".into());
    }
    Ok(out)
}

/// Build the Inner List for `components` (identifiers as serialized, e.g.
/// `"@query-param";name="Pet"`) and `params` (serialized `;k=v` suffix).
pub fn inner_list(components: &[&str], params: &str) -> InnerList {
    let src = format!("({}){params}", components.join(" "));
    match Parser::new(&format!("x={src}")).parse_dictionary() {
        Ok(d) => match d.into_iter().next() {
            Some((_, ListEntry::InnerList(l))) => l,
            _ => panic!("not an inner list: {src}"),
        },
        Err(e) => panic!("bad components {src}: {e}"),
    }
}

/// Signature-Input and Signature field values produced by [`sign`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub input: String,
    pub signature: String,
}

/// Sign `req` over `list` with label `label`.
pub fn sign(
    req: &Request,
    list: &InnerList,
    label: &str,
    key: &SigningKey,
) -> Result<Signed, String> {
    let base = signature_base(req, list)?;
    Ok(sign_base(&base, &params_value(list)?, label, key))
}

/// Sign an explicit base string (used to re-sign RFC Appendix B bases).
pub fn sign_base(base: &str, params: &str, label: &str, key: &SigningKey) -> Signed {
    let sig = key.sign(base.as_bytes());
    Signed {
        input: format!("{label}={params}"),
        signature: format!("{label}=:{}:", STANDARD.encode(sig.to_bytes())),
    }
}

fn dict(req: &Request, name: &str) -> Result<sfv::Dictionary, String> {
    let v = req.values(name);
    if v.is_empty() {
        return Err(format!("{name} absent"));
    }
    Parser::new(&v.join(", "))
        .parse_dictionary()
        .map_err(|e| format!("{name}: {e}"))
}

/// Reference verifier (Section 3.2). The Signature-Input and Signature are
/// read from the request's own header fields. Verifies the label `label`.
pub fn verify(req: &Request, label: &str, key: &VerifyingKey) -> Result<(), String> {
    let inputs = dict(req, "signature-input")?;
    let sigs = dict(req, "signature")?;
    let list = match inputs.get(label) {
        Some(ListEntry::InnerList(l)) => l.clone(),
        _ => return Err(format!("no Signature-Input for {label}")),
    };
    let sig = match sigs.get(label) {
        Some(ListEntry::Item(Item {
            bare_item: BareItem::ByteSequence(b),
            ..
        })) => b.clone(),
        _ => return Err(format!("no Signature byte sequence for {label}")),
    };
    check_params(&list.params)?;
    let base = signature_base(req, &list)?;
    let sig = Signature::from_slice(&sig).map_err(|e| e.to_string())?;
    key.verify(base.as_bytes(), &sig).map_err(|e| e.to_string())
}

fn check_params(p: &Parameters) -> Result<(), String> {
    // Section 3.2 step 6.5: an alg parameter must agree with the key.
    if let Some(alg) = p.get("alg") {
        if alg.as_string().map(|s| s.as_str()) != Some("ed25519") {
            return Err("alg parameter does not match an Ed25519 key".into());
        }
    }
    for (k, v) in p {
        let ok = match k.as_str() {
            "created" | "expires" => v.as_integer().is_some(),
            "nonce" | "alg" | "keyid" | "tag" => v.as_string().is_some(),
            _ => true,
        };
        if !ok {
            return Err(format!(
                "signature parameter {} has the wrong type",
                k.as_str()
            ));
        }
    }
    Ok(())
}

/// RFC 9421 Appendix B.1.4 test-key-ed25519 (private scalar `d`).
pub const TEST_KEY_ED25519_D: &str = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU";
/// RFC 9421 Appendix B.1.4 public key `x`.
pub const TEST_KEY_ED25519_X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";

pub fn test_key() -> SigningKey {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let d: [u8; 32] = URL_SAFE_NO_PAD
        .decode(TEST_KEY_ED25519_D)
        .expect("b64")
        .try_into()
        .expect("32 bytes");
    SigningKey::from_bytes(&d)
}
