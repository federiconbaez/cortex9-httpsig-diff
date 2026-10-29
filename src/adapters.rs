//! The implementations under test behind one interface.
//!
//! Every adapter receives the same [`Request`] and reads `Signature-Input`
//! and `Signature` from it. Repeated field lines are handed to each crate
//! the way its API asks for them (see the notes on each adapter).

use std::collections::HashMap;

use serde_json::json;
use web_bot_auth::components::{
    CoveredComponent, DerivedComponent, HTTPField, QueryParamParameters,
};
use web_bot_auth::keyring::{Algorithm, KeyRing};
use web_bot_auth::message_signatures::{MessageVerifier, SignedMessage};

use crate::model::Request;
use crate::reference;

pub trait Implementation {
    fn name(&self) -> &'static str;
    /// Verify the signature labelled `label` on `req` with the RFC 9421
    /// test-key-ed25519 public key. `Err` carries the crate's error text.
    fn verify(&self, req: &Request, label: &str) -> Result<(), String>;
}

fn joined(req: &Request, name: &str) -> String {
    req.values(name).join(", ")
}

/// The reference implementation in [`crate::reference`].
pub struct Reference;

impl Implementation for Reference {
    fn name(&self) -> &'static str {
        "reference"
    }
    fn verify(&self, req: &Request, label: &str) -> Result<(), String> {
        reference::verify(req, label, &reference::test_key().verifying_key())
    }
}

/// `web-bot-auth` 0.7.0 (Cloudflare).
///
/// The crate asks the integrator for component values through
/// `SignedMessage::lookup_component`. HTTP fields are returned raw, one entry
/// per field line, as the trait documents; the crate combines them. Derived
/// components are NOT computed by the crate: this adapter answers them with
/// the reference derivation, so for derived components the results reflect
/// the reference, and what is tested is the crate's own part (parsing the
/// fields, choosing the label, combining field lines, serializing
/// `@signature-params`, verifying).
pub struct WebBotAuth;

struct WbaMsg<'a>(&'a Request);

impl SignedMessage for WbaMsg<'_> {
    fn lookup_component(&self, name: &CoveredComponent) -> Vec<String> {
        let req = self.0;
        match name {
            CoveredComponent::HTTP(HTTPField { name, parameters }) => {
                if !parameters.0.is_empty() {
                    return vec![];
                }
                req.values(name).into_iter().map(str::to_owned).collect()
            }
            CoveredComponent::Derived(d) => {
                let v = match d {
                    DerivedComponent::Method { req: false } => Some(req.method.clone()),
                    DerivedComponent::TargetUri { req: false } => Some(req.target_uri()),
                    DerivedComponent::Authority { req: false } => Some(reference::authority(req)),
                    DerivedComponent::Scheme { req: false } => {
                        Some(req.scheme.to_ascii_lowercase())
                    }
                    DerivedComponent::RequestTarget { req: false } => Some(req.request_target()),
                    DerivedComponent::Path { req: false } => Some(if req.path.is_empty() {
                        "/".into()
                    } else {
                        req.path.clone()
                    }),
                    DerivedComponent::Query { req: false } => {
                        Some(format!("?{}", req.query.as_deref().unwrap_or("")))
                    }
                    DerivedComponent::QueryParams { parameters } => match parameters.0.as_slice() {
                        [QueryParamParameters::Name(n)] => reference::query_param(req, n).ok(),
                        _ => None,
                    },
                    _ => None,
                };
                v.into_iter().collect()
            }
        }
    }
}

impl Implementation for WebBotAuth {
    fn name(&self) -> &'static str {
        "web-bot-auth"
    }
    fn verify(&self, req: &Request, label: &str) -> Result<(), String> {
        let mut ring = KeyRing::default();
        ring.import_raw(
            "k".into(),
            Algorithm::Ed25519,
            reference::test_key().verifying_key().to_bytes().to_vec(),
        );
        let v = MessageVerifier::parse(&WbaMsg(req), |(k, _)| k.as_str() == label)
            .map_err(|e| format!("{e:?}"))?;
        v.verify(&ring, Some("k".into()))
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    }
}

/// `wimsey-httpsig` 0.9.0, as a plain RFC 9421 implementation (WIMSE profile
/// off). Repeated `Signature-Input` / `Signature` lines are joined with ", ".
pub struct Wimsey;

impl Implementation for Wimsey {
    fn name(&self) -> &'static str {
        "wimsey-httpsig"
    }
    fn verify(&self, req: &Request, label: &str) -> Result<(), String> {
        let seed = reference::test_key().to_bytes();
        let vk = wimsey_httpsig::SigningKey::from_ed25519_seed(&seed).verifying_key();
        let r = wimsey_httpsig::HttpRequest {
            method: req.method.clone(),
            authority: req.authority.clone(),
            path: req.path.clone(),
            query: req.query.clone(),
            headers: req.headers.clone(),
        };
        let cfg = wimsey_httpsig::VerifyConfig {
            label: Some(label.into()),
            ..Default::default()
        };
        wimsey_httpsig::verify(
            &r,
            &joined(req, "signature-input"),
            &joined(req, "signature"),
            &vk,
            &cfg,
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }
}

/// `aauth-httpsig` 0.1.2 through its `prepare_verification` entry point.
///
/// Its request type holds headers in a `HashMap<String, String>`, so repeated
/// field lines are folded by the adapter with ", " (raw values, no trimming).
/// The key is passed as an `hwk` `Signature-Key` (required by the API) and
/// then verified against the same trusted public key.
pub struct Aauth;

impl Implementation for Aauth {
    fn name(&self) -> &'static str {
        "aauth-httpsig"
    }
    fn verify(&self, req: &Request, label: &str) -> Result<(), String> {
        let mut headers: HashMap<String, String> = HashMap::new();
        for (n, v) in &req.headers {
            let key = headers
                .keys()
                .find(|k| k.eq_ignore_ascii_case(n))
                .cloned()
                .unwrap_or_else(|| n.clone());
            headers
                .entry(key)
                .and_modify(|e| {
                    e.push_str(", ");
                    e.push_str(v);
                })
                .or_insert_with(|| v.clone());
        }
        let uri = req.target_uri();
        let parts = aauth::RequestParts {
            method: &req.method,
            target_uri: &uri,
            headers: &headers,
            body: Some(&req.body),
        };
        let x = reference::TEST_KEY_ED25519_X;
        let sig_key = format!("{label}=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"{x}\"");
        let jwk = aauth::Jwk::from_value(&json!({"kty": "OKP", "crv": "Ed25519", "x": x}))
            .map_err(|e| e.to_string())?;
        let pk = aauth::jwk_to_public_key(&jwk).map_err(|e| e.to_string())?;
        let input = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("signature-input"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let sig = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("signature"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let prepared = aauth::prepare_verification(&parts, &input, &sig, &sig_key, Some(label))
            .map_err(|e| e.to_string())?;
        prepared.verify(&pk).map_err(|e| e.to_string())
    }
}

/// All implementations, reference first.
pub fn all() -> Vec<Box<dyn Implementation>> {
    vec![
        Box::new(Reference),
        Box::new(WebBotAuth),
        Box::new(Wimsey),
        Box::new(Aauth),
    ]
}
