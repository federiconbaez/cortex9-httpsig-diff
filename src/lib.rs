//! Differential harness for HTTP Message Signatures (RFC 9421).
//!
//! * [`model`]: the HTTP request as it arrives at a verifier.
//! * [`reference`]: a small RFC 9421 signer/verifier written from the RFC
//!   text, used to sign the corpus and as the positive control.
//! * [`adapters`]: the crates under test behind one interface.
//! * [`cases`]: the pre-registered corpus (Appendix B vectors and edge cases).
//! * [`matrix`]: runs every case through every implementation.

pub mod adapters;
pub mod cases;
pub mod matrix;
pub mod model;
pub mod reference;
