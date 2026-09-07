//! # kerbcore
//!
//! Pure-Rust Kerberos building blocks — no FFI, no dependency on a host krb5.
//!
//! **Spike status (1.5.1):** this first cut ships only the RFC 3961 / RFC 3962
//! crypto for the `aes256-cts-hmac-sha1-96` profile (etype 18) — n-fold, AES
//! CBC-CTS, DR/DK key derivation, HMAC-SHA1-96, RFC 3961 §5.3 subkey derivation,
//! and the generic encrypt-then-MAC primitive. It is KAT-verified against the
//! RFC 3961 n-fold vector and round-trips across the CTS edge lengths.
//!
//! The Kerberos **ASN.1 message codec** (AS/TGS/AP REQ+REP, PA-DATA, Ticket,
//! KRB-ERROR) and an **AS-REQ/TGS-REQ client** land next (1.6), at which point
//! this replaces `picky-krb` inside ADhammer's Kerberos stack. Offensive
//! compositions (golden/silver/diamond/S4U-abuse/PKINIT-relay) intentionally do
//! **not** live here — they stay in the ADhammer CLI per its dual-use rule.
//!
//! See `docs/PLAN_KRB_CRATE.md` in the ADhammer repo for the roadmap.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod der;
pub mod rc4;
pub mod rfc8009;

pub use crypto::*;
