//! # kerbcore
//!
//! Pure-Rust Kerberos building blocks — no FFI, no dependency on a host krb5,
//! `#![forbid(unsafe_code)]`. Three layers, each cross-checked against RFC
//! known-answer vectors and (for the codec) a differential re-encode oracle:
//!
//! - [`crypto`] — RFC 3961 / 3962 AES-CTS-HMAC-SHA1 (etypes 17 & 18): n-fold,
//!   AES CBC-CTS, DR/DK, HMAC-SHA1-96, subkey derivation, PBKDF2 string-to-key,
//!   and the generic encrypt-then-integrity primitive.
//! - [`rfc8009`] — RFC 8009 AES-SHA2 (etypes 19 & 20): SP800-108 KDF,
//!   encrypt-then-MAC, string-to-key. [`rc4`] — RFC 4757 RC4-HMAC (etype 23).
//! - [`der`] + [`types`] + [`messages`] — a hand-rolled X.690 DER codec (total,
//!   never-panicking decoder) and the RFC 4120 message set (Ticket, AS/TGS
//!   REQ+REP, KRB-ERROR, PA-DATA). [`client`] assembles AS-REQ / TGS-REQ and
//!   parses the KDC's reply.
//!
//! This is the crate that replaces `picky-krb` inside ADhammer's Kerberos stack.
//! Offensive compositions (golden / silver / diamond / S4U-abuse / PKINIT-relay)
//! intentionally do **not** live here — they stay in the ADhammer CLI per its
//! dual-use rule.
//!
//! ## Status
//! `0.2.x` — the AS/TGS crypto + codec + client are complete and live-validated
//! (real TGT + service ticket) against Windows Server 2019 / 2022 / 2025. The API
//! is pre-1.0 and may change. `0.2.0` adds the typed [`KerberosKey`] / [`Enctype`]
//! abstraction: one key value dispatches encrypt / decrypt / checksum / string-to-key
//! across the whole etype matrix (17/18/19/20/23), zeroizes its bytes on drop, and never
//! prints them via `Debug`. (The `client::build_tgs_req` wire path still targets the
//! AES-SHA1 session-key profile AD issues; migrating it onto `KerberosKey` is next.)

#![forbid(unsafe_code)]

pub mod client;
pub mod crypto;
pub mod der;
pub mod gss;
pub mod keys;
pub mod kkdcp;
pub mod kpasswd;
pub mod messages;
pub mod rc4;
pub mod rfc8009;
pub mod spnego;
pub mod types;

pub use crypto::*;
pub use keys::{Enctype, KerberosKey, KeyError};
