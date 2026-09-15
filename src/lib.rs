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
//!   parses the KDC's reply — including the AP exchange (AP-REQ builder + AP-REP
//!   mutual-auth verification), EncKDCRepPart nonce anti-replay, ETYPE-INFO2
//!   `s2kparams`, and RFC 6806 cross-realm referral detection + credential
//!   lifecycle (renew/validate).
//! - Higher protocol layers: [`gss`] (RFC 4121 krb5-gss context token + MIC +
//!   Wrap), [`spnego`] (RFC 4178 negotiation), [`kkdcp`] (MS-KKDCP HTTPS proxy
//!   container), [`kpasswd`] (RFC 3244 change/set-password + a KRB-PRIV codec),
//!   and [`fast`] (RFC 6113 FAST wire codec + KRB-FX-CF2 armor-key math — the
//!   end-to-end AES-SHA1 PRF + a live-DC round-trip are the remaining gap; see
//!   the module docs).
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
pub mod fast;
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

/// Umbrella error covering every failure mode kerbcore surfaces. Per-module
/// errors (`DerError`, `KeyError`, `GssError`, …) are the precise types the
/// individual APIs return; `KerbError` is what a caller uses at their public
/// API boundary when they want ONE error type to bubble.
///
/// Every module error has a `From` conversion into `KerbError`, so `?` works
/// across modules without hand-written glue:
///
/// ```
/// use kerbcore::KerbError;
///
/// fn parse_and_decrypt() -> Result<Vec<u8>, KerbError> {
///     let der: &[u8] = &[];
///     let _ = kerbcore::messages::KrbError::decode(der)?; // DerError -> KerbError
///     Ok(Vec::new())
/// }
/// ```
#[non_exhaustive]
#[derive(Debug)]
pub enum KerbError {
    /// A DER codec error — malformed / truncated / non-canonical bytes from a
    /// KDC or peer.
    Der(der::DerError),
    /// A key-layer error — wrong-length key, unsupported etype, or decrypt
    /// integrity/length failure via [`KerberosKey`].
    Key(keys::KeyError),
    /// AES-SHA1 authenticated-decrypt failure (raw [`crypto::decrypt_message`]).
    /// Prefer [`KerberosKey::decrypt`] which surfaces a `KeyError` instead.
    Decrypt(crypto::DecryptError),
    /// RC4-HMAC decrypt failure (raw [`rc4::decrypt`]).
    Rc4(rc4::Rc4Error),
    /// RFC 8009 (AES-SHA2) decrypt failure (raw [`rfc8009::decrypt`]).
    Rfc8009(rfc8009::Rfc8009Error),
    /// GSS per-message protection error (bad token id, MIC mismatch, replay
    /// window rejection).
    Gss(gss::GssError),
    /// SPNEGO negotiation error.
    Spnego(spnego::SpnegoError),
    /// FAST armoring error.
    Fast(fast::FastError),
    /// KKDCP HTTPS-proxy container error.
    Kkdcp(kkdcp::KkdcpError),
    /// kpasswd / KRB-PRIV codec error.
    Kpasswd(kpasswd::KpasswdError),
}

impl std::fmt::Display for KerbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KerbError::Der(e) => write!(f, "DER: {e:?}"),
            KerbError::Key(e) => write!(f, "key: {e:?}"),
            KerbError::Decrypt(e) => write!(f, "decrypt: {e:?}"),
            KerbError::Rc4(e) => write!(f, "rc4-hmac: {e:?}"),
            KerbError::Rfc8009(e) => write!(f, "rfc8009: {e:?}"),
            KerbError::Gss(e) => write!(f, "gss: {e:?}"),
            KerbError::Spnego(e) => write!(f, "spnego: {e:?}"),
            KerbError::Fast(e) => write!(f, "fast: {e:?}"),
            KerbError::Kkdcp(e) => write!(f, "kkdcp: {e:?}"),
            KerbError::Kpasswd(e) => write!(f, "kpasswd: {e:?}"),
        }
    }
}

impl std::error::Error for KerbError {}

macro_rules! from_impl {
    ($src:path, $variant:ident) => {
        impl From<$src> for KerbError {
            fn from(e: $src) -> Self {
                KerbError::$variant(e)
            }
        }
    };
}
from_impl!(der::DerError, Der);
from_impl!(keys::KeyError, Key);
from_impl!(crypto::DecryptError, Decrypt);
from_impl!(rc4::Rc4Error, Rc4);
from_impl!(rfc8009::Rfc8009Error, Rfc8009);
from_impl!(gss::GssError, Gss);
from_impl!(spnego::SpnegoError, Spnego);
from_impl!(fast::FastError, Fast);
from_impl!(kkdcp::KkdcpError, Kkdcp);
from_impl!(kpasswd::KpasswdError, Kpasswd);

#[cfg(test)]
mod kerb_error_tests {
    use super::*;

    #[test]
    fn each_module_error_lifts_via_question_mark() {
        // Compile-only proof that `?` works from every per-module error into KerbError.
        fn _f() -> Result<(), KerbError> {
            Err(der::DerError::Truncated)?
        }
        assert!(_f().is_err());
    }

    #[test]
    fn display_has_variant_prefix() {
        let e: KerbError = der::DerError::Truncated.into();
        let s = format!("{e}");
        assert!(s.starts_with("DER: "), "unexpected display: {s}");
    }

    #[test]
    fn kerb_error_implements_error_trait() {
        fn _accepts_error<E: std::error::Error>(_: E) {}
        _accepts_error(KerbError::from(der::DerError::Truncated));
    }
}
