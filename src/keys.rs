//! Typed enctype + key abstraction (0.2.0). One [`KerberosKey`] carries its [`Enctype`]
//! and dispatches encrypt / decrypt / checksum / string-to-key to the correct family, so
//! a caller can no longer (a) advertise the wrong etype, (b) feed a mis-sized key into an
//! AES primitive (previously a `panic!`), or (c) leak key bytes through `Debug`. This
//! wraps the proven per-family code in [`crate::crypto`] / [`crate::rfc8009`] /
//! [`crate::rc4`] — it is a dispatch layer, not a reimplementation.

use core::fmt;

use zeroize::Zeroizing;

use crate::rfc8009::Rfc8009Etype;
use crate::{crypto, rc4, rfc8009};

/// The Kerberos encryption types kerbcore implements. New enctypes (RFC 8009
/// AES-SHA2 variants, camellia, etc.) may be added in future minor releases —
/// callers should match with a `_` arm.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enctype {
    /// 17 — `aes128-cts-hmac-sha1-96` (RFC 3962).
    Aes128CtsHmacSha1_96,
    /// 18 — `aes256-cts-hmac-sha1-96` (RFC 3962).
    Aes256CtsHmacSha1_96,
    /// 19 — `aes128-cts-hmac-sha256-128` (RFC 8009).
    Aes128CtsHmacSha256_128,
    /// 20 — `aes256-cts-hmac-sha384-192` (RFC 8009).
    Aes256CtsHmacSha384_192,
    /// 23 — `rc4-hmac` (RFC 4757).
    Rc4Hmac,
}

impl Enctype {
    /// Map the on-wire etype number to an [`Enctype`], or `None` if unsupported.
    pub fn from_i32(v: i32) -> Option<Self> {
        Some(match v {
            17 => Self::Aes128CtsHmacSha1_96,
            18 => Self::Aes256CtsHmacSha1_96,
            19 => Self::Aes128CtsHmacSha256_128,
            20 => Self::Aes256CtsHmacSha384_192,
            23 => Self::Rc4Hmac,
            _ => return None,
        })
    }
    /// The on-wire etype number.
    pub fn to_i32(self) -> i32 {
        match self {
            Self::Aes128CtsHmacSha1_96 => 17,
            Self::Aes256CtsHmacSha1_96 => 18,
            Self::Aes128CtsHmacSha256_128 => 19,
            Self::Aes256CtsHmacSha384_192 => 20,
            Self::Rc4Hmac => 23,
        }
    }
    /// The key length in bytes for this etype.
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes256CtsHmacSha1_96 | Self::Aes256CtsHmacSha384_192 => 32,
            _ => 16,
        }
    }
    /// The confounder length in bytes (one AES block for AES; 8 for RC4).
    pub fn confounder_len(self) -> usize {
        match self {
            Self::Rc4Hmac => rc4::RC4_CONFOUNDER_LEN,
            _ => crypto::CONFOUNDER_LEN,
        }
    }
    /// The cksumtype kerbcore emits for a TGS-REQ authenticator under this key, or `None`
    /// when kerbcore does not yet emit one for it. `None` for the RFC 8009 etypes: their
    /// authenticator cksumtype integers are not yet verified here, and AD does not issue
    /// RFC 8009 TGT session keys by default, so [`crate::client::build_tgs_req`] refuses
    /// rather than guess. AES-SHA1 = 15/16 (RFC 3962), RC4 = -138 (hmac-md5).
    pub fn authenticator_cksumtype(self) -> Option<i32> {
        Some(match self {
            Self::Aes128CtsHmacSha1_96 => 15,
            Self::Aes256CtsHmacSha1_96 => 16,
            Self::Rc4Hmac => rc4::SIG_HMAC_MD5,
            Self::Aes128CtsHmacSha256_128 | Self::Aes256CtsHmacSha384_192 => return None,
        })
    }
    fn rfc8009(self) -> Option<Rfc8009Etype> {
        match self {
            Self::Aes128CtsHmacSha256_128 => Some(Rfc8009Etype::Aes128Sha256),
            Self::Aes256CtsHmacSha384_192 => Some(Rfc8009Etype::Aes256Sha384),
            _ => None,
        }
    }
}

/// Errors from the typed key API. All graceful — never a panic on wire input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyError {
    /// The etype number is not one kerbcore implements.
    UnsupportedEnctype(i32),
    /// The key length does not match the etype.
    WrongKeyLen {
        enctype: i32,
        got: usize,
        want: usize,
    },
    /// Decrypt failed — HMAC/checksum mismatch or a too-short ciphertext.
    Decrypt(&'static str),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedEnctype(e) => write!(f, "unsupported enctype {e}"),
            Self::WrongKeyLen { enctype, got, want } => {
                write!(f, "etype {enctype}: key is {got} bytes, want {want}")
            }
            Self::Decrypt(w) => write!(f, "decrypt failed: {w}"),
        }
    }
}
impl std::error::Error for KeyError {}

/// A Kerberos key tagged with its enctype. The raw bytes are zeroized on drop and never
/// printed by `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct KerberosKey {
    enctype: Enctype,
    key: Zeroizing<Vec<u8>>,
}

impl KerberosKey {
    /// Build a key, validating its length against the etype.
    pub fn new(enctype: Enctype, key: Vec<u8>) -> Result<Self, KeyError> {
        if key.len() != enctype.key_len() {
            return Err(KeyError::WrongKeyLen {
                enctype: enctype.to_i32(),
                got: key.len(),
                want: enctype.key_len(),
            });
        }
        Ok(Self {
            enctype,
            key: Zeroizing::new(key),
        })
    }
    /// Build a key from the on-wire etype number.
    pub fn from_i32(etype: i32, key: Vec<u8>) -> Result<Self, KeyError> {
        let e = Enctype::from_i32(etype).ok_or(KeyError::UnsupportedEnctype(etype))?;
        Self::new(e, key)
    }
    /// The etype.
    pub fn enctype(&self) -> Enctype {
        self.enctype
    }
    /// The raw key bytes (borrow; the buffer stays zeroize-on-drop).
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Encrypt `plaintext` for `usage` with a fresh OS-CSPRNG confounder (the production path).
    pub fn encrypt(&self, usage: u32, plaintext: &[u8]) -> Vec<u8> {
        let mut conf = vec![0u8; self.enctype.confounder_len()];
        getrandom::getrandom(&mut conf).expect("OS CSPRNG available for Kerberos confounder");
        self.encrypt_with_confounder(usage, &conf, plaintext)
    }

    /// Deterministic-confounder encrypt — for tests / differential vectors. `conf` must be the
    /// enctype's confounder length ([`Enctype::confounder_len`]); production code uses [`Self::encrypt`].
    pub fn encrypt_with_confounder(&self, usage: u32, conf: &[u8], plaintext: &[u8]) -> Vec<u8> {
        assert_eq!(
            conf.len(),
            self.enctype.confounder_len(),
            "confounder length must match the enctype"
        );
        match self.enctype {
            Enctype::Aes128CtsHmacSha1_96 | Enctype::Aes256CtsHmacSha1_96 => {
                let c: [u8; crypto::CONFOUNDER_LEN] = conf.try_into().expect("16-byte confounder");
                crypto::encrypt_message(&self.key, usage, &c, plaintext)
            }
            Enctype::Aes128CtsHmacSha256_128 | Enctype::Aes256CtsHmacSha384_192 => {
                let et = self.enctype.rfc8009().expect("rfc8009 etype");
                let c: [u8; crypto::CONFOUNDER_LEN] = conf.try_into().expect("16-byte confounder");
                rfc8009::encrypt(et, &self.key, usage, &c, plaintext)
            }
            Enctype::Rc4Hmac => {
                let c: [u8; rc4::RC4_CONFOUNDER_LEN] = conf.try_into().expect("8-byte confounder");
                rc4::encrypt(&self.key, usage as i32, &c, plaintext)
            }
        }
    }

    /// Decrypt a sealed message for `usage`.
    pub fn decrypt(&self, usage: u32, sealed: &[u8]) -> Result<Vec<u8>, KeyError> {
        match self.enctype {
            Enctype::Aes128CtsHmacSha1_96 | Enctype::Aes256CtsHmacSha1_96 => {
                crypto::decrypt_message(&self.key, usage, sealed)
                    .map_err(|_| KeyError::Decrypt("AES-SHA1 HMAC/length"))
            }
            Enctype::Aes128CtsHmacSha256_128 | Enctype::Aes256CtsHmacSha384_192 => {
                let et = self.enctype.rfc8009().expect("rfc8009 etype");
                rfc8009::decrypt(et, &self.key, usage, sealed)
                    .map_err(|_| KeyError::Decrypt("RFC8009 HMAC/length"))
            }
            Enctype::Rc4Hmac => rc4::decrypt(&self.key, usage as i32, sealed)
                .map_err(|_| KeyError::Decrypt("RC4-HMAC checksum/length")),
        }
    }

    /// The keyed checksum for `usage` (the authenticator/MIC checksum bytes for this etype).
    pub fn checksum(&self, usage: u32, data: &[u8]) -> Vec<u8> {
        match self.enctype {
            Enctype::Aes128CtsHmacSha1_96 | Enctype::Aes256CtsHmacSha1_96 => {
                crypto::hmac_sha1_96(&crypto::derive_kc(&self.key, usage), data).to_vec()
            }
            Enctype::Aes128CtsHmacSha256_128 | Enctype::Aes256CtsHmacSha384_192 => {
                let et = self.enctype.rfc8009().expect("rfc8009 etype");
                rfc8009::checksum(et, &self.key, usage, data)
            }
            Enctype::Rc4Hmac => rc4::hmac_md5_checksum(&self.key, usage as i32, data).to_vec(),
        }
    }

    /// Derive a key from a passphrase + salt via the etype's string-to-key. RC4 ignores the
    /// salt/iterations (its s2k is the NT hash).
    pub fn string_to_key(enctype: Enctype, passphrase: &str, salt: &[u8], iterations: u32) -> Self {
        let key = match enctype {
            Enctype::Aes128CtsHmacSha1_96 => {
                crypto::string_to_key(16, passphrase.as_bytes(), salt, iterations)
            }
            Enctype::Aes256CtsHmacSha1_96 => {
                crypto::string_to_key(32, passphrase.as_bytes(), salt, iterations)
            }
            Enctype::Aes128CtsHmacSha256_128 => rfc8009::string_to_key(
                Rfc8009Etype::Aes128Sha256,
                passphrase.as_bytes(),
                salt,
                iterations,
            ),
            Enctype::Aes256CtsHmacSha384_192 => rfc8009::string_to_key(
                Rfc8009Etype::Aes256Sha384,
                passphrase.as_bytes(),
                salt,
                iterations,
            ),
            Enctype::Rc4Hmac => rc4::nt_hash(passphrase).to_vec(),
        };
        Self {
            enctype,
            key: Zeroizing::new(key),
        }
    }
}

impl fmt::Debug for KerberosKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key bytes.
        write!(
            f,
            "KerberosKey {{ enctype: {:?}, key: <{} bytes redacted> }}",
            self.enctype,
            self.key.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Enctype; 5] = [
        Enctype::Aes128CtsHmacSha1_96,
        Enctype::Aes256CtsHmacSha1_96,
        Enctype::Aes128CtsHmacSha256_128,
        Enctype::Aes256CtsHmacSha384_192,
        Enctype::Rc4Hmac,
    ];

    fn test_key(e: Enctype) -> KerberosKey {
        let k: Vec<u8> = (0..e.key_len() as u8).map(|b| b ^ 0x5c).collect();
        KerberosKey::new(e, k).unwrap()
    }

    #[test]
    fn enctype_number_round_trips() {
        for e in ALL {
            assert_eq!(Enctype::from_i32(e.to_i32()), Some(e));
        }
        assert_eq!(Enctype::from_i32(1), None); // DES — unsupported
    }

    #[test]
    fn wrong_key_len_rejected() {
        let err = KerberosKey::new(Enctype::Aes256CtsHmacSha1_96, vec![0u8; 16]).unwrap_err();
        assert!(matches!(
            err,
            KeyError::WrongKeyLen {
                got: 16,
                want: 32,
                ..
            }
        ));
        assert!(matches!(
            KerberosKey::from_i32(1, vec![0u8; 8]),
            Err(KeyError::UnsupportedEnctype(1))
        ));
    }

    #[test]
    fn encrypt_decrypt_round_trip_every_enctype() {
        for e in ALL {
            let k = test_key(e);
            let msg = b"typed-key round trip across the whole etype matrix";
            let sealed = k.encrypt(7, msg);
            let back = k.decrypt(7, &sealed).expect("decrypt");
            assert_eq!(back, msg, "{e:?} round-trip");
            // wrong usage must fail to verify (proves usage is consumed)
            assert!(
                k.decrypt(8, &sealed).is_err(),
                "{e:?} wrong-usage must reject"
            );
        }
    }

    #[test]
    fn fresh_confounder_each_encrypt() {
        for e in ALL {
            let k = test_key(e);
            assert_ne!(
                k.encrypt(3, b"x"),
                k.encrypt(3, b"x"),
                "{e:?} confounder not random"
            );
        }
    }

    #[test]
    fn checksum_is_deterministic_and_keyed() {
        for e in ALL {
            let k = test_key(e);
            let a = k.checksum(6, b"body");
            assert_eq!(
                a,
                k.checksum(6, b"body"),
                "{e:?} checksum not deterministic"
            );
            assert_ne!(a, k.checksum(6, b"body2"), "{e:?} checksum ignores data");
            assert!(!a.is_empty());
        }
    }

    #[test]
    fn debug_never_leaks_key_bytes() {
        let k = KerberosKey::new(Enctype::Aes256CtsHmacSha1_96, vec![0xABu8; 32]).unwrap();
        let s = format!("{k:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains("ab"), "Debug leaked key bytes: {s}");
    }
}
