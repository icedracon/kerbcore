//! etype 23 — `rc4-hmac` (RFC 4757 / MS-KILE).
//!
//! Legacy but ubiquitous in Active Directory: RC4 service tickets, and the
//! crackable material behind kerberoasting / AS-REP-roasting. Its string-to-key
//! is simply the NT hash (`MD4(UTF-16LE(password))`) — which is exactly what makes
//! overpass-the-hash possible.
//!
//! Ported verbatim from ADhammer's live-DC-validated implementation (via
//! `ms-pac-forge::checksum`); a differential test in this module pins kerbcore's
//! output to that reference byte-for-byte. The confounder is an explicit parameter
//! (not RNG'd here) so the crate stays deterministic and RNG-free — callers supply
//! 8 random bytes in production.

use hmac::{Hmac, Mac};
use md4::Md4;
use md5::{Digest, Md5};

type HmacMd5 = Hmac<Md5>;

/// NT-hash length in bytes — the RC4-HMAC long-term key size.
pub const RC4_KEY_LEN: usize = 16;
/// RC4-HMAC confounder length (RFC 4757 §4).
pub const RC4_CONFOUNDER_LEN: usize = 8;
/// Leading HMAC-MD5 checksum length prepended to every RC4-HMAC ciphertext.
pub const RC4_CHECKSUM_LEN: usize = 16;

/// KERB_CHECKSUM_HMAC_MD5 signature type (RFC 4757 §4).
pub const SIG_HMAC_MD5: i32 = -138;

/// RC4-HMAC string-to-key: the NT hash, `MD4(UTF-16LE(password))`.
pub fn nt_hash(password: &str) -> [u8; RC4_KEY_LEN] {
    let mut md4 = Md4::new();
    for u in password.encode_utf16() {
        md4.update(u.to_le_bytes());
    }
    md4.finalize().into()
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut m = <HmacMd5 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// Raw RC4 keystream XOR (RFC 6229). Symmetric — the same call decrypts. Keys here
/// are always the 16-byte HMAC-MD5 output, so an empty key never reaches the KSA.
pub fn rc4_apply(key: &[u8], data: &[u8]) -> Vec<u8> {
    assert!(!key.is_empty(), "RC4 key must be non-empty");
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xff;
        s.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    data.iter()
        .map(|&b| {
            i = (i + 1) & 0xff;
            j = (j + s[i] as usize) & 0xff;
            s.swap(i, j);
            b ^ s[(s[i] as usize + s[j] as usize) & 0xff]
        })
        .collect()
}

/// MS-KILE key-usage remap for RC4-HMAC (RFC 4757 §3): a few usages are aliased.
/// The remapped value is emitted little-endian as the `T` seed for `Ki`.
fn usage_t(usage: i32) -> [u8; 4] {
    let ms = match usage {
        3 => 8,   // AS-REP enc-part
        9 => 8,   // TGS-REP enc-part (subkey)
        23 => 13, // per RFC 4757
        u => u,
    };
    (ms as u32).to_le_bytes()
}

/// RC4-HMAC encrypt (RFC 4757 §4). Output is `HMAC-MD5 checksum (16) || RC4(Ke, conf||plain)`.
///
/// `Ki = HMAC-MD5(key, T)`, `checksum = HMAC-MD5(Ki, conf||plain)`,
/// `Ke = HMAC-MD5(Ki, checksum)`. `key` is the NT hash (or any RC4 session key).
pub fn encrypt(
    key: &[u8],
    usage: i32,
    confounder: &[u8; RC4_CONFOUNDER_LEN],
    plaintext: &[u8],
) -> Vec<u8> {
    let ki = hmac_md5(key, &usage_t(usage));
    let mut data = confounder.to_vec();
    data.extend_from_slice(plaintext);
    let cksum = hmac_md5(&ki, &data);
    let ke = hmac_md5(&ki, &cksum);
    let mut out = cksum.to_vec();
    out.extend_from_slice(&rc4_apply(&ke, &data));
    out
}

/// Errors from [`decrypt`]. Wire-derived — a hostile peer can trigger either, so
/// both are graceful `Err`s, never panics.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rc4Error {
    /// Ciphertext shorter than checksum(16) + confounder(8).
    TooShort,
    /// HMAC-MD5 checksum did not verify — wrong key or tampered ciphertext.
    ChecksumMismatch,
}

impl core::fmt::Display for Rc4Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort => write!(f, "RC4-HMAC ciphertext too short"),
            Self::ChecksumMismatch => write!(f, "RC4-HMAC checksum mismatch (wrong key)"),
        }
    }
}
impl std::error::Error for Rc4Error {}

/// RC4-HMAC decrypt (RFC 4757 §4). Verifies the checksum, strips the 8-byte confounder.
pub fn decrypt(key: &[u8], usage: i32, ciphertext: &[u8]) -> Result<Vec<u8>, Rc4Error> {
    if ciphertext.len() < RC4_CHECKSUM_LEN + RC4_CONFOUNDER_LEN {
        return Err(Rc4Error::TooShort);
    }
    let (cksum, enc) = ciphertext.split_at(RC4_CHECKSUM_LEN);
    let ki = hmac_md5(key, &usage_t(usage));
    let ke = hmac_md5(&ki, cksum);
    let data = rc4_apply(&ke, enc);
    // Constant-time-ish compare over the 16-byte tag.
    let recomputed = hmac_md5(&ki, &data);
    let mut diff = 0u8;
    for i in 0..RC4_CHECKSUM_LEN {
        diff |= recomputed[i] ^ cksum[i];
    }
    if diff != 0 {
        return Err(Rc4Error::ChecksumMismatch);
    }
    Ok(data[RC4_CONFOUNDER_LEN..].to_vec())
}

/// KERB_CHECKSUM_HMAC_MD5 (checksum type -138, RFC 4757 §4) — the PAC-signature
/// algorithm that pairs with an RC4 key.
pub fn hmac_md5_checksum(key: &[u8], usage: i32, data: &[u8]) -> [u8; 16] {
    let ksign = hmac_md5(key, b"signaturekey\0");
    let mut md5 = Md5::new();
    md5.update(usage.to_le_bytes());
    md5.update(data);
    let tmp = md5.finalize();
    hmac_md5(&ksign, &tmp)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── KAT: NT hash (MD4 of UTF-16LE) against canonical values ─────────
    #[test]
    fn nt_hash_known_vectors() {
        assert_eq!(hex(&nt_hash("")), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(
            hex(&nt_hash("password")),
            "8846f7eaee8fb117ad06bdd830b7586c"
        );
    }

    // ─── KAT: raw RC4 against the classic RFC/Wikipedia vector ────────────
    #[test]
    fn rc4_known_stream() {
        assert_eq!(hex(&rc4_apply(b"Key", b"Plaintext")), "bbf316e8d940af0ad3");
        assert_eq!(hex(&rc4_apply(b"Wiki", b"pedia")), "1021bf0420");
    }

    // ─── KAT: HMAC-MD5 against RFC 2202 test case 1 ───────────────────────
    #[test]
    fn hmac_md5_rfc2202_case1() {
        let key = [0x0bu8; 16];
        assert_eq!(
            hex(&hmac_md5(&key, b"Hi There")),
            "9294727a3638bb1c13f48ef8158bfc9d"
        );
    }

    // ─── RC4-HMAC round-trip + tamper rejection ──────────────────────────
    #[test]
    fn rc4_hmac_roundtrip_and_tamper() {
        let key = nt_hash("Passw0rd!");
        let conf = [0xa5u8; RC4_CONFOUNDER_LEN];
        let pt = b"etype-23 encrypted part";
        let ct = encrypt(&key, 3, &conf, pt);
        assert_eq!(decrypt(&key, 3, &ct).unwrap(), pt);
        // Flip a byte in the encrypted region → checksum must reject.
        let mut bad = ct.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert_eq!(decrypt(&key, 3, &bad), Err(Rc4Error::ChecksumMismatch));
        // Too short.
        assert_eq!(decrypt(&key, 3, &[0u8; 10]), Err(Rc4Error::TooShort));
    }

    // ─── DIFFERENTIAL: byte-exact against the live-DC-validated reference ─
    // This is the real conformance anchor — it validates the usage remap and the
    // whole construction, which a symmetric round-trip cannot. ms-pac-forge is a
    // dev-dependency only.
    #[test]
    fn rc4_hmac_matches_ms_pac_forge_reference() {
        let key = nt_hash("Diff3renti@l");
        for usage in [1i32, 2, 3, 4, 7, 9, 11, 23] {
            for len in [0usize, 1, 8, 16, 17, 31, 64] {
                let conf = [0x3cu8; RC4_CONFOUNDER_LEN];
                let pt: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
                let ours = encrypt(&key, usage, &conf, &pt);
                let theirs = ms_pac_forge::checksum::rc4_encrypt(&key, usage, &pt, Some(conf));
                assert_eq!(
                    ours, theirs,
                    "usage={usage} len={len}: RC4-HMAC diverged from reference"
                );
                // And our decrypt reads their ciphertext.
                assert_eq!(decrypt(&key, usage, &theirs).unwrap(), pt);
            }
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
