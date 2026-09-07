//! etypes 19 & 20 — the RFC 8009 AES-SHA2 Kerberos profiles:
//! `aes128-cts-hmac-sha256-128` (19) and `aes256-cts-hmac-sha384-192` (20).
//!
//! This is the novel part of the crate: almost no Rust library implements RFC 8009
//! from scratch, and Windows Server 2022+ negotiates these enctypes. Unlike the
//! RFC 3961 profiles, key derivation here is the **NIST SP800-108 KDF in counter
//! mode** (not DR/DK/n-fold), and message protection is genuine **encrypt-then-MAC**
//! with HMAC-SHA-256/384 over `IV || ciphertext`.
//!
//! Every function is pinned to the RFC 8009 §7 known-answer test vectors (see the
//! tests): the derived Kc/Ke/Ki, and all four sample encryptions per enctype.
//!
//! AES-CTS itself is shared with the SHA-1 profiles ([`crate::crypto::aes_cts_encrypt`]).

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};

use crate::crypto::{aes_cts_decrypt, aes_cts_encrypt, AES_BLOCK_LEN};

/// The two RFC 8009 enctypes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rfc8009Etype {
    /// etype 19 — aes128-cts-hmac-sha256-128.
    Aes128Sha256,
    /// etype 20 — aes256-cts-hmac-sha384-192.
    Aes256Sha384,
}

impl Rfc8009Etype {
    /// IANA enctype number (19 or 20).
    pub fn number(self) -> i32 {
        match self {
            Rfc8009Etype::Aes128Sha256 => 19,
            Rfc8009Etype::Aes256Sha384 => 20,
        }
    }
    /// Base / encryption key length in bytes (AES-128 → 16, AES-256 → 32).
    pub fn key_len(self) -> usize {
        match self {
            Rfc8009Etype::Aes128Sha256 => 16,
            Rfc8009Etype::Aes256Sha384 => 32,
        }
    }
    /// Kc / Ki length and the truncated-MAC length `h`, in bytes (128 vs 192 bits).
    fn mac_len(self) -> usize {
        match self {
            Rfc8009Etype::Aes128Sha256 => 16,
            Rfc8009Etype::Aes256Sha384 => 24,
        }
    }
    fn hash_len(self) -> usize {
        match self {
            Rfc8009Etype::Aes128Sha256 => 32, // SHA-256
            Rfc8009Etype::Aes256Sha384 => 48, // SHA-384
        }
    }
    fn prf(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Rfc8009Etype::Aes128Sha256 => {
                let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac any key");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            Rfc8009Etype::Aes256Sha384 => {
                let mut m = <Hmac<Sha384> as Mac>::new_from_slice(key).expect("hmac any key");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
        }
    }
}

/// RFC 8009 §3 — KDF-HMAC-SHA2 (NIST SP800-108 counter mode). `out_len` is in bytes.
///
/// `Ki = PRF(key, [i]_4BE || label || 0x00 || [out_len*8]_4BE)`, concatenated over
/// the counter `i = 1..` and truncated to `out_len` bytes.
fn kdf(etype: Rfc8009Etype, key: &[u8], label: &[u8], out_len: usize) -> Vec<u8> {
    let k_bits = (out_len * 8) as u32;
    let h = etype.hash_len();
    let n = out_len.div_ceil(h);
    let mut out = Vec::with_capacity(n * h);
    for i in 1..=n as u32 {
        let mut input = Vec::with_capacity(4 + label.len() + 1 + 4);
        input.extend_from_slice(&i.to_be_bytes());
        input.extend_from_slice(label);
        input.push(0x00);
        input.extend_from_slice(&k_bits.to_be_bytes());
        out.extend_from_slice(&etype.prf(key, &input));
    }
    out.truncate(out_len);
    out
}

/// The KDF label for a subkey: 4-octet big-endian key usage followed by the
/// subkey discriminator (`0x99` = checksum Kc, `0xAA` = encryption Ke, `0x55` =
/// integrity Ki), per RFC 8009 §5.
fn label(usage: u32, discriminator: u8) -> Vec<u8> {
    let mut l = usage.to_be_bytes().to_vec();
    l.push(discriminator);
    l
}

/// Derive Kc (checksum subkey) for `usage`.
pub fn derive_kc(etype: Rfc8009Etype, base_key: &[u8], usage: u32) -> Vec<u8> {
    kdf(etype, base_key, &label(usage, 0x99), etype.mac_len())
}
/// Derive Ke (encryption subkey) for `usage`.
pub fn derive_ke(etype: Rfc8009Etype, base_key: &[u8], usage: u32) -> Vec<u8> {
    kdf(etype, base_key, &label(usage, 0xAA), etype.key_len())
}
/// Derive Ki (integrity subkey) for `usage`.
pub fn derive_ki(etype: Rfc8009Etype, base_key: &[u8], usage: u32) -> Vec<u8> {
    kdf(etype, base_key, &label(usage, 0x55), etype.mac_len())
}

/// RFC 8009 §5.3 encrypt: `C1 = AES-CTS(Ke, conf || plaintext)`,
/// `H = HMAC(Ki, IV || C1)[..h]`, output `C1 || H`. `confounder` is 16 bytes
/// (one AES block); callers supply RNG bytes in production.
pub fn encrypt(
    etype: Rfc8009Etype,
    base_key: &[u8],
    usage: u32,
    confounder: &[u8; AES_BLOCK_LEN],
    plaintext: &[u8],
) -> Vec<u8> {
    let ke = derive_ke(etype, base_key, usage);
    let ki = derive_ki(etype, base_key, usage);
    let mut conf_plain = Vec::with_capacity(AES_BLOCK_LEN + plaintext.len());
    conf_plain.extend_from_slice(confounder);
    conf_plain.extend_from_slice(plaintext);
    let c1 = aes_cts_encrypt(&ke, &[0u8; AES_BLOCK_LEN], &conf_plain);
    // RFC 8009 §5.3: H = HMAC(Ki, IV | C1), where IV is the all-zero initial
    // cipher state (verified byte-exact against the RFC §7 vectors).
    let mut mac_input = vec![0u8; AES_BLOCK_LEN];
    mac_input.extend_from_slice(&c1);
    let full_mac = ki_mac(etype, &ki, &mac_input);
    let mut out = c1;
    out.extend_from_slice(&full_mac[..etype.mac_len()]);
    out
}

fn ki_mac(etype: Rfc8009Etype, ki: &[u8], data: &[u8]) -> Vec<u8> {
    etype.prf(ki, data)
}

/// Errors from [`decrypt`]. Wire-derived — every variant is a graceful `Err`.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rfc8009Error {
    /// Ciphertext shorter than confounder + truncated-MAC.
    TooShort,
    /// HMAC verification failed — wrong key or tampered ciphertext.
    MacMismatch,
}

impl core::fmt::Display for Rfc8009Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort => write!(f, "RFC 8009 ciphertext too short"),
            Self::MacMismatch => write!(f, "RFC 8009 HMAC verification failed"),
        }
    }
}
impl std::error::Error for Rfc8009Error {}

/// RFC 8009 §5.3 decrypt: split the trailing `h`-byte HMAC, verify it over
/// `IV || C1`, AES-CTS-decrypt `C1`, strip the 16-byte confounder.
pub fn decrypt(
    etype: Rfc8009Etype,
    base_key: &[u8],
    usage: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Rfc8009Error> {
    let h = etype.mac_len();
    if ciphertext.len() < AES_BLOCK_LEN + h {
        return Err(Rfc8009Error::TooShort);
    }
    let ke = derive_ke(etype, base_key, usage);
    let ki = derive_ki(etype, base_key, usage);
    let (c1, tag) = ciphertext.split_at(ciphertext.len() - h);
    let mut mac_input = vec![0u8; AES_BLOCK_LEN];
    mac_input.extend_from_slice(c1);
    let full_mac = ki_mac(etype, &ki, &mac_input);
    // Constant-time compare over the truncated tag.
    let mut diff = 0u8;
    for i in 0..h {
        diff |= full_mac[i] ^ tag[i];
    }
    if diff != 0 {
        return Err(Rfc8009Error::MacMismatch);
    }
    let conf_plain = aes_cts_decrypt(&ke, &[0u8; AES_BLOCK_LEN], c1);
    Ok(conf_plain[AES_BLOCK_LEN..].to_vec())
}

/// The enctype-name prefix that RFC 8009 §4 mixes into the salt.
fn enctype_name(etype: Rfc8009Etype) -> &'static [u8] {
    match etype {
        Rfc8009Etype::Aes128Sha256 => b"aes128-cts-hmac-sha256-128",
        Rfc8009Etype::Aes256Sha384 => b"aes256-cts-hmac-sha384-192",
    }
}

/// RFC 8009 §4 string-to-key: `saltp = enctype-name || 0x00 || salt`;
/// `tkey = PBKDF2-HMAC-SHA2(passphrase, saltp, iterations, key_len)`;
/// `base-key = KDF-HMAC-SHA2(tkey, "kerberos", key_len)`. Default iterations 32768.
pub fn string_to_key(
    etype: Rfc8009Etype,
    passphrase: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Vec<u8> {
    let mut saltp = enctype_name(etype).to_vec();
    saltp.push(0x00);
    saltp.extend_from_slice(salt);
    let tkey = crate::crypto::pbkdf2(
        |k, d| etype.prf(k, d),
        etype.hash_len(),
        passphrase,
        &saltp,
        iterations,
        etype.key_len(),
    );
    kdf(etype, &tkey, b"kerberos", etype.key_len())
}

#[cfg(test)]
mod tests {
    use super::Rfc8009Etype::*;
    use super::*;

    // ── RFC 8009 §7 string-to-key: standard inputs → the published base-keys ─
    #[test]
    fn string_to_key_matches_rfc8009_section7() {
        // iter 32768, pass "password"; the §7 salt carries a 16-byte binary
        // prefix before the realm string.
        let mut salt = unhex("10 DF 9D D7 83 E5 BC 8A CE A1 73 0E 74 35 5F 61");
        salt.extend_from_slice(b"ATHENA.MIT.EDUraeburn");
        assert_eq!(
            hex(&string_to_key(Aes128Sha256, b"password", &salt, 32768)),
            "089bca48b105ea6ea77ca5d2f39dc5e7"
        );
        assert_eq!(
            hex(&string_to_key(Aes256Sha384, b"password", &salt, 32768)),
            "45bd806dbf6a833a9cffc1c94589a222367a79bc21c413718906e9f578a78467"
        );
    }

    /// Parse hex ignoring ALL whitespace, so vectors can be pasted byte-spaced
    /// verbatim from the RFC without any mid-byte-space hazard.
    fn unhex(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(clean.len().is_multiple_of(2), "odd hex length");
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // ── RFC 8009 §7: key derivation (usage 2), pasted byte-spaced from the RFC ─
    #[test]
    fn kdf_matches_rfc8009_aes128_sha256() {
        let base = unhex("37 05 D9 60 80 C1 77 28 A0 E8 00 EA B6 E0 D2 3C");
        assert_eq!(
            hex(&derive_kc(Aes128Sha256, &base, 2)),
            hex(&unhex("B3 1A 01 8A 48 F5 47 76 F4 03 E9 A3 96 32 5D C3"))
        );
        assert_eq!(
            hex(&derive_ke(Aes128Sha256, &base, 2)),
            hex(&unhex("9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E"))
        );
        assert_eq!(
            hex(&derive_ki(Aes128Sha256, &base, 2)),
            hex(&unhex("9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C"))
        );
    }

    #[test]
    fn kdf_matches_rfc8009_aes256_sha384() {
        let base = unhex("6D 40 4D 37 FA F7 9F 9D F0 D3 35 68 D3 20 66 98 00 EB 48 36 47 2E A8 A0 26 D1 6B 71 82 46 0C 52");
        assert_eq!(
            hex(&derive_kc(Aes256Sha384, &base, 2)),
            hex(&unhex(
                "EF 57 18 BE 86 CC 84 96 3D 8B BB 50 31 E9 F5 C4 BA 41 F2 8F AF 69 E7 3D"
            ))
        );
        assert_eq!(hex(&derive_ke(Aes256Sha384, &base, 2)), hex(&unhex("56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49")));
        assert_eq!(
            hex(&derive_ki(Aes256Sha384, &base, 2)),
            hex(&unhex(
                "69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F"
            ))
        );
    }

    // ── RFC 8009 §7: sample encryptions (usage 2), all four length classes ─
    fn check_sample(etype: Rfc8009Etype, base: &str, conf: &str, plain: &str, expect_ct: &str) {
        let base = unhex(base);
        let conf_v = unhex(conf);
        let mut c = [0u8; AES_BLOCK_LEN];
        c.copy_from_slice(&conf_v);
        let pt = unhex(plain);
        let expect = unhex(expect_ct);
        assert_eq!(
            hex(&encrypt(etype, &base, 2, &c, &pt)),
            hex(&expect),
            "{etype:?} encrypt mismatch"
        );
        assert_eq!(
            decrypt(etype, &base, 2, &expect).unwrap(),
            pt,
            "{etype:?} decrypt mismatch"
        );
    }

    #[test]
    fn encrypt_matches_rfc8009_aes128_sha256() {
        let base = "37 05 D9 60 80 C1 77 28 A0 E8 00 EA B6 E0 D2 3C";
        check_sample(Aes128Sha256, base,
            "7E 58 95 EA F2 67 24 35 BA D8 17 F5 45 A3 71 48", "",
            "EF 85 FB 89 0B B8 47 2F 4D AB 20 39 4D CA 78 1D AD 87 7E DA 39 D5 0C 87 0C 0D 5A 0A 8E 48 C7 18");
        check_sample(Aes128Sha256, base,
            "7B CA 28 5E 2F D4 13 0F B5 5B 1A 5C 83 BC 5B 24", "00 01 02 03 04 05",
            "84 D7 F3 07 54 ED 98 7B AB 0B F3 50 6B EB 09 CF B5 54 02 CE F7 E6 87 7C E9 9E 24 7E 52 D1 6E D4 42 1D FD F8 97 6C");
        check_sample(Aes128Sha256, base,
            "56 AB 21 71 3F F6 2C 0A 14 57 20 0F 6F A9 94 8F", "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F",
            "35 17 D6 40 F5 0D DC 8A D3 62 87 22 B3 56 9D 2A E0 74 93 FA 82 63 25 40 80 EA 65 C1 00 8E 8F C2 95 FB 48 52 E7 D8 3E 1E 7C 48 C3 7E EB E6 B0 D3");
        check_sample(Aes128Sha256, base,
            "A7 A4 E2 9A 47 28 CE 10 66 4F B6 4E 49 AD 3F AC", "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14",
            "72 0F 73 B1 8D 98 59 CD 6C CB 43 46 11 5C D3 36 C7 0F 58 ED C0 C4 43 7C 55 73 54 4C 31 C8 13 BC E1 E6 D0 72 C1 86 B3 9A 41 3C 2F 92 CA 9B 83 34 A2 87 FF CB FC");
    }

    #[test]
    fn encrypt_matches_rfc8009_aes256_sha384() {
        let base = "6D 40 4D 37 FA F7 9F 9D F0 D3 35 68 D3 20 66 98 00 EB 48 36 47 2E A8 A0 26 D1 6B 71 82 46 0C 52";
        check_sample(Aes256Sha384, base,
            "F7 64 E9 FA 15 C2 76 47 8B 2C 7D 0C 4E 5F 58 E4", "",
            "41 F5 3F A5 BF E7 02 6D 91 FA F9 BE 95 91 95 A0 58 70 72 73 A9 6A 40 F0 A0 19 60 62 1A C6 12 74 8B 9B BF BE 7E B4 CE 3C");
        check_sample(Aes256Sha384, base,
            "B8 0D 32 51 C1 F6 47 14 94 25 6F FE 71 2D 0B 9A", "00 01 02 03 04 05",
            "4E D7 B3 7C 2B CA C8 F7 4F 23 C1 CF 07 E6 2B C7 B7 5F B3 F6 37 B9 F5 59 C7 F6 64 F6 9E AB 7B 60 92 23 75 26 EA 0D 1F 61 CB 20 D6 9D 10 F2");
        check_sample(Aes256Sha384, base,
            "53 BF 8A 0D 10 52 65 D4 E2 76 42 86 24 CE 5E 63", "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F",
            "BC 47 FF EC 79 98 EB 91 E8 11 5C F8 D1 9D AC 4B BB E2 E1 63 E8 7D D3 7F 49 BE CA 92 02 77 64 F6 8C F5 1F 14 D7 98 C2 27 3F 35 DF 57 4D 1F 93 2E 40 C4 FF 25 5B 36 A2 66");
        check_sample(Aes256Sha384, base,
            "76 3E 65 36 7E 86 4F 02 F5 51 53 C7 E3 B5 8A F1", "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14",
            "40 01 3E 2D F5 8E 87 51 95 7D 28 78 BC D2 D6 FE 10 1C CF D5 56 CB 1E AE 79 DB 3C 3E E8 64 29 F2 B2 A6 02 AC 86 FE F6 EC B6 47 D6 29 5F AE 07 7A 1F EB 51 75 08 D2 C1 6B 41 92 E0 1F 62");
    }

    // ── Tamper rejection ─────────────────────────────────────────────────
    #[test]
    fn tampered_ciphertext_rejected_both_etypes() {
        for etype in [Aes128Sha256, Aes256Sha384] {
            let base = vec![0x11u8; etype.key_len()];
            let conf = [0x22u8; AES_BLOCK_LEN];
            let ct = encrypt(etype, &base, 5, &conf, b"tamper me");
            let mut bad = ct.clone();
            bad[0] ^= 0x01;
            assert_eq!(
                decrypt(etype, &base, 5, &bad),
                Err(Rfc8009Error::MacMismatch)
            );
            assert_eq!(
                decrypt(etype, &base, 5, &[0u8; 4]),
                Err(Rfc8009Error::TooShort)
            );
        }
    }
}
