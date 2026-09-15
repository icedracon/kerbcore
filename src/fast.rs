//! RFC 6113 — Kerberos FAST (Flexible Authentication Secure Tunneling), the `ms-kile-fast`
//! armoring layer. FAST wraps an AS/TGS exchange inside an *armored* tunnel keyed by an
//! **armor key**, defeating offline pre-auth dictionary attacks and enabling PKINIT/OTP
//! secure channels.
//!
//! Two halves live here, and one deliberately does **not**:
//!
//! 1. **The wire codec** (this is complete + offline-tested): `KrbFastArmor`,
//!    `KrbFastArmoredReq`, `KrbFastReq`, `PA-FX-FAST-REQUEST`, `KrbFastArmoredRep`,
//!    `PA-FX-FAST-REPLY`, `KrbFastResponse`.
//! 2. **The armor-key derivation** [`krb_fx_cf2`] / [`prf_plus`] / [`fast_armor_key`] — the
//!    RFC 6113 §5.1 key-combination math. It is **PRF-agnostic**: the caller supplies the
//!    RFC 3961 pseudo-random function for the enctype, so the (unambiguous) combining logic is
//!    tested here with a mock PRF.
//!
//! What is intentionally **absent**: a concrete RFC 3961/3962 §6 AES-SHA1 PRF. That PRF's
//! key-derivation constant has no RFC known-answer vector, so shipping one unverified would be
//! a silent landmine; and a full armored request can only be *trusted* once it round-trips
//! against a live KDC. Until then FAST here is "wire-complete, armor-key math complete,
//! end-to-end PRF + live validation pending" — see the crate roadmap. Callers with a
//! KAT-verified PRF (e.g. the RFC 8009 §3 PRF for etypes 19/20) can already drive
//! [`fast_armor_key`] to completion.

use crate::der::{
    context_tag, encode_integer, encode_octet_string, encode_sequence, explicit, one_or, tlv, Der,
    DerError, TAG_BIT_STRING, TAG_OCTET_STRING, TAG_SEQUENCE,
};
use crate::types::{Checksum, EncryptedData};

/// PA-DATA type for PA-FX-FAST (RFC 6113 §5.4.2).
pub const PA_FX_FAST: i32 = 136;
/// PA-DATA type for PA-FX-COOKIE (opaque KDC state echoed back).
pub const PA_FX_COOKIE: i32 = 133;
/// PA-DATA type for PA-ENCRYPTED-CHALLENGE (RFC 6113 §5.4.6 FAST factor).
pub const PA_ENCRYPTED_CHALLENGE: i32 = 138;

/// `armor-type` for an AP-REQ armor (the only type defined by RFC 6113 §5.4.1.1).
pub const FX_FAST_ARMOR_AP_REQUEST: i32 = 1;

// FAST armor-key peppers (RFC 6113 §5.4.1.1).
const PEPPER_SUBKEY: &[u8] = b"subkeyarmor";
const PEPPER_TICKET: &[u8] = b"ticketarmor";

/// FAST errors.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FastError {
    /// Malformed / truncated DER.
    BadToken,
}
impl From<DerError> for FastError {
    fn from(_: DerError) -> Self {
        FastError::BadToken
    }
}

// ── armor-key derivation (RFC 6113 §5.1) ──────────────────────────────────────

/// `PRF+(key, pepper)` (RFC 6113 §5.1): `PRF(key, 1||pepper) || PRF(key, 2||pepper) || …`
/// truncated to `out_len`. The counter is a single octet starting at 1. `prf` is the enctype's
/// RFC 3961 pseudo-random function.
pub fn prf_plus<F>(prf: F, key: &[u8], pepper: &[u8], out_len: usize) -> Vec<u8>
where
    F: Fn(&[u8], &[u8]) -> Vec<u8>,
{
    let mut out = Vec::with_capacity(out_len);
    let mut counter: u8 = 1;
    while out.len() < out_len {
        let mut input = Vec::with_capacity(1 + pepper.len());
        input.push(counter);
        input.extend_from_slice(pepper);
        let block = prf(key, &input);
        if block.is_empty() {
            break; // defensive: a broken PRF must not spin forever
        }
        out.extend_from_slice(&block);
        match counter.checked_add(1) {
            Some(n) => counter = n,
            None => break,
        }
    }
    out.truncate(out_len);
    out
}

/// `KRB-FX-CF2(K1, K2, pepper1, pepper2)` (RFC 6113 §5.1): the XOR of `PRF+(K1, pepper1)` and
/// `PRF+(K2, pepper2)`, truncated to `out_len`. For the AES profiles random-to-key is the
/// identity, so the result is directly the combined key bytes.
pub fn krb_fx_cf2<F>(
    prf: F,
    k1: &[u8],
    k2: &[u8],
    pepper1: &[u8],
    pepper2: &[u8],
    out_len: usize,
) -> Vec<u8>
where
    F: Fn(&[u8], &[u8]) -> Vec<u8> + Copy,
{
    let a = prf_plus(prf, k1, pepper1, out_len);
    let b = prf_plus(prf, k2, pepper2, out_len);
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// The FAST **armor key** (RFC 6113 §5.4.1.1): `KRB-FX-CF2(subkey, ticket_session_key,
/// "subkeyarmor", "ticketarmor")`. `subkey` is the armor AP-REQ authenticator subkey;
/// `ticket_session_key` is the armor ticket's session key; both keys and the output share the
/// enctype (`out_len` = its key length). Supply the enctype's RFC 3961 `prf`.
pub fn fast_armor_key<F>(
    prf: F,
    subkey: &[u8],
    ticket_session_key: &[u8],
    out_len: usize,
) -> Vec<u8>
where
    F: Fn(&[u8], &[u8]) -> Vec<u8> + Copy,
{
    krb_fx_cf2(
        prf,
        subkey,
        ticket_session_key,
        PEPPER_SUBKEY,
        PEPPER_TICKET,
        out_len,
    )
}

// ── PA-DATA (self-contained; PA-DATA ::= SEQUENCE { [1] type, [2] value }) ─────

fn encode_padata(padata_type: i32, padata_value: &[u8]) -> Vec<u8> {
    let body = [
        explicit(1, &encode_integer(padata_type as i64)),
        explicit(2, &encode_octet_string(padata_value)),
    ]
    .concat();
    encode_sequence(&body)
}

fn encode_padata_list(items: &[(i32, Vec<u8>)]) -> Vec<u8> {
    let body: Vec<u8> = items
        .iter()
        .flat_map(|(t, v)| encode_padata(*t, v))
        .collect();
    encode_sequence(&body)
}

fn parse_padata_list(seq_der: &[u8]) -> Result<Vec<(i32, Vec<u8>)>, FastError> {
    let body = one_or(seq_der, TAG_SEQUENCE)?;
    let mut r = Der::new(body);
    let mut out = Vec::new();
    while !r.is_empty() {
        let (_, entry) = r.read_tlv()?;
        let mut er = Der::new(entry);
        let t = {
            let mut ir = Der::new(er.expect(context_tag(1))?);
            i32::try_from(ir.read_integer()?).map_err(|_| FastError::BadToken)?
        };
        let v = one_or(er.expect(context_tag(2))?, TAG_OCTET_STRING)?.to_vec();
        out.push((t, v));
    }
    Ok(out)
}

// ── FAST wire structures ──────────────────────────────────────────────────────

/// `KrbFastArmor ::= SEQUENCE { armor-type [0] Int32, armor-value [1] OCTET STRING }`. For the
/// only defined type ([`FX_FAST_ARMOR_AP_REQUEST`]) `armor_value` is an AP-REQ DER.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KrbFastArmor {
    /// The armor type ([`FX_FAST_ARMOR_AP_REQUEST`]).
    pub armor_type: i32,
    /// The armor value (an AP-REQ for the AP-REQUEST type).
    pub armor_value: Vec<u8>,
}

impl KrbFastArmor {
    /// An AP-REQ armor from an AP-REQ DER.
    pub fn ap_request(ap_req: &[u8]) -> Self {
        KrbFastArmor {
            armor_type: FX_FAST_ARMOR_AP_REQUEST,
            armor_value: ap_req.to_vec(),
        }
    }
    fn encode(&self) -> Vec<u8> {
        let body = [
            explicit(0, &encode_integer(self.armor_type as i64)),
            explicit(1, &encode_octet_string(&self.armor_value)),
        ]
        .concat();
        encode_sequence(&body)
    }
    fn decode(der: &[u8]) -> Result<Self, FastError> {
        let seq = one_or(der, TAG_SEQUENCE)?;
        let mut r = Der::new(seq);
        let armor_type = {
            let mut ir = Der::new(r.expect(context_tag(0))?);
            i32::try_from(ir.read_integer()?).map_err(|_| FastError::BadToken)?
        };
        let armor_value = one_or(r.expect(context_tag(1))?, TAG_OCTET_STRING)?.to_vec();
        Ok(KrbFastArmor {
            armor_type,
            armor_value,
        })
    }
}

/// `KrbFastReq ::= SEQUENCE { fast-options [0] KrbFastFlags, padata [1] SEQUENCE OF PA-DATA,
/// req-body [2] KDC-REQ-BODY }` — the plaintext that gets encrypted into `enc-fast-req`.
/// `req_body` is an already-encoded KDC-REQ-BODY (kept opaque so FAST stays decoupled).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KrbFastReq {
    /// FAST options (32-bit `KrbFastFlags`).
    pub fast_options: u32,
    /// Inner pre-auth as `(type, value)` pairs.
    pub padata: Vec<(i32, Vec<u8>)>,
    /// The inner KDC-REQ-BODY DER.
    pub req_body: Vec<u8>,
}

impl KrbFastReq {
    /// Encode the `KrbFastReq` plaintext (encrypt this under the armor key at the FAST usage).
    pub fn encode(&self) -> Vec<u8> {
        let mut flags = vec![0u8];
        flags.extend_from_slice(&self.fast_options.to_be_bytes());
        let body = [
            explicit(0, &tlv(TAG_BIT_STRING, &flags)),
            explicit(1, &encode_padata_list(&self.padata)),
            explicit(2, &self.req_body),
        ]
        .concat();
        encode_sequence(&body)
    }
    /// Parse a decrypted `KrbFastReq`.
    pub fn decode(der: &[u8]) -> Result<Self, FastError> {
        let seq = one_or(der, TAG_SEQUENCE)?;
        let mut r = Der::new(seq);
        let flags = one_or(r.expect(context_tag(0))?, TAG_BIT_STRING)?;
        // BIT STRING = unused-bits octet + 4 flag octets.
        let fast_options = if flags.len() >= 5 {
            u32::from_be_bytes([flags[1], flags[2], flags[3], flags[4]])
        } else {
            0
        };
        let padata = parse_padata_list(r.expect(context_tag(1))?)?;
        let req_body = r.expect(context_tag(2))?.to_vec();
        Ok(KrbFastReq {
            fast_options,
            padata,
            req_body,
        })
    }
}

/// `KrbFastArmoredReq ::= SEQUENCE { armor [0] KrbFastArmor OPTIONAL, req-checksum [1] Checksum,
/// enc-fast-req [2] EncryptedData }`, and the wrapping `PA-FX-FAST-REQUEST ::= CHOICE {
/// armored-data [0] KrbFastArmoredReq }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KrbFastArmoredReq {
    /// The armor (present in the AS armor; omitted when a TGS armor is implied by the outer AP-REQ).
    pub armor: Option<KrbFastArmor>,
    /// Checksum over the outer request body, keyed by the armor key.
    pub req_checksum: Checksum,
    /// The encrypted `KrbFastReq`.
    pub enc_fast_req: EncryptedData,
}

impl KrbFastArmoredReq {
    fn encode_inner(&self) -> Vec<u8> {
        let mut body = Vec::new();
        if let Some(a) = &self.armor {
            body.extend_from_slice(&explicit(0, &a.encode()));
        }
        body.extend_from_slice(&explicit(1, &self.req_checksum.encode()));
        body.extend_from_slice(&explicit(2, &self.enc_fast_req.encode()));
        encode_sequence(&body)
    }

    /// Encode as a `PA-FX-FAST-REQUEST` padata value (the CHOICE `[0] armored-data`).
    pub fn encode_pa_fx_fast(&self) -> Vec<u8> {
        explicit(0, &self.encode_inner())
    }

    /// Parse a `PA-FX-FAST-REQUEST` padata value.
    pub fn parse_pa_fx_fast(der: &[u8]) -> Result<Self, FastError> {
        let mut r = Der::new(der);
        let inner = r.expect(context_tag(0))?; // CHOICE [0] armored-data
        let seq = one_or(inner, TAG_SEQUENCE)?;
        let mut sr = Der::new(seq);
        let armor = if sr.peek_tag() == Some(context_tag(0)) {
            Some(KrbFastArmor::decode(sr.expect(context_tag(0))?)?)
        } else {
            None
        };
        let req_checksum = Checksum::decode(sr.expect(context_tag(1))?)?;
        let enc_fast_req = EncryptedData::decode(sr.expect(context_tag(2))?)?;
        Ok(KrbFastArmoredReq {
            armor,
            req_checksum,
            enc_fast_req,
        })
    }
}

/// `PA-FX-FAST-REPLY ::= CHOICE { armored-data [0] KrbFastArmoredRep }`, where
/// `KrbFastArmoredRep ::= SEQUENCE { enc-fast-rep [0] EncryptedData }` (the encrypted
/// `KrbFastResponse`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KrbFastArmoredRep {
    /// The encrypted `KrbFastResponse`.
    pub enc_fast_rep: EncryptedData,
}

impl KrbFastArmoredRep {
    /// Encode as a `PA-FX-FAST-REPLY` padata value.
    pub fn encode_pa_fx_fast(&self) -> Vec<u8> {
        let seq = encode_sequence(&explicit(0, &self.enc_fast_rep.encode()));
        explicit(0, &seq)
    }
    /// Parse a `PA-FX-FAST-REPLY` padata value.
    pub fn parse_pa_fx_fast(der: &[u8]) -> Result<Self, FastError> {
        let mut r = Der::new(der);
        let seq = one_or(r.expect(context_tag(0))?, TAG_SEQUENCE)?;
        let mut sr = Der::new(seq);
        let enc_fast_rep = EncryptedData::decode(sr.expect(context_tag(0))?)?;
        Ok(KrbFastArmoredRep { enc_fast_rep })
    }
}

/// `KrbFastResponse ::= SEQUENCE { padata [0] SEQUENCE OF PA-DATA, strengthen-key [1]
/// EncryptionKey OPTIONAL, finished [2] KrbFastFinished OPTIONAL, … }` — the decrypted reply.
/// kerbcore surfaces the inner `padata` and the optional `strengthen-key` (which the client
/// mixes into the reply key via [`krb_fx_cf2`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KrbFastResponse {
    /// Inner pre-auth returned by the KDC.
    pub padata: Vec<(i32, Vec<u8>)>,
    /// Optional strengthen-key to combine into the reply key.
    pub strengthen_key: Option<crate::types::EncryptionKey>,
}

impl KrbFastResponse {
    /// Parse a decrypted `KrbFastResponse`.
    pub fn decode(der: &[u8]) -> Result<Self, FastError> {
        let seq = one_or(der, TAG_SEQUENCE)?;
        let mut r = Der::new(seq);
        let padata = parse_padata_list(r.expect(context_tag(0))?)?;
        let strengthen_key = if r.peek_tag() == Some(context_tag(1)) {
            Some(crate::types::EncryptionKey::decode(
                r.expect(context_tag(1))?,
            )?)
        } else {
            None
        };
        Ok(KrbFastResponse {
            padata,
            strengthen_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Checksum, EncryptedData, EncryptionKey};

    // A deterministic mock PRF (NOT a real Kerberos PRF): HMAC-free, just a keyed FNV-ish mix
    // producing 16 bytes. Enough to exercise the RFC 6113 §5.1 combining logic.
    fn mock_prf(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = [0u8; 16];
        let mut h: u64 = 0xcbf29ce484222325;
        for (i, b) in key.iter().chain(data.iter()).enumerate() {
            h ^= (*b as u64).wrapping_add(i as u64);
            h = h.wrapping_mul(0x100000001b3);
            out[i % 16] ^= (h >> ((i % 8) * 8)) as u8;
        }
        out.to_vec()
    }

    #[test]
    fn prf_plus_length_and_determinism() {
        let a = prf_plus(mock_prf, b"k", b"pepper", 40);
        let b = prf_plus(mock_prf, b"k", b"pepper", 40);
        assert_eq!(a.len(), 40);
        assert_eq!(a, b); // deterministic
                          // First 16 bytes == PRF(key, 1||pepper).
        let mut first = vec![1u8];
        first.extend_from_slice(b"pepper");
        assert_eq!(&a[..16], &mock_prf(b"k", &first)[..]);
    }

    #[test]
    fn cf2_is_xor_of_prf_plus_and_pepper_sensitive() {
        let k1 = b"key-one";
        let k2 = b"key-two";
        let out = krb_fx_cf2(mock_prf, k1, k2, b"p1", b"p2", 32);
        let a = prf_plus(mock_prf, k1, b"p1", 32);
        let b = prf_plus(mock_prf, k2, b"p2", 32);
        let expect: Vec<u8> = a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect();
        assert_eq!(out, expect);
        // Swapping peppers changes the armor key.
        let swapped = krb_fx_cf2(mock_prf, k1, k2, b"p2", b"p1", 32);
        assert_ne!(out, swapped);
    }

    #[test]
    fn fast_armor_key_uses_the_rfc_peppers_and_keylen() {
        let subkey = [0x11u8; 32];
        let tsk = [0x22u8; 32];
        let ak = fast_armor_key(mock_prf, &subkey, &tsk, 32);
        assert_eq!(ak.len(), 32);
        let manual = krb_fx_cf2(mock_prf, &subkey, &tsk, b"subkeyarmor", b"ticketarmor", 32);
        assert_eq!(ak, manual);
    }

    fn sample_ed() -> EncryptedData {
        EncryptedData {
            etype: 18,
            kvno: None,
            cipher: vec![0xAB; 24],
        }
    }

    #[test]
    fn fast_req_round_trip() {
        let req = KrbFastReq {
            fast_options: 0x0000_0000,
            padata: vec![
                (PA_FX_COOKIE, vec![1, 2, 3]),
                (PA_ENCRYPTED_CHALLENGE, vec![9]),
            ],
            req_body: crate::der::encode_sequence(&crate::der::encode_integer(7)),
        };
        let got = KrbFastReq::decode(&req.encode()).unwrap();
        assert_eq!(got, req);
    }

    #[test]
    fn pa_fx_fast_request_round_trip() {
        let armored = KrbFastArmoredReq {
            armor: Some(KrbFastArmor::ap_request(b"\x6e\x03ap-req")),
            req_checksum: Checksum {
                cksumtype: 16,
                checksum: vec![0xCC; 12],
            },
            enc_fast_req: sample_ed(),
        };
        let der = armored.encode_pa_fx_fast();
        let got = KrbFastArmoredReq::parse_pa_fx_fast(&der).unwrap();
        assert_eq!(got, armored);
    }

    #[test]
    fn pa_fx_fast_request_without_armor() {
        let armored = KrbFastArmoredReq {
            armor: None,
            req_checksum: Checksum {
                cksumtype: 16,
                checksum: vec![0x01; 12],
            },
            enc_fast_req: sample_ed(),
        };
        let got = KrbFastArmoredReq::parse_pa_fx_fast(&armored.encode_pa_fx_fast()).unwrap();
        assert_eq!(got.armor, None);
        assert_eq!(got, armored);
    }

    #[test]
    fn pa_fx_fast_reply_round_trip() {
        let rep = KrbFastArmoredRep {
            enc_fast_rep: sample_ed(),
        };
        let got = KrbFastArmoredRep::parse_pa_fx_fast(&rep.encode_pa_fx_fast()).unwrap();
        assert_eq!(got, rep);
    }

    #[test]
    fn fast_response_with_strengthen_key() {
        let body = [
            explicit(0, &encode_padata_list(&[(PA_FX_COOKIE, vec![7])])),
            explicit(
                1,
                &EncryptionKey {
                    keytype: 18,
                    keyvalue: vec![0x33; 32],
                }
                .encode(),
            ),
        ]
        .concat();
        let der = encode_sequence(&body);
        let got = KrbFastResponse::decode(&der).unwrap();
        assert_eq!(got.padata, vec![(PA_FX_COOKIE, vec![7])]);
        assert_eq!(got.strengthen_key.unwrap().keytype, 18);
    }

    #[test]
    fn garbage_does_not_panic() {
        for b in [&b""[..], &[0x30], &[0x30, 0x02, 0xA0, 0x00], &[0xFF; 8]] {
            let _ = KrbFastArmoredReq::parse_pa_fx_fast(b);
            let _ = KrbFastArmoredRep::parse_pa_fx_fast(b);
            let _ = KrbFastReq::decode(b);
            let _ = KrbFastResponse::decode(b);
        }
    }
}
