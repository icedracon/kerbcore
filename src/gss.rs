//! RFC 4121 — the Kerberos V5 GSS-API mechanism (krb5-gss).
//!
//! This is the wire glue an application uses once [`crate::client`] has produced an AP-REQ:
//! frame it as a GSS *initial context token* (RFC 2743 §3.1), then protect application
//! messages with per-message **MIC** (`GetMIC`, integrity) and **Wrap** (confidentiality)
//! tokens. Everything here is pure byte work over [`crate::keys::KerberosKey`] — no FFI, no
//! sockets. Parsers are total: malformed input returns [`GssError`], never a panic.
//!
//! Coverage: initial-context-token framing (AP-REQ/AP-REP/KRB-ERROR), MIC tokens
//! (TOK_ID `04 04`), and Wrap tokens **with confidentiality** (TOK_ID `05 04`, `Sealed`).
//! Integrity-only Wrap (`Sealed`=0) and DCE-style tokens are deliberately out of scope for
//! now (see the crate roadmap).

use crate::keys::{KerberosKey, KeyError};

/// The Kerberos V5 GSS mechanism OID, DER-encoded (`1.2.840.113554.1.2.2`): tag `06`, length
/// `09`, then the nine content octets.
pub const KRB5_MECH_OID_DER: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02,
];

/// Initial-context-token id for an AP-REQ (`01 00`).
pub const TOK_ID_AP_REQ: [u8; 2] = [0x01, 0x00];
/// Initial-context-token id for an AP-REP (`02 00`).
pub const TOK_ID_AP_REP: [u8; 2] = [0x02, 0x00];
/// Initial-context-token id for a KRB-ERROR (`03 00`).
pub const TOK_ID_KRB_ERROR: [u8; 2] = [0x03, 0x00];

/// Per-message TOK_ID for a MIC token (RFC 4121 §4.2.6.1).
pub const TOK_ID_MIC: [u8; 2] = [0x04, 0x04];
/// Per-message TOK_ID for a Wrap token (RFC 4121 §4.2.6.2).
pub const TOK_ID_WRAP: [u8; 2] = [0x05, 0x04];

// RFC 4121 §2 key usage numbers for per-message tokens.
const KG_USAGE_ACCEPTOR_SEAL: u32 = 22;
const KG_USAGE_ACCEPTOR_SIGN: u32 = 23;
const KG_USAGE_INITIATOR_SEAL: u32 = 24;
const KG_USAGE_INITIATOR_SIGN: u32 = 25;

// Per-message token flag bits (RFC 4121 §4.2.2).
const FLAG_SENT_BY_ACCEPTOR: u8 = 0x01;
const FLAG_SEALED: u8 = 0x02;
const FLAG_ACCEPTOR_SUBKEY: u8 = 0x04;

/// Errors from GSS token framing / per-message protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GssError {
    /// The token was truncated or otherwise structurally invalid.
    BadToken,
    /// The initial context token did not carry the Kerberos mech OID.
    WrongMech,
    /// A per-message token had the wrong TOK_ID for the operation.
    WrongTokId([u8; 2]),
    /// A MIC did not verify (tampered message or wrong key).
    BadMic,
    /// A Wrap token's embedded header did not match after decryption (tampering).
    BadHeader,
    /// The underlying Kerberos crypto failed (usually a decrypt integrity failure).
    Crypto(KeyError),
}

impl From<KeyError> for GssError {
    fn from(e: KeyError) -> Self {
        GssError::Crypto(e)
    }
}

/// Frame `inner` (typically an AP-REQ DER) as a GSS-API *initial context token* (RFC 2743
/// §3.1): `[APPLICATION 0] { mechOID, tokId, inner }`, i.e. `60 <len> <krb5-oid> <tok_id> <inner>`.
pub fn initial_context_token(tok_id: [u8; 2], inner: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(KRB5_MECH_OID_DER.len() + 2 + inner.len());
    content.extend_from_slice(KRB5_MECH_OID_DER);
    content.extend_from_slice(&tok_id);
    content.extend_from_slice(inner);
    let mut out = vec![0x60];
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(&content);
    out
}

/// Parse a GSS-API initial context token, returning `(tok_id, inner)`. Verifies the outer
/// `[APPLICATION 0]` tag and the Kerberos mech OID.
pub fn parse_initial_context_token(token: &[u8]) -> Result<([u8; 2], Vec<u8>), GssError> {
    let mut p = token;
    let tag = take(&mut p, 1)?[0];
    if tag != 0x60 {
        return Err(GssError::BadToken);
    }
    let len = read_der_len(&mut p)?;
    if len > p.len() {
        return Err(GssError::BadToken);
    }
    let mut body = &p[..len];
    if body.len() < KRB5_MECH_OID_DER.len() + 2 {
        return Err(GssError::BadToken);
    }
    if &body[..KRB5_MECH_OID_DER.len()] != KRB5_MECH_OID_DER {
        return Err(GssError::WrongMech);
    }
    body = &body[KRB5_MECH_OID_DER.len()..];
    let tok_id = [body[0], body[1]];
    Ok((tok_id, body[2..].to_vec()))
}

/// The 16-octet per-message token header (RFC 4121 §4.2.6). `rrc` is written big-endian into
/// octets 6..8; MIC tokens must pass `ec = 0, rrc = 0`.
fn header(tok_id: [u8; 2], flags: u8, ec: u16, rrc: u16, seq: u64) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[0] = tok_id[0];
    h[1] = tok_id[1];
    h[2] = flags;
    h[3] = 0xFF; // filler
    h[4..6].copy_from_slice(&ec.to_be_bytes());
    h[6..8].copy_from_slice(&rrc.to_be_bytes());
    h[8..16].copy_from_slice(&seq.to_be_bytes());
    h
}

fn sign_usage(sender_is_acceptor: bool) -> u32 {
    if sender_is_acceptor {
        KG_USAGE_ACCEPTOR_SIGN
    } else {
        KG_USAGE_INITIATOR_SIGN
    }
}

fn seal_usage(sender_is_acceptor: bool) -> u32 {
    if sender_is_acceptor {
        KG_USAGE_ACCEPTOR_SEAL
    } else {
        KG_USAGE_INITIATOR_SEAL
    }
}

/// Produce a **MIC token** (RFC 4121 §4.2.6.1) over `message`: `header(16) || checksum`, where
/// the checksum covers `message || header`. `is_acceptor` sets the sender role (flag +
/// key usage); `acceptor_subkey` sets the `AcceptorSubkey` flag.
pub fn get_mic(
    key: &KerberosKey,
    seq: u64,
    message: &[u8],
    is_acceptor: bool,
    acceptor_subkey: bool,
) -> Vec<u8> {
    let mut flags = 0u8;
    if is_acceptor {
        flags |= FLAG_SENT_BY_ACCEPTOR;
    }
    if acceptor_subkey {
        flags |= FLAG_ACCEPTOR_SUBKEY;
    }
    let h = header(TOK_ID_MIC, flags, 0, 0, seq);
    let mut to_sign = Vec::with_capacity(message.len() + 16);
    to_sign.extend_from_slice(message);
    to_sign.extend_from_slice(&h);
    let cksum = key.checksum(sign_usage(is_acceptor), &to_sign);
    let mut out = Vec::with_capacity(16 + cksum.len());
    out.extend_from_slice(&h);
    out.extend_from_slice(&cksum);
    out
}

/// Verify a **MIC token** against `message`. The sender role is taken from the token's flags.
pub fn verify_mic(key: &KerberosKey, token: &[u8], message: &[u8]) -> Result<(), GssError> {
    if token.len() < 16 {
        return Err(GssError::BadToken);
    }
    if token[0..2] != TOK_ID_MIC {
        return Err(GssError::WrongTokId([token[0], token[1]]));
    }
    let flags = token[2];
    let sender_is_acceptor = flags & FLAG_SENT_BY_ACCEPTOR != 0;
    let mut to_sign = Vec::with_capacity(message.len() + 16);
    to_sign.extend_from_slice(message);
    to_sign.extend_from_slice(&token[..16]);
    let expect = key.checksum(sign_usage(sender_is_acceptor), &to_sign);
    if ct_eq(&expect, &token[16..]) {
        Ok(())
    } else {
        Err(GssError::BadMic)
    }
}

/// Produce a **Wrap token with confidentiality** (RFC 4121 §4.2.6.2) over `plaintext`. Uses
/// `EC = 0` and `RRC = 0` (both spec-legal for AES), so the body is a straight Kerberos
/// encryption of `plaintext || header`. `is_acceptor`/`acceptor_subkey` set the flags + usage.
pub fn wrap(
    key: &KerberosKey,
    seq: u64,
    plaintext: &[u8],
    is_acceptor: bool,
    acceptor_subkey: bool,
) -> Vec<u8> {
    let mut flags = FLAG_SEALED;
    if is_acceptor {
        flags |= FLAG_SENT_BY_ACCEPTOR;
    }
    if acceptor_subkey {
        flags |= FLAG_ACCEPTOR_SUBKEY;
    }
    let h = header(TOK_ID_WRAP, flags, 0, 0, seq);
    let mut to_enc = Vec::with_capacity(plaintext.len() + 16);
    to_enc.extend_from_slice(plaintext);
    to_enc.extend_from_slice(&h);
    let cipher = key.encrypt(seal_usage(is_acceptor), &to_enc);
    // RRC = 0 => the rotation is the identity; emit header || cipher.
    let mut out = Vec::with_capacity(16 + cipher.len());
    out.extend_from_slice(&h);
    out.extend_from_slice(&cipher);
    out
}

/// Unwrap a **Wrap token with confidentiality**, returning the recovered plaintext. Handles a
/// non-zero `RRC` (rotates the body left before decrypting) and `EC` filler, and verifies the
/// decrypted trailing header matches the token header (with RRC/flags reset) — tamper-evident.
pub fn unwrap(key: &KerberosKey, token: &[u8]) -> Result<Vec<u8>, GssError> {
    if token.len() < 16 {
        return Err(GssError::BadToken);
    }
    if token[0..2] != TOK_ID_WRAP {
        return Err(GssError::WrongTokId([token[0], token[1]]));
    }
    let flags = token[2];
    if flags & FLAG_SEALED == 0 {
        // Integrity-only Wrap not supported yet.
        return Err(GssError::BadToken);
    }
    let sender_is_acceptor = flags & FLAG_SENT_BY_ACCEPTOR != 0;
    let ec = u16::from_be_bytes([token[4], token[5]]) as usize;
    let rrc = u16::from_be_bytes([token[6], token[7]]) as usize;

    let body = &token[16..];
    let cipher = rotate_left(body, rrc);
    let plain = key.decrypt(seal_usage(sender_is_acceptor), &cipher)?;
    // plain = plaintext || EC filler || header(16)
    if plain.len() < 16 + ec {
        return Err(GssError::BadHeader);
    }
    let hdr_start = plain.len() - 16;
    let got_hdr = &plain[hdr_start..];
    // The embedded header has RRC = 0; compare everything else against the token header.
    let mut want = [0u8; 16];
    want.copy_from_slice(&token[..16]);
    want[6] = 0;
    want[7] = 0;
    if !ct_eq(got_hdr, &want) {
        return Err(GssError::BadHeader);
    }
    Ok(plain[..hdr_start - ec].to_vec())
}

// ── small byte helpers ───────────────────────────────────────────────────────

/// Rotate `data` left by `n` octets (`n` is taken modulo the length). Inverse of the
/// right-rotation a sender applies via RRC.
fn rotate_left(data: &[u8], n: usize) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let n = n % data.len();
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[n..]);
    out.extend_from_slice(&data[..n]);
    out
}

/// Constant-time-ish equality for MAC/header comparison (no early return on first difference).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// DER definite-length encoding of `len`.
fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut b = len.to_be_bytes().to_vec();
        while b.first() == Some(&0) {
            b.remove(0);
        }
        let mut out = vec![0x80 | b.len() as u8];
        out.extend_from_slice(&b);
        out
    }
}

fn take<'a>(p: &mut &'a [u8], n: usize) -> Result<&'a [u8], GssError> {
    if p.len() < n {
        return Err(GssError::BadToken);
    }
    let (head, tail) = p.split_at(n);
    *p = tail;
    Ok(head)
}

/// Read a DER definite length from `p`, advancing it.
fn read_der_len(p: &mut &[u8]) -> Result<usize, GssError> {
    let first = take(p, 1)?[0];
    if first < 0x80 {
        return Ok(first as usize);
    }
    let n = (first & 0x7F) as usize;
    if n == 0 || n > core::mem::size_of::<usize>() {
        return Err(GssError::BadToken);
    }
    let bytes = take(p, n)?;
    let mut len = 0usize;
    for &b in bytes {
        len = (len << 8) | b as usize;
    }
    Ok(len)
}

/// Rotate `data` right by `n` octets (test helper mirroring a sender's RRC).
#[cfg(test)]
fn rotate_right(data: &[u8], n: usize) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let n = n % data.len();
    rotate_left(data, data.len() - n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{Enctype, KerberosKey};

    fn key() -> KerberosKey {
        KerberosKey::new(Enctype::Aes256CtsHmacSha1_96, vec![0x42u8; 32]).unwrap()
    }

    #[test]
    fn initial_context_token_round_trips() {
        let inner = b"\x6e\x03ap-req-bytes"; // stand-in AP-REQ DER
        let tok = initial_context_token(TOK_ID_AP_REQ, inner);
        assert_eq!(tok[0], 0x60);
        let (id, got) = parse_initial_context_token(&tok).unwrap();
        assert_eq!(id, TOK_ID_AP_REQ);
        assert_eq!(got, inner);
    }

    #[test]
    fn initial_context_token_long_length() {
        let inner = vec![0xABu8; 500]; // forces multi-octet DER length
        let tok = initial_context_token(TOK_ID_AP_REP, &inner);
        let (id, got) = parse_initial_context_token(&tok).unwrap();
        assert_eq!(id, TOK_ID_AP_REP);
        assert_eq!(got, inner);
    }

    #[test]
    fn parse_rejects_wrong_mech() {
        // valid frame but a bogus OID
        let mut tok = vec![0x60, 0x0d, 0x06, 0x09];
        tok.extend_from_slice(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x03]); // ...02.03
        tok.extend_from_slice(&[0x01, 0x00]);
        assert_eq!(parse_initial_context_token(&tok), Err(GssError::WrongMech));
    }

    #[test]
    fn mic_verifies_and_detects_tampering() {
        let k = key();
        let msg = b"the quick brown fox";
        let tok = get_mic(&k, 1, msg, false, false);
        assert_eq!(&tok[0..2], &TOK_ID_MIC);
        verify_mic(&k, &tok, msg).unwrap();
        // Tampered message: BadMic.
        assert_eq!(
            verify_mic(&k, &tok, b"the quick brown FOX"),
            Err(GssError::BadMic)
        );
        // Tampered checksum: BadMic.
        let mut bad = tok.clone();
        *bad.last_mut().unwrap() ^= 0xFF;
        assert_eq!(verify_mic(&k, &bad, msg), Err(GssError::BadMic));
    }

    #[test]
    fn mic_acceptor_role_uses_different_usage() {
        let k = key();
        let msg = b"role-bound";
        let init = get_mic(&k, 7, msg, false, false);
        let acc = get_mic(&k, 7, msg, true, false);
        // Different key usage (25 vs 23) => different checksum bytes.
        assert_ne!(init[16..], acc[16..]);
        // Each still self-verifies (role read from flags).
        verify_mic(&k, &init, msg).unwrap();
        verify_mic(&k, &acc, msg).unwrap();
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let k = key();
        let msg = b"confidential payload spanning a block or two........";
        let tok = wrap(&k, 42, msg, false, false);
        assert_eq!(&tok[0..2], &TOK_ID_WRAP);
        assert_eq!(tok[2] & FLAG_SEALED, FLAG_SEALED);
        let out = unwrap(&k, &tok).unwrap();
        assert_eq!(out, msg);
    }

    #[test]
    fn wrap_detects_tampering() {
        let k = key();
        let tok = wrap(&k, 1, b"secret", false, false);
        let mut bad = tok.clone();
        // flip a ciphertext byte -> Kerberos HMAC fails -> Crypto error.
        let i = tok.len() - 1;
        bad[i] ^= 0x01;
        assert!(matches!(unwrap(&k, &bad), Err(GssError::Crypto(_))));
    }

    #[test]
    fn unwrap_handles_nonzero_rrc() {
        // Hand-rotate a wrap body right by RRC and set the RRC field: unwrap must recover it.
        let k = key();
        let msg = b"rotate me right by seven";
        let mut tok = wrap(&k, 9, msg, false, false);
        let rrc = 7u16;
        let body = tok.split_off(16);
        let rotated = super::rotate_right(&body, rrc as usize);
        tok[6..8].copy_from_slice(&rrc.to_be_bytes());
        tok.extend_from_slice(&rotated);
        assert_eq!(unwrap(&k, &tok).unwrap(), msg);
    }
}
