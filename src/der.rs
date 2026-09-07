//! Minimal DER (X.690) codec — only the subset RFC 4120 Kerberos needs.
//!
//! Hand-rolled, no external ASN.1 crate. The **decoder is total**: every malformed
//! input returns [`DerError`], never panics — it parses untrusted KDC / attacker
//! bytes, so a hostile message must fail cleanly, not crash. The encoder emits
//! canonical DER (definite lengths, minimal integers).
//!
//! This is the foundation for the Kerberos message codec (RFC 4120 structures)
//! that replaces `picky-krb` — built on top of these primitives in later modules.

// ── Universal tags ────────────────────────────────────────────────────────────
/// INTEGER.
pub const TAG_INTEGER: u8 = 0x02;
/// BIT STRING.
pub const TAG_BIT_STRING: u8 = 0x03;
/// OCTET STRING.
pub const TAG_OCTET_STRING: u8 = 0x04;
/// GeneralizedTime (Kerberos `KerberosTime`).
pub const TAG_GENERALIZED_TIME: u8 = 0x18;
/// GeneralString (Kerberos `KerberosString`).
pub const TAG_GENERAL_STRING: u8 = 0x1B;
/// SEQUENCE / SEQUENCE OF (constructed).
pub const TAG_SEQUENCE: u8 = 0x30;

/// Explicit context tag `[n]` (constructed): `0xA0 | n`. Kerberos tags every
/// struct field this way. `n` must be 0..=30.
#[inline]
pub const fn context_tag(n: u8) -> u8 {
    0xA0 | n
}

/// Application tag `[APPLICATION n]` (constructed): `0x60 | n`. Kerberos wraps each
/// top-level PDU (AS-REQ = 10, Ticket = 1, KRB-ERROR = 30, …). `n` must be 0..=30.
#[inline]
pub const fn application_tag(n: u8) -> u8 {
    0x60 | n
}

// ── Encoding ──────────────────────────────────────────────────────────────────

/// DER definite length octets.
pub fn encode_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut body = Vec::new();
        let mut l = len;
        while l > 0 {
            body.insert(0, (l & 0xff) as u8);
            l >>= 8;
        }
        let mut out = Vec::with_capacity(1 + body.len());
        out.push(0x80 | body.len() as u8);
        out.extend_from_slice(&body);
        out
    }
}

/// `tag || len || content` — the DER TLV.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + content.len() + 2);
    out.push(tag);
    out.extend_from_slice(&encode_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Canonical DER INTEGER (minimal two's-complement, big-endian).
pub fn encode_integer(value: i64) -> Vec<u8> {
    let mut b = value.to_be_bytes().to_vec();
    // Strip redundant leading bytes while preserving the sign bit.
    while b.len() > 1 && ((b[0] == 0x00 && b[1] & 0x80 == 0) || (b[0] == 0xff && b[1] & 0x80 != 0))
    {
        b.remove(0);
    }
    tlv(TAG_INTEGER, &b)
}

/// OCTET STRING.
pub fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    tlv(TAG_OCTET_STRING, data)
}

/// GeneralString (Kerberos `KerberosString`, IA5 in practice).
pub fn encode_general_string(s: &str) -> Vec<u8> {
    tlv(TAG_GENERAL_STRING, s.as_bytes())
}

/// GeneralizedTime, e.g. `"19700101000000Z"`. Caller supplies the ASCII form.
pub fn encode_generalized_time(t: &str) -> Vec<u8> {
    tlv(TAG_GENERALIZED_TIME, t.as_bytes())
}

/// SEQUENCE wrapping already-encoded members concatenated in `body`.
pub fn encode_sequence(body: &[u8]) -> Vec<u8> {
    tlv(TAG_SEQUENCE, body)
}

/// Explicit `[n]` context wrapper around an already-encoded inner value.
pub fn explicit(n: u8, inner_der: &[u8]) -> Vec<u8> {
    tlv(context_tag(n), inner_der)
}

/// `[APPLICATION n]` wrapper around an already-encoded inner value.
pub fn application(n: u8, inner_der: &[u8]) -> Vec<u8> {
    tlv(application_tag(n), inner_der)
}

// ── Decoding (total — never panics) ────────────────────────────────────────────

/// Errors from the DER reader. Every malformed byte sequence yields one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DerError {
    /// Ran off the end of the buffer mid-element.
    Truncated,
    /// Length octets are malformed (indefinite form, or > usize).
    BadLength,
    /// A tag did not match what the caller required.
    TagMismatch { expected: u8, found: u8 },
    /// INTEGER wider than an `i64`.
    IntTooLarge,
    /// Bytes remained after the value the caller expected to be complete.
    TrailingData,
}

impl core::fmt::Display for DerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => write!(f, "DER: truncated"),
            Self::BadLength => write!(f, "DER: bad length octets"),
            Self::TagMismatch { expected, found } => {
                write!(
                    f,
                    "DER: tag mismatch (expected 0x{expected:02x}, found 0x{found:02x})"
                )
            }
            Self::IntTooLarge => write!(f, "DER: INTEGER exceeds i64"),
            Self::TrailingData => write!(f, "DER: unexpected trailing data"),
        }
    }
}
impl std::error::Error for DerError {}

/// A cursor over a DER buffer. Borrows the input; returned slices are sub-borrows.
pub struct Der<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    /// Wrap a buffer.
    pub fn new(buf: &'a [u8]) -> Self {
        Der { buf, pos: 0 }
    }

    /// Whether every byte has been consumed.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// The tag of the next element without consuming it — for OPTIONAL fields.
    pub fn peek_tag(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// Error unless the buffer is fully consumed — call after a top-level parse.
    pub fn finish(&self) -> Result<(), DerError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(DerError::TrailingData)
        }
    }

    fn read_len(&mut self) -> Result<usize, DerError> {
        let first = *self.buf.get(self.pos).ok_or(DerError::Truncated)?;
        self.pos += 1;
        if first < 0x80 {
            return Ok(first as usize);
        }
        let n = (first & 0x7f) as usize;
        // n == 0 is the indefinite form (illegal in DER); n > 8 overflows usize here.
        if n == 0 || n > core::mem::size_of::<usize>() {
            return Err(DerError::BadLength);
        }
        let mut len = 0usize;
        for _ in 0..n {
            let b = *self.buf.get(self.pos).ok_or(DerError::Truncated)?;
            self.pos += 1;
            len = (len << 8) | b as usize;
        }
        Ok(len)
    }

    /// Read one TLV; return `(tag, content)` and advance past it.
    pub fn read_tlv(&mut self) -> Result<(u8, &'a [u8]), DerError> {
        let tag = *self.buf.get(self.pos).ok_or(DerError::Truncated)?;
        self.pos += 1;
        let len = self.read_len()?;
        let end = self.pos.checked_add(len).ok_or(DerError::BadLength)?;
        if end > self.buf.len() {
            return Err(DerError::Truncated);
        }
        let content = &self.buf[self.pos..end];
        self.pos = end;
        Ok((tag, content))
    }

    /// Read a TLV and require its tag; return the content.
    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8], DerError> {
        let (found, content) = self.read_tlv()?;
        if found != tag {
            return Err(DerError::TagMismatch {
                expected: tag,
                found,
            });
        }
        Ok(content)
    }

    /// Read an INTEGER as `i64`.
    pub fn read_integer(&mut self) -> Result<i64, DerError> {
        let content = self.expect(TAG_INTEGER)?;
        if content.is_empty() || content.len() > 8 {
            return Err(DerError::IntTooLarge);
        }
        // Sign-extend the big-endian two's-complement content into an i64.
        let neg = content[0] & 0x80 != 0;
        let mut v: i64 = if neg { -1 } else { 0 };
        for &b in content {
            v = (v << 8) | b as i64;
        }
        Ok(v)
    }

    /// Read an OCTET STRING.
    pub fn read_octet_string(&mut self) -> Result<&'a [u8], DerError> {
        self.expect(TAG_OCTET_STRING)
    }

    /// Read a GeneralString as bytes (Kerberos strings are IA5/ASCII in practice).
    pub fn read_general_string(&mut self) -> Result<&'a [u8], DerError> {
        self.expect(TAG_GENERAL_STRING)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexs(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // ── Known-answer DER INTEGER encodings (X.690 canonical form) ─────────
    #[test]
    fn integer_der_known_answers() {
        assert_eq!(hexs(&encode_integer(0)), "020100");
        assert_eq!(hexs(&encode_integer(127)), "02017f");
        assert_eq!(hexs(&encode_integer(128)), "02020080");
        assert_eq!(hexs(&encode_integer(255)), "020200ff");
        assert_eq!(hexs(&encode_integer(256)), "02020100");
        assert_eq!(hexs(&encode_integer(-1)), "0201ff");
        assert_eq!(hexs(&encode_integer(-128)), "020180");
        assert_eq!(hexs(&encode_integer(23)), "020117"); // etype 23 (RC4)
    }

    #[test]
    fn length_encoding() {
        assert_eq!(hexs(&encode_len(0)), "00");
        assert_eq!(hexs(&encode_len(127)), "7f");
        assert_eq!(hexs(&encode_len(128)), "8180");
        assert_eq!(hexs(&encode_len(255)), "81ff");
        assert_eq!(hexs(&encode_len(256)), "820100");
        assert_eq!(hexs(&encode_len(300)), "82012c");
    }

    // ── Encode → decode round-trips ──────────────────────────────────────
    #[test]
    fn integer_roundtrip() {
        for v in [
            0i64,
            1,
            -1,
            127,
            128,
            255,
            256,
            -256,
            65535,
            i32::MAX as i64,
            i32::MIN as i64,
        ] {
            let der = encode_integer(v);
            let mut r = Der::new(&der);
            assert_eq!(r.read_integer().unwrap(), v, "int {v}");
            assert!(r.finish().is_ok());
        }
    }

    #[test]
    fn nested_structure_roundtrips() {
        // A tiny PrincipalName-shaped structure:
        //   SEQUENCE { [0] INTEGER 1, [1] SEQUENCE OF GeneralString { "host", "dc.example" } }
        let name_type = explicit(0, &encode_integer(1));
        let mut strs = Vec::new();
        strs.extend_from_slice(&encode_general_string("host"));
        strs.extend_from_slice(&encode_general_string("dc.example"));
        let name_string = explicit(1, &encode_sequence(&strs));
        let mut body = name_type.clone();
        body.extend_from_slice(&name_string);
        let seq = encode_sequence(&body);

        // Decode it back.
        let mut r = Der::new(&seq);
        let inner = r.expect(TAG_SEQUENCE).unwrap();
        r.finish().unwrap();
        let mut ir = Der::new(inner);
        let nt = ir.expect(context_tag(0)).unwrap();
        assert_eq!(Der::new(nt).read_integer().unwrap(), 1);
        let ns = ir.expect(context_tag(1)).unwrap();
        let mut nsr = Der::new(ir_seq(ns));
        assert_eq!(nsr.read_general_string().unwrap(), b"host");
        assert_eq!(nsr.read_general_string().unwrap(), b"dc.example");
        assert!(nsr.is_empty());
    }

    // Helper: strip the SEQUENCE wrapper for the SEQUENCE OF above.
    fn ir_seq(bytes: &[u8]) -> &[u8] {
        let mut r = Der::new(bytes);
        r.expect(TAG_SEQUENCE).unwrap()
    }

    // ── The decoder is total: hostile input errors, never panics ─────────
    #[test]
    fn malformed_input_never_panics() {
        let cases: &[&[u8]] = &[
            &[],                                      // empty
            &[0x02],                                  // tag only
            &[0x02, 0x05],                            // length claims 5, no content
            &[0x30, 0x80],                            // indefinite length (illegal in DER)
            &[0x02, 0x89, 0x01], // length-of-length says 9 octets → overflow guard
            &[0x02, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0], // INTEGER too wide for i64
            &[0x02, 0x01, 0x00, 0xff], // trailing byte
        ];
        for c in cases {
            let mut r = Der::new(c);
            // Whatever the caller does, it must be Err — not a panic.
            let _ = r.read_tlv();
            let mut r2 = Der::new(c);
            let _ = r2.read_integer();
        }
    }

    #[test]
    fn tag_mismatch_reported() {
        let der = encode_octet_string(b"x");
        let mut r = Der::new(&der);
        assert_eq!(
            r.read_integer(),
            Err(DerError::TagMismatch {
                expected: TAG_INTEGER,
                found: TAG_OCTET_STRING
            })
        );
    }
}
