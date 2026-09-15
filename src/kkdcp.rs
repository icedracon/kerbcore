//! MS-KKDCP — the Kerberos KDC Proxy Protocol. Tunnels AS/TGS exchanges to a KDC over HTTPS
//! (POST to `https://<proxy>/KdcProxy`) when UDP/TCP 88 is not reachable — the common path for
//! Kerberos from outside a network boundary.
//!
//! This module is only the wire container ([`KdcProxyMessage`], MS-KKDCP §2.2.2) — a
//! `SEQUENCE { kerb-message [0] OCTET STRING, target-domain [1] Realm OPTIONAL, dclocator-hint
//! [2] INTEGER OPTIONAL }` where `kerb-message` is the **TCP-framed** KDC message (a 4-octet
//! big-endian length prefix followed by the AS/TGS-REQ or reply DER). The HTTPS transport
//! itself is the caller's (kerbcore does no I/O). Total parser: malformed input → [`KkdcpError`].

use crate::der::{
    context_tag, encode_integer, encode_octet_string, encode_sequence, explicit, one_or, Der,
    DerError, TAG_OCTET_STRING, TAG_SEQUENCE,
};
use crate::types::{decode_realm, encode_realm};

/// KKDCP container errors.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KkdcpError {
    /// Structurally invalid container, bad DER, or a length prefix that overruns the buffer.
    BadMessage,
}

impl From<DerError> for KkdcpError {
    fn from(_: DerError) -> Self {
        KkdcpError::BadMessage
    }
}

/// A `KDC-PROXY-MESSAGE`. `kerb_message` is the bare KDC message DER (the 4-octet TCP length
/// prefix is added on [`Self::encode`] and stripped on [`Self::parse`], so callers deal only in
/// AS/TGS DER).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KdcProxyMessage {
    /// The wrapped KDC message (AS-REQ / TGS-REQ, or on the way back an AS-REP / TGS-REP / KRB-ERROR).
    pub kerb_message: Vec<u8>,
    /// The target realm (helps the proxy locate a KDC); usually set on the request.
    pub target_domain: Option<String>,
    /// Optional DC-locator hint bit field.
    pub dclocator_hint: Option<i32>,
}

impl KdcProxyMessage {
    /// A request container wrapping `kdc_req_der` for `realm`.
    pub fn request(kdc_req_der: &[u8], realm: &str) -> Self {
        KdcProxyMessage {
            kerb_message: kdc_req_der.to_vec(),
            target_domain: Some(realm.to_string()),
            dclocator_hint: None,
        }
    }

    /// Encode the container. The `kerb-message` OCTET STRING gets the 4-octet big-endian
    /// TCP length prefix MS-KKDCP requires.
    pub fn encode(&self) -> Vec<u8> {
        let mut framed = Vec::with_capacity(4 + self.kerb_message.len());
        framed.extend_from_slice(&(self.kerb_message.len() as u32).to_be_bytes());
        framed.extend_from_slice(&self.kerb_message);

        let mut body = explicit(0, &encode_octet_string(&framed));
        if let Some(d) = &self.target_domain {
            body.extend_from_slice(&explicit(1, &encode_realm(d)));
        }
        if let Some(h) = self.dclocator_hint {
            body.extend_from_slice(&explicit(2, &encode_integer(h as i64)));
        }
        encode_sequence(&body)
    }

    /// Parse a container, stripping and validating the 4-octet length prefix on `kerb-message`.
    pub fn parse(bytes: &[u8]) -> Result<Self, KkdcpError> {
        let seq = one_or(bytes, TAG_SEQUENCE)?;
        let mut r = Der::new(seq);
        let framed = one_or(r.expect(context_tag(0))?, TAG_OCTET_STRING)?;
        if framed.len() < 4 {
            return Err(KkdcpError::BadMessage);
        }
        let n = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
        if n != framed.len() - 4 {
            return Err(KkdcpError::BadMessage);
        }
        let kerb_message = framed[4..].to_vec();

        let mut target_domain = None;
        let mut dclocator_hint = None;
        if r.peek_tag() == Some(context_tag(1)) {
            target_domain = Some(decode_realm(r.expect(context_tag(1))?)?);
        }
        if r.peek_tag() == Some(context_tag(2)) {
            let mut ir = Der::new(r.expect(context_tag(2))?);
            let v = ir.read_integer()?;
            dclocator_hint = Some(i32::try_from(v).map_err(|_| KkdcpError::BadMessage)?);
        }
        Ok(KdcProxyMessage {
            kerb_message,
            target_domain,
            dclocator_hint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        let req = b"\x6a\x05as-req-der-bytes"; // stand-in AS-REQ DER
        let m = KdcProxyMessage::request(req, "EXAMPLE.COM");
        let enc = m.encode();
        let got = KdcProxyMessage::parse(&enc).unwrap();
        assert_eq!(got.kerb_message, req);
        assert_eq!(got.target_domain.as_deref(), Some("EXAMPLE.COM"));
        assert_eq!(got.dclocator_hint, None);
    }

    #[test]
    fn reply_without_target_domain_round_trips() {
        let reply = vec![0x6b, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let m = KdcProxyMessage {
            kerb_message: reply.clone(),
            target_domain: None,
            dclocator_hint: Some(0x4000_0000u32 as i32),
        };
        let got = KdcProxyMessage::parse(&m.encode()).unwrap();
        assert_eq!(got.kerb_message, reply);
        assert_eq!(got.target_domain, None);
        assert_eq!(got.dclocator_hint, Some(0x4000_0000u32 as i32));
    }

    #[test]
    fn rejects_bad_length_prefix() {
        // Length prefix claims more bytes than the OCTET STRING carries.
        let framed = [0x00u8, 0x00, 0x00, 0xFF, 0x01, 0x02]; // says 255, has 2
        let body = explicit(0, &encode_octet_string(&framed));
        let seq = encode_sequence(&body);
        assert_eq!(KdcProxyMessage::parse(&seq), Err(KkdcpError::BadMessage));
    }

    #[test]
    fn garbage_does_not_panic() {
        for b in [&b""[..], &[0x30], &[0x30, 0x00], &[0xFF; 6]] {
            let _ = KdcProxyMessage::parse(b);
        }
    }
}
