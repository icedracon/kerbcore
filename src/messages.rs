//! RFC 4120 message layer — `Ticket`, `KDC-REQ` (AS-REQ / TGS-REQ),
//! `KDC-REP` (AS-REP / TGS-REP), and `KRB-ERROR`. Built on [`crate::der`] and
//! [`crate::types`]; every `decode()` is total (no panics on hostile bytes).
//!
//! These replace the `picky_krb::messages` structs `adhammer-kerberos` consumes
//! (`AsReq`, `AsRep`, `KdcReq`, `KdcReqBody`, `KrbError`, `TgsReq`, …). The
//! application-tag ↔ msg-type mapping is: AS-REQ 10, AS-REP 11, TGS-REQ 12,
//! TGS-REP 13, KRB-ERROR 30.

use crate::der::{
    application_tag, context_tag, encode_general_string, encode_integer, encode_octet_string,
    encode_sequence, explicit, tlv, Der, DerError, TAG_BIT_STRING, TAG_GENERAL_STRING,
    TAG_OCTET_STRING, TAG_SEQUENCE,
};
use crate::types::{
    decode_realm, encode_realm, EncryptedData, KerberosTime, PaData, PrincipalName,
};

// ── small shared helpers ───────────────────────────────────────────────────

fn one(der: &[u8], tag: u8) -> Result<&[u8], DerError> {
    let mut r = Der::new(der);
    let c = r.expect(tag)?;
    r.finish()?;
    Ok(c)
}
fn read_i32(der: &[u8]) -> Result<i32, DerError> {
    let mut r = Der::new(der);
    let v = r.read_integer()?;
    r.finish()?;
    i32::try_from(v).map_err(|_| DerError::IntTooLarge)
}

/// `KerberosFlags ::= BIT STRING (SIZE (32))` — encoded as 0 unused bits + 4 octets.
fn encode_flags(flags: u32) -> Vec<u8> {
    let mut content = Vec::with_capacity(5);
    content.push(0x00); // unused bits
    content.extend_from_slice(&flags.to_be_bytes());
    tlv(TAG_BIT_STRING, &content)
}
fn decode_flags(der: &[u8]) -> Result<u32, DerError> {
    let c = one(der, TAG_BIT_STRING)?;
    let data = c.get(1..).ok_or(DerError::Truncated)?; // drop the unused-bits octet
    let mut v = 0u32;
    for &b in data.iter().take(4) {
        v = (v << 8) | b as u32;
    }
    Ok(v)
}

fn encode_int_seq(vals: &[i32]) -> Vec<u8> {
    let body: Vec<u8> = vals
        .iter()
        .flat_map(|v| encode_integer(*v as i64))
        .collect();
    encode_sequence(&body)
}
fn decode_int_seq(der: &[u8]) -> Result<Vec<i32>, DerError> {
    let seq = one(der, TAG_SEQUENCE)?;
    let mut r = Der::new(seq);
    let mut out = Vec::new();
    while !r.is_empty() {
        out.push(i32::try_from(r.read_integer()?).map_err(|_| DerError::IntTooLarge)?);
    }
    Ok(out)
}

fn encode_padata_seq(padata: &[PaData]) -> Vec<u8> {
    let body: Vec<u8> = padata.iter().flat_map(|p| p.encode()).collect();
    encode_sequence(&body)
}
fn decode_padata_seq(der: &[u8]) -> Result<Vec<PaData>, DerError> {
    let seq = one(der, TAG_SEQUENCE)?;
    let mut r = Der::new(seq);
    let mut out = Vec::new();
    while !r.is_empty() {
        let (_, item) = r.read_tlv()?;
        // Re-wrap the item as a full SEQUENCE element for PaData::decode.
        out.push(PaData::decode(&tlv(TAG_SEQUENCE, item))?);
    }
    Ok(out)
}

// ── Ticket [APPLICATION 1] ──────────────────────────────────────────────────

/// `Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno [0] INTEGER(5), realm [1] Realm,
/// sname [2] PrincipalName, enc-part [3] EncryptedData }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    /// Ticket version — always 5.
    pub tkt_vno: i32,
    /// The realm that issued the ticket.
    pub realm: String,
    /// The service the ticket is for.
    pub sname: PrincipalName,
    /// The encrypted `EncTicketPart`.
    pub enc_part: EncryptedData,
}

impl Ticket {
    /// Full DER, including the `[APPLICATION 1]` wrapper.
    pub fn encode(&self) -> Vec<u8> {
        let body = [
            explicit(0, &encode_integer(self.tkt_vno as i64)),
            explicit(1, &encode_realm(&self.realm)),
            explicit(2, &self.sname.encode()),
            explicit(3, &self.enc_part.encode()),
        ]
        .concat();
        tlv(application_tag(1), &encode_sequence(&body))
    }
    /// Parse a `Ticket`.
    pub fn decode(der: &[u8]) -> Result<Self, DerError> {
        let seq = one(one(der, application_tag(1))?, TAG_SEQUENCE)?;
        let mut r = Der::new(seq);
        let tkt_vno = read_i32(r.expect(context_tag(0))?)?;
        let realm = decode_realm(r.expect(context_tag(1))?)?;
        let sname = PrincipalName::decode(r.expect(context_tag(2))?)?;
        let enc_part = EncryptedData::decode(r.expect(context_tag(3))?)?;
        r.finish()?;
        Ok(Ticket {
            tkt_vno,
            realm,
            sname,
            enc_part,
        })
    }
}

// ── KDC-REQ-BODY ────────────────────────────────────────────────────────────

/// `KDC-REQ-BODY`. The three least-used optional fields (addresses,
/// enc-authorization-data, additional-tickets) are kept as raw DER passthrough so
/// real messages round-trip losslessly without modelling every sub-structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdcReqBody {
    /// `KDCOptions` flag bits.
    pub kdc_options: u32,
    /// Client principal (absent in a TGS-REQ).
    pub cname: Option<PrincipalName>,
    /// Target realm.
    pub realm: String,
    /// Service principal.
    pub sname: Option<PrincipalName>,
    /// Optional start time.
    pub from: Option<KerberosTime>,
    /// Expiry.
    pub till: KerberosTime,
    /// Optional renew-till.
    pub rtime: Option<KerberosTime>,
    /// Anti-replay nonce.
    pub nonce: u32,
    /// Requested enctypes, most-preferred first.
    pub etypes: Vec<i32>,
    /// `[9]` addresses — raw inner DER, if present.
    pub addresses: Option<Vec<u8>>,
    /// `[10]` enc-authorization-data — raw inner DER, if present.
    pub enc_authorization_data: Option<Vec<u8>>,
    /// `[11]` additional-tickets — raw inner DER, if present.
    pub additional_tickets: Option<Vec<u8>>,
}

impl KdcReqBody {
    /// Bare DER (`SEQUENCE`).
    pub fn encode(&self) -> Vec<u8> {
        let mut body = explicit(0, &encode_flags(self.kdc_options));
        if let Some(c) = &self.cname {
            body.extend_from_slice(&explicit(1, &c.encode()));
        }
        body.extend_from_slice(&explicit(2, &encode_realm(&self.realm)));
        if let Some(s) = &self.sname {
            body.extend_from_slice(&explicit(3, &s.encode()));
        }
        if let Some(t) = &self.from {
            body.extend_from_slice(&explicit(4, &t.encode()));
        }
        body.extend_from_slice(&explicit(5, &self.till.encode()));
        if let Some(t) = &self.rtime {
            body.extend_from_slice(&explicit(6, &t.encode()));
        }
        body.extend_from_slice(&explicit(7, &encode_integer(self.nonce as i64)));
        body.extend_from_slice(&explicit(8, &encode_int_seq(&self.etypes)));
        if let Some(v) = &self.addresses {
            body.extend_from_slice(&explicit(9, v));
        }
        if let Some(v) = &self.enc_authorization_data {
            body.extend_from_slice(&explicit(10, v));
        }
        if let Some(v) = &self.additional_tickets {
            body.extend_from_slice(&explicit(11, v));
        }
        encode_sequence(&body)
    }

    /// Parse a `KDC-REQ-BODY`.
    pub fn decode(der: &[u8]) -> Result<Self, DerError> {
        let body = one(der, TAG_SEQUENCE)?;
        let mut r = Der::new(body);
        let kdc_options = decode_flags(r.expect(context_tag(0))?)?;
        let cname = opt(&mut r, 1, PrincipalName::decode)?;
        let realm = decode_realm(r.expect(context_tag(2))?)?;
        let sname = opt(&mut r, 3, PrincipalName::decode)?;
        let from = opt(&mut r, 4, KerberosTime::decode)?;
        let till = KerberosTime::decode(r.expect(context_tag(5))?)?;
        let rtime = opt(&mut r, 6, KerberosTime::decode)?;
        let nonce = read_i32(r.expect(context_tag(7))?)? as u32;
        let etypes = decode_int_seq(r.expect(context_tag(8))?)?;
        let addresses = opt_raw(&mut r, 9);
        let enc_authorization_data = opt_raw(&mut r, 10);
        let additional_tickets = opt_raw(&mut r, 11);
        r.finish()?;
        Ok(KdcReqBody {
            kdc_options,
            cname,
            realm,
            sname,
            from,
            till,
            rtime,
            nonce,
            etypes,
            addresses,
            enc_authorization_data,
            additional_tickets,
        })
    }
}

/// Read an OPTIONAL `[n]`-tagged field, applying `f` to its inner DER.
fn opt<T>(
    r: &mut Der<'_>,
    n: u8,
    f: impl Fn(&[u8]) -> Result<T, DerError>,
) -> Result<Option<T>, DerError> {
    if r.peek_tag() == Some(context_tag(n)) {
        Ok(Some(f(r.expect(context_tag(n))?)?))
    } else {
        Ok(None)
    }
}
/// Read an OPTIONAL `[n]` field as raw inner DER bytes.
fn opt_raw(r: &mut Der<'_>, n: u8) -> Option<Vec<u8>> {
    if r.peek_tag() == Some(context_tag(n)) {
        r.expect(context_tag(n)).ok().map(|b| b.to_vec())
    } else {
        None
    }
}

// ── KDC-REQ (AS-REQ [APP 10] / TGS-REQ [APP 12]) ────────────────────────────

/// `KDC-REQ`. `msg_type` (10 = AS-REQ, 12 = TGS-REQ) also selects the outer
/// application tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdcReq {
    /// 10 = AS-REQ, 12 = TGS-REQ.
    pub msg_type: i32,
    /// Pre-authentication data.
    pub padata: Vec<PaData>,
    /// The request body.
    pub req_body: KdcReqBody,
}

impl KdcReq {
    /// Full DER, `[APPLICATION msg_type]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = explicit(1, &encode_integer(5)); // pvno [1] = 5
        body.extend_from_slice(&explicit(2, &encode_integer(self.msg_type as i64)));
        if !self.padata.is_empty() {
            body.extend_from_slice(&explicit(3, &encode_padata_seq(&self.padata)));
        }
        body.extend_from_slice(&explicit(4, &self.req_body.encode()));
        tlv(
            application_tag(self.msg_type as u8),
            &encode_sequence(&body),
        )
    }
    /// Parse an AS-REQ or TGS-REQ (app tag inferred, then checked against msg-type).
    pub fn decode(der: &[u8]) -> Result<Self, DerError> {
        let (app, inner) = Der::new(der).read_tlv().and_then(|(t, c)| {
            // app tag must be 10 or 12.
            if t == application_tag(10) || t == application_tag(12) {
                Ok((t, c))
            } else {
                Err(DerError::TagMismatch {
                    expected: application_tag(10),
                    found: t,
                })
            }
        })?;
        let _ = app;
        let seq = one(inner, TAG_SEQUENCE)?;
        let mut r = Der::new(seq);
        let _pvno = read_i32(r.expect(context_tag(1))?)?;
        let msg_type = read_i32(r.expect(context_tag(2))?)?;
        let padata = match opt(&mut r, 3, |b| Ok::<_, DerError>(b.to_vec()))? {
            Some(raw) => decode_padata_seq(&raw)?,
            None => Vec::new(),
        };
        let req_body = KdcReqBody::decode(r.expect(context_tag(4))?)?;
        r.finish()?;
        Ok(KdcReq {
            msg_type,
            padata,
            req_body,
        })
    }
}

// ── KDC-REP (AS-REP [APP 11] / TGS-REP [APP 13]) ────────────────────────────

/// `KDC-REP`. `msg_type` (11 = AS-REP, 13 = TGS-REP) selects the application tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdcRep {
    /// 11 = AS-REP, 13 = TGS-REP.
    pub msg_type: i32,
    /// Pre-auth data (often empty on a reply).
    pub padata: Vec<PaData>,
    /// Client realm.
    pub crealm: String,
    /// Client principal.
    pub cname: PrincipalName,
    /// The issued ticket.
    pub ticket: Ticket,
    /// The encrypted `EncKDCRepPart` (session key etc.).
    pub enc_part: EncryptedData,
}

impl KdcRep {
    /// Full DER, `[APPLICATION msg_type]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = explicit(0, &encode_integer(5)); // pvno [0] = 5
        body.extend_from_slice(&explicit(1, &encode_integer(self.msg_type as i64)));
        if !self.padata.is_empty() {
            body.extend_from_slice(&explicit(2, &encode_padata_seq(&self.padata)));
        }
        body.extend_from_slice(&explicit(3, &encode_realm(&self.crealm)));
        body.extend_from_slice(&explicit(4, &self.cname.encode()));
        body.extend_from_slice(&explicit(5, &self.ticket.encode()));
        body.extend_from_slice(&explicit(6, &self.enc_part.encode()));
        tlv(
            application_tag(self.msg_type as u8),
            &encode_sequence(&body),
        )
    }
    /// Parse an AS-REP or TGS-REP.
    pub fn decode(der: &[u8]) -> Result<Self, DerError> {
        let (_, inner) = Der::new(der).read_tlv().and_then(|(t, c)| {
            if t == application_tag(11) || t == application_tag(13) {
                Ok((t, c))
            } else {
                Err(DerError::TagMismatch {
                    expected: application_tag(11),
                    found: t,
                })
            }
        })?;
        let seq = one(inner, TAG_SEQUENCE)?;
        let mut r = Der::new(seq);
        let _pvno = read_i32(r.expect(context_tag(0))?)?;
        let msg_type = read_i32(r.expect(context_tag(1))?)?;
        let padata = match opt(&mut r, 2, |b| Ok::<_, DerError>(b.to_vec()))? {
            Some(raw) => decode_padata_seq(&raw)?,
            None => Vec::new(),
        };
        let crealm = decode_realm(r.expect(context_tag(3))?)?;
        let cname = PrincipalName::decode(r.expect(context_tag(4))?)?;
        let ticket = Ticket::decode(r.expect(context_tag(5))?)?;
        let enc_part = EncryptedData::decode(r.expect(context_tag(6))?)?;
        r.finish()?;
        Ok(KdcRep {
            msg_type,
            padata,
            crealm,
            cname,
            ticket,
            enc_part,
        })
    }
}

// ── KRB-ERROR [APPLICATION 30] ──────────────────────────────────────────────

/// `KRB-ERROR ::= [APPLICATION 30] SEQUENCE { … }`. The most common failure the
/// KDC returns (`KDC_ERR_PREAUTH_REQUIRED`, `KDC_ERR_C_PRINCIPAL_UNKNOWN`, …).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KrbError {
    /// Server time.
    pub stime: KerberosTime,
    /// Server microseconds.
    pub susec: i32,
    /// The `KDC_ERR_*` / `KRB_AP_ERR_*` code.
    pub error_code: i32,
    /// Server realm.
    pub realm: String,
    /// Server principal.
    pub sname: PrincipalName,
    /// Optional human error text.
    pub e_text: Option<String>,
    /// Optional error data (e.g. PA-DATA hints for pre-auth).
    pub e_data: Option<Vec<u8>>,
}

impl KrbError {
    /// Full DER, `[APPLICATION 30]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = explicit(0, &encode_integer(5)); // pvno
        body.extend_from_slice(&explicit(1, &encode_integer(30))); // msg-type
        body.extend_from_slice(&explicit(4, &self.stime.encode()));
        body.extend_from_slice(&explicit(5, &encode_integer(self.susec as i64)));
        body.extend_from_slice(&explicit(6, &encode_integer(self.error_code as i64)));
        body.extend_from_slice(&explicit(9, &encode_realm(&self.realm)));
        body.extend_from_slice(&explicit(10, &self.sname.encode()));
        if let Some(t) = &self.e_text {
            body.extend_from_slice(&explicit(11, &encode_general_string(t)));
        }
        if let Some(d) = &self.e_data {
            body.extend_from_slice(&explicit(12, &encode_octet_string(d)));
        }
        tlv(application_tag(30), &encode_sequence(&body))
    }
    /// Parse a `KRB-ERROR`.
    pub fn decode(der: &[u8]) -> Result<Self, DerError> {
        let seq = one(one(der, application_tag(30))?, TAG_SEQUENCE)?;
        let mut r = Der::new(seq);
        let _pvno = read_i32(r.expect(context_tag(0))?)?;
        let _msg_type = read_i32(r.expect(context_tag(1))?)?;
        // ctime [2] / cusec [3] are OPTIONAL — skip if present.
        let _ = opt(&mut r, 2, |b| Ok::<_, DerError>(b.to_vec()))?;
        let _ = opt(&mut r, 3, |b| Ok::<_, DerError>(b.to_vec()))?;
        let stime = KerberosTime::decode(r.expect(context_tag(4))?)?;
        let susec = read_i32(r.expect(context_tag(5))?)?;
        let error_code = read_i32(r.expect(context_tag(6))?)?;
        // crealm [7] / cname [8] OPTIONAL — skip.
        let _ = opt(&mut r, 7, |b| Ok::<_, DerError>(b.to_vec()))?;
        let _ = opt(&mut r, 8, |b| Ok::<_, DerError>(b.to_vec()))?;
        let realm = decode_realm(r.expect(context_tag(9))?)?;
        let sname = PrincipalName::decode(r.expect(context_tag(10))?)?;
        let e_text = opt(&mut r, 11, |b| {
            let c = one(b, TAG_GENERAL_STRING)?;
            Ok::<_, DerError>(String::from_utf8_lossy(c).into_owned())
        })?;
        let e_data = opt(&mut r, 12, |b| {
            Ok::<_, DerError>(one(b, TAG_OCTET_STRING)?.to_vec())
        })?;
        r.finish()?;
        Ok(KrbError {
            stime,
            susec,
            error_code,
            realm,
            sname,
            e_text,
            e_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_princ() -> PrincipalName {
        PrincipalName {
            name_type: 1,
            name_string: vec!["alice".into()],
        }
    }
    fn sample_svc() -> PrincipalName {
        PrincipalName {
            name_type: 2,
            name_string: vec!["host".into(), "dc.example.com".into()],
        }
    }
    fn sample_ticket() -> Ticket {
        Ticket {
            tkt_vno: 5,
            realm: "EXAMPLE.COM".into(),
            sname: sample_svc(),
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(2),
                cipher: vec![0xde, 0xad, 0xbe, 0xef],
            },
        }
    }

    #[test]
    fn ticket_roundtrip_and_app_tag() {
        let t = sample_ticket();
        let der = t.encode();
        assert_eq!(der[0], application_tag(1)); // 0x61
        assert_eq!(Ticket::decode(&der).unwrap(), t);
    }

    #[test]
    fn as_req_roundtrip_and_app_tag() {
        let body = KdcReqBody {
            kdc_options: 0x40810010,
            cname: Some(sample_princ()),
            realm: "EXAMPLE.COM".into(),
            sname: Some(sample_svc()),
            from: None,
            till: KerberosTime("20370913024805Z".into()),
            rtime: None,
            nonce: 0x1234_5678,
            etypes: vec![18, 17, 23],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };
        let req = KdcReq {
            msg_type: 10,
            padata: vec![PaData {
                padata_type: 128,
                padata_value: vec![0x30, 0x00],
            }],
            req_body: body,
        };
        let der = req.encode();
        assert_eq!(der[0], application_tag(10)); // 0x6a = AS-REQ
        assert_eq!(KdcReq::decode(&der).unwrap(), req);
    }

    #[test]
    fn as_rep_roundtrip_and_app_tag() {
        let rep = KdcRep {
            msg_type: 11,
            padata: vec![],
            crealm: "EXAMPLE.COM".into(),
            cname: sample_princ(),
            ticket: sample_ticket(),
            enc_part: EncryptedData {
                etype: 18,
                kvno: None,
                cipher: vec![1, 2, 3],
            },
        };
        let der = rep.encode();
        assert_eq!(der[0], application_tag(11)); // 0x6b = AS-REP
        assert_eq!(KdcRep::decode(&der).unwrap(), rep);
    }

    #[test]
    fn krb_error_roundtrip_and_app_tag() {
        let err = KrbError {
            stime: KerberosTime("20240102030405Z".into()),
            susec: 123456,
            error_code: 25, // KDC_ERR_PREAUTH_REQUIRED
            realm: "EXAMPLE.COM".into(),
            sname: sample_svc(),
            e_text: Some("NEEDED_PREAUTH".into()),
            e_data: Some(vec![0x30, 0x05, 0x02, 0x01, 0x01]),
        };
        let der = err.encode();
        assert_eq!(der[0], application_tag(30)); // 0x7e
        assert_eq!(KrbError::decode(&der).unwrap(), err);
    }

    #[test]
    fn kdc_req_body_optional_fields_roundtrip() {
        let body = KdcReqBody {
            kdc_options: 0,
            cname: None, // TGS-REQ shape
            realm: "R".into(),
            sname: Some(sample_svc()),
            from: Some(KerberosTime("20240101000000Z".into())),
            till: KerberosTime("20240102000000Z".into()),
            rtime: Some(KerberosTime("20240103000000Z".into())),
            nonce: 1,
            etypes: vec![18],
            addresses: Some(vec![0x30, 0x00]),
            enc_authorization_data: None,
            additional_tickets: Some(vec![0x30, 0x00]),
        };
        assert_eq!(KdcReqBody::decode(&body.encode()).unwrap(), body);
    }

    #[test]
    fn messages_reject_garbage_without_panic() {
        for bad in [&[][..], &[0x6a, 0x02, 0x30, 0x00][..], &[0xff][..]] {
            assert!(Ticket::decode(bad).is_err());
            assert!(KdcReq::decode(bad).is_err());
            assert!(KdcRep::decode(bad).is_err());
            assert!(KrbError::decode(bad).is_err());
        }
    }
}
