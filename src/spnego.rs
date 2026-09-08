//! RFC 4178 — SPNEGO (the `1.3.6.1.5.5.2` GSS pseudo-mechanism used by SMB/HTTP/LDAP on
//! Windows). SPNEGO negotiates which real mechanism (here: [`crate::gss`] krb5) both sides
//! speak, then carries that mechanism's tokens inside its own frames.
//!
//! - The **initiator** sends a `NegTokenInit` (its `mechTypes` preference list + an optimistic
//!   `mechToken`, i.e. a krb5 initial context token), wrapped in a GSS initial-context-token
//!   with the SPNEGO OID.
//! - The **acceptor** replies with `NegTokenResp` (a `negState` + the chosen `supportedMech`
//!   + an optional `responseToken`), sent as the bare `[1]` negotiation-token DER.
//!
//! Pure DER over [`crate::der`]; parsers are total (malformed input → [`SpnegoError`]).

use crate::der::{
    context_tag, encode_len, encode_octet_string, encode_sequence, explicit, one_or, tlv, Der,
    DerError, TAG_OCTET_STRING, TAG_SEQUENCE,
};

/// SPNEGO mechanism OID, DER-encoded (`1.3.6.1.5.5.2`).
pub const SPNEGO_OID_DER: &[u8] = &[0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02];
/// Legacy Microsoft Kerberos mech OID (`1.2.840.48018.1.2.2`), DER-encoded — Windows offers
/// this alongside the standard krb5 OID in its `mechTypes`.
pub const MS_KRB5_OID_DER: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02,
];

const TAG_OID: u8 = 0x06;
const TAG_ENUMERATED: u8 = 0x0A;

/// SPNEGO errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpnegoError {
    /// Structurally invalid / truncated token, or a DER decode failure.
    BadToken,
    /// The initial token did not carry the SPNEGO OID.
    NotSpnego,
}

impl From<DerError> for SpnegoError {
    fn from(_: DerError) -> Self {
        SpnegoError::BadToken
    }
}

/// `negState` (RFC 4178 §4.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegState {
    /// The mechanism completed successfully.
    AcceptCompleted,
    /// More tokens are required.
    AcceptIncomplete,
    /// The negotiation was rejected.
    Reject,
    /// A `mechListMIC` is required to finish.
    RequestMic,
}

impl NegState {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(NegState::AcceptCompleted),
            1 => Some(NegState::AcceptIncomplete),
            2 => Some(NegState::Reject),
            3 => Some(NegState::RequestMic),
            _ => None,
        }
    }
    fn to_u8(self) -> u8 {
        match self {
            NegState::AcceptCompleted => 0,
            NegState::AcceptIncomplete => 1,
            NegState::Reject => 2,
            NegState::RequestMic => 3,
        }
    }
}

/// `NegTokenInit ::= SEQUENCE { mechTypes [0], reqFlags [1] OPTIONAL (deprecated, not emitted),
/// mechToken [2] OPTIONAL, mechListMIC [3] OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NegTokenInit {
    /// The initiator's ordered mechanism preference, each a full DER OID (tag `06`).
    pub mech_types: Vec<Vec<u8>>,
    /// The optimistic first mechanism token (a krb5 GSS initial context token).
    pub mech_token: Option<Vec<u8>>,
    /// Optional MIC over the mech list.
    pub mech_list_mic: Option<Vec<u8>>,
}

impl NegTokenInit {
    /// Encode as a GSS initial-context-token: `60 <len> <spnego-oid> A0 { NegTokenInit }`.
    pub fn encode(&self) -> Vec<u8> {
        let mech_list: Vec<u8> = self.mech_types.concat();
        let mut fields = explicit(0, &encode_sequence(&mech_list)); // [0] mechTypes
        if let Some(t) = &self.mech_token {
            fields.extend_from_slice(&explicit(2, &encode_octet_string(t)));
        }
        if let Some(m) = &self.mech_list_mic {
            fields.extend_from_slice(&explicit(3, &encode_octet_string(m)));
        }
        let neg = encode_sequence(&fields);
        let choice = explicit(0, &neg); // NegotiationToken CHOICE [0] negTokenInit
        let mut content = Vec::with_capacity(SPNEGO_OID_DER.len() + choice.len());
        content.extend_from_slice(SPNEGO_OID_DER);
        content.extend_from_slice(&choice);
        let mut out = vec![0x60];
        out.extend_from_slice(&encode_len(content.len()));
        out.extend_from_slice(&content);
        out
    }

    /// Parse the initiator's initial context token.
    pub fn parse(token: &[u8]) -> Result<Self, SpnegoError> {
        let mut r = Der::new(token);
        let (tag, inner) = r.read_tlv()?;
        if tag != 0x60 {
            return Err(SpnegoError::BadToken);
        }
        if inner.len() < SPNEGO_OID_DER.len() || &inner[..SPNEGO_OID_DER.len()] != SPNEGO_OID_DER {
            return Err(SpnegoError::NotSpnego);
        }
        let rest = &inner[SPNEGO_OID_DER.len()..];
        let mut cr = Der::new(rest);
        let neg = one_or(cr.expect(context_tag(0))?, TAG_SEQUENCE)?; // A0 { SEQUENCE }
        let mut nr = Der::new(neg);

        let mech_list = one_or(nr.expect(context_tag(0))?, TAG_SEQUENCE)?;
        let mut ml = Der::new(mech_list);
        let mut mech_types = Vec::new();
        while !ml.is_empty() {
            let (t, c) = ml.read_tlv()?;
            if t != TAG_OID {
                return Err(SpnegoError::BadToken);
            }
            mech_types.push(tlv(TAG_OID, c));
        }

        let mut mech_token = None;
        let mut mech_list_mic = None;
        // reqFlags [1] is deprecated; skip it if present.
        if nr.peek_tag() == Some(context_tag(1)) {
            let _ = nr.expect(context_tag(1))?;
        }
        if nr.peek_tag() == Some(context_tag(2)) {
            mech_token = Some(one_or(nr.expect(context_tag(2))?, TAG_OCTET_STRING)?.to_vec());
        }
        if nr.peek_tag() == Some(context_tag(3)) {
            mech_list_mic = Some(one_or(nr.expect(context_tag(3))?, TAG_OCTET_STRING)?.to_vec());
        }
        Ok(NegTokenInit {
            mech_types,
            mech_token,
            mech_list_mic,
        })
    }
}

/// `NegTokenResp ::= SEQUENCE { negState [0] OPTIONAL, supportedMech [1] OPTIONAL,
/// responseToken [2] OPTIONAL, mechListMIC [3] OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NegTokenResp {
    /// The acceptor's negotiation state.
    pub neg_state: Option<NegState>,
    /// The mechanism the acceptor selected (full DER OID).
    pub supported_mech: Option<Vec<u8>>,
    /// The selected mechanism's response token (e.g. a krb5 AP-REP context token).
    pub response_token: Option<Vec<u8>>,
    /// Optional MIC over the mech list.
    pub mech_list_mic: Option<Vec<u8>>,
}

impl NegTokenResp {
    /// Encode as the bare negotiation-token `[1]` DER (no OID / no `60` wrapper).
    pub fn encode(&self) -> Vec<u8> {
        let mut fields = Vec::new();
        if let Some(s) = self.neg_state {
            fields.extend_from_slice(&explicit(0, &tlv(TAG_ENUMERATED, &[s.to_u8()])));
        }
        if let Some(m) = &self.supported_mech {
            fields.extend_from_slice(&explicit(1, m));
        }
        if let Some(t) = &self.response_token {
            fields.extend_from_slice(&explicit(2, &encode_octet_string(t)));
        }
        if let Some(m) = &self.mech_list_mic {
            fields.extend_from_slice(&explicit(3, &encode_octet_string(m)));
        }
        explicit(1, &encode_sequence(&fields)) // CHOICE [1] negTokenResp
    }

    /// Parse the acceptor's `[1]` negotiation token.
    pub fn parse(token: &[u8]) -> Result<Self, SpnegoError> {
        let mut r = Der::new(token);
        let (tag, inner) = r.read_tlv()?;
        if tag != context_tag(1) {
            return Err(SpnegoError::BadToken);
        }
        let seq = one_or(inner, TAG_SEQUENCE)?;
        let mut nr = Der::new(seq);
        let mut out = NegTokenResp::default();
        if nr.peek_tag() == Some(context_tag(0)) {
            let en = one_or(nr.expect(context_tag(0))?, TAG_ENUMERATED)?;
            let v = en.first().copied().ok_or(SpnegoError::BadToken)?;
            out.neg_state = Some(NegState::from_u8(v).ok_or(SpnegoError::BadToken)?);
        }
        if nr.peek_tag() == Some(context_tag(1)) {
            let oid = nr.expect(context_tag(1))?;
            // [1] wraps a bare MechType (OID) — keep the full TLV.
            let mut o = Der::new(oid);
            let (t, c) = o.read_tlv()?;
            if t != TAG_OID {
                return Err(SpnegoError::BadToken);
            }
            out.supported_mech = Some(tlv(TAG_OID, c));
        }
        if nr.peek_tag() == Some(context_tag(2)) {
            out.response_token =
                Some(one_or(nr.expect(context_tag(2))?, TAG_OCTET_STRING)?.to_vec());
        }
        if nr.peek_tag() == Some(context_tag(3)) {
            out.mech_list_mic =
                Some(one_or(nr.expect(context_tag(3))?, TAG_OCTET_STRING)?.to_vec());
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gss::KRB5_MECH_OID_DER;

    #[test]
    fn neg_token_init_round_trip() {
        let init = NegTokenInit {
            mech_types: vec![KRB5_MECH_OID_DER.to_vec(), MS_KRB5_OID_DER.to_vec()],
            mech_token: Some(b"\x60\x03krb5-ap-req".to_vec()),
            mech_list_mic: None,
        };
        let enc = init.encode();
        assert_eq!(enc[0], 0x60);
        let got = NegTokenInit::parse(&enc).unwrap();
        assert_eq!(got, init);
        assert_eq!(got.mech_types.len(), 2);
        assert_eq!(got.mech_types[0], KRB5_MECH_OID_DER);
    }

    #[test]
    fn neg_token_init_rejects_non_spnego() {
        // A valid 0x60 frame carrying the krb5 OID (not SPNEGO) must be rejected.
        let mut content = KRB5_MECH_OID_DER.to_vec();
        content.extend_from_slice(&[0x01, 0x00]);
        let mut tok = vec![0x60];
        tok.extend_from_slice(&encode_len(content.len()));
        tok.extend_from_slice(&content);
        assert_eq!(NegTokenInit::parse(&tok), Err(SpnegoError::NotSpnego));
    }

    #[test]
    fn neg_token_resp_round_trip() {
        let resp = NegTokenResp {
            neg_state: Some(NegState::AcceptCompleted),
            supported_mech: Some(KRB5_MECH_OID_DER.to_vec()),
            response_token: Some(b"ap-rep-bytes".to_vec()),
            mech_list_mic: Some(vec![0xAA; 12]),
        };
        let enc = resp.encode();
        assert_eq!(enc[0], context_tag(1));
        let got = NegTokenResp::parse(&enc).unwrap();
        assert_eq!(got, resp);
    }

    #[test]
    fn neg_token_resp_all_states() {
        for st in [
            NegState::AcceptCompleted,
            NegState::AcceptIncomplete,
            NegState::Reject,
            NegState::RequestMic,
        ] {
            let resp = NegTokenResp {
                neg_state: Some(st),
                ..Default::default()
            };
            assert_eq!(
                NegTokenResp::parse(&resp.encode()).unwrap().neg_state,
                Some(st)
            );
        }
    }

    #[test]
    fn garbage_does_not_panic() {
        for b in [
            &b""[..],
            &[0x60],
            &[0x60, 0x01, 0x00],
            &[0xA1, 0x02, 0x30, 0x00],
            &[0xFF; 8],
        ] {
            let _ = NegTokenInit::parse(b);
            let _ = NegTokenResp::parse(b);
        }
    }
}
