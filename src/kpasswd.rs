//! RFC 3244 / MS-KPWD — the Kerberos change-password / set-password protocol (port 464).
//!
//! A client that holds a ticket to `kadmin/changepw` sends a request that carries an AP-REQ
//! plus a **KRB-PRIV** ([APPLICATION 21], RFC 4120 §5.7) whose encrypted `user-data` is a
//! `ChangePasswdData` (the new password, optionally the target principal for set-password).
//! The KDC replies with an AP-REP + a KRB-PRIV whose first two `user-data` octets are a
//! [`ResultCode`].
//!
//! This module provides the `ChangePasswdData` codec, a general KRB-PRIV codec (usage 13), the
//! request/reply framing (length + version + AP-REQ + KRB-PRIV), and result-code parsing. The
//! socket + the AP-REQ/AP-REP themselves are the caller's ([`crate::client`]). Pure bytes;
//! total parsers.

use crate::der::{
    application_tag, context_tag, encode_integer, encode_octet_string, encode_sequence, explicit,
    one_or, Der, DerError, TAG_OCTET_STRING, TAG_SEQUENCE,
};
use crate::keys::{KerberosKey, KeyError};
use crate::types::{encode_realm, EncryptedData, KerberosTime, PrincipalName};

/// Key usage — KRB-PRIV `EncKrbPrivPart` (RFC 4120 §7.5.1).
pub const KU_KRB_PRIV: u32 = 13;

/// kpasswd protocol version for **change-password** (a user changing their own password).
pub const VERSION_CHANGE_PASSWD: u16 = 0x0001;
/// kpasswd protocol version for **set-password** (an admin setting another principal's password, MS-KPWD).
pub const VERSION_SET_PASSWD: u16 = 0xFF80;

/// Errors from the kpasswd/KRB-PRIV codecs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KpasswdError {
    /// Malformed container / DER, or a length field that overruns the buffer.
    BadMessage,
    /// The underlying Kerberos crypto failed.
    Crypto(KeyError),
}

impl From<DerError> for KpasswdError {
    fn from(_: DerError) -> Self {
        KpasswdError::BadMessage
    }
}
impl From<KeyError> for KpasswdError {
    fn from(e: KeyError) -> Self {
        KpasswdError::Crypto(e)
    }
}

/// kpasswd result codes (RFC 3244 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultCode {
    /// Request succeeded.
    Success,
    /// Request is malformed.
    Malformed,
    /// Server error / hard error.
    HardError,
    /// Authentication error.
    AuthError,
    /// Password change rejected (soft error, e.g. policy).
    SoftError,
    /// Accessed denied.
    AccessDenied,
    /// Wrong protocol version.
    BadVersion,
    /// The ticket lacked the INITIAL flag.
    InitialFlagNeeded,
    /// Any other / vendor-specific code.
    Other(u16),
}

impl ResultCode {
    /// Map the 16-bit wire value.
    pub fn from_u16(v: u16) -> Self {
        match v {
            0 => ResultCode::Success,
            1 => ResultCode::Malformed,
            2 => ResultCode::HardError,
            3 => ResultCode::AuthError,
            4 => ResultCode::SoftError,
            5 => ResultCode::AccessDenied,
            6 => ResultCode::BadVersion,
            7 => ResultCode::InitialFlagNeeded,
            other => ResultCode::Other(other),
        }
    }
}

/// `HostAddress ::= SEQUENCE { addr-type [0] Int32, address [1] OCTET STRING }` (RFC 4120 §5.2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAddress {
    /// e.g. 2 = IPv4, 24 = IPv6, 20 = NetBIOS.
    pub addr_type: i32,
    /// The address bytes.
    pub address: Vec<u8>,
}

impl HostAddress {
    /// The address type used by kpasswd when no real address is available (RFC 3244 permits it).
    pub fn none() -> Self {
        HostAddress {
            addr_type: 0,
            address: Vec::new(),
        }
    }
    fn encode(&self) -> Vec<u8> {
        let body = [
            explicit(0, &encode_integer(self.addr_type as i64)),
            explicit(1, &encode_octet_string(&self.address)),
        ]
        .concat();
        encode_sequence(&body)
    }
}

/// `ChangePasswdData ::= SEQUENCE { newpasswd [0] OCTET STRING, targname [1] PrincipalName
/// OPTIONAL, targrealm [2] Realm OPTIONAL }` (RFC 3244 §2 / set-password).
pub fn encode_change_passwd_data(
    newpasswd: &[u8],
    targname: Option<&PrincipalName>,
    targrealm: Option<&str>,
) -> Vec<u8> {
    let mut body = explicit(0, &encode_octet_string(newpasswd));
    if let Some(n) = targname {
        body.extend_from_slice(&explicit(1, &n.encode()));
    }
    if let Some(r) = targrealm {
        body.extend_from_slice(&explicit(2, &encode_realm(r)));
    }
    encode_sequence(&body)
}

/// Parse a `ChangePasswdData`, returning the new password bytes (the field callers act on).
pub fn parse_change_passwd_newpasswd(der: &[u8]) -> Result<Vec<u8>, KpasswdError> {
    let seq = one_or(der, TAG_SEQUENCE)?;
    let mut r = Der::new(seq);
    Ok(one_or(r.expect(context_tag(0))?, TAG_OCTET_STRING)?.to_vec())
}

/// Build a **KRB-PRIV** ([APPLICATION 21]) carrying `user_data`, encrypted under `key` at usage
/// [`KU_KRB_PRIV`] with a fresh CSPRNG confounder. `s_address` is the sender address (use
/// [`HostAddress::none`] when unavailable). `seq_number`/`timestamp`+`usec` bind it against replay.
pub fn build_krb_priv(
    key: &KerberosKey,
    user_data: &[u8],
    seq_number: Option<u32>,
    timestamp: Option<(&str, i32)>,
    s_address: &HostAddress,
) -> Vec<u8> {
    // EncKrbPrivPart ::= [APPLICATION 28] SEQUENCE { user-data [0], timestamp [1] OPT,
    //   usec [2] OPT, seq-number [3] OPT, s-address [4] HostAddress, r-address [5] OPT }
    let mut body = explicit(0, &encode_octet_string(user_data));
    if let Some((ts, usec)) = timestamp {
        body.extend_from_slice(&explicit(1, &KerberosTime(ts.to_string()).encode()));
        body.extend_from_slice(&explicit(2, &encode_integer(usec as i64)));
    }
    if let Some(n) = seq_number {
        body.extend_from_slice(&explicit(3, &encode_integer(n as i64)));
    }
    body.extend_from_slice(&explicit(4, &s_address.encode()));
    let enc_part_plain = crate::der::tlv(application_tag(28), &encode_sequence(&body));

    let ed = EncryptedData {
        etype: key.enctype().to_i32(),
        kvno: None,
        cipher: key.encrypt(KU_KRB_PRIV, &enc_part_plain),
    };
    // KRB-PRIV ::= [APPLICATION 21] SEQUENCE { pvno [0], msg-type [1], enc-part [3] }
    let priv_body = [
        explicit(0, &encode_integer(5)),
        explicit(1, &encode_integer(21)),
        explicit(3, &ed.encode()),
    ]
    .concat();
    crate::der::tlv(application_tag(21), &encode_sequence(&priv_body))
}

/// Extract the `EncryptedData` from a KRB-PRIV. Decrypt at usage [`KU_KRB_PRIV`], then pass the
/// plaintext to [`parse_enc_krb_priv_user_data`].
pub fn parse_krb_priv(der: &[u8]) -> Result<EncryptedData, KpasswdError> {
    let mut r = Der::new(der);
    let (tag, inner) = r.read_tlv()?;
    if tag != application_tag(21) {
        return Err(KpasswdError::BadMessage);
    }
    let seq = one_or(inner, TAG_SEQUENCE)?;
    let mut sr = Der::new(seq);
    let pvno = crate::der::read_u32(sr.expect(context_tag(0))?)?;
    let mt = crate::der::read_u32(sr.expect(context_tag(1))?)?;
    if pvno != 5 || mt != 21 {
        return Err(KpasswdError::BadMessage);
    }
    Ok(EncryptedData::decode(sr.expect(context_tag(3))?)?)
}

/// Parse a decrypted `EncKrbPrivPart`, returning its `user-data` (for a kpasswd reply this is
/// the 2-octet result code followed by an optional message).
pub fn parse_enc_krb_priv_user_data(plaintext: &[u8]) -> Result<Vec<u8>, KpasswdError> {
    let mut r = Der::new(plaintext);
    let (tag, inner) = r.read_tlv()?;
    if tag != application_tag(28) {
        return Err(KpasswdError::BadMessage);
    }
    let seq = one_or(inner, TAG_SEQUENCE)?;
    let mut sr = Der::new(seq);
    Ok(one_or(sr.expect(context_tag(0))?, TAG_OCTET_STRING)?.to_vec())
}

/// Frame a kpasswd request: `len(2) || version(2) || ap_req_len(2) || AP-REQ || KRB-PRIV`, all
/// lengths big-endian (RFC 3244 §2). `len` covers the whole message.
pub fn build_kpasswd_request(version: u16, ap_req: &[u8], krb_priv: &[u8]) -> Vec<u8> {
    let total = 6 + ap_req.len() + krb_priv.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as u16).to_be_bytes());
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&(ap_req.len() as u16).to_be_bytes());
    out.extend_from_slice(ap_req);
    out.extend_from_slice(krb_priv);
    out
}

/// A parsed kpasswd message (request or reply share the framing): the version, the AP-REQ /
/// AP-REP bytes, and the trailing KRB-PRIV bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KpasswdMessage {
    /// Protocol version ([`VERSION_CHANGE_PASSWD`] / [`VERSION_SET_PASSWD`]).
    pub version: u16,
    /// The AP-REQ (request) or AP-REP (reply) bytes.
    pub ap_message: Vec<u8>,
    /// The trailing KRB-PRIV bytes.
    pub krb_priv: Vec<u8>,
}

/// Parse the kpasswd framing (works for a request or a reply). Validates the length header and
/// the embedded AP-message length against the buffer.
pub fn parse_kpasswd_message(bytes: &[u8]) -> Result<KpasswdMessage, KpasswdError> {
    if bytes.len() < 6 {
        return Err(KpasswdError::BadMessage);
    }
    let total = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    if total != bytes.len() {
        return Err(KpasswdError::BadMessage);
    }
    let version = u16::from_be_bytes([bytes[2], bytes[3]]);
    let ap_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    if 6 + ap_len > bytes.len() {
        return Err(KpasswdError::BadMessage);
    }
    let ap_message = bytes[6..6 + ap_len].to_vec();
    let krb_priv = bytes[6 + ap_len..].to_vec();
    Ok(KpasswdMessage {
        version,
        ap_message,
        krb_priv,
    })
}

/// The [`ResultCode`] from a decrypted kpasswd reply `user-data` (its first two octets, BE).
pub fn result_code(user_data: &[u8]) -> Result<ResultCode, KpasswdError> {
    if user_data.len() < 2 {
        return Err(KpasswdError::BadMessage);
    }
    Ok(ResultCode::from_u16(u16::from_be_bytes([
        user_data[0],
        user_data[1],
    ])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{Enctype, KerberosKey};

    fn key() -> KerberosKey {
        KerberosKey::new(Enctype::Aes256CtsHmacSha1_96, vec![0x21u8; 32]).unwrap()
    }

    #[test]
    fn change_passwd_data_round_trip() {
        let cpd = encode_change_passwd_data(b"C0rrectH0rse!", None, None);
        assert_eq!(
            parse_change_passwd_newpasswd(&cpd).unwrap(),
            b"C0rrectH0rse!"
        );
    }

    #[test]
    fn krb_priv_encrypt_parse_decrypt_round_trip() {
        let k = key();
        let cpd = encode_change_passwd_data(b"new-pass", None, None);
        let kp = build_krb_priv(
            &k,
            &cpd,
            Some(1),
            Some(("20260908120000Z", 5)),
            &HostAddress::none(),
        );
        // Recover: parse KRB-PRIV -> decrypt -> parse EncKrbPrivPart -> ChangePasswdData.
        let ed = parse_krb_priv(&kp).unwrap();
        let plain = k.decrypt(KU_KRB_PRIV, &ed.cipher).unwrap();
        let user_data = parse_enc_krb_priv_user_data(&plain).unwrap();
        assert_eq!(
            parse_change_passwd_newpasswd(&user_data).unwrap(),
            b"new-pass"
        );
    }

    #[test]
    fn krb_priv_detects_tampering() {
        let k = key();
        let kp = build_krb_priv(&k, b"x", None, None, &HostAddress::none());
        let ed = parse_krb_priv(&kp).unwrap();
        let mut bad = ed.cipher.clone();
        *bad.last_mut().unwrap() ^= 0xFF;
        assert!(k.decrypt(KU_KRB_PRIV, &bad).is_err());
    }

    #[test]
    fn kpasswd_framing_round_trip() {
        let ap = b"\x6e\x05ap-req";
        let kp = b"\x75\x03krb-priv-bytes";
        let msg = build_kpasswd_request(VERSION_CHANGE_PASSWD, ap, kp);
        let got = parse_kpasswd_message(&msg).unwrap();
        assert_eq!(got.version, VERSION_CHANGE_PASSWD);
        assert_eq!(got.ap_message, ap);
        assert_eq!(got.krb_priv, kp);
    }

    #[test]
    fn kpasswd_framing_rejects_bad_ap_len() {
        // total header correct, but ap_len overruns.
        let mut m = vec![0x00, 0x08, 0x00, 0x01, 0xFF, 0xFF, 0xAA, 0xBB];
        m[1] = 0x08; // total = 8 = actual
        assert_eq!(parse_kpasswd_message(&m), Err(KpasswdError::BadMessage));
    }

    #[test]
    fn result_codes() {
        assert_eq!(result_code(&[0x00, 0x00]).unwrap(), ResultCode::Success);
        assert_eq!(
            result_code(&[0x00, 0x05]).unwrap(),
            ResultCode::AccessDenied
        );
        assert_eq!(result_code(&[0x00, 0x63]).unwrap(), ResultCode::Other(99));
        assert_eq!(result_code(&[0x00]), Err(KpasswdError::BadMessage));
    }
}
