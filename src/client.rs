//! AS-exchange client helpers — assemble an AS-REQ, build the PA-ENC-TIMESTAMP
//! pre-auth, and parse the pieces of the KDC's reply. Pure (no I/O): the caller
//! owns the socket. This is the glue that ties [`crate::crypto`] /
//! [`crate::rfc8009`] (keys) to [`crate::messages`] (wire) into a real Kerberos
//! AS handshake — the last layer before `kerbcore` can replace `picky-krb`.

use crate::der::{context_tag, encode_sequence, explicit, one_or, Der, DerError, TAG_SEQUENCE};
use crate::messages::{KdcReq, KdcReqBody};
use crate::types::{EncryptedData, KerberosTime, PaData, PrincipalName};

/// RFC 4120 §7.5.1 key usage — AS-REQ PA-ENC-TIMESTAMP padata.
pub const KU_AS_REQ_PA_ENC_TS: u32 = 1;
/// Key usage — AS-REP `EncASRepPart`, encrypted under the client key.
pub const KU_AS_REP_ENC_PART: u32 = 3;

/// PA-DATA type for the encrypted-timestamp pre-auth.
pub const PA_ENC_TIMESTAMP: i32 = 2;
/// PA-DATA type for ETYPE-INFO2 (carries the salt the KDC wants).
pub const PA_ETYPE_INFO2: i32 = 19;

/// NT-PRINCIPAL name type.
pub const NT_PRINCIPAL: i32 = 1;
/// NT-SRV-INST name type (used for the `krbtgt/REALM` service name).
pub const NT_SRV_INST: i32 = 2;

/// Format a Unix timestamp as a `KerberosTime` (`YYYYMMDDHHMMSSZ`, UTC).
/// Pure integer calendar math (Hinnant's `civil_from_days`) — no time crate.
pub fn unix_to_kerberos_time(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}{m:02}{d:02}{h:02}{mi:02}{s:02}Z")
}

/// `krbtgt/REALM` service principal (the AS target).
pub fn krbtgt_sname(realm: &str) -> PrincipalName {
    PrincipalName {
        name_type: NT_SRV_INST,
        name_string: vec!["krbtgt".to_string(), realm.to_string()],
    }
}

/// A client principal by sAMAccountName.
pub fn client_cname(user: &str) -> PrincipalName {
    PrincipalName {
        name_type: NT_PRINCIPAL,
        name_string: vec![user.to_string()],
    }
}

/// `PA-ENC-TS-ENC ::= SEQUENCE { patimestamp [0] KerberosTime, pausec [1] Microseconds OPTIONAL }`.
pub fn encode_pa_enc_ts_enc(kerberos_time: &str, usec: i32) -> Vec<u8> {
    let body = [
        explicit(0, &KerberosTime(kerberos_time.to_string()).encode()),
        explicit(1, &crate::der::encode_integer(usec as i64)),
    ]
    .concat();
    encode_sequence(&body)
}

/// Build an AS-REQ. `padata` is the pre-auth list (empty for the first,
/// deliberately-failing probe that makes the KDC reveal the salt).
pub fn build_as_req(
    realm: &str,
    cname: &PrincipalName,
    nonce: u32,
    till: &str,
    etypes: &[i32],
    padata: Vec<PaData>,
) -> Vec<u8> {
    let body = KdcReqBody {
        kdc_options: 0x4081_0010, // forwardable + renewable + canonicalize (typical)
        cname: Some(cname.clone()),
        realm: realm.to_string(),
        sname: Some(krbtgt_sname(realm)),
        from: None,
        till: KerberosTime(till.to_string()),
        rtime: None,
        nonce,
        etypes: etypes.to_vec(),
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    KdcReq {
        msg_type: 10,
        padata,
        req_body: body,
    }
    .encode()
}

/// A single `ETYPE-INFO2-ENTRY`: the enctype and (usually) the salt to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtypeInfo2Entry {
    /// The enctype the KDC has a key for.
    pub etype: i32,
    /// The salt for `string-to-key` (absent → use the default realm+principal salt).
    pub salt: Option<String>,
}

/// Parse `ETYPE-INFO2 ::= SEQUENCE OF ETYPE-INFO2-ENTRY` from a PA-DATA value.
/// `ETYPE-INFO2-ENTRY ::= SEQUENCE { etype [0] Int32, salt [1] KerberosString OPTIONAL, s2kparams [2] OCTET STRING OPTIONAL }`.
pub fn parse_etype_info2(padata_value: &[u8]) -> Result<Vec<EtypeInfo2Entry>, DerError> {
    let seq = one_or(padata_value, TAG_SEQUENCE)?;
    let mut r = Der::new(seq);
    let mut out = Vec::new();
    while !r.is_empty() {
        let (_, entry) = r.read_tlv()?;
        let mut er = Der::new(entry);
        let etype = {
            let mut ir = Der::new(er.expect(context_tag(0))?);
            i32::try_from(ir.read_integer()?).map_err(|_| DerError::IntTooLarge)?
        };
        let salt = if er.peek_tag() == Some(context_tag(1)) {
            let c = er.expect(context_tag(1))?;
            let inner = one_or(c, crate::der::TAG_GENERAL_STRING)?;
            Some(String::from_utf8_lossy(inner).into_owned())
        } else {
            None
        };
        out.push(EtypeInfo2Entry { etype, salt });
    }
    Ok(out)
}

/// Extract the session [`crate::types::EncryptionKey`] from a decrypted
/// `EncKDCRepPart` (`key` is field `[0]`). Works for `EncASRepPart` [APP 25] and
/// `EncTGSRepPart` [APP 26] — pass the plaintext after decrypting the AS-REP
/// enc-part with the client key at usage [`KU_AS_REP_ENC_PART`].
pub fn enc_kdc_rep_part_session_key(
    plaintext: &[u8],
) -> Result<crate::types::EncryptionKey, DerError> {
    // [APPLICATION 25|26] SEQUENCE { key [0] EncryptionKey, ... }
    let mut r = Der::new(plaintext);
    let (tag, inner) = r.read_tlv()?;
    if tag != crate::der::application_tag(25) && tag != crate::der::application_tag(26) {
        return Err(DerError::TagMismatch {
            expected: crate::der::application_tag(25),
            found: tag,
        });
    }
    let seq = one_or(inner, TAG_SEQUENCE)?;
    let mut sr = Der::new(seq);
    let key_der = sr.expect(context_tag(0))?;
    crate::types::EncryptionKey::decode(key_der)
}

/// Build the `PA-ENC-TIMESTAMP` padata from an already-encrypted timestamp.
pub fn pa_enc_timestamp(enc: &EncryptedData) -> PaData {
    PaData {
        padata_type: PA_ENC_TIMESTAMP,
        padata_value: enc.encode(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kerberos_time_epoch_and_known() {
        assert_eq!(unix_to_kerberos_time(0), "19700101000000Z");
        // 2024-01-02 03:04:05 UTC = 1704164645.
        assert_eq!(unix_to_kerberos_time(1_704_164_645), "20240102030405Z");
    }

    #[test]
    fn pa_enc_ts_enc_roundtrips_through_crypto() {
        // Encode a PA-ENC-TS-ENC, encrypt it, decrypt, and confirm the DER matches.
        let plain = encode_pa_enc_ts_enc("20240102030405Z", 123456);
        let key = [0x11u8; 32];
        let enc = crate::crypto::encrypt_message(&key, KU_AS_REQ_PA_ENC_TS, &[0x22u8; 16], &plain);
        let dec = crate::crypto::decrypt_message(&key, KU_AS_REQ_PA_ENC_TS, &enc).unwrap();
        assert_eq!(dec, plain);
    }

    #[test]
    fn as_req_has_krbtgt_sname() {
        let der = build_as_req(
            "EXAMPLE.COM",
            &client_cname("alice"),
            42,
            "20370913024805Z",
            &[18, 17],
            vec![],
        );
        // Re-decode via the message layer and check the target is krbtgt/EXAMPLE.COM.
        let req = KdcReq::decode(&der).unwrap();
        assert_eq!(req.req_body.sname.unwrap(), krbtgt_sname("EXAMPLE.COM"));
        assert_eq!(req.req_body.etypes, vec![18, 17]);
    }
}
