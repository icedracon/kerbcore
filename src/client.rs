//! AS-exchange client helpers — assemble an AS-REQ, build the PA-ENC-TIMESTAMP
//! pre-auth, and parse the pieces of the KDC's reply. Pure (no I/O): the caller
//! owns the socket. This is the glue that ties [`crate::crypto`] /
//! [`crate::rfc8009`] (keys) to [`crate::messages`] (wire) into a real Kerberos
//! AS handshake — the last layer before `kerbcore` can replace `picky-krb`.

use crate::der::{
    application_tag, context_tag, encode_integer, encode_sequence, explicit, one_or, tlv, Der,
    DerError, TAG_BIT_STRING, TAG_SEQUENCE,
};
use crate::messages::{KdcReq, KdcReqBody, Ticket};
use crate::types::{encode_realm, Checksum, EncryptedData, KerberosTime, PaData, PrincipalName};

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

// ── TGS exchange ────────────────────────────────────────────────────────────

/// Key usage — TGS-REQ authenticator checksum (over the KDC-REQ-BODY).
pub const KU_TGS_REQ_AUTH_CKSUM: u32 = 6;
/// Key usage — TGS-REQ authenticator encryption (under the TGT session key).
pub const KU_TGS_REQ_AUTH: u32 = 7;
/// Key usage — TGS-REP enc-part (under the TGT session key).
pub const KU_TGS_REP_ENC_PART: u32 = 8;
/// PA-DATA type for PA-TGS-REQ (an AP-REQ carried as pre-auth).
pub const PA_TGS_REQ: i32 = 1;
/// Checksum type hmac-sha1-96-aes256 (RFC 3962).
pub const CKSUM_HMAC_SHA1_96_AES256: i32 = 16;

/// `hmac-sha1-96-aes256` checksum: HMAC-SHA1-96 keyed by `Kc = DK(key, usage||0x99)`.
fn aes_checksum(key: &[u8], usage: u32, data: &[u8]) -> Vec<u8> {
    crate::crypto::hmac_sha1_96(&crate::crypto::derive_kc(key, usage), data).to_vec()
}

/// `Authenticator ::= [APPLICATION 2] SEQUENCE { … }` (the pieces a TGS-REQ needs).
fn encode_authenticator(
    crealm: &str,
    cname: &PrincipalName,
    cusec: i32,
    ctime: &str,
    cksum: Option<&Checksum>,
) -> Vec<u8> {
    let mut body = explicit(0, &encode_integer(5)); // authenticator-vno
    body.extend_from_slice(&explicit(1, &encode_realm(crealm)));
    body.extend_from_slice(&explicit(2, &cname.encode()));
    if let Some(c) = cksum {
        body.extend_from_slice(&explicit(3, &c.encode()));
    }
    body.extend_from_slice(&explicit(4, &encode_integer(cusec as i64)));
    body.extend_from_slice(&explicit(5, &KerberosTime(ctime.to_string()).encode()));
    tlv(application_tag(2), &encode_sequence(&body))
}

/// `AP-REQ ::= [APPLICATION 14] SEQUENCE { pvno [0], msg-type [1], ap-options [2],
/// ticket [3] Ticket, authenticator [4] EncryptedData }`.
fn encode_ap_req(ticket_der: &[u8], enc_auth: &EncryptedData) -> Vec<u8> {
    let ap_options = tlv(TAG_BIT_STRING, &[0x00, 0, 0, 0, 0]); // no options set
    let body = [
        explicit(0, &encode_integer(5)),
        explicit(1, &encode_integer(14)),
        explicit(2, &ap_options),
        explicit(3, ticket_der),
        explicit(4, &enc_auth.encode()),
    ]
    .concat();
    tlv(application_tag(14), &encode_sequence(&body))
}

/// Draw a fresh 16-byte Kerberos confounder from the OS CSPRNG. A confounder must be
/// unpredictable per RFC 8009 §3 / RFC 3961 §5.3 — a fixed one leaks plaintext structure
/// across sealed authenticators. Panics only if the OS RNG is unavailable (a broken host).
fn random_confounder() -> [u8; crate::crypto::CONFOUNDER_LEN] {
    let mut c = [0u8; crate::crypto::CONFOUNDER_LEN];
    getrandom::getrandom(&mut c).expect("OS CSPRNG available for Kerberos confounder");
    c
}

/// Build a TGS-REQ for `sname`, authenticated by `tgt` + `tgt_session_key` (from the
/// AS exchange). The authenticator's checksum covers the KDC-REQ-BODY (usage 6) and
/// the authenticator itself is encrypted under the TGT session key (usage 7), with a
/// **fresh random confounder** drawn from the OS CSPRNG.
///
/// LIMITATION (0.1.x): this targets the AES-SHA1 session-key profile — cksumtype 16,
/// etype 18, the profile every Active Directory KDC issues for the TGT session key.
/// RC4 / RFC 8009 TGT session keys need the typed-key enctype dispatch planned for
/// 0.2.0. For deterministic output (tests, differential vectors) use
/// [`build_tgs_req_with_confounder`].
#[allow(clippy::too_many_arguments)]
pub fn build_tgs_req(
    realm: &str,
    sname: &PrincipalName,
    tgt: &Ticket,
    tgt_session_key: &[u8],
    crealm: &str,
    cname: &PrincipalName,
    nonce: u32,
    till: &str,
    etypes: &[i32],
    ctime: &str,
    cusec: i32,
) -> Vec<u8> {
    build_tgs_req_with_confounder(
        realm,
        sname,
        tgt,
        tgt_session_key,
        crealm,
        cname,
        nonce,
        till,
        etypes,
        ctime,
        cusec,
        &random_confounder(),
    )
}

/// Deterministic-confounder form of [`build_tgs_req`]. Callers pass the 16-byte
/// authenticator confounder explicitly — for reproducible test/differential vectors,
/// or to hand the same value to a peer implementation. **Production code must use
/// [`build_tgs_req`]**, which draws the confounder from the OS CSPRNG; a reused or
/// predictable confounder weakens the sealed authenticator.
#[allow(clippy::too_many_arguments)]
pub fn build_tgs_req_with_confounder(
    realm: &str,
    sname: &PrincipalName,
    tgt: &Ticket,
    tgt_session_key: &[u8],
    crealm: &str,
    cname: &PrincipalName,
    nonce: u32,
    till: &str,
    etypes: &[i32],
    ctime: &str,
    cusec: i32,
    confounder: &[u8; crate::crypto::CONFOUNDER_LEN],
) -> Vec<u8> {
    // TGS-REQ omits cname in the body (identity comes from the ticket).
    let body = KdcReqBody {
        kdc_options: 0x4081_0000,
        cname: None,
        realm: realm.to_string(),
        sname: Some(sname.clone()),
        from: None,
        till: KerberosTime(till.to_string()),
        rtime: None,
        nonce,
        etypes: etypes.to_vec(),
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    let body_der = body.encode();
    let cksum = Checksum {
        cksumtype: CKSUM_HMAC_SHA1_96_AES256,
        checksum: aes_checksum(tgt_session_key, KU_TGS_REQ_AUTH_CKSUM, &body_der),
    };
    let auth = encode_authenticator(crealm, cname, cusec, ctime, Some(&cksum));
    let enc_auth = EncryptedData {
        etype: 18,
        kvno: None,
        cipher: crate::crypto::encrypt_message(tgt_session_key, KU_TGS_REQ_AUTH, confounder, &auth),
    };
    let ap_req = encode_ap_req(&tgt.encode(), &enc_auth);
    let padata = vec![PaData {
        padata_type: PA_TGS_REQ,
        padata_value: ap_req,
    }];
    KdcReq {
        msg_type: 12,
        padata,
        req_body: body,
    }
    .encode()
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

    fn sample_tgt() -> Ticket {
        Ticket {
            tkt_vno: 5,
            realm: "EXAMPLE.COM".into(),
            sname: krbtgt_sname("EXAMPLE.COM"),
            enc_part: crate::types::EncryptedData {
                etype: 18,
                kvno: Some(2),
                cipher: vec![0u8; 32],
            },
        }
    }

    fn svc_sname() -> PrincipalName {
        PrincipalName {
            name_type: NT_SRV_INST,
            name_string: vec!["host".into(), "dc.example.com".into()],
        }
    }

    #[test]
    fn tgs_req_uses_fresh_random_confounder() {
        // Two TGS-REQs with byte-identical inputs must differ — the confounder is
        // drawn from the OS CSPRNG per call. (Regression guard against the old fixed
        // `0x5a ^ i` confounder.)
        let (tgt, sk, sname, cname) = (
            sample_tgt(),
            [0x11u8; 32],
            svc_sname(),
            client_cname("alice"),
        );
        let a = build_tgs_req(
            "EXAMPLE.COM",
            &sname,
            &tgt,
            &sk,
            "EXAMPLE.COM",
            &cname,
            1,
            "20370913024805Z",
            &[18],
            "20240102030405Z",
            0,
        );
        let b = build_tgs_req(
            "EXAMPLE.COM",
            &sname,
            &tgt,
            &sk,
            "EXAMPLE.COM",
            &cname,
            1,
            "20370913024805Z",
            &[18],
            "20240102030405Z",
            0,
        );
        assert_ne!(a, b, "TGS-REQ must use a fresh random confounder each call");
    }

    #[test]
    fn tgs_req_with_confounder_is_deterministic() {
        let (tgt, sk, sname, cname) = (
            sample_tgt(),
            [0x11u8; 32],
            svc_sname(),
            client_cname("alice"),
        );
        let conf = [0x24u8; 16];
        let a = build_tgs_req_with_confounder(
            "EXAMPLE.COM",
            &sname,
            &tgt,
            &sk,
            "EXAMPLE.COM",
            &cname,
            1,
            "20370913024805Z",
            &[18],
            "20240102030405Z",
            0,
            &conf,
        );
        let b = build_tgs_req_with_confounder(
            "EXAMPLE.COM",
            &sname,
            &tgt,
            &sk,
            "EXAMPLE.COM",
            &cname,
            1,
            "20370913024805Z",
            &[18],
            "20240102030405Z",
            0,
            &conf,
        );
        assert_eq!(a, b, "same confounder + inputs must be byte-identical");
        // And the result is a well-formed TGS-REQ ([APPLICATION 12]).
        assert_eq!(KdcReq::decode(&a).unwrap().msg_type, 12);
    }
}
