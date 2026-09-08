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
    /// `s2kparams` (RFC 4120 §5.2.7.5) — cryptosystem-specific string-to-key parameters.
    /// For the AES profiles (RFC 3962 §4 / RFC 8009 §4) this is a 4-octet big-endian PBKDF2
    /// iteration count; absent means the profile default (4096 for RFC 3962). See
    /// [`Self::s2k_iterations`].
    pub s2kparams: Option<Vec<u8>>,
}

impl EtypeInfo2Entry {
    /// The PBKDF2 iteration count the KDC asks for, decoded from `s2kparams` for the AES
    /// profiles: a 4-octet big-endian count, where `0x0000_0000` means 2^32 (RFC 3962 §4).
    /// `None` when `s2kparams` is absent (use the profile default) or not 4 octets.
    pub fn s2k_iterations(&self) -> Option<u32> {
        match self.s2kparams.as_deref() {
            Some([a, b, c, d]) => {
                let n = u32::from_be_bytes([*a, *b, *c, *d]);
                // 0 denotes 2^32; callers cap this. Report u32::MAX as the closest value so a
                // hostile huge count can be clamped rather than looping 4 billion times.
                Some(if n == 0 { u32::MAX } else { n })
            }
            _ => None,
        }
    }
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
        let s2kparams = if er.peek_tag() == Some(context_tag(2)) {
            let c = er.expect(context_tag(2))?;
            Some(one_or(c, crate::der::TAG_OCTET_STRING)?.to_vec())
        } else {
            None
        };
        out.push(EtypeInfo2Entry {
            etype,
            salt,
            s2kparams,
        });
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

/// The fields of an `EncKDCRepPart` (RFC 4120 §5.4.2) kerbcore surfaces — enough to bind the
/// reply to the request (`nonce`) and know what was issued (`srealm`/`sname`/`endtime`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncKdcRepPart {
    /// The session key.
    pub key: crate::types::EncryptionKey,
    /// The nonce echoed from the request — MUST equal the request nonce (anti-replay).
    pub nonce: u32,
    /// Ticket expiry.
    pub endtime: String,
    /// Service realm the ticket is for.
    pub srealm: String,
    /// Service principal the ticket is for.
    pub sname: PrincipalName,
}

fn skip_opt(r: &mut Der<'_>, n: u8) -> Result<(), DerError> {
    if r.peek_tag() == Some(context_tag(n)) {
        r.expect(context_tag(n))?;
    }
    Ok(())
}

/// Parse an `EncKDCRepPart` ([APP 25] `EncASRepPart` / [APP 26] `EncTGSRepPart`), returning
/// the session key **and the echoed nonce** so the caller can reject a replayed/mismatched
/// reply ([`verify_kdc_rep`]). Total: malformed input errors, never panics.
pub fn parse_enc_kdc_rep_part(plaintext: &[u8]) -> Result<EncKdcRepPart, DerError> {
    let mut r = Der::new(plaintext);
    let (tag, inner) = r.read_tlv()?;
    if tag != application_tag(25) && tag != application_tag(26) {
        return Err(DerError::TagMismatch {
            expected: application_tag(25),
            found: tag,
        });
    }
    let seq = one_or(inner, TAG_SEQUENCE)?;
    let mut sr = Der::new(seq);
    let key = crate::types::EncryptionKey::decode(sr.expect(context_tag(0))?)?;
    let _last_req = sr.expect(context_tag(1))?; // [1] last-req (required) — not surfaced
    let nonce = crate::der::read_u32(sr.expect(context_tag(2))?)?;
    skip_opt(&mut sr, 3)?; // key-expiration OPTIONAL
    let _flags = sr.expect(context_tag(4))?; // [4] flags
    let _authtime = sr.expect(context_tag(5))?; // [5] authtime
    skip_opt(&mut sr, 6)?; // starttime OPTIONAL
    let endtime = KerberosTime::decode(sr.expect(context_tag(7))?)?.0;
    skip_opt(&mut sr, 8)?; // renew-till OPTIONAL
    let srealm = crate::types::decode_realm(sr.expect(context_tag(9))?)?;
    let sname = PrincipalName::decode(sr.expect(context_tag(10))?)?;
    Ok(EncKdcRepPart {
        key,
        nonce,
        endtime,
        srealm,
        sname,
    })
}

/// Anti-replay check: confirm a decrypted `EncKDCRepPart` echoes the nonce we sent. Returns
/// the parsed part on success, or [`DerError::MsgTypeMismatch`] when the nonce differs (a
/// replayed or substituted reply).
pub fn verify_kdc_rep(plaintext: &[u8], expected_nonce: u32) -> Result<EncKdcRepPart, DerError> {
    let part = parse_enc_kdc_rep_part(plaintext)?;
    if part.nonce != expected_nonce {
        return Err(DerError::MsgTypeMismatch);
    }
    Ok(part)
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

/// Build a TGS-REQ for `sname`, authenticated by `tgt` + the TGT session key (from the AS
/// exchange). **Etype-generic:** the authenticator's checksum type, the encryption, and the
/// `EncryptedData.etype` are all taken from the session key's [`crate::keys::Enctype`] — no
/// hardcoded AES256. The authenticator's checksum covers the KDC-REQ-BODY (usage 6); the
/// authenticator is encrypted under the session key (usage 7) with a **fresh CSPRNG confounder**.
///
/// Returns [`crate::keys::KeyError::UnsupportedEnctype`] for an RFC 8009 (etype 19/20) session
/// key — its authenticator cksumtype is not yet emitted here (AD does not issue RFC 8009 TGT
/// session keys by default). For deterministic output use [`build_tgs_req_with_confounder`].
#[allow(clippy::too_many_arguments)]
pub fn build_tgs_req(
    realm: &str,
    sname: &PrincipalName,
    tgt: &Ticket,
    tgt_session_key: &crate::keys::KerberosKey,
    crealm: &str,
    cname: &PrincipalName,
    nonce: u32,
    till: &str,
    etypes: &[i32],
    ctime: &str,
    cusec: i32,
) -> Result<Vec<u8>, crate::keys::KeyError> {
    let mut conf = vec![0u8; tgt_session_key.enctype().confounder_len()];
    getrandom::getrandom(&mut conf).expect("OS CSPRNG available for Kerberos confounder");
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
        &conf,
    )
}

/// Deterministic-confounder form of [`build_tgs_req`]. `confounder` must be the session key's
/// [`crate::keys::Enctype::confounder_len`] (16 for AES, 8 for RC4). **Production code uses
/// [`build_tgs_req`]** (CSPRNG confounder); a reused/predictable one weakens the authenticator.
#[allow(clippy::too_many_arguments)]
pub fn build_tgs_req_with_confounder(
    realm: &str,
    sname: &PrincipalName,
    tgt: &Ticket,
    tgt_session_key: &crate::keys::KerberosKey,
    crealm: &str,
    cname: &PrincipalName,
    nonce: u32,
    till: &str,
    etypes: &[i32],
    ctime: &str,
    cusec: i32,
    confounder: &[u8],
) -> Result<Vec<u8>, crate::keys::KeyError> {
    let enctype = tgt_session_key.enctype();
    let cksumtype = enctype
        .authenticator_cksumtype()
        .ok_or(crate::keys::KeyError::UnsupportedEnctype(enctype.to_i32()))?;
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
        cksumtype,
        checksum: tgt_session_key.checksum(KU_TGS_REQ_AUTH_CKSUM, &body_der),
    };
    let auth = encode_authenticator(crealm, cname, cusec, ctime, Some(&cksum));
    let enc_auth = EncryptedData {
        etype: enctype.to_i32(),
        kvno: None,
        cipher: tgt_session_key.encrypt_with_confounder(KU_TGS_REQ_AUTH, confounder, &auth),
    };
    let ap_req = encode_ap_req(&tgt.encode(), &enc_auth);
    let padata = vec![PaData {
        padata_type: PA_TGS_REQ,
        padata_value: ap_req,
    }];
    Ok(KdcReq {
        msg_type: 12,
        padata,
        req_body: body,
    }
    .encode())
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

    fn sample_sk() -> crate::keys::KerberosKey {
        crate::keys::KerberosKey::new(crate::keys::Enctype::Aes256CtsHmacSha1_96, vec![0x11u8; 32])
            .unwrap()
    }

    #[test]
    fn tgs_req_uses_fresh_random_confounder() {
        // Two TGS-REQs with byte-identical inputs must differ — the confounder is
        // drawn from the OS CSPRNG per call. (Regression guard against the old fixed
        // `0x5a ^ i` confounder.)
        let (tgt, sk, sname, cname) = (
            sample_tgt(),
            sample_sk(),
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
        )
        .unwrap();
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
        )
        .unwrap();
        assert_ne!(a, b, "TGS-REQ must use a fresh random confounder each call");
    }

    #[test]
    fn tgs_req_with_confounder_is_deterministic_and_etype_correct() {
        let (tgt, sk, sname, cname) = (
            sample_tgt(),
            sample_sk(),
            svc_sname(),
            client_cname("alice"),
        );
        let conf = [0x24u8; 16];
        let mk = || {
            build_tgs_req_with_confounder(
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
            )
            .unwrap()
        };
        let a = mk();
        assert_eq!(a, mk(), "same confounder + inputs must be byte-identical");
        assert_eq!(KdcReq::decode(&a).unwrap().msg_type, 12);
    }

    #[test]
    fn tgs_req_rejects_rfc8009_session_key() {
        // RFC 8009 (etype 19/20) session keys are not yet wired for the authenticator
        // cksumtype — must be a clean error, not a wrong/guessed constant.
        let sk = crate::keys::KerberosKey::new(
            crate::keys::Enctype::Aes256CtsHmacSha384_192,
            vec![0u8; 32],
        )
        .unwrap();
        let err = build_tgs_req(
            "EXAMPLE.COM",
            &svc_sname(),
            &sample_tgt(),
            &sk,
            "EXAMPLE.COM",
            &client_cname("alice"),
            1,
            "20370913024805Z",
            &[20],
            "20240102030405Z",
            0,
        )
        .unwrap_err();
        assert!(matches!(err, crate::keys::KeyError::UnsupportedEnctype(20)));
    }

    /// Build a minimal but structurally-valid `[APPLICATION 25] EncASRepPart` for the
    /// round-trip tests below.
    fn sample_enc_as_rep_part(nonce: u32) -> Vec<u8> {
        let key = crate::types::EncryptionKey {
            keytype: 18,
            keyvalue: vec![0x41u8; 32],
        }
        .encode();
        let sname = PrincipalName {
            name_type: 2,
            name_string: vec!["krbtgt".into(), "EXAMPLE.COM".into()],
        }
        .encode();
        let body = [
            explicit(0, &key),
            explicit(1, &encode_sequence(&[])), // last-req (contents irrelevant here)
            explicit(2, &encode_integer(nonce as i64)),
            explicit(4, &encode_integer(0)), // flags (discarded)
            explicit(5, &KerberosTime("20260908000000Z".into()).encode()), // authtime
            explicit(7, &KerberosTime("20260908100000Z".into()).encode()), // endtime
            explicit(9, &encode_realm("EXAMPLE.COM")),
            explicit(10, &sname),
        ]
        .concat();
        tlv(application_tag(25), &encode_sequence(&body))
    }

    #[test]
    fn enc_kdc_rep_part_extracts_nonce_and_sname() {
        let der = sample_enc_as_rep_part(0xDEAD_BEEF);
        let part = parse_enc_kdc_rep_part(&der).unwrap();
        assert_eq!(part.nonce, 0xDEAD_BEEF);
        assert_eq!(part.key.keytype, 18);
        assert_eq!(part.endtime, "20260908100000Z");
        assert_eq!(part.srealm, "EXAMPLE.COM");
        assert_eq!(part.sname.name_string, vec!["krbtgt", "EXAMPLE.COM"]);
    }

    #[test]
    fn verify_kdc_rep_matches_and_rejects_nonce() {
        let der = sample_enc_as_rep_part(4242);
        // Matching nonce: accepted.
        assert_eq!(verify_kdc_rep(&der, 4242).unwrap().nonce, 4242);
        // Mismatched nonce (a replayed/substituted reply): rejected, never panics.
        assert!(matches!(
            verify_kdc_rep(&der, 9999),
            Err(DerError::MsgTypeMismatch)
        ));
    }

    #[test]
    fn etype_info2_parses_salt_and_s2k_iterations() {
        use crate::der::{encode_general_string, encode_octet_string};
        let entry = |etype: i64, salt: &str, s2k: Option<&[u8]>| {
            let mut b = explicit(0, &encode_integer(etype));
            b.extend_from_slice(&explicit(1, &encode_general_string(salt)));
            if let Some(p) = s2k {
                b.extend_from_slice(&explicit(2, &encode_octet_string(p)));
            }
            encode_sequence(&b)
        };
        // Entry 0: AES256 with an explicit 0x0000_C000 (49152) iteration count.
        // Entry 1: no s2kparams (profile default).
        // Entry 2: s2kparams of 0x0000_0000 (denotes 2^32 -> reported as u32::MAX).
        let seq = [
            entry(18, "EXAMPLE.COMalice", Some(&[0x00, 0x00, 0xC0, 0x00])),
            entry(17, "EXAMPLE.COMalice", None),
            entry(18, "s", Some(&[0x00, 0x00, 0x00, 0x00])),
        ]
        .concat();
        let padata = encode_sequence(&seq);
        let entries = parse_etype_info2(&padata).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].etype, 18);
        assert_eq!(entries[0].salt.as_deref(), Some("EXAMPLE.COMalice"));
        assert_eq!(entries[0].s2k_iterations(), Some(49152));
        assert_eq!(entries[1].s2kparams, None);
        assert_eq!(entries[1].s2k_iterations(), None);
        assert_eq!(entries[2].s2k_iterations(), Some(u32::MAX));
    }

    #[test]
    fn enc_kdc_rep_part_rejects_wrong_app_tag() {
        // Wrap the same body under [APPLICATION 30] — not an EncKDCRepPart.
        let inner = {
            let der = sample_enc_as_rep_part(1);
            // strip the outer app-25 TLV, re-wrap under 30
            let mut r = Der::new(&der);
            let (_t, body) = r.read_tlv().unwrap();
            tlv(application_tag(30), body)
        };
        assert!(parse_enc_kdc_rep_part(&inner).is_err());
    }
}
