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

/// `Authenticator ::= [APPLICATION 2] SEQUENCE { … }`. `subkey`/`seq_number` are optional
/// (a TGS-REQ omits both; an application/GSS AP-REQ usually supplies them).
fn encode_authenticator(
    crealm: &str,
    cname: &PrincipalName,
    cusec: i32,
    ctime: &str,
    cksum: Option<&Checksum>,
    subkey: Option<&crate::types::EncryptionKey>,
    seq_number: Option<u32>,
) -> Vec<u8> {
    let mut body = explicit(0, &encode_integer(5)); // authenticator-vno
    body.extend_from_slice(&explicit(1, &encode_realm(crealm)));
    body.extend_from_slice(&explicit(2, &cname.encode()));
    if let Some(c) = cksum {
        body.extend_from_slice(&explicit(3, &c.encode()));
    }
    body.extend_from_slice(&explicit(4, &encode_integer(cusec as i64)));
    body.extend_from_slice(&explicit(5, &KerberosTime(ctime.to_string()).encode()));
    if let Some(sk) = subkey {
        body.extend_from_slice(&explicit(6, &sk.encode()));
    }
    if let Some(n) = seq_number {
        body.extend_from_slice(&explicit(7, &encode_integer(n as i64)));
    }
    tlv(application_tag(2), &encode_sequence(&body))
}

/// `AP-REQ ::= [APPLICATION 14] SEQUENCE { pvno [0], msg-type [1], ap-options [2],
/// ticket [3] Ticket, authenticator [4] EncryptedData }`. `ap_options` is the 32-bit
/// `APOptions` flags value (e.g. [`AP_OPTS_MUTUAL_REQUIRED`]).
fn encode_ap_req(ticket_der: &[u8], enc_auth: &EncryptedData, ap_options: u32) -> Vec<u8> {
    // KerberosFlags: BIT STRING, unused-bits octet (0) + 4 flag octets, big-endian.
    let mut opt = vec![0u8];
    opt.extend_from_slice(&ap_options.to_be_bytes());
    let ap_options = tlv(TAG_BIT_STRING, &opt);
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

/// Default TGS-REQ `KDCOptions`: forwardable (bit 1) + renewable (bit 8) + **canonicalize**
/// (bit 15). Canonicalize is on by default, so a TGS-REQ for a service in another realm gets
/// a referral TGT out of the box (RFC 6806) — chase it with [`referral_realm`].
const DEFAULT_TGS_KDC_OPTIONS: u32 = 0x4081_0000;
/// `KDCOptions` CANONICALIZE (bit 15) — canonicalize the principal and issue realm
/// **referrals** (RFC 6806). Included in [`DEFAULT_TGS_KDC_OPTIONS`]; exposed so a caller can
/// set/clear it explicitly via [`build_tgs_req_with_options`].
pub const KDC_OPT_CANONICALIZE: u32 = 0x0001_0000;
/// `KDCOptions` RENEWABLE-OK (bit 27) — accept a renewable ticket if the requested lifetime
/// can't be met.
pub const KDC_OPT_RENEWABLE_OK: u32 = 0x0000_0010;
/// `KDCOptions` RENEW (bit 30) — this TGS-REQ renews the presented (renewable) ticket rather
/// than requesting a new one (RFC 4120 §3.3, credential lifecycle).
pub const KDC_OPT_RENEW: u32 = 0x0000_0002;
/// `KDCOptions` VALIDATE (bit 31) — validate a postdated ticket that has reached its start
/// time (RFC 4120 §3.3).
pub const KDC_OPT_VALIDATE: u32 = 0x0000_0001;

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
    build_tgs_req_with_options(
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
        DEFAULT_TGS_KDC_OPTIONS,
        confounder,
    )
}

/// Deterministic-confounder TGS-REQ with an explicit `kdc_options` value — the etype-generic
/// core of [`build_tgs_req`]. Use this to set/clear specific `KDCOptions` bits (e.g. to add
/// FORWARDED for delegation, or clear [`KDC_OPT_CANONICALIZE`]); [`DEFAULT_TGS_KDC_OPTIONS`]
/// reproduces [`build_tgs_req`].
#[allow(clippy::too_many_arguments)]
pub fn build_tgs_req_with_options(
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
    kdc_options: u32,
    confounder: &[u8],
) -> Result<Vec<u8>, crate::keys::KeyError> {
    let enctype = tgt_session_key.enctype();
    let cksumtype = enctype
        .authenticator_cksumtype()
        .ok_or(crate::keys::KeyError::UnsupportedEnctype(enctype.to_i32()))?;
    // TGS-REQ omits cname in the body (identity comes from the ticket).
    let body = KdcReqBody {
        kdc_options,
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
    let auth = encode_authenticator(crealm, cname, cusec, ctime, Some(&cksum), None, None);
    let enc_auth = EncryptedData {
        etype: enctype.to_i32(),
        kvno: None,
        cipher: tgt_session_key.encrypt_with_confounder(KU_TGS_REQ_AUTH, confounder, &auth),
    };
    let ap_req = encode_ap_req(&tgt.encode(), &enc_auth, 0);
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

/// Cross-realm **referral** detection (RFC 6806). Given the `sname` from a decrypted
/// `EncKDCRepPart` ([`parse_enc_kdc_rep_part`]) and the service you actually requested,
/// return `Some(next_realm)` when the KDC handed back a referral TGT (`krbtgt/<REALM>`)
/// instead of the service ticket — i.e. the reply is a `krbtgt` for a realm that is *not*
/// the one you asked a real (non-krbtgt) service in. Return `None` when the reply is the
/// service ticket (chase complete) or a same-realm TGT.
///
/// Realm comparison is ASCII-case-insensitive (Kerberos realms are case-sensitive in the
/// RFC but AD treats them case-insensitively; callers targeting strict realms can compare
/// the returned value themselves).
pub fn referral_realm(
    rep_sname: &PrincipalName,
    requested_sname: &PrincipalName,
) -> Option<String> {
    // The reply must be a TGT: name-string == ["krbtgt", <REALM>].
    let next = match rep_sname.name_string.as_slice() {
        [svc, realm] if svc.eq_ignore_ascii_case("krbtgt") => realm.clone(),
        _ => return None,
    };
    // If we *asked* for that same krbtgt (a normal TGS-for-TGT), it is not a referral.
    if let [svc, realm] = requested_sname.name_string.as_slice() {
        if svc.eq_ignore_ascii_case("krbtgt") && realm.eq_ignore_ascii_case(&next) {
            return None;
        }
    }
    Some(next)
}

/// Error from a cross-realm referral chase ([`chase_referrals`]).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChaseError<E> {
    /// The KDC referred back to a realm already visited — a trust cycle. Carries the realm.
    LoopDetected(String),
    /// The chase exceeded `max_hops` without reaching the service ticket.
    MaxHopsExceeded(usize),
    /// The caller's per-hop TGS fetch failed.
    Fetch(E),
}

/// Drive a cross-realm TGS **referral chase** (RFC 6806) to completion. Starting in
/// `start_realm`, repeatedly invoke `fetch(realm)` — which performs ONE TGS exchange for
/// `target` using the current-realm TGT and returns the decrypted [`EncKdcRepPart`] — and follow
/// `krbtgt/<next>` referrals until the reply's `sname` is the service you asked for. kerbcore owns
/// the loop, referral detection ([`referral_realm`]), a visited-set **loop guard**, and a
/// `max_hops` bound; the caller owns the socket + its own TGT-per-realm handling inside `fetch`.
///
/// Returns the ordered realm path traversed (`[start, …, service-realm]`) on success.
pub fn chase_referrals<F, E>(
    target: &PrincipalName,
    start_realm: &str,
    max_hops: usize,
    mut fetch: F,
) -> Result<Vec<String>, ChaseError<E>>
where
    F: FnMut(&str) -> Result<EncKdcRepPart, E>,
{
    let mut path = vec![start_realm.to_string()];
    let mut visited = std::collections::HashSet::new();
    visited.insert(start_realm.to_ascii_uppercase());
    let mut current = start_realm.to_string();

    for _ in 0..max_hops {
        let rep = fetch(&current).map_err(ChaseError::Fetch)?;
        match referral_realm(&rep.sname, target) {
            // Referral TGT for another realm — hop, guarding against a trust cycle.
            Some(next) => {
                if !visited.insert(next.to_ascii_uppercase()) {
                    return Err(ChaseError::LoopDetected(next));
                }
                path.push(next.clone());
                current = next;
            }
            // The reply is the service ticket — chase complete.
            None => return Ok(path),
        }
    }
    Err(ChaseError::MaxHopsExceeded(max_hops))
}

/// Build a TGS-REQ that **renews** a renewable TGT (RFC 4120 §3.3 credential lifecycle): the
/// RENEW option is set, the service name is `krbtgt/<realm>`, and the ticket being renewed is
/// presented in the PA-TGS-REQ. `till` is the requested new end time (bounded by the ticket's
/// renew-till). Fresh CSPRNG confounder. Same etype rules as [`build_tgs_req`].
#[allow(clippy::too_many_arguments)]
pub fn build_tgs_renew(
    realm: &str,
    renewable_tgt: &Ticket,
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
    build_tgs_req_with_options(
        realm,
        &krbtgt_sname(realm),
        renewable_tgt,
        tgt_session_key,
        crealm,
        cname,
        nonce,
        till,
        etypes,
        ctime,
        cusec,
        KDC_OPT_RENEW | KDC_OPT_RENEWABLE_OK,
        &conf,
    )
}

// ── AP exchange (application authentication, RFC 4120 §5.5) ───────────────────

/// Key usage — AP-REQ authenticator checksum.
pub const KU_AP_REQ_AUTH_CKSUM: u32 = 10;
/// Key usage — AP-REQ authenticator (encrypted under the ticket session key or a subkey).
pub const KU_AP_REQ_AUTH: u32 = 11;
/// Key usage — AP-REP `EncAPRepPart` (encrypted under the ticket session key).
pub const KU_AP_REP_ENC_PART: u32 = 12;

/// `APOptions` MUTUAL-REQUIRED (bit 2) — the client asks the service to prove it can read
/// the ticket by returning an AP-REP (mutual authentication).
pub const AP_OPTS_MUTUAL_REQUIRED: u32 = 0x2000_0000;
/// `APOptions` USE-SESSION-KEY (bit 1) — the ticket is encrypted in the session key (user2user).
pub const AP_OPTS_USE_SESSION_KEY: u32 = 0x4000_0000;

/// Build a standalone **AP-REQ** ([APPLICATION 14]) to authenticate to a service, using a
/// service `ticket` (from a TGS exchange) and its `session_key`. Deterministic variant: the
/// caller supplies the authenticator-encryption `confounder`. `ap_options` is typically
/// [`AP_OPTS_MUTUAL_REQUIRED`] (or `0`); `cksum` carries an application checksum (e.g. the
/// RFC 4121 `0x8003` channel-binding checksum for GSS); `subkey`/`seq_number` negotiate a
/// per-message key and sequence base.
///
/// Etype-generic: the authenticator encryption + `EncryptedData.etype` come from
/// `session_key`'s [`crate::keys::Enctype`]. Returns the AP-REQ DER.
#[allow(clippy::too_many_arguments)]
pub fn build_ap_req_with_confounder(
    ticket: &Ticket,
    session_key: &crate::keys::KerberosKey,
    crealm: &str,
    cname: &PrincipalName,
    ctime: &str,
    cusec: i32,
    ap_options: u32,
    cksum: Option<&Checksum>,
    subkey: Option<&crate::types::EncryptionKey>,
    seq_number: Option<u32>,
    confounder: &[u8],
) -> Vec<u8> {
    let enctype = session_key.enctype();
    let auth = encode_authenticator(crealm, cname, cusec, ctime, cksum, subkey, seq_number);
    let enc_auth = EncryptedData {
        etype: enctype.to_i32(),
        kvno: None,
        cipher: session_key.encrypt_with_confounder(KU_AP_REQ_AUTH, confounder, &auth),
    };
    encode_ap_req(&ticket.encode(), &enc_auth, ap_options)
}

/// Fields of an `EncAPRepPart` ([APPLICATION 27], RFC 4120 §5.5.2). The client authenticates
/// the service by confirming `ctime`/`cusec` echo the AP-REQ authenticator ([`verify_ap_rep`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncApRepPart {
    /// Client time echoed from the AP-REQ authenticator.
    pub ctime: String,
    /// Client microseconds echoed from the AP-REQ authenticator.
    pub cusec: i32,
    /// Optional negotiated subkey (the service's choice for per-message tokens).
    pub subkey: Option<crate::types::EncryptionKey>,
    /// Optional starting sequence number chosen by the service.
    pub seq_number: Option<u32>,
}

/// Extract the encrypted part of an **AP-REP** ([APPLICATION 15], RFC 4120 §5.5.2). Decrypt the
/// returned [`EncryptedData`] under the ticket session key at usage [`KU_AP_REP_ENC_PART`],
/// then pass the plaintext to [`parse_enc_ap_rep_part`]. Total: malformed input errors.
pub fn parse_ap_rep(der: &[u8]) -> Result<EncryptedData, DerError> {
    let mut r = Der::new(der);
    let (tag, inner) = r.read_tlv()?;
    if tag != application_tag(15) {
        return Err(DerError::TagMismatch {
            expected: application_tag(15),
            found: tag,
        });
    }
    let seq = one_or(inner, TAG_SEQUENCE)?;
    let mut sr = Der::new(seq);
    let pvno = crate::der::read_u32(sr.expect(context_tag(0))?)?;
    let msg_type = crate::der::read_u32(sr.expect(context_tag(1))?)?;
    if pvno != 5 || msg_type != 15 {
        return Err(DerError::MsgTypeMismatch);
    }
    EncryptedData::decode(sr.expect(context_tag(2))?)
}

/// Parse a decrypted `EncAPRepPart` ([APPLICATION 27]). Total: malformed input errors.
pub fn parse_enc_ap_rep_part(plaintext: &[u8]) -> Result<EncApRepPart, DerError> {
    let mut r = Der::new(plaintext);
    let (tag, inner) = r.read_tlv()?;
    if tag != application_tag(27) {
        return Err(DerError::TagMismatch {
            expected: application_tag(27),
            found: tag,
        });
    }
    let seq = one_or(inner, TAG_SEQUENCE)?;
    let mut sr = Der::new(seq);
    let ctime = KerberosTime::decode(sr.expect(context_tag(0))?)?.0;
    let cusec = {
        let mut ir = Der::new(sr.expect(context_tag(1))?);
        i32::try_from(ir.read_integer()?).map_err(|_| DerError::IntTooLarge)?
    };
    let subkey = if sr.peek_tag() == Some(context_tag(2)) {
        Some(crate::types::EncryptionKey::decode(
            sr.expect(context_tag(2))?,
        )?)
    } else {
        None
    };
    let seq_number = if sr.peek_tag() == Some(context_tag(3)) {
        Some(crate::der::read_u32(sr.expect(context_tag(3))?)?)
    } else {
        None
    };
    Ok(EncApRepPart {
        ctime,
        cusec,
        subkey,
        seq_number,
    })
}

/// Mutual-authentication check: parse a decrypted `EncAPRepPart` and confirm it echoes the
/// `ctime`/`cusec` from our AP-REQ authenticator. A mismatch ([`DerError::MsgTypeMismatch`])
/// means the peer could not read the ticket — reject the context.
pub fn verify_ap_rep(
    plaintext: &[u8],
    expected_ctime: &str,
    expected_cusec: i32,
) -> Result<EncApRepPart, DerError> {
    let part = parse_enc_ap_rep_part(plaintext)?;
    if part.ctime != expected_ctime || part.cusec != expected_cusec {
        return Err(DerError::MsgTypeMismatch);
    }
    Ok(part)
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
    fn referral_realm_detection() {
        let krbtgt = |realm: &str| PrincipalName {
            name_type: 2,
            name_string: vec!["krbtgt".into(), realm.into()],
        };
        let svc = PrincipalName {
            name_type: 2,
            name_string: vec!["cifs".into(), "fs.b.example.com".into()],
        };
        // Asked for a service in realm B, got a referral TGT for realm B => chase to B.
        assert_eq!(
            referral_realm(&krbtgt("B.EXAMPLE.COM"), &svc).as_deref(),
            Some("B.EXAMPLE.COM")
        );
        // Reply IS the service ticket => done, no referral.
        assert_eq!(referral_realm(&svc, &svc), None);
        // Normal TGS-for-TGT (asked for krbtgt/B, got krbtgt/B) => not a referral.
        assert_eq!(
            referral_realm(&krbtgt("B.EXAMPLE.COM"), &krbtgt("B.EXAMPLE.COM")),
            None
        );
        // Case-insensitive realm match on the "same krbtgt" guard.
        assert_eq!(
            referral_realm(&krbtgt("b.example.com"), &krbtgt("B.EXAMPLE.COM")),
            None
        );
    }

    fn rep_with_sname(sname: PrincipalName, srealm: &str) -> EncKdcRepPart {
        EncKdcRepPart {
            key: crate::types::EncryptionKey {
                keytype: 18,
                keyvalue: vec![0u8; 32],
            },
            nonce: 1,
            endtime: "20260101000000Z".into(),
            srealm: srealm.into(),
            sname,
        }
    }
    fn krbtgt_rep(realm: &str) -> EncKdcRepPart {
        rep_with_sname(
            PrincipalName {
                name_type: 2,
                name_string: vec!["krbtgt".into(), realm.into()],
            },
            realm,
        )
    }

    #[test]
    fn chase_follows_referral_chain_to_service() {
        // A → B → C, service ticket issued in C.
        let svc = PrincipalName {
            name_type: 2,
            name_string: vec!["cifs".into(), "fs.c.example.com".into()],
        };
        let hops = [
            krbtgt_rep("B.EXAMPLE.COM"),                  // fetch(A) → referral to B
            krbtgt_rep("C.EXAMPLE.COM"),                  // fetch(B) → referral to C
            rep_with_sname(svc.clone(), "C.EXAMPLE.COM"), // fetch(C) → the service ticket
        ];
        let mut i = 0;
        let path = chase_referrals::<_, ()>(&svc, "A.EXAMPLE.COM", 10, |_realm| {
            let r = hops[i].clone();
            i += 1;
            Ok(r)
        })
        .unwrap();
        assert_eq!(path, ["A.EXAMPLE.COM", "B.EXAMPLE.COM", "C.EXAMPLE.COM"]);
        assert_eq!(i, 3, "exactly three TGS exchanges");
    }

    #[test]
    fn chase_detects_trust_loop() {
        let svc = PrincipalName {
            name_type: 2,
            name_string: vec!["cifs".into(), "x".into()],
        };
        // A → B → A (referral cycle).
        let hops = [krbtgt_rep("B.EXAMPLE.COM"), krbtgt_rep("A.EXAMPLE.COM")];
        let mut i = 0;
        let err = chase_referrals::<_, ()>(&svc, "A.EXAMPLE.COM", 10, |_r| {
            let r = hops[i].clone();
            i += 1;
            Ok(r)
        })
        .unwrap_err();
        assert_eq!(err, ChaseError::LoopDetected("A.EXAMPLE.COM".into()));
    }

    #[test]
    fn chase_bounds_hops_and_propagates_fetch_error() {
        let svc = PrincipalName {
            name_type: 2,
            name_string: vec!["cifs".into(), "x".into()],
        };
        // Endless fresh referrals → MaxHopsExceeded at the bound.
        let mut n = 0;
        let err = chase_referrals::<_, ()>(&svc, "R0", 2, |_r| {
            n += 1;
            Ok(krbtgt_rep(&format!("R{n}")))
        })
        .unwrap_err();
        assert_eq!(err, ChaseError::MaxHopsExceeded(2));
        // Fetch error is surfaced verbatim.
        let err2 = chase_referrals::<_, &str>(&svc, "R0", 5, |_r| Err("network down")).unwrap_err();
        assert_eq!(err2, ChaseError::Fetch("network down"));
    }

    #[test]
    fn default_tgs_req_sets_canonicalize_and_options_can_clear_it() {
        // Sanity: the default options constant carries CANONICALIZE (referrals out of the box).
        assert_eq!(
            DEFAULT_TGS_KDC_OPTIONS & KDC_OPT_CANONICALIZE,
            KDC_OPT_CANONICALIZE
        );
        let conf = [0u8; 16];
        let default = build_tgs_req_with_confounder(
            "EXAMPLE.COM",
            &svc_sname(),
            &sample_tgt(),
            &sample_sk(),
            "EXAMPLE.COM",
            &client_cname("alice"),
            1,
            "20370913024805Z",
            &[18],
            "20240102030405Z",
            0,
            &conf,
        )
        .unwrap();
        // Explicitly clearing CANONICALIZE via _with_options must change the encoded body.
        let no_canon = build_tgs_req_with_options(
            "EXAMPLE.COM",
            &svc_sname(),
            &sample_tgt(),
            &sample_sk(),
            "EXAMPLE.COM",
            &client_cname("alice"),
            1,
            "20370913024805Z",
            &[18],
            "20240102030405Z",
            0,
            DEFAULT_TGS_KDC_OPTIONS & !KDC_OPT_CANONICALIZE,
            &conf,
        )
        .unwrap();
        assert_ne!(default, no_canon);
    }

    #[test]
    fn tgs_renew_sets_renew_option_and_targets_krbtgt() {
        // RENEW bit is 0x0000_0002; renew request must carry it and differ from a normal req.
        assert_eq!(KDC_OPT_RENEW, 0x0000_0002);
        let renew = build_tgs_renew(
            "EXAMPLE.COM",
            &sample_tgt(),
            &sample_sk(),
            "EXAMPLE.COM",
            &client_cname("alice"),
            5,
            "20370913024805Z",
            &[18],
            "20240102030405Z",
            0,
        )
        .unwrap();
        // The kdc-options BIT STRING for RENEW|RENEWABLE-OK = 00 00 00 00 12 (unused-bits + flags).
        let needle = [0x00u8, 0x00, 0x00, 0x00, 0x12];
        assert!(
            renew.windows(5).any(|w| w == needle),
            "renew TGS-REQ should carry RENEW|RENEWABLE-OK flags"
        );
    }

    #[test]
    fn ap_req_build_then_ap_rep_mutual_auth_round_trip() {
        let sk = sample_sk(); // aes256 session key
        let ctime = "20260908120000Z";
        let cusec = 424242;
        // Client builds a mutual-auth AP-REQ.
        let ap_req = build_ap_req_with_confounder(
            &sample_tgt(),
            &sk,
            "EXAMPLE.COM",
            &client_cname("alice"),
            ctime,
            cusec,
            AP_OPTS_MUTUAL_REQUIRED,
            None,
            None,
            Some(1),
            &[0x55u8; 16],
        );
        assert!(!ap_req.is_empty());

        // Service side: craft the matching AP-REP echoing ctime/cusec, encrypted at usage 12.
        let enc_part = tlv(
            application_tag(27),
            &encode_sequence(
                &[
                    explicit(0, &KerberosTime(ctime.into()).encode()),
                    explicit(1, &encode_integer(cusec as i64)),
                ]
                .concat(),
            ),
        );
        let ed = EncryptedData {
            etype: sk.enctype().to_i32(),
            kvno: None,
            cipher: sk.encrypt(KU_AP_REP_ENC_PART, &enc_part),
        };
        let ap_rep = tlv(
            application_tag(15),
            &encode_sequence(
                &[
                    explicit(0, &encode_integer(5)),
                    explicit(1, &encode_integer(15)),
                    explicit(2, &ed.encode()),
                ]
                .concat(),
            ),
        );

        // Client verifies mutual auth end-to-end.
        let got = parse_ap_rep(&ap_rep).unwrap();
        let plain = sk.decrypt(KU_AP_REP_ENC_PART, &got.cipher).unwrap();
        let part = verify_ap_rep(&plain, ctime, cusec).unwrap();
        assert_eq!(part.ctime, ctime);
        assert_eq!(part.cusec, cusec);
        // A wrong ctime is rejected (a service that could not read the ticket).
        assert!(matches!(
            verify_ap_rep(&plain, "20000101000000Z", cusec),
            Err(DerError::MsgTypeMismatch)
        ));
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
