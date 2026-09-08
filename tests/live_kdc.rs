//! Live AS-exchange validation against a real Windows KDC.
//!
//! Skipped unless the environment supplies a target and credentials — so `cargo
//! test` in CI is a no-op and NO secrets ever live in the source tree:
//!
//! ```text
//! KERBCORE_LIVE_KDC=<host[:port]> KERBCORE_LIVE_REALM=<REALM> \
//! KERBCORE_LIVE_USER=<user> KERBCORE_LIVE_PASS=<pass> \
//!   cargo test --test live_kdc -- --nocapture
//! ```
//!
//! Stage 1 sends a no-pre-auth AS-REQ and parses the real KRB-ERROR
//! (`KDC_ERR_PREAUTH_REQUIRED`) + its ETYPE-INFO2 salt — proving the KDC accepts
//! kerbcore's DER and that kerbcore decodes real KDC bytes. Stage 2 sends the
//! PA-ENC-TIMESTAMP pre-auth, parses the AS-REP, and decrypts its enc-part —
//! proving the whole crypto + string-to-key + codec stack end-to-end.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kerbcore::client::{
    build_as_req, build_tgs_req, client_cname, enc_kdc_rep_part_session_key, encode_pa_enc_ts_enc,
    krbtgt_sname, pa_enc_timestamp, parse_etype_info2, unix_to_kerberos_time, KU_AS_REP_ENC_PART,
    KU_AS_REQ_PA_ENC_TS, KU_TGS_REP_ENC_PART, PA_ETYPE_INFO2,
};
use kerbcore::crypto::{decrypt_message, encrypt_message, string_to_key};
use kerbcore::messages::{KdcRep, KrbError};
use kerbcore::types::{EncryptedData, PaData};

const AES256: i32 = 18;

/// Kerberos-over-TCP: 4-byte big-endian length prefix + message; same framing back.
fn kdc_exchange(target: &str, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(target).expect("connect KDC");
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    let mut framed = (request.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(request);
    stream.write_all(&framed).expect("send AS-REQ");
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).expect("read length prefix");
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; len];
    stream.read_exact(&mut resp).expect("read response body");
    resp
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Parse a KRB-ERROR's e-data (`METHOD-DATA ::= SEQUENCE OF PA-DATA`) and return the
/// ETYPE-INFO2 salt for AES-256, if the KDC offered one.
fn salt_for_aes256(e_data: &[u8]) -> Option<String> {
    let mut r = kerbcore::der::Der::new(e_data);
    let seq = r.expect(kerbcore::der::TAG_SEQUENCE).ok()?;
    let mut sr = kerbcore::der::Der::new(seq);
    while !sr.is_empty() {
        let (_, item) = sr.read_tlv().ok()?;
        let pd = PaData::decode(&kerbcore::der::tlv(kerbcore::der::TAG_SEQUENCE, item)).ok()?;
        if pd.padata_type == PA_ETYPE_INFO2 {
            for e in parse_etype_info2(&pd.padata_value).ok()? {
                if e.etype == AES256 {
                    return e.salt;
                }
            }
        }
    }
    None
}

#[test]
fn live_as_exchange() {
    let (kdc, realm, user, pass) = match (
        std::env::var("KERBCORE_LIVE_KDC"),
        std::env::var("KERBCORE_LIVE_REALM"),
        std::env::var("KERBCORE_LIVE_USER"),
        std::env::var("KERBCORE_LIVE_PASS"),
    ) {
        (Ok(k), Ok(r), Ok(u), Ok(p)) => (k, r, u, p),
        _ => {
            eprintln!("live_kdc: skipped (set KERBCORE_LIVE_KDC / _REALM / _USER / _PASS to run)");
            return;
        }
    };
    let target = if kdc.contains(':') {
        kdc.clone()
    } else {
        format!("{kdc}:88")
    };
    let cname = client_cname(&user);
    let till = unix_to_kerberos_time(now_secs() + 6 * 3600);

    // ── Stage 1: no-pre-auth AS-REQ → expect KRB-ERROR(25) + salt ────────
    let req1 = build_as_req(
        &realm,
        &cname,
        0x1111_2222,
        &till,
        &[AES256, 17, 23],
        vec![],
    );
    let resp1 = kdc_exchange(&target, &req1);
    let err = KrbError::decode(&resp1).unwrap_or_else(|e| {
        panic!(
            "stage 1: expected KRB-ERROR, got {e:?} ({} bytes)",
            resp1.len()
        )
    });
    eprintln!(
        "stage 1 OK — KDC returned KRB-ERROR code {} (sname {:?}) from realm {}",
        err.error_code, err.sname.name_string, err.realm
    );
    assert_eq!(err.error_code, 25, "expected KDC_ERR_PREAUTH_REQUIRED");
    let salt = err
        .e_data
        .as_deref()
        .and_then(salt_for_aes256)
        .unwrap_or_else(|| format!("{}{}", realm, user)); // RFC 3961 default salt
    eprintln!("stage 1 OK — AES-256 salt from ETYPE-INFO2: {salt:?}");

    // ── Stage 2: PA-ENC-TIMESTAMP AS-REQ → AS-REP → decrypt enc-part ─────
    let key = string_to_key(32, pass.as_bytes(), salt.as_bytes(), 4096);
    let ts = encode_pa_enc_ts_enc(&unix_to_kerberos_time(now_secs()), 0);
    let conf: [u8; 16] = std::array::from_fn(|i| (now_secs() as u8).wrapping_add(i as u8));
    let ts_cipher = encrypt_message(&key, KU_AS_REQ_PA_ENC_TS, &conf, &ts);
    let enc = EncryptedData {
        etype: AES256,
        kvno: None,
        cipher: ts_cipher,
    };
    let req2 = build_as_req(
        &realm,
        &cname,
        0x3333_4444,
        &till,
        &[AES256],
        vec![pa_enc_timestamp(&enc)],
    );
    let resp2 = kdc_exchange(&target, &req2);

    if let Ok(e) = KrbError::decode(&resp2) {
        panic!(
            "stage 2: KDC rejected pre-auth with KRB-ERROR code {} (salt/iter/clock?)",
            e.error_code
        );
    }
    let rep = KdcRep::decode(&resp2).expect("stage 2: expected AS-REP");
    eprintln!(
        "stage 2 OK — AS-REP for {:?}, ticket for {:?} (enc etype {})",
        rep.cname.name_string, rep.ticket.sname.name_string, rep.ticket.enc_part.etype
    );
    assert_eq!(rep.msg_type, 11);

    // Decrypt the AS-REP enc-part with the client key at usage 3 → EncASRepPart.
    let plain = decrypt_message(&key, KU_AS_REP_ENC_PART, &rep.enc_part.cipher)
        .expect("stage 2: decrypt AS-REP enc-part (wrong key?)");
    let session_key = enc_kdc_rep_part_session_key(&plain).expect("parse EncASRepPart session key");
    eprintln!(
        "stage 2 OK — decrypted EncASRepPart; session key etype {} ({} bytes). FULL AS EXCHANGE VALIDATED.",
        session_key.keytype,
        session_key.keyvalue.len()
    );
    assert_eq!(session_key.keytype, AES256);
    assert_eq!(session_key.keyvalue.len(), 32);

    // ── Stage 3: TGS-REQ (AP-REQ w/ the TGT) → TGS-REP → service session key ─
    let tgt_key =
        kerbcore::KerberosKey::from_i32(session_key.keytype, session_key.keyvalue.clone())
            .expect("TGT session key etype supported");
    let tgs = build_tgs_req(
        &realm,
        &krbtgt_sname(&realm), // ask for a ticket to the TGS itself (always valid)
        &rep.ticket,
        &tgt_key,
        &realm,
        &cname,
        0x5555_6666,
        &till,
        &[AES256],
        &unix_to_kerberos_time(now_secs()),
        0,
    )
    .expect("build TGS-REQ");
    let resp3 = kdc_exchange(&target, &tgs);
    if let Ok(e) = KrbError::decode(&resp3) {
        panic!(
            "stage 3: TGS-REQ rejected with KRB-ERROR code {}",
            e.error_code
        );
    }
    let tgs_rep = KdcRep::decode(&resp3).expect("stage 3: expected TGS-REP");
    assert_eq!(tgs_rep.msg_type, 13);
    // Decrypt the TGS-REP enc-part with the TGT session key at usage 8.
    let tgs_plain = decrypt_message(
        &session_key.keyvalue,
        KU_TGS_REP_ENC_PART,
        &tgs_rep.enc_part.cipher,
    )
    .expect("stage 3: decrypt TGS-REP enc-part");
    let svc_key =
        enc_kdc_rep_part_session_key(&tgs_plain).expect("parse EncTGSRepPart session key");
    eprintln!(
        "stage 3 OK — TGS-REP; service ticket for {:?}, service session key etype {} ({} bytes). FULL AS+TGS EXCHANGE VALIDATED.",
        tgs_rep.ticket.sname.name_string, svc_key.keytype, svc_key.keyvalue.len()
    );
    assert_eq!(svc_key.keyvalue.len(), 32);
}
