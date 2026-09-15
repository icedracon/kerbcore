//! `get_tgt.rs` — obtain a real Kerberos TGT from a live KDC, from scratch, in
//! ~90 lines of pure Rust.
//!
//! Compare with `libgssapi-sys`, where you'd link `libkrb5`, ship an
//! `/etc/krb5.conf`, set `KRB5_CONFIG`, and call `krb5_get_init_creds_password`
//! — a single-page C function that expands into the entire MIT stack behind an
//! FFI wall. Here the stack IS the code below: AS-REQ construction
//! (`kerbcore::client`), etype dispatch + string-to-key + PA-ENC-TIMESTAMP
//! encrypt + AS-REP decrypt (`kerbcore::keys::KerberosKey`), `KDC-REP` /
//! `KRB-ERROR` DER (`kerbcore::messages`). No `/etc/krb5.conf` required — the
//! caller supplies target + realm + user + password directly.
//!
//! Run with:
//! ```text
//! KDC=<host[:port]> REALM=<REALM> USER=<user> PASS=<pass> \
//!   cargo run --example get_tgt
//! ```
//!
//! The KDC connection is a plain TCP socket with the 4-byte length prefix
//! RFC 4120 §7.2.2 mandates. Nothing kerbcore-specific about the I/O — the
//! caller owns the socket.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kerbcore::client::{
    build_as_req, client_cname, encode_pa_enc_ts_enc, pa_enc_timestamp, parse_etype_info2,
    unix_to_kerberos_time, verify_kdc_rep, KU_AS_REP_ENC_PART, KU_AS_REQ_PA_ENC_TS,
    PA_ETYPE_INFO2,
};
use kerbcore::keys::{Enctype, KerberosKey};
use kerbcore::messages::{KdcRep, KrbError};
use kerbcore::types::{EncryptedData, PaData};

const AES256: i32 = 18;

fn main() {
    let kdc = env("KDC");
    let realm = env("REALM").to_uppercase();
    let user = env("USER");
    let pass = env("PASS");
    let nonce = rand_nonce();

    // ── Stage 1: no-pre-auth AS-REQ. Server 2019+ answers with
    //    `KDC_ERR_PREAUTH_REQUIRED` carrying ETYPE-INFO2 — the salt we need.
    let stage1 = build_as_req(
        &realm,
        &client_cname(&user),
        nonce,
        &far_future(),
        &[AES256],
        vec![],
    );
    let resp1 = kdc_exchange(&kdc, &stage1);
    let err = KrbError::decode(&resp1).expect("expected KRB-ERROR on stage 1");
    let salt = err
        .e_data
        .as_deref()
        .and_then(salt_for_aes256)
        .unwrap_or_else(|| format!("{realm}{user}"));

    // ── Derive the long-term AES-256 key with the typed dispatch (Enctype +
    //    Zeroize-on-drop). One call — no manual etype match.
    let key = KerberosKey::string_to_key(Enctype::Aes256CtsHmacSha1_96, &pass, salt.as_bytes(), 4096);

    // ── PA-ENC-TIMESTAMP encrypted with the long-term key at usage 1.
    let ts_der = encode_pa_enc_ts_enc(&unix_to_kerberos_time(now_secs()), 0);
    let ts_cipher = key.encrypt(KU_AS_REQ_PA_ENC_TS, &ts_der);
    let ts_pa = pa_enc_timestamp(&EncryptedData {
        etype: AES256,
        kvno: None,
        cipher: ts_cipher,
    });

    // ── Stage 2: AS-REQ with PA-ENC-TIMESTAMP → the KDC's AS-REP.
    let stage2 = build_as_req(
        &realm,
        &client_cname(&user),
        nonce,
        &far_future(),
        &[AES256],
        vec![ts_pa],
    );
    let resp2 = kdc_exchange(&kdc, &stage2);
    let rep = KdcRep::decode(&resp2).expect("AS-REP DER");
    let plaintext = key
        .decrypt(KU_AS_REP_ENC_PART, &rep.enc_part.cipher)
        .expect("AS-REP decrypt");
    let enc = verify_kdc_rep(&plaintext, nonce).expect("EncKdcRepPart / nonce OK");

    println!(
        "[+] TGT acquired for {user}@{realm}  end_time={}  session_key_len={}",
        enc.endtime,
        enc.key.keyvalue.len()
    );
    // A production caller would now serialize (rep.ticket, enc.key, cname) into an
    // MIT ccache and export `KRB5CCNAME`. The `ccache-io` crate does exactly that;
    // wire it in with `ccache-io = { version = "0.1", features = ["kerbcore"] }`.
}

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("set env var {k}"))
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn far_future() -> String {
    unix_to_kerberos_time(now_secs().saturating_add(10 * 3600))
}

fn rand_nonce() -> u32 {
    // Simple non-crypto nonce — fine for demo. Production: `getrandom::getrandom`.
    (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos()) | 1
}

fn kdc_exchange(target: &str, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(target).expect("connect KDC");
    stream.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let mut framed = (request.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(request);
    stream.write_all(&framed).unwrap();
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; len];
    stream.read_exact(&mut resp).unwrap();
    resp
}

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
