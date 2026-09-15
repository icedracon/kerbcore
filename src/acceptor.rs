//! Server-side AP-REQ acceptor scaffold — the half kerbcore was missing.
//!
//! For the client role, [`crate::client`] builds AP-REQ, decrypts AP-REP, and
//! runs the AS/TGS exchange. The acceptor side — parse an inbound AP-REQ,
//! decrypt the authenticator, validate timestamps, defend against replay — is
//! what libgssapi's `gss_accept_sec_context` does behind an FFI wall. This
//! module ships the primitives so a Rust acceptor (an HTTP service, an SMB
//! server, a custom protocol) can do it without libclang / libkrb5.
//!
//! ## What ships in 0.3
//!
//! - [`parse_ap_req`] — total decoder for `[APPLICATION 14] AP-REQ` → [`ApReq`]
//!   (ticket + encrypted authenticator + AP options).
//! - [`Authenticator`] + [`parse_authenticator`] — decode the decrypted
//!   `[APPLICATION 2]` plaintext into a plain struct.
//! - [`ReplayCache`] trait — storage-agnostic anti-replay for
//!   `(client-principal, ctime, cusec)` triples. Two impls: an in-memory
//!   [`HashSetReplayCache`] (RFC 4120 §3.2.3-compliant when the caller
//!   expires entries at `authenticator.ctime + skew`), and a
//!   [`NoopReplayCache`] for the "I don't care about replay in this deployment"
//!   case (documented, not the default).
//! - [`verify_ap_req`] — pin them all together: decrypt the authenticator with
//!   a caller-supplied session key, check the ctime against `now ± skew`,
//!   record the replay ID, return an [`AuthContext`] the acceptor can use to
//!   pull the negotiated subkey / seq_number / client principal.
//!
//! ## What's deferred to 1.0
//!
//! - **Ticket decrypt** — extracting the session key from
//!   `ticket.enc_part.cipher` needs an `EncTicketPart` parser (currently the
//!   ticket-plaintext parser isn't public). Callers who have the session key
//!   from a keytab-decrypted ticket (or, in a test harness, from a prior AS/TGS
//!   round-trip) can already use `verify_ap_req` today.
//! - **AP-REP builder** — the caller can echo the authenticator's
//!   ctime/cusec back through [`crate::client::parse_enc_ap_rep_part`]-shaped
//!   encoding by hand for now; a `build_ap_rep` is 1.0-scope.
//! - **PAC extraction** — sits inside the ticket plaintext, unblocked by the
//!   same EncTicketPart work.

use crate::client::KU_AP_REQ_AUTH;
use crate::der::{
    application_tag, context_tag, one_or, read_u32, Der, DerError, TAG_BIT_STRING, TAG_SEQUENCE,
};
use crate::keys::{KerberosKey, KeyError};
use crate::messages::Ticket;
use crate::types::{Checksum, EncryptedData, EncryptionKey, KerberosTime, PrincipalName};
use std::collections::HashMap;

// ── AP-REQ ───────────────────────────────────────────────────────────────────

/// Parsed AP-REQ — the acceptor-facing view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApReq {
    /// Always 5.
    pub pvno: i32,
    /// Always 14.
    pub msg_type: i32,
    /// 32-bit `APOptions` flags (`AP_OPTS_MUTUAL_REQUIRED`, `AP_OPTS_USE_SESSION_KEY`).
    pub ap_options: u32,
    /// The service ticket.
    pub ticket: Ticket,
    /// Encrypted `Authenticator`.
    pub enc_auth: EncryptedData,
}

/// Total decoder for `[APPLICATION 14] AP-REQ` — malformed input errors, never
/// panics. Structural check only; the authenticator is not decrypted here (the
/// acceptor needs the session key first — see [`verify_ap_req`]).
pub fn parse_ap_req(der: &[u8]) -> Result<ApReq, DerError> {
    let mut r = Der::new(der);
    let (tag, inner) = r.read_tlv()?;
    if tag != application_tag(14) {
        return Err(DerError::TagMismatch {
            expected: application_tag(14),
            found: tag,
        });
    }
    let seq = one_or(inner, TAG_SEQUENCE)?;
    let mut sr = Der::new(seq);
    let pvno = read_i32(sr.expect(context_tag(0))?)?;
    let msg_type = read_i32(sr.expect(context_tag(1))?)?;
    if pvno != 5 || msg_type != 14 {
        return Err(DerError::MsgTypeMismatch);
    }
    // ap-options [2] BIT STRING — one unused-bits octet, then 4 flag octets big-endian.
    let opt_bytes = one_or(sr.expect(context_tag(2))?, TAG_BIT_STRING)?;
    if opt_bytes.len() < 5 {
        return Err(DerError::Truncated);
    }
    let ap_options = u32::from_be_bytes([opt_bytes[1], opt_bytes[2], opt_bytes[3], opt_bytes[4]]);
    let ticket = Ticket::decode(sr.expect(context_tag(3))?)?;
    let enc_auth = EncryptedData::decode(sr.expect(context_tag(4))?)?;
    Ok(ApReq {
        pvno,
        msg_type,
        ap_options,
        ticket,
        enc_auth,
    })
}

// ── Authenticator ────────────────────────────────────────────────────────────

/// `Authenticator ::= [APPLICATION 2] SEQUENCE { authenticator-vno [0] INTEGER,
/// crealm [1] Realm, cname [2] PrincipalName, cksum [3] Checksum OPTIONAL,
/// cusec [4] INTEGER, ctime [5] KerberosTime, subkey [6] EncryptionKey OPTIONAL,
/// seq-number [7] UInt32 OPTIONAL, authorization-data [8] ... OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authenticator {
    /// Always 5.
    pub authenticator_vno: i32,
    /// Client realm.
    pub crealm: String,
    /// Client principal name.
    pub cname: PrincipalName,
    /// Optional application checksum (RFC 4121 GSS uses this heavily).
    pub cksum: Option<Checksum>,
    /// Client microseconds within `ctime`.
    pub cusec: i32,
    /// Client time (Kerberos-format).
    pub ctime: String,
    /// Optional session-subkey the client negotiates for per-message tokens.
    pub subkey: Option<EncryptionKey>,
    /// Optional starting sequence number the client picks.
    pub seq_number: Option<u32>,
}

/// Parse a decrypted `[APPLICATION 2] Authenticator`. Total: malformed input
/// errors. Authorization-data ([8]) is currently skipped without surfacing —
/// unblock-later when the PAC-in-authenticator flow lands (S4U2Self chains
/// carry them).
pub fn parse_authenticator(plaintext: &[u8]) -> Result<Authenticator, DerError> {
    let mut r = Der::new(plaintext);
    let (tag, inner) = r.read_tlv()?;
    if tag != application_tag(2) {
        return Err(DerError::TagMismatch {
            expected: application_tag(2),
            found: tag,
        });
    }
    let seq = one_or(inner, TAG_SEQUENCE)?;
    let mut sr = Der::new(seq);
    let authenticator_vno = read_i32(sr.expect(context_tag(0))?)?;
    if authenticator_vno != 5 {
        return Err(DerError::BadProtocolVersion);
    }
    let crealm = crate::types::decode_realm(sr.expect(context_tag(1))?)?;
    let cname = PrincipalName::decode(sr.expect(context_tag(2))?)?;
    let cksum = if sr.peek_tag() == Some(context_tag(3)) {
        Some(Checksum::decode(sr.expect(context_tag(3))?)?)
    } else {
        None
    };
    let cusec = read_i32(sr.expect(context_tag(4))?)?;
    let ctime = KerberosTime::decode(sr.expect(context_tag(5))?)?.0;
    let subkey = if sr.peek_tag() == Some(context_tag(6)) {
        Some(EncryptionKey::decode(sr.expect(context_tag(6))?)?)
    } else {
        None
    };
    let seq_number = if sr.peek_tag() == Some(context_tag(7)) {
        Some(read_u32(sr.expect(context_tag(7))?)?)
    } else {
        None
    };
    Ok(Authenticator {
        authenticator_vno,
        crealm,
        cname,
        cksum,
        cusec,
        ctime,
        subkey,
        seq_number,
    })
}

// ── Replay cache ────────────────────────────────────────────────────────────

/// Anti-replay storage. An acceptor must reject an `AP-REQ` whose
/// `(client-principal, ctime, cusec)` was seen before within the allowed clock
/// skew — RFC 4120 §3.2.3. The concrete storage (in-memory, Redis, SQLite,
/// distributed cache) is caller-owned; this trait is the boundary.
pub trait ReplayCache {
    /// Try to record `id` with `expires_at` as its watermark. Returns
    /// [`Replay`] when `id` is already present. Implementations SHOULD
    /// garbage-collect entries whose `expires_at` is in the past.
    fn remember(&mut self, id: [u8; 32], expires_at: u64) -> Result<(), Replay>;
}

/// Marker returned when an ID is already in the replay cache — the AP-REQ
/// MUST be rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Replay;

/// In-memory replay cache backed by a `HashMap`. Sufficient for a single-process
/// acceptor; NOT sufficient for a horizontally-scaled service where two
/// instances could each accept the same AP-REQ. For that, plug your own
/// [`ReplayCache`] on top of shared storage.
#[derive(Debug, Default)]
pub struct HashSetReplayCache {
    seen: HashMap<[u8; 32], u64>,
}

impl HashSetReplayCache {
    /// Fresh empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sweep entries whose `expires_at` is at or before `now_secs`. Call
    /// periodically from the acceptor's housekeeping loop.
    pub fn expire(&mut self, now_secs: u64) {
        self.seen.retain(|_, exp| *exp > now_secs);
    }

    /// How many entries the cache currently holds (post-expiry, if you called
    /// `expire` first).
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// True when the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl ReplayCache for HashSetReplayCache {
    fn remember(&mut self, id: [u8; 32], expires_at: u64) -> Result<(), Replay> {
        if self.seen.contains_key(&id) {
            return Err(Replay);
        }
        self.seen.insert(id, expires_at);
        Ok(())
    }
}

/// Reject-nothing cache — every `remember` returns `Ok(())`. Use ONLY when the
/// deployment can accept replay (e.g. an idempotent, single-request read
/// endpoint). Named explicitly so `ReplayCache: NoopReplayCache` in the
/// acceptor's config reads as the operator's on-the-record choice.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopReplayCache;

impl ReplayCache for NoopReplayCache {
    fn remember(&mut self, _id: [u8; 32], _expires_at: u64) -> Result<(), Replay> {
        Ok(())
    }
}

// ── verify_ap_req ───────────────────────────────────────────────────────────

/// Outcome of a successful [`verify_ap_req`]. The acceptor uses this to bind
/// the incoming request to the authenticated identity and to pick up any
/// subkey the client negotiated for per-message tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    /// The decrypted authenticator (ctime, cusec, cksum, subkey, seq_number).
    pub authenticator: Authenticator,
    /// The client realm from the authenticator.
    pub client_realm: String,
    /// The client principal from the authenticator.
    pub client_principal: PrincipalName,
    /// Convenience: same as `authenticator.subkey` — pull if you want the
    /// service-side session key for [`crate::gss`] per-message tokens.
    pub subkey: Option<EncryptionKey>,
    /// Convenience: same as `authenticator.seq_number` — starting seq number.
    pub sequence_number: Option<u32>,
}

/// Errors from [`verify_ap_req`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptorError {
    /// The authenticator ciphertext did not decrypt cleanly under the supplied
    /// session key (integrity check failed OR the wrong key was used).
    Decrypt(&'static str),
    /// The decrypted plaintext did not parse as `Authenticator`.
    BadAuthenticator(DerError),
    /// `ctime` was outside `now ± clock_skew_seconds`. Prevents a stale
    /// authenticator from being replayed after the skew window.
    ClockSkewExceeded {
        /// Client time (Kerberos generalized-time).
        ctime: String,
        /// Server-provided `now` in Unix seconds.
        now_secs: u64,
        /// The configured skew window.
        allowed_skew_seconds: u64,
    },
    /// Malformed `ctime` — not a Kerberos generalized-time (`YYYYMMDDHHMMSSZ`).
    BadClientTime(String),
    /// The `(cname, ctime, cusec)` triple was seen before within the skew
    /// window — replay rejected.
    Replay,
}

impl std::fmt::Display for AcceptorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptorError::Decrypt(s) => write!(f, "authenticator decrypt failed: {s}"),
            AcceptorError::BadAuthenticator(e) => write!(f, "authenticator parse: {e:?}"),
            AcceptorError::ClockSkewExceeded {
                ctime,
                now_secs,
                allowed_skew_seconds,
            } => write!(
                f,
                "authenticator ctime {ctime} outside {allowed_skew_seconds}s of now={now_secs}"
            ),
            AcceptorError::BadClientTime(s) => write!(f, "malformed ctime: {s}"),
            AcceptorError::Replay => write!(f, "AP-REQ replay rejected"),
        }
    }
}

impl std::error::Error for AcceptorError {}

impl From<KeyError> for AcceptorError {
    fn from(_: KeyError) -> Self {
        AcceptorError::Decrypt("KeyError from KerberosKey::decrypt")
    }
}

/// Verify an inbound AP-REQ and gate it against clock skew + replay.
///
/// **Preconditions**: the caller has already extracted `session_key` from the
/// ticket (typical shape: decrypt `ap_req.ticket.enc_part.cipher` with the
/// service's long-term key at key-usage 2, parse `EncTicketPart`, pull `.key`).
/// The full ticket-plaintext parser lands in 1.0; today the shape works for
/// callers who plug the session key in from a keytab or an out-of-band path
/// (tests, fixtures).
///
/// **Postconditions on `Ok`**: the authenticator decrypted cleanly, its
/// `ctime` was within `clock_skew_seconds` of `now_secs`, and the
/// `(cname, ctime, cusec)` replay ID was inserted into `replay_cache` with
/// expiry `now_secs + clock_skew_seconds`. Return value carries the
/// authenticator + convenience aliases for the negotiated subkey / seq_number.
pub fn verify_ap_req<C: ReplayCache>(
    ap_req: &ApReq,
    session_key: &KerberosKey,
    clock_skew_seconds: u64,
    now_secs: u64,
    replay_cache: &mut C,
) -> Result<AuthContext, AcceptorError> {
    // 1) Decrypt the authenticator under the session key at usage 11.
    let plaintext = session_key
        .decrypt(KU_AP_REQ_AUTH, &ap_req.enc_auth.cipher)
        .map_err(AcceptorError::from)?;

    // 2) Parse.
    let authenticator =
        parse_authenticator(&plaintext).map_err(AcceptorError::BadAuthenticator)?;

    // 3) Clock-skew check.
    let ctime_secs = parse_kerberos_time(&authenticator.ctime)
        .ok_or_else(|| AcceptorError::BadClientTime(authenticator.ctime.clone()))?;
    let skew = clock_skew_seconds as i64;
    let delta = ctime_secs as i64 - now_secs as i64;
    if delta.abs() > skew {
        return Err(AcceptorError::ClockSkewExceeded {
            ctime: authenticator.ctime.clone(),
            now_secs,
            allowed_skew_seconds: clock_skew_seconds,
        });
    }

    // 4) Replay check — hash (cname bytes || ctime || cusec).
    let id = replay_id(&authenticator);
    replay_cache
        .remember(id, now_secs.saturating_add(clock_skew_seconds))
        .map_err(|_| AcceptorError::Replay)?;

    Ok(AuthContext {
        subkey: authenticator.subkey.clone(),
        sequence_number: authenticator.seq_number,
        client_realm: authenticator.crealm.clone(),
        client_principal: authenticator.cname.clone(),
        authenticator,
    })
}

/// SHA-256 hash of `(cname bytes || ctime bytes || cusec bytes)` — the replay ID.
fn replay_id(a: &Authenticator) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    // A stable-ish serialization: name components joined by 0x1f (unit
    // separator, ASCII), then ctime, then cusec.
    for comp in &a.cname.name_string {
        h.update(comp.as_bytes());
        h.update([0x1f]);
    }
    h.update(a.crealm.as_bytes());
    h.update([0x1e]); // record separator
    h.update(a.ctime.as_bytes());
    h.update([0x1e]);
    h.update((a.cusec as i64).to_be_bytes());
    h.finalize().into()
}

/// Kerberos `GeneralizedTime` (`YYYYMMDDHHMMSSZ`) → Unix seconds. `None` for
/// any parse failure — the caller surfaces a `BadClientTime` in that case.
/// Kerberos always uses UTC, so no timezone offset handling.
fn parse_kerberos_time(s: &str) -> Option<u64> {
    if s.len() != 15 || !s.ends_with('Z') {
        return None;
    }
    let n = |a: usize, b: usize| s[a..b].parse::<u32>().ok();
    let y = n(0, 4)? as i64;
    let mo = n(4, 6)? as i64;
    let d = n(6, 8)? as i64;
    let h = n(8, 10)? as i64;
    let mi = n(10, 12)? as i64;
    let se = n(12, 14)? as i64;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    // Days-from-civil (Howard Hinnant), UTC epoch anchor.
    let y2 = y - i64::from(mo <= 2);
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let doy = (153 * (mo + if mo > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + h * 3600 + mi * 60 + se;
    if secs < 0 {
        None
    } else {
        Some(secs as u64)
    }
}

/// Read a KRB Int32 as `i32` from a bare-DER integer element.
fn read_i32(der: &[u8]) -> Result<i32, DerError> {
    let mut r = Der::new(der);
    let n = r.read_integer()?;
    r.finish()?;
    i32::try_from(n).map_err(|_| DerError::IntTooLarge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{build_ap_req_with_confounder, AP_OPTS_MUTUAL_REQUIRED};
    use crate::keys::Enctype;
    use crate::messages::Ticket;

    fn ticket_stub() -> Ticket {
        Ticket {
            tkt_vno: 5,
            realm: "CORP.LOCAL".into(),
            sname: PrincipalName {
                name_type: 2,
                name_string: vec!["HTTP".into(), "web.corp.local".into()],
            },
            enc_part: EncryptedData {
                etype: 18,
                kvno: None,
                cipher: vec![0u8; 32], // opaque placeholder — never decrypted in these tests
            },
        }
    }

    fn make_ap_req(session_key: &KerberosKey, ctime: &str, cusec: i32) -> Vec<u8> {
        build_ap_req_with_confounder(
            &ticket_stub(),
            session_key,
            "CORP.LOCAL",
            &PrincipalName {
                name_type: 1,
                name_string: vec!["alice".into()],
            },
            ctime,
            cusec,
            AP_OPTS_MUTUAL_REQUIRED,
            None,
            None,
            None,
            &[0u8; 16], // deterministic confounder for tests
        )
    }

    fn key() -> KerberosKey {
        KerberosKey::new(Enctype::Aes256CtsHmacSha1_96, vec![0x42u8; 32]).unwrap()
    }

    #[test]
    fn ap_req_round_trips_through_parse() {
        let k = key();
        let der = make_ap_req(&k, "20260101120000Z", 0);
        let parsed = parse_ap_req(&der).unwrap();
        assert_eq!(parsed.pvno, 5);
        assert_eq!(parsed.msg_type, 14);
        assert_eq!(parsed.ap_options, AP_OPTS_MUTUAL_REQUIRED);
        assert_eq!(parsed.ticket.sname.name_string[0], "HTTP");
    }

    #[test]
    fn verify_ap_req_happy_path() {
        let k = key();
        // 2026-01-01 12:00:00 UTC = 1_767_268_800 unix
        let now: u64 = 1_767_268_800;
        let der = make_ap_req(&k, "20260101120000Z", 0);
        let ap = parse_ap_req(&der).unwrap();
        let mut cache = HashSetReplayCache::new();
        let ctx = verify_ap_req(&ap, &k, 300, now, &mut cache).unwrap();
        assert_eq!(ctx.client_realm, "CORP.LOCAL");
        assert_eq!(ctx.client_principal.name_string[0], "alice");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn verify_ap_req_rejects_wrong_key() {
        let k = key();
        let now: u64 = 1_767_268_800;
        let der = make_ap_req(&k, "20260101120000Z", 0);
        let ap = parse_ap_req(&der).unwrap();
        let wrong = KerberosKey::new(Enctype::Aes256CtsHmacSha1_96, vec![0xffu8; 32]).unwrap();
        let mut cache = HashSetReplayCache::new();
        let err = verify_ap_req(&ap, &wrong, 300, now, &mut cache).unwrap_err();
        assert!(matches!(err, AcceptorError::Decrypt(_)));
    }

    #[test]
    fn verify_ap_req_rejects_replay() {
        let k = key();
        let now: u64 = 1_767_268_800;
        let der = make_ap_req(&k, "20260101120000Z", 0);
        let ap = parse_ap_req(&der).unwrap();
        let mut cache = HashSetReplayCache::new();
        verify_ap_req(&ap, &k, 300, now, &mut cache).unwrap();
        let err = verify_ap_req(&ap, &k, 300, now, &mut cache).unwrap_err();
        assert_eq!(err, AcceptorError::Replay);
    }

    #[test]
    fn verify_ap_req_rejects_stale_ctime() {
        let k = key();
        // ctime is at 2026-01-01 12:00:00; check with now = 1 hour later, skew = 60s.
        let now: u64 = 1_767_268_800 + 3600;
        let der = make_ap_req(&k, "20260101120000Z", 0);
        let ap = parse_ap_req(&der).unwrap();
        let mut cache = HashSetReplayCache::new();
        let err = verify_ap_req(&ap, &k, 60, now, &mut cache).unwrap_err();
        assert!(matches!(err, AcceptorError::ClockSkewExceeded { .. }));
    }

    #[test]
    fn noop_replay_cache_accepts_everything() {
        let mut c = NoopReplayCache;
        assert!(c.remember([0u8; 32], 0).is_ok());
        assert!(c.remember([0u8; 32], 0).is_ok());
        assert!(c.remember([0u8; 32], 0).is_ok());
    }

    #[test]
    fn hash_set_replay_cache_expires() {
        let mut c = HashSetReplayCache::new();
        c.remember([1u8; 32], 100).unwrap();
        c.remember([2u8; 32], 200).unwrap();
        assert_eq!(c.len(), 2);
        c.expire(150);
        assert_eq!(c.len(), 1);
        c.expire(999);
        assert!(c.is_empty());
    }

    #[test]
    fn parse_kerberos_time_epoch_and_2026() {
        assert_eq!(parse_kerberos_time("19700101000000Z"), Some(0));
        // 2026-01-01T12:00:00Z = 1_767_268_800
        assert_eq!(parse_kerberos_time("20260101120000Z"), Some(1_767_268_800));
    }

    #[test]
    fn parse_kerberos_time_rejects_bogus() {
        assert!(parse_kerberos_time("20260132120000Z").is_none()); // day 32
        assert!(parse_kerberos_time("20260101120000").is_none()); // no Z
        assert!(parse_kerberos_time("XXXX0101120000Z").is_none()); // non-digit
    }
}
