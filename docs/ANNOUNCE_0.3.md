# kerbcore 0.3 — a full-stack Kerberos client (and now server acceptor) in pure Rust

*Draft — held for user approval before posting anywhere.*

---

Kerbcore 0.3 ships this week. It's a from-scratch Kerberos implementation in Rust
with **no FFI, no libclang, no runtime dep on MIT krb5 or Heimdal, and no `unsafe`
anywhere** (`#![forbid(unsafe_code)]` at the crate root). Eight external deps total:
`aes`, `hmac`, `sha1`, `sha2`, `md4`, `md-5`, `getrandom`, `zeroize`.

This is the release where kerbcore stops being "the crate that replaces picky-krb
inside one security tool" and starts being usable as the Kerberos foundation for
other Rust projects.

## What ships in 0.3

- **Full etype matrix**: 17 (AES128-SHA1-96), 18 (AES256-SHA1-96), 19 (AES128-SHA2-128,
  RFC 8009), 20 (AES256-SHA2-192, RFC 8009), 23 (RC4-HMAC). RFC 8009 (AES-SHA2) is
  implemented from scratch — few Rust libraries do it; on Windows it's added in
  Server 2025 / 11 24H2. All KAT-tested against the RFC 8009 §7 vectors.
- **Typed keys** with Zeroize-on-drop. `KerberosKey` dispatches encrypt / decrypt /
  checksum / string-to-key across the whole matrix from a single call site — no manual
  etype match, and a wrong-length key can't slip through into an AES primitive as a
  panic (previously a real bug source).
- **AS/TGS client** live-validated against Windows Server 2019, 2022, and 2025 KDCs.
  Each obtains a real TGT and service ticket, handling the three different salt schemes
  the servers return (the salt is parsed from the KDC's ETYPE-INFO2, never guessed).
- **AP exchange** — AP-REQ builder for clients, and now (0.3) `verify_ap_req` +
  `parse_authenticator` + a `ReplayCache` trait for acceptors. Two impls ship: an
  in-memory `HashSetReplayCache` (single-process acceptors) and a `NoopReplayCache`
  (documented, for idempotent single-request endpoints).
- **RFC 4121 GSS-API** — MIC / VerifyMIC / Wrap / Unwrap on top of any session key.
- **SPNEGO** — the negotiation pseudo-mechanism SMB/HTTP/LDAP use on Windows.
- **FAST** (RFC 6113) — armor-key math + wire codec; use for offline-dictionary
  hardening or PKINIT tunneling.
- **MS-KKDCP** — the HTTPS proxy container Windows uses to run Kerberos over the
  internet.
- **kpasswd / KRB-PRIV** — RFC 3244 change/set-password.
- **Cross-realm referrals** — RFC 6806 with loop detection and a hop cap.
- **`krb5.conf` loader** — new in 0.3. `Krb5Config::from_path("/etc/krb5.conf")` gets
  you `default_realm`, per-realm KDC lists, and DNS-suffix → realm mapping. Std-only,
  no external deps. The migration path for callers coming off libgssapi.
- **A total DER decoder** — every malformed byte returns a `DerError`, never a panic.
  Fuzz-clean at 6.4 billion iterations.

## Where kerbcore fits, honestly

The Rust Kerberos landscape has real choices already, and each is legitimately
better than kerbcore for a specific use case:

| You want... | Reach for | Why |
|---|---|---|
| Kerberos that just works everywhere your OS runs, production-mature | `libgssapi-sys` | Battle-tested MIT/Heimdal FFI, largest user base — the boring safe default |
| Windows-native SSPI parity from Rust | `sspi-rs` | Real SSPI reimplementation, substantial user base |
| Just KRB message codec, no client | `picky-krb` | Smallest surface, long history |
| Static binary, no libclang, no libkrb5, cross-compile to musl / Alpine / embedded | **kerbcore** | Zero FFI, zero system deps |
| Wire-level control (roast, forge, inspect PA-data, hand-crafted AS/TGS/S4U) | **kerbcore** | Types are yours; codec is total (no panic on hostile input) |
| An acceptor that can't afford the libkrb5 C audit surface | **kerbcore** | Pure Rust, `#![forbid(unsafe_code)]` |

kerbcore is the top of a specific niche — **pure-Rust Kerberos client + acceptor with
zero FFI** — not the biggest Rust Kerberos crate overall. Two consumers on crates.io
today (`adhammer` and `ccache-io 0.1.1`); more welcome.

## What kerbcore is not

- **Not audited by anyone external.** The crypto is KAT-tested against the RFCs and
  differentially against picky-krb (dev-dep only). That's not the same as a third-party
  security review — one is high on the 1.0 checklist.
- **Not a full acceptor yet.** 0.3 parses AP-REQ + verifies the authenticator + gates
  replay. It doesn't yet decrypt the ticket plaintext to extract the session key
  (an `EncTicketPart` parser lands in 1.0). Callers who have the session key from a
  keytab-decrypted ticket can use `verify_ap_req` today.
- **Not a drop-in for every libgssapi caller.** No AP-REP builder, no PAC extraction
  from tickets, no service-side keytab I/O (see the `keytab-io` sibling crate — a small
  additional dep). All on the 1.0 roadmap.
- **Pre-1.0.** 0.3 is the API-freeze candidate: every public enum that could grow is
  `#[non_exhaustive]`, and the top-level `KerbError` umbrella means callers who want
  one error type at their public API boundary have one. The plan: 60 days of external
  use, then 1.0.

## Runnable examples

Three real examples ship under `examples/`:

```sh
# offline — no KDC required, exercises RFC 4121 message protection
cargo run --example gss_wrap_unwrap

# online — env-configured, gets a real TGT from a live KDC in ~90 LOC
KDC=<host:88> REALM=CORP.LOCAL USER=alice PASS=... \
  cargo run --example get_tgt

# online — no-preauth account → hashcat -m 18200 line
KDC=<host:88> REALM=CORP.LOCAL USER=svcacc \
  cargo run --example asrep_roast
```

`get_tgt.rs` is the direct comparison to `libgssapi_sys::krb5_get_init_creds_password`.
Same job, ~90 lines of Rust vs a full C dep tree behind an FFI wall.

## Adopting it

```toml
[dependencies]
kerbcore = "0.3"
```

If you want the ccache-io bridge (round-trip an on-disk `krb5cc_*` file into
kerbcore's wire types with no manual field shuffling):

```toml
[dependencies]
ccache-io = { version = "0.1", features = ["kerbcore"] }
kerbcore = "0.3"
```

## Feedback wanted

Two things would move kerbcore toward 1.0 fast:

1. **Try `verify_ap_req` in a real Rust acceptor** and file an issue on what's missing
   (EncTicketPart, AP-REP builder, PAC extraction — all known gaps, prioritization
   helps).
2. **Try the `KerbError` umbrella at your public API boundary.** If a specific per-module
   error you need to distinguish is hidden inside a `KerbError::Der` variant when it
   should be its own top-level variant, that's the API-freeze feedback that matters.

Issues and PRs at `github.com/icedracon/kerbcore`. License: MIT.

---

*Draft only — not posted. See `git log` for the actual release commit train.*
