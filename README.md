# kerbcore

Pure-Rust Kerberos building blocks — **no FFI, no dependency on a host krb5**.

> **Spike status (1.5.1).** Local, unpublished (`publish = false`). This first cut
> ships only the RFC 3961 / RFC 3962 crypto for the `aes256-cts-hmac-sha1-96`
> profile (etype 18). The ASN.1 message codec and an AS/TGS client land next (1.6),
> at which point `kerbcore` replaces `picky-krb` inside ADhammer's Kerberos stack.
> Ship-target version when frozen: `0.1.0-beta.1`.

## What it does today

RFC 3961 / RFC 3962 primitives for the AES profile every modern AD KDC negotiates:

- `nfold` — RFC 3961 §5.2 n-fold
- `aes_cts_encrypt` / `aes_cts_decrypt` — RFC 3962 §5 AES CBC-CTS (CS3)
- `dr` / `dk` — RFC 3961 §5.1 DR/DK derivation (AES-256)
- `hmac_sha1_96` — RFC 2104 HMAC-SHA1 truncated to 96 bits
- `derive_kc` / `derive_ke` / `derive_ki` — RFC 3961 §5.3 subkey derivation
- `encrypt_message` / `decrypt_message` — the generic encrypt-then-MAC primitive
  that KILE `EncryptedData` and GSS-API wrap-tokens compose out of

## Conformance

Known-answer tested, not just round-tripped:

- `nfold("012345", 64) == 0xbe072631276b1955` (RFC 3961 §5.2 worked example)
- HMAC-SHA1 against RFC 2202 test case 1
- DR/DK determinism + AES `random_to_key = identity`
- AES-CTS round-trips across the edge lengths (1 / 15 / 16 / 17 / 32 / 47 / 48 B)
- encrypt-then-MAC round-trip + tamper / wrong-usage / truncation rejection

`cargo test` → 18 passing.

## Dependencies

`aes`, `hmac`, `sha1` (RustCrypto). No FFI, no system krb5, `#![forbid(unsafe_code)]`.

## Scope

The offensive compositions (golden/silver/diamond tickets, S4U abuse, unPAC,
PKINIT-relay) intentionally do **not** live here — they stay in the ADhammer CLI.
`kerbcore` is the dual-use core: the wire crypto and (soon) the ASN.1 codec + a
plain AS/TGS client that a defender, DFIR engineer, or interop author would want.

## Provenance

The crypto here is lifted verbatim from ADhammer's KAT-verified sealer
(`crates/kerberos/src/rpc_seal.rs` at git tag `v1.4.7`, cut from `main` in 1.4.8).
Rationale: `docs/PLAN_KRB_CRATE.md` in the ADhammer repo.

## License

MIT.
