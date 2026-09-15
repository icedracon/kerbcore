//! MIT `krb5.conf` loader — the migration path for callers coming from libgssapi.
//!
//! Every libgssapi-based Rust app reads `/etc/krb5.conf` implicitly at library init.
//! kerbcore is deliberately I/O-free at the wire layer, but that leaves a callsite
//! gap: applications that want to consume an operator's existing `krb5.conf`
//! (default realm, per-realm KDC list, domain-realm mapping) instead of getting
//! those from CLI args have to hand-parse the file. This module does that parse
//! and returns a plain data struct — nothing kerbcore-specific about it.
//!
//! Std-only, no external deps. Written for the *client* subset of the file:
//! `[libdefaults] default_realm`, `[realms] REALM = { kdc = …, admin_server = … }`,
//! and `[domain_realm]` mapping. Unknown keys are ignored (permissive by design
//! — the file often carries MIT-specific settings kerbcore doesn't need).
//!
//! ## Grammar (subset)
//!
//! ```text
//! krb5conf   = section*
//! section    = "[" name "]" section-body
//! section-body = (subsection | assignment)*
//! subsection = key "=" "{" (assignment)* "}"
//! assignment = key "=" value
//! ```
//!
//! Whitespace and `#` comments are ignored. Values that appear more than once
//! under the same key (typical for `kdc =`) are collected into a Vec.
//!
//! ## Example
//!
//! ```
//! let conf = kerbcore::config::Krb5Config::parse(r#"
//! [libdefaults]
//!     default_realm = CORP.LOCAL
//!
//! [realms]
//!     CORP.LOCAL = {
//!         kdc = dc01.corp.local
//!         kdc = dc02.corp.local
//!         admin_server = dc01.corp.local
//!     }
//! "#).unwrap();
//!
//! assert_eq!(conf.default_realm(), Some("CORP.LOCAL"));
//! assert_eq!(conf.kdcs_for("CORP.LOCAL"), &["dc01.corp.local", "dc02.corp.local"]);
//! assert_eq!(conf.admin_server_for("CORP.LOCAL"), Some("dc01.corp.local"));
//! ```

use std::collections::HashMap;
use std::path::Path;

/// Parsed `krb5.conf` — enough to drive an [`crate::client`] AS/TGS exchange
/// from an operator-supplied file. Non-exhaustive: future minor versions may
/// surface additional fields (`libdefaults.ticket_lifetime`, capaths, …).
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Krb5Config {
    /// `[libdefaults] default_realm`, upcased. `None` when the file has no
    /// `libdefaults` section or no `default_realm` key.
    pub default_realm: Option<String>,
    /// `[realms] <REALM> = { kdc = ... }` — one entry per realm the file
    /// defines. Realm keys are upcased on ingest.
    pub realms: HashMap<String, RealmConfig>,
    /// `[domain_realm] .corp.local = CORP.LOCAL` — DNS-suffix → realm mapping.
    /// Suffixes are stored verbatim (retaining any leading `.`); values are
    /// upcased.
    pub domain_realm: HashMap<String, String>,
}

/// Per-realm section: `kdc` addresses (one or more) + optional `admin_server`.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RealmConfig {
    /// Every `kdc = <host[:port]>` under the realm, in file order.
    pub kdcs: Vec<String>,
    /// The `admin_server = <host>` value if present.
    pub admin_server: Option<String>,
}

impl Krb5Config {
    /// Read + parse a `krb5.conf` file. Convenience wrapper over
    /// [`Self::parse`] that reports read errors alongside parse errors under
    /// one [`ConfigError`] variant.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path.as_ref())
            .map_err(|e| ConfigError::Io(e.to_string()))?;
        Self::parse(&text)
    }

    /// Parse a `krb5.conf` string.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let mut out = Krb5Config::default();
        let mut section: Option<String> = None;
        let mut lines = text.lines().enumerate().peekable();
        while let Some((lineno, raw)) = lines.next() {
            let line = trim_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            if let Some(name) = section_header(line) {
                section = Some(name.to_ascii_lowercase());
                continue;
            }
            let s = section.as_deref().ok_or_else(|| ConfigError::UnexpectedLine {
                line: lineno + 1,
                content: line.to_string(),
            })?;

            match s {
                "libdefaults" => {
                    if let Some((k, v)) = split_kv(line) {
                        if k.eq_ignore_ascii_case("default_realm") {
                            out.default_realm = Some(v.to_ascii_uppercase());
                        }
                    }
                }
                "realms" => {
                    // Either `REALM = { ... }` on one line, or `REALM = {` opens a
                    // multi-line subsection terminated by `}`.
                    if let Some((k, v)) = split_kv(line) {
                        if v.trim_start().starts_with('{') {
                            let realm_key = k.to_ascii_uppercase();
                            let mut realm = out.realms.remove(&realm_key).unwrap_or_default();
                            let rest = v.trim_start().trim_start_matches('{');
                            let mut done = read_realm_body(rest.trim(), &mut realm);
                            while !done {
                                let (n, r) = lines.next().ok_or(ConfigError::UnclosedSubsection {
                                    line: lineno + 1,
                                    realm: realm_key.clone(),
                                })?;
                                let inner = trim_comment(r).trim();
                                if inner.is_empty() {
                                    continue;
                                }
                                done = read_realm_body(inner, &mut realm);
                                let _ = n;
                            }
                            out.realms.insert(realm_key, realm);
                        }
                    }
                }
                "domain_realm" => {
                    if let Some((k, v)) = split_kv(line) {
                        out.domain_realm.insert(k.to_string(), v.to_ascii_uppercase());
                    }
                }
                _ => {
                    // Silently accept unknown sections — MIT files carry many.
                }
            }
        }
        Ok(out)
    }

    /// `[libdefaults] default_realm` if present.
    #[must_use]
    pub fn default_realm(&self) -> Option<&str> {
        self.default_realm.as_deref()
    }

    /// KDC hostnames the file lists for `realm` (case-insensitive lookup).
    /// Returns `&[]` when the realm is not present.
    #[must_use]
    pub fn kdcs_for(&self, realm: &str) -> &[String] {
        self.realms
            .get(&realm.to_ascii_uppercase())
            .map(|r| r.kdcs.as_slice())
            .unwrap_or(&[])
    }

    /// The `admin_server` for `realm`, if the file has one.
    #[must_use]
    pub fn admin_server_for(&self, realm: &str) -> Option<&str> {
        self.realms
            .get(&realm.to_ascii_uppercase())
            .and_then(|r| r.admin_server.as_deref())
    }

    /// Resolve `hostname` → realm via `[domain_realm]`. Walks the DNS labels
    /// right-to-left so `web.dev.corp.local` matches a `.corp.local` entry
    /// even when `.dev.corp.local` is absent — the MIT resolution rule.
    #[must_use]
    pub fn realm_for_host(&self, hostname: &str) -> Option<&str> {
        // Exact hostname wins.
        if let Some(r) = self.domain_realm.get(hostname) {
            return Some(r.as_str());
        }
        // Then progressively shorter dotted suffixes.
        let lower = hostname.to_ascii_lowercase();
        let mut idx = 0;
        while let Some(dot) = lower[idx..].find('.') {
            idx += dot;
            let suffix = &lower[idx..];
            if let Some(r) = self.domain_realm.get(suffix) {
                return Some(r.as_str());
            }
            idx += 1;
        }
        None
    }
}

/// Errors from the krb5.conf loader.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Filesystem read failed.
    Io(String),
    /// A non-blank line appeared before any `[section]` header.
    UnexpectedLine {
        /// 1-indexed line number.
        line: usize,
        /// Trimmed content of the offending line.
        content: String,
    },
    /// A `{` subsection was opened but never closed (missing `}`).
    UnclosedSubsection {
        /// 1-indexed line the subsection opened on.
        line: usize,
        /// The realm key the subsection was under.
        realm: String,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(msg) => write!(f, "read krb5.conf: {msg}"),
            ConfigError::UnexpectedLine { line, content } => {
                write!(f, "line {line}: content before any [section]: {content:?}")
            }
            ConfigError::UnclosedSubsection { line, realm } => {
                write!(f, "line {line}: unclosed {{ ... }} for realm {realm}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

// ── internal parse helpers ──

fn trim_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

fn section_header(line: &str) -> Option<&str> {
    let l = line.strip_prefix('[')?;
    let end = l.find(']')?;
    Some(l[..end].trim())
}

fn split_kv(line: &str) -> Option<(&str, &str)> {
    let eq = line.find('=')?;
    let k = line[..eq].trim();
    let v = line[eq + 1..].trim();
    if k.is_empty() {
        None
    } else {
        Some((k, v))
    }
}

/// Feed one line's worth of realm-body content into `realm`. Returns `true`
/// when the body's closing `}` has been consumed.
fn read_realm_body(body: &str, realm: &mut RealmConfig) -> bool {
    let (payload, closing) = match body.rfind('}') {
        Some(i) => (body[..i].trim(), true),
        None => (body.trim(), false),
    };
    for chunk in payload.split(['\n', ';']) {
        if let Some((k, v)) = split_kv(chunk.trim()) {
            match k.to_ascii_lowercase().as_str() {
                "kdc" => realm.kdcs.push(v.to_string()),
                "admin_server" => realm.admin_server = Some(v.to_string()),
                _ => {} // Ignore unknown realm keys (e.g. default_domain).
            }
        }
    }
    closing
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_mit_shape() {
        let src = r#"
# comment line
[libdefaults]
    default_realm = corp.local

[realms]
    CORP.LOCAL = {
        kdc = dc01.corp.local
        kdc = dc02.corp.local:88
        admin_server = dc01.corp.local
        default_domain = corp.local
    }

[domain_realm]
    .corp.local = CORP.LOCAL
    corp.local = CORP.LOCAL
"#;
        let conf = Krb5Config::parse(src).unwrap();
        assert_eq!(conf.default_realm(), Some("CORP.LOCAL"));
        assert_eq!(
            conf.kdcs_for("corp.local"), // case-insensitive lookup
            &["dc01.corp.local".to_string(), "dc02.corp.local:88".to_string()]
        );
        assert_eq!(conf.admin_server_for("CORP.LOCAL"), Some("dc01.corp.local"));
        assert_eq!(conf.realm_for_host("web.corp.local"), Some("CORP.LOCAL"));
        assert_eq!(conf.realm_for_host("corp.local"), Some("CORP.LOCAL"));
    }

    #[test]
    fn multiple_realms() {
        let src = r#"
[realms]
    A.LOCAL = {
        kdc = a-dc
    }
    B.LOCAL = {
        kdc = b-dc-1
        kdc = b-dc-2
    }
"#;
        let conf = Krb5Config::parse(src).unwrap();
        assert_eq!(conf.kdcs_for("A.LOCAL"), &["a-dc".to_string()]);
        assert_eq!(conf.kdcs_for("B.LOCAL").len(), 2);
    }

    #[test]
    fn unknown_sections_are_ignored() {
        let src = r#"
[appdefaults]
    kinit = { renewable = true }

[libdefaults]
    default_realm = X.LOCAL
"#;
        let conf = Krb5Config::parse(src).unwrap();
        assert_eq!(conf.default_realm(), Some("X.LOCAL"));
    }

    #[test]
    fn realm_for_host_walks_suffixes() {
        let src = r#"
[domain_realm]
    .corp.local = CORP.LOCAL
"#;
        let conf = Krb5Config::parse(src).unwrap();
        assert_eq!(
            conf.realm_for_host("very.deep.host.corp.local"),
            Some("CORP.LOCAL")
        );
        assert_eq!(conf.realm_for_host("stranger.example.net"), None);
    }

    #[test]
    fn rejects_content_before_first_section() {
        let src = "default_realm = X\n";
        assert!(matches!(
            Krb5Config::parse(src).unwrap_err(),
            ConfigError::UnexpectedLine { line: 1, .. }
        ));
    }

    #[test]
    fn comment_stripping() {
        let src = r#"
[libdefaults]
    default_realm = A.LOCAL  # inline comment
"#;
        let conf = Krb5Config::parse(src).unwrap();
        assert_eq!(conf.default_realm(), Some("A.LOCAL"));
    }

    #[test]
    fn empty_file_yields_default() {
        let conf = Krb5Config::parse("").unwrap();
        assert_eq!(conf, Krb5Config::default());
    }
}
