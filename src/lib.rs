//! `wyrtloom-config` — a reusable configuration loader for the Wyrtloom
//! dashboard ecosystem.
//!
//! It defines a `wyrtloom.toml` schema and the [`load`], [`save`], and
//! [`validate`] functions that turn that file into the strongly-typed core
//! domain objects from [`wyrtloom_core`]:
//!
//! * the `[security]` table becomes a [`wyrtloom_core::security::SecurityPolicy`];
//! * each `[[plugin]]` entry becomes a [`PluginEntry`], which pairs a
//!   [`wyrtloom_core::plugin::PluginManifest`] with an `enabled` flag and a
//!   free-form `settings` map.
//!
//! Core types ([`SemVer`], [`Capability`], [`PluginClass`], …) are reused
//! directly — this crate never redefines them.
//!
//! ```no_run
//! let cfg = wyrtloom_config::load("wyrtloom.toml").unwrap();
//! wyrtloom_config::validate(&cfg).unwrap();
//! let policy = cfg.security_policy();
//! for plugin in &cfg.plugins {
//!     println!("{} enabled={}", plugin.manifest.name, plugin.enabled);
//! }
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use wyrtloom_core::plugin::{
    Capability, CoreContractVersions, PluginClass, PluginManifest,
};
use wyrtloom_core::security::SecurityPolicy;
use wyrtloom_core::storage::validate_db_path;
use wyrtloom_core::types::{ContractId, SemVer};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Opaque error type for all config operations.
///
/// Variants deliberately carry only a short, human-readable summary so that
/// internal detail (file-system layout, parser internals) does not leak to
/// callers or logs.
#[derive(Error, Debug)]
pub enum ConfigError {
    /// The config file could not be read or written.
    #[error("config i/o error")]
    Io,
    /// The config text could not be parsed as the `wyrtloom.toml` schema.
    #[error("config parse error: {0}")]
    Parse(String),
    /// The config could not be serialised back to TOML.
    #[error("config serialise error")]
    Serialize,
    /// The config parsed but failed validation.
    #[error("config validation error: {0}")]
    Validation(String),
}

// ---------------------------------------------------------------------------
// Settings value
// ---------------------------------------------------------------------------

/// A free-form, per-plugin settings map (e.g. `db_path`, `base_url`).
///
/// Values are stored as [`toml::Value`] so any TOML scalar/array/table is
/// preserved across a save/load round-trip.
pub type Settings = BTreeMap<String, toml::Value>;

// ---------------------------------------------------------------------------
// Public, typed config
// ---------------------------------------------------------------------------

/// A fully-typed Wyrtloom configuration, reusing core domain objects.
#[derive(Debug, Clone)]
pub struct Config {
    /// Capability policy assembled from the `[security]` table.
    pub security: SecuritySection,
    /// One entry per `[[plugin]]` table.
    pub plugins: Vec<PluginEntry>,
}

impl Config {
    /// Build the core [`SecurityPolicy`] described by this config.
    pub fn security_policy(&self) -> SecurityPolicy {
        self.security.to_policy()
    }
}

/// The `[security]` table in typed form.
///
/// Mirrors [`SecurityPolicy`] field-for-field (which is not itself
/// (de)serialisable), so it can round-trip through TOML while still producing
/// the exact core type via [`SecuritySection::to_policy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecuritySection {
    pub file_read_prefixes: Vec<String>,
    pub file_write_prefixes: Vec<String>,
    pub network_allowlist: Vec<String>,
    pub allow_shell: bool,
    pub allow_git: bool,
}

impl SecuritySection {
    /// Convert into the core [`SecurityPolicy`].
    pub fn to_policy(&self) -> SecurityPolicy {
        SecurityPolicy {
            file_read_prefixes: self.file_read_prefixes.clone(),
            file_write_prefixes: self.file_write_prefixes.clone(),
            network_allowlist: self.network_allowlist.clone(),
            allow_shell: self.allow_shell,
            allow_git: self.allow_git,
        }
    }

    /// Build from a core [`SecurityPolicy`].
    pub fn from_policy(policy: &SecurityPolicy) -> Self {
        Self {
            file_read_prefixes: policy.file_read_prefixes.clone(),
            file_write_prefixes: policy.file_write_prefixes.clone(),
            network_allowlist: policy.network_allowlist.clone(),
            allow_shell: policy.allow_shell,
            allow_git: policy.allow_git,
        }
    }
}

/// One configured plugin: its core manifest plus operator-supplied wiring.
///
/// [`PluginManifest`] does not implement [`PartialEq`], so `PluginEntry`
/// implements it by hand (see below), comparing manifests structurally.
#[derive(Debug, Clone)]
pub struct PluginEntry {
    /// The core manifest reused verbatim by the loader/registry.
    pub manifest: PluginManifest,
    /// Whether the operator has enabled this plugin.
    pub enabled: bool,
    /// Free-form plugin settings (e.g. `db_path`, `base_url`).
    pub settings: Settings,
}

/// Structural equality for [`PluginManifest`], which does not itself derive
/// [`PartialEq`]. Kept local so the core type is not modified.
fn manifest_eq(a: &PluginManifest, b: &PluginManifest) -> bool {
    a.name == b.name
        && a.version == b.version
        && a.class == b.class
        && a.capabilities == b.capabilities
        && a.implements == b.implements
}

impl PartialEq for PluginEntry {
    fn eq(&self, other: &Self) -> bool {
        self.enabled == other.enabled
            && self.settings == other.settings
            && manifest_eq(&self.manifest, &other.manifest)
    }
}

impl PartialEq for Config {
    fn eq(&self, other: &Self) -> bool {
        self.security == other.security && self.plugins == other.plugins
    }
}

// ---------------------------------------------------------------------------
// On-disk (raw) schema — what serde actually (de)serialises
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    security: RawSecurity,
    #[serde(default, rename = "plugin")]
    plugins: Vec<RawPlugin>,
}

// `deny_unknown_fields` so a typo'd, security-relevant key (e.g. `allow_shel`)
// is a hard parse error rather than silently falling back to the default.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawSecurity {
    #[serde(default)]
    file_read_prefixes: Vec<String>,
    #[serde(default)]
    file_write_prefixes: Vec<String>,
    #[serde(default)]
    network_allowlist: Vec<String>,
    #[serde(default)]
    allow_shell: bool,
    #[serde(default)]
    allow_git: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPlugin {
    name: String,
    version: String,
    class: String,
    #[serde(default)]
    capabilities: Vec<RawCapability>,
    /// `(contract-id, required-version)` pairs.
    #[serde(default)]
    implements: Vec<RawContract>,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    settings: Settings,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawContract {
    contract: String,
    version: String,
}

/// TOML form of a [`Capability`]: a `kind` discriminant plus an optional
/// `target` (path for file caps, host for network). `shell`/`git` take no
/// target.
///
/// ```toml
/// capabilities = [
///   { kind = "file_read",  target = "/var/data" },
///   { kind = "network",    target = "localhost" },
///   { kind = "git" },
/// ]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCapability {
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<String>,
}

// ---------------------------------------------------------------------------
// Conversions: raw <-> typed
// ---------------------------------------------------------------------------

fn parse_semver(s: &str) -> Result<SemVer, ConfigError> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return Err(ConfigError::Parse(format!(
            "version '{s}' must be MAJOR.MINOR.PATCH"
        )));
    }
    // Each component must be a canonical decimal: digits only (rejecting the
    // leading `+`/`-` and whitespace that `u32::from_str` would otherwise
    // accept), and no leading zeros (so the on-disk string round-trips
    // losslessly against `SemVer`'s `Display`). `"0"` itself is allowed.
    let parse = |p: &str| -> Result<u32, ConfigError> {
        let canonical = !p.is_empty()
            && p.bytes().all(|b| b.is_ascii_digit())
            && (p == "0" || !p.starts_with('0'));
        if !canonical {
            return Err(ConfigError::Parse(format!(
                "version component '{p}' is not a canonical number"
            )));
        }
        p.parse::<u32>()
            .map_err(|_| ConfigError::Parse(format!("version component '{p}' is out of range")))
    };
    Ok(SemVer::new(parse(parts[0])?, parse(parts[1])?, parse(parts[2])?))
}

impl RawCapability {
    fn to_capability(&self) -> Result<Capability, ConfigError> {
        let need_target = || {
            self.target.clone().ok_or_else(|| {
                ConfigError::Parse(format!("capability '{}' requires a `target`", self.kind))
            })
        };
        let cap = match self.kind.as_str() {
            "file_read" => Capability::FileRead(need_target()?),
            "file_write" => Capability::FileWrite(need_target()?),
            "network" => Capability::Network(need_target()?),
            "shell" => Capability::Shell,
            "git" => Capability::Git,
            other => {
                return Err(ConfigError::Parse(format!(
                    "unknown capability kind '{other}'"
                )))
            }
        };
        Ok(cap)
    }

    fn from_capability(cap: &Capability) -> Self {
        let (kind, target) = match cap {
            Capability::FileRead(p) => ("file_read", Some(p.clone())),
            Capability::FileWrite(p) => ("file_write", Some(p.clone())),
            Capability::Network(h) => ("network", Some(h.clone())),
            Capability::Shell => ("shell", None),
            Capability::Git => ("git", None),
        };
        Self { kind: kind.to_string(), target }
    }
}

fn parse_class(s: &str) -> Result<PluginClass, ConfigError> {
    match s {
        "safe" => Ok(PluginClass::Safe),
        "unsafe" => Ok(PluginClass::Unsafe),
        other => Err(ConfigError::Parse(format!(
            "unknown plugin class '{other}' (expected 'safe' or 'unsafe')"
        ))),
    }
}

fn class_str(class: &PluginClass) -> &'static str {
    match class {
        PluginClass::Safe => "safe",
        PluginClass::Unsafe => "unsafe",
    }
}

impl RawPlugin {
    fn to_entry(&self) -> Result<PluginEntry, ConfigError> {
        let mut capabilities = Vec::with_capacity(self.capabilities.len());
        for c in &self.capabilities {
            capabilities.push(c.to_capability()?);
        }
        let mut implements: Vec<(ContractId, SemVer)> = Vec::with_capacity(self.implements.len());
        for i in &self.implements {
            implements.push((i.contract.clone(), parse_semver(&i.version)?));
        }
        let manifest = PluginManifest {
            name: self.name.clone(),
            version: parse_semver(&self.version)?,
            class: parse_class(&self.class)?,
            capabilities,
            implements,
        };
        Ok(PluginEntry {
            manifest,
            enabled: self.enabled,
            settings: self.settings.clone(),
        })
    }

    fn from_entry(entry: &PluginEntry) -> Self {
        let m = &entry.manifest;
        Self {
            name: m.name.clone(),
            version: m.version.to_string(),
            class: class_str(&m.class).to_string(),
            capabilities: m.capabilities.iter().map(RawCapability::from_capability).collect(),
            implements: m
                .implements
                .iter()
                .map(|(c, v)| RawContract { contract: c.clone(), version: v.to_string() })
                .collect(),
            enabled: entry.enabled,
            settings: entry.settings.clone(),
        }
    }
}

impl RawConfig {
    fn to_config(&self) -> Result<Config, ConfigError> {
        let mut plugins = Vec::with_capacity(self.plugins.len());
        for p in &self.plugins {
            plugins.push(p.to_entry()?);
        }
        Ok(Config {
            security: SecuritySection {
                file_read_prefixes: self.security.file_read_prefixes.clone(),
                file_write_prefixes: self.security.file_write_prefixes.clone(),
                network_allowlist: self.security.network_allowlist.clone(),
                allow_shell: self.security.allow_shell,
                allow_git: self.security.allow_git,
            },
            plugins,
        })
    }

    fn from_config(cfg: &Config) -> Self {
        Self {
            security: RawSecurity {
                file_read_prefixes: cfg.security.file_read_prefixes.clone(),
                file_write_prefixes: cfg.security.file_write_prefixes.clone(),
                network_allowlist: cfg.security.network_allowlist.clone(),
                allow_shell: cfg.security.allow_shell,
                allow_git: cfg.security.allow_git,
            },
            plugins: cfg.plugins.iter().map(RawPlugin::from_entry).collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Public API: parse / serialise / load / save / validate
// ---------------------------------------------------------------------------

/// Parse a `wyrtloom.toml` document from a string into a typed [`Config`].
pub fn from_str(text: &str) -> Result<Config, ConfigError> {
    let raw: RawConfig = toml::from_str(text).map_err(|e| ConfigError::Parse(e.message().to_string()))?;
    raw.to_config()
}

/// Serialise a [`Config`] back to a `wyrtloom.toml` document.
pub fn to_string(cfg: &Config) -> Result<String, ConfigError> {
    let raw = RawConfig::from_config(cfg);
    toml::to_string_pretty(&raw).map_err(|_| ConfigError::Serialize)
}

/// Load and parse a `wyrtloom.toml` file from `path`.
///
/// This does *not* run [`validate`]; call it separately so callers can decide
/// how to surface validation failures.
pub fn load(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|_| ConfigError::Io)?;
    from_str(&text)
}

/// Serialise `cfg` and write it to `path` as `wyrtloom.toml`.
pub fn save(path: impl AsRef<Path>, cfg: &Config) -> Result<(), ConfigError> {
    let text = to_string(cfg)?;
    std::fs::write(path, text).map_err(|_| ConfigError::Io)
}

/// Deterministically validate a [`Config`] against the v0.1 core contracts.
///
/// Checks, in order:
/// 1. every plugin name is valid per [`PluginManifest::validate_name`];
/// 2. `Safe` plugins declare no capabilities;
/// 3. file-path capabilities and any path-like settings reject `..` traversal;
/// 4. every declared `implements` contract version is compatible with
///    [`CoreContractVersions::v0_1`].
pub fn validate(cfg: &Config) -> Result<(), ConfigError> {
    let core = CoreContractVersions::v0_1();

    for entry in &cfg.plugins {
        let m = &entry.manifest;

        // 1. Plugin name well-formed.
        PluginManifest::validate_name(&m.name).map_err(ConfigError::Validation)?;

        // 2. Safe plugins must declare no capabilities.
        if m.class == PluginClass::Safe && !m.capabilities.is_empty() {
            return Err(ConfigError::Validation(format!(
                "safe plugin '{}' must not declare capabilities",
                m.name
            )));
        }

        // 3a. File-path capabilities must not contain traversal.
        for cap in &m.capabilities {
            match cap {
                Capability::FileRead(p) | Capability::FileWrite(p) => {
                    validate_db_path(p).map_err(|_| {
                        ConfigError::Validation(format!(
                            "plugin '{}' capability path contains traversal",
                            m.name
                        ))
                    })?;
                }
                _ => {}
            }
        }

        // 3b. Settings must not smuggle `..` traversal. Rather than guess which
        // keys name paths (a fragile, easily-bypassed heuristic), every string
        // value — at any depth, including inside nested tables and arrays — is
        // screened. A non-path string containing `..` is harmless to reject; a
        // path one that does is exactly what we must catch.
        for value in entry.settings.values() {
            if let Some(bad) = first_traversal_value(value) {
                return Err(ConfigError::Validation(format!(
                    "plugin '{}' setting value '{}' contains path traversal",
                    m.name, bad
                )));
            }
        }

        // 4. Declared contract versions must be compatible with the core.
        for (contract, version) in &m.implements {
            if !core.is_compatible(contract, version) {
                // Distinguish the common "minor too low" case (same major, but the
                // plugin declares an older minor than core requires) from a true
                // major/contract mismatch, since the generic wording is misleading
                // when the plugin simply needs to bump its minor.
                let detail = match core.0.get(contract.as_str()) {
                    Some(core_ver)
                        if version.major == core_ver.major && version.minor < core_ver.minor =>
                    {
                        format!(
                            "plugin minor too low: declares v{version} but core requires \
                             at least v{}.{}.0",
                            core_ver.major, core_ver.minor
                        )
                    }
                    Some(core_ver) => format!(
                        "incompatible with core's v{core_ver} for this contract"
                    ),
                    None => "unknown contract not provided by core".to_string(),
                };
                return Err(ConfigError::Validation(format!(
                    "plugin '{}' declares contract '{}' v{} — {}",
                    m.name, contract, version, detail
                )));
            }
        }
    }

    // 5. The `[security]` table's file-capability prefixes are themselves paths
    // and must not smuggle `..` traversal, consistent with how plugin file
    // capabilities are screened in step 3. (`network_allowlist` entries are
    // hosts, not paths, so they are intentionally left unscreened.)
    for prefix in cfg
        .security
        .file_read_prefixes
        .iter()
        .chain(&cfg.security.file_write_prefixes)
    {
        validate_db_path(prefix).map_err(|_| {
            ConfigError::Validation(format!(
                "[security] prefix '{prefix}' contains path traversal"
            ))
        })?;
    }

    Ok(())
}

/// Recursively scan a settings value for any string that
/// [`validate_db_path`] rejects (i.e. contains a `..` path component),
/// returning the offending string. Descends into tables and arrays so a
/// traversal value nested under any key is still caught.
fn first_traversal_value(value: &toml::Value) -> Option<&str> {
    match value {
        toml::Value::String(s) => validate_db_path(s).err().map(|_| s.as_str()),
        toml::Value::Array(items) => items.iter().find_map(first_traversal_value),
        toml::Value::Table(table) => table.values().find_map(first_traversal_value),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_toml() -> &'static str {
        r#"
[security]
file_read_prefixes  = ["/var/data", "/tmp"]
file_write_prefixes = ["/var/data"]
network_allowlist   = ["localhost"]
allow_shell = false
allow_git   = true

[[plugin]]
name    = "kanban-sqlite"
version = "0.2.0"
class   = "unsafe"
enabled = true
implements = [{ contract = "wyrtloom.kanban", version = "0.2.0" }]
capabilities = [
    { kind = "file_read",  target = "/var/data" },
    { kind = "file_write", target = "/var/data" },
]

[plugin.settings]
db_path = "/var/data/kanban.db"

[[plugin]]
name    = "workflow-profile"
version = "0.1.0"
class   = "safe"
enabled = false
implements = [{ contract = "wyrtloom.provider", version = "0.1.0" }]
"#
    }

    fn built_config() -> Config {
        let mut settings = Settings::new();
        settings.insert("base_url".into(), toml::Value::String("http://localhost:8080".into()));
        Config {
            security: SecuritySection {
                file_read_prefixes: vec!["/var/data".into()],
                file_write_prefixes: vec!["/var/data".into()],
                network_allowlist: vec!["localhost".into()],
                allow_shell: false,
                allow_git: true,
            },
            plugins: vec![
                PluginEntry {
                    manifest: PluginManifest {
                        name: "provider-ollama".into(),
                        version: SemVer::new(0, 1, 0),
                        class: PluginClass::Unsafe,
                        capabilities: vec![Capability::Network("localhost".into())],
                        implements: vec![("wyrtloom.provider".into(), SemVer::new(0, 1, 0))],
                    },
                    enabled: true,
                    settings,
                },
                PluginEntry {
                    manifest: PluginManifest {
                        name: "workflow-profile".into(),
                        version: SemVer::new(0, 1, 0),
                        class: PluginClass::Safe,
                        capabilities: vec![],
                        implements: vec![],
                    },
                    enabled: false,
                    settings: Settings::new(),
                },
            ],
        }
    }

    // ---- Round-trip ----------------------------------------------------------

    #[test]
    fn round_trip_build_save_load_equal() {
        let cfg = built_config();
        let dir = std::env::temp_dir();
        let path = dir.join(format!("wyrtloom-config-rt-{}.toml", std::process::id()));
        save(&path, &cfg).expect("save");
        let loaded = load(&path).expect("load");
        let _ = std::fs::remove_file(&path);
        assert_eq!(cfg, loaded, "round-trip mismatch");
    }

    #[test]
    fn round_trip_via_string() {
        let cfg = built_config();
        let text = to_string(&cfg).expect("to_string");
        let parsed = from_str(&text).expect("from_str");
        assert_eq!(cfg, parsed);
    }

    // ---- Parse a realistic sample -------------------------------------------

    #[test]
    fn parses_sample_with_security_and_two_plugins() {
        let cfg = from_str(sample_toml()).expect("parse sample");

        // Security policy reproduced exactly.
        let policy = cfg.security_policy();
        assert_eq!(policy.file_read_prefixes, vec!["/var/data", "/tmp"]);
        assert_eq!(policy.file_write_prefixes, vec!["/var/data"]);
        assert_eq!(policy.network_allowlist, vec!["localhost"]);
        assert!(!policy.allow_shell);
        assert!(policy.allow_git);

        // Two plugin entries.
        assert_eq!(cfg.plugins.len(), 2);

        // First plugin: manifest + capabilities + settings.
        let kanban = &cfg.plugins[0];
        assert_eq!(kanban.manifest.name, "kanban-sqlite");
        assert_eq!(kanban.manifest.version, SemVer::new(0, 2, 0));
        assert_eq!(kanban.manifest.class, PluginClass::Unsafe);
        assert!(kanban.enabled);
        assert_eq!(
            kanban.manifest.capabilities,
            vec![
                Capability::FileRead("/var/data".into()),
                Capability::FileWrite("/var/data".into()),
            ]
        );
        assert_eq!(
            kanban.manifest.implements,
            vec![("wyrtloom.kanban".to_string(), SemVer::new(0, 2, 0))]
        );
        assert_eq!(
            kanban.settings.get("db_path").and_then(|v| v.as_str()),
            Some("/var/data/kanban.db")
        );

        // Second plugin: safe, disabled, no settings.
        let wf = &cfg.plugins[1];
        assert_eq!(wf.manifest.name, "workflow-profile");
        assert_eq!(wf.manifest.class, PluginClass::Safe);
        assert!(!wf.enabled);
        assert!(wf.manifest.capabilities.is_empty());
        assert!(wf.settings.is_empty());

        // The whole sample validates.
        validate(&cfg).expect("sample should validate");
    }

    // ---- Rejection cases -----------------------------------------------------

    #[test]
    fn rejects_bad_plugin_name() {
        let cfg = from_str(
            r#"
[[plugin]]
name    = "../evil"
version = "0.1.0"
class   = "safe"
"#,
        )
        .expect("parses fine; name is checked by validate()");
        let err = validate(&cfg).unwrap_err();
        assert!(matches!(err, ConfigError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn rejects_safe_plugin_with_capability() {
        let cfg = from_str(
            r#"
[[plugin]]
name    = "rogue-safe"
version = "0.1.0"
class   = "safe"
capabilities = [{ kind = "shell" }]
"#,
        )
        .expect("parse");
        let err = validate(&cfg).unwrap_err();
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("must not declare capabilities")),
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_incompatible_contract_version() {
        // Major bump => incompatible with the 0.x core floor.
        let cfg = from_str(
            r#"
[[plugin]]
name    = "future-kanban"
version = "1.0.0"
class   = "unsafe"
implements = [{ contract = "wyrtloom.kanban", version = "1.0.0" }]
"#,
        )
        .expect("parse");
        let err = validate(&cfg).unwrap_err();
        assert!(matches!(err, ConfigError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn rejects_unknown_contract() {
        let cfg = from_str(
            r#"
[[plugin]]
name    = "mystery"
version = "0.1.0"
class   = "unsafe"
implements = [{ contract = "wyrtloom.unknown", version = "0.1.0" }]
"#,
        )
        .expect("parse");
        assert!(matches!(validate(&cfg), Err(ConfigError::Validation(_))));
    }

    #[test]
    fn rejects_path_traversal_in_settings() {
        let cfg = from_str(
            r#"
[[plugin]]
name    = "kanban-sqlite"
version = "0.1.0"
class   = "unsafe"

[plugin.settings]
db_path = "../../etc/passwd"
"#,
        )
        .expect("parse");
        assert!(matches!(validate(&cfg), Err(ConfigError::Validation(_))));
    }

    #[test]
    fn rejects_path_traversal_in_nested_settings() {
        // `..` hidden under an arbitrarily-named nested table must still be caught.
        let cfg = from_str(
            r#"
[[plugin]]
name    = "kanban-sqlite"
version = "0.1.0"
class   = "unsafe"

[plugin.settings.storage]
location = "../../etc/passwd"
"#,
        )
        .expect("parse");
        assert!(matches!(validate(&cfg), Err(ConfigError::Validation(_))));
    }

    #[test]
    fn rejects_path_traversal_in_settings_array_and_odd_key() {
        // Array element traversal, under a key the old heuristic would have missed.
        let cfg = from_str(
            r#"
[[plugin]]
name    = "kanban-sqlite"
version = "0.1.0"
class   = "unsafe"

[plugin.settings]
database = ["/var/data", "../../etc"]
"#,
        )
        .expect("parse");
        assert!(matches!(validate(&cfg), Err(ConfigError::Validation(_))));
    }

    #[test]
    fn rejects_path_traversal_in_capability() {
        let cfg = from_str(
            r#"
[[plugin]]
name    = "kanban-sqlite"
version = "0.1.0"
class   = "unsafe"
capabilities = [{ kind = "file_read", target = "/tmp/../etc" }]
"#,
        )
        .expect("parse");
        assert!(matches!(validate(&cfg), Err(ConfigError::Validation(_))));
    }

    #[test]
    fn rejects_path_traversal_in_security_prefix() {
        // A `[security]` prefix that escapes via `..` must be rejected, just like
        // a plugin file-capability target (finding: prefixes were unscreened).
        let cfg = from_str(
            r#"
[security]
file_read_prefixes = ["../.."]
"#,
        )
        .expect("parse");
        match validate(&cfg) {
            Err(ConfigError::Validation(msg)) => {
                assert!(msg.contains("[security]") && msg.contains("traversal"), "got {msg}")
            }
            other => panic!("expected validation error, got {other:?}"),
        }

        // A write prefix with traversal is caught too.
        let cfg = from_str(
            r#"
[security]
file_write_prefixes = ["/var/data/../../etc"]
"#,
        )
        .expect("parse");
        assert!(matches!(validate(&cfg), Err(ConfigError::Validation(_))));
    }

    // ---- Parser-level errors -------------------------------------------------

    #[test]
    fn rejects_unknown_capability_key() {
        // A typo'd key inside a capability entry must be a hard parse error
        // (RawCapability now uses `deny_unknown_fields`), not a silent ignore.
        let err = from_str(
            r#"
[[plugin]]
name    = "x"
version = "0.1.0"
class   = "unsafe"
capabilities = [{ kind = "file_read", targett = "/tmp" }]
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "got {err:?}");
    }

    #[test]
    fn rejects_unknown_capability_kind() {
        let err = from_str(
            r#"
[[plugin]]
name    = "x"
version = "0.1.0"
class   = "unsafe"
capabilities = [{ kind = "teleport" }]
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn rejects_unknown_class() {
        let err = from_str(
            r#"
[[plugin]]
name    = "x"
version = "0.1.0"
class   = "chaotic"
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn rejects_malformed_version() {
        let err = from_str(
            r#"
[[plugin]]
name    = "x"
version = "0.1"
class   = "safe"
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn rejects_non_canonical_version_components() {
        // Leading zeros and signs would round-trip lossily / aren't real semver.
        for bad in ["0.01.0", "+1.0.0", "1.0.0 ", "1..0"] {
            let toml = format!(
                "[[plugin]]\nname=\"x\"\nversion=\"{bad}\"\nclass=\"safe\"\n"
            );
            assert!(
                matches!(from_str(&toml), Err(ConfigError::Parse(_))),
                "should reject version {bad:?}"
            );
        }
        // But a plain zero component is fine.
        assert!(from_str("[[plugin]]\nname=\"x\"\nversion=\"0.1.0\"\nclass=\"safe\"\n").is_ok());
    }

    #[test]
    fn rejects_unknown_top_level_and_security_keys() {
        // A typo in a security-relevant key must be a hard error, not a silent default.
        assert!(matches!(
            from_str("[security]\nallow_shel = true\n"),
            Err(ConfigError::Parse(_))
        ));
        assert!(matches!(
            from_str("[[plugin]]\nname=\"x\"\nversion=\"0.1.0\"\nclass=\"safe\"\nenabledd=true\n"),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn enabled_defaults_to_true() {
        let cfg = from_str(
            r#"
[[plugin]]
name    = "defaulted"
version = "0.1.0"
class   = "safe"
"#,
        )
        .expect("parse");
        assert!(cfg.plugins[0].enabled);
    }

    #[test]
    fn empty_config_is_valid() {
        let cfg = from_str("").expect("parse empty");
        assert!(cfg.plugins.is_empty());
        validate(&cfg).expect("empty validates");
        // Default security policy is fully deny.
        let p = cfg.security_policy();
        assert!(p.file_read_prefixes.is_empty());
        assert!(!p.allow_git);
    }
}
