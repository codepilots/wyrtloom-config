# wyrtloom-config

A reusable configuration loader for the [Wyrtloom](https://github.com/codepilots/wyrtloom)
dashboard ecosystem. It defines the `wyrtloom.toml` schema and turns it into the
strongly-typed domain objects from `wyrtloom-core` — never redefining core types
such as `SecurityPolicy`, `PluginManifest`, `Capability`, or `SemVer`.

The crate depends **only** on `wyrtloom-core` (plus `serde`, `toml`,
`serde_json`, and `thiserror`).

## What it does

* The `[security]` table builds a `wyrtloom_core::security::SecurityPolicy`.
* Each `[[plugin]]` entry yields a `PluginEntry` that pairs a
  `wyrtloom_core::plugin::PluginManifest` with an `enabled: bool` and a
  free-form `settings` table (e.g. `db_path`, `base_url`).
* `validate()` deterministically checks a parsed config against the v0.1 core
  contracts.

## API

```rust
use wyrtloom_config::{load, save, validate, from_str, to_string, Config};

// Parse from disk and validate.
let cfg = wyrtloom_config::load("wyrtloom.toml")?;
wyrtloom_config::validate(&cfg)?;

// Use the typed core objects.
let policy = cfg.security_policy(); // wyrtloom_core::security::SecurityPolicy
for plugin in &cfg.plugins {
    let manifest = &plugin.manifest; // wyrtloom_core::plugin::PluginManifest
    println!("{} enabled={}", manifest.name, plugin.enabled);
}

// Serialise back out.
wyrtloom_config::save("wyrtloom.toml", &cfg)?;
# Ok::<(), wyrtloom_config::ConfigError>(())
```

`load`/`save` operate on files; `from_str`/`to_string` operate on strings.
Parsing does **not** auto-validate — call `validate()` explicitly so callers
control how validation failures are surfaced.

## Schema

```toml
[security]
file_read_prefixes  = ["/var/data", "/tmp"]
file_write_prefixes = ["/var/data"]
network_allowlist   = ["localhost"]
allow_shell = false
allow_git   = true

[[plugin]]
name    = "kanban-sqlite"
version = "0.2.0"          # MAJOR.MINOR.PATCH
class   = "unsafe"          # "safe" | "unsafe"
enabled = true              # defaults to true if omitted
implements = [
    { contract = "wyrtloom.kanban", version = "0.2.0" },
]
capabilities = [
    { kind = "file_read",  target = "/var/data" },
    { kind = "file_write", target = "/var/data" },
    { kind = "network",    target = "localhost" },
    { kind = "shell" },     # shell/git take no target
    { kind = "git" },
]

[plugin.settings]           # free-form; any TOML values
db_path = "/var/data/kanban.db"

[[plugin]]
name    = "workflow-profile"
version = "0.1.0"
class   = "safe"            # safe plugins must declare no capabilities
enabled = false
implements = [
    { contract = "wyrtloom.provider", version = "0.1.0" },
]
```

### Capability mapping

| TOML `kind`   | `target`         | `wyrtloom_core::plugin::Capability` |
| ------------- | ---------------- | ----------------------------------- |
| `file_read`   | path (required)  | `FileRead(path)`                    |
| `file_write`  | path (required)  | `FileWrite(path)`                   |
| `network`     | host (required)  | `Network(host)`                     |
| `shell`       | —                | `Shell`                             |
| `git`         | —                | `Git`                               |

## Validation

`validate()` is deterministic and checks, in order:

1. every plugin name is valid per `PluginManifest::validate_name`
   (`[a-z0-9_-]{1,64}`);
2. `Safe` plugins declare **no** capabilities;
3. file-path capabilities and **every** string value in a plugin's `settings`
   table — at any depth, including inside nested tables and arrays — reject
   `..` traversal (via `wyrtloom_core::storage::validate_db_path`), so a
   traversal value cannot hide behind an unconventional key;
4. every declared `implements` contract version is compatible with
   `CoreContractVersions::v0_1()`.

Parsing is strict: version strings must be canonical `MAJOR.MINOR.PATCH`
decimals (no signs or leading zeros), and unknown keys in the `[security]`,
`[[plugin]]`, top-level, or `implements` tables are rejected rather than
silently ignored (a `settings` table is the only free-form region).

Errors are opaque (`ConfigError`) and do not leak internal detail.

## License

Apache-2.0. See [LICENSE](./LICENSE).
