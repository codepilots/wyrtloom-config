# Security model — `wyrtloom-config`

This crate is the `wyrtloom.toml` loader for the Wyrtloom dashboard ecosystem. It
parses the on-disk config into strongly-typed core domain objects
([`wyrtloom_core`]) — a [`SecurityPolicy`] from the `[security]` table and a
[`PluginManifest`] per `[[plugin]]` entry — and validates them against the v0.1
core contracts. The security-relevant surface is entirely in
[`src/lib.rs`](src/lib.rs); citations below refer to it unless noted.

---

## Threat model & scope

**What this crate defends against.** The `wyrtloom.toml` file (and any TOML text
fed to `from_str`) is treated as **potentially attacker-influenced** input — for
example a config-edit API endpoint that accepts a config body from a client, or a
tampered-with file on disk. The job of this crate is to ensure that such input
cannot:

- name a plugin in a way that smuggles path components or shell-unsafe characters
  (`validate_name`, `src/lib.rs:447`);
- declare a `safe`-class plugin that nevertheless carries system capabilities
  (`src/lib.rs:450`);
- claim to implement a core contract at a version the core cannot honour
  (`is_compatible`, `src/lib.rs:488`);
- embed `..` path-traversal in plugin file capabilities, in *any* nested
  `[plugin.settings]` value, or in the `[security]` `file_read_prefixes` /
  `file_write_prefixes` (`src/lib.rs:458-484`, `516-531`);
- crash the loader with malformed TOML (parsing returns a typed
  `ConfigError::Parse`, never a panic — `src/lib.rs:407`);
- silently flip a security-relevant flag through a typo'd key
  (`#[serde(deny_unknown_fields)]` on every raw struct — `src/lib.rs:174, 185,
  200, 221, 239`).

**What is out of scope (explicitly *not* this crate's job).**

- **Runtime capability enforcement.** This crate validates the *structure and
  policy* of a config. It does not gate file/network/shell access at runtime —
  that is the host's `SecurityModule` in `wyrtloom_core::security`. A capability
  that passes validation here is still subject to runtime checks there.
- **Path confinement.** Traversal screening rejects `..` but does **not** reject
  absolute paths or resolve symlinks (see Gotchas). Confinement of a path to a
  jail is the consumer's responsibility.
- **Secrets / network exposure.** `network_allowlist` entries are hosts, not
  paths, and are intentionally left unscreened (`src/lib.rs:518-519`).

The trust boundary is: **input TOML is untrusted; the typed `Config` /
`SecurityPolicy` / `PluginManifest` this crate emits is trusted by the host —
but only after `validate()` has been run.**

---

## Security mechanisms

### Strict parsing (parse-time, in `from_str`)

- **`#[serde(deny_unknown_fields)]` on every raw struct** (`RawConfig`,
  `RawSecurity`, `RawPlugin`, `RawContract`, `RawCapability` —
  `src/lib.rs:174, 185, 200, 221, 239`). A typo in a security-relevant key
  is a **hard parse error**, not a silent fall-through to a permissive default.
  For instance `allow_shel = true` does not quietly leave `allow_shell` at its
  `false` default — it fails the parse outright (test
  `rejects_unknown_top_level_and_security_keys`, `src/lib.rs:939`). The same
  applies to a typo'd capability key like `targett` (test at `src/lib.rs:863`).
- **Canonical SemVer parsing** (`parse_semver`, `src/lib.rs:250`). Versions must
  be exactly `MAJOR.MINOR.PATCH` with digits-only components and **no leading
  zeros, signs, or whitespace** — forms that `u32::from_str` would otherwise
  accept (`+1.0.0`, `0.01.0`, `1.0.0 `) are rejected so the on-disk string
  round-trips losslessly against `SemVer`'s `Display` (tests at
  `src/lib.rs:909, 923`).
- **Closed enums.** Unknown `class` (`parse_class`, `src/lib.rs:310`) and unknown
  capability `kind` (`RawCapability::to_capability`, `src/lib.rs:289`) are parse
  errors, not ignored values.
- **No panics, no detail leakage.** Malformed TOML maps to a typed
  `ConfigError::Parse(String)` carrying only the parser's short message
  (`src/lib.rs:407`); the `ConfigError` variants deliberately carry minimal
  internal detail so file-system layout / parser internals do not leak to callers
  or logs (`src/lib.rs:42-61`).

### Policy validation (in `validate`, `src/lib.rs:440`)

Run in a deterministic order over each plugin, then the `[security]` table:

1. **Plugin name validation** — `PluginManifest::validate_name`
   (`src/lib.rs:447`; core at
   [`../wyrtloom/crates/core/src/plugin.rs:39`](../wyrtloom/crates/core/src/plugin.rs)):
   non-empty, ≤ 64 chars, and restricted to `[a-z0-9_-]`. This is what rejects a
   name like `../evil` (test `rejects_bad_plugin_name`, `src/lib.rs:697`).
2. **SAFE plugins must declare no capabilities** (`src/lib.rs:450`). A
   `class = "safe"` plugin with any capability is a validation error — a `safe`
   plugin is by definition capability-free, so this prevents privilege smuggling
   through misclassification (test `rejects_safe_plugin_with_capability`,
   `src/lib.rs:713`).
3. **Traversal screening of file capabilities** (`src/lib.rs:458-470`):
   `Capability::FileRead` / `FileWrite` targets are passed through
   `validate_db_path`, rejecting any `..` component (test at `src/lib.rs:817`).
4. **Traversal screening of all settings, recursively** (`src/lib.rs:477-484`
   plus `first_traversal_value`, `src/lib.rs:540`). Rather than guess which keys
   name paths — a fragile, bypassable heuristic — **every string value at any
   depth** is screened, descending into nested tables and arrays. A `..` hidden
   under an arbitrarily-named nested table or inside an array element is still
   caught (tests `rejects_path_traversal_in_nested_settings`,
   `rejects_path_traversal_in_settings_array_and_odd_key`, `src/lib.rs:781, 799`).
   Rejecting a harmless non-path string that happens to contain `..` is an
   accepted, deliberate trade-off.
5. **Contract-version compatibility** (`src/lib.rs:487-513`). Every declared
   `implements` `(contract, version)` must satisfy
   `CoreContractVersions::v0_1().is_compatible(...)`
   ([`plugin.rs:107, 126`](../wyrtloom/crates/core/src/plugin.rs)). An unknown
   contract, or a version with an incompatible major (e.g. a `1.0.0` plugin
   against the `0.x` floor), is rejected (tests
   `rejects_incompatible_contract_version`, `rejects_unknown_contract`,
   `src/lib.rs:731, 749`). The error message distinguishes "minor too low" from a
   true major/contract mismatch.
6. **Traversal screening of `[security]` prefixes** (`src/lib.rs:516-531`).
   `file_read_prefixes` and `file_write_prefixes` are themselves paths and are
   run through `validate_db_path`, consistent with plugin file capabilities. A
   prefix like `../..` or `/var/data/../../etc` is rejected (test
   `rejects_path_traversal_in_security_prefix`, `src/lib.rs:832`).
   `network_allowlist` is intentionally excluded — its entries are hosts.

### Fail-safe consumption by the host

The host treats a failed load as **deny-everything**, never as "permissive
default". In the dashboard API:

- `wyrtloom-dashboard-api/src/main.rs:123-125` loads the policy as
  `wyrtloom_config::load(...).map(|c| c.security_policy()).unwrap_or_else(|_|
  SecurityPolicy::deny_all())`. If the config is missing, unparseable, or
  otherwise errors, the process runs under a fully-closed policy.
- The config-edit endpoint
  (`wyrtloom-dashboard-api/src/routes.rs:404-424`, `put_config`) is the
  reference pattern: it `from_str` → **`validate`** → `save`, rejecting the body
  with a generic `400` (and a server-side audit record) before anything is
  persisted. Internal parser/validator detail is logged but never echoed to the
  client.

---

## Key decisions & rationale

- **Reuse core types, never redefine them.** `Capability`, `PluginClass`,
  `SemVer`, `SecurityPolicy`, `PluginManifest` come straight from `wyrtloom_core`
  (`src/lib.rs:31-36`). There is one definition of "what a capability is" and one
  validator (`validate_name`, `validate_db_path`) shared across the workspace, so
  the loader cannot drift from the runtime's notion of the same concept.
- **Screen every string, not "the path-looking keys".** A key-name allowlist for
  path screening is trivially bypassed by renaming a key. Screening all strings
  recursively (`first_traversal_value`) is conservative-by-construction:
  false-positives are cheap, a missed traversal is not (`src/lib.rs:472-476`).
- **`deny_unknown_fields` everywhere over leniency.** For a security config,
  silently ignoring an unrecognised key is the dangerous failure mode (a
  mistyped `allow_shell` could leave shell access unexpectedly off — or a future
  renamed flag silently on). Hard-failing surfaces the mistake immediately.
- **Parse and validate are separate steps.** `load` does *not* auto-validate
  (`src/lib.rs:417-424`) so callers choose how to surface validation failures
  (e.g. the API returns a generic `400` and audits the detail). This is a
  deliberate ergonomic split — see the Gotchas for the obligation it creates.
- **Errors are opaque.** `ConfigError` carries only short summaries to avoid
  leaking filesystem layout or parser internals into logs/responses
  (`src/lib.rs:42-61`).

---

## Gotchas / watch-outs

- **`save()` does NOT auto-validate — and neither does `load()`.** `save`
  (`src/lib.rs:427`) serializes and writes the `Config` **as-is**; `load`
  (`src/lib.rs:421`) parses but does not validate. **Any consumer that persists
  an attacker-influenced config MUST call `validate()` first.** Without it, a
  traversal `db_path`, a SAFE-plugin-with-capabilities, or a `..` security prefix
  could be written to disk and then *trusted* on the next `load`. The dashboard
  API's `put_config` (`routes.rs:414`) does this correctly; a future
  config-edit path that skips the `validate` call would reintroduce exactly the
  problems this crate exists to prevent.

- **`validate_db_path` screens `..` but NOT absolute paths or symlinks.** Its
  only check is for a `ParentDir` (`..`) component
  ([`storage.rs:7`](../wyrtloom/crates/core/src/storage.rs)). An absolute path
  (`/etc/passwd`) passes, and symlinks are not resolved. **Confinement to a
  directory is therefore *not* guaranteed by this crate** — a consumer needing a
  jail must canonicalize and bound-check the path itself.

- **This crate validates structure/policy only; it does not enforce capabilities
  at runtime.** A capability that survives `validate()` is still subject to the
  host's `SecurityModule` checks. Passing validation here means "the config is
  well-formed and policy-consistent", not "this access is permitted".

- **`network_allowlist` is unscreened by design.** Entries are hosts, not paths
  (`src/lib.rs:518-519`); do not assume traversal screening has touched them.

- **`enabled` defaults to `true`.** A `[[plugin]]` with no `enabled` key is
  enabled (`default_true`, `src/lib.rs:210, 216`; test
  `enabled_defaults_to_true`, `src/lib.rs:951`). Disabling a plugin requires an
  explicit `enabled = false`.

[`wyrtloom_core`]: ../wyrtloom/crates/core
[`SecurityPolicy`]: ../wyrtloom/crates/core/src/security.rs
[`PluginManifest`]: ../wyrtloom/crates/core/src/plugin.rs
