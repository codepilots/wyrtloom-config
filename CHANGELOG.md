# Changelog

All notable changes to `wyrtloom-config` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-06-14

### Added

- Initial release.
- `wyrtloom.toml` schema with a `[security]` table and `[[plugin]]` entries.
- `load(path)` / `save(path, &cfg)` and `from_str` / `to_string` for file- and
  string-based (de)serialisation.
- `validate(&cfg)`: deterministic validation against the v0.1 core contracts
  (plugin-name rules, safe-plugin capability ban, recursive `..`-traversal
  screening of capability paths and all `settings` string values, and
  contract-version compatibility via `CoreContractVersions::v0_1()`).
- Strict parsing: canonical `MAJOR.MINOR.PATCH` version strings (no signs or
  leading zeros) and `deny_unknown_fields` on the structured tables so a typo'd,
  security-relevant key is a hard error instead of a silent default.
- Typed `Config`, `SecuritySection`, and `PluginEntry` (`manifest` + `enabled`
  + free-form `settings`) reusing `wyrtloom-core` types throughout
  (`SecurityPolicy`, `PluginManifest`, `Capability`, `PluginClass`, `SemVer`).
- Opaque `ConfigError` error type.
