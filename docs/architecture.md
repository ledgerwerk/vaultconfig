---
title: "Architecture Documentation"
version: 2
generator: "archledger 0.4.0"
arc42_template_version: "9.0-EN"
---

# Architecture Documentation

Generated from archledger records. Do not edit this generated file directly.

# Introduction and Goals

VaultConfig is a Python library and local CLI for managing named application
configurations, validating their contents, and optionally encrypting configuration files
at rest. It also provides a separate Python API for storing individual named secrets
without embedding them in application configuration.

Application developers use the Python API to load validated settings and retrieve
secrets. Operators use the CLI to inspect, modify, encrypt, and export configuration or
supply it to a child process. Maintainers need changes to preserve compatibility with
existing configuration files and keep optional integrations isolated.

## Requirements Overview

<!-- archledger: no accepted records for this section yet -->

## Quality Goals

<!-- archledger: no accepted records for this section yet -->

## Stakeholders

<!-- archledger: no accepted records for this section yet -->

# Architecture Constraints

- The package supports Python 3.10 and later. TOML and INI are available in the core
  install. YAML requires the `yaml` extra.
- A `ConfigManager` uses one format per instance. The config name is the file stem, and
  the format handler supplies the allowed extensions. JSON is supported by shared
  mapping I/O, not as a managed configuration format.
- V1 configuration files and V2 secret vaults have separate wire formats. Neither
  implementation automatically migrates data to the other.

<!-- archledger: no accepted records for this section yet -->

# Context and Scope

VaultConfig runs in the calling application or CLI process. It manages local files and
delegates keyring operations to a supported OS backend. It does not run a service or
provide remote synchronization, shared access policy, or credential recovery.

## Business Context

<!-- archledger: no accepted records for this section yet -->

## Technical Context

<!-- archledger: no accepted records for this section yet -->

# Solution Strategy

The configuration path normalizes format-specific input to Python mappings, optionally
validates those mappings against a schema, and serializes them independently of
encryption. The secret-storage path instead exposes a small `SecretStore` protocol for
named strings. This keeps callers independent of the selected secret backend without
coupling secret storage to configuration parsing.

## Strategy Items

<!-- archledger: no accepted records for this section yet -->

# Building Block View

| Component                         | Responsibility                                                                                                                                                 |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `vaultconfig.cli`                 | Click entry point for configuration management, import and export, encryption, and process launch.                                                             |
| `ConfigManager` and `ConfigEntry` | Resolve and persist named files, cache loaded entries, and read values by dotted path.                                                                         |
| `formats` and `io`                | Adapt TOML, INI, and optional YAML to mappings. Shared I/O handles JSON as well.                                                                               |
| `schema`                          | Wrap Pydantic validation and identify sensitive paths, including nested fields.                                                                                |
| `crypt` and `obscure`             | Encrypt complete configuration byte streams or reversibly conceal selected string values, respectively.                                                        |
| `env_export`                      | Flatten and filter configuration values and format them for shell export or use in a child process.                                                            |
| `secrets`                         | Define `SecretStore`, implement `FileVault` and `KeyringVault`, and keep envelope parsing, cryptography, and filesystem handling separate from the public API. |

<!-- archledger: no accepted records for this section yet -->

# Runtime View

1. **Load a configuration.** `ConfigManager` resolves the configured name and extension,
   reads the bytes, decrypts V1 data if present, parses with the selected format
   handler, and validates with the optional schema before caching a `ConfigEntry`.
2. **Save a configuration.** The manager validates the mapping, obscures schema-marked
   strings when requested, serializes the result, and encrypts it if a password is
   configured. It writes a temporary file beside the destination and replaces the
   destination atomically.
3. **Update a file vault.** The caller supplies the passphrase to `FileVault.open()`. A
   modifying operation checks under the vault lock that the file still matches the
   unlocked session's snapshot, writes a new encrypted envelope by atomic replacement,
   and rejects stale sessions. Leaving the context closes the session.

<!-- archledger: no accepted records for this section yet -->

# Deployment View

Install `vaultconfig` into the application environment. The same package exposes the
`vaultconfig` console script. No database or server deployment is required.

- **Configuration files:** The CLI chooses an explicit directory first, then
  `VAULTCONFIG_DIR`, then the platform default. Defaults use `APPDATA` on Windows or
  `XDG_CONFIG_HOME` on other platforms when set, with home-directory fallbacks. Python
  callers pass the directory directly to `ConfigManager`.
- **File vault:** The application chooses a writable, protected directory. The backend
  checks ownership and permissions on POSIX. On Windows, the deployment must supply
  appropriate access controls.
- **OS keyring:** Install the `keyring` extra and provide a supported native backend in
  the current user session. An unavailable or unsupported backend fails rather than
  falling back to plaintext.

<!-- archledger: no accepted records for this section yet -->

# Cross-cutting Concepts

| Protection                  | Scope and boundary                                                                                                                                                                               |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Obscuring                   | Reversible concealment of selected strings. It is not encryption and does not provide protection at rest.                                                                                        |
| V1 configuration encryption | PBKDF2-HMAC-SHA256 and NaCl SecretBox protect a complete configuration byte stream. The configuration format is parsed only after decryption.                                                    |
| V2 file vault               | Argon2id and NaCl SecretBox protect named secret entries. The envelope validates size and KDF bounds before deriving the key. Public metadata includes the entry count, not the names or values. |
| OS keyring                  | `KeyringVault` delegates storage and access control to the selected native backend. It does not use the V2 envelope.                                                                             |

Configuration exceptions distinguish format, validation, lookup, and encryption
failures. Secret-store exceptions distinguish absence from backend failure: a missing
value returns `None`, while an unavailable keyring raises `SecretStoreUnavailableError`.

<!-- archledger: no accepted records for this section yet -->

# Architecture Decisions

These decisions describe the current implementation:

| Decision                                                         | Consequence                                                                                                                                          |
| ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Keep format handling behind adapters.                            | The manager can share validation and encryption across formats. Supported types and round-trip behavior still depend on the selected adapter.        |
| Keep V1 encrypted configuration separate from V2 secret storage. | Existing configurations remain readable. Moving credentials into a secret vault requires an explicit application or operator workflow.               |
| Update local files through atomic replacement.                   | Each replacement is atomic. Multi-file configuration updates use backups and best-effort rollback rather than a single atomic directory transaction. |

<!-- archledger: no accepted records for this section yet -->

# Quality Requirements

The test suite exercises configuration and format behavior, V1 encryption, strict V2
envelope parsing, file-vault persistence, and keyring backend selection. CI runs the
suite on Linux, Windows, and macOS across Python 3.10 through 3.14.

| Scenario                                                           | Expected result                                                                                                         |
| ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| A caller reloads an existing V1 file with the correct password.    | The manager returns the parsed configuration without converting its encryption format.                                  |
| Two unlocked file-vault sessions attempt to modify the same vault. | Once one session writes an update, the stale session raises `VaultConflictError` rather than overwriting it.            |
| The OS keyring is unavailable or unsupported.                      | The operation raises `SecretStoreUnavailableError` rather than reporting a missing secret or falling back to plaintext. |

## Quality Requirements Overview

<!-- archledger: no accepted records for this section yet -->

## Quality Scenarios

<!-- archledger: no accepted records for this section yet -->

# Risks and Technical Debt

- **Runtime exposure:** Decrypted values exist in the calling process. Closing a
  file-vault session clears its mapping but cannot guarantee wiping Python strings or
  copies. Treat rendered output and child-process environments as disclosures when they
  include sensitive values.
- **Recovery:** A lost file-vault passphrase cannot be reset. Keep a protected encrypted
  backup and retain the passphrase under separate controls. Keyring availability and
  recovery depend on the OS backend.
- **Multi-file scope:** Manager-level encryption changes act on loaded entries.
  Auto-loading logs individual failures and can leave entries unloaded. Verify the
  expected file set and encryption status before and after a bulk change.

## Risk Overview

<!-- archledger: no accepted records for this section yet -->

# Glossary

| Term           | Meaning                                                                                      |
| -------------- | -------------------------------------------------------------------------------------------- |
| Config entry   | A named configuration mapping held by `ConfigManager`.                                       |
| Sensitive path | A schema-derived dotted path that identifies a value for optional obscuring.                 |
| Secret store   | A backend that reads, writes, and deletes opaque string values by name.                      |
| Envelope       | The versioned on-disk representation of a V2 file vault, containing metadata and ciphertext. |

<!-- archledger: no accepted records for this section yet -->
