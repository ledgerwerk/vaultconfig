---
schema_version: 4
id: content-0008
kind: content
type: section
section: cross_cutting_concepts
title: Cross-cutting Concepts
order: 80
status: accepted
version: 2
body_format: markdown
source_refs:
  - vaultconfig/crypt.py
  - vaultconfig/obscure.py
  - vaultconfig/config.py
  - vaultconfig/secrets/crypto.py
  - vaultconfig/secrets/envelope.py
  - vaultconfig/secrets/errors.py
---

| Protection | Scope and boundary |
| --- | --- |
| Obscuring | Reversible concealment of selected strings. It is not encryption and does not provide protection at rest. |
| V1 configuration encryption | PBKDF2-HMAC-SHA256 and NaCl SecretBox protect a complete configuration byte stream. The configuration format is parsed only after decryption. |
| V2 file vault | Argon2id and NaCl SecretBox protect named secret entries. The envelope validates size and KDF bounds before deriving the key. Public metadata includes the entry count, not the names or values. |
| OS keyring | `KeyringVault` delegates storage and access control to the selected native backend. It does not use the V2 envelope. |

Configuration exceptions distinguish format, validation, lookup, and encryption failures. Secret-store exceptions distinguish absence from backend failure: a missing value returns `None`, while an unavailable keyring raises `SecretStoreUnavailableError`.
