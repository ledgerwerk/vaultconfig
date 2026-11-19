---
schema_version: 2
object_type: release_entry
versioning:
  schema_version: 1
  revision: 1
entry_id: entry-0001
release_version: v0.3.0
kind: added
summary:
  Added `FileVault` and optional `KeyringVault` for storing named secrets outside
  configuration files
status: accepted
audience: null
scopes: []
source_refs:
  - git:fb129f37310f17ec4fba7a57ff2e9415dac3a3aa
paths:
  - vaultconfig/secrets/encrypted_file.py
  - vaultconfig/secrets/keyring_store.py
  - docs/secrets.md
issues: []
prs: []
sources: []
contributors: []
breaking: false
internal: false
order: 1
---

Install `vaultconfig[keyring]` for OS keyring support. Existing V1 encrypted
configuration files remain readable and are not migrated automatically.
