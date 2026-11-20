---
schema_version: 2
object_type: release_entry
versioning:
  schema_version: 1
  revision: 2
entry_id: entry-0003
release_version: v0.3.1
kind: changed
summary:
  Changed KeyringVault to probe backend availability without secrets and delete without
  a pre-read
status: accepted
audience: null
scopes: []
source_refs: []
paths:
  - vaultconfig/secrets/keyring_store.py
  - tests/test_secrets_keyring.py
issues: []
prs: []
sources:
  - tl:task-0004
contributors: []
breaking: false
internal: false
order: 3
---
