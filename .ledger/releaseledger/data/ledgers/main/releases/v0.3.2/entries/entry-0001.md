---
schema_version: 2
object_type: release_entry
versioning:
  schema_version: 1
  revision: 1
entry_id: entry-0001
release_version: v0.3.2
kind: added
summary: Added a configurable FileVault minimum passphrase length, defaulting to 12,
  with structured policy errors
status: accepted
audience: null
scopes: []
source_refs:
- git:6562c616b405a383dce5bcc47c05d56ab0a7fb88
paths:
- README.md
- docs/api.md
- docs/changelog.md
- docs/secrets.md
- docs/security.md
- tests/test_secrets_file.py
- vaultconfig/secrets/__init__.py
- vaultconfig/secrets/crypto.py
- vaultconfig/secrets/encrypted_file.py
- vaultconfig/secrets/errors.py
issues: []
prs: []
sources:
- git:6562c616b405a383dce5bcc47c05d56ab0a7fb88
contributors:
- '@holgern'
breaking: false
internal: false
order: 1
---
