---
schema_version: 4
id: content-0003
kind: content
type: section
section: context_and_scope
title: Context and Scope
order: 30
status: accepted
version: 2
body_format: markdown
source_refs:
  - vaultconfig/cli.py
  - vaultconfig/config.py
  - vaultconfig/secrets/keyring_store.py
---

VaultConfig runs in the calling application or CLI process. It manages local files and
delegates keyring operations to a supported OS backend. It does not run a service or
provide remote synchronization, shared access policy, or credential recovery.
