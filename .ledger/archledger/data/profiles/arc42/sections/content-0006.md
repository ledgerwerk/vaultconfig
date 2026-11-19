---
schema_version: 4
id: content-0006
kind: content
type: section
section: runtime_view
title: Runtime View
order: 60
status: accepted
version: 2
body_format: markdown
source_refs:
  - vaultconfig/config.py
  - vaultconfig/cli.py
  - vaultconfig/secrets/encrypted_file.py
  - vaultconfig/secrets/fileio.py
---

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
