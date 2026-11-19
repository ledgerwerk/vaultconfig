---
schema_version: 4
id: content-0010
kind: content
type: section
section: quality_requirements
title: Quality Requirements
order: 100
status: accepted
version: 2
body_format: markdown
source_refs:
  - tests/test_config.py
  - tests/test_crypt.py
  - tests/test_formats.py
  - tests/test_secrets_envelope.py
  - tests/test_secrets_file.py
  - tests/test_secrets_keyring.py
  - .github/workflows/tests.yml
---

The test suite exercises configuration and format behavior, V1 encryption, strict V2 envelope parsing, file-vault persistence, and keyring backend selection. CI runs the suite on Linux, Windows, and macOS across Python 3.10 through 3.14.

| Scenario | Expected result |
| --- | --- |
| A caller reloads an existing V1 file with the correct password. | The manager returns the parsed configuration without converting its encryption format. |
| Two unlocked file-vault sessions attempt to modify the same vault. | Once one session writes an update, the stale session raises `VaultConflictError` rather than overwriting it. |
| The OS keyring is unavailable or unsupported. | The operation raises `SecretStoreUnavailableError` rather than reporting a missing secret or falling back to plaintext. |
