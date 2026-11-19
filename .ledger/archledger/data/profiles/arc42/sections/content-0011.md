---
schema_version: 4
id: content-0011
kind: content
type: section
section: risks_and_technical_debt
title: Risks and Technical Debt
order: 110
status: accepted
version: 2
body_format: markdown
source_refs:
  - vaultconfig/config.py
  - vaultconfig/cli.py
  - vaultconfig/secrets/encrypted_file.py
  - vaultconfig/secrets/keyring_store.py
---

- **Runtime exposure:** Decrypted values exist in the calling process. Closing a file-vault session clears its mapping but cannot guarantee wiping Python strings or copies. Treat rendered output and child-process environments as disclosures when they include sensitive values.
- **Recovery:** A lost file-vault passphrase cannot be reset. Keep a protected encrypted backup and retain the passphrase under separate controls. Keyring availability and recovery depend on the OS backend.
- **Multi-file scope:** Manager-level encryption changes act on loaded entries. Auto-loading logs individual failures and can leave entries unloaded. Verify the expected file set and encryption status before and after a bulk change.
