# Secret storage API

`vaultconfig.secrets` stores opaque string secrets separately from application
configuration. It provides a passphrase-encrypted file vault and an optional
operating-system keyring backend. It does not replace `ConfigManager`, V1
configuration-file encryption, or password obscuring.

## Installation

`FileVault` is included in the core installation. Install the optional keyring
integration to use `KeyringVault`:

```bash
pip install 'vaultconfig[keyring]'
```

The OS keyring must also be configured and available to the current user session. A
headless or locked session may make it unavailable.

## Shared interface

Both backends implement the `SecretStore` protocol:

```python
from typing import Protocol


class SecretStore(Protocol):
    def get_secret(self, name: str) -> str | None: ...
    def set_secret(self, name: str, value: str) -> None: ...
    def delete_secret(self, name: str) -> bool: ...
```

Names must be non-empty strings of at most 1024 characters. Values must be strings. A
missing secret returns `None`; deleting a missing secret returns `False`. Backend
failures raise `SecretStoreUnavailableError` rather than being treated as missing data.
Secret values are not included in backend error messages.

`FileVault.open()` also returns the optional `CreateOnlySecretStore` protocol, which
adds `create_secret(name, value)` without making it a required member of `SecretStore`.
FileVault checks for an existing name while holding the vault lock, raises
`SecretExistsError` instead of replacing it, and retains stale-revision conflict
protection. `KeyringVault` does not provide atomic create-only semantics.

## Passphrase-encrypted file vault

Create a vault once, then explicitly unlock it for each operation. The application
supplies the passphrase; this API does not read environment variables or prompt
implicitly.

```python
from getpass import getpass
from pathlib import Path
from vaultconfig.secrets import FileVault

vault = FileVault(Path.home() / ".local/share/example/credentials.vault")

# Run only when creating a new vault. Existing files are not overwritten.
vault.initialize(getpass("Choose a vault passphrase: "))

with vault.open(getpass("Unlock the vault: ")) as store:
    store.set_secret("mail:alice@example.net", "application password")
    password = store.get_secret("mail:alice@example.net")
```

Each successful `set_secret` or `delete_secret` is committed immediately using an atomic
replacement. A stale concurrent session cannot silently overwrite a newer update.
Leaving the context closes the logical session and clears its mutable in-memory mapping.
Python cannot guarantee that immutable strings or prior copies are erased from memory.

`FileVault` requires a passphrase, not a short PIN. Argon2id slows offline guessing, but
security still depends on passphrase entropy. Short numeric PINs are not suitable for a
copied vault file. Use a strong master passphrase or an OS/hardware-backed key store
when a short local unlock code is required. New passphrases must be at least 12
characters and no more than 4096 UTF-8 bytes. The passphrase is used exactly as
supplied, without Unicode normalization. A lost passphrase cannot be reset or recovered.
Changing it requires the old passphrase:

```python
vault.change_passphrase(old_passphrase, new_passphrase)
```

Keep a protected backup of the encrypted vault and store its passphrase separately.

### Safe metadata inspection

`vault.inspect()` performs the normal bounded file read, path/permission checks, and V2
metadata validation without decrypting the ciphertext. It returns the format, entry
count, KDF name, operations limit, and memory limit. It does not expose secret names or
values.

```python
info = vault.inspect()
print(info.format, info.entry_count, info.kdf_name)
```

### File protections and limits

On POSIX, VaultConfig creates the containing directory with mode `0700` and vault and
lock files with mode `0600`. Existing directories and files are checked for ownership
and permissions. Recognized symlinks and unsafe paths are rejected. On Windows, this
backend does not audit or change access-control lists; use a directory protected by the
current user's Windows permissions.

The V2 format uses Argon2id and NaCl SecretBox (XSalsa20-Poly1305). VaultConfig pins the
new-vault defaults to 2 operations and 64 MiB of memory. Existing V2 vaults are
decrypted with their stored KDF parameters. The parser rejects KDF settings outside 2 to
10 operations and 19 to 256 MiB before running the KDF. Envelopes are limited to 16 MiB,
plaintext to approximately 12 MiB, and a vault to 4096 entries. Public metadata reveals
the format, KDF settings, salt, and entry count; secret names and values are encrypted.

## OS keyring

`KeyringVault` groups entries under a service name and isolates them by both service and
secret name:

```python
from vaultconfig.secrets import KeyringVault

store = KeyringVault(service="example:mail.example.net")
store.set_secret("alice@example.net", "application password")
password = store.get_secret("alice@example.net")
backend = store.backend_info()
availability = store.probe()
```

The backend must be a supported native keyring backend with positive priority: Secret
Service, KWallet, macOS Keychain, or Windows Vault. `keyrings.alt`, plaintext file
backends, and composite fallback backends are rejected. There is no plaintext fallback.
`backend_info()` returns backend type and name metadata, not secret contents.

`probe()` returns immutable `SecretBackendInfo` data without looking up a secret. A
successful probe reports the accepted native backend family. An unavailable probe
reports one stable reason code: `not-installed`, `no-backend`, `backend-rejected`,
`backend-locked`, or `backend-error`. It includes no secret values or raw backend
exception strings. There is no fallback to file or plaintext storage. `delete_secret()`
calls the backend delete operation directly, returns `False` for a missing entry, and
does not retrieve the secret first. Keyring unlock behavior and process access controls
vary by operating system. A keyring does not necessarily prompt for each read or use
hardware-bound storage.

## Errors, threat boundaries, and recovery

Neither backend protects a secret from malware or a user process that can read it while
the application is running. Keyring protection depends on the selected OS service and
account session. A file vault protects data at rest, but its passphrase and decrypted
values exist in application memory while in use.

File-vault format, unlock, permission, and concurrent-update failures use the public
`VaultError` subclasses. Keyring availability or operation failures raise
`SecretStoreUnavailableError`. There is no VaultConfig recovery path for a lost
file-vault passphrase or lost OS keyring data. Keep backups and passphrases under
separate controls.

## V1 configuration encryption and V2 secret vaults

These are separate formats and APIs:

- **V1 configuration encryption** uses the `VAULTCONFIG_ENCRYPT_V1:` header and protects
  an entire configuration byte stream. `vaultconfig.crypt.encrypt` and
  `vaultconfig.crypt.decrypt` use PBKDF2-HMAC-SHA256 and NaCl SecretBox. Existing V1
  files remain readable; this API does not rewrite them.
- **V2 secret vaults** use the `vaultconfig-secret-v2` envelope and `FileVault`. They
  store named opaque secrets using Argon2id and SecretBox. `KeyringVault` stores entries
  through the selected OS keyring and does not use the V2 file envelope.

A V1 encrypted configuration is not automatically a V2 secret vault. There is no
automatic migration or bulk import. To move a value, decrypt the V1 configuration using
the existing API, select the intended secret explicitly, create and verify a separate V2
vault, and retain a protected backup of the V1 file. Password obscuring through
`vaultconfig.obscure` is not encryption and is not a secret-storage backend.
