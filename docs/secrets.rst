Secret Storage API
==================

``vaultconfig.secrets`` is a programmatic API for storing opaque string secrets
separately from application configuration. It provides a passphrase-encrypted
file vault and an optional operating-system keyring backend. It does not change
or replace ``ConfigManager``, configuration-file encryption, or password
obscuring.

Install
-------

``FileVault`` is available with the normal VaultConfig installation. Install the
optional Python keyring integration when using ``KeyringVault``::

   pip install 'vaultconfig[keyring]'

The OS keyring itself must be configured and available to the current user
session. A headless or locked session can make it unavailable.

Common API
----------

Both backends implement the ``SecretStore`` protocol. Secret names must be
non-empty strings of at most 1024 characters, and values must be strings. A
missing value returns ``None``; deleting a missing value returns ``False``.
Backend failures raise ``SecretStoreUnavailableError`` instead of being treated
as missing data. Secret values are never used as error messages.

Passphrase-encrypted file vault
-------------------------------

Create a vault once, then explicitly unlock it for each operation. The library
does not look up a passphrase in environment variables or prompt implicitly.
The calling application should acquire the passphrase through its own trusted
interaction, for example with ``getpass``::

   from getpass import getpass
   from pathlib import Path

   from vaultconfig.secrets import FileVault

   vault = FileVault(
       Path.home() / ".local" / "share" / "example" / "credentials.vault"
   )

   # Run only when creating a new vault. This refuses to overwrite an existing one.
   vault.initialize(getpass("Choose a vault passphrase: "))

   with vault.open(getpass("Unlock the vault: ")) as secrets:
       secrets.set_secret("mail:alice@example.net", "application password")
       password = secrets.get_secret("mail:alice@example.net")

Each successful ``set_secret`` or ``delete_secret`` is committed immediately
using an atomic replacement. Concurrent stale sessions cannot silently
overwrite a newer update. Leaving the context closes the logical session and
clears its mutable in-memory mapping. Python cannot guarantee that immutable
strings or prior copies are erased from memory.

New vault passphrases must be at least 12 characters and no more than 4096
UTF-8 bytes. The passphrase is used exactly as supplied, without Unicode
normalization. A lost passphrase cannot be reset or recovered. Changing it
requires the old passphrase. Keep a protected backup of the encrypted vault and
store its passphrase separately.

On POSIX, VaultConfig creates the containing directory with mode ``0700`` and
the vault and lock files with mode ``0600``. Existing directories and files are
checked for ownership and permissions. Recognized symlinks and unsafe paths are
rejected. Windows access-control lists are not audited or changed by this
backend; use a directory protected by the current user's Windows permissions.

The V2 file format uses Argon2id and NaCl SecretBox (XSalsa20-Poly1305). The
default Argon2id profile uses 2 operations and 64 MiB of memory. The parser
rejects KDF settings outside 2 to 10 operations and 19 to 256 MiB before
running the KDF. Envelopes are limited to 16 MiB, plaintext to approximately
12 MiB, and a vault to 4096 entries. The public metadata reveals the format,
KDF settings, salt, and entry count; secret names and values are encrypted.

OS keyring
----------

``KeyringVault`` groups entries under the supplied service name and isolates
entries by both service and secret name::

   from vaultconfig.secrets import KeyringVault

   store = KeyringVault(service="imapledger:mail.example.net:993")
   store.set_secret("alice@example.net", "application password")
   password = store.get_secret("alice@example.net")
   backend = store.backend_info()

The backend must be a supported native keyring backend with positive priority:
Secret Service, KWallet, macOS Keychain, or Windows Vault. ``keyrings.alt``,
plaintext file backends, and composite fallback backends are rejected. There is
no plaintext fallback. ``backend_info()`` returns backend type/name metadata,
not secret contents. Keyring unlock behavior and process access controls vary by
operating system; a keyring does not necessarily prompt for each read or use
hardware-bound storage.

Security limits and recovery
----------------------------

Neither backend protects a secret from malware or a user process that can read
it while the application is running. Keyring protection depends on the selected
OS service and account session. A file vault protects data at rest, but its
passphrase and decrypted values exist in application memory while in use.
Keep backups and passphrases under separate controls. Losing the file-vault
passphrase, or losing the OS keyring data, has no VaultConfig recovery path.

V1 configuration encryption and V2 secret vaults
-------------------------------------------------

These are separate formats and APIs:

* **V1 configuration encryption** uses the ``VAULTCONFIG_ENCRYPT_V1:`` header
  and protects an entire configuration byte stream. The existing
  ``vaultconfig.crypt.encrypt`` and ``vaultconfig.crypt.decrypt`` APIs continue
  to use PBKDF2-HMAC-SHA256 and NaCl SecretBox. Existing V1 files remain
  readable; this feature does not rewrite them.
* **V2 secret vaults** use the ``vaultconfig-secret-v2`` envelope and the
  ``FileVault`` API. They store named opaque secrets using Argon2id and SecretBox.
  ``KeyringVault`` stores entries through the selected OS keyring and does not
  use the V2 file envelope.

A V1 encrypted configuration is not automatically a V2 secret vault. There is
no automatic migration or bulk import. If moving a value, decrypt the V1
configuration using the existing API, select the intended secret explicitly,
create and verify a separate V2 vault, and retain a protected backup of the V1
file. Password obscuring through ``vaultconfig.obscure`` is not encryption and
is not a secret-storage backend.
