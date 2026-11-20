# Security model

VaultConfig has separate mechanisms for reversible password obscuring, V1
configuration-file encryption, and V2 secret storage. They have different formats, APIs,
and threat boundaries.

## Password obscuring is not encryption

`vaultconfig.obscure` uses AES-CTR with a random IV and URL-safe Base64 encoding. The
default key is included in the package. Obscuring is intended only to make casual
viewing less immediate. It does not provide authenticated encryption and does not
protect a file from someone who can read the file and use VaultConfig.

Schema-marked sensitive fields are obscured when saved, and the CLI can explicitly
obscure a value with `set --obscure`. Values are not automatically classified as
sensitive based on their names. A custom obscuring key changes which key is used, but
does not make the feature equivalent to secret storage. If the CLI is configured with an
invalid custom key or an unreadable key file, it fails rather than falling back to the
package key.

## V1 configuration-file encryption

The existing configuration encryption APIs and CLI use the `VAULTCONFIG_ENCRYPT_V1:`
format. They encrypt the configuration byte stream with NaCl SecretBox
(XSalsa20-Poly1305). The encryption key is derived with PBKDF2-HMAC-SHA256 using 600,000
iterations and a random 16-byte salt; each encryption uses a random 24-byte nonce.
SecretBox authenticates the ciphertext, so a wrong password or modified ciphertext does
not yield a valid plaintext configuration.

When loading an encrypted configuration, an in-memory session password takes priority,
followed by `VAULTCONFIG_PASSWORD_<CONFIG_NAME>` and the manager-level password. The CLI
supplies `VAULTCONFIG_PASSWORD` as the manager-level password; a Python caller can pass
`password=` to `ConfigManager`. If no password is available, `crypt.get_password` checks
`VAULTCONFIG_PASSWORD`, then `VAULTCONFIG_PASSWORD_COMMAND`, then prompts when a
terminal is available. The command is parsed into arguments and launched without a
shell, with a 30-second timeout; it supplies the password on standard output. A
configured command that fails or times out raises an error instead of falling through to
a prompt. Commands that create or set a new encryption password use a hidden prompt
unless `--password` is supplied.

`crypt.get_password(changing=True)` sets `VAULTCONFIG_PASSWORD_CHANGE=1` in the
password-command process environment. The current CLI's new-password prompts are handled
separately.

`VAULTCONFIG_DIR` selects the default CLI configuration directory.
`VAULTCONFIG_CIPHER_KEY` and `VAULTCONFIG_CIPHER_KEY_FILE` configure the CLI's obscurer
key; when both are set, the key file is used. These variables affect obscuring, not V1
encryption or `FileVault`.

## V2 file vault and OS keyring

`FileVault` stores named string secrets in the V2 envelope, using Argon2id and NaCl
SecretBox. Secret names and values are encrypted, while format metadata, KDF parameters,
salt, and entry count remain visible. New passphrases use a configurable minimum-length
policy, defaulting to 12 characters; the policy applies to initialization and passphrase
changes, not to opening an existing vault. Vault files are size-limited and validate KDF
parameters before running the KDF. See {doc}`secrets` for the exact limits, file
permissions, locking, errors, and recovery behavior.

`KeyringVault` delegates storage to an accepted native OS keyring backend. VaultConfig
rejects plaintext and composite fallback backends, but the operating system's keyring
policy and session behavior still determine the protection provided. Installing the
Python `keyring` extra does not create or unlock an OS keyring.

Neither backend protects a value from malware or another process that can access it
while the application is using the secret. Decrypted values also exist in application
memory. Keep backups and credentials under separate controls; VaultConfig has no
recovery mechanism for a lost file-vault passphrase or lost keyring data.

## Filesystem behavior and limits

Configuration writes use a private temporary file and atomic replacement. On POSIX,
these temporary and resulting files are created with restrictive owner-only permissions.
Temporary-file cleanup is best effort. Overwriting and unlinking a file cannot guarantee
physical erasure on SSDs, copy-on-write filesystems, snapshots, or journaled storage, so
VaultConfig does not claim secure deletion.

The file-vault backend additionally checks paths and permissions, uses a lock, and
detects stale concurrent updates. Its Windows backend does not audit or change
access-control lists; protect the containing directory with Windows permissions.

## Keep formats separate

V1 encrypted configuration files, V2 `FileVault` files, OS keyring entries, and obscured
strings are not interchangeable. There is no automatic migration from a configuration
file or an obscured value into a secret store. Select each value deliberately, write it
to the new store, verify it, and retain an appropriately protected backup before
removing the original.
