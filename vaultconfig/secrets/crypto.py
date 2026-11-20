from __future__ import annotations

import os

from nacl import exceptions, secret
from nacl.pwhash import argon2id

from .envelope import (
    Envelope,
    EnvelopeMetadata,
    decode_plaintext,
    encode_plaintext,
    parse_envelope,
)
from .errors import (
    SecretStoreUnavailableError,
    VaultError,
    VaultPassphrasePolicyError,
    VaultUnlockError,
)

DEFAULT_OPSLIMIT = 2
DEFAULT_MEMLIMIT_BYTES = 64 * 1024 * 1024
DEFAULT_MIN_PASSPHRASE_LENGTH = 12
MAX_PASSPHRASE_BYTES = 4096


def encode_passphrase(
    passphrase: str,
    *,
    require_strength: bool,
    min_length: int = DEFAULT_MIN_PASSPHRASE_LENGTH,
) -> bytes:
    if not isinstance(passphrase, str):
        raise VaultError("passphrase must be text")
    if require_strength and len(passphrase) < min_length:
        raise VaultPassphrasePolicyError(
            f"passphrase must be at least {min_length} characters",
            reason="too-short",
            minimum_length=min_length,
        )
    try:
        encoded = passphrase.encode("utf-8")
    except UnicodeEncodeError:
        raise VaultError("passphrase must be valid Unicode text") from None
    if len(encoded) > MAX_PASSPHRASE_BYTES:
        raise VaultPassphrasePolicyError(
            f"passphrase must be no more than {MAX_PASSPHRASE_BYTES} UTF-8 bytes",
            reason="too-large",
            maximum_bytes=MAX_PASSPHRASE_BYTES,
        )
    return encoded


def _derive_key(
    passphrase: bytes,
    salt: bytes,
    opslimit: int,
    memlimit_bytes: int,
) -> bytes:
    try:
        return argon2id.kdf(
            secret.SecretBox.KEY_SIZE,
            passphrase,
            salt,
            opslimit=opslimit,
            memlimit=memlimit_bytes,
        )
    except (ValueError, RuntimeError, MemoryError, OverflowError):
        raise SecretStoreUnavailableError("Argon2id key derivation failed") from None


def encrypt_v2(secrets: dict[str, str], passphrase: bytes) -> bytes:
    salt = os.urandom(argon2id.SALTBYTES)
    metadata = EnvelopeMetadata(
        salt=salt,
        opslimit=DEFAULT_OPSLIMIT,
        memlimit_bytes=DEFAULT_MEMLIMIT_BYTES,
        entry_count=len(secrets),
    )
    plaintext = encode_plaintext(secrets, metadata)
    key = _derive_key(passphrase, salt, DEFAULT_OPSLIMIT, DEFAULT_MEMLIMIT_BYTES)
    try:
        nonce = os.urandom(secret.SecretBox.NONCE_SIZE)
        payload = secret.SecretBox(key).encrypt(plaintext, nonce)
        return Envelope(metadata=metadata, payload=bytes(payload)).to_bytes()
    except (OSError, ValueError, TypeError, RuntimeError, MemoryError):
        raise VaultError("vault encryption failed") from None


def decrypt_v2(data: bytes, passphrase: bytes) -> dict[str, str]:
    envelope = parse_envelope(data)
    key = _derive_key(
        passphrase,
        envelope.metadata.salt,
        envelope.metadata.opslimit,
        envelope.metadata.memlimit_bytes,
    )
    try:
        plaintext = secret.SecretBox(key).decrypt(envelope.payload)
    except (exceptions.CryptoError, ValueError):
        raise VaultUnlockError("vault could not be unlocked") from None
    return decode_plaintext(plaintext, envelope.metadata)
