from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import NoReturn

from .errors import VaultFormatError

FORMAT = "vaultconfig-secret-v2"
KDF_NAME = "argon2id"
CIPHER_NAME = "xsalsa20-poly1305-secretbox"
INNER_SCHEMA_VERSION = 1

MAX_ENVELOPE_SIZE = 16 * 1024 * 1024
MAX_PLAINTEXT_SIZE = 12 * 1024 * 1024 - 4096
MAX_SECRET_ENTRIES = 4096
MAX_SECRET_NAME_LENGTH = 1024
MIN_OPSLIMIT = 2
MAX_OPSLIMIT = 10
MIN_MEMLIMIT_BYTES = 19 * 1024 * 1024
MAX_MEMLIMIT_BYTES = 256 * 1024 * 1024
SALT_SIZE = 16
NONCE_SIZE = 24
MAC_SIZE = 16
MIN_CIPHERTEXT_SIZE = NONCE_SIZE + MAC_SIZE


class _InvalidJSON(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _InvalidJSON
        result[key] = value
    return result


def _reject_constant(_: str) -> NoReturn:
    raise _InvalidJSON


def _load_json(data: bytes) -> object:
    try:
        text = data.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise VaultFormatError("invalid vault data") from None


def _dump_json(document: object, *, limit: int) -> bytes:
    try:
        data = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise VaultFormatError("invalid vault data") from None
    if len(data) > limit:
        raise VaultFormatError("vault data exceeds size limit")
    return data


def _require_object(value: object, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise VaultFormatError("invalid vault data")
    return value


def _decode_base64(value: object) -> bytes:
    if not isinstance(value, str):
        raise VaultFormatError("invalid vault data")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise VaultFormatError("invalid vault data") from None


def _validate_secret_entries(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > MAX_SECRET_ENTRIES:
        raise VaultFormatError("invalid vault data")
    secrets: dict[str, str] = {}
    for name, secret in value.items():
        if (
            not isinstance(name, str)
            or not name
            or len(name) > MAX_SECRET_NAME_LENGTH
            or not isinstance(secret, str)
        ):
            raise VaultFormatError("invalid vault data")
        secrets[name] = secret
    return secrets


@dataclass(frozen=True, slots=True)
class EnvelopeMetadata:
    salt: bytes
    opslimit: int
    memlimit_bytes: int
    entry_count: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.salt, bytes)
            or len(self.salt) != SALT_SIZE
            or type(self.opslimit) is not int
            or not MIN_OPSLIMIT <= self.opslimit <= MAX_OPSLIMIT
            or type(self.memlimit_bytes) is not int
            or not MIN_MEMLIMIT_BYTES <= self.memlimit_bytes <= MAX_MEMLIMIT_BYTES
            or type(self.entry_count) is not int
            or not 0 <= self.entry_count <= MAX_SECRET_ENTRIES
        ):
            raise VaultFormatError("invalid vault metadata")

    def binding_document(self) -> dict[str, object]:
        return {
            "format": FORMAT,
            "kdf": {
                "name": KDF_NAME,
                "salt": base64.b64encode(self.salt).decode("ascii"),
                "opslimit": self.opslimit,
                "memlimit_bytes": self.memlimit_bytes,
            },
            "cipher": {"name": CIPHER_NAME},
            "entry_count": self.entry_count,
        }


@dataclass(frozen=True, slots=True)
class Envelope:
    metadata: EnvelopeMetadata
    payload: bytes

    def __post_init__(self) -> None:
        if (
            not isinstance(self.payload, bytes)
            or len(self.payload) < MIN_CIPHERTEXT_SIZE
        ):
            raise VaultFormatError("invalid vault data")

    def to_bytes(self) -> bytes:
        document = self.metadata.binding_document()
        cipher = document["cipher"]
        assert isinstance(cipher, dict)
        cipher["payload"] = base64.b64encode(self.payload).decode("ascii")
        return _dump_json(document, limit=MAX_ENVELOPE_SIZE)


def parse_envelope(data: bytes) -> Envelope:
    if not isinstance(data, bytes) or not data or len(data) > MAX_ENVELOPE_SIZE:
        raise VaultFormatError("invalid vault data")
    document = _require_object(
        _load_json(data), {"format", "kdf", "cipher", "entry_count"}
    )
    if document["format"] != FORMAT:
        raise VaultFormatError("unsupported vault format")

    entry_count = document["entry_count"]
    if type(entry_count) is not int or not 0 <= entry_count <= MAX_SECRET_ENTRIES:
        raise VaultFormatError("invalid vault metadata")

    kdf = _require_object(
        document["kdf"], {"name", "salt", "opslimit", "memlimit_bytes"}
    )
    if kdf["name"] != KDF_NAME:
        raise VaultFormatError("unsupported vault KDF")
    salt = _decode_base64(kdf["salt"])

    cipher = _require_object(document["cipher"], {"name", "payload"})
    if cipher["name"] != CIPHER_NAME:
        raise VaultFormatError("unsupported vault cipher")
    payload = _decode_base64(cipher["payload"])

    metadata = EnvelopeMetadata(
        salt=salt,
        opslimit=kdf["opslimit"],  # type: ignore[arg-type]
        memlimit_bytes=kdf["memlimit_bytes"],  # type: ignore[arg-type]
        entry_count=entry_count,
    )
    return Envelope(metadata=metadata, payload=payload)


def encode_plaintext(secrets: Mapping[str, str], metadata: EnvelopeMetadata) -> bytes:
    if not isinstance(secrets, Mapping):
        raise VaultFormatError("invalid vault data")
    entries = _validate_secret_entries(dict(secrets.items()))
    if len(entries) != metadata.entry_count:
        raise VaultFormatError("invalid vault metadata")
    return _dump_json(
        {
            "format": FORMAT,
            "schema_version": INNER_SCHEMA_VERSION,
            "binding": metadata.binding_document(),
            "secrets": entries,
        },
        limit=MAX_PLAINTEXT_SIZE,
    )


def decode_plaintext(data: bytes, metadata: EnvelopeMetadata) -> dict[str, str]:
    if not isinstance(data, bytes) or not data or len(data) > MAX_PLAINTEXT_SIZE:
        raise VaultFormatError("invalid vault data")
    document = _require_object(
        _load_json(data), {"format", "schema_version", "binding", "secrets"}
    )
    if (
        document["format"] != FORMAT
        or type(document["schema_version"]) is not int
        or document["schema_version"] != INNER_SCHEMA_VERSION
        or document["binding"] != metadata.binding_document()
    ):
        raise VaultFormatError("invalid vault data")
    secrets = _validate_secret_entries(document["secrets"])
    if len(secrets) != metadata.entry_count:
        raise VaultFormatError("invalid vault data")
    return secrets
