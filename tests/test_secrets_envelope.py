from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from vaultconfig.secrets import (
    FileVaultInfo,
    SecretBackendInfo,
    SecretExistsError,
    SecretStore,
    VaultError,
    VaultFormatError,
)
from vaultconfig.secrets.envelope import (
    CIPHER_NAME,
    FORMAT,
    KDF_NAME,
    MAX_ENVELOPE_SIZE,
    MAX_SECRET_ENTRIES,
    Envelope,
    EnvelopeMetadata,
    decode_plaintext,
    encode_plaintext,
    parse_envelope,
)


@pytest.fixture
def metadata() -> EnvelopeMetadata:
    return EnvelopeMetadata(
        salt=b"s" * 16,
        opslimit=2,
        memlimit_bytes=64 * 1024 * 1024,
        entry_count=1,
    )


def _envelope_document(metadata: EnvelopeMetadata) -> dict[str, object]:
    return {
        **metadata.binding_document(),
        "cipher": {"name": CIPHER_NAME, "payload": ""},
    }


def test_secret_store_is_a_runtime_protocol() -> None:
    class Store:
        def get_secret(self, name: str) -> str | None:
            return None

        def set_secret(self, name: str, value: str) -> None:
            pass

        def delete_secret(self, name: str) -> bool:
            return False

    assert isinstance(Store(), SecretStore)


def test_importing_secret_api_does_not_load_cli_or_optional_dependencies() -> None:
    script = (
        "import sys; from vaultconfig.secrets import KeyringVault; "
        "blocked = {'click', 'rich', 'pydantic', 'keyring', 'vaultconfig.cli'}; "
        "loaded = blocked.intersection(sys.modules); "
        "assert not loaded, loaded"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).parents[1],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_envelope_and_inner_payload_roundtrip_are_deterministic(
    metadata: EnvelopeMetadata,
) -> None:
    envelope = Envelope(metadata=metadata, payload=b"p" * 40)
    encoded = envelope.to_bytes()

    assert parse_envelope(encoded) == envelope
    assert envelope.to_bytes() == encoded

    plaintext = encode_plaintext({"imap/account": "private-value"}, metadata)
    assert decode_plaintext(plaintext, metadata) == {"imap/account": "private-value"}
    assert encode_plaintext({"imap/account": "private-value"}, metadata) == plaintext


def test_envelope_rejects_duplicate_json_keys() -> None:
    duplicate = (
        b'{"format":"vaultconfig-secret-v2","format":"vaultconfig-secret-v2",'
        b'"kdf":{},"cipher":{},"entry_count":0}'
    )
    with pytest.raises(VaultFormatError, match="invalid vault data"):
        parse_envelope(duplicate)


def test_envelope_rejects_unknown_fields(metadata: EnvelopeMetadata) -> None:
    document = _envelope_document(metadata)
    document["unexpected"] = True
    with pytest.raises(VaultFormatError):
        parse_envelope(json.dumps(document).encode())


def test_envelope_rejects_unsupported_format_and_algorithms(
    metadata: EnvelopeMetadata,
) -> None:
    document = _envelope_document(metadata)
    document["format"] = "vaultconfig-secret-v1"
    with pytest.raises(VaultFormatError, match="unsupported vault format"):
        parse_envelope(json.dumps(document).encode())

    document = _envelope_document(metadata)
    kdf = document["kdf"]
    assert isinstance(kdf, dict)
    kdf["name"] = "unknown-kdf"
    with pytest.raises(VaultFormatError, match="unsupported vault KDF"):
        parse_envelope(json.dumps(document).encode())

    document = _envelope_document(metadata)
    cipher = document["cipher"]
    assert isinstance(cipher, dict)
    cipher["name"] = "unknown-cipher"
    with pytest.raises(VaultFormatError, match="unsupported vault cipher"):
        parse_envelope(json.dumps(document).encode())


def test_envelope_rejects_invalid_kdf_and_entry_bounds(
    metadata: EnvelopeMetadata,
) -> None:
    document = _envelope_document(metadata)
    kdf = document["kdf"]
    assert isinstance(kdf, dict)
    kdf["opslimit"] = 1
    with pytest.raises(VaultFormatError):
        parse_envelope(json.dumps(document).encode())

    document = _envelope_document(metadata)
    kdf = document["kdf"]
    assert isinstance(kdf, dict)
    kdf["memlimit_bytes"] = 1
    with pytest.raises(VaultFormatError):
        parse_envelope(json.dumps(document).encode())

    document = _envelope_document(metadata)
    document["entry_count"] = MAX_SECRET_ENTRIES + 1
    with pytest.raises(VaultFormatError):
        parse_envelope(json.dumps(document).encode())


def test_envelope_rejects_invalid_base64_and_short_ciphertext(
    metadata: EnvelopeMetadata,
) -> None:
    document = _envelope_document(metadata)
    cipher = document["cipher"]
    assert isinstance(cipher, dict)
    cipher["payload"] = "!"
    with pytest.raises(VaultFormatError):
        parse_envelope(json.dumps(document).encode())

    with pytest.raises(VaultFormatError):
        Envelope(metadata=metadata, payload=b"short")


def test_envelope_rejects_oversized_input() -> None:
    with pytest.raises(VaultFormatError):
        parse_envelope(b" " * (MAX_ENVELOPE_SIZE + 1))


def test_plaintext_rejects_binding_entry_count_and_duplicate_key_mismatches(
    metadata: EnvelopeMetadata,
) -> None:
    with pytest.raises(VaultFormatError):
        encode_plaintext({}, metadata)

    valid = json.loads(encode_plaintext({"imap/account": "private-value"}, metadata))
    valid["binding"]["entry_count"] = 0
    with pytest.raises(VaultFormatError):
        decode_plaintext(json.dumps(valid).encode(), metadata)

    duplicate_secret = (
        b'{"format":"vaultconfig-secret-v2","schema_version":1,'
        b'"binding":{},"secrets":{"mail":"first","mail":"second"}}'
    )
    with pytest.raises(VaultFormatError):
        decode_plaintext(duplicate_secret, metadata)


def test_secret_validation_does_not_echo_secret_values(
    metadata: EnvelopeMetadata,
) -> None:
    secret = "never-include-this-value"
    with pytest.raises(VaultFormatError) as raised:
        encode_plaintext({"": secret}, metadata)
    assert secret not in str(raised.value)


def test_metadata_rejects_boolean_integer_parameters() -> None:
    with pytest.raises(VaultFormatError):
        EnvelopeMetadata(
            salt=b"s" * 16,
            opslimit=True,
            memlimit_bytes=64 * 1024 * 1024,
            entry_count=0,
        )


def test_supported_format_constants() -> None:
    assert FORMAT == "vaultconfig-secret-v2"
    assert KDF_NAME == "argon2id"


def test_public_diagnostic_types_and_secret_exists_error() -> None:
    from vaultconfig import secrets as secrets_api

    backend_info = SecretBackendInfo(
        kind="keyring",
        available=False,
        backend=None,
        reason="not-installed",
    )
    file_info = FileVaultInfo(
        format="vaultconfig-secret-v2",
        entry_count=3,
        kdf_name="argon2id",
        opslimit=2,
        memlimit_bytes=64 * 1024 * 1024,
    )

    assert backend_info.reason == "not-installed"
    assert file_info.entry_count == 3
    assert not hasattr(backend_info, "__dict__")
    with pytest.raises(AttributeError):
        backend_info.reason = "backend-error"  # type: ignore[misc]
    assert issubclass(SecretExistsError, VaultError)
    assert {
        "FileVaultInfo",
        "SecretBackendInfo",
        "SecretExistsError",
    }.issubset(secrets_api.__all__)
    assert "encrypt_v2" not in secrets_api.__all__
    assert not hasattr(SecretStore, "create_secret")
