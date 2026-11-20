from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path

import pytest

from vaultconfig.secrets import (
    CreateOnlySecretStore,
    FileVault,
    FileVaultInfo,
    SecretExistsError,
    VaultConflictError,
    VaultError,
    VaultFormatError,
    VaultLockedError,
    VaultPermissionError,
    VaultUnlockError,
)
from vaultconfig.secrets.crypto import (
    DEFAULT_MEMLIMIT_BYTES,
    DEFAULT_OPSLIMIT,
)

PASSPHRASE = "a sufficiently long example passphrase"


def test_file_vault_initialize_roundtrip_and_idempotent_delete(tmp_path: Path) -> None:
    path = tmp_path / "private" / "credentials.vault"
    vault = FileVault(path)
    vault.initialize(PASSPHRASE)

    with vault.open(PASSPHRASE) as store:
        assert store.get_secret("mail") is None
        store.set_secret("mail", "opaque-secret")
        assert store.get_secret("mail") == "opaque-secret"
        assert store.delete_secret("missing") is False
        assert store.delete_secret("mail") is True
        assert store.delete_secret("mail") is False

    with vault.open(PASSPHRASE) as store:
        assert store.get_secret("mail") is None

    assert b"opaque-secret" not in path.read_bytes()
    with pytest.raises(VaultConflictError):
        vault.initialize(PASSPHRASE)


def test_each_file_write_uses_fresh_randomization(tmp_path: Path) -> None:
    vault = FileVault(tmp_path / "credentials.vault")
    vault.initialize(PASSPHRASE)

    with vault.open(PASSPHRASE) as store:
        store.set_secret("mail", "same-value")
    first = vault.path.read_bytes()
    with vault.open(PASSPHRASE) as store:
        store.set_secret("mail", "same-value")
    second = vault.path.read_bytes()

    assert first != second


def test_each_encryption_uses_a_fresh_salt_and_nonce(tmp_path: Path) -> None:
    vault = FileVault(tmp_path / "credentials.vault")
    vault.initialize(PASSPHRASE)
    first = json.loads(vault.path.read_bytes())

    with vault.open(PASSPHRASE) as store:
        store.set_secret("mail", "same-value")
    second = json.loads(vault.path.read_bytes())

    first_salt = base64.b64decode(first["kdf"]["salt"])
    second_salt = base64.b64decode(second["kdf"]["salt"])
    first_nonce = base64.b64decode(first["cipher"]["payload"])[:24]
    second_nonce = base64.b64decode(second["cipher"]["payload"])[:24]

    assert first_salt != second_salt
    assert first_nonce != second_nonce


def test_failed_atomic_replace_preserves_previous_vault(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault = FileVault(tmp_path / "credentials.vault")
    vault.initialize(PASSPHRASE)
    with vault.open(PASSPHRASE) as store:
        store.set_secret("mail", "old-value")
    original = vault.path.read_bytes()

    def fail_replace(
        source: str | os.PathLike[str],
        target: str | os.PathLike[str],
    ) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr("vaultconfig.secrets.fileio.os.replace", fail_replace)
    with vault.open(PASSPHRASE) as store:
        with pytest.raises(VaultError, match="could not write vault file"):
            store.set_secret("mail", "new-value")
        assert store.get_secret("mail") == "old-value"

    assert vault.path.read_bytes() == original
    assert list(vault.path.parent.glob(".credentials.vault.*.tmp")) == []


def test_atomic_replacement_uses_a_private_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault = FileVault(tmp_path / "credentials.vault")
    vault.initialize(PASSPHRASE)
    original_replace = os.replace
    replacement_modes: list[int] = []

    def record_replace(
        source: str | os.PathLike[str],
        target: str | os.PathLike[str],
    ) -> None:
        replacement_modes.append(stat.S_IMODE(Path(source).stat().st_mode))
        original_replace(source, target)

    monkeypatch.setattr("vaultconfig.secrets.fileio.os.replace", record_replace)
    with vault.open(PASSPHRASE) as store:
        store.set_secret("mail", "secret")

    assert len(replacement_modes) == 1
    if os.name == "posix":
        assert replacement_modes == [0o600]


def test_file_vault_requires_explicit_strong_passphrase(tmp_path: Path) -> None:
    vault = FileVault(tmp_path / "credentials.vault")
    with pytest.raises(VaultError, match="minimum length"):
        vault.initialize("short")
    assert not vault.path.exists()


def test_wrong_passphrase_and_ciphertext_tampering_have_uniform_unlock_errors(
    tmp_path: Path,
) -> None:
    path = tmp_path / "credentials.vault"
    vault = FileVault(path)
    vault.initialize(PASSPHRASE)

    with (
        pytest.raises(VaultUnlockError) as wrong,
        vault.open("a different sufficiently long passphrase"),
    ):
        pass

    document = json.loads(path.read_bytes())
    cipher = document["cipher"]
    payload = bytearray(base64.b64decode(cipher["payload"]))
    payload[-1] ^= 1
    cipher["payload"] = base64.b64encode(payload).decode("ascii")
    path.write_text(json.dumps(document), encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(VaultUnlockError) as tampered, vault.open(PASSPHRASE):
        pass
    assert str(wrong.value) == str(tampered.value)


def test_file_vault_passphrase_change_reencrypts_and_uses_exact_unicode(
    tmp_path: Path,
) -> None:
    path = tmp_path / "credentials.vault"
    vault = FileVault(path)
    old_passphrase = "é" * 12
    new_passphrase = "new distinct long passphrase"
    vault.initialize(old_passphrase)
    with vault.open(old_passphrase) as store:
        store.set_secret("mail", "secret")

    old_contents = path.read_bytes()
    vault.change_passphrase(old_passphrase, new_passphrase)
    assert path.read_bytes() != old_contents
    with pytest.raises(VaultUnlockError), vault.open(old_passphrase):
        pass
    with vault.open(new_passphrase) as store:
        assert store.get_secret("mail") == "secret"

    decomposed = "e\u0301" * 12
    with pytest.raises(VaultUnlockError), vault.open(decomposed):
        pass


def test_open_store_repr_and_closed_session_do_not_expose_secrets(
    tmp_path: Path,
) -> None:
    path = tmp_path / "credentials.vault"
    vault = FileVault(path)
    vault.initialize(PASSPHRASE)

    with vault.open(PASSPHRASE) as store:
        store.set_secret("mail", "do-not-print-this")
        assert "do-not-print-this" not in repr(store)
    with pytest.raises(VaultLockedError):
        store.get_secret("mail")


def test_file_vault_rejects_stale_concurrent_session(tmp_path: Path) -> None:
    vault = FileVault(tmp_path / "credentials.vault")
    vault.initialize(PASSPHRASE)

    with vault.open(PASSPHRASE) as first, vault.open(PASSPHRASE) as second:
        first.set_secret("first", "one")
        with pytest.raises(VaultConflictError):
            second.set_secret("second", "two")

    with vault.open(PASSPHRASE) as store:
        assert store.get_secret("first") == "one"
        assert store.get_secret("second") is None


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions are unavailable")
def test_file_vault_uses_private_directory_file_and_lock_modes(tmp_path: Path) -> None:
    path = tmp_path / "private" / "credentials.vault"
    vault = FileVault(path)
    vault.initialize(PASSPHRASE)
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert (
        stat.S_IMODE((path.parent / ".credentials.vault.lock").stat().st_mode) == 0o600
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink checks are unavailable")
def test_file_vault_rejects_symlinked_file_and_parent(tmp_path: Path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir(mode=0o700)
    real_vault = FileVault(real_dir / "credentials.vault")
    real_vault.initialize(PASSPHRASE)

    file_link = tmp_path / "file-link.vault"
    file_link.symlink_to(real_vault.path)
    with pytest.raises(VaultPermissionError):
        FileVault(file_link).inspect()
    with pytest.raises(VaultPermissionError), FileVault(file_link).open(PASSPHRASE):
        pass

    parent_link = tmp_path / "parent-link"
    parent_link.symlink_to(real_dir, target_is_directory=True)
    with pytest.raises(VaultPermissionError):
        FileVault(parent_link / "new.vault").initialize(PASSPHRASE)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions are unavailable")
def test_file_vault_rejects_unsafe_file_permissions(tmp_path: Path) -> None:
    path = tmp_path / "credentials.vault"
    vault = FileVault(path)
    vault.initialize(PASSPHRASE)
    path.chmod(0o644)
    with pytest.raises(VaultPermissionError), vault.open(PASSPHRASE):
        pass


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "geteuid"),
    reason="POSIX ownership checks are unavailable",
)
def test_file_vault_rejects_wrong_file_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault = FileVault(tmp_path / "credentials.vault")
    vault.initialize(PASSPHRASE)
    original_fstat = os.fstat

    def wrong_owner_fstat(descriptor: int) -> os.stat_result:
        info = original_fstat(descriptor)
        values = list(info)
        values[4] = info.st_uid + 1
        return os.stat_result(values)

    monkeypatch.setattr("vaultconfig.secrets.fileio.os.fstat", wrong_owner_fstat)
    with pytest.raises(VaultPermissionError, match="user-owned"):
        vault.inspect()


def test_file_vault_rejects_oversized_file_before_unlock(tmp_path: Path) -> None:
    path = tmp_path / "credentials.vault"
    vault = FileVault(path)
    vault.initialize(PASSPHRASE)
    path.write_bytes(b"x" * (16 * 1024 * 1024 + 1))
    path.chmod(0o600)
    with pytest.raises(VaultFormatError, match="size limit"), vault.open(PASSPHRASE):
        pass


def test_new_vault_uses_explicit_argon2id_defaults(tmp_path: Path) -> None:
    assert DEFAULT_OPSLIMIT == 2
    assert DEFAULT_MEMLIMIT_BYTES == 64 * 1024 * 1024

    vault = FileVault(tmp_path / "credentials.vault")
    vault.initialize(PASSPHRASE)

    kdf = json.loads(vault.path.read_bytes())["kdf"]
    assert kdf["name"] == "argon2id"
    assert kdf["opslimit"] == 2
    assert kdf["memlimit_bytes"] == 64 * 1024 * 1024


def test_existing_v2_uses_its_stored_kdf_parameters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault = FileVault(tmp_path / "credentials.vault")
    with monkeypatch.context() as profile:
        profile.setattr("vaultconfig.secrets.crypto.DEFAULT_OPSLIMIT", 3)
        profile.setattr(
            "vaultconfig.secrets.crypto.DEFAULT_MEMLIMIT_BYTES",
            32 * 1024 * 1024,
        )
        vault.initialize(PASSPHRASE)
        with vault.open(PASSPHRASE) as store:
            store.set_secret("legacy", "stored-kdf-value")

    kdf = json.loads(vault.path.read_bytes())["kdf"]
    assert kdf["opslimit"] == 3
    assert kdf["memlimit_bytes"] == 32 * 1024 * 1024
    with vault.open(PASSPHRASE) as store:
        assert store.get_secret("legacy") == "stored-kdf-value"


def test_invalid_kdf_metadata_is_rejected_before_derivation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault = FileVault(tmp_path / "credentials.vault")
    vault.initialize(PASSPHRASE)

    document = json.loads(vault.path.read_bytes())
    document["kdf"]["opslimit"] = 1
    vault.path.write_text(json.dumps(document), encoding="utf-8")
    if os.name == "posix":
        vault.path.chmod(0o600)

    def fail_derivation(*args: object, **kwargs: object) -> bytes:
        pytest.fail("Argon2id derivation ran for invalid metadata")

    monkeypatch.setattr("vaultconfig.secrets.crypto.argon2id.kdf", fail_derivation)
    with pytest.raises(VaultFormatError), vault.open(PASSPHRASE):
        pass


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("kdf", "opslimit", 11),
        ("kdf", "opslimit", 2.5),
        ("kdf", "opslimit", True),
        ("kdf", "memlimit_bytes", 18 * 1024 * 1024),
        ("kdf", "memlimit_bytes", 257 * 1024 * 1024),
        ("kdf", "memlimit_bytes", "67108864"),
        ("kdf", "name", "scrypt"),
        ("cipher", "name", "unknown-cipher"),
    ],
)
def test_invalid_metadata_is_rejected_before_kdf_derivation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    section: str,
    field: str,
    value: object,
) -> None:
    vault = FileVault(tmp_path / "credentials.vault")
    vault.initialize(PASSPHRASE)

    document = json.loads(vault.path.read_bytes())
    document[section][field] = value
    vault.path.write_text(json.dumps(document), encoding="utf-8")
    if os.name == "posix":
        vault.path.chmod(0o600)

    def fail_derivation(*args: object, **kwargs: object) -> bytes:
        pytest.fail("Argon2id derivation ran for invalid metadata")

    monkeypatch.setattr("vaultconfig.secrets.crypto.argon2id.kdf", fail_derivation)
    with pytest.raises(VaultFormatError), vault.open(PASSPHRASE):
        pass


def test_file_vault_inspect_returns_metadata_without_decryption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault = FileVault(tmp_path / "credentials.vault")
    vault.initialize(PASSPHRASE)
    with vault.open(PASSPHRASE) as store:
        store.set_secret("private-name", "private-secret-value")

    def fail_decryption(data: bytes, passphrase: bytes) -> dict[str, str]:
        pytest.fail("inspection attempted to decrypt the vault")

    monkeypatch.setattr(
        "vaultconfig.secrets.encrypted_file.decrypt_v2",
        fail_decryption,
    )

    info = vault.inspect()

    assert info == FileVaultInfo(
        format="vaultconfig-secret-v2",
        entry_count=1,
        kdf_name="argon2id",
        opslimit=2,
        memlimit_bytes=64 * 1024 * 1024,
    )
    assert "private-name" not in repr(info)
    assert "private-secret-value" not in repr(info)


@pytest.mark.parametrize(
    "invalid_envelope",
    ["malformed", "invalid-kdf", "oversized"],
)
def test_file_vault_inspect_rejects_invalid_envelopes(
    tmp_path: Path,
    invalid_envelope: str,
) -> None:
    vault = FileVault(tmp_path / "credentials.vault")
    vault.initialize(PASSPHRASE)

    if invalid_envelope == "malformed":
        vault.path.write_bytes(b"not-json")
    elif invalid_envelope == "invalid-kdf":
        document = json.loads(vault.path.read_bytes())
        document["kdf"]["opslimit"] = 1
        vault.path.write_text(json.dumps(document), encoding="utf-8")
    else:
        vault.path.write_bytes(b"x" * (16 * 1024 * 1024 + 1))
    if os.name == "posix":
        vault.path.chmod(0o600)

    with pytest.raises(VaultFormatError):
        vault.inspect()


def test_file_vault_create_secret_only_creates_missing_names(tmp_path: Path) -> None:
    vault = FileVault(tmp_path / "credentials.vault")
    vault.initialize(PASSPHRASE)

    with vault.open(PASSPHRASE) as store:
        assert isinstance(store, CreateOnlySecretStore)
        store.create_secret("mail", "first-value")
        store.create_secret("empty", "")
        assert store.get_secret("mail") == "first-value"
        assert store.get_secret("empty") == ""
        with pytest.raises(SecretExistsError):
            store.create_secret("mail", "replacement-value")
        assert store.get_secret("mail") == "first-value"


def test_file_vault_create_secret_does_not_overwrite_concurrent_creation(
    tmp_path: Path,
) -> None:
    vault = FileVault(tmp_path / "credentials.vault")
    vault.initialize(PASSPHRASE)

    with vault.open(PASSPHRASE) as first, vault.open(PASSPHRASE) as second:
        assert first.get_secret("shared") is None
        second.create_secret("shared", "second-value")
        with pytest.raises(VaultConflictError):
            first.create_secret("shared", "first-value")

    with vault.open(PASSPHRASE) as store:
        assert store.get_secret("shared") == "second-value"
