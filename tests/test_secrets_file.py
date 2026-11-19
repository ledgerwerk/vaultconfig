from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path

import pytest

from vaultconfig.secrets import (
    FileVault,
    VaultConflictError,
    VaultError,
    VaultFormatError,
    VaultLockedError,
    VaultPermissionError,
    VaultUnlockError,
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


def test_file_vault_rejects_oversized_file_before_unlock(tmp_path: Path) -> None:
    path = tmp_path / "credentials.vault"
    vault = FileVault(path)
    vault.initialize(PASSPHRASE)
    path.write_bytes(b"x" * (16 * 1024 * 1024 + 1))
    path.chmod(0o600)
    with pytest.raises(VaultFormatError, match="size limit"), vault.open(PASSPHRASE):
        pass
