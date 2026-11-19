from __future__ import annotations

import errno
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .envelope import MAX_ENVELOPE_SIZE
from .errors import (
    VaultConflictError,
    VaultError,
    VaultFormatError,
    VaultPermissionError,
)

if os.name != "nt":
    import fcntl


def vault_path(path: str | os.PathLike[str]) -> Path:
    try:
        value = os.fspath(path)
        if "\0" in value:
            raise ValueError
        return Path(os.path.abspath(Path(value).expanduser()))
    except (TypeError, ValueError, OSError):
        raise VaultPermissionError("invalid vault path") from None


def _check_directory(path: Path, *, create: bool) -> None:
    parent = path.parent
    current = Path(parent.anchor)
    for part in parent.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if not create:
                raise
            created = False
            try:
                current.mkdir(mode=0o700)
                created = True
            except FileExistsError:
                pass
            except OSError:
                raise VaultPermissionError("vault directory is unavailable") from None
            if created and os.name != "nt":
                try:
                    os.chmod(current, 0o700)
                except OSError:
                    raise VaultPermissionError(
                        "vault directory is unavailable"
                    ) from None
            try:
                info = current.lstat()
            except OSError:
                raise VaultPermissionError("vault directory is unavailable") from None
        except OSError:
            raise VaultPermissionError("vault directory is unavailable") from None

        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise VaultPermissionError("vault path contains an unsafe directory")
        if os.name != "nt":
            mode = stat.S_IMODE(info.st_mode)
            if current == parent:
                if mode & 0o777 != 0o700 or (
                    hasattr(os, "geteuid") and info.st_uid != os.geteuid()
                ):
                    raise VaultPermissionError(
                        "vault directory must be private and user-owned"
                    )
            elif mode & 0o022 and not mode & stat.S_ISVTX:
                raise VaultPermissionError(
                    "vault path contains a writable shared directory"
                )

    if os.name != "nt" and current == parent == Path(parent.anchor):
        info = parent.lstat()
        if stat.S_IMODE(info.st_mode) & 0o777 != 0o700:
            raise VaultPermissionError("vault directory must be private and user-owned")


def _existing_file(path: Path) -> os.stat_result | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise VaultPermissionError("vault file is unavailable") from None

    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise VaultPermissionError("vault path is not a regular file")
    if os.name != "nt":
        if stat.S_IMODE(info.st_mode) & 0o777 != 0o600:
            raise VaultPermissionError("vault file must have mode 0600")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise VaultPermissionError("vault file must be user-owned")
    return info


def vault_file_exists(path: str | os.PathLike[str]) -> bool:
    target = vault_path(path)
    _check_directory(target, create=False)
    return _existing_file(target) is not None


def read_vault_file(path: str | os.PathLike[str]) -> bytes:
    target = vault_path(path)
    _check_directory(target, create=False)
    _existing_file(target)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EACCES, errno.EPERM, errno.ENOTDIR):
            raise VaultPermissionError("vault file is not safely accessible") from None
        raise VaultError("could not read vault file") from None

    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise VaultPermissionError("vault path is not a regular file")
        if os.name != "nt":
            if stat.S_IMODE(info.st_mode) & 0o777 != 0o600:
                raise VaultPermissionError("vault file must have mode 0600")
            if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
                raise VaultPermissionError("vault file must be user-owned")
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            descriptor = -1
            data = source.read(MAX_ENVELOPE_SIZE + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(data) > MAX_ENVELOPE_SIZE:
        raise VaultFormatError("vault file exceeds size limit")
    return data


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno in (errno.EINVAL, errno.ENOTSUP, errno.EISDIR):
            return
        raise VaultError("could not sync vault directory") from None
    try:
        try:
            os.fsync(descriptor)
        except OSError as exc:
            if exc.errno not in (errno.EINVAL, errno.ENOTSUP, errno.EBADF):
                raise VaultError("could not sync vault directory") from None
    finally:
        os.close(descriptor)


def write_vault_file(
    path: str | os.PathLike[str],
    data: bytes,
    *,
    overwrite: bool,
) -> None:
    target = vault_path(path)
    if not isinstance(data, bytes) or not data or len(data) > MAX_ENVELOPE_SIZE:
        raise VaultFormatError("invalid vault data")
    _check_directory(target, create=True)
    existing = _existing_file(target)
    if existing is not None and not overwrite:
        raise VaultConflictError("vault file already exists")

    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
        )
        temporary_path = Path(temporary_name)
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary_path, target)
        temporary_path = None
        _sync_directory(target.parent)
    except OSError as exc:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass
        if exc.errno in (errno.EACCES, errno.EPERM):
            raise VaultPermissionError("vault file is not safely writable") from None
        raise VaultError("could not write vault file") from None


def _lock_file_path(path: Path) -> Path:
    return path.with_name(f".{path.name}.lock")


@contextmanager
def vault_lock(path: str | os.PathLike[str]) -> Iterator[None]:
    target = vault_path(path)
    _check_directory(target, create=True)
    lock_path = _lock_file_path(target)
    _existing_file(lock_path)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError:
        raise VaultPermissionError("vault lock is not safely accessible") from None

    locked = False
    try:
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise VaultPermissionError("vault lock is not a regular file")
            if os.name == "nt":
                import msvcrt

                if info.st_size == 0:
                    os.write(descriptor, b"\0")
                    os.fsync(descriptor)
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)  # type: ignore[attr-defined]
            else:
                if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
                    raise VaultPermissionError("vault lock must be user-owned")
                os.fchmod(descriptor, 0o600)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            locked = True
        except OSError:
            raise VaultError("could not lock vault file") from None
        yield
    finally:
        try:
            if locked:
                try:
                    if os.name == "nt":
                        import msvcrt

                        os.lseek(descriptor, 0, os.SEEK_SET)
                        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
                    else:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError:
                    raise VaultError("could not unlock vault file") from None
        finally:
            os.close(descriptor)
