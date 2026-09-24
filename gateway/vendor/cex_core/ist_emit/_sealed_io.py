from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import stat
import struct
import zipfile
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, TypeVar


_Error = TypeVar("_Error", bound=Exception)
FileIdentity = tuple[int, int, int, int, int]

# skill 剪切声明：上游此处的 run_owner_commit_scope / RunCancelled 钩子
# （main/ist_core/run_governance.py）不随包分发，本包内恒为空作用域/不取消。
# fd 级原子写、回滚校验、预算校验语义逐字保留。


@contextmanager
def _run_owner_commit_scope():
    yield


def _is_run_cancelled(exc: BaseException) -> bool:
    return False


def _identity(info: os.stat_result) -> FileIdentity:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
    )


def canonical_json(
    value: Any,
    *,
    ensure_ascii: bool,
    omit: str | Iterable[str] | None = None,
) -> bytes:
    body = dict(value) if isinstance(value, Mapping) else value
    if isinstance(body, dict):
        omitted = (omit,) if isinstance(omit, str) else tuple(omit or ())
        for field in omitted:
            body.pop(field, None)
    return json.dumps(
        body,
        ensure_ascii=ensure_ascii,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


CONTRACT_CARD_MAX_BYTES = 4 * 1024 * 1024

_BUDGET_UNBOUNDED = 1 << 62


def scan_json_budget(
    payload: bytes | str,
    *,
    abort_tokens: int | None = None,
    abort_depth: int | None = None,
) -> tuple[int, int]:
    raw = payload.encode("utf-8") if isinstance(payload, str) else payload
    stop_tokens = _BUDGET_UNBOUNDED if abort_tokens is None else abort_tokens
    stop_depth = _BUDGET_UNBOUNDED if abort_depth is None else abort_depth
    aborting = abort_tokens is not None or abort_depth is not None
    depth = 0
    max_depth = 0
    tokens = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
            continue
        if byte in (0x7B, 0x5B):
            depth += 1
            tokens += 1
            if depth > max_depth:
                max_depth = depth
        elif byte in (0x7D, 0x5D):
            depth = max(0, depth - 1)
            continue
        elif byte == 0x2C:
            tokens += 1
        else:
            continue
        if aborting and (max_depth > stop_depth or tokens > stop_tokens):
            return tokens, max_depth
    return tokens, max_depth


def validate_json_budget(
    payload: bytes | str,
    *,
    error_type: type[_Error],
    message: str,
    max_depth: int = 128,
    max_tokens: int = 500_000,
) -> None:
    tokens, depth = scan_json_budget(
        payload, abort_tokens=max_tokens, abort_depth=max_depth,
    )
    if depth > max_depth or tokens > max_tokens:
        raise error_type(message)


def file_identity(info: os.stat_result) -> FileIdentity:
    return _identity(info)


def validate_xlsx_zip_budget(
    payload: bytes,
    *,
    error_type: type[_Error],
    message: str,
    max_members: int = 4096,
    max_member_bytes: int = 128 * 1024 * 1024,
    max_total_bytes: int = 512 * 1024 * 1024,
    max_compression_ratio: int = 500,
    max_central_directory_bytes: int = 32 * 1024 * 1024,
) -> None:
    try:
        tail_start = max(0, len(payload) - (65_535 + 22))
        eocd_offset = payload.rfind(b"PK\x05\x06", tail_start)
        if eocd_offset < 0 or eocd_offset + 22 > len(payload):
            raise error_type(message)
        (
            _signature,
            disk_number,
            central_disk,
            entries_on_disk,
            total_entries,
            central_size,
            _central_offset,
            comment_size,
        ) = struct.unpack_from("<4s4H2LH", payload, eocd_offset)
        if eocd_offset + 22 + comment_size != len(payload):
            raise error_type(message)
        if disk_number != 0 or central_disk != 0 or entries_on_disk != total_entries:
            raise error_type(message)
        if total_entries == 0xFFFF or central_size == 0xFFFFFFFF:
            locator_offset = eocd_offset - 20
            if locator_offset < 0 or payload[locator_offset:locator_offset + 4] != b"PK\x06\x07":
                raise error_type(message)
            _locator_sig, zip64_disk, zip64_offset, disk_count = struct.unpack_from(
                "<4sLQL", payload, locator_offset,
            )
            if zip64_disk != 0 or disk_count != 1 or zip64_offset + 56 > len(payload):
                raise error_type(message)
            if payload[zip64_offset:zip64_offset + 4] != b"PK\x06\x06":
                raise error_type(message)
            (
                _zip64_sig,
                zip64_record_size,
                _made_by,
                _needed,
                zip64_disk_number,
                zip64_central_disk,
                zip64_entries_on_disk,
                total_entries,
                central_size,
                _zip64_central_offset,
            ) = struct.unpack_from("<4sQ2H2L4Q", payload, zip64_offset)
            if (
                zip64_record_size < 44
                or zip64_disk_number != 0
                or zip64_central_disk != 0
                or zip64_entries_on_disk != total_entries
            ):
                raise error_type(message)
        if total_entries > max_members or central_size > max_central_directory_bytes:
            raise error_type(message)
    except (struct.error, OverflowError, IndexError) as exc:
        raise error_type(message) from exc
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            infos = archive.infolist()
            if len(infos) > max_members:
                raise error_type(message)
            total = 0
            for info in infos:
                name = str(info.filename or "")
                parts = Path(name).parts
                if (
                    not name
                    or name.startswith(("/", "\\"))
                    or ".." in parts
                    or "\x00" in name
                    or info.flag_bits & 0x1
                ):
                    raise error_type(message)
                size = int(info.file_size)
                compressed = int(info.compress_size)
                total += size
                if size > max_member_bytes or total > max_total_bytes:
                    raise error_type(message)
                if size and (compressed <= 0 or size > compressed * max_compression_ratio):
                    raise error_type(message)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError) as exc:
        raise error_type(message) from exc


def lexical_absolute(path: str | Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def lexical_path_inside_root(
    path: str | Path,
    trusted_root: str | Path,
    *,
    error_type: type[_Error],
    traversal_message: str,
    outside_message: str,
) -> Path:
    raw = Path(path)
    if ".." in raw.parts:
        raise error_type(traversal_message)
    root = lexical_absolute(trusted_root)
    target = lexical_absolute(raw if raw.is_absolute() else root / raw)
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise error_type(outside_message) from exc
    return target


def directory_flags(*, error_type: type[_Error], unavailable_message: str) -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise error_type(unavailable_message)
    return (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )


def open_directory_nofollow(
    path: str | Path,
    *,
    error_type: type[_Error],
    invalid_message: str,
    unavailable_message: str,
    preserve_missing: bool = False,
    create_missing: bool = False,
    create_mode: int = 0o755,
) -> int:
    absolute = lexical_absolute(path)
    if not absolute.is_absolute() or len(absolute.parts) < 2:
        raise error_type(invalid_message)
    flags = directory_flags(
        error_type=error_type,
        unavailable_message=unavailable_message,
    )
    descriptor = os.open(absolute.anchor, flags)
    try:
        for component in absolute.parts[1:]:
            try:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create_missing:
                    raise
                try:
                    os.mkdir(component, create_mode, dir_fd=descriptor)
                except FileExistsError:
                    pass
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except FileNotFoundError:
        os.close(descriptor)
        if preserve_missing:
            raise
        raise error_type(unavailable_message) from None
    except OSError as exc:
        os.close(descriptor)
        raise error_type(unavailable_message) from exc


def _inode_key(info: os.stat_result | FileIdentity) -> tuple[int, int]:
    if isinstance(info, os.stat_result):
        return int(info.st_dev), int(info.st_ino)
    return int(info[0]), int(info[1])


def open_or_create_regular_at_nofollow(
    directory_fd: int,
    name: str,
    flags: int,
    *,
    mode: int,
    error_type: type[_Error],
    unavailable_message: str,
) -> int:
    if (
        not name
        or name in {".", ".."}
        or Path(name).name != name
        or flags & (os.O_CREAT | os.O_EXCL)
        or not getattr(os, "O_NOFOLLOW", 0)
        or not flags & os.O_NOFOLLOW
    ):
        raise error_type(unavailable_message)
    try:
        try:
            return os.open(name, flags, dir_fd=directory_fd)
        except FileNotFoundError:
            try:
                return os.open(
                    name,
                    flags | os.O_CREAT | os.O_EXCL,
                    mode,
                    dir_fd=directory_fd,
                )
            except FileExistsError:
                return os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise error_type(unavailable_message) from exc


def atomic_write_bytes_at_nofollow(
    directory_fd: int,
    name: str,
    payload: bytes,
    *,
    error_type: type[_Error],
    unavailable_message: str,
    mode: int = 0o600,
) -> str:
    if not name or name in {".", ".."} or Path(name).name != name:
        raise error_type(unavailable_message)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    if not nofollow:
        raise error_type(unavailable_message)

    old_info: os.stat_result | None
    try:
        old_info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        old_info = None
    if old_info is not None and (
        not stat.S_ISREG(old_info.st_mode)
        or int(old_info.st_nlink) != 1
        or (hasattr(os, "getuid") and int(old_info.st_uid) != os.getuid())
    ):
        raise error_type(unavailable_message)

    token = f"{os.getpid()}.{secrets.token_hex(12)}"
    tmp_name = f".{name}.{token}.tmp"
    backup_name = f".{name}.{token}.rollback" if old_info is not None else ""
    file_fd: int | None = None
    new_info: os.stat_result | None = None
    replaced = False
    try:
        if old_info is not None:
            os.link(
                name,
                backup_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            backup = os.stat(
                backup_name, dir_fd=directory_fd, follow_symlinks=False
            )
            if (
                _inode_key(current) != _inode_key(old_info)
                or _inode_key(backup) != _inode_key(old_info)
                or int(current.st_nlink) != 2
                or int(backup.st_nlink) != 2
            ):
                raise OSError("atomic rollback inode binding failed")

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | cloexec
        file_fd = os.open(tmp_name, flags, mode, dir_fd=directory_fd)
        os.fchmod(file_fd, mode)
        view = memoryview(payload)
        while view:
            written = os.write(file_fd, view)
            if written <= 0:
                raise OSError("short atomic write")
            view = view[written:]
        os.fsync(file_fd)
        new_info = os.fstat(file_fd)
        if not stat.S_ISREG(new_info.st_mode) or int(new_info.st_nlink) != 1:
            raise OSError("atomic staging inode identity is invalid")
        os.close(file_fd)
        file_fd = None

        with _run_owner_commit_scope():
            try:
                os.replace(
                    tmp_name,
                    name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                )
                tmp_name = ""
                replaced = True
                os.fsync(directory_fd)
                observed, observed_identity = read_regular_at_nofollow(
                    directory_fd,
                    name,
                    error_type=error_type,
                    open_message=unavailable_message,
                    bounds_message=unavailable_message,
                    changed_message=unavailable_message,
                    max_bytes=len(payload),
                    min_bytes=len(payload),
                    return_identity=True,
                )
                if (
                    observed != payload
                    or new_info is None
                    or _inode_key(observed_identity) != _inode_key(new_info)
                ):
                    raise OSError("atomic publish read-back mismatch")
            except BaseException as publish_exc:
                try:
                    if backup_name:
                        os.replace(
                            backup_name,
                            name,
                            src_dir_fd=directory_fd,
                            dst_dir_fd=directory_fd,
                        )
                        backup_name = ""
                        restored = os.stat(
                            name, dir_fd=directory_fd, follow_symlinks=False
                        )
                        if (
                            old_info is None
                            or _inode_key(restored) != _inode_key(old_info)
                            or not stat.S_ISREG(restored.st_mode)
                            or int(restored.st_nlink) != 1
                        ):
                            raise OSError("atomic rollback verification failed")
                    elif replaced:
                        current = os.stat(
                            name, dir_fd=directory_fd, follow_symlinks=False
                        )
                        if new_info is None or _inode_key(current) != _inode_key(new_info):
                            raise OSError("atomic rollback target identity changed")
                        os.unlink(name, dir_fd=directory_fd)
                        try:
                            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        except FileNotFoundError:
                            pass
                        else:
                            raise OSError("atomic rollback removal failed")
                    os.fsync(directory_fd)
                except BaseException as rollback_exc:
                    raise error_type(
                        f"{unavailable_message}; verified rollback failed"
                    ) from rollback_exc
                raise publish_exc

            if backup_name:
                try:
                    os.unlink(backup_name, dir_fd=directory_fd)
                    backup_name = ""
                except OSError as cleanup_exc:
                    os.replace(
                        backup_name,
                        name,
                        src_dir_fd=directory_fd,
                        dst_dir_fd=directory_fd,
                    )
                    backup_name = ""
                    os.fsync(directory_fd)
                    raise error_type(unavailable_message) from cleanup_exc
                try:
                    os.fsync(directory_fd)
                except OSError:
                    pass
    except BaseException as exc:
        if file_fd is not None:
            os.close(file_fd)
        if _is_run_cancelled(exc) or not isinstance(exc, Exception):
            raise
        if isinstance(exc, error_type):
            raise
        raise error_type(unavailable_message) from exc
    finally:
        for residue in (tmp_name, backup_name):
            if not residue:
                continue
            try:
                os.unlink(residue, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
    return sha256_bytes(payload)


def atomic_write_bytes_nofollow(
    path: str | Path,
    payload: bytes,
    *,
    error_type: type[_Error],
    invalid_message: str,
    unavailable_message: str,
    create_parents: bool = True,
    mode: int = 0o600,
) -> str:
    absolute = lexical_absolute(path)
    if not absolute.is_absolute() or absolute.name in {"", ".", ".."}:
        raise error_type(invalid_message)
    parent_fd = open_directory_nofollow(
        absolute.parent,
        error_type=error_type,
        invalid_message=invalid_message,
        unavailable_message=unavailable_message,
        create_missing=create_parents,
    )
    try:
        return atomic_write_bytes_at_nofollow(
            parent_fd,
            absolute.name,
            payload,
            error_type=error_type,
            unavailable_message=unavailable_message,
            mode=mode,
        )
    finally:
        os.close(parent_fd)


def read_regular_at_nofollow(
    directory_fd: int,
    name: str,
    *,
    error_type: type[_Error],
    open_message: str,
    bounds_message: str,
    changed_message: str,
    max_bytes: int | None = None,
    min_bytes: int = 0,
    chunk_bytes: int = 1024 * 1024,
    preserve_missing: bool = False,
    return_identity: bool = False,
    require_current_uid: bool = False,
) -> bytes | tuple[bytes, FileIdentity]:
    leaf = str(name or "")
    if (
        not leaf
        or leaf in {".", ".."}
        or Path(leaf).name != leaf
        or "/" in leaf
        or "\\" in leaf
    ):
        raise error_type(open_message)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        file_fd = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        if preserve_missing:
            raise
        raise error_type(open_message) from None
    except OSError as exc:
        raise error_type(open_message) from exc
    try:
        before = os.fstat(file_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or int(before.st_nlink) != 1
            or (
                require_current_uid
                and hasattr(os, "getuid")
                and int(before.st_uid) != os.getuid()
            )
            or int(before.st_size) < min_bytes
            or (max_bytes is not None and int(before.st_size) > max_bytes)
        ):
            raise error_type(bounds_message)
        limit = (max_bytes + 1) if max_bytes is not None else (int(before.st_size) + 1)
        chunks: list[bytes] = []
        remaining = limit
        while remaining > 0:
            chunk = os.read(file_fd, min(chunk_bytes, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(file_fd)
        stable = _identity(before) == _identity(after)
        if (
            not stable
            or len(payload) != int(before.st_size)
            or (max_bytes is not None and len(payload) > max_bytes)
        ):
            raise error_type(changed_message)
        return (payload, _identity(after)) if return_identity else payload
    finally:
        os.close(file_fd)


def read_regular_nofollow(
    path: str | Path,
    *,
    error_type: type[_Error],
    invalid_message: str,
    directory_message: str,
    open_message: str,
    bounds_message: str,
    changed_message: str,
    max_bytes: int | None = None,
    min_bytes: int = 0,
    preserve_missing: bool = False,
    return_identity: bool = False,
    trusted_root: str | Path | None = None,
    require_current_uid: bool = False,
) -> bytes | tuple[bytes, FileIdentity]:
    raw = Path(path)
    if ".." in raw.parts:
        raise error_type(invalid_message)
    absolute = (
        lexical_absolute(raw)
        if trusted_root is None
        else lexical_path_inside_root(
            raw,
            trusted_root,
            error_type=error_type,
            traversal_message=invalid_message,
            outside_message=invalid_message,
        )
    )
    if not absolute.is_absolute() or absolute.name in {"", ".", ".."}:
        raise error_type(invalid_message)
    parent_fd = open_directory_nofollow(
        absolute.parent,
        error_type=error_type,
        invalid_message=invalid_message,
        unavailable_message=directory_message,
        preserve_missing=preserve_missing,
    )
    try:
        return read_regular_at_nofollow(
            parent_fd,
            absolute.name,
            error_type=error_type,
            open_message=open_message,
            bounds_message=bounds_message,
            changed_message=changed_message,
            max_bytes=max_bytes,
            min_bytes=min_bytes,
            preserve_missing=preserve_missing,
            return_identity=return_identity,
            require_current_uid=require_current_uid,
        )
    finally:
        os.close(parent_fd)


def stat_regular_nofollow(
    path: str | Path,
    *,
    error_type: type[_Error],
    invalid_message: str,
    directory_message: str,
    open_message: str,
    bounds_message: str,
    max_bytes: int | None = None,
    min_bytes: int = 0,
) -> FileIdentity:
    absolute = lexical_absolute(path)
    if not absolute.is_absolute() or absolute.name in {"", ".", ".."}:
        raise error_type(invalid_message)
    parent_fd = open_directory_nofollow(
        absolute.parent,
        error_type=error_type,
        invalid_message=invalid_message,
        unavailable_message=directory_message,
    )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        try:
            file_fd = os.open(absolute.name, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise error_type(open_message) from exc
        try:
            info = os.fstat(file_fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or int(info.st_nlink) != 1
                or int(info.st_size) < min_bytes
                or (max_bytes is not None and int(info.st_size) > max_bytes)
            ):
                raise error_type(bounds_message)
            return _identity(info)
        finally:
            os.close(file_fd)
    finally:
        os.close(parent_fd)
