#!/usr/bin/env python3
"""pecia: evidence-preserving continuity for research repositories that several AI agents work on in turn.

The name comes from the medieval pecia system: a university-inspected exemplar was split into
sections, and each section was lent to one copyist at a time.

Single file, Python standard library only (3.10+), git 2.27+.

The repository, not any conversation, is the authoritative record:
  .pecia/STATE.md     versioned task state (goal, scope, next, decisions, obligations)
  .pecia/REVIEW.md    versioned review record and obligation discharges
  .pecia/policy.json  versioned snapshot and artifact policy
  .pecia/runtime/     machine-local, ignored: events, cache, recovery scratch
  .git/pecia/lease/   the write lease and heartbeats, in the git directory so git clean leaves them
  .git/pecia/snapshot.lock   the lock snapshots of this working tree take turns under, there for the same reason
  refs/pecia/snap/*   local snapshot commits built from a scratch index
  <git-common-dir>/pecia/artifacts   byte-exact store for designated artifacts
  <git-common-dir>/pecia/runner      the copy of pecia.py the agent hooks run, and the policy recorded with it

Nothing in this tool resets, cleans, checks out, or overwrites the working tree.
"""
from __future__ import annotations

import argparse
import array
import bisect
import contextlib
import datetime as _dt
import errno
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import socket
import stat as stat_mod
import subprocess
import sys
import tempfile
import threading
import time
import types
import unicodedata
import uuid
from pathlib import Path

VERSION = "0.1.2rc15"
PECIA_DIR = ".pecia"
STATE_REL = ".pecia/STATE.md"
REVIEW_REL = ".pecia/REVIEW.md"
POLICY_REL = ".pecia/policy.json"
RUNTIME_REL = ".pecia/runtime"
BIN_REL = ".pecia/bin"
REF_ROOT = "refs/pecia/snap"
IS_WINDOWS = os.name == "nt"

EXIT_OK = 0
EXIT_ATTENTION = 1
EXIT_ERROR = 2
EXIT_LOCKED = 3

DEFAULT_POLICY: dict = {
    "version": 1,
    "agents": {"codex": ["codex"], "claude": ["claude"]},
    "snapshot": {
        "interval_seconds": 180,
        "retain_count": 200,
        "retain_days": 14,
        "min_keep": 20,
        "keep_work": 10,
        "max_untracked_file_mb": 25,
        # Filename-specific on purpose: broad substring patterns such as *secret* or *token*
        # silently dropped ordinary source (secret_rotation.py, tokenizer.json) from snapshots.
        "exclude_globs": [
            ".env*", "*.env", ".dev.vars", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
            "*.ppk", "*.kdbx", "id_rsa", "id_rsa.*", "id_dsa", "id_dsa.*", "id_ecdsa", "id_ecdsa.*",
            "id_ed25519", "id_ed25519.*", ".netrc", "_netrc", ".npmrc", ".pypirc", ".pgpass", ".htpasswd",
            "*.tfvars", "*.tfvars.json", "*.tfstate", "*.tfstate.*", "**/.kube/config",
            "**/.docker/config.json", "**/.aws/credentials", "**/.aws/config", "credentials.json",
            "client_secret*.json", "service-account*.json", "service_account*.json",
            "serviceAccountKey*.json", "token.json", "token.pickle", ".git-credentials", "kaggle.json",
            ".vault-token", ".s3cfg", ".boto", "**/.streamlit/secrets.toml", "secrets.json", "secrets.yml",
            "secrets.yaml", "secrets.toml", "secrets.env", "**/.envs/**",
            "**/secrets/**", "**/.secrets/**",
        ],
    },
    "artifacts": {
        "include_globs": [],
        "max_file_mb": 500,
        "store": "",
        "prune_dirs": [".git", "node_modules", ".venv", "venv", "__pycache__",
                       ".mypy_cache", ".pytest_cache", ".pecia/runtime"],
    },
    "guard": {"require_lease": False, "bind_process": True, "block_prompts": True,
              "allow_foreign_host_lease": False},
    "lock": {"heartbeat_seconds": 15, "stale_after_seconds": 120},
}
# The secret patterns as shipped. A tracked file one of them excludes is named by every snapshot, by status and by
# recovery, since its changes are in no snapshot (XA1-13); a pattern the user added is not reported.
_DEFAULT_EXCLUDES = frozenset(DEFAULT_POLICY["snapshot"]["exclude_globs"])


class PeciaError(Exception):
    exit_code = EXIT_ERROR


class LockHeld(PeciaError):
    exit_code = EXIT_LOCKED


class GitError(PeciaError):
    def __init__(self, args, code, stderr):
        super().__init__("git " + " ".join(args) + f" failed ({code}): " + stderr.strip())
        self.code = code
        self.stderr = stderr


# ---------------------------------------------------------------- utilities

def utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def iso(ts: _dt.datetime | None = None) -> str:
    return (ts or utcnow()).isoformat(timespec="seconds")


_READ_FLAGS = (os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0)
               | getattr(os, "O_BINARY", 0))


def _open_regular(path):
    """Open a file for reading only if it is a regular file. The open never blocks, so a named pipe
    or a device planted where pecia expects one of its files is refused instead of hanging a
    snapshot or a hook (U-02); it raises OSError."""
    fd = os.open(str(path), _READ_FLAGS)
    try:
        if not stat_mod.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", str(path))
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def _read_regular(path, limit: int | None = None) -> bytes:
    """The bytes of a regular file. With limit, a larger file raises OSError instead of being read,
    so a huge file, or a link to a device such as /dev/zero, cannot exhaust memory (R10-03)."""
    with _open_regular(path) as f:
        if limit is None:
            return f.read()
        data = f.read(limit + 1)
        if len(data) > limit:
            raise OSError(errno.EFBIG, f"larger than {limit} bytes", str(path))
        return data


_TEXT_LIMIT = 64 << 20  # pecia's own text and settings files
_JSON_LIMIT = 256 << 20  # artifact lists can be long


def _old_shim(path: Path) -> bool:
    """Whether path holds exactly the Windows shim an earlier version wrote (G4-02)."""
    try:
        # Its line endings may have been converted at checkout, as core.autocrlf does (IR31 S-1).
        data = _read_regular(path, 4096).replace(b"\r\n", b"\n")
        return data in {o.encode().replace(b"\r\n", b"\n") for o in _OLD_SHIMS}
    except OSError:
        return False


def _readable_differs(a: Path, b: Path) -> bool:
    """True when a's bytes differ from b's, or a cannot be read as a regular file (init then replaces
    the entry rather than hanging on a pipe there, R10-13)."""
    try:
        return _read_regular(a) != _read_regular(b)
    except OSError:
        return True


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with _open_regular(path) as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_text(path: Path) -> str:
    return _read_regular(path, _TEXT_LIMIT).decode("utf-8", "replace")


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write through a temporary file beside path and replace the directory entry, so a partial
    file never appears and an existing symlink is replaced, never followed. The folder is held
    (see _HeldDir), so the write cannot be redirected by swapping a folder on the way for a link."""
    _write_replacing(Path(path), data, keep_mode=True)


def _write_replacing(path: Path, data: bytes, keep_mode: bool, mode: int | None = None) -> None:
    with _held_dir(path.parent, create=True) as d:
        if mode is None and keep_mode:
            try:
                st = d.lstat(path.name)
                mode = st.st_mode & 0o777 if stat_mod.S_ISREG(st.st_mode) else 0o644
            except OSError:
                mode = 0o644
        fd, tmp = d.new_temp(".tmp-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                if mode is not None:
                    d.set_mode(f.fileno(), tmp, mode)
            d.replace(tmp, path.name)
        except BaseException:
            d.unlink_quietly(tmp)
            raise


def _replace_with_retry(src, dst, attempts: int = 20, **dir_fds) -> None:
    # On Windows, MoveFileEx fails with a sharing violation while another process
    # (for example a guard hook) has the destination open. Retry briefly.
    for i in range(attempts):
        try:
            os.replace(src, dst, **dir_fds)
            return
        except PermissionError:
            if i == attempts - 1:
                raise
            time.sleep(0.025 * (i + 1))


def atomic_write_json(path: Path, data) -> None:
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    _write_replacing(Path(path), text.encode("utf-8"), keep_mode=False)


# ---------------------------------------------------------------- held folders
#
# A check on a path followed by an operation on the same path leaves a gap: a folder on the way can be
# swapped for a link in between, and the operation then lands outside the repository (V-05, V-07).
# pecia therefore deletes, moves, replaces and creates files only inside a held folder: one reached
# from a trusted base folder (a working tree root, a git directory, the artifact store location)
# without following any link on the way, and kept so that what pecia checked is what it works in.
# On POSIX each folder is opened relative to the one above it with O_NOFOLLOW, and the work uses the
# final descriptor. On Windows, which has no such calls, each folder on the way is held open without
# delete sharing, which stops anyone renaming, deleting or replacing it until pecia lets go; each is
# checked for a link while held, and the work uses paths that can no longer change.

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_DIR_FDS = (not IS_WINDOWS and bool(_O_NOFOLLOW) and bool(_O_DIRECTORY)
            and {os.open, os.link, os.unlink, os.rename, os.stat, os.mkdir, os.rmdir} <= os.supports_dir_fd
            and os.listdir in os.supports_fd)
_BASES: dict = {}


def _register_base(p, kind: str = "tree", refresh: bool = False) -> None:
    """Record a folder as a trusted base. kind tree: a working tree root or a git directory, which pecia
    found itself; held folders are reached from the outermost such base that contains them, and every
    folder below it is checked. kind store: the artifacts.store location the user chose, which may be
    reached through a link; folders below it are held from it, even when it lies under a tree base.
    The folder's identity is recorded the first time it can be read, and a base that is found replaced by
    another folder later in the same run is refused (R13-05). refresh only fills in an identity that could
    not be read before, as for a store on a drive mounted after the run began; it never replaces one (Z-01)."""
    try:
        s = os.path.normpath(os.fspath(p))
        if not os.path.isabs(s):
            return
        key = os.path.normcase(s)
        old = _BASES.get(key)
        if old is not None and old["ident"] is not None:
            if kind == "store":
                old["kind"] = "store"  # the location the user chose is held from itself, whatever it lies under
            return
        try:
            ident = _ident(_base_stat(s))
        except (OSError, ValueError, AttributeError):
            ident = None
        _BASES[key] = {"path": s, "kind": kind if old is None or kind == "store" else old["kind"], "ident": ident}
    except (TypeError, ValueError):
        pass


def _base_stat(s):
    """The stat a base's identity is recorded from. On Windows it is read through a handle on the folder, as
    _HeldDir checks it, so the recorded and the checked identity come from the same call (M-03)."""
    if IS_WINDOWS and not _DIR_FDS:
        h = _win_hold(s, reparse=False)
        try:
            return _win_handle_stat(h)
        finally:
            _win_release(h)
    return os.stat(s)


def _anchor(target):
    """(base, names) for the base target is held from: the innermost store base whose own store folder (the
    repository-id folder pecia keeps there) contains it, if any, otherwise the outermost tree base containing it,
    otherwise a store base containing it; None when no base contains it. A store location the user chose is trusted
    for the store pecia keeps in it and nothing else: a runtime or checkout file below it is still reached from its
    working tree (N-19)."""
    cur = os.path.normpath(os.fspath(target))
    names, outer, store, any_store = [], None, None, None
    while True:
        rec = _BASES.get(os.path.normcase(cur))
        if rec is not None:
            here = (rec["path"], list(reversed(names)))
            if rec["kind"] == "store":
                sub = rec.get("sub")
                if any_store is None:
                    any_store = here
                if store is None and sub and here[1] and os.path.normcase(here[1][0]) == os.path.normcase(sub):
                    store = here
            else:
                outer = here
        parent, name = os.path.split(cur)
        if parent == cur or not name:
            return store or outer or any_store
        names.append(name)
        cur = parent


def _set_store_folder(base, name: str) -> None:
    """Record the repository-id folder pecia keeps in the store location base (see _anchor)."""
    rec = _BASES.get(os.path.normcase(os.path.normpath(os.fspath(base))))
    if rec is not None and rec["kind"] == "store" and name:
        rec["sub"] = name


def _check_base_identity(base, st) -> None:
    rec = _BASES.get(os.path.normcase(os.path.normpath(os.fspath(base))))
    if rec is None:
        return
    if rec["ident"] is None:
        rec["ident"] = _ident(st)
        return
    if _ident(st) == rec["ident"]:
        return
    raise UnsafePath(f"{fwd(base)} is no longer the folder it was when pecia started (it was moved, replaced, or "
                     "swapped for a link), so pecia refuses to write there. Run the command again.")


def _held_dir(path, create: bool = False) -> "_HeldDir":
    """The folder path, held from its trusted base (see _anchor). A base is never created: a store
    location that is missing, such as a drive that is not mounted, stays missing (R13-03). A folder
    outside every base is held from itself, which is then trusted, as before rc7."""
    found = _anchor(path)
    if found is None:
        if create:
            Path(path).mkdir(parents=True, exist_ok=True)
        return _HeldDir(path, [], False)
    return _HeldDir(found[0], found[1], create)


def _unlink_at(path) -> None:
    """Delete one file through its held folder. Raises OSError as os.unlink does."""
    path = Path(path)
    with _held_dir(path.parent) as d:
        d.unlink(path.name)


def _rmtree_at(path) -> None:
    """Remove a folder pecia made, and everything in it, through held folders: a link inside is removed
    itself, never followed, and a folder swapped for a link is never entered. Errors are ignored."""
    path = Path(path)
    try:
        with _held_dir(path.parent) as d:
            _rmtree_in(d, path.name, 0)
    except (OSError, PeciaError):
        pass


def _rmtree_in(d: "_HeldDir", name: str, depth: int) -> None:
    try:
        st = d.lstat(name)
    except OSError:
        return
    if stat_mod.S_ISDIR(st.st_mode) and depth < 64:
        try:
            c = d.child(name)
        except (OSError, PeciaError):
            c = None  # a link (a Windows junction looks like a folder): removed below, not entered
        if c is not None:
            with c:
                try:
                    names = c.names()
                except OSError:
                    names = []
                for n in names:
                    _rmtree_in(c, n, depth + 1)
    try:
        d.unlink(name)
    except OSError:
        try:
            d.rmdir(name)
        except OSError:
            if IS_WINDOWS and stat_mod.S_ISREG(st.st_mode) and st.st_nlink <= 1:  # a read-only file; never a link (U2)
                # Its read-only flag is cleared through a handle on the file itself, and only while it has no
                # other name: a hard link would carry the change to a file outside the repository (X-06). One
                # that has is left in place, and close reports what it could not remove.
                try:
                    if _win_set_attrs(d.path / name, clear_readonly=True):
                        d.unlink(name)
                except (OSError, NotImplementedError):
                    pass


def _create_excl(path, mode: int = 0o644) -> int:
    """Create a new file by name in its held folder and return a descriptor open for writing; raises
    FileExistsError if anything, a link included, is there already."""
    path = Path(path)
    with _held_dir(path.parent) as d:
        return d.open_fd(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), mode)


def _win_long(path) -> str:
    s = os.path.abspath(os.fspath(path))
    if s.startswith("\\\\?\\"):
        return s
    return "\\\\?\\UNC\\" + s[2:] if s.startswith("\\\\") else "\\\\?\\" + s


_WIN_K32 = None


def _win_k32():
    """kernel32 with the signatures pecia uses, loaded once (Windows only)."""
    global _WIN_K32
    if _WIN_K32 is None:
        import ctypes
        from ctypes import wintypes
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        k.CreateFileW.restype = wintypes.HANDLE
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
        k.GetFinalPathNameByHandleW.restype = wintypes.DWORD
        k.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        k.GetFileInformationByHandle.restype = wintypes.BOOL
        k.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        k.SetFileInformationByHandle.restype = wintypes.BOOL
        k.GetSystemTimeAsFileTime.argtypes = [ctypes.c_void_p]
        k.GetCurrentProcess.restype = wintypes.HANDLE
        k.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE),
                                      wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k.DuplicateHandle.restype = wintypes.BOOL
        _WIN_K32 = k
    return _WIN_K32


def _win_hold(path, reparse: bool):
    """Open a folder on Windows without delete sharing, so it cannot be renamed, deleted or replaced
    while the handle is open. With reparse, a link there is opened itself, never followed."""
    import ctypes
    _win_k32()
    # FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES; share read and write but not delete. A handle with only
    # attribute access would not count against delete sharing, so the listing right is needed.
    flags = 0x02000000 | (0x00200000 if reparse else 0)  # BACKUP_SEMANTICS (folders), OPEN_REPARSE_POINT
    h = _WIN_K32.CreateFileW(_win_long(path), 0x0001 | 0x0080, 0x1 | 0x2, None, 3, flags, None)
    if h is None or h == ctypes.c_void_p(-1).value:
        err = ctypes.get_last_error()
        raise OSError(None, ctypes.FormatError(err).strip(), os.fspath(path), err)
    return h


def _win_handle_stat(h):
    """Windows: os.fstat of the folder an open handle holds, read through a duplicate of that handle. Its identity
    is the held folder's, whatever its name leads to now, and it is read the way os.stat reads the identity
    _register_base records, so the two compare (M-03)."""
    import ctypes
    import msvcrt
    from ctypes import wintypes
    k = _win_k32()
    proc = k.GetCurrentProcess()
    dup = wintypes.HANDLE()
    if not k.DuplicateHandle(proc, h, proc, ctypes.byref(dup), 0, False, 0x2):  # DUPLICATE_SAME_ACCESS
        err = ctypes.get_last_error()
        raise OSError(None, ctypes.FormatError(err).strip(), None, err)
    try:
        fd = msvcrt.open_osfhandle(dup.value, os.O_RDONLY)
    except BaseException:
        k.CloseHandle(dup)
        raise
    try:
        return os.fstat(fd)
    finally:
        os.close(fd)


def _win_final(h):
    """Where an open handle really is, after every link and junction, or None if the system cannot say."""
    import ctypes
    try:
        buf = ctypes.create_unicode_buffer(32768)
        n = _WIN_K32.GetFinalPathNameByHandleW(h, buf, 32768, 0)
        return buf.value if 0 < n < 32768 else None
    except Exception:  # noqa: BLE001
        return None


def _win_release(h) -> None:
    try:
        _WIN_K32.CloseHandle(h)
    except Exception:
        pass


def _win_is_link(h) -> bool:
    """Windows: True when the object an open handle refers to is now a link or junction (a reparse point), or
    when that cannot be read."""
    import ctypes
    from ctypes import wintypes

    class _Info(ctypes.Structure):
        _fields_ = [("attrs", wintypes.DWORD), ("rest", ctypes.c_byte * 48)]
    info = _Info()
    try:
        if not _win_k32().GetFileInformationByHandle(h, ctypes.byref(info)):
            return True
    except Exception:  # noqa: BLE001
        return True
    return bool(info.attrs & 0x400)


def _win_change_time(path):
    """Windows: the NTFS change time of the file at path, in 100-nanosecond units, or None when it cannot be read.
    Writing a file's data or setting its times updates it, so a same-size rewrite that restores the modification
    time still changes it; os.stat on Windows does not report it (C-04)."""
    import ctypes
    from ctypes import wintypes

    class _Basic(ctypes.Structure):
        _fields_ = [("created", ctypes.c_longlong), ("accessed", ctypes.c_longlong), ("written", ctypes.c_longlong),
                    ("changed", ctypes.c_longlong), ("attrs", wintypes.DWORD)]
    try:
        k = _win_k32()
        get = k.GetFileInformationByHandleEx
        get.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        get.restype = wintypes.BOOL
        # FILE_READ_ATTRIBUTES only, sharing everything, so the file stays usable by whoever has it open.
        h = k.CreateFileW(_win_long(path), 0x0080, 0x1 | 0x2 | 0x4, None, 3, 0x02000000, None)
    except Exception:  # noqa: BLE001
        return None
    if h is None or h == ctypes.c_void_p(-1).value:
        return None
    try:
        info = _Basic()
        if not get(h, 0, ctypes.byref(info), ctypes.sizeof(info)):  # FileBasicInfo
            return None
        return int(info.changed)
    finally:
        k.CloseHandle(h)


def _source_key(path, st) -> list:
    """What must match for an artifact's cached digest to be reused: size, modification time, change time and
    file id. On Windows os.stat reports the creation time as st_ctime, so the NTFS change time is added; when it
    cannot be read the key holds None, which never matches a stored key (C-04)."""
    key = [st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino]
    if IS_WINDOWS:
        key.append(_win_change_time(path))
    return key


def _win_set_attrs(path, touch: bool = False, times_ns: tuple | None = None, clear_readonly: bool = False) -> bool:
    """Windows: change the times or the read-only flag of the regular file at path itself, through a handle on
    it. A link there is opened itself, never followed, and is refused. The handle does not share delete, so the
    name cannot be moved or replaced while pecia works on it, and the change is made only while the file has no
    other name: through a hard link it would reach a file outside the repository (X-06, X-08). touch sets the
    access and modification times to now; times_ns sets them to (atime_ns, mtime_ns). False when refused."""
    import ctypes
    from ctypes import wintypes

    class _Info(ctypes.Structure):
        _fields_ = [("attrs", wintypes.DWORD), ("created", wintypes.FILETIME), ("accessed", wintypes.FILETIME),
                    ("written", wintypes.FILETIME), ("volume", wintypes.DWORD), ("size_hi", wintypes.DWORD),
                    ("size_lo", wintypes.DWORD), ("links", wintypes.DWORD), ("index_hi", wintypes.DWORD),
                    ("index_lo", wintypes.DWORD)]

    class _Basic(ctypes.Structure):
        _fields_ = [("created", ctypes.c_longlong), ("accessed", ctypes.c_longlong), ("written", ctypes.c_longlong),
                    ("changed", ctypes.c_longlong), ("attrs", wintypes.DWORD)]
    k = _win_k32()
    # FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES; share read and write, not delete;
    # OPEN_EXISTING; OPEN_REPARSE_POINT | BACKUP_SEMANTICS. A handle with only attribute access would not
    # count against delete sharing (see _win_hold), so the data right is what keeps the name in place.
    h = k.CreateFileW(_win_long(path), 0x0001 | 0x0080 | 0x0100, 0x1 | 0x2, None, 3, 0x00200000 | 0x02000000, None)
    if h is None or h == ctypes.c_void_p(-1).value:
        return False
    try:
        info = _Info()
        if not k.GetFileInformationByHandle(h, ctypes.byref(info)):
            return False
        if info.attrs & (0x10 | 0x400) or info.links != 1:  # a folder, a link or junction, or more than one name
            return False
        basic = _Basic(0, 0, 0, 0, 0)  # zero leaves a field as it is
        if touch:
            now = wintypes.FILETIME()
            k.GetSystemTimeAsFileTime(ctypes.byref(now))
            basic.accessed = basic.written = (now.dwHighDateTime << 32) | now.dwLowDateTime
        elif times_ns is not None:
            basic.accessed, basic.written = (t // 100 + 116444736000000000 for t in times_ns)
        if clear_readonly and info.attrs & 0x1:
            basic.attrs = (info.attrs & ~0x1) or 0x80  # FILE_ATTRIBUTE_NORMAL when nothing else is left
        if basic.accessed or basic.written or basic.attrs:
            return bool(k.SetFileInformationByHandle(h, 0, ctypes.byref(basic), ctypes.sizeof(basic)))
        return True
    finally:
        _win_release(h)


class _HeldDir:
    """A folder held so that work inside it cannot be redirected by swapping it, or a folder on the way
    from base, for a link. base itself is opened as given (it is trusted: a resolved working tree or git
    directory, or the store location the user chose); each name below it must be a real folder, and
    with create a missing one is made. A link or non-folder on the way raises UnsafePath."""

    def __init__(self, base, names, create: bool = False):
        self.path = Path(base).joinpath(*names)
        self.fd = None
        self._handles = []
        for n in names:
            if n in ("", ".", "..") or "/" in n or (IS_WINDOWS and ("\\" in n or ":" in n)):
                raise UnsafePath(f"{fwd(self.path)}: invalid path component {n!r}")
        try:
            if _DIR_FDS:
                self.fd = os.open(os.fspath(base), os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC)
                _check_base_identity(base, os.fstat(self.fd))
                shown = Path(base)
                for n in names:
                    shown = shown / n
                    nfd = _open_child_dir(self.fd, n, create, shown)
                    os.close(self.fd)
                    self.fd = nfd
            elif IS_WINDOWS:
                cur = Path(base)
                self._handles.append(_win_hold(cur, reparse=False))
                # The identity checked is the held folder's, read through its handle. A stat of the name could
                # pass while the handle held another folder, reached through a link put there just before it was
                # opened and removed just after (M-03). Unreadable is refused: pecia cannot tell what it holds.
                try:
                    held = _win_handle_stat(self._handles[-1])
                except (OSError, ValueError, AttributeError) as e:
                    raise UnsafePath(f"{fwd(base)}: pecia could not read which folder it holds there ({e}), so it "
                                     "refuses to write there.") from None
                _check_base_identity(base, held)
                for n in names:
                    cur = cur / n
                    if create and not os.path.lexists(cur):
                        try:
                            os.mkdir(cur)
                        except FileExistsError:
                            pass
                    self._handles.append(_win_hold(cur, reparse=True))
                    _check_held(cur)
            else:  # no descriptor-relative calls here: the checks pecia made before rc7, by path
                cur = Path(base)
                _check_base_identity(base, os.stat(cur))
                for n in names:
                    cur = cur / n
                    if create and not os.path.lexists(cur):
                        try:
                            os.mkdir(cur)
                        except FileExistsError:
                            pass
                    _check_held(cur)
        except BaseException:
            self.close()
            raise

    def child(self, name: str, create: bool = False) -> "_HeldDir":
        """A folder directly inside this one, held the same way. Keep this one open while using it."""
        if name in ("", ".", "..") or "/" in name or (IS_WINDOWS and ("\\" in name or ":" in name)):
            raise UnsafePath(f"{fwd(self.path)}: invalid path component {name!r}")
        c = _HeldDir.__new__(_HeldDir)
        c.path, c.fd, c._handles = self.path / name, None, []
        try:
            if self.fd is not None:
                c.fd = _open_child_dir(self.fd, name, create, c.path)
            else:
                if create and not os.path.lexists(c.path):
                    try:
                        os.mkdir(c.path)
                    except FileExistsError:
                        pass
                if IS_WINDOWS:
                    c._handles.append(_win_hold(c.path, reparse=True))
                _check_held(c.path)
        except BaseException:
            c.close()
            raise
        return c

    def close(self) -> None:
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None
        for h in self._handles:
            _win_release(h)
        self._handles = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def _check_made_inside(self, name: str, fd: int | None = None, made: bool = True) -> None:
        """Windows: what pecia just created must really be inside this folder. An empty folder can be
        turned into a junction, and back, while held; the final path of the new file or folder shows
        where it really went, and anything made elsewhere is removed again (U1)."""
        if not (IS_WINDOWS and self._handles):
            return
        folder = _win_final(self._handles[-1])
        if fd is not None:
            import msvcrt
            try:
                item = _win_final(msvcrt.get_osfhandle(fd))
            except OSError:
                item = None
        else:
            try:
                h = _win_hold(self.path / name, reparse=True)
            except OSError:
                return
            item = _win_final(h)
            _win_release(h)
        if folder is None or item is None:
            return  # the system cannot say; the held folders still cannot be renamed or replaced
        if os.path.normcase(os.path.dirname(item)) == os.path.normcase(folder):
            return
        if fd is not None:
            os.close(fd)
        # What pecia made out there is left and named, not removed: by the time it could be removed by name, that name
        # may lead somewhere else, and removing it would then delete something pecia never made (H-02).
        stray = f"; pecia created an empty {'file' if fd is not None else 'folder'} at {fwd(item)} and left it there" \
            if made else ""
        raise UnsafePath(f"{fwd(self.path / name)} is not inside {fwd(self.path)} (a link or junction); nothing was "
                         f"written{stray}")

    def _at(self, name: str):
        return (name, {"dir_fd": self.fd}) if self.fd is not None else (os.fspath(self.path / name), {})

    def names(self) -> list:
        listed = os.listdir(self.fd if self.fd is not None else os.fspath(self.path))
        if IS_WINDOWS and self._handles and _win_is_link(self._handles[-1]):
            # An empty folder can be turned into a junction while held, and a listing by name would then show the
            # entries of the folder it points to. The held folder itself is checked after listing: anything
            # listed through a junction is refused, and a folder still empty at the listing yields no names.
            raise UnsafePath(f"{fwd(self.path)} became a link or junction while pecia held it; nothing in it was changed")
        return listed

    def lstat(self, name: str):
        p, kw = self._at(name)
        return os.stat(p, follow_symlinks=False, **kw)

    def unlink(self, name: str) -> None:
        p, kw = self._at(name)
        os.unlink(p, **kw)

    def unlink_quietly(self, name: str) -> None:
        try:
            self.unlink(name)
        except OSError:
            pass

    def rmdir(self, name: str) -> None:
        p, kw = self._at(name)
        os.rmdir(p, **kw)

    def open_fd(self, name: str, flags: int, mode: int = 0o644) -> int:
        p, kw = self._at(name)
        fd = os.open(p, flags | _O_NOFOLLOW | _O_CLOEXEC, mode, **kw)
        if flags & os.O_CREAT:
            self._check_made_inside(name, fd, made=bool(flags & os.O_EXCL))
        return fd

    def open_read(self, name: str):
        """A regular file here, opened for reading without following a link or blocking on a pipe."""
        if self.fd is None and _is_link(self.path / name):
            raise OSError(errno.ELOOP, "a symlink or junction", fwd(self.path / name))
        fd = self.open_fd(name, _READ_FLAGS)
        try:
            if not stat_mod.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(errno.EINVAL, "not a regular file", fwd(self.path / name))
            return os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise

    def new_temp(self, prefix: str):
        """(descriptor, name) of a new, empty file here that nobody else has opened."""
        if self.fd is None:
            fd, full = tempfile.mkstemp(dir=os.fspath(self.path), prefix=prefix)
            self._check_made_inside(os.path.basename(full), fd)
            return fd, os.path.basename(full)
        for _ in range(100):
            name = prefix + secrets.token_hex(6)
            try:
                return os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC, 0o600,
                               dir_fd=self.fd), name
            except FileExistsError:
                continue
        raise FileExistsError(errno.EEXIST, "no free temporary name", fwd(self.path))

    def new_folder(self, prefix: str) -> str:
        """The name of a new, empty folder made here."""
        if self.fd is None:
            name = os.path.basename(tempfile.mkdtemp(dir=os.fspath(self.path), prefix=prefix))
            self._check_made_inside(name)
            return name
        for _ in range(100):
            name = prefix + secrets.token_hex(6)
            try:
                os.mkdir(name, 0o700, dir_fd=self.fd)
                return name
            except FileExistsError:
                continue
        raise FileExistsError(errno.EEXIST, "no free folder name", fwd(self.path))

    def set_mode(self, fd: int, name: str, mode: int) -> None:
        try:
            if self.fd is not None or not IS_WINDOWS:
                os.fchmod(fd, mode)
            else:
                os.chmod(self.path / name, mode)
        except (OSError, AttributeError):
            pass

    def replace(self, src: str, dst: str, into: "_HeldDir | None" = None) -> None:
        """Move src here to dst here (or in into), replacing a file at dst."""
        to = into or self
        if self.fd is not None:
            _replace_with_retry(src, dst, src_dir_fd=self.fd, dst_dir_fd=to.fd)
        else:
            _replace_with_retry(self.path / src, to.path / dst)

    def link_no_clobber(self, src: str, dst: str) -> None:
        """Give src the name dst atomically, failing with FileExistsError if dst exists; then drop src.
        Windows rename never replaces an existing file; elsewhere a hard link gives the same guarantee.
        A file system without hard links offers no atomic way to publish without overwriting, so the
        write is refused there rather than risk a partial file at dst if it is interrupted."""
        if self.fd is None and IS_WINDOWS:
            os.rename(self.path / src, self.path / dst)
            return
        p, kw = self._at(src)
        q, kw2 = self._at(dst)
        nofollow = {"follow_symlinks": False} if os.link in os.supports_follow_symlinks else {}
        try:
            if self.fd is not None:
                os.link(src, dst, src_dir_fd=self.fd, dst_dir_fd=self.fd, **nofollow)
            else:
                os.link(p, q, **nofollow)
        except FileExistsError:
            raise
        except OSError as e:
            raise NoAtomicPublish(
                f"this file system cannot create hard links ({e.strerror or e}), so pecia cannot publish the "
                "restored file without risking a partial file if interrupted; nothing was written. Use "
                "the recover inspect command and copy the file by hand.") from e
        self.unlink(src)


def _open_child_dir(fd: int, name: str, create: bool, shown: Path) -> int:
    flags = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC
    for attempt in range(2):
        try:
            return os.open(name, flags, dir_fd=fd)
        except FileNotFoundError:
            if not create or attempt:
                raise
            try:
                os.mkdir(name, 0o777, dir_fd=fd)
            except FileExistsError:
                pass
        except PermissionError:
            # A folder that may be searched but not listed: Linux can still hold it with O_PATH.
            if not getattr(os, "O_PATH", 0):
                raise
            return os.open(name, os.O_PATH | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=fd)
        except OSError as e:
            if e.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
                raise UnsafePath(f"{fwd(shown)} is a symlink or junction, or not a folder. pecia refuses to "
                                 "work through it, since it could lead outside the repository.") from None
            raise
    raise FileNotFoundError(errno.ENOENT, "folder vanished", fwd(shown))


def _ident(st) -> tuple:
    return (st.st_dev, st.st_ino)


def _check_published(d: "_HeldDir", name: str, ident: tuple, shown: str, digest: str | None = None) -> None:
    """After publishing, the name must hold the file pecia wrote. Something that swapped pecia's
    temporary file in the instant before it was published is reported, never trusted. Only where
    folders are held by descriptor: a Windows rename moves the entry itself and never follows a link,
    and FAT volumes there renumber a file when it is renamed."""
    if d.fd is None:
        return
    try:
        same = _ident(d.lstat(name)) == ident
    except OSError:
        same = False
    if not same and digest is not None:
        # Some file systems, FAT among them, number a file by its directory entry, which a rename changes
        # (U4); the bytes then decide.
        try:
            h = hashlib.sha256()
            with d.open_read(name) as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            same = h.hexdigest() == digest
        except OSError:
            same = False
    if not same:
        raise OSError(errno.EEXIST, "the file was replaced while pecia published it; check it by hand", shown)


def _check_held(p: Path) -> None:
    if not os.path.lexists(p):
        raise FileNotFoundError(errno.ENOENT, "no such folder", fwd(p))
    if _is_link(p) or not os.path.isdir(p):
        raise UnsafePath(f"{fwd(p)} is a symlink or junction, or not a folder. pecia refuses to work through "
                         "it, since it could lead outside the repository.")


def load_json(path: Path, default=None):
    try:
        return json.loads(_read_regular(path, _JSON_LIMIT).decode("utf-8"))
    except (OSError, ValueError):
        return default


def deep_merge(base: dict, extra: dict) -> dict:
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def fwd(path) -> str:
    return str(path).replace("\\", "/")


# ---------------------------------------------------------------- git

# GIT_DIFF_OPTS sets a diff's context after its options, so it would widen the hunks pecia reads (R24-234); git diff's
# external program is never one pecia asks for.
_SCRUB_ENV = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
              "GIT_COMMON_DIR", "GIT_PREFIX", "GIT_NAMESPACE", "GIT_DIFF_OPTS", "GIT_EXTERNAL_DIFF")


# A git setting in the repository could otherwise make pecia's own git calls run a command or hang: an
# fsmonitor hook runs on status and on staging, also in a submodule, whose child git inherits these, and an
# order file that is a named pipe blocks status and diff (R19-C1). The repository's git hooks would run too:
# reference-transaction on every snapshot ref and post-index-change on every scratch index (X-07), and a log
# that shows signatures runs the configured verifier (Z-04).


def _no_hooks_path() -> str:
    """A hooks folder that cannot exist, so git finds no hook at all: a name below a system file that only an
    administrator can replace, never below pecia's own file, which may sit in a working tree an agent can edit
    (Z-05). On Linux and macOS that is the null device; on Windows, kernel32.dll in the system folder."""
    if os.name != "nt":
        return "/dev/null/no-hooks"
    system = ""
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(260)
        if 0 < ctypes.windll.kernel32.GetSystemDirectoryW(buf, 260) < 260:
            system = buf.value
    except Exception:  # noqa: BLE001
        system = ""
    system = system or os.path.join(os.environ.get("SystemRoot") or r"C:\Windows", "System32")
    return fwd(os.path.join(system, "kernel32.dll", "no-hooks"))


_NO_HOOKS = _no_hooks_path()
_GIT_SAFE = ("-c", "core.fsmonitor=false", "-c", "diff.orderFile=/dev/null", "-c", f"core.hooksPath={_NO_HOOKS}",
             "-c", "log.showSignature=false")


def find_program(name: str):
    """The full path of the program name on PATH, or None. Only absolute PATH entries are searched: never the
    current folder, which Windows searches first for a bare name (CreateProcess, cmd.exe and shutil.which), and
    never an empty or relative entry, which means the current folder too. pecia runs in the repository, so a git.exe,
    codex.cmd or claude.exe placed there would otherwise run instead (G4-02). On Windows the PATHEXT extensions are
    tried as cmd.exe does. A name with a folder in it is not looked up here."""
    if os.path.isabs(name):
        return name if os.path.isfile(name) else None
    if "/" in name or "\\" in name:
        return None
    exts = [""]
    if IS_WINDOWS:
        known = [e for e in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(os.pathsep) if e]
        exts = ([""] if os.path.splitext(name)[1].upper() in {e.upper() for e in known} else []) + known
    for d in os.environ.get("PATH", os.defpath).split(os.pathsep):
        d = d.strip().strip('"') if IS_WINDOWS else d
        if not d or not os.path.isabs(d):
            continue
        for ext in exts:
            p = os.path.join(d, name + ext)
            if os.path.isfile(p) and (IS_WINDOWS or os.access(p, os.X_OK)):
                return p
    return None


_GIT_EXE: dict = {}


def _git_exe() -> str:
    """git's full path, found once per PATH value (G4-02). A missing git raises the error starting it by name gave."""
    key = os.environ.get("PATH", "")
    exe = _GIT_EXE.get(key)
    if exe is None:
        exe = find_program("git")
        if exe is None:
            raise FileNotFoundError(errno.ENOENT, "git was not found on PATH", "git")
        _GIT_EXE[key] = exe
    return exe


_MEMO: dict | None = None  # while a latest search runs: what git says that cannot change during it (R24-12)
_SHA_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


@contextlib.contextmanager
def _search_memo():
    """Within one latest search, HEAD, the branch, and what git says about a commit given by its full ID are read once:
    the search plans every older snapshot, and these do not change while it runs, as pecia writes nothing then."""
    global _MEMO
    outer = _MEMO
    if outer is None:
        _MEMO = {}
    try:
        yield
    finally:
        if outer is None:
            _MEMO = None


def _memo_lru(name: str, key, make, size: int = 16):
    """make(), remembered under key among the last size results of its kind while a search runs."""
    if _MEMO is None:
        return make()
    lru = _MEMO.setdefault(name, {})
    if key in lru:
        lru[key] = lru.pop(key)  # most recent last
        return lru[key]
    value = make()
    lru[key] = value
    while len(lru) > size:
        lru.pop(next(iter(lru)))
    return value


def run_git(cwd, args, env=None, input_bytes=None, check=True, pass_fds=()):
    full_env = dict(os.environ)
    for k in _SCRUB_ENV:
        full_env.pop(k, None)
    full_env["GIT_TERMINAL_PROMPT"] = "0"
    if env:
        full_env.update(env)
    kwargs = {"cwd": str(cwd), "env": full_env, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
    if pass_fds:
        kwargs["pass_fds"] = tuple(pass_fds)
    if input_bytes is None:
        kwargs["stdin"] = subprocess.DEVNULL
    else:
        kwargs["input"] = input_bytes
    p = subprocess.run([_git_exe(), *_GIT_SAFE, *args], **kwargs)
    if check and p.returncode != 0:
        raise GitError(args, p.returncode, p.stderr.decode("utf-8", "replace"))
    return p


def git_text(cwd, *args, env=None, check=True) -> str:
    out = run_git(cwd, list(args), env=env, check=check).stdout
    return out.decode("utf-8", "surrogateescape").rstrip("\n")


def z_split(data: bytes) -> list[str]:
    seen, out = set(), []
    for part in data.split(b"\0"):
        if not part:
            continue
        s = part.decode("utf-8", "surrogateescape")
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def nul_join(paths) -> bytes:
    return b"\0".join(p.encode("utf-8", "surrogateescape") for p in paths)


class Repo:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self._fmt = None
        self._common = None
        _register_base(self.root)

    @staticmethod
    def discover(explicit=None) -> "Repo":
        if explicit:
            base = Path(explicit)
        else:
            here = Path(__file__).resolve()
            if here.parent.name == "bin" and here.parent.parent.name == PECIA_DIR:
                return Repo(here.parent.parent.parent)
            base = Path(os.getcwd())
        try:
            top = git_text(base, "rev-parse", "--show-toplevel")
        except (GitError, OSError):
            raise PeciaError(f"not inside a git working tree: {base}")
        return Repo(top)

    def path(self, rel: str) -> Path:
        return self.root.joinpath(*rel.split("/"))

    @property
    def runtime(self) -> Path:
        # pecia keeps its lock, heartbeats, records and backups here. A symlink or junction at
        # .pecia or .pecia/runtime would send those writes outside the repository. So would any link
        # inside .pecia/runtime, and the only way one arrives with a clone is as a tracked file:
        # the folder is excluded locally, so nothing in it should ever be tracked. Both are refused.
        # Checked on every use, not once per process: launch and watch run for hours, and an agent they
        # started could put a link here meanwhile (R10-02).
        for rel in (PECIA_DIR, RUNTIME_REL):
            if _is_link(self.path(rel)):
                raise PeciaError(f"{rel} is a symlink or junction. pecia refuses to keep its state through a "
                                 "link that can point outside the repository. Replace it with a regular folder.")
        if not getattr(self, "_runtime_ok", False):
            tracked = run_git(self.root, ["ls-files", "-s", "-z", "--", RUNTIME_REL], check=False)
            links = [rec.split(b"\t", 1)[1].decode("utf-8", "replace") for rec in tracked.stdout.split(b"\0")
                     if rec.startswith(b"120000 ") and b"\t" in rec]
            if links:
                raise PeciaError(f"{RUNTIME_REL} holds a symlink tracked by git ({links[0]}). It is pecia's private "
                                 "state folder, and a committed link there could send pecia's writes to a file "
                                 f"outside the repository. Remove it with: git rm {links[0]}")
            self._runtime_ok = True
        return self.path(RUNTIME_REL)

    def ensure_runtime(self) -> Path:
        self.runtime  # refuses a link there with its own message
        _HeldDir(self.root, RUNTIME_REL.split("/"), create=True).close()
        if not getattr(self, "_excluded", False):
            # The state folder must never be committed, even in a clone where init never ran.
            try:
                _ensure_local_exclude(self, [".pecia/runtime/", ".pecia-restore-*"])
            except (OSError, PeciaError):
                pass
            self._excluded = True
        return self.runtime

    def git_path(self, name: str) -> Path:
        p = Path(git_text(self.root, "rev-parse", "--git-path", name))
        return p if p.is_absolute() else (self.root / p).resolve()

    def git_dir(self) -> Path:
        """This working tree's own git directory, resolved. pecia builds the paths of its own folders
        below it without resolving them, so a link planted at one of them is seen, never followed."""
        if getattr(self, "_gitdir", None) is None:
            self._gitdir = Path(git_text(self.root, "rev-parse", "--absolute-git-dir")).resolve()
            _register_base(self._gitdir)
        return self._gitdir

    def common_dir(self) -> Path:
        if self._common is None:
            p = Path(git_text(self.root, "rev-parse", "--git-common-dir"))
            self._common = p if p.is_absolute() else (self.root / p).resolve()
            _register_base(self._common)
        return self._common

    def object_format(self) -> str:
        if self._fmt is None:
            p = run_git(self.root, ["rev-parse", "--show-object-format"], check=False)
            self._fmt = p.stdout.decode().strip() if p.returncode == 0 and p.stdout.strip() else "sha1"
        return self._fmt

    def zero_oid(self) -> str:
        return "0" * (64 if self.object_format() == "sha256" else 40)

    def head(self):
        memo = _MEMO.get(("head", str(self.root))) if _MEMO is not None else None
        if memo is not None:
            return memo[0]
        p = run_git(self.root, ["rev-parse", "--verify", "-q", "HEAD^{commit}"], check=False)
        out = p.stdout.decode().strip() if p.returncode == 0 else None
        if _MEMO is not None:
            _MEMO[("head", str(self.root))] = (out,)
        return out

    def branch(self):
        memo = _MEMO.get(("branch", str(self.root))) if _MEMO is not None else None
        if memo is not None:
            return memo[0]
        p = run_git(self.root, ["symbolic-ref", "-q", "--short", "HEAD"], check=False)
        out = p.stdout.decode().strip() if p.returncode == 0 else None
        if _MEMO is not None:
            _MEMO[("branch", str(self.root))] = (out,)
        return out

    def worktree_id(self, create: bool = True):
        # Stored in the per-worktree git directory so it survives renaming or moving the folder.
        # With create False (a dry run) a missing id is not written, and None is returned (T-03).
        if not getattr(self, "_wtid", None):
            idfile = self.git_dir() / "pecia-worktree-id"
            if not create:
                return _read_stable_id(idfile, self.root.name)
            self._wtid = _stable_id(idfile, self.root.name)
        return self._wtid

    def log_event(self, event: str, **data) -> None:
        """Append one line to the event log. Never raises, and never follows a symlink."""
        try:
            self.ensure_runtime()
            line = json.dumps({"ts": iso(), "event": event, **data}, sort_keys=True, default=str) + "\n"
            path = self.runtime / "events.jsonl"
            if _is_link(path):
                return
            flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
            with _held_dir(path.parent) as d:
                # A new log is created exclusively, which never follows a link at its name; an existing one is
                # opened without creating anything, and on Windows, where opens follow a link at the name, it
                # must really be in this folder (Z-02).
                try:
                    fd = d.open_fd(path.name, flags | os.O_CREAT | os.O_EXCL, 0o644)
                except FileExistsError:
                    fd = d.open_fd(path.name, flags)
                    d._check_made_inside(path.name, fd, made=False)
            try:
                # Append only to a regular file that has no other name: a hard link would send the line
                # into a file outside the repository (U-01), and a pipe would block (U-02). Anything
                # else drops this optional log line.
                st = os.fstat(fd)
                if stat_mod.S_ISREG(st.st_mode) and st.st_nlink <= 1:
                    os.write(fd, line.encode("utf-8"))
            finally:
                os.close(fd)
        except Exception:
            pass


def recorded_policy_path(repo: Repo, create: bool = True):
    """The copy of .pecia/policy.json recorded for this working tree beside the hook runner. There is one
    per working tree, written only by init and when pecia creates a worktree, never by a snapshot: a
    single copy that every snapshot refreshed let another branch's or worktree's policy decide what a
    later checkout excluded (R4-02). With create False, a working tree that has no id yet gets None and
    no id is written, so a dry run changes nothing (T-03)."""
    wid = repo.worktree_id(create=create)
    return None if wid is None else runner_dir(repo) / f"policy-{wid}.json"


def _main_tree_recorded_policy(repo: Repo):
    try:
        wid = _read_regular(repo.common_dir() / "pecia-worktree-id").decode("utf-8").strip()
    except (OSError, ValueError):
        return None
    return runner_dir(repo) / f"policy-{wid}.json" if re.fullmatch(r"[A-Za-z0-9_-]{1,60}", wid) else None


def policy_source(repo: Repo):
    """The policy file in effect: the working tree's .pecia/policy.json; on a checkout without one, such
    as another branch or a commit from before init, the copy init recorded for this working tree, or else
    the copy recorded for the main working tree; otherwise None, the built-in defaults."""
    p = repo.path(POLICY_REL)
    if p.exists():
        return p
    try:
        for rec in (recorded_policy_path(repo, create=False), _main_tree_recorded_policy(repo)):
            if rec is not None and rec.is_file() and not _is_link(rec):
                return rec
    except (PeciaError, OSError):
        pass
    return None


def load_policy(repo: Repo) -> dict:
    pol = json.loads(json.dumps(DEFAULT_POLICY))
    p = policy_source(repo)
    if p is not None:
        name = POLICY_REL if p == repo.path(POLICY_REL) else fwd(p)
        try:
            user = json.loads(_read_regular(p, _TEXT_LIMIT).decode("utf-8"))
        except (ValueError, RecursionError) as e:
            raise PeciaError(f"invalid {name}: {type(e).__name__}: {e}")
        if not isinstance(user, dict):
            raise PeciaError(f"invalid {name}: it must hold a JSON object, not {type(user).__name__}")
        _warned, refused = _mistyped_sections(user)
        if refused:
            # The guard then fails closed and each snapshot hook records the failed capture (XA1-15, RT-15).
            raise PeciaError(f"invalid {name}: {refused[0]}")
        deep_merge(pol, user)
        _normalize_pattern_lists(pol)
    return pol


def _json_kind(value) -> str:
    """How a JSON value is named in a message about it."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true or false"
    return {list: "a list", str: "a string", int: "a number", float: "a number"}.get(type(value), type(value).__name__)


def _mistyped_sections(user: dict) -> tuple[list, list]:
    """The sections of a policy that are not JSON objects, checked before the policy is merged with the defaults; load_policy
    and doctor both use this one rule. deep_merge put such a value in place of the whole section, and what read the section
    then failed or read nothing: an artifacts section that was a list, null or a string stored no designated file without
    a word, and recover apply latest restored an older stored copy as complete (XA1-05). Such an artifacts section is not
    merged: its defaults stay and include_globs is marked unreadable, so every snapshot still records the working tree and
    reports the files designated before as not covered until the section is fixed. user is changed in place. Returns
    (warnings, errors): doctor prints both; load_policy refuses a policy with errors.
    A snapshot, guard, lock or agents section that is not an object is an error: snapshotting under the default
    exclusions would drop the user's own, and the hook used to fail on it without a word while the guard admitted the
    session (XA1-15). load_policy refuses the policy, as one that does not parse, so the guard fails closed and every
    capture path records the failed capture (RP-01, RT-15)."""
    warnings: list = []
    errors: list = []
    for sec in ("snapshot", "guard", "lock", "agents"):
        if sec in user and not isinstance(user[sec], dict):
            errors.append(f"the {sec} section must be a JSON object, not {_json_kind(user[sec])}")
    if "artifacts" in user and not isinstance(user["artifacts"], dict):
        value, kind = user["artifacts"], _json_kind(user["artifacts"])
        why = (f"the artifacts section of {POLICY_REL} is not a JSON object ({kind}), so no designated file was stored; "
               "write it as an object, such as {\"include_globs\": [\"results/*.csv\"]}")
        user["artifacts"] = {"include_globs": _UnreadableDesignation(value, why)}
        warnings.append(f"the artifacts section of {POLICY_REL} is not a JSON object ({kind}); no file can be designated, "
                        "and each snapshot reports the files designated before as not covered until it is written as "
                        "an object, such as {\"include_globs\": [\"results/*.csv\"]}")
    return warnings, errors


_PATTERN_LISTS = (("snapshot", "exclude_globs"), ("artifacts", "include_globs"), ("artifacts", "prune_dirs"))


class _UnreadableDesignation(list):
    """artifacts.include_globs as load_policy leaves it when the policy's value is neither a pattern nor a list, or when
    the artifacts section itself is not an object (XA1-05): no pattern can be read, and capture_artifacts reports the files
    designated before as not covered instead of storing none of them without a word (G1-07). It is an empty list
    everywhere else, as the recorded policy shows."""

    def __init__(self, value, why: str | None = None):
        super().__init__()
        self.value = value
        self.why = why


class _PartlyReadableDesignation(list):
    """artifacts.include_globs as load_policy leaves it when its list holds entries that are not strings: the patterns
    that are strings, with the entries left out. capture_artifacts uses the patterns and reports as not covered the
    files designated before that none of them matches, since a dropped entry may have been what designated them
    (IR31-01)."""

    def __init__(self, kept, dropped):
        super().__init__(kept)
        self.dropped = dropped


def _normalize_pattern_lists(pol: dict) -> list:
    """A pattern list written as one string, such as "*.env", was read character by character, so a
    lone * excluded every file from snapshots. A string now counts as a list of one pattern. In a list, the entries
    that are not strings are left out and the other patterns kept: one bad entry used to replace the whole list by the
    default, which for artifacts.include_globs designates nothing, so no designated file was stored and recovery then
    restored an older stored version as complete (G1-07). Any other value falls back to the default, except for
    artifacts.include_globs, where it marks the designation unreadable. Returns what was changed, for doctor."""
    changed = []
    for sec, key in _PATTERN_LISTS:
        section = pol.get(sec)
        if not isinstance(section, dict) or key not in section:
            continue
        v = section[key]
        if isinstance(v, str):
            section[key] = [v]
            changed.append(f"{sec}.{key} is a single string; it is read as a list of that one pattern")
        elif isinstance(v, list) and not all(isinstance(x, str) for x in v):
            bad = [x for x in v if not isinstance(x, str)]
            kept = [x for x in v if isinstance(x, str)]
            if (sec, key) == ("artifacts", "include_globs") and not kept:
                # No entry is a pattern: nothing can be designated, as for a value that is no list (IR31-01).
                section[key] = _UnreadableDesignation(v)
                changed.append(f"{sec}.{key} holds no entry that is a pattern ({json.dumps(bad, default=str)[:80]}); "
                               "no file can be designated, and each snapshot reports the files designated before as "
                               "not covered until it is fixed")
            elif (sec, key) == ("artifacts", "include_globs"):
                section[key] = _PartlyReadableDesignation(kept, bad)
                changed.append(f"{sec}.{key} holds entries that are not strings ({json.dumps(bad, default=str)[:80]}); "
                               "they are left out and the other patterns are used, and each snapshot reports the "
                               "files designated before that no other pattern matches as not covered until it is "
                               "fixed")
            else:
                section[key] = kept
                changed.append(f"{sec}.{key} holds entries that are not strings ({json.dumps(bad, default=str)[:80]}); "
                               "they are left out and the other patterns are used")
        elif not isinstance(v, list) and (sec, key) == ("artifacts", "include_globs"):
            section[key] = _UnreadableDesignation(v)
            changed.append(f"{sec}.{key} is neither a pattern nor a list of patterns; no file can be designated, and "
                           "each snapshot reports the files designated before as not covered until it is fixed")
        elif not isinstance(v, list):
            section[key] = list(DEFAULT_POLICY[sec][key])
            changed.append(f"{sec}.{key} is not a list of strings; the default is used instead")
    return changed


# ---------------------------------------------------------------- globs

_GLOB_CACHE: dict = {}


def _norm_pattern(pattern: str) -> str:
    """A pattern in the one form glob_regex, the artifact walk and _folder_may_hold all read: surrounding spaces removed,
    backslashes as /, ./ segments removed, and a leading ./ written as the leading / it means. ./results/*.csv, or the
    pattern with a leading space, designated nothing, because the walk started from a folder named with the space and the
    regex kept the ./ that no path has, and nothing said so (XA1-07). A pattern written with a leading ./ or / names the
    tree root, as a leading / always did."""
    pat = pattern.strip().replace("\\", "/")
    rooted = False
    while pat.startswith(("./", "/")):
        rooted = True
        pat = pat[2:] if pat.startswith("./") else pat[1:]
    while "/./" in pat:
        pat = pat.replace("/./", "/")
    if pat.endswith("/."):
        pat = pat[:-1]
    return ("/" + pat) if rooted else pat


def glob_regex(pattern: str, icase: bool = False):
    key = (pattern, icase)
    if key in _GLOB_CACHE:
        return _GLOB_CACHE[key]
    pat = _norm_pattern(pattern)
    if not pat:
        _GLOB_CACHE[key] = None
        return None
    if pat.endswith("/"):
        pat += "**"
    anchored = "/" in pat.rstrip("/")
    pat = pat.lstrip("/")
    out, i, n = [], 0, len(pat)
    while i < n:
        c = pat[i]
        if c == "*":
            if i + 1 < n and pat[i + 1] == "*":
                if i + 2 < n and pat[i + 2] == "/":
                    out.append("(?:[^/]*/)*")
                    i += 3
                    continue
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pat.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
            else:
                body = pat[i + 1:j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j + 1
                continue
        else:
            out.append(re.escape(c))
        i += 1
    body = "".join(out)
    # DOTALL and \Z: a name may hold a newline, which . did not match and before which $ matched, so a designated file
    # named with one was never stored and an excluded one was snapshotted (G1-03).
    rx = ("^" + body + r"\Z") if anchored else ("^(?:.*/)?" + body + r"\Z")
    compiled = re.compile(rx, re.DOTALL | (re.IGNORECASE if (icase or IS_WINDOWS) else 0))
    _GLOB_CACHE[key] = compiled
    return compiled


def _folder_may_hold(folder: str, patterns) -> bool:
    """Whether a file under folder (a path ending in /) could match one of patterns: true for an empty list (every
    path), for any pattern without a slash (it matches at any depth), and for one whose literal folders and folder
    lead one into the other. It may answer true where no file could match; never false where one could."""
    f = folder.strip("/")
    if not patterns:
        return True
    for pat in patterns:
        p = _norm_pattern(pat).lstrip("/")  # the form glob_regex reads (XA1-07)
        if "/" not in p.rstrip("/"):
            return True
        lit = []
        for part in p.split("/")[:-1]:
            if any(ch in part for ch in "*?["):
                break
            lit.append(part)
        prefix = "/".join(lit)
        if not prefix or f == prefix or f.startswith(prefix + "/") or prefix.startswith(f + "/"):
            return True
    return False


def match_any(path: str, patterns, icase: bool = False) -> bool:
    for pat in patterns or ():
        rx = glob_regex(pat, icase)
        if rx is not None and rx.match(path):
            return True
    return False


def is_excluded(path: str, excludes) -> bool:
    # Secret exclusion is always case-insensitive: .ENV and Credentials.json are still secrets.
    return match_any(path, excludes, icase=True)


# ---------------------------------------------------------------- STATE / REVIEW parsing

_HEADING = re.compile(r"^##\s+(.+?)\s*$")
_BULLET = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+(.*\S)\s*$")
_LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
_CHECKBOX = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+\[( |x|X)\]")
_OBL_ID = re.compile(r"(?<![A-Za-z0-9_-])([A-Z][A-Z0-9]*-\d+)(?![A-Za-z0-9_])")
_DISCHARGE = re.compile(r"^\s*(?:(?:[-*+]|\d+[.)])\s+)?[*_`]*DISCHARGED[*_`]*\s+[*_`]*([A-Z][A-Z0-9]*-\d+)[*_`]*\s*:\s*(.*)$")
_CONNECTORS = {"and", "or", "plus", "&"}


def parse_sections(text: str) -> dict:
    sections, cur = {}, None
    for line in text.splitlines():
        m = _HEADING.match(line)
        if m:
            cur = m.group(1).strip().upper()
            sections.setdefault(cur, [])
            continue
        if cur is not None:
            sections[cur].append(line)
    return sections


def _bullets(lines) -> list[str]:
    out = []
    for line in lines:
        m = _BULLET.match(line)
        if m:
            out.append(m.group(1))
    return out


def section(text: str, name: str) -> list[str]:
    """Lines of the first level-two heading whose name starts with NAME, so headings such as
    Open obligations or Scope of this task still resolve."""
    for key, lines in parse_sections(text).items():
        if key == name or key.startswith(name + " ") or key.startswith(name + ":"):
            return lines
    return []


_SCOPE_SPLIT = re.compile(r"\s*,\s*|(?:^|\s+)(?:and|or|plus|&)(?:\s+|$)", re.IGNORECASE)


def _scope_tokens(bullet: str) -> list[str]:
    raw = re.findall(r"`([^`]+)`", bullet)
    # Text outside backtick spans is tokenized too, so `src/**` and tests/** yields both.
    body = re.sub(r"`[^`]+`", " ", bullet).split("(", 1)[0]
    for part in _SCOPE_SPLIT.split(body):
        part = part.strip()
        pieces = part.split()
        # Space-separated globs only when every piece looks like a path; otherwise the
        # spaces belong to one path such as Course Materials/**.
        if len(pieces) > 1 and all(("/" in x or any(c in x for c in "*?[")) for x in pieces):
            raw.extend(pieces)
        elif part:
            raw.append(part)
    out = []
    for tok in raw:
        tok = tok.strip().strip(";:").replace("\\", "/")
        while tok.startswith("./"):
            tok = tok[2:]
        if tok and tok.lower() not in _CONNECTORS:
            out.append(tok)
    return out


def parse_scope(text: str) -> list[str]:
    """Each SCOPE bullet holds one or more globs. Backticked spans are taken verbatim; otherwise
    globs are separated by commas or the words and, or. A trailing parenthetical is a comment.
    A literal path with no glob characters also covers everything below it."""
    globs: list[str] = []
    for b in _bullets(section(text, "SCOPE")):
        if b.strip().startswith("("):
            continue
        for tok in _scope_tokens(b):
            cand = [tok]
            if not any(ch in tok for ch in "*?["):
                cand.append(tok.rstrip("/") + "/**")
            for g in cand:
                if g not in globs:
                    globs.append(g)
    return globs


_ITEM_HEAD = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+(?:\[( |x|X)\]\s*)?(.*)$")
_ID_TOKEN = r"[A-Z][A-Z0-9]*-\d+"
_ID_PAREN = re.compile(r"\((" + _ID_TOKEN + r")\)")
_ID_LEAD_COLON = re.compile(r"^(?:~~)?[*_`]*(" + _ID_TOKEN + r")[*_`]*\s*:")
_ID_LEAD_BOLD = re.compile(r"^(?:~~)?(?:\*\*|__)(" + _ID_TOKEN + r")(?:\*\*|__)")


def parse_obligation_lines(text: str) -> tuple[dict, list[str], int]:
    """Return (id to open flag, duplicate ids, list items without a recognizable id).
    An id is recognized only in an unambiguous position: ID: at the start of the item, a bold
    ID at the start, or a parenthesized (ID). Tokens such as UTF-8 or SHA-256 in prose never count."""
    result: dict = {}
    dups: list[str] = []
    no_id = 0
    for line in section(text, "OPEN"):
        m = _ITEM_HEAD.match(line)
        if not m:
            continue
        box, rest = m.group(1), m.group(2).strip()
        lm = _ID_LEAD_COLON.match(rest) or _ID_LEAD_BOLD.match(rest)
        oid = lm.group(1) if lm else None
        if not oid:
            # Fall back to a parenthesized ID only when the item has no leading one, so a
            # cross-reference such as (OBL-1) inside OBL-2's text cannot hijack it.
            found = _ID_PAREN.findall(rest)
            oid = found[-1] if found else None
        if not oid:
            if rest and not rest.startswith("("):
                no_id += 1
            continue
        closed = (box in ("x", "X")) or rest.startswith("~~")
        if oid in result:
            dups.append(oid)
        result[oid] = result.get(oid, True) and not closed
    return result, sorted(set(dups)), no_id


def parse_obligations(text: str) -> dict:
    return parse_obligation_lines(text)[0]


def has_next(text: str) -> bool:
    for b in _bullets(section(text, "NEXT")):
        if not b.strip().startswith("("):
            return True
    return False


def parse_discharges(text: str) -> dict:
    """Map obligation ID to the list of evidence strings given for it."""
    out: dict = {}
    for line in text.splitlines():
        m = _DISCHARGE.match(line)
        if not m:
            continue
        ev = re.search(r"evidence\s*=\s*([^;]+)", m.group(2))
        out.setdefault(m.group(1), []).append(ev.group(1).strip() if ev else "")
    return out


_NOT_EVIDENCE = ("AGENTS.md", "CLAUDE.md", "README.md", "README")


def evidence_valid(repo: Repo, evidence: str) -> bool:
    """The evidence value must START with something checkable: a commit that exists, or a file
    that exists inside the repository (not an instruction file or pecia bookkeeping).
    Prose such as model agreement does not qualify, whatever files it mentions later."""
    ev = (evidence or "").strip()
    if not ev:
        return False
    first = ev.split()[0].strip("`'\"()[]").rstrip(".,;:")
    if not first or first[0] in "<(-":
        return False
    if re.fullmatch(r"[0-9a-fA-F]{7,64}", first):
        return run_git(repo.root, ["rev-parse", "--verify", "-q", f"{first}^{{commit}}"], check=False).returncode == 0
    if "/" not in first and "." not in first:
        return False
    try:
        p = (repo.root / first).resolve()
        rel = p.relative_to(repo.root.resolve()).as_posix()
    except (OSError, ValueError):
        return False
    # Compared as the file system compares names, so .PECIA/STATE.md is pecia's own file where case is ignored; the
    # repository itself and git's folder are no evidence either (R24-14, R24-30).
    key = _path_key(repo)
    k = key(rel)
    if (rel == "." or k in (key(PECIA_DIR), key(".git")) or k.startswith((key(PECIA_DIR) + "/", key(".git") + "/"))
            or k in {key(n) for n in _NOT_EVIDENCE} or not p.exists()):
        return False
    return True


# ---------------------------------------------------------------- consistency check

_GIT_UNOPENED = re.compile(r"could not open directory '(.*)': ([^\n]*)")  # to the last ': ' (R24-40)
# git names a working-tree path it cannot read as the path alone, as perror does, whatever words the name starts with
# (R24-41), or after error: or warning: inside open("..."), lstat("...") or stat("..."). Other messages with a prefix
# that end in the same reason, as unable to access for an ignore or attributes file, are about files outside the tree
# or about git's own reading of them, never a file whose uncommitted work git missed (R24-24).
_GIT_UNREADABLE = re.compile(r'(?m)^(?:(?:error|warning): (?:open|lstat|stat)\("(?P<q>[^\n]+?)"\)|'
                             r'(?!(?:error|warning|fatal|hint): )(?P<b>[^\n]+?)): '
                             r'(?:Permission denied|Operation not permitted)\s*$')


def _git_unopened(repo: Repo, err: str) -> list[str]:
    """The folders git said it could not open, once each. A folder removed while git listed it is no folder git could
    not read (R24-23): git names it with No such file or directory, and it is gone when looked for."""
    out = []
    for folder, reason in _GIT_UNOPENED.findall(err):
        if "No such file or directory" in reason or "Not a directory" in reason or folder in out:
            continue
        try:
            os.lstat(repo.path(folder.rstrip("/")))
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError:
            pass
        out.append(folder)
    return out


def _git_unreadable(repo: Repo, err: str) -> list[str]:
    """The working-tree paths git said it could not read, once each (R24-06, R24-24). A line that ends the same way but
    names nothing in the tree, as another program's message can, is passed over (R24-52, S2)."""
    out = []
    for m in _GIT_UNREADABLE.finditer(err):
        path = m.group("q") or m.group("b")
        if path.startswith("/") or path in out:
            continue
        try:
            os.lstat(repo.path(path))
        except (FileNotFoundError, NotADirectoryError):
            continue
        except (OSError, ValueError):
            pass
        out.append(path)
    return out


class _StatusEntries(list):
    """git status entries, with the folders git said it could not open (E1-03) and the paths it said it could not read
    (R24-06): git status exits 0 in both cases and says so only on standard error."""
    unopened: list = []
    unreadable: list = []


def status_entries(repo: Repo) -> list[tuple[str, str]]:
    # --ignore-submodules=dirty: a submodule's own uncommitted content is not captured anyway, and looking
    # into it would run the submodule's git, with whatever its configuration says (R19-C1).
    p = run_git(repo.root, ["--no-optional-locks", "status", "--porcelain=v1", "-z",
                            "--untracked-files=all", "--no-renames", "--ignore-submodules=dirty"],
                env={"LC_ALL": "C", "LANGUAGE": "C"})
    out = p.stdout
    entries = _StatusEntries()
    # git still exits 0 when it cannot open a folder, and says so only in a warning (E1-03).
    err = p.stderr.decode("utf-8", "surrogateescape")  # names as the file system has them (R24-40)
    entries.unopened = _git_unopened(repo, err)
    entries.unreadable = _git_unreadable(repo, err)
    for rec in out.split(b"\0"):
        if len(rec) < 4:
            continue
        s = rec.decode("utf-8", "surrogateescape")
        path = s[3:]
        if path == RUNTIME_REL or path.startswith(RUNTIME_REL + "/"):
            continue
        entries.append((s[:2], path))
    return entries


def hash_paths(repo: Repo, paths: list[str], env: dict | None = None) -> dict:
    """Blob IDs as git would store them (clean filters applied). Paths go on the command line,
    never through stdin, so names with control characters or quotes cannot break the batch."""
    result: dict = {}
    chunk: list[str] = []
    size = 0

    def flush(ch):
        if not ch:
            return
        p = run_git(repo.root, ["hash-object", "--", *ch], env=env, check=False)
        oids = p.stdout.decode().split()
        if p.returncode == 0 and len(oids) == len(ch):
            result.update(zip(ch, oids))
            return
        for one in ch:
            q = run_git(repo.root, ["hash-object", "--", one], env=env, check=False)
            if q.returncode == 0:
                result[one] = q.stdout.decode().strip()

    for path in paths:
        if size + len(path) > 6000:
            flush(chunk)
            chunk, size = [], 0
        chunk.append(path)
        size += len(path) + 3
    flush(chunk)
    return result


def _flagged_entries(repo: Repo, env: dict | None = None) -> list[str]:
    """Tracked paths hidden from status by skip-worktree or assume-unchanged that exist on disk."""
    out = run_git(repo.root, ["ls-files", "-v", "-z"], env=env).stdout
    flagged = []
    for rec in out.split(b"\0"):
        if len(rec) < 3:
            continue
        s = rec.decode("utf-8", "surrogateescape")
        tag, path = s[0], s[2:]
        if (tag.upper() == "S" or tag.islower()) and os.path.isfile(repo.path(path)) \
                and not os.path.islink(repo.path(path)):
            flagged.append(path)
    return flagged


def hidden_edits(repo: Repo) -> list[str]:
    flagged = _flagged_entries(repo)
    if not flagged:
        return []
    staged = {}
    for rec in run_git(repo.root, ["ls-files", "-s", "-z"]).stdout.split(b"\0"):
        if b"\t" in rec:
            meta, _, path = rec.partition(b"\t")
            staged[path.decode("utf-8", "surrogateescape")] = meta.decode().split(" ")[1]
    now = hash_paths(repo, flagged)
    return [p for p in flagged if now.get(p) and now.get(p) != staged.get(p)]


def _batch_blobs(repo: Repo, specs: list[str]) -> list:
    """Read many <rev>:<path> blobs in one git process. Missing specs yield None."""
    if not specs:
        return []
    out = run_git(repo.root, ["cat-file", "--batch"],
                  input_bytes=("\n".join(specs) + "\n").encode("utf-8", "surrogateescape")).stdout
    blobs, pos = [], 0
    for _ in specs:
        nl = out.index(b"\n", pos)
        header = out[pos:nl].decode("utf-8", "replace").split(" ")
        pos = nl + 1
        if len(header) == 3 and header[1] == "blob":
            size = int(header[2])
            blobs.append(out[pos:pos + size])
            pos += size + 1
        elif len(header) == 3:
            pos += int(header[2]) + 1
            blobs.append(None)
        else:
            blobs.append(None)
    return blobs


# The placeholder obligation STATE.md held as 0.1.2rc15's init wrote it. The README had it committed before it was
# deleted, so every later check reported it closed without a discharge (XA3-01); read from history, that exact line is
# no obligation, so a repository set up that way heals. The template now writes an example no parser reads.
_RC15_PLACEHOLDER = "- [ ] OBL-1: (unresolved claim, proof obligation, or defect)"


def _without_rc15_placeholder(text: str) -> str:
    return "\n".join(ln for ln in text.splitlines() if ln.strip() != _RC15_PLACEHOLDER)


def check_obligations(repo: Repo, current_text: str) -> tuple[list[str], list[str]]:
    """Return (closed without committed valid discharge, closed with discharge only in the working copy)."""
    current = parse_obligations(current_text)
    seen = set(current)
    if repo.head():
        commits = git_text(repo.root, "log", "--format=%H", "--", STATE_REL).split()
        for blob in _batch_blobs(repo, [f"{c}:{STATE_REL}" for c in commits]):
            if blob is not None:
                seen |= set(parse_obligations(_without_rc15_placeholder(blob.decode("utf-8", "replace"))))
    still_open = {k for k, is_open in current.items() if is_open}
    committed_review = ""
    if repo.head():
        p = run_git(repo.root, ["show", f"HEAD:{REVIEW_REL}"], check=False)
        committed_review = p.stdout.decode("utf-8", "replace") if p.returncode == 0 else ""
    review_path = repo.path(REVIEW_REL)
    working_review = read_text(review_path) if review_path.exists() else ""
    committed = parse_discharges(committed_review)
    working = parse_discharges(working_review)
    missing, uncommitted = [], []
    for k in sorted(seen - still_open):
        if any(evidence_valid(repo, e) for e in committed.get(k, [])):
            continue
        if any(evidence_valid(repo, e) for e in working.get(k, [])):
            uncommitted.append(k)
        else:
            missing.append(k)
    return missing, uncommitted


def _commit_files(repo: Repo, c: str) -> list[str]:
    parents = git_text(repo.root, "rev-list", "--parents", "-n", "1", c).split()[1:]
    if parents:
        out = run_git(repo.root, ["diff", "--name-only", "-z", "--no-renames", parents[0], c]).stdout
    else:
        out = run_git(repo.root, ["diff-tree", "-r", "--root", "--no-commit-id", "--name-only", "-z",
                                  "--no-renames", c]).stdout
    return z_split(out)


def commits_with_files(repo: Repo, rev_range: str) -> list[tuple]:
    """[(commit, paths it changed against its first parent)] for every commit in rev_range, newest
    first, from one git log call. Merge commits, which git log lists without files, are diffed one by one."""
    # log.showSignature would interleave signature checks with the records parsed here. Each record
    # starts with a NUL of its own; since no path is empty, an empty field always precedes a header,
    # whatever bytes the paths contain.
    out = run_git(repo.root, ["-c", "log.showSignature=false", "log", "--no-renames", "--name-only", "-z",
                              "--format=%x00%H %P", rev_range]).stdout
    records, cur, want_header, first = [], None, False, False
    for tok in out.split(b"\0"):
        if want_header:
            cur = (tok.decode("ascii", "replace").split(), [])
            records.append(cur)
            want_header, first = False, True
            continue
        if tok == b"":
            want_header = True
            continue
        if cur is None:
            continue
        if first:
            tok = tok[1:] if tok.startswith(b"\n") else tok  # one newline separates header and paths
            first = False
        if tok:
            cur[1].append(tok.decode("utf-8", "surrogateescape"))
    result = []
    for ids, files in records:
        if not ids:
            continue
        result.append((ids[0], _commit_files(repo, ids[0]) if len(ids) > 2 else files))
    return result


def run_check(repo: Repo) -> dict:
    findings = []

    def add(level, code, message, **data):
        findings.append({"level": level, "code": code, "message": message, **data})

    result = {"verdict": None, "head": repo.head(), "state_commit": None, "scope": [],
              "findings": findings,
              "limits": "Mechanical consistency only. It cannot establish that STATE.md is correct or that NEXT is the right step."}
    state_path = repo.path(STATE_REL)
    if not state_path.exists():
        add("reconcile", "STATE_MISSING", f"{STATE_REL} does not exist. Run {pecia_cmd(repo)} init.")
        result["verdict"] = "NEEDS_RECONCILIATION"
        return result
    text = read_text(state_path)
    head = result["head"]
    s = git_text(repo.root, "log", "-1", "--format=%H", "--", STATE_REL) if head else ""
    result["state_commit"] = s or None
    committed_text = ""
    if s:
        p = run_git(repo.root, ["show", f"{s}:{STATE_REL}"], check=False)
        committed_text = p.stdout.decode("utf-8", "replace") if p.returncode == 0 else ""
    scope_work, scope_comm = parse_scope(text), parse_scope(committed_text)
    # An uncommitted edit must not narrow the scope used to judge committed history: use the union.
    # An empty scope means every path, so if either version is empty the union is everything.
    if s and (not scope_work or not scope_comm):
        scope = []
    else:
        scope = scope_comm + [g for g in scope_work if g not in scope_comm] if s else scope_work
    result["scope"] = scope
    if s and scope_work != scope_comm:
        add("note", "SCOPE_CHANGED_UNCOMMITTED",
            "Uncommitted STATE.md edits change SCOPE; checking against the union of both versions.")
    if not scope:
        add("note", "SCOPE_EMPTY", "SCOPE lists no paths, so every changed file counts as in scope.")

    def in_scope(p: str) -> bool:
        if p.startswith(PECIA_DIR + "/"):
            return False
        return match_any(p, scope) if scope else True

    if not s:
        add("reconcile", "STATE_NOT_COMMITTED", f"{STATE_REL} has never been committed. Commit it so the other agent can verify it.")
    else:
        changed = z_split(run_git(repo.root, ["diff", "--name-only", "-z", "--no-renames", s, "HEAD"]).stdout)
        changed_in = [f for f in changed if in_scope(f)]
        # Judge each commit, not only the net difference: commits that change in-scope paths and
        # then change them back leave no net difference but are still work STATE.md does not describe.
        commits = commits_with_files(repo, f"{s}..HEAD")
        hit_commits = [(c, [f for f in files if in_scope(f)]) for c, files in commits]
        hit_commits = [(c, hits) for c, hits in hit_commits if hits]
        touched = sorted({f for _, hits in hit_commits for f in hits})
        if hit_commits or changed_in:
            listed = []
            if hit_commits:
                info = git_text(repo.root, "-c", "log.showSignature=false", "log", "--no-walk=unsorted",
                                "--format=%H%x09%h%x09%s", *[c for c, _ in hit_commits[:50]]).splitlines()
                meta = {}
                for line in info:
                    parts = line.split("\t", 2)
                    if len(parts) >= 2:
                        meta[parts[0]] = (parts[1], parts[2] if len(parts) > 2 else "")
                for c, hits in hit_commits[:50]:
                    short, subject = meta.get(c, (c[:7], ""))
                    listed.append({"commit": short, "subject": subject, "files": hits[:50]})
            net = "" if len(changed_in) == len(touched) else f" ({len(changed_in)} with a net change)"
            add("reconcile", "IN_SCOPE_COMMITS_SINCE_STATE",
                f"{len(hit_commits)} of {len(commits)} commit(s) after the last STATE.md update touch "
                f"{len(touched)} in-scope path(s){net}.",
                commits=listed, paths=(touched or changed_in)[:100], net_changed=changed_in[:100])
        elif commits:
            add("note", "OUT_OF_SCOPE_COMMITS_SINCE_STATE",
                f"{len(commits)} commit(s) after the last STATE.md update change only out-of-scope paths.")
    dirty = status_entries(repo)
    unseen = list(getattr(dirty, "unopened", [])) + list(getattr(dirty, "unreadable", []))
    if unseen:
        # Whether work in scope may lie there decides the level: a folder no SCOPE pattern can reach is a note (R24-09).
        in_reach = any(in_scope(u) if not u.endswith("/") else _folder_may_hold(u, scope) for u in unseen)
        add("reconcile" if in_reach else "note", "FOLDER_GIT_CANNOT_OPEN",
            f"git could not read {', '.join(unseen[:3])}" + (f" and {len(unseen) - 3} more" if len(unseen) > 3 else "")
            + ", so uncommitted work there cannot be seen, and snapshots report it as not covered. Make it readable "
              "to this account, or ignore it in .gitignore; editing STATE.md does not settle this.", paths=unseen[:100])
    state_dirty = any(p == STATE_REL for _, p in dirty)
    dirty_in = [p for _, p in dirty if in_scope(p)]
    dirty_out = [p for _, p in dirty if not in_scope(p) and not p.startswith(PECIA_DIR + "/")]
    if dirty_in:
        msg = "Uncommitted in-scope changes are not described by the committed state."
        if state_dirty:
            msg = "Uncommitted in-scope changes exist alongside an uncommitted STATE.md edit. Commit them together."
        add("reconcile", "DIRTY_IN_SCOPE", msg, paths=dirty_in[:100])
    elif state_dirty:
        add("note", "STATE_EDIT_UNCOMMITTED", "STATE.md has uncommitted edits.")
    if dirty_out:
        add("note", "DIRTY_OUT_OF_SCOPE", f"{len(dirty_out)} uncommitted out-of-scope path(s).", paths=dirty_out[:100])
    hidden = hidden_edits(repo)
    hidden_in = [p for p in hidden if in_scope(p)]
    if hidden_in:
        add("reconcile", "HIDDEN_EDITS_IN_SCOPE",
            "Edited files are hidden from git status by skip-worktree or assume-unchanged flags.", paths=hidden_in[:100])
    elif hidden:
        add("note", "HIDDEN_EDITS_OUT_OF_SCOPE", "Out-of-scope edits are hidden by skip-worktree or assume-unchanged flags.",
            paths=hidden[:100])
    _, dup_ids, no_id = parse_obligation_lines(text)
    if dup_ids:
        add("reconcile", "DUPLICATE_OBLIGATION_ID",
            "More than one OPEN item resolves to the same ID: " + ", ".join(dup_ids) + ". Give each a unique ID.")
    if no_id:
        add("note", "OPEN_ITEM_WITHOUT_ID",
            f"{no_id} OPEN item(s) carry no recognizable ID (write ID: text, **ID**, or (ID)), so their removal "
            "cannot be detected.")
    missing, uncommitted = check_obligations(repo, text)
    for ob in missing:
        add("reconcile", "OBLIGATION_CLOSED_WITHOUT_DISCHARGE",
            f"{ob} is no longer open, and the committed {REVIEW_REL} has no DISCHARGED entry whose evidence is "
            "an existing commit or an existing file.", obligation=ob)
    for ob in uncommitted:
        add("reconcile", "OBLIGATION_DISCHARGE_UNCOMMITTED",
            f"{ob} is discharged only in the uncommitted {REVIEW_REL}. Commit it with the work.", obligation=ob)
    if not has_next(text):
        add("note", "NEXT_EMPTY", "NEXT has no concrete action.")
    result["verdict"] = "NEEDS_RECONCILIATION" if any(f["level"] == "reconcile" for f in findings) else "CURRENT"
    return result


def format_check(res: dict) -> str:
    lines = [f"verdict: {res['verdict']}"]
    if res.get("state_commit"):
        lines.append(f"state last committed in: {res['state_commit'][:12]}")
    if res.get("scope"):
        lines.append("scope as parsed: " + ", ".join(res["scope"][:20]))
    for f in res["findings"]:
        lines.append(f"  [{f['level']}] {f['code']}: {f['message']}")
        for c in f.get("commits", [])[:10]:
            lines.append(f"      {c['commit']} {c['subject']}  ({', '.join(c['files'][:5])})")
        if not f.get("commits"):
            for p in f.get("paths", [])[:10]:
                lines.append(f"      {p}")
    lines.append(res["limits"])
    return "\n".join(lines)


# ---------------------------------------------------------------- artifacts

_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,60}")


def _derived_id(label: str, data: bytes) -> str:
    name = re.sub(r"[^A-Za-z0-9_-]+", "-", label).strip("-") or "repo"
    return f"{name[:40]}-{hashlib.sha256(data).hexdigest()[:8]}"


def _read_stable_id(idfile: Path, label: str):
    """The id _stable_id returns for this file, without writing anything: None when no file is
    there, the stored id when it is valid, and otherwise the id derived from the file's bytes (an
    empty, undecodable, unreadable, or dangling file), exactly as _stable_id derives it (R6-05)."""
    if not os.path.lexists(idfile):
        return None
    try:
        data = _read_regular(idfile)
    except OSError:
        data = b""
    got = data.decode("utf-8", "replace").strip()
    return got if _ID_RE.fullmatch(got) else _derived_id(label, data)


def _stable_id(idfile: Path, label: str) -> str:
    try:
        wid = _read_regular(idfile).decode("utf-8").strip()
    except (OSError, ValueError):
        wid = ""
    if re.fullmatch(r"[A-Za-z0-9_-]{1,60}", wid or ""):
        return wid
    name = re.sub(r"[^A-Za-z0-9_-]+", "-", label).strip("-") or "repo"
    wid = f"{name[:40]}-{secrets.token_hex(4)}"
    try:
        # The id lives in a git directory, which exists; it is never made by name, so a git directory found
        # replaced is refused before anything is created (Z-06).
        fd = _create_excl(idfile)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(wid + "\n")
    except FileExistsError:
        # Another process created it first; give it a moment to finish writing. A file whose bytes are
        # not a valid id (R5-07) gets an id derived from those bytes, so it stays stable and nothing crashes.
        data = b""
        for _ in range(20):
            try:
                data = _read_regular(idfile)
            except OSError:
                data = b""
            got = data.decode("utf-8", "replace").strip()
            if re.fullmatch(r"[A-Za-z0-9_-]{1,60}", got):
                return got
            time.sleep(0.01)
        wid = _derived_id(label, data)
    return wid


def _refuse_linked_dirs(*paths) -> None:
    """pecia's own folders must be real folders. A symlink or junction at one of them could send
    pecia's writes and deletions to files outside the repository (T-01, T-02, T-07)."""
    for d in paths:
        if _is_link(d):
            raise UnsafePath(f"{fwd(d)} is a symlink or junction. pecia keeps its private files there and refuses "
                             "to read, write or delete through a link, which could reach files outside the "
                             "repository. Replace it with a regular folder.")
        if os.path.lexists(d) and not d.is_dir():
            raise UnsafePath(f"{fwd(d)} is not a folder. pecia keeps its private files there; move it aside.")


def _configured_store(policy: dict) -> str:
    """artifacts.store as set, or empty; a value that is not a string counts as set, and store_root
    reports it (R10-06)."""
    raw = policy.get("artifacts", {}).get("store") if isinstance(policy.get("artifacts"), dict) else None
    if raw is None:
        return ""
    return raw.strip() if isinstance(raw, str) else repr(raw)


def store_root(repo: Repo, policy: dict, write: bool = True) -> Path:
    """The artifact store. A store location set in the policy may itself be a link, since the user
    chose it; every folder pecia creates is checked, as is the default location in the git directory.
    Callers that only read (recovery, inspection, artifact lists) pass write False: reading through a
    link changes nothing, every object is checked against its SHA-256 before use, and refusing there
    would stand between the user and their evidence."""
    raw = policy["artifacts"].get("store")
    if raw is not None and not isinstance(raw, str):
        raise UnsafePath(f"artifacts.store in {POLICY_REL} must be a path in a string, not {type(raw).__name__}.")
    configured = (raw or "").strip()
    if configured:
        base = Path(os.path.expandvars(os.path.expanduser(configured)))
        if not base.is_absolute():
            # Resolved against whatever folder a command runs in, a relative store would put each
            # snapshot's objects somewhere else and leave recovery looking in the wrong place (U-03).
            raise UnsafePath(f"artifacts.store in {POLICY_REL} is {configured}, which is not an absolute path "
                             "after expanding ~ and environment variables. Set an absolute path.")
        common = repo.common_dir()
        if not write:  # reading creates no id (R6-11); without one this repository stored nothing there
            rid = _read_stable_id(common / "pecia-repo-id", common.parent.name)
            if rid and _store_in_worktree(repo, base) is None:
                # Trusted as a base only when it passes the check the write path makes, and with the folder pecia
                # keeps there known, so that folder is all it anchors (N-19).
                _register_base(base, kind="store", refresh=True)
                _set_store_folder(base, rid)
            return base / (rid or "pecia-no-repository-id-yet")
        if not base.is_dir():
            # Never created: on a drive that is not mounted it would land on the system disk, and the
            # evidence would vanish under the mount once the drive is back (R13-03).
            raise UnsafePath(f"the artifacts.store location {fwd(base)} does not exist or cannot be reached (a drive "
                             "that is not mounted, or a link to a missing folder). pecia never creates it; create "
                             "the folder yourself, or mount the drive.")
        inside = _store_in_worktree(repo, base)
        if inside is not None:
            # Snapshots stage the working tree's files, so a store kept inside it would put evidence
            # meant to stay out of git into snapshot commits (V-04).
            raise UnsafePath(f"artifacts.store in {POLICY_REL} is {configured}, inside the working tree "
                             f"{fwd(inside)}. Snapshots would commit the stored evidence into git. Set a "
                             "folder outside every working tree of this repository.")
        # Registered only once every check above passed, and with the folder pecia keeps there, which is all it
        # anchors: a setting refused here must not leave a trusted base behind (N-19).
        _register_base(base, kind="store", refresh=True)
        root = base / _stable_id(common / "pecia-repo-id", common.parent.name)
        _set_store_folder(base, root.name)
        own = [root]
    else:
        common = repo.common_dir()
        root = common / "pecia" / "artifacts"
        own = [common / "pecia", root]
    if write:
        try:
            _refuse_linked_dirs(*own, root / "objects", root / "manifests", root / "quarantine")
        except UnsafePath as e:
            raise UnsafePath(f"{e} To keep the artifact store on another drive, set artifacts.store in "
                             f"{POLICY_REL}, take a snapshot, and move this store's contents into the folder "
                             f"{pecia_cmd(repo)} doctor then names.") from None
    return root


def _same_folder(a, ast, b, bst) -> bool:
    """Same folder by identity; where the file system reports no file numbers (some network shares
    give 0 for every folder), by resolved path instead."""
    if ast.st_ino and bst.st_ino:
        return os.path.samestat(ast, bst)
    try:
        return os.path.normcase(str(Path(a).resolve())) == os.path.normcase(str(Path(b).resolve()))
    except (OSError, RuntimeError):
        return False


def _store_in_worktree(repo: Repo, base: Path):
    """The working tree of this repository that contains base, or None. Folders are compared by
    identity, not by spelling, so letter case and links cannot hide that a store is inside a working
    tree (U3). Inside the git directory is not inside a working tree: git never stages it."""
    try:
        roots = [(w, os.stat(w)) for w in [repo.root, *_worktree_roots(repo)]]
        common = os.stat(repo.common_dir())
    except (OSError, PeciaError):
        return None
    try:
        cur = Path(os.fspath(base)).resolve()  # a link on the way is followed: git does not stage what it leads to
    except (OSError, RuntimeError):
        return None
    while True:
        try:
            st = os.stat(cur)
        except OSError:
            st = None
        if st is not None:
            if _same_folder(cur, st, repo.common_dir(), common):
                return None
            for w, wst in roots:
                if _same_folder(cur, st, w, wst):
                    return w
        if cur.parent == cur:
            return None
        cur = cur.parent


def _object_path(objects: Path, digest: str) -> Path:
    return objects / digest[:2] / digest


def object_ok(obj: Path, digest: str, size: int | None = None) -> bool:
    """True only when the stored object exists and its bytes hash to its own name."""
    try:
        if size is not None and obj.stat().st_size != size:
            return False
        return sha256_file(obj) == digest
    except OSError:
        return False


_TOUCH_AFTER_S = 45 * 60  # garbage collection spares unreferenced objects younger than an hour


def _obj_sig(obj: Path):
    try:
        st = obj.stat()
    except OSError:
        return None
    sig = [st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino]
    if IS_WINDOWS:
        # os.stat reports the creation time as st_ctime there; the NTFS change time is what a same-size rewrite
        # that restores the modification time still updates (C-04, R21-02). None never matches a record.
        sig.append(_win_change_time(obj))
    return sig


def load_ledger(store: Path) -> dict:
    """{digest: [size, mtime_ns, ctime_ns, inode, (Windows: NTFS change time,) recorded_ns]}: the stored object's metadata at the
    moment its bytes last hashed to its name. While that metadata is unchanged, the object is trusted
    without rereading it. Losing the file only costs a reread."""
    data = load_json(store / "verified.json", {}) or {}
    return data if isinstance(data, dict) else {}


def save_ledger(store: Path, ledger: dict) -> None:
    try:
        atomic_write_json(store / "verified.json", ledger)
    except (OSError, PeciaError):
        pass


def record_verified(ledger: dict, digest: str, obj: Path) -> None:
    sig = _obj_sig(obj)
    if sig is not None:
        ledger[digest] = sig + [time.time_ns()]


def object_trusted(ledger: dict, digest: str, obj: Path, size: int | None = None) -> bool:
    """True when the object's size, timestamps and inode are exactly what they were when its bytes
    last verified, and that record was not taken within the racy window of a change to the object
    (a same-size rewrite inside one timestamp tick would be invisible)."""
    rec = ledger.get(digest)
    sig = _obj_sig(obj)
    if sig is None or None in sig or not isinstance(rec, list) or len(rec) != len(sig) + 1:
        return False
    if sig != rec[:-1] or (size is not None and sig[0] != size):
        return False
    try:
        return int(rec[-1]) - max(int(rec[1]), int(rec[2])) > _RACY_NS
    except (TypeError, ValueError):
        return False


def _sole_object(obj: Path) -> bool:
    """True when obj is a regular file that is not a link and has no other name. A hard link would make
    a timestamp change, or anything else done to the object, reach a file outside the store (U-04)."""
    try:
        st = os.lstat(obj)
    except OSError:
        return False
    return stat_mod.S_ISREG(st.st_mode) and st.st_nlink <= 1


def _touch_if_old(obj: Path) -> bool:
    """Refresh an object's age so garbage collection cannot race its reuse. Only objects close to
    the collection age are touched, so trusted metadata does not change on every snapshot."""
    try:
        if not _sole_object(obj):
            return False
        if time.time() - os.lstat(obj).st_mtime <= _TOUCH_AFTER_S:
            return False
        if os.utime in os.supports_fd:
            # Touch the file that was checked, through its own descriptor, opened in its held folder: a
            # link swapped in after the check is never followed (R10-12, V-07).
            with _held_dir(obj.parent) as d:
                fd = d.open_fd(obj.name, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
            try:
                st = os.fstat(fd)
                if not stat_mod.S_ISREG(st.st_mode) or st.st_nlink > 1:
                    return False
                os.utime(fd)
            finally:
                os.close(fd)
        elif IS_WINDOWS:
            # No descriptor-based utime here. The folder is held, so it cannot be swapped for a junction, and the
            # object is changed through a handle on itself while it has one name (X-08).
            with _held_dir(obj.parent) as d:
                return _win_set_attrs(d.path / obj.name, touch=True)
        else:
            with _held_dir(obj.parent):
                os.utime(obj)
        return True
    except (OSError, PeciaError):
        pass
    return False


def _copy_verified(src: Path, dest: Path, want: str) -> bool:
    """Copy src to dest through a temporary file, publishing it only if the copied bytes hash
    to want. Replaces any existing dest, which callers use only to repair a corrupt object. The
    folder is held, so the copy lands where it was checked (V-05)."""
    dest = Path(dest)
    with _held_dir(dest.parent, create=True) as d:
        fd, tmp = d.new_temp(".tmp-")
        try:
            h = hashlib.sha256()
            with os.fdopen(fd, "wb") as out, _open_regular(src) as inp:
                for chunk in iter(lambda: inp.read(1 << 20), b""):
                    h.update(chunk)
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
                ident = _ident(os.fstat(out.fileno()))
            if h.hexdigest() != want:
                d.unlink_quietly(tmp)
                return False
            d.replace(tmp, dest.name)
        except BaseException:
            d.unlink_quietly(tmp)
            raise
        _check_published(d, dest.name, ident, fwd(dest), want)
        return True


def store_object(src: Path, objects: Path, repaired: list | None = None, ledger: dict | None = None):
    """Store src content-addressed and return its SHA-256, or None if src kept changing.
    An existing object is reused only after its own bytes verify; a corrupt object is
    rebuilt from src while src still holds the right content."""
    for _ in range(2):
        pre = sha256_file(src)
        dest = _object_path(objects, pre)
        _refuse_linked_dirs(dest.parent)  # T-02: an object folder that is a link would put the evidence elsewhere
        # An object that is a symlink, a hard link or not a regular file is replaced by a fresh, verified
        # copy; nothing is written through it (U-04, U-06).
        if dest.exists() and _sole_object(dest):
            if object_ok(dest, pre):
                _touch_if_old(dest)
                if ledger is not None:
                    record_verified(ledger, pre, dest)
                return pre
            if repaired is not None:
                repaired.append(pre)
        if _copy_verified(src, dest, pre):
            if ledger is not None:
                record_verified(ledger, pre, dest)
            return pre
    return None


def walk_artifact_candidates(repo: Repo, patterns, prune_dirs, errors: list | None = None):
    """Designated files under the folders patterns can match. A folder that cannot be listed is added to errors as
    (folder, reason): os.walk passes over it without a word by default, and its files would be taken for absent
    (E1-02)."""
    roots = set()
    for pat in patterns:
        # The walk starts where the pattern, in the form glob_regex reads, can match: from the unstripped pattern, a
        # leading space named a folder that does not exist, and ./ one no path has (XA1-07).
        p = _norm_pattern(pat).lstrip("/")
        if "/" not in p.rstrip("/"):
            roots.add("")
            continue
        lit = []
        for part in p.split("/")[:-1]:
            if any(ch in part for ch in "*?["):
                break
            lit.append(part)
        roots.add("/".join(lit))
    if "" in roots:
        roots = {""}
    else:
        roots = {r for r in roots if not any(r != o and r.startswith(o + "/") for o in roots)}
    prune_paths = {d.strip("/") for d in prune_dirs if "/" in d.strip("/")}
    prune_names = {d.strip("/") for d in prune_dirs if "/" not in d.strip("/")}
    def unlisted(e: OSError, root=""):
        if errors is None or isinstance(e, (FileNotFoundError, NotADirectoryError)):
            return  # a folder removed while the walk ran, as a build's scratch folder is, holds nothing now (R24-08)
        try:
            rel = Path(os.fspath(e.filename)).relative_to(repo.root).as_posix() if e.filename is not None else root
        except (TypeError, ValueError):
            rel = root
        errors.append((rel or ".", e.strerror or str(e)))
    for r in sorted(roots):
        base = repo.path(r) if r else repo.root
        try:
            st = os.stat(base)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError as e:
            # A pattern's folder below one pecia cannot search: Path.is_dir answers False on Python 3.14 and raises
            # before it, either way the files there were lost from view (R24-05).
            unlisted(e, r)
            continue
        if not stat_mod.S_ISDIR(st.st_mode):
            continue
        for dirpath, dirnames, filenames in os.walk(base, onerror=lambda e, r=r: unlisted(e, r)):
            rel_dir = Path(dirpath).relative_to(repo.root).as_posix()
            rel_dir = "" if rel_dir == "." else rel_dir
            keep = []
            for d in dirnames:
                rd = f"{rel_dir}/{d}" if rel_dir else d
                if d in prune_names or rd in prune_paths or _is_link(os.path.join(dirpath, d)):
                    continue
                keep.append(d)
            dirnames[:] = keep
            for fname in filenames:
                rf = f"{rel_dir}/{fname}" if rel_dir else fname
                if _is_link(os.path.join(dirpath, fname)):
                    continue
                if match_any(rf, patterns):
                    yield rf


_RACY_NS = 3_000_000_000


def _first_sentence(text: str) -> str:
    """The first sentence of a message, for a one-line reason; doctor gives the full account."""
    m = re.match(r"(.+?\.)(\s|$)", text, re.S)
    return (m.group(1) if m else text).strip()


def _unlisted_designated(errors: list) -> list[dict]:
    """The coverage entry for designated folders that could not be listed: their files cannot be named, so every
    designated file's older versions become suspect, as when artifact capture fails as a whole (E1-02, R14-02)."""
    if not errors:
        return []
    names = ", ".join(f"{d} ({why})" for d, why in errors[:3]) + (f" and {len(errors) - 3} more" if len(errors) > 3 else "")
    return [{"path": "(designated artifacts)",
             "why": f"pecia could not list the folder {names}, so designated files in it are not in this snapshot and "
                    "it cannot name them; make the folder readable to this account, or, if it holds no designated "
                    "files, name it in artifacts.prune_dirs"}]


def _dropped_designation(repo: Repo, patterns, excludes, cache: dict, captured: dict) -> list:
    """The files a partly readable artifacts.include_globs may have designated through an entry that was left out: those
    captured here before that exist now and that no remaining pattern matches. Without that record the snapshot cannot
    name them, and says so (IR31-01)."""
    why = (f"artifacts.include_globs holds entries that are not patterns "
           f"({json.dumps(patterns.dropped, default=str)[:60]}); this file was designated before and no remaining "
           "pattern matches it, so it was not stored; fix the policy")
    before = [k for k in cache if isinstance(k, str) and _valid_artifact_path(k)]
    if not before:
        return [{"path": "(designated artifacts)", "why": why.replace("this file was designated before and no remaining "
                                                                    "pattern matches it", "pecia has no record of what "
                                                                    "they designated")}]
    out = []
    for rel in sorted(before):
        if rel in captured or match_any(rel, list(patterns)) or is_excluded(rel, excludes):
            continue
        try:
            st = os.lstat(repo.path(rel))
        except (OSError, ValueError, UnsafePath):
            continue
        if stat_mod.S_ISREG(st.st_mode):
            out.append({"path": rel, "why": why})
    return out


def capture_artifacts(repo: Repo, policy: dict, excludes, force: bool = False) -> dict:
    apol = policy["artifacts"]
    patterns = apol.get("include_globs")
    if isinstance(patterns, _UnreadableDesignation):
        # No pattern can be read. The files stored for the designation before are reported not covered, as when
        # capture fails as a whole (R10-06), so recovery does not take an older stored copy for the newest (G1-07).
        why = patterns.why or ("artifacts.include_globs is neither a pattern nor a list of patterns, so no designated "
                               "file was stored; fix the policy")
        repo.log_event("artifact_designation_unreadable", value=json.dumps(patterns.value, default=str)[:200])
        try:
            cache = load_json(repo.ensure_runtime() / "artifact-cache.json", {}) or {}
        except (OSError, PeciaError):
            cache = {}
        before = sorted(k for k in cache if isinstance(k, str) and _valid_artifact_path(k))
        named = [{"path": rel, "why": why} for rel in before if not is_excluded(rel, excludes)]
        # The cache names only what was captured here before, so the snapshot also says it could not name every
        # designated file, which makes older stored copies suspect, as when capture fails as a whole (IR31-03).
        return {"digest": None, "files": {}, "repaired": [],
                "skipped": named + [{"path": "(designated artifacts)", "why": why}]}
    patterns = patterns or []
    if not patterns:
        return {"digest": None, "files": {}, "skipped": []}
    limit = int(float(apol["max_file_mb"]) * 1024 * 1024)
    try:
        store = store_root(repo, policy)
        objects = store / "objects"
        _held_dir(objects, create=True).close()
    except (UnsafePath, OSError) as e:
        # The tree snapshot still goes ahead; every designated file is reported as not covered, with
        # the reason, so status and the next snapshot keep saying so until the store is usable (R6-03).
        why = "artifact store unusable: " + _first_sentence(str(e))
        repo.log_event("artifact_store_unusable", error=str(e))
        errors: list = []
        named = [{"path": rel, "why": why} for rel in
                 walk_artifact_candidates(repo, patterns, apol.get("prune_dirs", []), errors)
                 if not is_excluded(rel, excludes)]
        return {"digest": None, "files": {}, "repaired": [], "skipped": named + _unlisted_designated(errors)}
    cache_path = repo.ensure_runtime() / "artifact-cache.json"
    cache = load_json(cache_path, {}) or {}
    ledger = load_ledger(store)
    ledger_before = dict(ledger)
    files, skipped, repaired, unlisted, walked = {}, [], [], [], []
    now_ns = time.time_ns()
    for rel in walk_artifact_candidates(repo, patterns, apol.get("prune_dirs", []), unlisted):
        walked.append(rel)
        if is_excluded(rel, excludes):
            skipped.append({"path": rel, "why": "excluded by snapshot.exclude_globs"})
            continue
        p = repo.path(rel)
        entry, outcome = None, "unstable"
        for _attempt in range(2):
            try:
                st = p.stat()
            except FileNotFoundError:
                outcome = "gone"
                break
            except OSError as e:
                # A file pecia cannot read, as in a folder it may list but not search, is not gone (R24-05).
                outcome = f"could not be read: {e.strerror or e}"
                break
            if not stat_mod.S_ISREG(st.st_mode):
                # A pipe, socket or device matching the globs: opening a pipe would block the snapshot
                # for good (R8-02).
                outcome = "not a regular file"
                break
            if st.st_size > limit:
                outcome = "too large"
                break
            key = _source_key(p, st)
            c = cache.get(rel)
            # Reuse a cached digest only when the source's size, mtime, ctime and inode all match and
            # it was not freshly modified (same-tick rewrites), and the stored object is either
            # unchanged since its bytes last verified (ledger) or verifies now. Anything else, and
            # every forced or periodic full pass, goes through store_object, which rehashes the source
            # and the object.
            ok_entry = (isinstance(c, list) and len(c) == len(key) + 1 and None not in key
                        and isinstance(c[-1], str) and _SHA256_RE.match(c[-1]))
            obj = _object_path(objects, c[-1]) if ok_entry else None
            if obj is not None and (_is_link(obj.parent) or not _sole_object(obj)):
                obj = None  # never reuse or touch an object reached through a link, or with other names (R6-08, U-04)
            if (not force and obj is not None and c[:-1] == key and now_ns - st.st_mtime_ns > _RACY_NS
                    and (object_trusted(ledger, c[-1], obj, st.st_size) or object_ok(obj, c[-1], st.st_size))):
                digest = c[-1]
                if _touch_if_old(obj):
                    ledger.pop(digest, None)  # metadata changed; the next pass rereads the object once
                elif not object_trusted(ledger, digest, obj, st.st_size):
                    record_verified(ledger, digest, obj)
                entry = (digest, st.st_size)
                break
            try:
                digest = store_object(p, objects, repaired, ledger)
            except UnsafePath as e:
                outcome = "artifact store unusable: " + _first_sentence(str(e))
                break
            except FileNotFoundError:
                outcome = "gone"
                break
            except OSError as e:
                # An unreadable file, or a store folder that cannot be written: this file is not
                # covered, and the snapshot of everything else goes ahead (R7-02).
                outcome = f"could not be stored: {e.strerror or e}"
                break
            if digest is None:
                continue
            # The digest, the size and the cache key must describe one version of the file. If the
            # file changed while it was being stored, try once more; otherwise report it as uncovered.
            try:
                st2 = p.stat()
                stored_size = _object_path(objects, digest).stat().st_size
            except OSError:
                continue
            if _source_key(p, st2) != key or stored_size != st.st_size:
                continue
            cache[rel] = key + [digest]
            entry = (digest, st.st_size)
            break
        if entry is None:
            if outcome == "too large":
                skipped.append({"path": rel, "why": f"over artifacts.max_file_mb ({apol['max_file_mb']})"})
            elif outcome == "unstable":
                skipped.append({"path": rel, "why": "changed while being copied"})
            elif outcome == "not a regular file":
                skipped.append({"path": rel, "why": "not a regular file (a pipe, socket or device)"})
            elif outcome.startswith(("artifact store unusable", "could not be stored", "could not be read")):
                skipped.append({"path": rel, "why": outcome})
            continue
        files[rel] = {"sha256": entry[0], "size": entry[1]}
    skipped += _unlisted_designated(unlisted)
    if isinstance(apol.get("include_globs"), _PartlyReadableDesignation):
        skipped += _dropped_designation(repo, apol["include_globs"], excludes, cache, files)
    atomic_write_json(cache_path, cache)
    if ledger != ledger_before:
        save_ledger(store, ledger)
    if repaired:
        repo.log_event("artifact_objects_repaired", digests=repaired)
    digest = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest() if files else None
    return {"digest": digest, "files": files, "skipped": skipped, "repaired": repaired, "store": fwd(store),
            "unmatched": _unmatched_patterns(patterns, walked)}


def _unmatched_patterns(patterns, walked) -> list:
    """The include_globs patterns that matched no file the artifact walk reached. Such a pattern designates nothing, which
    no one saw (XA1-07): snapshot, status and doctor name it. It is a warning, not a file left out, since a pattern for
    results not made yet is legitimate."""
    out = []
    for pat in patterns or ():
        if isinstance(pat, str) and pat not in out and not any(match_any(rel, [pat]) for rel in walked):
            out.append(pat)
    return out


_ARTIFACT_LINE = re.compile(r"^Pecia-Artifact:\s+([0-9a-f]{64})\s+(\d+)\s+(.+)$")


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _valid_artifact_path(path) -> bool:
    """A repository-relative path with / separators that cannot leave the directory it is joined to."""
    if not isinstance(path, str) or not path or "\0" in path or path.startswith("/"):
        return False
    if IS_WINDOWS and ("\\" in path or ":" in path):
        return False
    return all(part not in ("", ".", "..") for part in path.split("/"))


def _clean_files(files) -> tuple[dict, int]:
    """Keep only well-formed artifact entries; return them and how many were dropped."""
    if not isinstance(files, dict):
        return {}, 1
    clean, bad = {}, 0
    for path, meta in files.items():
        size = meta.get("size") if isinstance(meta, dict) else None
        if (_valid_artifact_path(path) and isinstance(meta, dict) and isinstance(meta.get("sha256"), str)
                and _SHA256_RE.match(meta["sha256"]) and isinstance(size, int) and not isinstance(size, bool)
                and size >= 0):
            clean[path] = {"sha256": meta["sha256"], "size": size}
        else:
            bad += 1
    return clean, bad


def _inventory_digest(files: dict):
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest() if files else None


def _artifact_lines(files: dict) -> list[str]:
    """One commit-message line per stored artifact. The snapshot commit is immutable and kept alive
    by its ref, so the artifact list cannot disappear while the snapshot exists."""
    return [f"Pecia-Artifact: {m['sha256']} {m['size']} {json.dumps(path)}" for path, m in sorted(files.items())]


_STAGED_MAX = 2000


def _staged_lines(repo: Repo, head: str | None) -> list[str]:
    """What the index held, where it differs from HEAD, retained in the snapshot's message: one line per file, the
    version staged (all zeros for a file staged as deleted), its path and a count (R24-232). Recovery does not use
    this diagnostic record to settle a snapshot with a dropped commit (R24-237). A
    file in conflict or a submodule is left out; more than 2,000 files, or an index git cannot read, records that the
    list is not whole."""
    if not head:
        return []
    r = run_git(repo.root, ["diff-index", "--cached", "--raw", "-z", "--no-renames", "--ignore-submodules=all", head],
                check=False)
    if r.returncode != 0:
        return ["Pecia-Indexed: 0 more"]
    out, parts, i = [], r.stdout.split(b"\0"), 0
    while i + 1 < len(parts):
        meta, name = parts[i].decode("ascii", "replace").split(), parts[i + 1].decode("utf-8", "surrogateescape")
        i += 2
        if len(meta) != 5 or meta[4][:1] not in "AMDT" or "160000" in (meta[0].lstrip(":"), meta[1]):
            continue
        out.append(f"Pecia-Index: {meta[3]} {json.dumps(name)}")
    more = len(out) > _STAGED_MAX
    return [f"Pecia-Indexed: {min(len(out), _STAGED_MAX)}" + (" more" if more else "")] + out[:_STAGED_MAX]


def _snap_staged(repo: Repo, commit: str):
    """The versions a snapshot recorded as staged, {path: blob ID, or None for a file staged as deleted}, and whether
    the list is whole; None for a snapshot that recorded none, as one taken by an earlier pecia."""
    memo = _MEMO.setdefault("snap_staged", {}) if _MEMO is not None else {}
    if commit not in memo:
        res, files, whole = None, {}, True
        for line in _commit_message(repo, commit).splitlines():
            if line.startswith("Pecia-Indexed: "):
                res = True
                whole = not line.endswith(" more")
            elif line.startswith("Pecia-Index: "):
                f = line[len("Pecia-Index: "):].split(" ", 1)
                try:
                    name = json.loads(f[1]) if len(f) == 2 else None
                except ValueError:
                    name = None
                if isinstance(name, str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", f[0]):
                    files[name] = None if set(f[0]) == {"0"} else f[0]
        memo[commit] = (files, whole) if res else None
    return memo[commit]


_UNCOVERED_LINE = re.compile(r"^Pecia-Uncovered: (.+)$")
_UNCOVERED_MAX = 5000
UNLISTED_UNTRACKED = "(untracked files)"  # the coverage entry for untracked files git could not list (E1-03)


def _uncovered_lines(uncovered: list) -> list[str]:
    """One commit-message line per file this snapshot could not store, so recovery knows that a newer
    version of it existed and was never captured (R13-02)."""
    tracked = {u["path"] for u in uncovered if str(u.get("why", "")).startswith("git could not stage it")}
    paths = sorted({u["path"] for u in uncovered if isinstance(u.get("path"), str) and u["path"] != UNLISTED_UNTRACKED},
                   key=lambda p: (p not in tracked, p))  # tracked files first: they are few, and never cut off
    lines = [f"Pecia-Uncovered: {json.dumps(p)}" for p in paths[:_UNCOVERED_MAX]]
    # Untracked files git could not list cannot be named; that the snapshot left out files it did not name is
    # recorded as more files than the list holds, which recovery already reads that way (E1-03, R16-01). The count
    # is then a lower bound.
    more = max(len(paths) - _UNCOVERED_MAX, 0) + any(u.get("path") == UNLISTED_UNTRACKED for u in uncovered)
    if more:
        lines.append(f"Pecia-Uncovered-More: {more}")
    return lines


_UNCOVERED_FIND = re.compile(r"(?m)^Pecia-Uncovered: (.+)$")
_UNCOVERED_MORE = re.compile(r"(?m)^Pecia-Uncovered-More: (\d+)$")
_EXCLUDED_FIND = re.compile(r"(?m)^Pecia-Excluded-Tracked: (.+)$")


def _default_excluded(skipped: list, spol: dict) -> list[dict]:
    """The tracked files a snapshot left out that a default secret pattern of the policy excludes, as {path, pattern}
    by path. A pattern counts as a default one when it is one of the patterns pecia ships, so a policy.json that holds
    the whole list, as init writes it, is reached too; a pattern the user added is not reported (XA1-13)."""
    pats = [g for g in spol.get("exclude_globs") or [] if isinstance(g, str) and g in _DEFAULT_EXCLUDES]
    out = []
    for s in skipped:
        if s.get("why") != "tracked but excluded" or not isinstance(s.get("path"), str):
            continue
        pat = next((g for g in pats if match_any(s["path"], [g], icase=True)), None)
        if pat is not None:
            out.append({"path": s["path"], "pattern": pat})
    return sorted(out, key=lambda i: i["path"])


def _excluded_lines(items: list) -> list[str]:
    """One commit-message line per tracked file a default secret pattern excluded, so recovery can name it."""
    return [f"Pecia-Excluded-Tracked: {json.dumps({'path': i['path'], 'pattern': i['pattern']})}"
            for i in items[:_UNCOVERED_MAX]]


def _parse_excluded(message: str) -> list[dict]:
    out = []
    for raw in _EXCLUDED_FIND.findall(message or ""):
        try:
            item = json.loads(raw)
        except ValueError:
            continue
        if isinstance(item, dict) and _valid_artifact_path(item.get("path")) and isinstance(item.get("pattern"), str):
            out.append({"path": item["path"], "pattern": item["pattern"]})
    return out


def _snap_excluded(snap: dict) -> list[dict]:
    """The tracked files a snapshot from list_snapshots recorded as excluded by a default secret pattern."""
    body = snap.get("_body")
    if not body or "\nPecia-Excluded-Tracked" not in body:
        return []
    if snap.get("_excluded") is None:
        snap["_excluded"] = _parse_excluded(body)
    return snap["_excluded"]


def excluded_tracked_warning(items: list, limit: int = 20) -> str:
    if not items:
        return ""
    lines = [f"WARNING {len(items)} tracked file(s) match the default secret patterns in snapshot.exclude_globs, so no "
             "snapshot holds them and recovery cannot restore changes made to them since their last commit:"]
    lines += [f"  {i['path']} ({i['pattern']})" for i in items[:limit]]
    if len(items) > limit:
        lines.append(f"  ... and {len(items) - limit} more (see pecia status --json)")
    lines.append("  Commit the changes you want to keep. If such a file holds no secret, remove its pattern from "
                 "snapshot.exclude_globs in .pecia/policy.json (the README lists the default patterns).")
    return "\n".join(lines)


def _parse_uncovered(message: str) -> tuple[list[str], int]:
    """(paths this snapshot reported as not covered, how many more it did not list)."""
    out = []
    for raw in _UNCOVERED_FIND.findall(message):
        try:
            p = json.loads(raw)
        except ValueError:
            continue
        if isinstance(p, str) and (_valid_artifact_path(p) or p == "(designated artifacts)"):
            out.append(p)
    m = _UNCOVERED_MORE.search(message)
    return out, (int(m.group(1)) if m else 0)


def _snap_uncovered(snap: dict) -> tuple[list[str], int]:
    """The uncovered list of a snapshot from list_snapshots, parsed only when asked for (R14-04)."""
    body = snap.get("_body")
    if not body:
        return [], 0
    cached = snap.get("_uncovered")
    if cached is None:
        cached = _parse_uncovered(body)
        snap["_uncovered"] = cached
    return cached


def _snap_public(snap: dict) -> dict:
    """A snapshot as JSON output shows it: without pecia's private keys, with the files it could not
    store (R15-05)."""
    out = {k: v for k, v in snap.items() if not k.startswith("_")}
    out["uncovered"], out["uncovered_more"] = _snap_uncovered(snap)
    return out


def _parse_inventory(message: str):
    """Return (files listed in the commit or None, declared digest, declared count, unreadable lines)."""
    files, found, declared, count, bad = {}, False, None, 0, 0
    for line in message.splitlines():
        m = _ARTIFACT_LINE.match(line)
        if m:
            found = True
            try:
                path = json.loads(m.group(3))
            except ValueError:
                path = None
            if _valid_artifact_path(path):
                files[path] = {"sha256": m.group(1), "size": int(m.group(2))}
            else:
                bad += 1
        elif line.startswith("Pecia-Artifact:"):
            found = True
            bad += 1
        elif line.startswith("Pecia-Artifacts:"):
            parts = line.split(":", 1)[1].split()
            if parts and parts[0] != "none":
                declared = parts[0]
            if len(parts) > 1 and parts[1].isdigit():
                count = int(parts[1])
    return (files if found else None), declared, count, bad


def _commit_message(repo: Repo, commit: str) -> str:
    if _MEMO is not None and _SHA_RE.fullmatch(commit or ""):
        msgs = _MEMO.setdefault("messages", {})
        if commit not in msgs:
            # The search asks for the snapshots' messages in order: read the next ones in one batch, a few at a
            # time, since a message lists every stored artifact.
            order = _MEMO.get("message_order", [])
            at = order.index(commit) if commit in order else -1
            batch = order[at:at + 16] if at >= 0 else [commit]
            msgs.clear()
            msgs.update(_commit_messages(repo, batch))
        if commit in msgs:
            return msgs[commit]
    out = run_git(repo.root, ["cat-file", "commit", commit], check=False).stdout.decode("utf-8", "replace")
    return out.split("\n\n", 1)[1] if "\n\n" in out else ""


_STORE_LINE = re.compile(r"(?m)^Pecia-Store: (.+)$")


def snapshot_object_dirs(repo: Repo, policy: dict, commit: str, message: str | None = None):
    """The object folders to read a snapshot's artifacts from, most specific first: the store the
    snapshot recorded when it was taken, the store the policy names now, and the default store in
    .git. An object is used only once its bytes match its SHA-256, so looking in several places is
    safe, and recovery keeps working after artifacts.store changes or when the store's location
    depended on where a command ran (R10-05). Returns (folders, why the current setting is unusable)."""
    if message is None:
        message = _commit_message(repo, commit)
    cands, problem = [], None
    m = _STORE_LINE.search(message or "")
    if m and Path(m.group(1).strip()).is_absolute():
        cands.append(Path(m.group(1).strip()))
    try:
        cands.append(store_root(repo, policy, write=False))
    except PeciaError as e:
        problem = str(e)
    cands.append(repo.common_dir() / "pecia" / "artifacts")
    out, seen = [], set()
    for c in cands:
        key = os.path.normcase(os.path.normpath(fwd(c)))
        if key not in seen:
            seen.add(key)
            out.append(c / "objects")
    return out, problem


def locate_object(dirs, digest: str):
    """(path, state): the first copy whose bytes match the digest (ok); else the first copy found
    (corrupt); else (None, missing)."""
    first = None
    for d in dirs:
        o = _object_path(d, digest)
        if os.path.lexists(o):
            if object_ok(o, digest):
                return o, "ok"
            first = first or o
    return (first, "corrupt") if first is not None else (None, "missing")


def artifact_inventory(repo: Repo, policy: dict, commit: str, message: str | None = None) -> dict:
    """The artifacts a snapshot promises, with any reason the list cannot be trusted.
    fatal: the list is missing or contradicts the snapshot's declared digest, so evidence may be lost.
    notices: the manifest file in the store (a cache) is missing or differs; the commit's list wins."""
    if message is None:
        message = _commit_message(repo, commit)
    listed, declared, count, bad = _parse_inventory(message)
    try:
        data = load_json(store_root(repo, policy, write=False) / "manifests" / f"{commit}.json", None)
    except PeciaError:
        data = None
    raw = data.get("files") if isinstance(data, dict) else None
    cached, bad_cached = _clean_files(raw) if raw is not None else (None, 0)
    res = {"files": {}, "declared": declared, "count": count, "fatal": [], "notices": [],
           "manifest_file": cached is not None}
    if listed is not None:
        res["files"] = listed
        if bad:
            res["fatal"].append(f"{bad} line(s) of the artifact list in the snapshot commit cannot be read")
        if _inventory_digest(listed) != declared or len(listed) != count:
            res["fatal"].append("the artifact list in the snapshot commit does not match its declared digest")
        if cached is None and count:
            res["notices"].append("manifest file missing from the store; the list was read from the snapshot commit")
        elif cached is not None and cached != listed:
            res["notices"].append("manifest file differs from the snapshot commit; the commit's list was used")
        return res
    if not count and not declared:
        return res
    if cached is None:
        res["fatal"].append(f"the artifact manifest for this snapshot is missing, so {count} artifact(s) it "
                            "recorded cannot be listed or restored")
    elif bad_cached:
        res["files"] = cached
        res["fatal"].append(f"the artifact manifest for this snapshot has {bad_cached} malformed entr"
                            f"{'y' if bad_cached == 1 else 'ies'}, which cannot be listed or restored")
    elif _inventory_digest(cached) != declared:
        res["files"] = cached
        res["fatal"].append("the artifact manifest does not match the digest recorded in the snapshot")
    else:
        res["files"] = cached
    return res


def load_manifest(repo: Repo, policy: dict, commit: str) -> dict:
    return artifact_inventory(repo, policy, commit)["files"]


def _snapshot_refs(repo: Repo, prefix: str) -> list:
    """(ref, commit, tree, parent, time) of each snapshot ref under prefix. These fields can never hold a
    newline or a NUL, so one line per ref with NUL between fields is unambiguous; the messages, which hold
    free text, are read separately (C-05)."""
    fmt = "%(refname)%00%(objectname)%00%(tree)%00%(parent)%00%(creatordate:unix)"
    out = run_git(repo.root, ["for-each-ref", f"--format={fmt}", prefix]).stdout
    refs = []
    for line in out.split(b"\n"):
        fields = line.split(b"\0")
        if len(fields) == 5:
            refs.append(tuple(f.decode("utf-8", "replace") for f in fields))
    return refs


def _commit_messages(repo: Repo, commits: list) -> dict:
    """{commit: message} read with git cat-file --batch, which states each object's size, so no byte a
    message may contain can split or merge records (C-05)."""
    want = [c for c in dict.fromkeys(commits) if re.fullmatch(r"[0-9a-f]{40,64}", c or "")]
    if not want:
        return {}
    out = run_git(repo.root, ["cat-file", "--batch"], input_bytes=("\n".join(want) + "\n").encode()).stdout
    msgs, pos = {}, 0
    while pos < len(out):
        nl = out.find(b"\n", pos)
        if nl < 0:
            break
        head = out[pos:nl].split(b" ")
        pos = nl + 1
        if len(head) != 3 or not head[2].isdigit():
            continue  # "<oid> missing" and the like carry no content
        size = int(head[2])
        raw = out[pos:pos + size]
        pos += size + 1
        if head[1] == b"commit":
            text = raw.decode("utf-8", "replace")
            msgs[head[0].decode()] = text.split("\n\n", 1)[1] if "\n\n" in text else ""
    return msgs


def _live_snapshot_messages(repo: Repo) -> dict:
    refs = _snapshot_refs(repo, REF_ROOT + "/")
    return _commit_messages(repo, [r[1] for r in refs])


def gc_artifact_store(repo: Repo, policy: dict) -> None:
    store = store_root(repo, policy)
    manifests, objects = store / "manifests", store / "objects"
    if not manifests.is_dir():
        return
    # A store set with artifacts.store lives outside the project, so every copy of the project folder
    # made with its .git uses the same folder, and their snapshots are invisible from here. There,
    # only pecia's own abandoned partial writes are removed; objects and manifests stay (IR-30).
    shared = bool(_configured_store(policy))
    msgs = _live_snapshot_messages(repo)
    live = set(msgs)
    cutoff = time.time() - 3600
    referenced = set()
    unreadable = []
    for commit, body in msgs.items():
        inv = artifact_inventory(repo, policy, commit, body)
        referenced |= {f["sha256"] for f in inv["files"].values()}
        if inv["fatal"]:
            unreadable.append(commit)
    try:
        # Every deletion below happens inside a held folder, by name, so a folder swapped for a link
        # after it was checked cannot send it outside the store (V-07).
        with _held_dir(manifests) as md:
            for name in sorted(md.names()):
                if not name.endswith(".json"):
                    continue
                try:
                    st = md.lstat(name)
                except OSError:
                    continue
                if not stat_mod.S_ISREG(st.st_mode):
                    continue
                young = st.st_mtime >= cutoff
                if name[:-5] not in live and not young and not shared:
                    # Young manifests may belong to a snapshot whose ref is not written yet.
                    md.unlink_quietly(name)
                    continue
                try:
                    with md.open_read(name) as f:
                        data = json.loads(f.read(_JSON_LIMIT + 1).decode("utf-8"))
                except (OSError, ValueError):
                    data = {}
                files, _ = _clean_files(data.get("files") if isinstance(data, dict) else None)
                referenced |= {f["sha256"] for f in files.values()}
    except (OSError, PeciaError):
        unreadable.append("(manifest folder)")
    if unreadable:
        # A snapshot whose artifact list cannot be read may still need objects nobody else lists,
        # so no object is deleted until verify reports it and the snapshot is dealt with.
        repo.log_event("artifact_gc_skipped", reason="unreadable artifact list", snapshots=unreadable[:50])
    elif os.path.isdir(objects):
        # Only regular files that look like store objects, in real two-character folders, are ever
        # deleted; a link anywhere is skipped and logged (T-07).
        try:
            with _held_dir(objects) as od:
                for sub in sorted(od.names()):
                    if not re.fullmatch(r"[0-9a-f]{2}", sub):
                        continue
                    try:
                        sst = od.lstat(sub)
                        if not stat_mod.S_ISDIR(sst.st_mode) and not stat_mod.S_ISLNK(sst.st_mode):
                            continue
                        sd = od.child(sub)
                    except UnsafePath:
                        repo.log_event("artifact_gc_skipped_link", path=fwd(objects / sub))
                        continue
                    except OSError:  # an unreadable folder is left alone (R6-07)
                        continue
                    with sd:
                        try:
                            entries = sorted(sd.names())
                        except OSError:
                            continue
                        for obj in entries:
                            try:
                                st = sd.lstat(obj)
                                if not stat_mod.S_ISREG(st.st_mode):
                                    continue
                                is_tmp = obj.startswith(".tmp-")
                                if not is_tmp and not (re.fullmatch(r"[0-9a-f]{64}", obj) and obj.startswith(sub)):
                                    continue
                                if st.st_mtime >= cutoff:
                                    continue
                                if is_tmp or (obj not in referenced and not shared):
                                    sd.unlink(obj)
                            except OSError:
                                pass
        except (OSError, PeciaError) as e:
            repo.log_event("artifact_gc_skipped", reason=str(e))
    ledger = load_ledger(store)
    gone = [d for d in ledger if not _object_path(objects, d).exists()]
    if gone:
        for d in gone:
            ledger.pop(d, None)
        save_ledger(store, ledger)


def quarantined_copy(store: Path, digest: str):
    qdir = store / "quarantine"
    if not qdir.is_dir():
        return None
    found = sorted(qdir.glob(digest + ".*"))
    return found[-1] if found else None


def verify_store(repo: Repo, policy: dict) -> dict:
    """Check every live snapshot's artifact list and hash every object it references. A missing
    manifest file is rebuilt from the snapshot commit and reported; a list that cannot be read or
    contradicts its snapshot is an integrity failure."""
    store = store_root(repo, policy)
    objects = store / "objects"
    ledger = load_ledger(store)
    uses: dict = {}
    rep = {"snapshots": 0, "checked": 0, "ok": 0, "corrupt": [], "missing": [], "inventory_problems": [],
           "manifests_restored": [], "quarantined": []}
    for commit, body in sorted(_live_snapshot_messages(repo).items()):
        rep["snapshots"] += 1
        inv = artifact_inventory(repo, policy, commit, body)
        for why in inv["fatal"]:
            rep["inventory_problems"].append({"snapshot": commit, "why": why})
        if inv["files"] and not inv["manifest_file"] and not inv["fatal"]:
            try:
                atomic_write_json(store / "manifests" / f"{commit}.json",
                                  {"version": 1, "created": iso(), "commit": commit, "files": inv["files"],
                                   "restored_by": "verify"})
                rep["manifests_restored"].append(commit)
            except (OSError, PeciaError):
                pass
        for path, meta in inv["files"].items():
            u = uses.setdefault(meta["sha256"], {"refs": [], "paths": set()})
            u["paths"].add(path)
            u["refs"].append((commit, path, meta["size"]))
    for digest, info in sorted(uses.items()):
        if not digest:
            continue
        rep["checked"] += 1
        obj = _object_path(objects, digest)
        entry = {"sha256": digest, "paths": sorted(info["paths"])}
        if _is_link(obj.parent) or _is_link(obj):
            # Moving it to quarantine would move a file outside the store (T-07). The next snapshot
            # refuses the link too, so it is reported here as missing until a regular folder replaces it.
            entry["why"] = "reached through a symlink or junction, which pecia neither reads nor moves"
            rep["missing"].append(entry)
        elif not obj.exists():
            q = quarantined_copy(store, digest)
            if q:
                entry["quarantined_at"] = fwd(q)
            rep["missing"].append(entry)
        elif object_ok(obj, digest):
            # The object is judged by its hash alone. A recorded size that disagrees (an earlier
            # version could record a stale size for a file that changed during capture) is an
            # inventory problem; the bytes themselves are intact and stay where they are.
            rep["ok"] += 1
            record_verified(ledger, digest, obj)
            actual = obj.stat().st_size
            for commit, path, size in info["refs"]:
                if size != actual:
                    rep["inventory_problems"].append({
                        "snapshot": commit, "why": f"{path}: recorded size {size} differs from the stored bytes "
                                                   f"({actual}); the bytes match the SHA-256 and are intact"})
        else:
            # Move the bad bytes aside instead of deleting them, so the next snapshot rebuilds the
            # object from the source file while that file still holds the right content.
            ledger.pop(digest, None)
            try:
                qdir = store / "quarantine"
                dest = qdir / f"{digest}.{utcnow().strftime('%Y%m%dT%H%M%S%fZ')}"
                # Moved between held folders, by name: a folder swapped for a link after the checks above
                # cannot make this move a file outside the store (V-07).
                with _held_dir(obj.parent) as sd, _held_dir(qdir, create=True) as qd:
                    if not stat_mod.S_ISREG(sd.lstat(digest).st_mode):
                        raise OSError(errno.EINVAL, "not a regular file", fwd(obj))
                    sd.replace(digest, dest.name, into=qd)
                    if IS_WINDOWS and _is_link(qd.path):
                        # An empty quarantine folder turned into a junction before the move (U1). The damaged copy
                        # went where the junction leads and is left there and named: moving it back by name could
                        # move whatever that name leads to by then, a file outside the store (M-02). The next
                        # snapshot rebuilds the object from the source file.
                        raise OSError(errno.EINVAL, "the quarantine folder became a junction while pecia moved the "
                                                    f"damaged copy into it; that copy is now at {fwd(qd.path / dest.name)}"
                                                    " and was left there", fwd(qd.path))
                entry["quarantined_at"] = fwd(dest)
                rep["quarantined"].append(digest)
            except (OSError, PeciaError) as e:
                entry["quarantine_error"] = str(e)
            rep["corrupt"].append(entry)
    save_ledger(store, ledger)
    repo.log_event("verify_store", checked=rep["checked"], corrupt=len(rep["corrupt"]), missing=len(rep["missing"]),
                   inventory_problems=len(rep["inventory_problems"]), manifests_restored=len(rep["manifests_restored"]))
    return rep


# ---------------------------------------------------------------- snapshots

def _parse_trailers(body: str) -> dict:
    out = {}
    for line in body.splitlines():
        m = re.match(r"^Pecia-([A-Za-z]+):\s*(.*)$", line)
        if m:
            out[m.group(1).lower()] = m.group(2).strip()
    return out


_REF_TAIL = re.compile(r"^(\d{10})-(\d{8}T\d{6}\d*Z)-[0-9a-f]+$")


def _parse_gap(raw):
    """The Pecia-Gap record of a capture-failure record (RP-01), or None for a snapshot."""
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return {"cause": "(the record of this failed capture cannot be read)", "count": 1}
    return data if isinstance(data, dict) else {"cause": "(the record of this failed capture cannot be read)", "count": 1}


def list_snapshots(repo: Repo, all_worktrees=False) -> list[dict]:
    """Newest first. Order comes from a per-worktree sequence number in the ref name, never
    from clocks, so a clock that steps backward cannot reorder or prune the wrong snapshot."""
    if all_worktrees:
        prefix = REF_ROOT + "/"
    else:
        wid = repo.worktree_id(create=False)  # a tree without an id has no snapshots; listing writes nothing
        if wid is None:
            return []
        prefix = f"{REF_ROOT}/{wid}/"
    refs = _snapshot_refs(repo, prefix)
    bodies = _commit_messages(repo, [r[1] for r in refs])
    snaps = []
    for ref, commit, tree, parent, ts in refs:
        body = bodies.get(commit, "")
        tr = _parse_trailers(body)
        m = _REF_TAIL.match(ref.rsplit("/", 1)[-1])
        seq, stamp = (int(m.group(1)), m.group(2)) if m else (0, "")
        snaps.append({"ref": ref, "commit": commit, "tree": tree, "parent": parent.split(" ")[0] if parent else "",
                      "seq": seq, "stamp": stamp, "time": int(ts or 0), "reason": tr.get("reason", ""),
                      "agent": tr.get("agent", ""), "head": tr.get("head", ""), "branch": tr.get("branch", ""),
                      "detached": tr.get("detached") == "yes", "reflog": tr.get("reflog"),
                      "artifacts": tr.get("artifacts", "none").split(" ")[0], "skipped": tr.get("skipped", "0"),
                      "has_uncovered": "\nPecia-Uncovered" in body,
                      "_body": body if "\nPecia-Uncovered" in body or "\nPecia-Excluded-Tracked" in body else None,
                      "gap": _parse_gap(tr.get("gap"))})
    if all_worktrees:
        snaps.sort(key=lambda s: (s["time"], s["seq"], s["stamp"]), reverse=True)
    else:
        snaps.sort(key=lambda s: (s["seq"], s["stamp"], s["ref"]), reverse=True)
    return snaps


def _carries_work(repo: Repo, snaps: list[dict]) -> dict:
    """Map snapshot ref to True when it carries work of either kind; see _work_kinds."""
    return {ref: tree or arts for ref, (tree, arts) in _work_kinds(repo, snaps).items()}


def _work_kinds(repo: Repo, snaps: list[dict]) -> dict:
    """Map snapshot ref to (tree work, artifact work): whether its tree differs from its parent
    commit's tree, and whether it holds an artifact set that differs from the next older
    snapshot's. snaps is newest first."""
    parents = sorted({s["parent"] for s in snaps if s["parent"]})
    trees = {}
    if parents:
        out = run_git(repo.root, ["rev-parse", *[f"{p}^{{tree}}" for p in parents]], check=False).stdout.decode().split()
        if len(out) == len(parents):
            trees = dict(zip(parents, out))
    work = {}
    for i, s in enumerate(snaps):
        tree_work = (not s["parent"]) or trees.get(s["parent"]) != s["tree"]
        arts = s.get("artifacts") or "none"
        # A capture-failure record holds no artifacts and takes no part in what the next snapshot's set is compared
        # with (RP-01, C17 requirement 4).
        nxt = next((o for o in snaps[i + 1:] if not o.get("gap")), None)
        older = (nxt.get("artifacts") or "none") if nxt else "none"
        work[s["ref"]] = (bool(tree_work) and not s.get("gap"), arts != "none" and arts != older)
    return work


def resolve_snapshot(repo: Repo, spec: str, policy: dict | None = None) -> dict:
    """latest: the newest snapshot taken on the current HEAD that still has something to restore right
    now, or that holds work which is missing and can no longer be restored. Such a snapshot is never
    passed over for an older one: recovering it reports the loss as incomplete, and names any older
    snapshot that holds an earlier version, which the user may then choose explicitly (V-01).
    A snapshot taken on an earlier commit of the same branch is chosen for the paths no later commit touched (N-12);
    one taken before history last moved here, as by a reset, rebase, amend, merge, pull or checkout, never is: what
    it holds is reported instead (R24-87).
    newest: the literal newest snapshot. N: the snapshot at position N in the snapshots list, which counts from 0, so 0
    is the newest (N-10). Otherwise a ref or commit prefix."""
    mine = list_snapshots(repo)
    if spec in ("latest", "last", "newest", "0"):
        if not mine:
            raise PeciaError("no snapshots exist for this working tree")
        if spec in ("newest", "0"):
            return mine[0]
        return _resolve_latest(repo, mine, policy or load_policy(repo))
    if spec.isdigit() and len(spec) < 6:
        i = int(spec)
        if i < len(mine):
            return mine[i]
        raise PeciaError(f"only {len(mine)} snapshots exist for this working tree")
    everything = list_snapshots(repo, all_worktrees=True)
    hits = [s for s in everything if s["ref"] == spec or s["ref"].endswith("/" + spec)
            or (len(spec) >= 7 and s["commit"].startswith(spec))]
    if len(hits) == 1:
        return hits[0]
    if not hits:
        raise PeciaError(f"no snapshot matches {spec}")
    raise PeciaError(f"{spec} is ambiguous ({len(hits)} matches); use a longer prefix")


_SUSPECT_RANK = {None: 0, "artifacts": 1, "all": 2, "tracked": 3}


def _resolve_latest(repo: Repo, mine: list, policy: dict) -> dict:
    with _search_memo():
        _MEMO.setdefault("message_order", [s["commit"] for s in mine])
        return dict(_search_latest(repo, mine, policy), latest=True)


def _search_latest(repo: Repo, mine: list, policy: dict) -> dict:
    """The snapshot recover latest uses: the newest one with work to restore now among those taken since history last
    moved in this worktree (R24-87). A history move is any step in HEAD's reflog but a commit made here on top of HEAD:
    a reset, rebase, amend, merge, pull, cherry-pick, or a checkout of another commit or branch. latest never restores
    across one; a version a snapshot taken before it holds, of a file that is not here now, is reported with the
    snapshot that holds it and the command that restores it, until recover ack (R24-87). Seven internal reviews found
    that rules guessing from history which commit superseded which version each hid a real loss; there are none.
    Among the snapshots taken since: a newer snapshot that holds only losses (evidence that cannot be restored, or a
    newest version that was never stored) does not end the search, so it cannot hide older lost work that can be
    restored (R17-01); its losses are carried to the snapshot chosen, reported there, and older versions of those files
    are never restored implicitly (V-01, R13-02). When no snapshot has work to restore, the newest one with losses is
    reported. Older versions are named, for the user to restore by naming the snapshot. The work older snapshots taken
    since would restore once the chosen one's is back is named with it, so a recovery that says complete leaves nothing
    for the next (G1-09)."""
    head = repo.head() or ""
    branch = _line_branch(repo) or "(detached or unborn)"
    entries = _head_reflog(repo)
    _mark_reverts(repo, entries)
    moved = _moves(entries) if entries else []
    last_move = next((i for i, m in enumerate(moved) if m), None)

    # HEAD moved without an entry in this worktree's reflog, as by git update-ref from another worktree or after git
    # reflog delete: a move newer than every entry, after which only a snapshot on HEAD's own commit with no entry since
    # counts as taken (R24-96).
    unseen = bool(entries) and bool(head) and entries[0]["oid"] != head

    def after_last_move(s) -> bool:
        # A snapshot on another line, or on a commit HEAD's history no longer holds, is before a move by the evidence
        # rule below.
        mk = s.get("reflog")
        if not entries:
            # A snapshot that recorded a place, which HEAD's reflog no longer holds, as after git reflog expire
            # --expire=now --all, was taken before a move that may have gone with the entries (d2, RP-13).
            if mk and mk != "none":
                return False
            # No reflog: only a snapshot on HEAD itself is known to be after every move.
            return bool(head) and (s["parent"] or "") == head
        if not mk or mk == "none":
            # Taken before pecia recorded its place in the reflog, or when it was empty: before every move the reflog
            # holds now, since entry times can come from the environment (R24-108).
            return last_move is None and not unseen
        a = _mark_index(entries, mk)
        if a is None:
            return False
        if unseen:
            return a == 0 and (s["parent"] or "") == head
        return last_move is None or a <= last_move

    # A snapshot taken on another line shows a move made after it, with or without a reflog: every snapshot taken before it
    # is before a move too. (One on a commit HEAD's history no longer holds is placed before a move by the reflog, or
    # without one by its base, which is not HEAD.)
    evidence = max((s["seq"] for s in mine if _snap_line(s, branch) != branch), default=None)
    # Monotone: a snapshot older than one taken before a move was taken before it too, whatever its own place in the
    # reflog says, as when an entry it was placed by was deleted (R24-97).
    cand = [s for s in mine if after_last_move(s)]
    cand_refs = {s["ref"] for s in cand}
    floor = max([s["seq"] for s in mine if s["ref"] not in cand_refs] + ([evidence] if evidence is not None else []),
                default=None)
    on_head = [s for s in cand if floor is None or s["seq"] > floor]
    since_refs = {s["ref"] for s in on_head}
    acked = _acked_keys(repo)
    before_all = [s for s in mine if s["ref"] not in since_refs]
    before = before_all  # recover ack hides what it acknowledged, report by report, not whole snapshots (R24-110)
    walk = list(enumerate(on_head))
    work = _carries_work(repo, mine)
    cache: dict = {}

    def sig_of(s):
        # What a snapshot could not store is part of what it says: a newer snapshot of the same tree
        # without those files does not speak for it (R14-01).
        return (s["tree"], s["parent"], s["artifacts"], s["branch"],
                tuple(_snap_uncovered(s)[0]) if s.get("has_uncovered") else ())
    # What snapshots newer than a candidate could not name makes the candidate's older versions suspect
    # (R14-02, R14-03): of every designated file when artifact capture failed as a whole, and of every
    # untracked or designated file when more files were left out than the list holds. A snapshot's own
    # captured work is never suspect (R15-01).
    newer_suspect, flag = [], None
    for s_ in on_head:
        newer_suspect.append(flag)
        if (s_.get("gap") or {}).get("tracked"):
            # A failed capture whose list of changed paths is not whole (git status failed, or the list was cut off)
            # makes older versions of every file suspect, tracked ones included: a kind of its own, so E1-03's kinds
            # keep exempting tracked files (RP-01, C17 requirement 3).
            flag = "tracked"
        elif s_.get("has_uncovered"):
            own, more = _snap_uncovered(s_)
            if more:
                flag = max(flag, "all", key=lambda k: _SUSPECT_RANK[k])
            elif "(designated artifacts)" in own and flag is None:
                flag = "artifacts"
    key, holds = _path_key(repo), _Holds(repo)
    since_held: set = set()

    def search(pre: dict):
        """One pass. pre: losses an earlier pass found past an answer whose work they took away, each with the place in
        the walk where it is found; every snapshot newer than that place withholds it from the start (R24-21)."""
        seen, carried, first, dyn = set(), {}, None, None
        # The first answer must report what every later answer would, once the work of this one, and of each snapshot
        # a later answer would choose, is back (J-04, N-01, E1-01, R24-03, R24-04). So the search does not stop at the
        # snapshot chosen: it goes on through every older snapshot, as the later answers would, with the paths the
        # answers restore taken as restored, and their losses are reported now. restored: the paths an answer would
        # restore and speak for once back (N-01's rule: a designated copy at the committed version speaks for nothing).
        # A path an older snapshot could lose is either one of those, or missing now, where a newer snapshot that lists
        # it would have restored it or reported it lost first.
        answer, restored, later = None, set(), {}
        # What the later answers would restore, by the snapshot that holds it: a file an older snapshot taken since holds
        # that is missing now or back at its committed version, which the answer does not hold, as after a deletion, a
        # rename or git restore made since that older snapshot. The first answer names it, and is not complete while a
        # second recovery would still restore something (G1-09).
        later_work: dict = {}
        answer_keys: set = set()
        for t, (idx, snap) in enumerate(walk):
            withheld = list(carried.values()) + [u for k, (u, src) in pre.items() if src > t and k not in carried]
            suspect = max(newer_suspect[idx], dyn, key=lambda k: _SUSPECT_RANK[k])
            # Snapshots with the same content and base give the same plan, and one with no work of its own,
            # no artifacts and nothing it could not store has nothing to say.
            sig = sig_of(snap)
            if sig in seen or (not work.get(snap["ref"]) and snap["artifacts"] in ("none", "")
                               and not snap.get("has_uncovered")):
                continue
            snap = dict(snap, implicit=True, suspect=suspect, withheld=withheld)
            own_list, own_more = _snap_uncovered(snap) if snap.get("has_uncovered") else ([], 0)
            kind = ("tracked" if (snap.get("gap") or {}).get("tracked") else "all" if own_more else
                    "artifacts" if "(designated artifacts)" in own_list else None)
            if kind:
                snap["unnamed_lost"] = _unnamed_losses(repo, snap, on_head[idx + 1:], policy, kind, cache=cache)
            plan = recover_plan(repo, snap, policy)
            # What a snapshot taken since the last move speaks for: no version taken before that move is reported for
            # it, being older.
            since_held.update(holds.of(snap, plan))
            if not any(u["path"] == "(artifact list)" for u in plan["unrecoverable"]):
                seen.add(sig)
            elif any(sig_of(o) == sig for o in on_head[idx + 1:]):
                # An older twin declares the very same tree and artifacts and may still have a readable
                # artifact list: it restores the same evidence, not an older version.
                continue
            if answer is not None:
                # Past the answer: the paths an answer restores are back, so this snapshot neither restores nor loses them.
                plan = {g: ([i for i in v if key(i["path"]) not in restored] if g in _PLAN_GROUPS else v)
                        for g, v in plan.items()}
            has_work = bool(plan["missing"] or plan["reverted"])
            if has_work and answer is None:
                answer = (idx, snap, plan)
                answer_keys = {key(i["path"]) for g in ("missing", "reverted") for i in plan[g]}
            elif has_work:
                # A designated copy at the committed version speaks for nothing (N-01): it is no later work for a file
                # the answer restores, and a version a later snapshot holds of its own takes its place (IR31-05).
                held_here = holds.of(snap, plan)
                for g in ("missing", "reverted"):
                    for i in plan[g]:
                        k = key(i["path"])
                        held = k in held_here
                        if not held and k in answer_keys:
                            continue
                        if k not in later_work or (held and not later_work[k][1]):
                            later_work[k] = ({"path": i["path"], "snapshot": snap["ref"], "group": g}, held)
            if has_work:
                # A designated copy at the committed version, once restored, leaves the file where git restore would:
                # an older snapshot's loss of a newer version still stands (N-01, R23-19).
                restored |= {key(i["path"]) for g in ("missing", "reverted") for i in plan[g]} & holds.of(snap, plan)
            own_losses = [dict(u, category=c, snapshot=snap["ref"]) for c in ("unrecoverable", "never_stored")
                          for u in plan[c] if u.get("snapshot") in (None, snap["ref"])]
            if own_losses:
                for u in own_losses:
                    if key(u["path"]) not in carried:
                        carried[key(u["path"])] = u
                        if answer is not None and idx != answer[0]:
                            later[key(u["path"])] = (u, t)
                if any(u["path"] == "(artifact list)" for u in own_losses):
                    dyn = max(dyn, "artifacts", key=lambda k: _SUSPECT_RANK[k])  # its artifacts are unknown
                if first is None:
                    first = (idx, snap)
        if answer is not None:
            idx, snap, plan = answer
            have = {key(w["path"]) for w in snap["withheld"]}
            add = [u for k, (u, _src) in later.items() if k not in have]
            if add or later_work:
                # Losses the later answers would report are reported with the first (J-04), and so is the work they
                # would restore (G1-09).
                snap = dict(snap, withheld=snap["withheld"] + add, later_work=[w for w, _held in later_work.values()])
                plan = recover_plan(repo, snap, policy)
            return ("answer", idx, snap, plan, later)
        if first is not None:
            # No snapshot has work to restore: the newest one with losses is reported, with every loss an older
            # snapshot holds for a file no newer snapshot speaks for (R24-11; until 0.1.2rc13 only its own, R18-02).
            idx, snap = first
            older = [u for u in carried.values() if u["snapshot"] != snap["ref"]
                     and not any(key(w["path"]) == key(u["path"]) for w in snap["withheld"])]
            if older:
                snap = dict(snap, withheld=snap["withheld"] + older)
            return ("first", idx, snap, recover_plan(repo, snap, policy), later)
        return ("none",)

    pre: dict = {}
    found: tuple = ("none",)
    moved_losses = None
    for _ in range(2 * len(walk) + 4):
        found = search(pre)
        if found[0] == "answer":
            _, idx, snap, plan, later = found
            new = {k: v for k, v in later.items() if k not in pre}
            if new and not (plan["missing"] or plan["reverted"]):
                # The losses older snapshots hold took away all the answer's work: restoring nothing, it would be chosen
                # again by every later recovery, and older work would never come back (R24-21). The search runs again
                # with those losses withheld from the start, so the answer is the newest snapshot with work left.
                pre.update(new)
                continue
            if moved_losses is None:
                # Every snapshot taken since has been planned by now, so what they hold is known.
                moved_losses, hidden, settles_snapshot = _before_move_losses(repo, policy, before, since_held, entries, moved, work, head,
                                                           branch, acked, since=on_head)
            work_k = {key(i["path"]) for g in ("missing", "reverted") for i in plan[g]}
            add = {k: (u, len(walk) + 1) for k, u in moved_losses.items() if k in work_k and k not in pre
                   and not u.get("beside")}
            if add and work_k <= set(add) | {k for k in pre}:
                # The same for what the snapshots taken before the move hold: when it takes away all the answer's work,
                # every snapshot taken since withholds it from the start, so an older one's work is restored (fuzz17,
                # seed 1520014).
                pre.update(add)
                continue
        break
    if moved_losses is None:
        moved_losses, hidden, settles_snapshot = _before_move_losses(repo, policy, before, since_held, entries, moved, work, head, branch,
                                                   acked, since=on_head)
    ctx = {"since": since_refs, "before": len(before_all), "acked": hidden,
           "move": entries[last_move] if last_move is not None else None,
           "newest_before": max((s["seq"] for s in before_all), default=None)}

    def with_moved(snap, plan):
        # A file the snapshot chosen restores as a designated copy at the committed version, which speaks for nothing
        # (N-01), is withheld for the newer version reported, as for any loss (V-01).
        listed = {key(u["path"]) for g in _LOSS_GROUPS for u in plan[g]}
        have = {key(w["path"]) for w in snap["withheld"]}
        add = [u for k, u in moved_losses.items() if k not in listed and k not in have]
        if not add:
            return snap, plan
        snap = dict(snap, withheld=snap["withheld"] + add)
        return snap, recover_plan(repo, snap, policy)

    def finish(snap):
        # A capture-failure record is no capture by any agent (RP-01, C17 requirement 4).
        losses = _agent_replaced_losses(repo, policy, [s_ for s_ in mine if not s_.get("gap")], snap, acked, entries,
                                        moved, [s_ for s_ in on_head if not s_.get("gap")], settles_snapshot)
        if losses:
            snap = dict(snap, implicit=True, withheld=list(snap.get("withheld") or []) + losses)
            snap["note"] = ((snap.get("note") + "; ") if snap.get("note") else "") + (
                "earlier work replaced by a different agent remains reported until restored or acknowledged")
        return snap

    if found[0] in ("answer", "first"):
        _, idx, snap, plan, _later = found
        snap, plan = with_moved(snap, plan)
        return finish(_latest_notes(repo, mine, on_head, idx, snap, plan, policy, cache, ctx))
    if on_head:
        if moved_losses:
            first_snap = dict(on_head[0], implicit=True, suspect=newer_suspect[0], withheld=[])
            snap, plan = with_moved(first_snap, recover_plan(repo, first_snap, policy))
            return finish(_latest_notes(repo, mine, on_head, 0, snap, plan, policy, cache, ctx))
        note = "no snapshot taken since history last moved has anything to restore"
        unnamed = _unnamed_note(on_head)
        if unnamed:
            # Files no snapshot ever held cannot be named here, but that a snapshot left some out can (E1-02, E1-03).
            note += "; " + unnamed
        return finish(dict(on_head[0], note=_moved_note(ctx, note)))
    if not mine:
        raise PeciaError("no snapshots exist for this working tree")
    # No snapshot was taken since history last moved: latest restores nothing, and reports what older snapshots hold.
    snap = dict(mine[0], implicit=True, suspect=None, withheld=list(moved_losses.values()), report_only=True)
    plan = recover_plan(repo, snap, policy)
    return finish(_latest_notes(repo, mine, on_head, 0, snap, plan, policy, cache, ctx))


def _agent_replaced_losses(repo: Repo, policy: dict, mine: list, chosen: dict, acked: set,
                           entries: list, moved: list, since: list, settles_snapshot) -> list:
    """Lost work replaced by a different recorded agent within any one history epoch.

    Each consecutive writer owns its latest changed version. Identical captures do not transfer ownership, and
    unlabelled captures cannot establish a new writer. Completed writer segments remain independent losses until
    their change survives or is acknowledged. This is recorded attribution, not inference about unsnapshotted edits.
    """
    agents = {s.get("agent") for s in mine} - {None, "", "-"}
    if len(agents) < 2:
        return []
    key, holds = _path_key(repo), _Holds(repo)
    records, paths = [], {}
    pos_of, move_at = _snapshot_positions(mine, entries, moved)
    since_refs = {s["ref"] for s in since}
    for s in reversed(mine):
        p = recover_plan(repo, dict(s, implicit=True, moved=True, suspect=None, withheld=[]), policy)
        own = holds.of(s, p)
        inventory = artifact_inventory(repo, policy, s["commit"])["files"]
        versions = {key(path): ["git", oid, f"{s['commit']}:{path}"]
                    for path, (mode, typ, oid) in _snapshot_tree(repo, s["commit"]).items()
                    if typ == "blob" and mode in ("100644", "100755")}
        versions.update({key(path): ["artifact", meta["sha256"]] for path, meta in inventory.items()})
        items = {}
        for group in ("missing", "reverted", "identical", "differs", "unrecoverable", "never_stored", "unsafe"):
            for i in p[group]:
                k = key(i["path"])
                if k not in own or i["path"] in ("(artifact list)", "(designated artifacts)", UNLISTED_UNTRACKED):
                    continue
                items[k] = i
                paths[k] = i["path"]
                if group == "never_stored":
                    versions[k] = None  # a fallback Git entry does not describe the uncaptured bytes
        end = bisect.bisect_left(move_at, pos_of[s["ref"]]) - 1
        # A branch change also separates writers when its reflog entry has disappeared.
        epoch = (move_at[end] if end >= 0 else -1, s.get("branch"))
        records.append((s, items, versions, epoch))

    retired = []
    for k in paths:
        writer, latest, previous, previous_epoch = None, None, None, None
        for s, items, versions, epoch in records:
            if epoch != previous_epoch:
                writer, latest, previous = None, None, None
            previous_epoch = epoch
            version = versions.get(k)
            same = _same_version(repo, previous, version)
            agent = s.get("agent")
            if k in items and agent not in (None, "", "-") and (writer is None or not same):
                if writer is not None and writer != agent:
                    retired.append((k, *latest))
                writer, latest = agent, (s, items[k], version)
            previous = version
    if not retired:
        return []

    head = repo.head() or ""
    head_versions = {key(path): ["git", oid, f"{head}:{path}"]
                     for path, (mode, typ, oid) in (_snapshot_tree(repo, head) if head else {}).items()
                     if typ == "blob" and mode in ("100644", "100755")}
    selected = recover_plan(repo, chosen, policy)
    restored = {key(i["path"]): _item_version(i, chosen["commit"])
                for g in ("missing", "reverted") for i in selected[g]}
    # An old capture is not a surviving copy after a later move (R24-244).
    newest, _, newest_versions, _ = next(
        (r for r in reversed(records) if r[0]["ref"] in since_refs), (None, {}, {}, None))
    available, disk = {}, {}

    def readable(s, v):
        if not v:
            return False
        ident = (s["commit"] if s else "", *v)
        if ident not in available:
            if v[0] == "artifact":
                dirs, problem = snapshot_object_dirs(repo, policy, s["commit"])
                available[ident] = not _object_problem(dirs, problem, v[1])
            else:
                available[ident] = run_git(repo.root, ["cat-file", "-e", v[1] + "^{blob}"], check=False).returncode == 0
        return available[ident]

    def survives(k, s, v, other, other_snap=None):
        if not v or not other or not readable(other_snap, other):
            return False
        if _same_version(repo, v, other):
            return True
        if v[0] != "git" or other[0] != "git":
            return False  # byte-exact copies require exact bytes, including across representations
        base = _snapshot_tree(repo, s["parent"]) if s.get("parent") else {}
        base_oid = next((oid for path, (mode, typ, oid) in base.items()
                         if key(path) == k and typ == "blob" and mode in ("100644", "100755")), None)
        return _holds_change(repo, base_oid, v[1], other[1])

    out = {}
    for k, s, item, version in retired:
        path = item["path"]
        if settles_snapshot(s, k, path, version):
            continue  # use the same local kept-commit and intervening-evidence rule as the history reader
        if k not in disk:
            try:
                data = _read_regular(_safe_target(repo, path))
                digest = hashlib.sha256(data).hexdigest()
                h = run_git(repo.root, ["hash-object", "-w", "--stdin", f"--path={path}"],
                            check=False, input_bytes=data)
                oid = h.stdout.decode("ascii", "replace").strip() if h.returncode == 0 else None
                disk[k] = (digest, ["git", oid, oid] if oid else None)
            except (OSError, UnsafePath):
                disk[k] = (None, None)
        if (version and version[0] == "artifact" and version[1] == disk[k][0]
                or survives(k, s, version, disk[k][1])
                or survives(k, s, version, head_versions.get(k))
                or survives(k, s, version, newest_versions.get(k), newest)
                or survives(k, s, version, restored.get(k), chosen)):
            continue
        name = s["ref"].rsplit("/", 1)[-1]
        bad = None
        if version and version[0] == "artifact":
            dirs, problem = snapshot_object_dirs(repo, policy, s["commit"])
            bad = _object_problem(dirs, problem, version[1])
        if not version:
            tag, remedy = "never_stored", "that version was never stored, so pecia cannot establish its survival"
        elif bad:
            tag, remedy = "unrecoverable", bad
        else:
            tag = "version:" + json.dumps(version)
            remedy = (f"recover inspect {name} opens its stored bytes for comparison, to take from by hand"
                      if version[0] == "artifact" else
                      f"git show {shlex.quote(s['commit'] + ':' + path)} shows that version, to take from by hand")
        ack = f"{s['ref']}\x1f{k}\x1f{tag}"
        if ack in acked:
            continue
        why = (f"snapshot {name} holds work from {s['agent']} replaced by a different agent; {remedy}; "
               "newer work stays as it is; recover ack, run by you outside an agent session, ends this report")
        if k in out:
            e = out[k]
            e.setdefault("also_snapshots", []).append(s["ref"])
            e.setdefault("ack_also", []).append(ack)
            if len(e["also_snapshots"]) <= 3:
                e["why"] += "; " + why
        else:
            out[k] = {"path": path, "category": "agent_replaced", "snapshot": s["ref"],
                      "ack": ack, "why": why, "beside": True}
    return list(out.values())


def _item_version(item: dict, commit: str) -> list | None:
    """Which version of a file a plan item restores, so two snapshots that hold the same one can be told apart from two
    that do not: a stored copy by its SHA-256, a file of a snapshot's tree by its blob and where to check it out."""
    if item.get("source") == "artifact" and item.get("sha256"):
        return ["artifact", item["sha256"]]
    if item.get("source") == "git" and item.get("oid"):
        return ["git", item["oid"], f"{commit}:{item['path']}"]
    return None


def _same_version(repo: Repo, a, b) -> bool:
    """Whether two versions are the same bytes, whichever kind holds each: one content may be stored as an artifact by
    one snapshot and kept in another's tree (R24-38)."""
    if not a or not b:
        return False
    if a[0] == b[0]:
        return a[1] == b[1]
    git_v, art = (a, b) if a[0] == "git" else (b, a)
    memo = _MEMO.setdefault("version_sha", {}) if _MEMO is not None else {}
    if git_v[2] not in memo:
        try:
            memo[git_v[2]] = hashlib.sha256(_checkout_bytes(repo, git_v[2])).hexdigest()
        except (GitError, OSError):
            memo[git_v[2]] = None
    return memo[git_v[2]] == art[1]


_LOCAL_COMMIT = re.compile(r"^commit(?: \((initial|amend)\))?:(?: |$)")
# A merge commit made here: git commit concluding a merge, or git merge or git pull making one. A merge is a history
# move, but its own version of a file (a hand resolution, or both sides' changes joined) is the user's work (R24-75).
_MERGE_MADE = re.compile(r"^(?:commit \(merge\): |(?:merge|pull)\b[^:]*: Merge made by )")
_CHECKOUT_MOVE = re.compile(r"^checkout: moving from (.*) to (.*)$")
# Commits made here whose versions come partly from elsewhere: a cherry-pick or a rebase step ended after a conflict,
# and git am, which records a resolution the same as a clean patch. Like a merge, each is a history move, never settles a
# file, and is named when dropped (R24-102, R24-119).
_FOREIGN_MADE = re.compile(r"^(?:commit \(cherry-pick\): |[^:()]*\(continue\): |am: )")
# git revert ended after a conflict records a plain commit entry; its message says what it reverts (R24-94).
_REVERT_LINE = re.compile(r"(?m)^This reverts commit [0-9a-f]{7,64}")
# Entries whose commit replays another, keeping its author, date and message: a rebase step under whatever command ran
# it (git rebase, git pull --rebase, git pull with pull.rebase set, or a tool's own action name), a cherry-pick, git am
# (R24-138, R24-150).
_REPLAY = re.compile(r"^(?:[^:()]*\((?:pick|reword|edit|squash|fixup|continue)\)|cherry-pick|commit \(cherry-pick\)|am): ")
_ACK_ROOT = "refs/pecia/acks"
# The message of the entry pecia writes to start HEAD's reflog where it holds none (RP-13, register row 223). The entry
# moves nothing, and _moves counts it as no move, so a snapshot taken before it is not placed before a move by it.
_SEED_SUBJECT = "pecia: HEAD's reflog started here; this entry moves nothing"


def _ref_format(repo: Repo) -> str:
    """files or reftable. A reftable repository keeps no logs/HEAD file and a stub HEAD (R24-120); git before 2.45, which
    cannot report the format, has only files."""
    if getattr(repo, "_ref_format", None) is None:
        r = run_git(repo.root, ["rev-parse", "--show-ref-format"], check=False)
        out = r.stdout.decode("ascii", "replace").strip() if r.returncode == 0 else ""
        repo._ref_format = out if out in ("files", "reftable") else "files"
    return repo._ref_format


def _head_log_to_seed(repo: Repo):
    """(HEAD's commit, the path of HEAD's log, or None in a reftable repository) where HEAD is born and its reflog holds
    no entry: no log, as where core.logAllRefUpdates is false, or an empty one, as after every entry expired. None
    otherwise, and where anything but a regular file is at that path or its folder is a link: pecia never writes
    through a link (RP-13)."""
    if _ref_format(repo) == "reftable":
        try:
            head = repo.head()
            return (head, None) if head and not _head_reflog(repo) else None
        except PeciaError:
            return None
    log = repo.git_dir() / "logs" / "HEAD"
    try:
        if _is_link(log.parent):
            return None
        st = os.lstat(log)
        if not stat_mod.S_ISREG(st.st_mode) or st.st_size:
            return None
    except FileNotFoundError:
        pass
    except OSError:
        return None
    head = repo.head()
    return (head, log) if head else None


def _seed_head_log(repo: Repo, need=None) -> bool:
    """Start HEAD's reflog where it holds no entry (_head_log_to_seed) with one entry that moves nothing, its old and new
    commit both HEAD's, and leave core.logAllRefUpdates as it is: git appends to an existing HEAD log whatever that
    setting says, so from then on HEAD's moves are recorded, every snapshot records its place among them, and a version
    a round trip or a dropped commit discarded is reported as with reflogs on (option c of the R24-63 assessment,
    register row 223). With HEAD on a branch git writes the entry, given the old value too, so nothing can move; git
    writes no entry for a detached HEAD that does not change, so there pecia creates the log itself, only where none
    exists, from the held git directory. Returns whether HEAD's log was started. Never raises."""
    ok, why = False, ""
    try:
        need = need if need is not None else _head_log_to_seed(repo)
        if not need:
            return False
        head, log = need
        if repo.branch() is not None:
            r = run_git(repo.root, ["-c", "core.logAllRefUpdates=always", "update-ref", "-m", _SEED_SUBJECT, "HEAD",
                                    head, head], check=False)
            ok, why = r.returncode == 0, r.stderr.decode("utf-8", "replace").strip()
        elif log is not None and not os.path.lexists(log):
            line = f"{head} {head} pecia <pecia@localhost> {int(time.time())} +0000\t{_SEED_SUBJECT}\n".encode()
            with _HeldDir(repo.git_dir(), ["logs"], create=True) as d:
                fd, tmp = d.new_temp(".pecia-tmp-")
                try:
                    with os.fdopen(fd, "wb") as f:
                        f.write(line)
                        f.flush()
                        os.fsync(f.fileno())
                        d.set_mode(f.fileno(), tmp, 0o644)
                    d.link_no_clobber(tmp, log.name)
                except BaseException:
                    d.unlink_quietly(tmp)
                    raise
            ok = True
        else:
            return False  # detached in a reftable repository, or an empty log: git writes no such entry there
    except (OSError, PeciaError) as e:
        why = str(e)
    if _MEMO is not None:
        _MEMO.pop("head_reflog", None)
    try:
        if ok:
            repo.log_event("head_reflog_started", head=need[0])
        else:
            repo.log_event("head_reflog_not_started", error=why[:500])
    except Exception:  # noqa: BLE001 - the event log never stops a snapshot
        pass
    return ok


def _head_reflog(repo: Repo):
    """HEAD's reflog in this worktree, newest first: [{oid, time, subject, parents, revert}], or None where git keeps
    none. Read once per search. revert is filled in by _mark_reverts, which reads commit messages."""
    memo = _MEMO.setdefault("head_reflog", {}) if _MEMO is not None else {}
    k = str(repo.root)
    if k not in memo:
        rows = None
        if _ref_format(repo) == "reftable":
            present = run_git(repo.root, ["reflog", "exists", "HEAD"], check=False).returncode == 0
            log = None
        else:
            log = repo.git_dir() / "logs" / "HEAD"
            try:
                with open(log, "rb"):
                    present = True
            except FileNotFoundError:
                present = False  # git log -g would read the branch's log instead, which records no checkout (R24-107)
            except OSError as e:
                raise PeciaError(f"HEAD's reflog, {fwd(log)}, cannot be read ({e.strerror or e}); it tells which "
                                 "snapshots were taken since history last moved, so make it readable to this account")
        if present and repo.head():
            r = run_git(repo.root, ["-c", "log.showSignature=false", "log", "-g", "--format=%H%x00%gd%x00%gs%x00%P",
                                    "--date=unix", "HEAD"], check=False)
            if r.returncode != 0 and (log is None or log.stat().st_size):
                raise PeciaError("git could not read HEAD's reflog: "
                                 + (r.stderr.decode("utf-8", "replace").strip() or f"exit status {r.returncode}"))
            rows = []
            for line in r.stdout.decode("utf-8", "replace").splitlines():
                f = line.split("\0")
                if len(f) != 4 or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", f[0]):
                    continue
                m = re.search(r"@\{(\d+)\}$", f[1])
                rows.append({"oid": f[0], "time": int(m.group(1)) if m else 0, "subject": f[2],
                             "parents": f[3].split(), "revert": False})
            rows = rows or None
        memo[k] = rows
    return memo[k]


def _mark_reverts(repo: Repo, rows, upto: int | None = None) -> None:
    """Mark the plain commit entries among rows[:upto] whose message carries git revert's line (R24-94): one git call for
    their messages, made only where moves are classified, never for a snapshot's place (R24-117)."""
    if not rows:
        return
    want = sorted({e["oid"] for e in rows[:upto] if e["subject"].startswith("commit: ") and "revert_read" not in e})
    if want:
        b = run_git(repo.root, ["-c", "log.showSignature=false", "log", "--no-walk=unsorted", "--stdin",
                                "--format=%x00%H%x00%B"], check=False,
                    input_bytes="".join(f"{o}\n" for o in want).encode())
        parts = b.stdout.decode("utf-8", "replace").split("\0") if b.returncode == 0 else []
        reverts = {parts[i].strip() for i in range(1, len(parts) - 1, 2) if _REVERT_LINE.search(parts[i + 1])}
        wanted = set(want)
        for e in rows[:upto]:
            if e["oid"] in wanted and e["subject"].startswith("commit: "):
                e["revert"] = e["oid"] in reverts
                e["revert_read"] = True


def _subject_tag(subject: str) -> str:
    return hashlib.sha256(subject.encode("utf-8", "replace")).hexdigest()[:12]


def _reflog_mark(repo: Repo, seen: list | None = None) -> str:
    """Where HEAD's reflog stands as a snapshot is taken: its length and its newest entry, so a later search can tell
    which entries came after the snapshot without comparing clocks (R24-87). A reflog pecia cannot read gives none, which
    places the snapshot before every move the reflog holds (R24-107, R24-108). With seen, the entries read, or the error,
    are put there, so the snapshot reads the reflog once (R24-117)."""
    try:
        entries = _head_reflog(repo)
    except PeciaError as e:
        if seen is not None:
            seen[:] = [e]
        return "none"
    if seen is not None:
        seen[:] = [entries]
    if not entries:
        return "none"
    e = entries[0]
    return f"{len(entries)} {e['oid']} {e['time']} {_subject_tag(e['subject'])}"


def _ack_mark(repo: Repo) -> str:
    """Where HEAD's reflog stands as recover ack records an acknowledgement: _reflog_mark's length and newest entry, and
    the entry before that one, so that a later search tells that entry apart from an identical one in the same second,
    as two quick tries on a throwaway branch make (R24-213)."""
    seen: list = []
    mark = _reflog_mark(repo, seen)
    entries = seen[0] if seen and isinstance(seen[0], list) else []
    if mark == "none":
        return mark
    if len(entries) > 1:
        e = entries[1]
        return f"{mark} {e['oid']} {e['time']} {_subject_tag(e['subject'])}"
    return f"{mark} - 0 -"


def _ack_mark_index(entries: list, mark: str):
    """The index in entries of the entry an acknowledgement recorded, or None when it is gone. Of identical entries the
    one followed by the entry recorded with it is taken: the one at the recorded length where that is one, else the
    oldest; without such a match, as after expiry, the oldest identical entry, so that more entries count as later,
    never fewer (S2 of the seventeenth review, R24-213). A mark of four fields, as before this, is read as a snapshot's
    with the oldest match."""
    f = mark.split()
    if len(f) != 7:
        return _mark_index(entries, mark, oldest=True)
    try:
        n, t, ct = int(f[0]), int(f[2]), int(f[5])
    except ValueError:
        return None

    def match(e, oid, t_, tag):
        return e["oid"] == oid and e["time"] == t_ and _subject_tag(e["subject"]) == tag
    found = [j for j, e in enumerate(entries) if match(e, f[1], t, f[3])]
    if not found:
        return None
    good = [j for j in found if (j + 1 == len(entries) if f[4] == "-" else
                                 j + 1 < len(entries) and match(entries[j + 1], f[4], ct, f[6]))]
    i0 = len(entries) - n
    return i0 if i0 in good else max(good) if good else max(found)


def _mark_index(entries: list, mark: str, oldest: bool = False):
    """The index in entries (newest first) of the newest entry when the snapshot was taken, or None when it is not
    there any more. Where expiry shortened the reflog and the same entry appears more than once, the oldest match is
    taken, so that more entries count as later, never fewer. With oldest, the oldest match even where the entry at the
    recorded length matches, as an acknowledgement's end needs: after expiry an identical entry there, in the same
    second, can be a newer one (S2 of the seventeenth review); a snapshot is placed at the recorded length, since
    switching branches at one commit within a second makes such entries without any expiry."""
    try:
        n, oid, t, tag = mark.split()
        n, t = int(n), int(t)
    except ValueError:
        return None

    def match(e):
        return e["oid"] == oid and e["time"] == t and _subject_tag(e["subject"]) == tag
    memo = _MEMO.setdefault("mark_index", {}) if _MEMO is not None else {}
    mk = (id(entries), len(entries), mark, oldest)
    if mk in memo and memo[mk][0] is entries:
        return memo[mk][1]
    i = len(entries) - n
    if 0 <= i < len(entries) and match(entries[i]) and not (oldest and any(match(e) for e in entries[i + 1:])):
        found = i
    else:
        # The oldest match, even where an entry at the recorded length matches: after expiry an identical entry
        # there can be a newer one (S2 of the seventeenth review).
        found = max((j for j, e in enumerate(entries) if match(e)), default=None)
    memo[mk] = (entries, found)
    return found


def _moves(entries: list) -> list:
    """For each reflog entry, whether it moved history: anything but a commit made here on top of HEAD, or git reset to
    HEAD itself (by name, or by its commit ID as an aborted cherry-pick does) or a checkout of the branch already checked
    out, which leave HEAD where it was (R24-87). Judged by the
    entry's own words and the entry before it; where expiry removed entries between, a commit no longer sits on the
    entry before it and counts as a move, never the reverse (seventh internal review, git reflog expire). A revert ended
    after a conflict, which git records as a plain commit, is a move, as one without a conflict is (R24-94)."""
    out = []
    for i, e in enumerate(entries):
        old = entries[i + 1]["oid"] if i + 1 < len(entries) else None
        if e["subject"] == _SEED_SUBJECT and (old is None or e["oid"] == old):
            # The entry pecia wrote to start HEAD's reflog, which moves nothing (RP-13): a snapshot taken before it, with
            # no place, is not placed before a move by it.
            out.append(False)
            continue
        m = _LOCAL_COMMIT.match(e["subject"])
        if (m and m.group(1) != "amend" and not e.get("revert")
                and (e["parents"][:1] == [old] if old else not e["parents"] or i + 1 == len(entries))):
            out.append(False)
            continue
        c = _CHECKOUT_MOVE.match(e["subject"])
        # git cherry-pick --abort and git revert --abort reset to HEAD by its commit ID.
        r = re.match(r"reset: moving to ([0-9a-f]{40}|[0-9a-f]{64})$", e["subject"])
        noop = (e["subject"] == "reset: moving to HEAD" or bool(c and c.group(1) == c.group(2))
                or bool(r and r.group(1) == e["oid"]))
        out.append(not (noop and old is not None and e["oid"] == old))
    return out


def _moved_since(repo: Repo, snap: dict, seen: list | None = None) -> bool:
    """Whether history moved after the snapshot was taken: then the same tree on the same commit gets a snapshot of its
    own, since latest never restores across the move (R24-87). Without a reflog, pecia cannot tell, and says no; with one
    it cannot read, yes. seen holds the reflog as _reflog_mark read it for this snapshot, when it did."""
    try:
        if seen:
            if isinstance(seen[0], PeciaError):
                raise seen[0]
            entries = seen[0]
        else:
            entries = _head_reflog(repo)
    except PeciaError:
        return True
    mark = snap.get("reflog")
    if not entries or not mark or mark == "none":
        # Taken with no reflog, or before pecia recorded its place in it: when entries exist now, history may have moved
        # since (R24-104).
        return bool(entries)
    a = _mark_index(entries, mark)
    if a is None:
        return True
    _mark_reverts(repo, entries, a)  # only the entries newer than the place are classified, so only theirs are read
    moved = _moves(entries[:a + 1])
    return any(moved[:a])


def _ack_record(repo: Repo) -> dict:
    """What recover ack acknowledged in this worktree, kept in a blob that refs/pecia/acks/WORKTREE names: {acked: the
    reports, by snapshot, file and version or commit (R24-110), at: {report: where HEAD's reflog stood when it was
    acknowledged} (R24-181)}."""
    wid = repo.worktree_id(create=False)
    if wid is None:
        return {}
    r = run_git(repo.root, ["cat-file", "blob", f"{_ACK_ROOT}/{wid}"], check=False)
    if r.returncode != 0:
        return {}
    try:
        data = json.loads(r.stdout.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise PeciaError(f"the record of what recover ack acknowledged, {_ACK_ROOT}/{wid}, cannot be read; delete it "
                         "with git update-ref -d, and every report is shown again")
    return data if isinstance(data, dict) else {}


def _acked_keys(repo: Repo) -> set:
    """The reports recover ack acknowledged in this worktree."""
    return {str(x) for x in _ack_record(repo).get("acked", [])}


def _ack_marks(repo: Repo) -> dict:
    """{report: where HEAD's reflog stood when recover ack acknowledged it}; a report acknowledged by 0.1.2rc14 drafts
    before this record has none."""
    at = _ack_record(repo).get("at")
    return {str(k): str(v) for k, v in at.items() if isinstance(v, str)} if isinstance(at, dict) else {}


_LATER_ROOT = "refs/pecia/later"


def _later_named(repo: Repo):
    """The snapshots an INCOMPLETE recovery in this worktree named under later_recovery, which retention keeps until a
    recovery completes, as it keeps the record of a loss (X-03): the next recover apply latest restores from them what
    the first promised (XA1-09). Kept in a blob that refs/pecia/later/WORKTREE names: {"snapshots": [ref, ...]}. Returns
    the set of refs, empty without a record, or None when the record exists and cannot be read."""
    wid = repo.worktree_id(create=False)
    if wid is None:
        return set()
    r = run_git(repo.root, ["cat-file", "--batch"], input_bytes=f"{_LATER_ROOT}/{wid}\n".encode(), check=False)
    head, _, body = r.stdout.partition(b"\n")
    if r.returncode == 0 and head.endswith(b" missing"):
        return set()
    try:
        if r.returncode != 0 or head.split(b" ")[1] != b"blob":
            return None
        data = json.loads(body[:int(head.split(b" ")[2])].decode("utf-8"))
        refs = data.get("snapshots") if isinstance(data, dict) else None
        return {str(x) for x in refs} if isinstance(refs, list) else None
    except (IndexError, ValueError, UnicodeDecodeError):
        return None


def _note_later_recovery(repo: Repo, report: dict, latest: bool, all_paths: bool) -> str | None:
    """After a recovery (never a dry run): add the snapshots its later_recovery entries name to the record retention
    keeps, or end the record when a recover apply latest over every path is complete, which leaves nothing for a further
    recovery (XA1-09). Returns a note for the report when the record cannot be written."""
    wid = repo.worktree_id(create=False)
    named = {u["snapshot"] for u in report.get("later_recovery") or [] if u.get("snapshot")}
    ref = f"{_LATER_ROOT}/{wid}"
    if wid is None or (not named and not (latest and all_paths and report.get("result") == "complete")):
        return None
    if not named:
        if run_git(repo.root, ["update-ref", "-d", ref], check=False).returncode != 0:
            repo.log_event("later_record_failed", action="end")
        return None
    have = _later_named(repo) or set()
    refs = {r_[0] for r_ in _snapshot_refs(repo, f"{REF_ROOT}/{wid}/")}
    keep = sorted(r_ for r_ in have | named if r_ in refs)
    blob = run_git(repo.root, ["hash-object", "-w", "--stdin"],
                   input_bytes=json.dumps({"snapshots": keep}, indent=1).encode(), check=False)
    oid = blob.stdout.decode("ascii", "replace").strip()
    if blob.returncode == 0 and oid and run_git(repo.root, ["update-ref", ref, oid], check=False).returncode == 0:
        return None
    repo.log_event("later_record_failed", action="add", snapshots=keep[:200])
    return ("pecia could not record the snapshots named under later_recovery, so retention may remove them before the "
            "next recovery: run recover apply latest again soon, or the command each entry gives")


_START_ROOT = "refs/pecia/start"


def _start_info(repo: Repo) -> tuple:
    """What pecia recorded when its first snapshot here was taken, in a blob that refs/pecia/start/WORKTREE names:
    (place, bases). place is where HEAD's reflog stood then, none when none could be recorded, or None without a
    record; the commits made here since then are searched for dropped ones, whatever retention has removed (R24-137).
    bases are HEAD and every local branch then: the work there that no branch holds any more is searched too, as the
    commits a first snapshot was taken on (R24-146)."""
    wid = repo.worktree_id(create=False)
    if wid is None:
        return None, []
    r = run_git(repo.root, ["cat-file", "blob", f"{_START_ROOT}/{wid}"], check=False)
    if r.returncode != 0:
        return None, []
    try:
        data = json.loads(r.stdout.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return "none", []  # unreadable: the whole reflog is searched, the louder way
    if not isinstance(data, dict):
        return "none", []
    m = data.get("reflog")
    bases = [b for b in data.get("bases") or [] if isinstance(b, str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", b)]
    return (m if isinstance(m, str) and m else "none"), bases


def _start_mark(repo: Repo):
    return _start_info(repo)[0]


def _record_start(repo: Repo, mark: str, bases: list) -> None:
    wid = repo.worktree_id(create=False)
    if not wid:
        return
    blob = run_git(repo.root, ["hash-object", "-w", "--stdin"], check=False,
                   input_bytes=json.dumps({"reflog": mark, "bases": list(dict.fromkeys(b for b in bases if b))[:5000],
                                           "recorded": iso()}).encode())
    if blob.returncode == 0:
        # Created only where none exists, so a record already made stays.
        run_git(repo.root, ["update-ref", f"{_START_ROOT}/{wid}", blob.stdout.decode().strip(), ""], check=False)


def _stashes(repo: Repo) -> list:
    """Every stash entry, newest first: [(commit, parents)], from the stash's reflog (R24-115), and refs/stash itself
    when its reflog holds no entry, as after the entries expired (R24-101)."""
    memo = _MEMO.setdefault("stashes", {}) if _MEMO is not None else {}
    k = str(repo.root)
    if k not in memo:
        out = []
        if run_git(repo.root, ["rev-parse", "-q", "--verify", "refs/stash"], check=False).returncode == 0:
            r = run_git(repo.root, ["log", "-g", "--format=%H %P", "refs/stash"], check=False)
            for line in r.stdout.decode("ascii", "replace").splitlines() if r.returncode == 0 else []:
                f = line.split()
                if f:
                    out.append((f[0], f[1:]))
            if not out:
                r = run_git(repo.root, ["rev-list", "--parents", "-n1", "refs/stash"], check=False)
                f = r.stdout.decode("ascii", "replace").split() if r.returncode == 0 else []
                if f:
                    out.append((f[0], f[1:]))
        memo[k] = out
    return memo[k]


def _held_refs(repo: Repo) -> list:
    """The revisions whose history holds a commit: branches, tags, remote branches, HEAD, every other worktree's HEAD
    (S3 of the thirteenth review) and every stash entry."""
    return ["--branches", "--tags", "--remotes", "HEAD"] + _other_heads(repo) + [w for w, _p in _stashes(repo)]


def _other_heads(repo: Repo) -> list:
    """The commits the repository's other worktrees have checked out, which hold their history as a branch does. Not a
    snapshot's own commit, as recover inspect checks one out: its parent, the snapshot's base, is held by nothing the
    user made (R24-173)."""
    memo = _MEMO.setdefault("other_heads", {}) if _MEMO is not None else {}
    k = str(repo.root)
    if k not in memo:
        r = run_git(repo.root, ["worktree", "list", "--porcelain"], check=False)
        heads, where = [], ""
        for ln in r.stdout.decode("utf-8", "replace").splitlines() if r.returncode == 0 else []:
            if ln.startswith("worktree "):
                where = ln[len("worktree "):]
            elif ln.startswith("HEAD ") and len(ln.split()) == 2:
                # Not an inspection pecia made, under any worktree's runtime folder, whose snapshot retention may since
                # have removed (S2 of the fifteenth review).
                if f"/{RUNTIME_REL}/recover/" not in where.replace("\\", "/") + "/":
                    heads.append(ln.split()[1])
        mine = repo.head()  # use this search's existing HEAD value (R24-116, reftable call bound)
        heads = [h for h in dict.fromkeys(heads) if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", h) and h != mine]
        if heads:
            s_ = run_git(repo.root, ["for-each-ref", "--format=%(objectname)", "refs/pecia/"], check=False)
            snaps = set(s_.stdout.decode("ascii", "replace").split()) if s_.returncode == 0 else set()
            heads = [h for h in heads if h not in snaps]
        memo[k] = heads
    return memo[k]


def _history_blobs(repo: Repo, bases: list) -> set:
    """The file versions commits on branches, tags, remote branches, every stash entry, HEAD and every other worktree's
    HEAD wrote since the given bases: a version among them is in history. Bounded at 5,000 commits; a version beyond is
    not found, and so is reported."""
    memo = _MEMO.setdefault("history_blobs", {}) if _MEMO is not None else {}
    k = tuple(sorted(set(bases)))
    if k in memo:
        return memo[k]
    r = run_git(repo.root, ["-c", "log.showSignature=false", "log", "-z", "--raw", "--no-renames", "--no-abbrev",
                            "--format=%x00", "-n5000", "--branches", "--tags", "--remotes", "HEAD", *_other_heads(repo),
                            "--stdin"],
                check=False, input_bytes="".join(f"^{b}\n" for b in k).encode())
    outs = [r.stdout if r.returncode == 0 else b""]
    # Every stash entry: its working-tree commit is a merge, which git log does not diff, so its working-tree, index and
    # untracked-files commits are each read against what they were made on (R24-101, R24-115).
    pairs, roots = [], []
    for w, parents in _stashes(repo):
        if parents:
            pairs.append(f"{w} {parents[0]}")
            if len(parents) > 1:
                pairs.append(f"{parents[1]} {parents[0]}")
            if len(parents) > 2:
                roots.append(parents[2])
    if pairs:
        d = run_git(repo.root, ["diff-tree", "-r", "-z", "--raw", "--no-renames", "--no-abbrev", "--stdin"], check=False,
                    input_bytes="".join(f"{x}\n" for x in pairs).encode())
        outs.append(d.stdout if d.returncode == 0 else b"")
    if roots:
        d = run_git(repo.root, ["diff-tree", "-r", "-z", "--raw", "--root", "--no-renames", "--no-abbrev", "--stdin"],
                    check=False, input_bytes="".join(f"{x}\n" for x in roots).encode())
        outs.append(d.stdout if d.returncode == 0 else b"")
    blobs = set()
    for tok in b"\0".join(outs).split(b"\0"):
        t = tok.decode("utf-8", "replace").strip("\n")
        if t.startswith(":"):
            meta = t[1:].split(" ")
            if len(meta) >= 5:
                blobs.add(meta[3])
    memo[k] = blobs
    return blobs


def _stdin_names(out: bytes, ids: list, key, aliases=None) -> dict:
    """{id: {path key: path}} from git diff-tree --name-only -z --stdin, where each id's paths follow it in input order and an
    id with no difference prints nothing. Not z_split, which drops a path met again under the next id."""
    names: dict = {i: {} for i in ids}
    at, cur = 0, None
    for raw in out.split(b"\0"):
        t = raw.decode("utf-8", "surrogateescape").strip("\n")
        nxt = next((j for j in range(at, len(ids)) if ids[j] == t), None)
        if nxt is not None:
            cur, at = ids[nxt], nxt + 1
        elif cur is not None and t:
            names[cur][key(t)] = t
            if aliases is not None:
                aliases.setdefault(cur, {}).setdefault(key(t), set()).add(t)
    return names


def _local_commits(repo: Repo, entries: list, upto: int, kept_upto: int | None = None) -> list:
    """The commits made here that HEAD's reflog records among its newest upto entries, newest first, each {index, oid,
    time, merge, foreign, replay, parent, files, names, kept}. A commit, an amend and a first commit (commit, commit
    (amend), commit (initial)) may settle a file, and so may a clean replay of one, a rebase step, a cherry-pick (replay);
    a merge, a revert, and a cherry-pick, rebase step or git am ended after a conflict (foreign) never do, since their
    versions came partly from elsewhere, and are named when dropped (R24-75, R24-94, R24-102, R24-119, R24-150). files and
    names: the path keys the commit itself changed, against its first parent, or for a merge those it left different from
    every parent; for an amend, or a first commit that replaced another HEAD, only those that also differ from the HEAD it
    replaced, so an amend that takes a file's change out of the last commit changed nothing of that file (R24-91).
    amended: the commit an amend replaced (R24-124; only an amend, S1 of the twelfth review). kept: whether a branch,
    tag, remote branch, a stash entry or HEAD still holds it. A kept commit's files are read only among the newest
    kept_upto entries, and newer than the oldest commit history no longer holds, where they can settle a file; without
    kept_upto, all are read."""
    memo = _MEMO.setdefault("local_commits", {}) if _MEMO is not None else {}
    k = (str(repo.root), upto, kept_upto)
    if k in memo:
        return memo[k]
    out = []
    for i, e in enumerate((entries or [])[:upto]):
        merge = len(e["parents"]) > 1 and bool(_MERGE_MADE.match(e["subject"]))
        foreign = merge or bool(_FOREIGN_MADE.match(e["subject"])) or bool(e.get("revert"))
        local = _LOCAL_COMMIT.match(e["subject"])
        replay = not local and bool(_REPLAY.match(e["subject"]))
        if not foreign and not local and not replay:
            continue
        old = entries[i + 1]["oid"] if i + 1 < len(entries) else None
        c = {"index": i, "oid": e["oid"], "time": e["time"], "files": None, "names": None, "merge": merge,
             "foreign": foreign, "replay": replay, "parent": e["parents"][0] if e["parents"] else None}
        if local and not merge and old and e["parents"][:1] != [old]:
            c["replaced"] = old  # the HEAD an amend, or a first commit, replaced (R24-124)
            if local.group(1) == "amend":
                c["amended"] = old
        elif replay and old and i + 1 < len(entries) and e["parents"][:1] == entries[i + 1]["parents"][:1]:
            # A rebase step made in place of the commit before it, on the same parent, as a fixup or squash is: it
            # replaces that commit as an amend does (R24-150).
            c["amended"] = old
        out.append(c)
    if out:
        r = run_git(repo.root, ["rev-list", "--stdin", "--not", *_held_refs(repo)], check=False,
                    input_bytes="".join(f"{c['oid']}\n" for c in out).encode())
        gone = set(r.stdout.decode("ascii", "replace").split()) if r.returncode == 0 else {c["oid"] for c in out}
        for c in out:
            c["kept"] = c["oid"] not in gone
    need = len(entries or []) if kept_upto is None else max(
        [kept_upto] + [c["index"] + 1 for c in out if not c["kept"]])
    _commit_names(repo, [c for c in out if not c["kept"] or c["index"] < need])
    memo[k] = out
    return out


def _line_commits(repo: Repo, tips: list, known: set, start: int) -> tuple:
    """The commits under the given tips that history no longer holds and HEAD's reflog does not record among the
    commits searched, as commits made before pecia's first snapshot here, or by another worktree, under a commit a
    snapshot was taken on (R24-146): ([{index, oid, merge, foreign, line, parent, files, names, kept}], {commit: parents}
    for every commit history no longer holds under them, the commits searched too, for telling ancestry apart, whether
    that bound cut the walk short, and the tips whose history git cannot read). Bounded at 5,000 commits; a tip git no
    longer has is passed over, and one whose history cannot be read is returned to be reported (R24-162)."""
    tips = list(dict.fromkeys(t for t in tips if t))
    memo = _MEMO.setdefault("line_commits", {}) if _MEMO is not None else {}
    mk = (str(repo.root), tuple(sorted(tips)), tuple(sorted(known)), start)
    if mk in memo:
        return memo[mk]
    rows: list = []
    unreadable: list = []
    args = ["rev-list", "--parents", "--topo-order", "-n", "5000", "--stdin", "--not", *_held_refs(repo)]
    if tips:
        r = run_git(repo.root, args, check=False, input_bytes="".join(f"{t}\n" for t in tips).encode())
        if r.returncode != 0:
            # One tip whose objects git removed fails the whole call: those are passed over, in one call, and the rest
            # read again together (S4 of the fourteenth review).
            chk = run_git(repo.root, ["cat-file", "--batch-check=%(objecttype)"], check=False,
                          input_bytes="".join(f"{t}\n" for t in tips).encode())
            kinds = chk.stdout.decode("ascii", "replace").splitlines() if chk.returncode == 0 else []
            if len(kinds) == len(tips):
                tips = [t for t, kind in zip(tips, kinds) if kind.strip() == "commit"]
                r = run_git(repo.root, args, check=False, input_bytes="".join(f"{t}\n" for t in tips).encode())
        if r.returncode == 0:
            rows = [ln.split() for ln in r.stdout.decode("ascii", "replace").splitlines() if ln.strip()]
        else:
            # One whose history lacks an object fails it still: each tip is read on its own; one git no longer has is
            # passed over, one whose history cannot be read is reported.
            seen_: set = set()
            for t in tips:
                if run_git(repo.root, ["cat-file", "-e", f"{t}^{{commit}}"], check=False).returncode != 0:
                    continue
                r1 = run_git(repo.root, args, check=False, input_bytes=f"{t}\n".encode())
                if r1.returncode != 0:
                    unreadable.append(t)
                    continue
                for ln in r1.stdout.decode("ascii", "replace").splitlines():
                    f = ln.split()
                    if f and f[0] not in seen_ and len(seen_) < 5000:
                        seen_.add(f[0])
                        rows.append(f)
    graph = {f[0]: f[1:] for f in rows}
    # A commit the shallow file lists, which git shows with no parent, is a shallow clone's boundary: it was fetched,
    # so the history it stands on is the remote's, also where it was made here and pushed (R24-225), and once a fetch
    # moves the boundary it is in no ref here (R24-218). Only one the shallow file lists: a graft or a replacement
    # shows a commit made here with no parent too (R24-223).
    shallow_ = _shallow_commits(repo) if any(len(f) == 1 for f in rows) else set()
    bounds = {f[0] for f in rows if len(f) == 1 and f[0] not in known and f[0] in shallow_}
    out = []
    for j, f in enumerate(rows):
        if f[0] in known or f[0] in bounds:
            continue
        merge = len(f) > 2
        out.append({"index": start + j, "oid": f[0], "time": None, "files": None, "names": None, "merge": merge,
                    "foreign": merge, "replay": False, "line": True, "parent": f[1] if len(f) > 1 else None,
                    "kept": False})
    _commit_names(repo, out)
    memo[mk] = (out, graph, len(rows) >= 5000, unreadable)
    return memo[mk]


def _shallow_commits(repo: Repo) -> set:
    """The commits the repository's shallow file lists, the boundaries of a shallow clone; empty for a full one."""
    memo = _MEMO.setdefault("shallow", {}) if _MEMO is not None else {}
    k = str(repo.root)
    if k not in memo:
        r = run_git(repo.root, ["rev-parse", "--git-path", "shallow"], check=False)
        out: set = set()
        if r.returncode == 0 and r.stdout.strip():
            p = Path(os.fsdecode(r.stdout.rstrip(b"\r\n")))
            try:
                data = (p if p.is_absolute() else repo.root / p).read_bytes()
                out = {x for x in data.decode("ascii", "replace").split()
                       if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", x)}
            except OSError:
                pass
        memo[k] = out
    return memo[k]


def _tree_paths(repo: Repo, commit: str, paths: list) -> bytes | None:
    """Read named tree entries in bounded calls, including both sides of a large case rename (R24-239).
    A failed chunk invalidates the whole lookup, so a partial list cannot be mistaken for deleted files."""
    batches, batch, size = [], [], 0
    for path in paths:
        # Count the Windows quoting and UTF-16 units, leaving ample room for git's program and fixed arguments.
        cost = len(subprocess.list2cmdline([path]).encode("utf-16-le", "surrogatepass")) // 2 + 1
        if batch and size + cost > 12000:
            batches.append(batch)
            batch, size = [], 0
        batch.append(path)
        size += cost
    if batch:
        batches.append(batch)
    output = []
    for names in batches:
        try:
            r = run_git(repo.root, ["ls-tree", "-z", commit, "--", *names], check=False)
        except OSError:
            return None
        if r.returncode != 0:
            return None
        output.append(r.stdout)
    return b"".join(output)


def _commit_names(repo: Repo, todo: list) -> None:
    """Fill in each commit's files and names, as _local_commits describes them."""
    key = _path_key(repo)
    aliases: dict = {}
    plain, replaced = [], []
    for c in todo:
        if c["merge"]:
            # The files the merge left different from every parent: its own versions. A dropped merge is named for
            # them; one history holds settles nothing, since a merge brings in versions the snapshot never saw (R24-77).
            r = run_git(repo.root, ["diff-tree", "-r", "-c", "--no-commit-id", "--name-only", "-z", c["oid"]],
                        check=False)
            if r.returncode == 0:
                c["names"] = {key(p): p for p in z_split(r.stdout)}
                for p in z_split(r.stdout):
                    aliases.setdefault(c["oid"], {}).setdefault(key(p), set()).add(p)
                c["files"] = set(c["names"])
        elif c.get("replaced"):
            replaced.append((c, c["replaced"]))
        else:
            plain.append(c)
    if replaced:
        # Against the HEAD it replaced, and against its own first parent (the empty tree for a first commit), in one git
        # call each; the commit changed a file of its own only where both differ.
        ids = [c["oid"] for c, _old in replaced]
        r1 = run_git(repo.root, ["diff-tree", "-r", "--no-renames", "--name-only", "-z", "--stdin"], check=False,
                     input_bytes="".join(f"{c['oid']} {old}\n" for c, old in replaced).encode())
        r2 = run_git(repo.root, ["diff-tree", "-r", "--root", "--no-renames", "--name-only", "-z", "--stdin"],
                     check=False, input_bytes="".join(f"{i_}\n" for i_ in ids).encode())
        if r1.returncode == 0 and r2.returncode == 0:
            vs_old = _stdin_names(r1.stdout, ids, key, aliases)
            vs_parent = _stdin_names(r2.stdout, ids, key, aliases)
            for c, _old in replaced:
                c["names"] = {k_: n for k_, n in vs_parent[c["oid"]].items() if k_ in vs_old[c["oid"]]}
                c["files"] = set(c["names"])
    if plain:
        # One record per commit, each starting with a NUL of its own before its id, as commits_with_files reads them.
        r = run_git(repo.root, ["-c", "log.showSignature=false", "log", "--no-walk=unsorted", "--no-renames", "-m",
                                "--first-parent", "--name-only", "-z", "--format=%x00%H", "--stdin"], check=False,
                    input_bytes="".join(f"{c['oid']}\n" for c in plain).encode())
        files: dict = {}
        cur, want = None, False
        for tok in r.stdout.split(b"\0") if r.returncode == 0 else []:
            if want:
                cur = tok.decode("ascii", "replace").strip()
                files.setdefault(cur, {})
                want = False
                continue
            if tok == b"":
                want = True
                continue
            t = tok[1:] if tok.startswith(b"\n") else tok
            if cur and t:
                n = t.decode("utf-8", "surrogateescape")
                files[cur][key(n)] = n
                aliases.setdefault(cur, {}).setdefault(key(n), set()).add(n)
        for c in plain:
            c["names"] = files.get(c["oid"])
            c["files"] = set(c["names"]) if c["names"] is not None else None
    for c in todo:
        # Git trees distinguish spellings that the working filesystem equates. Retain both sides of a case rename,
        # then choose the spelling that exists in this commit, not whichever diff entry happened to be last (R24-238).
        c["aliases"] = {k: sorted(v) for k, v in aliases.get(c["oid"], {}).items() if len(v) > 1}
        if not c["aliases"] or c.get("names") is None:
            continue
        paths = sorted({p for v in c["aliases"].values() for p in v})
        listed_data = _tree_paths(repo, c["oid"], paths)
        present: dict = {}
        for entry in z_split(listed_data) if listed_data is not None else []:
            if "\t" in entry:
                _meta, p = entry.split("\t", 1)
                present.setdefault(key(p), []).append(p)
        c["ambiguous_names"] = set()
        for k in c["aliases"]:
            if k not in c["names"]:
                continue
            found = present.get(k, [])
            if len(found) == 1:
                c["names"][k] = found[0]
            elif len(found) > 1 or listed_data is None:
                c["ambiguous_names"].add(k)  # no unique version can represent this filesystem path


def _blob_id(data: bytes, ref: str) -> str:
    """The ID git gives these bytes as a blob, in the object format of the ID ref (SHA-1 or SHA-256)."""
    h = hashlib.sha256() if len(ref) == 64 else hashlib.sha1()
    h.update(b"blob %d\0" % len(data))
    h.update(data)
    return h.hexdigest()


_LINES_KEPT = 16 * 1024 * 1024


def _blob_raw(repo: Repo, oid: str):
    """A blob's bytes, or None where git cannot read it or it is over 4 MB. The blobs read are kept for the rest of the
    search up to 16 MB in all, those used longest ago given up first; lines are made from them when asked and not kept,
    which would take ten times the bytes, and a version tested for lines is kept as their hashes (_blob_index; R24-165,
    R24-178, R24-208, R24-214)."""
    memo = _MEMO.setdefault("blob_lines", {}) if _MEMO is not None else {}
    k = (str(repo.root), oid)
    if k in memo:
        v = memo.pop(k)
        memo[k] = v  # the newest used last, so the oldest is given up first
        return v
    r = run_git(repo.root, ["cat-file", "blob", oid], check=False)
    # A blob over 4 MB is not read into lines: only a merge, or that very version, can say it holds a change.
    v = r.stdout if r.returncode == 0 and len(r.stdout) <= 4 * 1024 * 1024 else None
    if _MEMO is not None:
        size = len(v) if v is not None else 0
        while memo and _MEMO.get("blob_lines_size", 0) + size > _LINES_KEPT:
            _old, gone = next(iter(memo.items()))
            del memo[_old]
            _MEMO["blob_lines_size"] = _MEMO.get("blob_lines_size", 0) - (len(gone) if gone is not None else 0)
        if _MEMO.get("blob_lines_size", 0) + size <= _LINES_KEPT:
            _MEMO["blob_lines_size"] = _MEMO.get("blob_lines_size", 0) + size
            memo[k] = v
    return v


def _blob_lines(repo: Repo, oid: str):
    """A blob's lines, or None where git cannot read it or it is over 4 MB (_blob_raw)."""
    v = _blob_raw(repo, oid)
    return v.splitlines(keepends=True) if v is not None else None


_INDEX_KEPT = 64 * 1024 * 1024


def _blob_index(repo: Repo, oid: str):
    """The sorted hashes of a blob's lines, eight bytes each, or None as for _blob_lines: all a test of whether a version
    has a line needs, kept for the search up to 64 MB, those used longest ago given up first, so the versions every test
    of one file reads against stay even for a large file (R24-208, R24-214). A line whose hash another line shares is
    taken for present, which can only send the test on to the merge or report more."""
    memo = _MEMO.setdefault("blob_index", {}) if _MEMO is not None else {}
    k = (str(repo.root), oid)
    if k in memo:
        v = memo.pop(k)
        memo[k] = v
        return v
    lines = _blob_lines(repo, oid)
    v = None if lines is None else array.array("q", sorted(hash(x) for x in lines))
    if _MEMO is not None:
        size = 8 * len(v) if v is not None else 0
        while memo and _MEMO.get("blob_index_size", 0) + size > _INDEX_KEPT:
            _old, gone = next(iter(memo.items()))
            del memo[_old]
            _MEMO["blob_index_size"] = _MEMO.get("blob_index_size", 0) - (8 * len(gone) if gone is not None else 0)
        if _MEMO.get("blob_index_size", 0) + size <= _INDEX_KEPT:
            _MEMO["blob_index_size"] = _MEMO.get("blob_index_size", 0) + size
            memo[k] = v
    return v


def _in_index(index, line: bytes) -> bool:
    """Whether a version's line hashes (_blob_index) hold this line's."""
    h = hash(line)
    i = bisect.bisect_left(index, h)
    return i < len(index) and index[i] == h


def _change_sets(repo: Repo, base: str, theirs: str):
    """(the lines theirs added to base, the lines found once in base that theirs took out), kept for the search, so
    that each version read against one change costs a lookup of those lines alone (R24-208); None where either cannot
    be read into lines."""
    memo = _MEMO.setdefault("change_sets", {}) if _MEMO is not None else {}
    k = (str(repo.root), base, theirs)
    if k not in memo:
        lt, lb = _blob_lines(repo, theirs), _blob_lines(repo, base)
        if lt is None or lb is None:
            memo[k] = None
        else:
            st = set(lt)
            memo[k] = (st - set(lb), _once(lb) - st)
    return memo[k]


def _holds_change(repo: Repo, base: str | None, theirs: str | None, ours: str | None) -> bool:
    """Whether the file version ours already holds the change from base to theirs, each a blob ID or None for no file:
    merged into ours as git merge-file merges, the change conflicts with nothing and adds nothing. A rebase replay, a
    squash merge, a fixup squashed in, or an amend that kept the change holds it, also beside a change upstream made
    nearby (R24-114), while the same line changed at another place in the file does not stand in for it (R24-126,
    R24-128). A file added from nothing is held by a version that keeps its lines in their order (R24-163); one git
    cannot merge as text only by that very version. A line the change added that ours lacks settles it without a
    merge (R24-165)."""
    if theirs == ours or base == theirs:
        return True
    if theirs is None or ours is None:
        return False
    memo = _MEMO.setdefault("holds_change", {}) if _MEMO is not None else {}
    k = (str(repo.root), base, theirs, ours)
    if k in memo:
        return memo[k]
    held = False
    if base is None:
        lt, lo = _blob_lines(repo, theirs), _blob_lines(repo, ours)
        if lt is not None and lo is not None:
            it = iter(lo)
            held = all(any(x == y for y in it) for x in lt)
    else:
        ch, ix = _change_sets(repo, base, theirs), _blob_index(repo, ours)
        quick = ch is not None and ix is not None
        absent = quick and any(not _in_index(ix, x) for x in ch[0])
        kept = quick and not absent and any(_in_index(ix, x) for x in ch[1])
        if quick and absent:
            held = False  # theirs adds a line ours does not have
        elif quick and kept:
            held = False  # theirs takes out a line base has once, which ours still has (R24-179)
        else:
            r = run_git(repo.root, ["merge-file", "-p", "-q", "--object-id", ours, base, theirs], check=False)
            if r.returncode == 129:  # git before 2.43 merges files only
                r = _merge_files(repo, base, theirs, ours)
            held = r is not None and r.returncode == 0 and _blob_id(r.stdout, ours) == ours
    memo[k] = held
    return held


def _once(lines: list) -> set:
    """The lines found exactly once among lines."""
    seen, twice = set(), set()
    for x in lines:
        (twice if x in seen else seen).add(x)
    return seen - twice


def _pathspec_text(path: str) -> str:
    """path as a shell-quoted literal pathspec for a git command a report prints. After -- git still reads a path as a
    pattern, so fig[1].png also names fig1.png and :!name names every other file; following the printed restore then
    overwrote uncommitted work in those files (G1-02). A name without git's pattern characters and without a leading
    colon is printed as it is, as before."""
    if path.startswith(":") or any(ch in path for ch in "*?[\\"):
        return shlex.quote(":(literal)" + path)
    return shlex.quote(path)


def _recover_path_option(path: str) -> str:
    """A literal single-path option, including a name argparse would otherwise treat as another option."""
    return "--paths" + ("=" if path.startswith("-") else " ") + shlex.quote(path)


def _merge_files(repo: Repo, base: str, theirs: str, ours: str):
    """git merge-file -p over the three blobs written to a scratch folder, for git without --object-id; None, so not
    held, where the folder cannot be made or written (R24-144)."""
    try:
        tmp = scratch_dir(repo, "merge-")
    except (OSError, PeciaError):
        return None
    try:
        with _held_dir(tmp) as held, contextlib.ExitStack() as opened:
            names, fds = [], []
            for n, oid in (("ours", ours), ("base", base), ("theirs", theirs)):
                b = run_git(repo.root, ["cat-file", "blob", oid], check=False)
                if b.returncode != 0:
                    return None
                # A planted entry is never opened for truncation. Keep the file and its folder held
                # until Git finishes; a replaced POSIX name must not change the merge's input (F4-01).
                fd = held.open_fd(n, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
                f = opened.enter_context(os.fdopen(fd, "w+b"))
                f.write(b.stdout)
                f.flush()
                f.seek(0)
                if IS_WINDOWS:
                    names.append(str(tmp / n))  # the open CRT descriptor denies deletion/rename
                else:
                    via = next((p for p in (f"/proc/self/fd/{fd}", f"/dev/fd/{fd}") if os.path.exists(p)), None)
                    if via is None:
                        return None  # no stable descriptor path: cannot use a merge to prove survival
                    names.append(via)
                    fds.append(fd)
            return run_git(repo.root, ["merge-file", "-p", "-q", *names], check=False, pass_fds=fds)
    except (OSError, PeciaError):
        return None
    finally:
        try:
            _rmtree_at(tmp)
        except (OSError, PeciaError):
            pass


def _snapshot_positions(snapshots: list, entries: list, moved: list) -> tuple:
    """Place snapshots in the same history epochs for every recovery report."""
    n = len(entries or [])
    # Epochs: a version at reflog position p (0 the newest entry) was taken in the epoch that the history move nearest
    # after it ended, at its own position; -1 where no entry ended it, as for a move HEAD made without an entry, or one
    # known only from a newer snapshot (R24-157). Where the reflog cannot tell snapshots apart, positions are fractions:
    # at one entry, a snapshot on another commit than the entry's was taken after HEAD moved without an entry, which
    # ends the epoch of those before it (S1 of the fourteenth review); a snapshot with no place counts as taken before
    # every entry (R24-108), and each run of such snapshots on one base and branch is an epoch of its own (R24-172,
    # R24-184, S2 of the fourteenth review).
    pos_of: dict = {}
    extra: list = []
    at_entry: dict = {}
    for s_ in snapshots:
        mk = s_.get("reflog")
        at_entry.setdefault(_mark_index(entries, mk) if entries and mk and mk != "none" else None, []).append(s_)
    for a, grp in at_entry.items():
        grp.sort(key=lambda s_: s_["seq"])
        if a is None:
            runs, prev, run_of, prev_gone, gone_by = 0, object(), [], False, None
            for s_ in grp:
                mk = s_.get("reflog")
                key_ = (s_.get("parent"), s_.get("branch"))
                by = s_.get("agent") if s_.get("agent") not in (None, "", "-") else None
                # Each snapshot an earlier pecia took, with no Pecia-Reflog line at all, is an epoch of its own: with a
                # move between two of them on one commit and branch, the older one's version is read too (f, RP-13).
                if mk is None:
                    runs, prev, prev_gone, gone_by = runs + 1, object(), False, None
                # So is each one whose recorded place went with every entry of HEAD's reflog (d2, RP-13), except right
                # after such a snapshot of the same run by another recorded agent: what that agent's version replaced is
                # the cross-agent report's, within one epoch, as with no move (R24-155, R24-244).
                elif not entries and mk != "none":
                    if not (prev_gone and key_ == prev and gone_by and by and gone_by != by):
                        runs += 1
                    prev, prev_gone, gone_by = key_, True, by
                # A new base, or a new branch at the same one, as a checkout -b at the same commit makes (R24-184).
                else:
                    if key_ != prev or prev_gone:
                        runs += 1
                    prev, prev_gone, gone_by = key_, False, None
                run_of.append(runs)
            for s_, r_ in zip(grp, run_of):
                pos_of[s_["ref"]] = n + 1 + (runs - r_)  # the oldest run the farthest back
            extra += [n + 0.5 + j for j in range(runs)]
        else:
            eps, cur, sub = 0.5 / (2 * len(grp) + 1), entries[a]["oid"], 0
            for s_ in grp:
                if s_.get("parent") and s_["parent"] != cur:
                    sub, cur = sub + 1, s_["parent"]
                    extra.append(a - (2 * sub - 1) * eps)
                pos_of[s_["ref"]] = a - 2 * sub * eps
    move_at = sorted([i for i in range(min(n, len(moved or []))) if moved[i]] + extra)

    return pos_of, move_at


def _before_move_losses(repo: Repo, policy: dict, before: list, since_held: set, entries, moved: list, work: dict,
                        head: str, branch: str, acked: set | None = None, since: list | None = None) -> tuple:
    """Losses, hidden count and a kept-commit settlement query for the same search (R24-87, R24-245).
    History moves divide HEAD's reflog into epochs.
    For each file and each epoch before the last move, the newest version of it taken there counts: a snapshot's own
    version of the file, unless a commit made here later in that epoch changed the file and history still holds it
    (registered). A dropped commit never settles an earlier snapshot (R24-237). Every commit history no longer holds,
    made here or under a commit a snapshot
    was taken on, counts too, unless a newer commit or snapshot of its line counts in its place. Each counted version is
    reported unless its change came through: the file is at it now, the version is in history, or a version that
    survives, HEAD's, the file now, a snapshot's taken since the last move or a commit's history holds, holds everything
    its line did to the file since the line left history (R24-146 to R24-148, R24-155 to R24-161). Only what survives
    settles: a version history no longer holds carries nothing, it is reported with the rest of its line (R24-168), and
    an acknowledged report speaks for nothing but what it named (R24-170). A designated copy is settled only by the same
    bytes, on disk, on HEAD or stored by a snapshot taken since (R24-171). Nothing here is restored; each loss names its
    snapshot or commit and how to see or restore it."""
    out: dict = {}
    acked = acked or set()
    since = since or []
    hidden, handled = set(), set()
    key, holds = _path_key(repo), _Holds(repo)
    n = len(entries or [])
    head_tree = _snapshot_tree(repo, head) if head else {}
    head_names = {key(b): b for b, (mode, typ, _o) in head_tree.items() if typ == "blob" and mode in ("100644", "100755")}
    marks = [_mark_index(entries, b["reflog"]) for b in before if entries and b.get("reflog") not in (None, "none")]
    unmarked = any(b.get("reflog") in (None, "none") for b in before)
    upto = n if unmarked or None in marks else max(marks, default=0)
    window = upto
    st, st_bases = _start_info(repo)
    if entries:
        # Dropped commits made here are searched back to where HEAD's reflog stood at pecia's first snapshot here, which
        # retention never removes (R24-127, R24-136, R24-137); without that record, the whole reflog.
        i_ = _mark_index(entries, st) if st not in (None, "none") else None
        window = max(upto, n if i_ is None else i_)
    commits = _local_commits(repo, entries, window, kept_upto=upto) if entries else []
    # And the commits under HEAD and every local branch at pecia's first snapshot here, under every snapshot's base and
    # under the dropped commits found, that history no longer holds (R24-146).
    lines, graph, cut, unreadable_tips = _line_commits(
        repo, st_bases + [s_["parent"] for s_ in before + since if s_.get("parent")]
        + [c["oid"] for c in commits if not c["kept"]], {c["oid"] for c in commits}, window)
    allc = commits + lines
    kept_of = {c["oid"]: c["kept"] for c in allc}
    for s_ in before + since:
        if s_.get("parent") and not cut:
            kept_of.setdefault(s_["parent"], s_["parent"] not in graph)
    hist: list = []

    pos_of, move_at = _snapshot_positions(before + since, entries, moved)

    def end_of(p):
        j = bisect.bisect_left(move_at, p) - 1
        return move_at[j] if j >= 0 else -1

    def spos(s):
        return pos_of.get(s["ref"], n + 1)

    def cpos(c):
        return c["index"]

    def in_history(i, s):
        v = _item_version(i, s["commit"])
        name_ = head_names.get(key(i["path"]))
        if name_ and _same_version(repo, v, ["git", head_tree[name_][2], f"{head}:{name_}"]):
            return True
        if v and v[0] == "git":
            # Written since the snapshots' bases, or by one of the 50 newest commits history holds that changed the
            # file, as an older version put back by hand is (fourteenth round).
            return in_hist(v[1]) or v[1] in kept_since(None, key(i["path"]), i["path"])
        return False

    def in_hist(blob):
        if not hist:
            hist.append(_history_blobs(repo, [b["parent"] for b in before if b["parent"]]))
        return blob in hist[0]

    unknown = object()
    blobs: dict = {}
    path_aliases: dict = {}
    ambiguous = {(c["oid"], k) for c in allc for k in c.get("ambiguous_names", ())}
    for c in allc:
        for k, p in (c.get("names") or {}).items():
            path_aliases.setdefault(k, set()).add(p)
        for k, paths in c.get("aliases", {}).items():
            path_aliases.setdefault(k, set()).update(paths)
    for k, p in head_names.items():
        path_aliases.setdefault(k, set()).add(p)

    def fetch(triples):
        """The blobs of the given (commit, path key, path) triples, in one git call, reading no whole tree (R24-143):
        None where the commit has no such file or holds a submodule there (R24-164), unknown where git cannot say, as
        for a missing object (R24-152)."""
        want = [t for t in dict.fromkeys(triples) if (t[0], t[1]) not in blobs]
        for t in [t for t in want if "\n" in t[2] or (t[0], t[1]) in ambiguous]:
            blobs[(t[0], t[1])] = unknown
        want = [t for t in want if (t[0], t[1]) not in blobs]
        if not want:
            return
        r = run_git(repo.root, ["cat-file", "--batch-check=%(objectname) %(objecttype)"], check=False,
                    input_bytes="".join(f"{c_}:{p_}\n" for c_, _k, p_ in want).encode("utf-8", "surrogateescape"))
        rows = r.stdout.decode("utf-8", "replace").splitlines() if r.returncode == 0 else []
        if len(rows) != len(want):
            for c_, k_, _p in want:
                blobs[(c_, k_)] = unknown
            return
        missing: dict = {}
        for (c_, k_, p_), row in zip(want, rows):
            f = row.split()
            if row.endswith(" missing"):
                missing.setdefault(c_, []).append((k_, p_))
            else:
                blobs[(c_, k_)] = f[0] if len(f) == 2 and f[1] == "blob" else None
        for c_, pairs in missing.items():
            # git says missing both for a path the commit does not have and for an object it does not have, and a
            # submodule's commit is never in this repository: the commit's own tree tells them apart.
            paths = sorted({p for k_, p_ in pairs for p in path_aliases.get(k_, {p_}) | {p_}})
            t_ = _tree_paths(repo, c_, paths)
            listed = {}
            if t_ is not None:
                for ent in z_split(t_):
                    if "\t" in ent:
                        meta, name_ = ent.split("\t", 1)
                        listed.setdefault(key(name_), []).append((name_, meta.split()))
            for k_, p_ in pairs:
                found = listed.get(k_, [])
                value = None
                if t_ is None or len(found) > 1:
                    value = unknown
                elif found:
                    name_, meta = found[0]
                    if len(meta) != 3:
                        value = unknown
                    elif meta[1] == "blob":
                        # An exact missing blob is unreadable; an alternate spelling may be the parent's side of a
                        # case rename. Check the object exists before using the tree's object ID (R24-152, R24-238).
                        if name_ == p_:
                            value = unknown
                        else:
                            check = run_git(repo.root, ["cat-file", "-t", meta[2]], check=False)
                            value = meta[2] if check.returncode == 0 and check.stdout.strip() == b"blob" else unknown
                blobs[(c_, k_)] = value

    def blob_at(commit, k, path):
        if not commit:
            return None
        if (commit, k) not in blobs:
            fetch([(commit, k, path)])
        return blobs.get((commit, k), unknown)

    def head_blob(k):
        name_ = head_names.get(k)
        return head_tree[name_][2] if name_ else None

    ancestry: dict = {}
    below: dict = {}
    kept_parents = {c["oid"]: c.get("parent") for c in allc if c["kept"]}

    def is_ancestor(a, b):
        if a == b:
            return True
        if kept_of.get(a) is False and kept_of.get(b) is True:
            return False  # history holds every ancestor of a commit it holds (R24-151)
        if a in graph and b in graph:
            # Both under the tips and held by no branch: every commit between them is held by none either, so the
            # parents read once answer it (R24-151); past the walk's bound an ancestor may be missed, never invented.
            if b not in below:
                seen_, todo_ = set(), list(graph[b])
                while todo_:
                    x = todo_.pop()
                    if x in graph and x not in seen_:
                        seen_.add(x)
                        todo_.extend(graph[x])
                below[b] = seen_
            return a in below[b]
        if (a, b) not in ancestry:
            # Reading a snapshot independently can ask whether each kept replay precedes the snapshot's base.
            # A known first-parent path from a back to b proves the reverse impossible, without another git call.
            cur, seen = a, set()
            while cur in kept_parents and cur not in seen:
                seen.add(cur)
                cur = kept_parents[cur]
                if cur == b:
                    ancestry[(a, b)] = False
                    break
        if (a, b) not in ancestry:
            ancestry[(a, b)] = run_git(repo.root, ["merge-base", "--is-ancestor", a, b], check=False).returncode == 0
        return ancestry[(a, b)]

    marks = _ack_marks(repo) if acked else {}

    again_: dict = {}

    def again(oid, kk):
        """Whether HEAD held the commit again after the acknowledgement that names it, as after git reset --hard onto
        it or a cherry-pick that made it anew: its loss now is a later one, and is reported (R24-181). Every entry newer
        than the acknowledgement is read (R24-186). Where the entry it recorded is gone, every entry left is, whatever
        its date, since a clock set back dates a later one earlier (R24-187, R24-201): git expires the entries of a
        commit no branch holds sooner than the reachable entry recorded, so one left is newer, but for a hand-deleted
        entry. A descendant of the commit counts as holding it, as on a rescue branch since deleted, wherever it was made
        (S1 of the sixteenth review); history holds none, since it does not hold the commit."""
        if (oid, kk) in again_:
            return again_[(oid, kk)]
        mk = marks.get(kk)
        if not entries or not mk:
            return False
        f_ = mk.split()
        if len(f_) not in (4, 7) or not all(x.isdigit() for x in f_[0:3:2] + f_[5:6]):
            return True  # a record that cannot be read: reported again, the safe way
        a = _ack_mark_index(entries, mk)
        newer = entries if a is None else entries[:a]
        again_[(oid, kk)] = any(e["oid"] == oid or (kept_of.get(e["oid"]) is False and is_ancestor(oid, e["oid"]))
                                or (e["oid"] not in kept_of and held_under(oid, e["oid"])) for e in newer)
        return again_[(oid, kk)]

    under_: dict = {}
    failed: set = set()
    desc_: dict = {}

    def held_under(oid, e_oid):
        """Whether a commit HEAD's reflog records, which the search did not walk, descends from oid: as one on a rescue
        branch another worktree made, checked out here, the branch since deleted (S1 of the sixteenth review). The
        commits history does not hold under all such entries are read once; history holds none of oid's descendants."""
        if "g" not in under_:
            want = list(dict.fromkeys(e["oid"] for e in entries if e["oid"] not in kept_of))
            g_, cut_ = {}, False
            args = ["rev-list", "--parents", "-n", "5000", "--stdin", "--not", *_held_refs(repo)]

            def walk(tips_):
                r_ = run_git(repo.root, args, check=False, input_bytes="".join(f"{o}\n" for o in tips_).encode())
                return ({f[0]: f[1:] for f in (ln.split() for ln in r_.stdout.decode("ascii", "replace").splitlines())
                         if f} if r_.returncode == 0 else None)
            if want:
                got = walk(want)
                if got is None:
                    # An entry whose commit git removed fails the call: those are passed over, and the rest read again,
                    # each on its own if one's history lacks an object, as for the search's own walk (R24-162).
                    chk = run_git(repo.root, ["cat-file", "--batch-check=%(objecttype)"], check=False,
                                  input_bytes="".join(f"{o}\n" for o in want).encode())
                    kinds = chk.stdout.decode("ascii", "replace").splitlines() if chk.returncode == 0 else []
                    want = [o for o, kind in zip(want, kinds) if kind.strip() == "commit"] if len(kinds) == len(want) \
                        else want
                    got = walk(want)
                    if got is None:
                        got = {}
                        for o in want:
                            one = walk([o])
                            if one is None:
                                failed.add(o)
                            got.update(one or {})
                g_ = got
                cut_ = len(g_) >= 5000
            under_["g"], under_["cut"] = g_, cut_
        g_ = under_["g"]
        if e_oid in g_ and oid in g_:
            # The descendants of oid among those commits, read once for each acknowledged commit asked about, not the
            # ancestors of every entry (S3 of the seventeenth review).
            if oid not in desc_:
                if "children" not in under_:
                    kids: dict = {}
                    for x, ps in g_.items():
                        for p_ in ps:
                            kids.setdefault(p_, []).append(x)
                    under_["children"] = kids
                seen_, todo_ = set(), [oid]
                while todo_:
                    x = todo_.pop()
                    if x not in seen_:
                        seen_.add(x)
                        todo_.extend(under_["children"].get(x, ()))
                desc_[oid] = seen_
            if e_oid in desc_[oid]:
                return True
        # Past the bound, or for a history that lacks an object, git is asked for this one (S1 of the seventeenth
        # review); otherwise history holds the entry, or oid is under none of them.
        return (under_["cut"] or e_oid in failed) and is_ancestor(oid, e_oid)

    def is_acked(kk, oid=None):
        return kk in acked and not (oid and again(oid, kk))

    bases_: dict = {}

    def fork(c):
        """Where the line of commit c left HEAD's history: its merge base with HEAD, so that a change that only takes out
        what the line itself added counts as nothing come through against a HEAD that never had it (R24-135)."""
        if c not in bases_:
            # A commit history no longer holds, with one parent, left HEAD's history where its parent did: a line of
            # them asks git once (R24-198).
            chain, x = [], c
            while x not in bases_ and kept_of.get(x) is False and len(graph.get(x) or ()) == 1:
                chain.append(x)
                x = graph[x][0]
            if x not in bases_:
                r = run_git(repo.root, ["merge-base", x, "HEAD"], check=False) if head else None
                bases_[x] = (r.stdout.decode("ascii", "replace").split() or [None])[0] if r and r.returncode == 0 else None
            for y in chain:
                bases_[y] = bases_[x]
        return bases_[c]

    # Lineage, from what git records: the commit an amend, or a rebase step made in its place, replaced (R24-124); and
    # the commit a rebase step or a cherry-pick replayed: one searched with the same author, message and files and the
    # same change by patch ID, without context, whatever its date (R24-138, R24-149, R24-150, R24-156, R24-158).
    after_: dict = {}
    twins_of: dict = {}  # the commits a replay replayed, linked by patch ID only (R24-167)

    amends: dict = {}  # the amend or in-place step that replaced each commit (R24-185)

    def link(a, b):
        after_.setdefault(a, []).append(b)
    for c in allc:
        if c.get("amended"):
            link(c["amended"], c["oid"])
            amends.setdefault(c["amended"], []).append(c)
    picks = [c for c in allc if c.get("replay") and not c.get("amended") and c.get("names") is not None]
    if picks:
        pool = [c for c in allc if c.get("names") is not None]
        r = run_git(repo.root, ["-c", "log.showSignature=false", "log", "--no-walk=unsorted", "--stdin",
                                "--format=%x00%H%x00%an%x00%ae%x00%B"], check=False,
                    input_bytes="".join(f"{o}\n" for o in dict.fromkeys(c["oid"] for c in pool)).encode())
        parts = r.stdout.decode("utf-8", "replace").split("\0") if r.returncode == 0 else []

        def plain(msg):
            # git cherry-pick -x adds a line naming the commit it picked; the rest of the message is the commit's.
            return re.sub(r"\n*\(cherry picked from commit [0-9a-f]{40,64}\)\s*$", "", msg.strip()).strip()
        sig = {parts[i].strip(): (parts[i + 1], parts[i + 2], plain(parts[i + 3]))
               for i in range(1, len(parts) - 3, 4)}
        made: dict = {}
        for o in pool:
            if o["oid"] in sig:
                made.setdefault((sig[o["oid"]], frozenset(o["names"])), []).append(o)
        pairs = []
        for p_ in picks:
            pairs += [(o, p_) for o in made.get((sig.get(p_["oid"]), frozenset(p_["names"])), [])
                      if o["oid"] != p_["oid"] and o["index"] > p_["index"]]
        if pairs:
            ids = list(dict.fromkeys([o["oid"] for o, _p in pairs] + [p_["oid"] for _o, p_ in pairs]))
            # git log -p runs a configured textconv driver by default, which would run a command during recovery
            # and put its output, not the file's bytes, into the patch IDs (G4-03).
            lp = run_git(repo.root, ["-c", "log.showSignature=false", "log", "--no-walk=unsorted", "-p", "-U0",
                                     "--no-textconv", "--no-ext-diff", "--no-renames", "--no-color",
                                     "--format=commit %H", "--stdin"], check=False,
                         input_bytes="".join(f"{o}\n" for o in ids).encode())
            pid = run_git(repo.root, ["patch-id", "--stable"], check=False, input_bytes=lp.stdout) \
                if lp.returncode == 0 else None
            by = {}
            for ln in pid.stdout.decode("ascii", "replace").splitlines() if pid is not None and pid.returncode == 0 else []:
                f_ = ln.split()
                if len(f_) == 2:
                    by[f_[1]] = f_[0]
            for o, p_ in pairs:
                if by.get(o["oid"]) and by.get(o["oid"]) == by.get(p_["oid"]):
                    link(o["oid"], p_["oid"])
                    twins_of.setdefault(p_["oid"], []).append(o["oid"])
    lineage: dict = {}

    def line_of(a):
        """The commit and every commit that replaced it, by amend, rebase or cherry-pick, transitively."""
        if a not in lineage:
            seen, todo = {a}, [a]
            while todo:
                for y in after_.get(todo.pop(), []):
                    if y not in seen:
                        seen.add(y)
                        todo.append(y)
            lineage[a] = seen
        return lineage[a]

    by_oid = {c_["oid"]: c_ for c_ in allc}

    def covers(a, d, k):
        """Whether a version of the file reported or come through on commit d speaks for commit a: d is a, or descends
        from it, from an amend or a step made in place of it that changed the file itself, or from a replay of it by
        patch ID whose version holds its own change of the file, whitespace included. An amend that only took a's change
        of the file out, leaving the file as a's parent had it, or a replay that changed it, speaks for none of it; one
        that kept a's version as it was speaks for it, and so does one that changed the file otherwise, the line's newer
        version (R24-91, R24-185, S4 of the fifteenth review, R24-209). The file's path is carried along the chain, so that a step made in
        place that left the file as it was still compares the next one (S4 of the sixteenth review)."""
        seen, todo = {a}, [(a, ((by_oid.get(a) or {}).get("names") or {}).get(k))]
        while todo:
            x, path_x = todo.pop()
            if x == d or is_ancestor(x, d):
                return True
            cx = by_oid.get(x)
            for r in amends.get(x, []):
                if r["oid"] in seen or r["files"] is None:
                    continue
                # One that changed the file itself, or kept x's version of it as it was; not one that put it back.
                if k in r["files"] or (path_x is not None and blob_at(r["oid"], k, path_x) is not unknown
                                       and blob_at(r["oid"], k, path_x) == blob_at(x, k, path_x)):
                    seen.add(r["oid"])
                    todo.append((r["oid"], (r.get("names") or {}).get(k) or path_x))
            for r_ in after_.get(x, []):
                if r_ in seen or x not in twins_of.get(r_, ()) or not cx:
                    continue
                path_ = (cx.get("names") or {}).get(k)
                if path_ is None:
                    continue
                own_, rb = blob_at(x, k, path_), blob_at(r_, k, path_)
                pb = blob_at(cx["parent"], k, path_) if cx.get("parent") else None
                if unknown not in (own_, rb, pb) and _holds_change(repo, pb, own_, rb):
                    seen.add(r_)
                    todo.append((r_, ((by_oid.get(r_) or {}).get("names") or {}).get(k) or path_))
        return False

    def follows(a, d):
        """Whether commit d came from commit a: d is a, or a replacement of a, or one of them is d's ancestor."""
        return any(r_ == d or is_ancestor(r_, d) for r_ in line_of(a))

    def carries(a, d):
        """Whether a commit history holds that came from a carries a's whole line: one made here, or a replay made in
        place of a commit of that line (an amend, a fixup). A replay onto another parent carries only its own commit's
        change (R24-92)."""
        if d.get("foreign"):
            return False
        return not d.get("replay") or bool(d.get("amended")) and d["amended"] in line_of(a)

    disk_: dict = {}

    def disk(k, path):
        """The file now: (missing, None), (file, its blob as git would store it), or (unsafe, the error)."""
        if k not in disk_:
            try:
                target = _safe_target(repo, path)
                if _presence(target) == "missing":
                    disk_[k] = ("missing", None)
                else:
                    data = _read_regular(target)
                    name_ = head_names.get(k)
                    try:
                        at_head = bool(name_) and data == _checkout_bytes(repo, f"{head}:{name_}")
                    except GitError:
                        at_head = False
                    if at_head:
                        disk_[k] = ("file", head_blob(k))
                    else:
                        # As git would store it, clean filters and line endings applied, to compare with versions in git.
                        h = run_git(repo.root, ["hash-object", "-w", "--stdin", f"--path={path}"], check=False,
                                    input_bytes=data)
                        disk_[k] = ("file", h.stdout.decode("ascii", "replace").strip() if h.returncode == 0 else None)
            except (UnsafePath, OSError) as e:
                disk_[k] = ("unsafe", e)
        return disk_[k]

    snaps_all = [s_ for s_ in since + before if s_.get("commit")]  # the newest first
    speak_of: dict = {}  # what each snapshot taken before the move speaks for, filled in as each is planned
    after_cache: dict = {}

    def versions_after(end, k, path, commit=False):
        """The versions of the file taken after the move at reflog position end that carry its change: HEAD's, the file
        now, those of the eight newest snapshots taken since the last move, those of the commits history holds that were
        made after that move and changed the file, and those of the snapshots taken after that move and before the last
        one of a file they hold a version of their own of, each of which is read in its turn, or was replaced by a newer
        version of its own epoch that is; for a dropped commit's change (commit), only the snapshot its epoch was read
        by, so that an edit taking that change out later in the epoch leaves the commit named (S2 of the twentieth
        review). Never a dropped commit's, whose version is read only for the files it changed and can be settled for
        its own change alone (R24-167, R24-168)."""
        # Read again once another snapshot taken before the move speaks, or its epoch is read (S4 of the seventeenth
        # review).
        ck = (end, k, len(speak_of), len(ep_state), commit)
        if ck not in after_cache:
            comm_ = [c for c in allc if c["kept"] and c["index"] <= end and c["files"] is not None and k in c["files"]]
            # A snapshot taken before the last move counts only for a file it holds a version of its own of: the rest of
            # its tree is what commits held, which counts through those commits (R24-146). And only as its epoch was
            # read: a version that came through carries; one a report shown now names stands for what it holds only in
            # that report; one an acknowledgement hides, one settled for its
            # own change alone and one a commit made later in its epoch replaced carry nothing, nor does any snapshot
            # an acknowledgement names for the file, whatever its epoch (R24-210, R24-211, R24-216, S2 of the
            # nineteenth review).
            # For a dropped commit's change, only the snapshot each epoch was read by: an older one of the epoch, whose
            # version may hold what the newer one took out, was never read, and a commit stays named after the file is
            # edited again (S2 of the twentieth review).
            mid = [(s_, ep_state.get((k, end_of(spos(s_))))) for s_ in before
                   if spos(s_) <= end and k in speak_of.get(s_["ref"], ()) and (s_["ref"], k) not in acked_snaps
                   and (not commit or ep_reader.get((k, end_of(spos(s_)))) == s_["ref"])]
            mid = [(s_, st_) for s_, st_ in mid if st_ in ("settled", "shown")][:8]
            fetch([(s_["commit"], k, path) for s_ in since] + [(s_["commit"], k, path) for s_, _st in mid]
                  + [(c["oid"], k, (c["names"] or {}).get(k, path)) for c in comm_])
            d_ = disk(k, path)
            vs = [head_blob(k)] + ([d_[1]] if d_[0] == "missing" or (d_[0] == "file" and d_[1]) else [])
            # The eight newest versions taken since, and those of recover ack's own snapshots besides, after them, so that
            # an ack's snapshot pushes none of them out, also of the four a file over 4 MB is merged with (S4 of the
            # nineteenth review, S1 of the twentieth).
            acks_ = [s_ for s_ in since if s_.get("reason") == "recover ack"]
            taken = [b_ for b_ in dict.fromkeys(blobs.get((s_["commit"], k), unknown) for s_ in since
                                                if s_.get("reason") != "recover ack") if b_ is not unknown]
            vs += taken[:8] + [blobs.get((s_["commit"], k), unknown) for s_ in acks_]
            vs += [blobs.get((c["oid"], k), unknown) for c in comm_]
            vs += [blobs.get((s_["commit"], k), unknown) for s_, st_ in mid if st_ == "settled"]
            vs = list(dict.fromkeys(v for v in vs if v is not unknown))
            shown_ = [blobs.get((s_["commit"], k), unknown) for s_, st_ in mid if st_ == "shown"]
            after_cache[ck] = (vs, [v for v in dict.fromkeys(shown_) if v is not unknown and v not in vs])
        return after_cache[ck]

    hist_cache: dict = {}

    def kept_since(fc, k, path):
        """The versions of the file in the 50 newest commits history holds, on any branch, tag, remote branch or HEAD,
        that changed it since the commit fc: a squash merge, a replay another worktree made, a later commit upstream
        (R24-176, R24-177)."""
        ck = (fc, k)
        if ck not in hist_cache:
            r = run_git(repo.root, ["rev-list", "-n", "50", "HEAD", "--branches", "--tags", "--remotes",
                                    *_other_heads(repo), *([f"^{fc}"] if fc else []), "--", path], check=False)
            cs = r.stdout.decode("ascii", "replace").split() if r.returncode == 0 else []
            fetch([(c_, k, path) for c_ in cs])
            hist_cache[ck] = list(dict.fromkeys(b_ for b_ in (blobs.get((c_, k), unknown) for c_ in cs)
                                                if b_ is not unknown))
        return hist_cache[ck]

    # The snapshots an acknowledgement names, for each file: they carry nothing, even where expiry has put them in one
    # run with a newer snapshot whose version came through (S2 of the nineteenth review).
    acked_snaps = {(a_.split("\x1f")[0], a_.split("\x1f")[1]) for a_ in acked
                   if a_.count("\x1f") >= 2 and a_.split("\x1f")[0]}
    nocheck = object()
    SHOWN = "shown"  # came_through's answer for a change held only by a version a report shown now names
    ep_state: dict = {}  # (file, epoch): how the newest snapshot of that epoch that speaks for the file was read
    ep_reader: dict = {}  # (file, epoch): that snapshot

    def came_through(base, theirs, end, k, path, fc=None, own=nocheck, commit=False):
        """Whether a version that survives holds the change from base to theirs (R24-155): one taken after the move at
        end, or one a commit history holds made since fc. With own, the version the line's last step was made on when
        that is not base, the same version must hold that step's own change too: a commit history holds under it, which
        holds what the line did before, does not hold what the step took out (fourteenth round). For a file over 4 MB,
        which no line test can narrow, at most four of each are merged with it (R24-165)."""
        def held(o):
            return _holds_change(repo, base, theirs, o) and (
                own is nocheck or own is not unknown and _holds_change(repo, own, theirs, o))
        vs, shown_ = versions_after(end, k, path, commit)
        if theirs in vs:
            return True
        big = theirs is not None and _blob_raw(repo, theirs) is None  # theirs None: the line deleted the file
        if any(held(o) for o in (vs[:4] if big else vs)):
            return True
        hv = [o for o in kept_since(fc, k, path) if o not in vs]
        if theirs in hv or any(held(o) for o in (hv[:4] if big else hv)):
            return True
        # Held only by a snapshot taken between the moves whose own version is reported now: it is named in that
        # report, which shows it, never settled by it (S1 of the eighteenth review).
        sh = [o for o in shown_ if o not in hv]
        return SHOWN if theirs in sh or any(held(o) for o in (sh[:4] if big else sh)) else False

    def here_at(path, c):
        try:
            return _raw_equals_base(repo, _safe_target(repo, path), f"{c}:{path}")
        except (UnsafePath, OSError, GitError):
            return False

    # What each file's reports and settled versions speak for: (commit, whole, reported), the snapshot's base or the
    # commit itself, whether everything its line did to the file was accounted for, so that a commit it came from is
    # covered by it, and whether a report shown now names it, whose acknowledgement then acknowledges what it covers.
    covered: dict = {}

    def cover(k, oid, whole=True, reported=False):
        if oid:
            covered.setdefault(k, []).append((oid, whole, reported))

    more: dict = {}
    parts_: dict = {}  # each file's report, piece by piece: (commit, snapshot, words)

    def add(k, path, piece, snapshot=None):
        """Report a loss of the file, in a report of its own or beside what the file's report holds already. False when
        an acknowledgement hides it: then it speaks for nothing (R24-170)."""
        tag, why, cat = piece["tag"], piece["why"], piece.get("category", "before_move")
        kk = f"{snapshot or ''}\x1f{k}\x1f{tag}"
        extra = [f"\x1f{k}\x1fcommit:" + piece["commit"]] if piece.get("commit") and snapshot else []
        handled.add(k)
        if is_acked(kk, None if snapshot else piece.get("commit")) or any(is_acked(a, piece["commit"]) for a in extra):
            hidden.add(k)
            return False
        parts_.setdefault(k, []).append((piece.get("commit"), snapshot, why))
        if k in out:
            e = out[k]
            if piece.get("commit"):
                e.setdefault("also", []).append(piece["commit"])
            else:
                e.setdefault("also_snapshots", []).append(snapshot)
            e["ack_also"] = list(e.get("ack_also") or []) + [kk] + extra
            # The first few in words; the rest only by name, in also and also_snapshots (fourteenth review, f11).
            more[k] = more.get(k, 0) + 1
            if more[k] <= 3:
                e["why"] += "; " + why
            if not e.get("commit") and piece.get("commit"):
                e["commit"] = piece["commit"]
            return True
        out[k] = {"path": path, "category": cat, "snapshot": snapshot, "ack": kk, "why": why,
                  **({"commit": piece["commit"]} if piece.get("commit") else {}),
                  **({"version": piece["version"]} if piece.get("version") else {}),
                  **({"ack_also": extra} if extra else {})}
        return True

    def history_moved(b_, k, path, g, own=None):
        """Whether history changed the file since the snapshot's base, or where its line left HEAD's history, so that
        the snapshot's whole version would undo that change, as after git fetch and git reset --hard to upstream
        (R24-212): not where that version holds the change, as one HEAD reached by an amend of part of it does
        (R24-227)."""
        if not b_ or g == "differs":
            return False
        was = blob_at(b_, k, path)
        return (was is not unknown and was != head_blob(k)
                and not (own is not None and own is not unknown and _holds_change(repo, was, head_blob(k), own)))

    def snap_text(s, path, now, changed=False, since_=None, moved=False, artifact=False):
        name, q = s["ref"].rsplit("/", 1)[-1], _pathspec_text(path)
        # A file changed since holds newer work, which no command given here replaces (R24-175); the diff starts where
        # the loss is counted from, the snapshot's base or where its line left HEAD's history (R24-182). Where history
        # changed the file since, the snapshot's whole version would undo that change, so there is no command either
        # (R24-212).
        show = shlex.quote(s['commit'] + ':' + path)
        how = ((f"the file's newer version stays as it is: git diff {since_} {s['commit']} -- {q} shows all that "
                f"version holds that history does not, to make again by hand, and git show {show} shows that whole "
                "version" if since_ else
                f"the file's newer version stays as it is: git show {show} shows that whole version, to take from by "
                "hand") if changed else
               (f"HEAD's version of the file is not the one that snapshot was taken on, as after a reset to upstream "
                f"or on another branch, so that snapshot's whole version would undo the difference: git diff {since_} "
                f"{s['commit']} -- {q} shows all that version holds that history does not, to make again by hand, and "
                f"git show {show} shows that whole version") if moved else
               f"recover apply {name} --allow-other-base {_recover_path_option(path)} restores it")
        if changed and artifact:
            how = (f"the file's newer version stays as it is: recover inspect {name} opens a separate inspection "
                   f"with the byte-exact stored copy of {shlex.quote(path)}; compare that copy and take the wanted "
                   "changes by hand")
        return (f"snapshot {name}, taken before history last moved here (git reset, rebase, commit --amend, merge, pull, "
                f"cherry-pick, or a checkout of another commit or branch), holds a version of this file of its own, and "
                f"the file is {now}; latest never restores across a history move. If that version is the one you want, "
                f"{how}; if you removed or replaced it on purpose, nothing is lost, and recover ack, run by you outside "
                "an agent session, ends this report")

    def now_of(k, path):
        d_ = disk(k, path)
        if d_[0] == "missing":
            return "missing now"
        if d_[0] == "file" and d_[1] and d_[1] == head_blob(k):
            return "at the version committed on HEAD now"
        return "changed since, without that change"

    def superseding(s, k, path, base, own, after_move=True):
        """The kept commit made here after the snapshot that changed the file, whose version is the newer (registered): the
        oldest in the snapshot's own epoch, or, after the move that ended it, the oldest on the snapshot's line, an
        amend of its commit or one made on it, which history holds, when no snapshot taken after that move and before
        that commit shows the file without the snapshot's change, as one after a reset --hard does (R24-147, R24-159,
        R24-160). None for a snapshot with no place (R24-108)."""
        p = spos(s)
        if p >= n:
            return None
        e_ = end_of(p)
        later = [c for c in commits if c["kept"] and c["index"] < p and not c.get("replay") and c["files"] is not None
                 and k in c["files"]]
        same = [c for c in later if c["index"] > e_]
        if same:
            return same[-1]
        # After the move only a commit history holds: a dropped one on the line never had to see the version (R24-160).
        # Not for a designated copy, whose bytes no snapshot between can be compared with (R24-171).
        after = [c for c in later if after_move and c["kept"] and s.get("parent") and follows(s["parent"], c["oid"])]
        if not after:
            return None
        d = after[-1]
        if own is not None and own is not unknown and base is not unknown:
            between = [s2 for s2 in snaps_all if d["index"] < spos(s2) <= e_]
            fetch([(s2["commit"], k, path) for s2 in between])
            for s2 in between:
                b2 = blobs.get((s2["commit"], k), unknown)
                if b2 is not unknown and not _holds_change(repo, base, own, b2):
                    return None
        return d

    def kept_successor(c, k):
        """A commit history holds, newer than c, that came from c, changed the file and carries c's line: an amend of
        it, or a commit made here on one (R24-124, R24-141). It carries c's own change only: what c was made on is
        read on its own, since the successor may stand on a replay of c onto another parent (R24-169). It comes from c
        as a covering version does: not through an amend that only took c's change of the file out, nor through a
        replay whose version lacks it (R24-193, S2 of the sixteenth review)."""
        for d in allc:
            if d["index"] >= c["index"]:
                break
            if d["kept"] and d["files"] is not None and k in d["files"] and carries(c["oid"], d) \
                    and covers(c["oid"], d["oid"], k):
                return True
        return False

    def twins(c):
        """The commits history holds that are c's twins by patch ID: those c replayed, and replays of c (R24-196)."""
        return [o for o in list(twins_of.get(c["oid"], ())) + [r_ for r_ in after_.get(c["oid"], ())
                                                              if c["oid"] in twins_of.get(r_, ())] if kept_of.get(o)]

    since_sha: dict = {}
    globs_ = [g for g in ((policy.get("artifacts") or {}).get("include_globs") or []) if isinstance(g, str)]

    def designated(path):
        return bool(globs_) and match_any(path, globs_)

    shas_: dict = {}

    def blob_sha(b):
        """The SHA-256 of a blob's bytes, as a designated copy is stored by, or None where git cannot read it."""
        if b not in shas_:
            r = run_git(repo.root, ["cat-file", "blob", b], check=False)
            shas_[b] = hashlib.sha256(r.stdout).hexdigest() if r.returncode == 0 else None
        return shas_[b]

    def stored_since(k, sha):
        """Whether a snapshot taken since the last move stored a designated copy of the file with these bytes."""
        if not sha:
            return False
        if not since_sha:
            since_sha[None] = set()
            for s_ in since:
                inv = artifact_inventory(repo, policy, s_["commit"], _commit_message(repo, s_["commit"]))
                for p_, meta in inv["files"].items():
                    if isinstance(meta, dict) and meta.get("sha256"):
                        since_sha.setdefault(key(p_), set()).add(meta["sha256"])
        return sha in since_sha.get(k, ())

    unplaced: dict = {}
    spoken: set = set()  # (file, epoch) already read, the newest snapshot of the epoch first
    for s in before:
        if not work.get(s["ref"]) and s["artifacts"] in ("none", "") and not s.get("has_uncovered"):
            continue
        plan = recover_plan(repo, dict(s, implicit=True, suspect=None, withheld=[], moved=True), policy)
        speak = holds.of(s, plan)
        # As a carrier, only for a file it holds a version of its own of, not one it only reports never stored, whose
        # tree version is its base's (S3 of the fifteenth review).
        speak_of[s["ref"]] = speak & {key(i["path"]) for g in ("missing", "reverted", "identical", "differs")
                                      for i in plan[g]}
        p_s = spos(s)
        ep = end_of(p_s)
        for g in ("missing", "reverted", "identical", "differs"):
            for i in plan[g]:
                k = key(i["path"])
                if (k, ep) in spoken or k not in speak:
                    continue
                spoken.add((k, ep))
                ep_reader[(k, ep)] = s["ref"]
                git_item = i.get("source") == "git"
                if p_s > n and entries:
                    unplaced.setdefault(k, i["path"])
                if git_item and (g == "identical" or in_history(i, s)):
                    cover(k, s.get("parent"))
                    ep_state[(k, ep)] = "settled"
                    continue
                # A snapshot on a commit history holds: its own change, from that commit; on one it no longer holds, all
                # its line did since it left HEAD's history, as for a dropped commit (R24-155); with no merge base, as on
                # an orphan line, its own change (R24-174).
                b_ = ((s["parent"] if kept_of.get(s["parent"]) is True else fork(s["parent"]) or s["parent"])
                      if s.get("parent") else None)
                base = blob_at(b_, k, i["path"]) if b_ else None
                own = (i.get("oid") or blob_at(s["commit"], k, i["path"])) if git_item else None
                d = superseding(s, k, i["path"], base, own, after_move=git_item)
                if d is not None and not d.get("foreign"):
                    # A kept commit settles the snapshot (registered); a dropped one never does (R24-237).
                    # A merge or a revert settles nothing (R24-75, R24-94). The superseded snapshot carries nothing
                    # for older versions; the kept commit's actual content is evaluated separately (R24-216).
                    ep_state[(k, ep)] = "superseded"
                    continue
                changed = g == "differs" or k in since_held
                if not git_item:
                    # A designated copy is evidence, kept byte for byte: settled only by the same bytes, on disk, on HEAD
                    # or stored by a snapshot taken since, and it speaks for no commit it was taken on unless reported
                    # (R24-161, R24-171).
                    if g == "identical" or in_history(i, s) or stored_since(k, i.get("sha256")):
                        ep_state[(k, ep)] = "settled"
                        continue
                    objdirs, store_problem = snapshot_object_dirs(repo, policy, s["commit"],
                                                                  _commit_message(repo, s["commit"]))
                    bad = _object_problem(objdirs, store_problem, i["sha256"])
                    if bad:
                        # The same unavailable copy keeps its acknowledgement key when newer bytes appear (R24-243).
                        ep_state[(k, ep)] = "hidden"
                        if add(k, i["path"], {"tag": "unrecoverable", "category": "unrecoverable",
                                              "why": bad + "; that snapshot was taken before history last moved here; "
                                              "recover ack, run by you outside an agent session, ends this report"},
                               snapshot=s["ref"]):
                            cover(k, s.get("parent"), reported=True)
                        continue
                    now = ("missing now" if g == "missing" else
                           "changed since history moved, to other bytes" if g == "differs" else
                           "at the version committed on HEAD now" if str(i.get("base_spec")).startswith(head + ":") else
                           "back at the version committed on that snapshot's base now")
                    v = _item_version(i, s["commit"])
                    shown = add(k, i["path"], {"tag": "version:" + json.dumps(v), "version": v,
                                               "why": snap_text(s, i["path"], now, changed=changed, since_=b_, artifact=True)},
                                snapshot=s["ref"])
                    ep_state[(k, ep)] = "shown" if shown else "hidden"
                    if shown:
                        cover(k, s.get("parent"), reported=True)
                    continue
                mine = blob_at(s["parent"], k, i["path"]) if s.get("parent") and b_ != s["parent"] else nocheck
                ct = (came_through(base, own, ep, k, i["path"], b_, mine)
                      if base is not unknown and own is not unknown else False)
                if ct is True:
                    # From a parent history no longer holds, with no merge base with HEAD, as on an orphan line or in a
                    # shallow clone, only the snapshot's own change was asked: it speaks for no commit under it, which is
                    # read on its own (R24-203), and carries nothing for one (R24-211).
                    whole = kept_of.get(s.get("parent")) is True or b_ != s.get("parent")
                    cover(k, s.get("parent"), whole=whole)
                    ep_state[(k, ep)] = "settled" if whole else "own"
                    continue
                now = ("missing now" if g == "missing" else
                       "changed since history moved, without that version's change" if g == "differs" else
                       "at the version committed on HEAD now" if str(i.get("base_spec")).startswith(head + ":") else
                       "back at the version committed on that snapshot's base now")
                v = _item_version(i, s["commit"])
                shown = add(k, i["path"], {"tag": "version:" + json.dumps(v), "version": v,
                                           "why": snap_text(s, i["path"], now, changed=changed, since_=b_,
                                                            moved=history_moved(b_, k, i["path"], g, own))},
                            snapshot=s["ref"])
                ep_state[(k, ep)] = "shown" if shown else "hidden"
                if shown:
                    cover(k, s.get("parent"), reported=True)
        for u in plan["unsafe"]:
            # A file pecia cannot reach now is reported, as the search of snapshots taken since reports it (R24-99).
            k = key(u["path"])
            if k in since_held or (k, ep) in spoken:
                continue
            spoken.add((k, ep))
            ep_state[(k, ep)] = "hidden"  # a file pecia cannot read carries nothing
            if add(k, u["path"], {"tag": "unsafe", "category": "unsafe",
                                  "why": u["why"] + f"; snapshot {s['ref'].rsplit('/', 1)[-1]}, taken before history "
                                                    "last moved here, holds this file, so recovery cannot tell whether it "
                                                    "is lost"},
                   snapshot=s["ref"]):
                cover(k, s.get("parent"), reported=True)
        for cat in ("never_stored", "unrecoverable"):
            for u in plan[cat]:
                k = key(u["path"])
                # A newer version can be restored beside a loss; it cannot stand for unreadable older content.
                if u.get("snapshot") not in (None, s["ref"]) or (k, ep) in spoken:
                    continue
                spoken.add((k, ep))
                ep_state[(k, ep)] = "hidden"  # a version never stored, or one that cannot be read, carries nothing
                d = (superseding(s, k, u["path"], None, None, after_move=False) if u["path"] != "(artifact list)"
                     else None)
                if d is not None and not d.get("foreign"):
                    continue
                if add(k, u["path"], {"tag": cat, "category": cat,
                                      "why": u["why"] + "; that snapshot was taken before history last moved here; "
                                                        "recover ack, run by you outside an agent session, ends this "
                                                        "report"},
                       snapshot=s["ref"]):
                    cover(k, s.get("parent"), reported=True)

    def made(c):
        # One HEAD's reflog here does not record: made before pecia's first snapshot here, in another worktree, or
        # elsewhere and fetched, as an upstream commit a force-push later dropped (R24-205).
        return (f"a commit made here, {c['oid']}," if not c.get("line") else
                f"a commit, {c['oid']}, that HEAD's reflog here does not record, found under a commit a snapshot was "
                "taken on or a branch pecia's first snapshot here recorded,")

    def how_to(c, k, path, since_=None):
        q = _pathspec_text(path)
        gone = blob_at(c["oid"], k, path) is None  # the commit deleted the file (R24-191)
        now = now_of(k, path)
        if now == "changed since, without that change" or k in since_held:
            # The file holds newer work, which no command given here replaces (R24-175, R24-199); the diff starts where
            # its line left HEAD's history, so it shows every change of the line that is lost (R24-182).
            if gone:
                return ("that commit deleted the file, and the file's newer version stays as it is: no command given "
                        "here deletes it; delete it by hand if that version is not wanted either")
            return ("the file's newer version stays as it is: "
                    + (f"git diff {since_} {c['oid']} -- {q} shows all that commit's line did to the file that history "
                       "does not hold, to make again by hand, and " if since_ else "")
                    + f"git show {shlex.quote(c['oid'] + ':' + path)} shows its whole version")
        was = blob_at(since_, k, path) if since_ else None
        # Not where the commit's version holds history's change since, which restoring it keeps (R24-227).
        mine_ = blob_at(c["oid"], k, path)
        moved = (now in ("at the version committed on HEAD now", "missing now") and was is not unknown
                 and was != head_blob(k) and not (was is not None and mine_ is not None and mine_ is not unknown
                                                  and _holds_change(repo, was, head_blob(k), mine_)))
        if gone:
            # A deletion where history changed the file since gets no command either: git rm would delete that change
            # (R24-219).
            return ("that commit deleted the file, and history changed the file since that commit's line left it, so no "
                    "command given here deletes it: delete it by hand if that change is not wanted either" if moved else
                    f"that commit deleted the file, and git rm -- {q} deletes it again")
        if moved:
            # History changed the file since the commit's line left it, as a pull --rebase does: the commit's whole
            # version would put that change back, also where the file is missing now (R24-197, R24-207), and where
            # the commit added it from nothing beside another version history holds (R24-218).
            return ("history changed the file since that commit's line left it, so its whole version would undo that "
                    "change: "
                    + (f"git diff {since_} {c['oid']} -- {q} shows all that commit's line did to the file, to make "
                       "again by hand, and " if since_ else "")
                    + f"git show {shlex.quote(c['oid'] + ':' + path)} shows its whole version")
        return (f"git restore --source={c['oid']} -- {q} restores that whole version of the file, and git diff "
                f"{c['oid']} -- {q} shows how it differs from the file now")

    # Every commit history no longer holds, newest first, for each file it changed: covered by a newer version of its
    # line that is reported or came through, settled by a commit history holds that carries its line, and otherwise
    # named when its change did not come through (R24-113, R24-146 to R24-148, R24-156 to R24-160).
    # The versions of every commit searched, in one git call (R24-143, R24-165).
    fetch([(c["oid"], k_, p_) for c in allc if not c["kept"] and c.get("names") for k_, p_ in c["names"].items()]
          + [(o, k_, p_) for c in allc if not c["kept"] and c.get("names")
             for o in twins(c) for k_, p_ in c["names"].items()]
          + [(c["parent"], k_, p_) for c in allc if not c["kept"] and c.get("names") and c.get("parent")
             for k_, p_ in c["names"].items()])
    judged: set = set()
    for c in allc:
        if c["kept"] or not c.get("names") or c["oid"] in judged:
            continue  # a commit HEAD's reflog records twice, as a cherry-pick that made it anew, is read once
        judged.add(c["oid"])
        forked = []
        for k, path in sorted(c["names"].items()):
            kk = f"\x1f{k}\x1fcommit:" + c["oid"]
            b = blob_at(c["oid"], k, path)
            pb = blob_at(c["parent"], k, path) if c.get("parent") else None
            # A designated file is evidence, kept byte for byte: only its very bytes settle it, in a dropped commit as in
            # a snapshot, whatever newer version of its line came through (R24-183, R24-194). A deletion holds no bytes,
            # and is read as any file's change is (R24-197).
            evidence = designated(path) and b is not None
            by_ = [r_ for o, w, r_ in covered.get(k, ()) if w and covers(c["oid"], o, k)]
            if by_ and not evidence and not all(by_):
                continue  # a newer version of its line came through, holding its change
            # One a reported version holds is read as well, and named in that report when lost, so that recover ack
            # acknowledges nothing unseen (R24-170, R24-182).
            if not evidence and kept_successor(c, k):
                cover(k, c["oid"], whole=False)
                continue
            if is_acked(kk, c["oid"]):
                # Acknowledged: hidden, and it speaks for nothing else (R24-170), unless HEAD held it again since, when
                # its loss now is a later one (R24-181).
                hidden.add(k)
                continue
            if b is unknown:
                if add(k, path, {"tag": "unrecoverable:" + c["oid"], "commit": c["oid"], "category": "unrecoverable",
                                 "why": (f"{made(c)} which no branch holds any more, changed this file, and git cannot "
                                         "read that commit's version of it, so it cannot be restored; recover ack, run "
                                         "by you outside an agent session, ends this report")}):
                    cover(k, c["oid"], whole=False, reported=True)
                continue
            # The file on disk is read as git would store it first: bytes that differ there differ raw, but for a filter
            # that does not give back what it took, which can only report more (R24-198).
            if b == head_blob(k) or (b is not None and in_hist(b)) or (
                    disk(k, path)[0] == "file" and disk(k, path)[1] in (b, None) and here_at(path, c["oid"])):
                cover(k, c["oid"])
                continue
            if evidence and (b in kept_since(None, k, path) or stored_since(k, blob_sha(b))):
                cover(k, c["oid"])
                continue
            # With no merge base, as on an orphan line or in a shallow clone, its own change from its parent, which speaks
            # for no commit under it (R24-174, R24-203).
            fk = fork(c["oid"])
            hb_ = fk or c.get("parent")
            if hb_ and not forked:
                forked.append(hb_)
                fetch([(hb_, k_, p_) for k_, p_ in c["names"].items()])
            base = blob_at(hb_, k, path) if hb_ else None
            tw = twins(c) if not evidence and not c.get("foreign") else []
            held_ = [blob_at(o, k, path) for o in tw] if tw and pb is not unknown else []
            held_ = [t_ for t_ in held_ if t_ is not unknown and _holds_change(repo, pb, b, t_)]
            if held_:
                # A twin by patch ID history holds, the commit it replayed or a replay of it: settled when its version
                # holds this commit's own change, whitespace included; what this commit was made on is read on its own
                # (R24-167, R24-168, S3 of the fourteenth review, R24-196), unless the same version holds all its line
                # did since it left HEAD's history, as the replay of an amend does, which speaks for the line (R24-204).
                cover(k, c["oid"], whole=fk is not None and base is not unknown
                      and any(_holds_change(repo, base, b, t_) for t_ in held_))
                continue
            mine = pb if c.get("parent") and hb_ != c["parent"] else nocheck
            # A commit found under a recorded base has no place in HEAD's reflog: every commit made here is after it
            # (S1 of the fifteenth review).
            end_c = end_of(cpos(c)) if not c.get("line") and cpos(c) < n else (move_at[-1] if move_at else -1)
            # One a report shown now covers is named in it without every surviving version read against it, which for a
            # long line costs a test for each carrier and commit: naming one whose change came through elsewhere only
            # adds a name to a report shown anyway (R24-198).
            if not evidence and not by_ and base is not unknown \
                    and came_through(base, b, end_c, k, path, hb_, mine, commit=True) is True:
                cover(k, c["oid"], whole=fk is not None)
                continue
            d_ = disk(k, path)
            if d_[0] == "unsafe":
                # As for a snapshot's file, one pecia cannot reach or read now is reported (R24-99, R24-129, R24-140).
                if add(k, path, {"tag": "unsafe:" + c["oid"], "commit": c["oid"], "category": "unsafe",
                                 "why": (f"{made(c)} which no branch holds any more, changed this file, and pecia cannot "
                                         f"reach or read the file now ({d_[1]}), so recovery cannot tell whether that "
                                         f"commit's version is lost: git show "
                                         f"{shlex.quote(c['oid'] + ':' + path)} shows it")}):
                    cover(k, c["oid"], reported=True)
                continue
            beside = (" that snapshot has no place in HEAD's reflog, so which of the two versions is newer cannot be "
                      "told;" if k in unplaced and k in out else "")
            if add(k, path, {"tag": "commit:" + c["oid"], "commit": c["oid"],
                             "why": (f"{made(c)} which no branch holds any more, changed this file, and the file is "
                                     f"{now_of(k, path)};{beside} no snapshot holds that commit's version as uncommitted "
                                     f"work, and it is nowhere in history: {how_to(c, k, path, hb_)}. If that commit was "
                                     "dropped on purpose, by you or upstream, nothing is lost, and recover ack, run by you outside an agent "
                                     "session, ends this report")}):
                cover(k, c["oid"], reported=True)
    for t in unreadable_tips:
        # A commit pecia searched under, whose history git cannot read: whether commits there are lost cannot be told
        # (R24-162).
        add("\x00history", "(dropped commits)", {
            "tag": "unrecoverable:" + t, "category": "unrecoverable",
            "why": (f"git cannot read the history under {t}, a commit pecia searches for work no branch holds any more, "
                    "so recovery cannot tell whether commits made there are lost; git fsck names what is missing; recover "
                    "ack, run by you outside an agent session, ends this report")})
    dropped_ = [c for c in allc if not c["kept"]]
    for k in out:
        ps = parts_.get(k, [])
        if sum(1 for c_, _s, _w in ps if c_) > 1:
            # The commits in the order their versions were last the line's own, so the first named holds the newest:
            # a version an amend that left the file alone carried on is as new as that amend (fourteenth round's fz_drop,
            # OLDER).
            path = out[k]["path"]
            fetch([(d["oid"], k, path) for d in dropped_])

            def last(c_):
                # Only commits of c_'s own line: one on another line that lacks the file, or happens to hold the same
                # version, says nothing of how new c_'s is (R24-200).
                b_ = blob_at(c_, k, path)
                seen_at = [d["index"] for d in dropped_ if b_ is not unknown and blob_at(d["oid"], k, path) == b_
                           and covers(c_, d["oid"], k)]
                return min(seen_at + [by_oid[c_]["index"] if c_ in by_oid else 10 ** 9])
            snaps_p = [x for x in ps if not x[0]]
            ps = snaps_p + sorted((x for x in ps if x[0]), key=lambda x: last(x[0]))
            e = out[k]
            e["commit"] = [x[0] for x in ps if x[0]][0]
            e["also"] = [x[0] for x in ps if x[0]]
            e["why"] = "; ".join(w_ for _c, _s, w_ in ps[:4])
        if out[k].get("also"):
            # Every commit the report names but its first, once.
            out[k]["also"] = [c_ for c_ in dict.fromkeys(out[k]["also"]) if c_ != out[k].get("commit")]
            if not out[k]["also"]:
                del out[k]["also"]
        if more.get(k, 0) > 3:
            out[k]["why"] += (f"; and {more[k] - 3} more version(s) of this file, each named by its snapshot or commit "
                              "in this report")
        if k in since_held:
            # A snapshot taken since the move holds a newer version of the file: that version is still restored, and
            # this report is about the older work it does not hold (R24-155).
            out[k]["beside"] = True
    def settles_snapshot(s, k, path, version):
        """Apply this reader's existing settlement rule to an independently retired writer version."""
        # With no pre-move snapshots, kept files were unnecessary for the history report. Read those required by
        # this older writer now; the reflog window still starts at the first recorded snapshot.
        _commit_names(repo, [c for c in commits if c["kept"] and c["index"] < spos(s) and c["files"] is None])
        ordinary = bool(version and version[0] == "git")
        base = blob_at(s["parent"], k, path) if ordinary and s.get("parent") else None
        own = version[1] if ordinary else unknown
        d = superseding(s, k, path, base, own, after_move=ordinary)
        return d is not None and not d.get("foreign")

    return out, len(hidden - set(out)), settles_snapshot


def _named_in(u: dict) -> list:
    """Every snapshot and commit a report, or an acknowledgement, names: its own first, then also_snapshots and also, so
    that the text output shows all that recover ack ends (R24-195)."""
    out = []
    if u.get("snapshot"):
        out.append(f"snapshot {u['snapshot'].rsplit('/', 1)[-1]}")
    if u.get("commit"):
        out.append(f"commit {u['commit']}")
    out += [f"snapshot {s_.rsplit('/', 1)[-1]}" for s_ in u.get("also_snapshots") or []]
    out += [f"commit {c_}" for c_ in u.get("also") or []]
    return out or ["no snapshot or commit"]


def _print_also(u: dict) -> None:
    """In text output, the snapshots and commits a report names beyond the first few its words give (R24-195)."""
    if u.get("also") or u.get("also_snapshots"):
        print("    this report names, and recover ack ends: " + "; ".join(_named_in(u)))


def _moved_note(ctx: dict, text: str | None) -> str | None:
    """The note's part about history moves: where history last moved, and that older snapshots were not searched."""
    if not ctx or not ctx.get("before"):
        return text
    e = ctx.get("move")
    where = (f"history last moved here with {e['subject'] or 'an entry with no message'} "
             f"({_dt.datetime.fromtimestamp(e['time'], _dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')})" if e else
             "history moved here, or the snapshots were taken on another branch")
    part = (f"{where}; latest searched only the {len(ctx['since'])} snapshot(s) taken since and restores nothing from "
            f"the {ctx['before']} taken before")
    if ctx.get("acked"):
        part += f"; {ctx['acked']} report(s) from them are not shown, acknowledged with recover ack"
    return f"{text}; {part}" if text else part


def _line_branch(repo: Repo) -> str | None:
    """The branch HEAD's line belongs to: the branch checked out, or, while a rebase of a branch stops with HEAD detached,
    the branch being rebased, so snapshots taken at a stop belong to its line (R24-57)."""
    b = repo.branch()
    if b:
        return b
    memo = _MEMO.setdefault("line_branch", {}) if _MEMO is not None else {}
    if str(repo.root) not in memo:
        memo[str(repo.root)] = _rebase_branch(repo)
    return memo[str(repo.root)]


def _rebase_branch(repo: Repo) -> str | None:
    """The branch a rebase in progress rebases, from git's own state files; None when there is none. Looked up once
    per search: every plan asks (R24-69)."""
    for name in ("rebase-merge/head-name", "rebase-apply/head-name"):
        r = run_git(repo.root, ["rev-parse", "--git-path", name], check=False)
        if r.returncode != 0:
            continue
        f = Path(r.stdout.decode("utf-8", "surrogateescape").strip())
        if not f.is_absolute():
            f = repo.root / f
        try:
            ref = _read_regular(f, 4096).decode("utf-8", "replace").strip()
        except OSError:
            continue
        if ref.startswith("refs/heads/"):
            return ref[len("refs/heads/"):]
    return None


def _snap_line(snap: dict, branch: str) -> str:
    """The line a snapshot is read on: its branch, and for one taken at a rebase stop, with HEAD detached, the detached
    line as well, which git rebase --quit leaves HEAD on (R24-65)."""
    if snap.get("detached") and branch == "(detached or unborn)":
        return branch
    return snap.get("branch") or branch


def _unnamed_note(snaps: list) -> str | None:
    """That snapshots could not name every file they left out (more than the list holds, artifact capture failed as a
    whole, a designated folder pecia could not list, or a folder git could not open), when any did (R24-28)."""
    marked = []
    for s in snaps:
        if s.get("has_uncovered"):
            own, more = _snap_uncovered(s)
            if more or "(designated artifacts)" in own:
                marked.append(s)
    if not marked:
        return None
    return (f"{len(marked)} snapshot(s) on this branch's history could not name every file they left out (the newest: "
            f"{marked[0]['ref'].rsplit('/', 1)[-1]}; status and the snapshot's warning say where), so a file they did "
            "not name may never have been stored, and recovery cannot report it")


_PLAN_GROUPS = ("identical", "missing", "reverted", "differs", "unsupported", "unrecoverable", "unsafe", "never_stored",
                "before_move", "agent_replaced")
_LOSS_GROUPS = ("unrecoverable", "never_stored", "before_move", "agent_replaced")


class _Holds:
    """The paths a snapshot speaks for, by N-01's rule: every snapshot's tree holds every tracked file, and every
    snapshot stores every designated file that exists, the committed version too, so a snapshot holds a file only
    when its own delta has it (a git item of its plan), its stored copy differs from the version committed on its
    base, or it reports the file lost. When the committed version cannot be read, as with an LFS smudge filter
    offline, the copy is not taken for a newer one, so a loss stays reported (R23-19)."""

    def __init__(self, repo: Repo):
        self.repo, self.key, self.trees, self.shas = repo, _path_key(repo), {}, {}

    def committed(self, parent: str, path: str):
        """The SHA-256 of the version committed on parent, None when there is none, False when it cannot be read."""
        if not parent:
            return None
        if parent not in self.trees:
            self.trees[parent] = {self.key(b): b for b, (mode, typ, _oid) in _snapshot_tree(self.repo, parent).items()
                                  if typ == "blob" and mode in ("100644", "100755")}
        name = self.trees[parent].get(self.key(path))
        if name is None:
            return None
        if (parent, name) not in self.shas:
            try:
                self.shas[(parent, name)] = hashlib.sha256(_checkout_bytes(self.repo, f"{parent}:{name}")).hexdigest()
            except (GitError, OSError):
                self.shas[(parent, name)] = False
        return self.shas[(parent, name)]

    def of(self, snap: dict, plan: dict) -> set:
        out = set()
        for g in _PLAN_GROUPS:
            for i in plan.get(g, []):
                if g in _LOSS_GROUPS or i.get("source") != "artifact":
                    out.add(self.key(i["path"]))
                    continue
                c = self.committed(snap.get("parent") or "", i["path"])
                if c is not False and i.get("sha256") != c:
                    out.add(self.key(i["path"]))
        return out


def _latest_notes(repo: Repo, mine: list, on_head: list, idx: int, snap: dict, plan: dict, policy: dict,
                  cache: dict, ctx: dict | None = None) -> dict:
    notes = []
    if snap.get("report_only"):
        notes.append("no snapshot was taken since history last moved here, so latest restores nothing")
    elif snap["ref"] != mine[0]["ref"]:
        # Every newer snapshot was taken since history last moved, as every snapshot taken before a move is older than
        # those taken since, and had nothing to restore (R24-29, R24-87).
        newer = mine[:[s["ref"] for s in mine].index(snap["ref"])]
        n_on = len(newer)
        text = ("chose the newest snapshot taken since history last moved with work to restore" if plan["missing"]
                or plan["reverted"] else "no snapshot taken since history last moved has work to restore, so the "
                "losses are reported with this one")
        if n_on:
            text += f"; {n_on} newer snapshot(s) had nothing to restore"
        notes.append(text)
    older = {}
    if plan["unrecoverable"] or plan["never_stored"]:
        older = {u["path"]: snap["ref"] for u in plan["unrecoverable"] + plan["never_stored"] if u.get("held_here")}
        older.update({u["path"]: u["snapshot"] for u in snap.get("unnamed_lost") or []
                      if u["path"] in {n["path"] for n in plan["never_stored"]} and u["path"] not in older})
        older.update(_older_versions(repo, on_head[idx + 1:], policy,
                                     [u["path"] for u in plan["unrecoverable"] + plan["never_stored"]
                                      if u["path"] not in older], cache=cache))
        snap = dict(snap, older_versions=[{"path": p, "snapshot": r} for p, r in older.items()])

    def hint(p):
        r = older[p].rsplit("/", 1)[-1]
        option = _recover_path_option(p) if p != '(artifact list)' else '--paths <path>'
        return f"recover apply {r} {option}"
    if plan["unrecoverable"]:
        notes.append(f"{len(plan['unrecoverable'])} item(s) cannot be restored, so recovery reports it incomplete; "
                     "pecia does not fall back to older versions on its own"
                     + "".join(f"; an older version of {u['path']} is in {older[u['path']].rsplit('/', 1)[-1]} "
                               f"(restore it explicitly with {hint(u['path'])})"
                               for u in plan["unrecoverable"] if u["path"] in older))
    if plan["never_stored"]:
        back = sum("back at its committed version" in str(u.get("why")) for u in plan["never_stored"])
        notes.append((f"{len(plan['never_stored'])} missing file(s) had a newer version that pecia never stored, so "
                      "recovery reports it incomplete; if you removed them on purpose, nothing is lost" if not back else
                      f"{len(plan['never_stored'])} file(s), missing or back at their committed version, had a newer "
                      "version that pecia never stored, so recovery reports it incomplete; if you removed them or "
                      "restored them to the committed version on purpose, nothing is lost")
                     + "".join(f"; an earlier version of {u['path']} is in {older[u['path']].rsplit('/', 1)[-1]}, "
                               f"which you can restore with {hint(u['path'])} only if that earlier version is what "
                               "you want" for u in plan["never_stored"] if u["path"] in older))
    if plan["before_move"]:
        notes.append(f"{len(plan['before_move'])} file(s) have a version of their own in a snapshot taken before history "
                     "last moved here, or in a commit history no longer holds, whose change the file does not hold now; "
                     "latest never restores across a history move, so recovery reports it incomplete. Each entry names "
                     "the snapshot or commit and the command that restores the file, or, where newer work or a later "
                     "change of history is in the way, what to make again by hand; when you have checked them, "
                     "recover ack, run by you outside an agent session, ends the report")
    if plan.get("later_recovery"):
        notes.append(f"{len(plan['later_recovery'])} file(s) that an older snapshot taken since holds, and this one does "
                     "not, come back with a further recover apply latest once this snapshot's work is restored, so "
                     "recovery reports it incomplete until then; each entry gives the command that restores it now")
    unnamed = _unnamed_note(on_head)
    if unnamed:
        notes.append(unnamed)
    note = _moved_note(ctx or {}, "; ".join(notes) if notes else None)
    out = dict(snap, note=note) if note else snap
    return out


def _fold_case(path: str) -> str:
    """The spelling a file system that ignores case compares: each character mapped on its own to its upper case, as
    NTFS does with its upcase table. Full Unicode case folding goes further and is wrong here: it makes strasse and
    the same word spelled with a sharp s one name, while NTFS keeps them as two files (J-03)."""
    return "".join(u if len(u := c.upper()) == 1 else c for c in path)


def _path_key(repo: Repo):
    """How this working tree tells two paths apart. On a file system that ignores case, as git records in
    core.ignorecase (Windows and macOS by default), data.bin and DATA.bin are one file, so a loss recorded
    under one spelling must withhold a version stored under the other (Y-02)."""
    key = getattr(repo, "_path_key", None)
    if key is None:
        r = run_git(repo.root, ["config", "--bool", "core.ignorecase"], check=False)
        key = _fold_case if r.stdout.strip() == b"true" else (lambda path: path)
        try:
            repo._path_key = key
        except AttributeError:
            pass
    return key


def _unnamed_losses(repo: Repo, snap: dict, older: list, policy: dict, kind: str,
                    cache: dict | None = None) -> list:
    """Files a snapshot may have left out without naming them (its artifact capture failed as a whole, or
    it left out more files than its list holds): those an older snapshot could restore that are absent
    from this snapshot's tree and artifact list. kind artifacts looks at designated files only; kind all
    also at files that were untracked when the older snapshot was taken (R16-01). Every older snapshot with
    distinct content is looked at, however far back: a bound would hide a loss whose older version lies
    beyond it and let recovery report itself complete (C-03). Plans are shared through cache."""
    key = _path_key(repo)
    try:
        have = {key(p) for p in set(_snapshot_tree(repo, snap["commit"]))
                | set(artifact_inventory(repo, policy, snap["commit"])["files"])}
    except (PeciaError, OSError):
        have = set()
    found, seen, found_k = {}, set(), set()
    for o in older:
        sig = (o["tree"], o["parent"], o["artifacts"], o["branch"])
        if sig in seen:
            continue
        seen.add(sig)
        plan = _plain_plan(repo, o, policy, cache)
        if plan is None:
            continue
        for i in plan["missing"] + plan["reverted"]:
            p = i["path"]
            if key(p) in have or key(p) in found_k:
                continue
            if i.get("source") == "artifact" or (kind == "all" and i.get("new")) or kind == "tracked":
                found[p] = o["ref"]
                found_k.add(key(p))
    return [{"path": p, "snapshot": r} for p, r in sorted(found.items())]


def _plain_plan(repo: Repo, snap: dict, policy: dict, cache: dict | None):
    """The plan of an older snapshot as it stands, once per snapshot within one latest search (R17-02)."""
    key = snap["commit"]
    if cache is not None and key in cache:
        return cache[key]
    try:
        plan = recover_plan(repo, {k: v for k, v in snap.items() if k not in
                                   ("implicit", "suspect", "withheld", "unnamed_lost")}, policy)
    except (PeciaError, OSError):
        plan = None
    if cache is not None:
        cache[key] = plan
    return plan


def _older_versions(repo: Repo, older: list, policy: dict, lost: list, limit: int = 20,
                    cache: dict | None = None) -> dict:
    """{path: ref} of the newest older snapshot that could restore each lost path; for an unreadable
    artifact list, the newest older snapshot with anything restorable. Looks at most limit snapshots."""
    found, seen, key = {}, set(), _path_key(repo)
    for snap in older:
        if len(found) == len(set(lost)) or limit <= 0:
            break
        sig = (snap["tree"], snap["parent"], snap["artifacts"], snap["branch"])
        if sig in seen:
            continue
        seen.add(sig)
        limit -= 1
        plan = _plain_plan(repo, snap, policy, cache)
        if plan is None:
            continue
        avail = {key(i["path"]) for i in plan["missing"] + plan["reverted"]}
        for p in lost:
            if p not in found and (key(p) in avail or (p == "(artifact list)" and avail)):
                found[p] = snap["ref"]
    return found


def _num(value, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _loss_keepers(repo: Repo, policy: dict, snaps: list, doomed) -> set:
    """Snapshots retention must keep for what they record as lost (X-03). A snapshot that reports a file it
    never stored is what stops latest from restoring an older version of that file in its place (R13-02). For
    each lost file, and for a snapshot that could not name everything it left out, the newest snapshot that
    reports it is kept while any older snapshot that stays holds that file (or, for the unnamed kind, any older
    snapshot at all), on all branches together and on its own branch. snaps is newest first; doomed(i, s) says
    whether retention would delete it."""
    reporters = [(i, s) for i, s in enumerate(snaps) if s.get("has_uncovered")]
    if not reporters or not any(doomed(i, s) for i, s in reporters):
        return set()
    newest, pkey = {}, _path_key(repo)
    for i, s in reporters:  # newest first, so the first reporter seen for a key is the newest
        own, more = _snap_uncovered(s)
        keys = [("path", pkey(p)) for p in own if p != "(designated artifacts)"]
        keys += [("flag", "all")] * bool(more) + [("flag", "artifacts")] * ("(designated artifacts)" in own)
        for k in keys:
            newest.setdefault((k, None), (i, s))
            newest.setdefault((k, s.get("branch") or ""), (i, s))
    held: dict = {}

    def holds(o, path):
        if o["ref"] not in held:
            try:
                names = {pkey(n) for n in _snapshot_tree(repo, o["commit"])}
                names |= {pkey(n) for n in artifact_inventory(repo, policy, o["commit"], o.get("_body"))["files"]}
            except (PeciaError, OSError):
                names = None  # unknown: assume it may hold the file
            held[o["ref"]] = names
        return held[o["ref"]] is None or path in held[o["ref"]]
    extra: set = set()
    grew = True
    while grew:  # a snapshot kept here can hold another lost file in its turn
        grew = False
        for ((kind, key), branch), (i, s) in newest.items():
            if s["ref"] in extra or not doomed(i, s):
                continue
            for j in range(i + 1, len(snaps)):
                o = snaps[j]
                if (doomed(j, o) and o["ref"] not in extra) or (branch is not None and (o.get("branch") or "") != branch):
                    continue
                if kind == "flag" or holds(o, key):
                    extra.add(s["ref"])
                    grew = True
                    break
    return extra


def prune_snapshots(repo: Repo, policy: dict, protect: str | None = None) -> int:
    """Retention: delete beyond retain_count; delete beyond min_keep when older than retain_days.
    Never delete the ref just created, and always keep the newest work-carrying snapshots."""
    spol = policy["snapshot"]
    keep_n = max(1, int(_num(spol.get("retain_count"), 200)))
    min_keep = max(1, int(_num(spol.get("min_keep"), 20)))
    keep_work = min(keep_n, max(1, int(_num(spol.get("keep_work"), 10))))
    cutoff = time.time() - _num(spol.get("retain_days"), 14) * 86400
    snaps = list_snapshots(repo)
    kinds = _work_kinds(repo, snaps)
    # Separate budgets, so a stream of new artifact versions can never push out the snapshots that
    # hold uncommitted edits, and the reverse.
    keep = set([s["ref"] for s in snaps if kinds.get(s["ref"], (False, False))[0]][:keep_work])
    keep |= set([s["ref"] for s in snaps if kinds.get(s["ref"], (False, False))[1]][:keep_work])
    if protect:
        keep.add(protect)
    # A capture-failure record ends only by recover ack, never by retention (RP-01, C17 requirement 6).
    keep |= {s["ref"] for s in snaps if s.get("gap")}

    def doomed(i, s):
        return i != 0 and s["ref"] not in keep and (i >= keep_n or (i >= min_keep and s["time"] < cutoff))
    keep |= _loss_keepers(repo, policy, snaps, doomed)
    if any(doomed(i, s) for i, s in enumerate(snaps)):
        # The snapshots an INCOMPLETE recovery named under later_recovery, kept until a recovery completes, from the
        # record that recovery wrote; no latest search runs here (XA1-09). A record that cannot be read keeps them all.
        named = _later_named(repo)
        if named is None:
            repo.log_event("later_record_unreadable")
        keep |= {s["ref"] for s in snaps} if named is None else named
    deleted = 0
    for i, s in enumerate(snaps):
        if i == 0 or s["ref"] in keep:
            continue
        if i >= keep_n or (i >= min_keep and s["time"] < cutoff):
            if run_git(repo.root, ["update-ref", "-d", s["ref"], s["commit"]], check=False).returncode == 0:
                deleted += 1
    if deleted:
        try:
            gc_artifact_store(repo, policy)
        except UnsafePath as e:  # the snapshot itself is already recorded; deleting nothing is safe
            repo.log_event("artifact_gc_refused", error=str(e))
    return deleted


_GIT_VERSION = None


def git_version() -> tuple:
    global _GIT_VERSION
    if _GIT_VERSION is None:
        p = subprocess.run([_git_exe(), "version"], capture_output=True, stdin=subprocess.DEVNULL)
        m = re.search(rb"(\d+)\.(\d+)", p.stdout)
        _GIT_VERSION = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
    return _GIT_VERSION


def _sparse_flag() -> list[str]:
    # Without --sparse, git add silently skips paths outside a sparse-checkout cone (git 2.34+).
    return ["--sparse"] if git_version() >= (2, 34) else []


def _add_untracked(repo: Repo, env: dict, paths: list[str]) -> list[str]:
    lit = dict(env, GIT_LITERAL_PATHSPECS="1")
    if not paths:
        return []
    p = run_git(repo.root, ["add", *_sparse_flag(), "--pathspec-from-file=-", "--pathspec-file-nul"], env=lit,
                input_bytes=nul_join(paths), check=False)
    if p.returncode == 0:
        return []
    failed = []
    for rel in paths:
        if not os.path.lexists(repo.path(rel)):
            continue
        q = run_git(repo.root, ["add", *_sparse_flag(), "--", rel], env=lit, check=False)
        if q.returncode != 0:
            failed.append(rel)
    return failed


_SPECIAL_SKIP = "not a regular file (a pipe, socket or device)"


def _add_tracked_changes(repo: Repo, env: dict, check: bool) -> list[dict] | None:
    """git add -u into the scratch index. git refuses the whole update when a tracked path is now a
    pipe, socket or device, which lost every snapshot while one was there (R10-07). Those paths are
    then left at their last staged version and reported, and everything else is added. Returns the
    skipped paths. A path git still refuses for another reason, such as a file this user cannot read,
    is reported as not covered and the rest is staged."""
    if run_git(repo.root, ["add", "-u", *_sparse_flag()], env=env, check=False).returncode == 0:
        return []
    d = run_git(repo.root, ["diff", "--name-only", "-z"], env=env, check=False)
    if d.returncode != 0:
        # git diff can fail on the same cause, such as a required filter that is not installed (Git
        # LFS without git-lfs on the hooks' PATH). ls-files compares file metadata only.
        d = run_git(repo.root, ["ls-files", "-z", "-m", "-d"], env=env, check=False)
    if d.returncode != 0:  # the scratch index itself is unusable: the caller rebuilds it from HEAD
        if check:
            run_git(repo.root, ["add", "-u", *_sparse_flag()], env=env)
        return None
    changed = sorted(set(z_split(d.stdout)))
    special, ok = [], []
    for rel in changed:
        try:
            mode = os.lstat(repo.path(rel)).st_mode
        except FileNotFoundError:
            ok.append(rel)  # deleted: add -u records the deletion
            continue
        except OSError:
            special.append(rel)
            continue
        (ok if stat_mod.S_ISREG(mode) or stat_mod.S_ISLNK(mode) or stat_mod.S_ISDIR(mode) else special).append(rel)
    skipped = [{"path": rel, "why": _SPECIAL_SKIP} for rel in special]
    if not ok:
        return skipped
    lit = dict(env, GIT_LITERAL_PATHSPECS="1")
    if run_git(repo.root, ["add", "-u", *_sparse_flag(), "--pathspec-from-file=-", "--pathspec-file-nul"],
               env=lit, input_bytes=nul_join(ok), check=False).returncode == 0:
        return skipped
    # Something else stops git, such as a file this user cannot read or a filter that is not installed.
    # Stage each path on its own; one that git still refuses keeps its last staged version and is
    # reported as not covered, instead of losing the whole snapshot.
    for rel in ok:
        r = run_git(repo.root, ["add", "-u", *_sparse_flag(), "--", rel], env=lit, check=False)
        if r.returncode != 0:
            err = (r.stderr.decode("utf-8", "replace").strip().splitlines() or ["git add failed"])[0]
            skipped.append({"path": rel, "why": f"git could not stage it: {err[:200]}"})
    return skipped


def _copy_keeping_time(src: Path, dest: Path, times_ns: tuple | None = None) -> None:
    """Copy src to the new file dest, made by name in dest's held folder (R13-08), keeping src's
    modification time as shutil.copy2 did, or giving it times_ns (access, modification) instead."""
    st = os.stat(src)
    times_ns = times_ns or (st.st_atime_ns, st.st_mtime_ns)
    with _held_dir(dest.parent) as d, _open_regular(src) as inp:
        fd = d.open_fd(dest.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "wb") as out:
            shutil.copyfileobj(inp, out, 1 << 20)
            out.flush()
            if os.utime in os.supports_fd:
                os.utime(out.fileno(), ns=times_ns)
        if os.utime not in os.supports_fd:
            # Windows: the folder is held, and the time is set through a handle on the file itself while it still
            # has one name, so a link put in its place after the write is refused (X-08).
            if IS_WINDOWS:
                _win_set_attrs(d.path / dest.name, times_ns=times_ns)
            else:
                os.utime(dest, ns=times_ns)


def _staging_env(index: Path) -> dict:
    """The environment of the git calls that stage a snapshot into its scratch index. git decides whether to read a
    tracked file again from the stat data its index entry records, under the repository's core.trustctime and
    core.checkStat; with trustctime off or checkStat minimal, a file rewritten in place at the same size whose
    modification time was put back looked unchanged, and its new version never reached a snapshot (XA1-10). These calls
    compare every stat field git records, whatever the repository sets. The settings travel in GIT_CONFIG_PARAMETERS,
    the variable git's own -c options are passed in, which every git pecia supports reads; settings already there are
    kept, with these last."""
    ours = "'core.trustctime=true' 'core.checkstat=default'"
    inherited = os.environ.get("GIT_CONFIG_PARAMETERS", "").strip()
    return {"GIT_INDEX_FILE": str(index), "GIT_CONFIG_PARAMETERS": f"{inherited} {ours}" if inherited else ours}


# The time given to the scratch index on a periodic rehash: one second after the epoch (a zero time would mean no time
# at all to git). Every entry whose file is not older than it is racily clean by git's rule, so git add -u reads each
# tracked file again and compares it by content, which covers a rewrite no stat field reveals, as where the change time
# a system reports is the creation time (XA1-10, concern XA1/S-1).
_BY_CONTENT_NS = (1_000_000_000, 1_000_000_000)


def _seed_scratch_index(repo: Repo, env: dict, head, by_content: bool = False) -> list[dict]:
    index_path = Path(env["GIT_INDEX_FILE"])
    real_index = repo.git_path("index")
    if real_index.exists():
        try:
            # copy2 keeps the index file's modification time. Git rechecks by content any entry whose
            # file is not older than the index itself (the racy-git rule); a fresh copy time would
            # make such entries look settled, and a same-size edit made within the same second as
            # the last staging would never reach a snapshot. On a periodic rehash the copy is made older
            # than every file instead, so every entry is rechecked by content (XA1-10).
            _copy_keeping_time(real_index, index_path, _BY_CONTENT_NS if by_content else None)
            flagged = _flagged_entries(repo, env)
            if flagged:
                # Hidden edits (skip-worktree, assume-unchanged) must still be captured. The two flags
                # need separate calls: given together, update-index applies only the last one.
                for flag in ("--no-skip-worktree", "--no-assume-unchanged"):
                    run_git(repo.root, ["update-index", flag, "-z", "--stdin"],
                            env=env, input_bytes=nul_join(flagged) + b"\0", check=False)
            skipped = _add_tracked_changes(repo, env, check=False)
            if skipped is not None:
                return skipped
        except OSError:
            pass
    if index_path.exists():
        _unlink_at(index_path)
    if head:
        run_git(repo.root, ["read-tree", head], env=env)
    return _add_tracked_changes(repo, env, check=True) or []


def scratch_dir(repo: Repo, prefix: str) -> Path:
    """A private temporary directory inside this repository's git directory, so scratch files
    stay on the project's own drive and never touch the system temp folder."""
    gitdir = repo.git_dir()
    root = gitdir / "pecia-tmp"
    cutoff = time.time() - 3600
    try:  # fallback folders from a time pecia-tmp was refused (R7-09)
        for old in gitdir.glob("pecia-scratch-*"):
            if not _is_link(old) and old.is_dir() and os.lstat(old).st_mtime < cutoff:
                _rmtree_at(old)
    except OSError:
        pass
    try:
        _refuse_linked_dirs(root)  # a link here sent the cleanup below into another folder (T-01)
    except UnsafePath as e:
        # Snapshots go on in a fresh folder that mkdtemp creates; nothing is cleaned up through the
        # link, and doctor reports it.
        repo.log_event("scratch_folder_refused", error=str(e))
        with _held_dir(gitdir) as d:
            return gitdir / d.new_folder("pecia-scratch-" + prefix)
    _held_dir(root, create=True).close()
    for old in root.iterdir():
        try:
            # Only stale folders pecia made itself: real folders named by its own prefixes.
            if (not _is_link(old) and old.is_dir() and re.match(r"(snap|nohooks|merge)-", old.name)
                    and os.lstat(old).st_mtime < cutoff):
                _rmtree_at(old)
        except OSError:
            pass
    with _held_dir(root, create=True) as d:  # made by name in the held folder (R13-08)
        return root / d.new_folder(prefix)


def _work_signature(repo: Repo, paths) -> dict:
    sig = {}
    for rel in paths:
        try:
            st = os.lstat(repo.path(rel))
            sig[rel] = (st.st_size, st.st_mtime_ns)
        except OSError:
            sig[rel] = None
    return sig


def _stage_tree(repo: Repo, env: dict, head, excludes, limit: int, spol: dict,
                by_content: bool = False) -> tuple[str, list[dict]]:
    """Build the snapshot tree in the scratch index and return (tree id, skipped paths). With by_content (the periodic
    rehash), every tracked file is compared by content, not by its stat data (XA1-10)."""
    skipped: list[dict] = []
    index = Path(env["GIT_INDEX_FILE"])
    if index.exists():
        _unlink_at(index)
    skipped += _seed_scratch_index(repo, env, head, by_content)
    listing = run_git(repo.root, ["ls-files", "-z", "--others", "--exclude-standard"],
                      env=dict(env, LC_ALL="C", LANGUAGE="C"))
    untracked = z_split(listing.stdout)
    # git lists what it can and still exits 0 when it cannot open a folder, saying so only in a warning, so the
    # untracked files there would be left out without a word (E1-03). The messages are read in English.
    unopened = _git_unopened(repo, listing.stderr.decode("utf-8", "surrogateescape"))
    if unopened:
        names = ", ".join(unopened[:3]) + (f" and {len(unopened) - 3} more" if len(unopened) > 3 else "")
        skipped.append({"path": UNLISTED_UNTRACKED,
                        "why": f"git could not open {names}, so untracked files there are not in this snapshot and "
                               "it cannot name them; check that this account can read every folder in the tree"})
    to_add = []
    for rel in untracked:
        if is_excluded(rel, excludes):
            skipped.append({"path": rel, "why": "excluded"})
            continue
        if rel.endswith("/") and _own_worktree_folder(repo, rel):
            # git lists a worktree of this repository nested here as one folder, and adding it records only a gitlink,
            # which recovery then reported as an unsupported submodule entry after every restore (G1-06). Its files
            # are snapshotted in that worktree itself (G1-05).
            skipped.append({"path": rel, "why": _OWN_WORKTREE_SKIP})
            continue
        try:
            size = os.lstat(repo.path(rel)).st_size
        except FileNotFoundError:
            continue  # gone since git listed it
        except OSError as e:
            skipped.append({"path": rel, "why": f"could not be read: {e.strerror or e}"})  # R24-05
            continue
        if size > limit:
            skipped.append({"path": rel, "why": f"untracked file over {spol['max_untracked_file_mb']} MB"})
            continue
        to_add.append(rel)
    for rel in _add_untracked(repo, env, to_add):
        skipped.append({"path": rel, "why": "git add failed"})
    tracked = z_split(run_git(repo.root, ["ls-files", "-z", "--cached"], env=env).stdout)
    # git add -u, like git status, exits 0 when it cannot read a tracked file, as in a folder this account may list but
    # not search, and keeps the file's last staged version without a word (R24-06).
    for rel in tracked:
        try:
            os.lstat(repo.path(rel))
        except (FileNotFoundError, NotADirectoryError):
            pass
        except OSError as e:
            if not is_excluded(rel, excludes):
                skipped.append({"path": rel, "why": f"git could not stage it: {e.strerror or e}"})
    drop = [p for p in tracked if is_excluded(p, excludes)]
    if drop:
        run_git(repo.root, ["rm", "--cached", "-q", "-f", "--ignore-unmatch",
                            "--pathspec-from-file=-", "--pathspec-file-nul"],
                env=dict(env, GIT_LITERAL_PATHSPECS="1"), input_bytes=nul_join(drop))
        skipped += [{"path": p, "why": "tracked but excluded"} for p in drop]
    return git_text(repo.root, "write-tree", env=env), skipped


_OWN_WORKTREE_SKIP = "a worktree of this repository, snapshotted on its own"
_DELIBERATE_SKIPS = ("excluded", "excluded by snapshot.exclude_globs", "tracked but excluded", _SPECIAL_SKIP,
                     _OWN_WORKTREE_SKIP)


def _own_worktree_folder(repo: Repo, rel: str) -> bool:
    """Whether the folder rel holds a .git file naming a worktree record of repo's own repository."""
    try:
        dot = repo.path(rel.rstrip("/")) / ".git"
        if _is_link(dot) or not dot.is_file():
            return False
        text = _read_regular(dot, 4096).decode("utf-8", "surrogateescape").strip()
        if not text.startswith("gitdir:"):
            return False
        target = Path(text[7:].strip())
        target = (target if target.is_absolute() else dot.parent / target).resolve()
        if target.parent != (repo.common_dir() / "worktrees").resolve():
            return False
        # git's record must name this very folder: a copy of a worktree's folder carries the same .git file, and is
        # no worktree, so its files would be in no snapshot (IR31-04).
        return _admin_record(target).resolve() == dot.resolve()
    except (OSError, PeciaError, ValueError):
        return False


_SHRINK_WHY = ("the previous snapshot stored it as a designated artifact and no artifacts.include_globs pattern matches it "
               "now, so this version was not stored; if you took it out of the designation on purpose, nothing is lost")


def _designation_shrink(repo: Repo, policy: dict, last, arts: dict, excludes, tree: str, skipped: list) -> list[dict]:
    """The files the previous snapshot of this working tree stored as designated artifacts that this one leaves out
    because the designation no longer names them, whatever the cause: an artifacts section that is not an object, a
    pattern rewritten or removed, or a designation pecia cannot read. Each is reported as not covered, so recovery
    withholds the older stored copy and says the newest version was never stored, instead of restoring the older copy as
    complete (XA1-05, XA1-07). Only files that exist now, are not excluded, are not in this snapshot's tree and are not
    reported already. The comparison is with the previous snapshot only, so a deliberate narrowing is reported once, by
    the snapshot that first leaves the file out; its Pecia-Uncovered line keeps recovery truthful after that."""
    try:
        if not last or last.get("artifacts") in (None, "", "none"):
            return []
        before = artifact_inventory(repo, policy, last["commit"])["files"]
        if not before:
            return []
        apol = policy.get("artifacts") if isinstance(policy.get("artifacts"), dict) else {}
        raw = apol.get("include_globs")
        readable = isinstance(raw, list) and not isinstance(raw, _UnreadableDesignation)
        pats = [g for g in raw if isinstance(g, str)] if readable else None
        said = {s.get("path") for s in skipped}
        stored = arts.get("files") or {}
        cands = []
        for rel in sorted(before):
            if rel in stored or rel in said or is_excluded(rel, excludes):
                continue
            if pats is not None and match_any(rel, pats):
                continue  # still designated: what kept it out is reported where it happened
            try:
                st = os.lstat(repo.path(rel))
            except (OSError, ValueError, PeciaError):
                continue
            if stat_mod.S_ISREG(st.st_mode):
                cands.append(rel)
        if not cands:
            return []
        # A file now in the snapshot's own tree, as one taken out of .gitignore, is covered there.
        named_ = ["--", *cands] if len(cands) <= 200 else []  # a long list: the whole tree, not a long command line
        held = set(z_split(run_git(repo.root, ["ls-tree", "-r", "-z", "--name-only", tree, *named_],
                                   env={"GIT_LITERAL_PATHSPECS": "1"}, check=False).stdout))
        why = _SHRINK_WHY if pats is not None else (getattr(raw, "why", None) or _SHRINK_WHY)
        return [{"path": rel, "why": why} for rel in cands if rel not in held]
    except Exception as e:  # noqa: BLE001 - never lose the snapshot to this check; say it could not be made
        repo.log_event("designation_check_failed", error=f"{type(e).__name__}: {e}")
        return [{"path": "(designated artifacts)",
                 "why": f"pecia could not compare this designation with the previous snapshot's: {type(e).__name__}"}]


# ---------------------------------------------------------------- capture-failure records (RP-01)

_GAP_REASON = "capture-failed"
_GAP_UNLISTED_DESIGNATION = "designated artifacts: the designation could not be read"


def _gap_excludes(repo: Repo) -> list:
    """What a capture-failure record leaves out of the paths it names: the built-in exclusions, those of the recorded
    policy copy, and those of the working tree's policy when it can be read, so a secret file is never reported as lost
    (C17 requirement 2)."""
    ex = list(DEFAULT_POLICY["snapshot"]["exclude_globs"]) + [RUNTIME_REL + "/**", "**/.pecia-restore-*"]
    sources = []
    try:
        sources = [p for p in (recorded_policy_path(repo, create=False), _main_tree_recorded_policy(repo), policy_source(repo))
                   if p is not None]
    except (PeciaError, OSError):
        pass
    for src in sources:
        try:
            if _is_link(src) or not src.is_file():
                continue
            data = json.loads(_read_regular(src, _TEXT_LIMIT).decode("utf-8"))
            sp = data.get("snapshot") if isinstance(data, dict) else None
            globs = sp.get("exclude_globs") if isinstance(sp, dict) else None
            globs = [globs] if isinstance(globs, str) else globs
            if isinstance(globs, list):
                ex += [g for g in globs if isinstance(g, str)]
        except (OSError, ValueError, RecursionError, PeciaError):
            continue
    return ex


def _error_text(error) -> str:
    text = str(error) if isinstance(error, PeciaError) else f"{type(error).__name__}: {error}"
    return _one_line(text).strip()[:400] or type(error).__name__


def record_capture_failure(repo: Repo, reason: str, agent, error, policy_cause: bool = False) -> dict | None:
    """Record a capture that failed: a commit kept by a ref in this working tree's snapshot namespace, holding no content
    of its own (its tree is HEAD's), that names the paths git status lists as changed at the failure as not covered, and
    says what it could not name. Recovery then reports those paths' newest versions as never stored instead of restoring
    an older version as complete, and status, doctor and recover list the record until recover ack (RP-01, the C17
    design of triage revision 2, requirements 1 to 9). Never raises; returns what it recorded, or None."""
    try:
        return _record_capture_failure(repo, reason, agent, error, policy_cause)
    except BaseException as e:  # noqa: B036 - recording must never take a hook or a loop down
        try:
            repo.log_event("capture_failure_unrecorded", reason=reason, error=f"{type(e).__name__}: {e}")
        except BaseException:  # noqa: B036
            pass
        return None


def _record_capture_failure(repo: Repo, reason: str, agent, error, policy_cause: bool) -> dict:
    cause = _error_text(error)
    reason, agent = _one_line(reason), (_one_line(agent) if agent else None)
    # Placed like a snapshot taken now: HEAD's reflog read before git status, then HEAD and the line (requirement 5).
    seen: list = []
    mark = _reflog_mark(repo, seen)
    head, branch = repo.head(), _line_branch(repo)
    detached = bool(branch) and repo.branch() is None
    excludes = _gap_excludes(repo)
    named: dict = {}
    unnamed: list = []
    tracked_unknown = False
    try:
        entries = status_entries(repo)
        for _code, rel in entries:
            if is_excluded(rel, excludes) or (policy_cause and rel == POLICY_REL):
                # The policy that could not be used is the cause the record names; its unusable bytes are no work.
                continue
            named.setdefault(rel, f"a capture failed ({reason}) and this changed file was not stored")
        if getattr(entries, "unopened", None):
            unnamed.append("untracked files in folders git could not open: " + ", ".join(entries.unopened[:3]))
    except Exception as e:  # noqa: BLE001 - git status itself failed: nothing can be named, tracked files included
        unnamed.append(f"git status failed: {_error_text(e)}")
        tracked_unknown = True
    snaps = list_snapshots(repo)
    good = next((s for s in snaps if not s.get("gap")), None)
    # Designated files are ignored files, which git status does not list: those the last good snapshot stored that exist
    # now are named; when the designation cannot be read, the rest cannot be named (requirements 2 and 3).
    try:
        designation, pol = None, None
        try:
            pol = load_policy(repo)
            designation = pol["artifacts"].get("include_globs")
        except Exception:  # noqa: BLE001
            designation = None
        if designation is None or isinstance(designation, _UnreadableDesignation):
            unnamed.append(_GAP_UNLISTED_DESIGNATION)
        if good and good.get("artifacts") not in (None, "", "none"):
            for rel in sorted(artifact_inventory(repo, pol or {"artifacts": {}}, good["commit"])["files"]):
                if rel in named or is_excluded(rel, excludes):
                    continue
                try:
                    if stat_mod.S_ISREG(os.lstat(repo.path(rel)).st_mode):
                        named[rel] = f"a capture failed ({reason}) and this designated file was not stored"
                except (OSError, ValueError, PeciaError):
                    continue
        if designation and not isinstance(designation, _UnreadableDesignation):
            pats = [g for g in designation if isinstance(g, str)]
            for rel in walk_artifact_candidates(repo, pats, pol["artifacts"].get("prune_dirs") or []):
                if rel not in named and not is_excluded(rel, excludes):
                    named[rel] = f"a capture failed ({reason}) and this designated file was not stored"
    except Exception as e:  # noqa: BLE001
        unnamed.append(f"designated artifacts could not be listed: {_error_text(e)}")
    newest = snaps[0] if snaps else None
    prev = newest.get("gap") if newest else None
    collapse = bool(prev) and (newest.get("parent") or "") == (head or "") and \
        (newest.get("branch") or "(detached or unborn)") == (branch or "(detached or unborn)")
    now = iso()
    if collapse:
        # Failures before the next successful snapshot collapse into one record: a count, the first and last time, the
        # last cause, and the union of named paths and of what could not be named (requirement 7).
        own, _more = _snap_uncovered(newest) if newest.get("has_uncovered") else ([], 0)
        for rel in own:
            if rel != "(designated artifacts)":
                named.setdefault(rel, f"a capture failed ({reason}) and this changed file was not stored")
        unnamed = list(dict.fromkeys(list(prev.get("unnamed") or []) + unnamed))
        tracked_unknown = tracked_unknown or bool(prev.get("tracked"))
        mark, head = newest.get("reflog") or mark, newest.get("parent") or head
        first, count = prev.get("first") or now, int(prev.get("count") or 1) + 1
    else:
        first, count = now, 1
    items = [{"path": p, "why": w} for p, w in sorted(named.items())]
    if len(items) > _UNCOVERED_MAX:
        unnamed.append(f"the list of changed paths was cut off at {_UNCOVERED_MAX}")
        tracked_unknown = True
    if any(u == _GAP_UNLISTED_DESIGNATION or u.startswith("designated artifacts could not") for u in unnamed):
        items.append({"path": "(designated artifacts)", "why": "the designation could not be read"})
    if tracked_unknown or any(u.startswith("untracked files in folders") for u in unnamed):
        items.append({"path": UNLISTED_UNTRACKED, "why": "not every changed file could be listed"})
    gap = {"count": count, "first": first, "last": now, "cause": cause, "event": reason, "agent": agent,
           "last_good": good["ref"] if good else None, "named": len(named), "unnamed": unnamed,
           "tracked": tracked_unknown}
    msg = "\n".join([
        f"pecia capture failure: {reason}", "",
        f"Pecia-Version: {VERSION}",
        f"Pecia-Reason: {_GAP_REASON}",
        # The agent is kept in the record for display only: a record is no capture by that agent (requirement 4).
        "Pecia-Agent: -",
        f"Pecia-Worktree: {_one_line(fwd(repo.root))}",
        f"Pecia-Branch: {branch or '(detached or unborn)'}",
        *(["Pecia-Detached: yes"] if detached else []),
        f"Pecia-Head: {head or '(unborn)'}",
        f"Pecia-Reflog: {mark}",
        "Pecia-Artifacts: none 0",
        f"Pecia-Skipped: {len(named)}",
        "Pecia-Stable: no",
        f"Pecia-Host: {_one_line(socket.gethostname())}",
        f"Pecia-Gap: {json.dumps(gap, sort_keys=True, ensure_ascii=True)}",
        *_uncovered_lines(items), "",
    ])
    # No restorable content: the tree is HEAD's, never the index's or the last good snapshot's (requirement 4).
    tree = (git_text(repo.root, "rev-parse", f"{head}^{{tree}}") if head else
            run_git(repo.root, ["mktree"], input_bytes=b"").stdout.decode().strip())
    stamp_ = f"{int(time.time())} +0000"
    ident = {"GIT_AUTHOR_NAME": "pecia", "GIT_AUTHOR_EMAIL": "pecia@localhost", "GIT_COMMITTER_NAME": "pecia",
             "GIT_COMMITTER_EMAIL": "pecia@localhost", "GIT_AUTHOR_DATE": stamp_, "GIT_COMMITTER_DATE": stamp_}
    args = ["commit-tree", "--no-gpg-sign"] + (["-p", head] if head else []) + ["-F", "-", tree]
    commit = run_git(repo.root, args, env=ident, input_bytes=msg.encode("utf-8")).stdout.decode().strip()
    if collapse:
        ref = newest["ref"]
        run_git(repo.root, ["update-ref", "-m", "pecia capture failure", ref, commit, newest["commit"]])
    else:
        seq = (max((s["seq"] for s in snaps), default=0) + 1) % 10_000_000_000
        ref = (f"{REF_ROOT}/{repo.worktree_id()}/{seq:010d}-{utcnow().strftime('%Y%m%dT%H%M%S%fZ')}-"
               f"{secrets.token_hex(3)}")
        run_git(repo.root, ["update-ref", "-m", "pecia capture failure", ref, commit, repo.zero_oid()])
    try:
        repo.log_event("capture_failed", ref=ref, reason=reason, agent=agent, error=cause, count=count,
                       named=len(named), unnamed=unnamed)
    except Exception:  # noqa: BLE001
        pass
    return dict(gap, ref=ref, new=not collapse)


def _gap_before_move(repo: Repo, snap: dict, entries=None) -> bool:
    """Whether a record was taken before history last moved here, judged by its reflog mark as latest judges a
    snapshot's; for display only."""
    try:
        entries = _head_reflog(repo) if entries is None else entries
    except PeciaError:
        return False
    if not entries:
        return False
    moved = _moves(entries)
    last_move = next((i for i, m in enumerate(moved) if m), None)
    mk = snap.get("reflog")
    if not mk or mk == "none":
        return last_move is not None
    a = _mark_index(entries, mk)
    if a is None:
        return True
    return last_move is not None and a > last_move


def capture_failures(repo: Repo, snaps: list | None = None) -> list:
    """Every capture-failure record of this working tree, newest first, as status, doctor and recover list them until
    recover ack (C17 requirement 8)."""
    try:
        snaps = list_snapshots(repo) if snaps is None else snaps
        try:
            entries = _head_reflog(repo)
        except PeciaError:
            entries = []
    except (PeciaError, OSError):
        return []
    out = []
    for s in snaps:
        g = s.get("gap")
        if not g:
            continue
        out.append({"ref": s["ref"], "count": g.get("count", 1), "first": g.get("first"), "last": g.get("last"),
                    "cause": g.get("cause"), "event": g.get("event"), "agent": g.get("agent"),
                    "last_good": g.get("last_good"), "named": g.get("named", 0), "unnamed": g.get("unnamed") or [],
                    "tracked": bool(g.get("tracked")), "head": s.get("head"), "branch": s.get("branch"),
                    "before_move": _gap_before_move(repo, s, entries)})
    return out


def _gap_line(rec: dict) -> str:
    """One line for a capture-failure record, as status, doctor and recover print it."""
    when = rec.get("first") if rec.get("count", 1) == 1 else f"{rec.get('first')} to {rec.get('last')}"
    unnamed = rec.get("unnamed") or []
    return (f"WARNING a snapshot could not be taken ({rec.get('event')}, agent {rec.get('agent') or '-'}, "
            f"{rec.get('count', 1)} time(s), {when}): {rec.get('cause')}. "
            f"It named {rec.get('named', 0)} changed file(s), whose newest version recover latest reports as never stored "
            "unless a newer snapshot holds it"
            + (f"; it could not name {'; '.join(unnamed)}" if unnamed else "")
            + (", taken before history last moved here" if rec.get("before_move") else "")
            + f". recover ack, run by you outside an agent session, ends this report (record "
              f"{str(rec.get('ref', '')).rsplit('/', 1)[-1]}; last good snapshot "
              f"{str(rec.get('last_good') or 'none').rsplit('/', 1)[-1]})")


def _end_capture_failures(repo: Repo) -> list:
    """recover ack: delete every capture-failure record of this working tree, the only way one ends (C17 requirement 9).
    Returns the records ended."""
    ended = []
    for rec in capture_failures(repo):
        snap = next((s for s in list_snapshots(repo) if s["ref"] == rec["ref"]), None)
        if snap is None:
            continue
        if run_git(repo.root, ["update-ref", "-d", rec["ref"], snap["commit"]], check=False).returncode == 0:
            ended.append(rec)
    if ended:
        repo.log_event("capture_failures_acknowledged", refs=[r["ref"] for r in ended])
    return ended


def _capture_failure_message(tree: Repo, rec, error) -> str:
    """The one line a hook, watch or launch prints for a failed capture."""
    where = fwd(tree.root)
    said = "the failed capture is recorded" if rec else "pecia could not record the failed capture"
    return (f"pecia: WARNING no snapshot of {where} was taken: {_error_text(error)}; {said}, and status, doctor and "
            "recover report it until recover ack")


def _policy_problem(repo: Repo) -> str | None:
    """What makes the working tree's policy unusable as written, for doctor, which printed ok on its existence alone while
    every snapshot hook failed on it (A1a-01, XA1-15; RP-01, C17 requirement 8, RT-15). None when it parses and every
    section has its type."""
    try:
        raw = json.loads(_read_regular(repo.path(POLICY_REL), _TEXT_LIMIT).decode("utf-8"))
    except (ValueError, RecursionError) as e:
        return (f"it does not parse ({type(e).__name__}: {_one_line(str(e))[:120]}), so every snapshot fails and the guard "
                "blocks every session until it is fixed; each failed capture is recorded")
    except OSError as e:
        return f"it cannot be read as a regular file ({e.strerror or e})"
    if not isinstance(raw, dict):
        return f"it must hold a JSON object, not {_json_kind(raw)}, so every snapshot fails until it is fixed"
    warned, refused = _mistyped_sections(raw)
    if refused:
        return (f"{refused[0]}, so every snapshot fails and the guard blocks every session until it is fixed; each failed "
                "capture is recorded")
    if warned:
        return warned[0]
    return None


def _unmatched_line(pat: str) -> str:
    return (f"WARNING artifacts.include_globs pattern {json.dumps(pat)} matches no file in this working tree, so it "
            "designates nothing; if it should, write it relative to the tree root with / between folders, as "
            "out/*.json")


def _note_designation(repo: Repo, unmatched: list) -> list:
    """Record the include_globs patterns that matched no file at this snapshot attempt, for status (XA1-07). Never
    raises; returns the list."""
    try:
        path = repo.ensure_runtime() / "designation.json"
        prev = load_json(path, {}) or {}
        if prev.get("unmatched") != unmatched:
            atomic_write_json(path, {"ts": time.time(), "unmatched": unmatched})
            if unmatched:
                repo.log_event("designation_matches_nothing", patterns=unmatched[:50])
    except Exception:  # noqa: BLE001
        pass
    return unmatched


def _note_coverage(repo: Repo, skipped: list[dict], excluded: list | None = None) -> list[dict]:
    """Return the skipped files that were left out for a reason other than a deliberate exclusion
    (too large, unreadable, changing while copied), record them for status and doctor, and log an
    event whenever that set changes. The tracked files a default secret pattern excluded are recorded beside them,
    for status, with an event when that set changes (XA1-13). Never raises."""
    uncovered = [s for s in skipped if s.get("why") not in _DELIBERATE_SKIPS]
    try:
        path = repo.ensure_runtime() / "coverage.json"
        prev = load_json(path, {}) or {}
        paths = sorted(s["path"] for s in uncovered)
        excluded = list(excluded or [])
        was_excluded = prev.get("excluded_tracked") or []
        if paths != prev.get("paths") or excluded != was_excluded:
            atomic_write_json(path, {"ts": time.time(), "paths": paths, "items": uncovered[:200],
                                     "excluded_tracked": excluded})
            if paths and paths != prev.get("paths"):
                repo.log_event("work_not_covered", count=len(paths), items=uncovered[:200])
            if excluded and excluded != was_excluded:
                repo.log_event("tracked_excluded_by_default", count=len(excluded), items=excluded[:200])
    except Exception:
        pass
    return uncovered


def uncovered_warning(uncovered: list[dict], limit: int = 20) -> str:
    if not uncovered:
        return ""
    # A folder pecia or git could not list is an entry of its own, not a file: its line says what to do (R24-13).
    markers = [s for s in uncovered if s.get("path") in ("(designated artifacts)", UNLISTED_UNTRACKED)]
    files = [s for s in uncovered if s not in markers]
    lines = ([f"WARNING {len(files)} file(s) are not covered by any snapshot:"] if files else
             ["WARNING some files are not covered by any snapshot:"])
    lines += [f"  {s['path']} ({s['why']})" for s in (markers + files)[:limit]]
    if len(uncovered) > limit:
        lines.append(f"  ... and {len(uncovered) - limit} more (see pecia snapshot --json)")
    unusable = [s for s in files if str(s.get("why", "")).startswith("artifact store unusable")]
    unstored = [s for s in files if str(s.get("why", "")).startswith(("could not be stored", "could not be read",
                                                                        "git could not stage it"))]
    if unusable:
        lines.append("  The artifact store cannot be used; run pecia doctor for the fix. The rest of the working tree "
                     "was snapshotted.")
    if unstored:
        lines.append("  Make sure pecia can read those files and write to the artifact store (pecia doctor names "
                     "it); the error is on each line. The rest of the working tree was snapshotted.")
    if len(unusable) + len(unstored) < len(files):
        lines.append("  Raise snapshot.max_untracked_file_mb, add them to artifacts.include_globs, or commit them.")
    return "\n".join(lines)


_SNAP_LOCK_WAIT_S = 90


class _NoOsLock(Exception):
    pass


def _os_try_lock(fd: int) -> bool:
    """A non-blocking exclusive lock held by the operating system on an open file. It is released
    when the descriptor closes, including when its process dies or is killed, so no process id,
    start time, age limit or zombie state has to be judged."""
    if IS_WINDOWS:
        import msvcrt
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError as e:
            if e.errno in (errno.EACCES, errno.EDEADLK, getattr(errno, "EDEADLOCK", errno.EDEADLK)):
                return False
            raise _NoOsLock(str(e)) from e
    import fcntl
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False
    except OSError as e:
        raise _NoOsLock(str(e)) from e


def _os_unlock(fd: int) -> None:
    try:
        if IS_WINDOWS:
            import msvcrt
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass  # closing the descriptor releases it anyway


_LOCK_FLAGS = (os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
               | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_BINARY", 0))


def _lock_candidates(lock: Path):
    yield lock
    for i in range(1, 8):
        yield lock.with_name(f"{lock.stem}-{i}{lock.suffix}")


def _open_lock_file(lock: Path):
    """Open the lock file every snapshot of this tree uses, or None. The first of a fixed list of names
    that is a regular file, or that can be created, is used, so racing processes always agree on it.
    An entry that is a link, a pipe or a folder is skipped and left where it is, never followed,
    renamed or replaced: renaming it aside let racing processes each lock a file of their own (R11-03),
    and on Windows, which has no O_NOFOLLOW, opening it could create or lock a file outside the
    repository (R11-01). Content is never read or written; a hard-linked name is skipped all the same."""
    try:
        held = _held_dir(lock.parent)
    except (OSError, PeciaError):
        return None
    with held as d:  # the folder is held, so the names below are looked up where they were checked
        for cand in _lock_candidates(lock):
            name = cand.name
            for _ in range(5):
                try:
                    st = d.lstat(name)
                except FileNotFoundError:
                    try:
                        fd = d.open_fd(name, _LOCK_FLAGS | os.O_CREAT | os.O_EXCL, 0o644)
                    except FileExistsError:
                        continue  # another process created it first: look again
                    except OSError:
                        break
                    return fd
                except OSError:
                    break
                if not stat_mod.S_ISREG(st.st_mode) or st.st_nlink > 1:
                    # Not usable: the next name. A hard-linked file is skipped too, because the byte-range
                    # lock Windows takes is mandatory and would block other programs' use of the linked file.
                    break
                try:
                    fd = d.open_fd(name, _LOCK_FLAGS)
                except FileNotFoundError:
                    continue
                except OSError:
                    break
                fst = os.fstat(fd)
                if stat_mod.S_ISREG(fst.st_mode) and fst.st_nlink <= 1:
                    return fd
                os.close(fd)
                break
    return None


def _one_line(text) -> str:
    """A value for one line of a snapshot message. Control characters and line or paragraph separators become
    spaces, so a reason or an agent name cannot end its line and start a line of pecia's own, or split a record
    when the message is read back (C-05). Unpaired surrogates, which cannot be stored as UTF-8, become spaces
    too."""
    return "".join(" " if unicodedata.category(ch) in ("Cc", "Zl", "Zp", "Cs") else ch for ch in str(text))


def take_snapshot(repo: Repo, reason: str, agent: str | None = None, policy: dict | None = None,
                  force: bool = False, rehash: bool = False) -> dict:
    """One snapshot at a time per working tree (R5-05). The lock is held by the operating system on snapshot.lock in
    pecia's folder in this working tree's git directory, where git clean -fdx cannot remove it while a snapshot holds
    it (N-04), and then on .pecia/runtime/snapshot.lock, the one 0.1.2rc12 and earlier lock, so an older and a newer
    pecia still take turns during an upgrade. Always in that order, so two snapshots never wait on each other. A
    killed, crashed or zombie snapshot never leaves a lock behind, and a live snapshot keeps it however long it runs
    (IR-42, U-05, U-07). The files' content is never read or written. Where no lock can be taken, snapshots go
    ahead without one and the event is logged."""
    held = []
    try:
        for lock in _snapshot_lock_paths(repo):
            fd = _open_lock_file(lock)
            if fd is None:
                repo.log_event("snapshot_lock_unusable", path=fwd(lock))
                continue
            held.append([fd, False])
            deadline = time.time() + _SNAP_LOCK_WAIT_S
            while True:
                try:
                    if _os_try_lock(fd):
                        held[-1][1] = True
                        break
                except _NoOsLock as e:
                    repo.log_event("snapshot_lock_unsupported", error=str(e))
                    break
                if time.time() > deadline:
                    raise PeciaError(f"another snapshot of this working tree has been running for over "
                                     f"{_SNAP_LOCK_WAIT_S} s ({fwd(lock)}); try again shortly")
                time.sleep(0.1)
        return _take_snapshot_unlocked(repo, reason, agent, policy, force, rehash)
    finally:
        for fd, locked in reversed(held):
            if locked:
                _os_unlock(fd)
            os.close(fd)


def _snapshot_lock_paths(repo: Repo) -> list:
    """The snapshot lock in pecia's folder in this working tree's git directory, then the one in .pecia/runtime."""
    out = []
    try:
        repo.common_dir()  # registered first, so a linked tree's git directory is reached as a child of it
        folder = repo.git_dir() / LEASE_NAMES[0]
        if _is_link(folder):
            raise PeciaError(f"{fwd(folder)} is a symlink or junction")
        _held_dir(folder, create=True).close()
        out.append(folder / "snapshot.lock")
    except (OSError, PeciaError) as e:
        repo.log_event("snapshot_lock_unusable", error=str(e))
    out.append(repo.ensure_runtime() / "snapshot.lock")
    return out


def _take_snapshot_unlocked(repo: Repo, reason: str, agent: str | None = None, policy: dict | None = None,
                            force: bool = False, rehash: bool = False) -> dict:
    policy = policy or load_policy(repo)
    reason, agent = _one_line(reason), (_one_line(agent) if agent is not None else None)
    spol = policy["snapshot"]
    excludes = list(spol.get("exclude_globs", [])) + [RUNTIME_REL + "/**", "**/.pecia-restore-*"]
    limit = int(_num(spol.get("max_untracked_file_mb"), 25) * 1024 * 1024)
    # Where HEAD's reflog holds no entry, as with reflogs off, it is started first with one entry that moves nothing, so
    # this snapshot has a place and later moves are recorded (RP-13, register row 223).
    _seed_head_log(repo)
    # Where HEAD's reflog stood, read before HEAD and the files: a move that lands while the snapshot stages them leaves
    # the snapshot placed before it, so it never counts as taken since the move with content from before it (R24-98).
    seen: list = []
    mark = _reflog_mark(repo, seen)
    head, branch = repo.head(), _line_branch(repo)
    for _ in range(3):
        # A commit that landed between the two reads would place a snapshot taken on it before it, and settle the
        # snapshot's own work (R24-112): read both again until the newest entry is HEAD's, or until neither changes, as
        # when HEAD moved without an entry here (R24-96).
        if mark == "none" or not head or mark.split(" ")[1] == head:
            break
        again, head_again = _reflog_mark(repo, seen), repo.head()
        if (again, head_again) == (mark, head):
            break
        mark, head, branch = again, head_again, _line_branch(repo)
    # At a rebase stop the line is the branch being rebased (R24-57), with HEAD detached; recorded, so that after
    # git rebase --quit, which leaves HEAD detached there, the snapshot belongs to the detached line too (R24-65).
    detached_stop = bool(branch) and repo.branch() is None
    tmpdir = scratch_dir(repo, "snap-")
    env = _staging_env(tmpdir / "index")
    try:
        # Files an agent is editing can change while they are staged one by one. Compare the size
        # and modification time of every changed path before and after staging, retry once, and
        # otherwise record the snapshot as unstable instead of presenting a mixed state as consistent.
        stable = False
        for _ in range(2):
            watch = [p for _, p in status_entries(repo)]
            before_sig = _work_signature(repo, watch)
            # The periodic rehash compares tracked files by content too, not only artifacts (XA1-10).
            tree, skipped = _stage_tree(repo, env, head, excludes, limit, spol, by_content=rehash)
            staged = _staged_lines(repo, head)
            if _work_signature(repo, watch) == before_sig:
                stable = True
                break
        try:
            arts = capture_artifacts(repo, policy, excludes, force=force or rehash)
        except Exception as e:  # noqa: BLE001 - the tree snapshot must never be lost to an artifact problem
            # A malformed artifacts policy, or anything else unexpected while storing artifacts, leaves the
            # designated files reported as not covered; the working tree is still recorded (R10-06).
            repo.log_event("artifact_capture_failed", error=f"{type(e).__name__}: {e}")
            why = f"artifact capture failed: {type(e).__name__}: {_first_sentence(str(e))}"
            try:  # name each designated file, so recovery knows which versions were never stored (R14-02)
                apol = policy.get("artifacts") if isinstance(policy.get("artifacts"), dict) else {}
                raw = apol.get("include_globs")
                pats = [g for g in (raw or []) if isinstance(g, str)]
                prune = [g for g in (apol.get("prune_dirs") or []) if isinstance(g, str)]
                unlisted: list = []
                named = [{"path": rel, "why": why} for rel in walk_artifact_candidates(repo, pats, prune, unlisted)
                         if not is_excluded(rel, excludes)] + _unlisted_designated(unlisted)
                # A designation this fallback cannot read in full names nothing it left out: say so, so older stored
                # copies are suspect, instead of recording an empty list (XA1-05).
                if (not isinstance(policy.get("artifacts"), dict) or isinstance(raw, _UnreadableDesignation)
                        or (raw is not None and not isinstance(raw, (list, str)))
                        or (isinstance(raw, list) and len(pats) != len(raw))):
                    named.append({"path": "(designated artifacts)", "why": why})
            except Exception:  # noqa: BLE001
                named = None
            arts = {"digest": None, "files": {}, "repaired": [],
                    "skipped": named if named is not None else [{"path": "(designated artifacts)", "why": why}]}
        skipped += arts["skipped"]
        snaps = list_snapshots(repo)
        # A capture-failure record takes no part in the unchanged comparison, nor in what this snapshot reports against:
        # the newest snapshot that was taken is (RP-01, C17 requirement 4). Sequence numbers count every ref.
        last = next((s_ for s_ in snaps if not s_.get("gap")), None)
        skipped += _designation_shrink(repo, policy, last, arts, excludes, tree, skipped)
        unmatched = _note_designation(repo, arts.get("unmatched") or [])
        art_digest = arts["digest"] or "none"
        excluded_tracked = _default_excluded(skipped, spol)
        uncovered = _note_coverage(repo, skipped, excluded_tracked)
        listed, more = _snap_uncovered(last) if last else ([], 0)
        # A tracked file newly left out by a default secret pattern gets a snapshot of its own, as a file newly left out
        # does, so the newest snapshot names every such file for recovery (XA1-13).
        excluded_gained = ({i["path"] for i in excluded_tracked} - {i["path"] for i in _snap_excluded(last)}
                           if last else set())
        now_paths = {u["path"] for u in uncovered}
        # Only a list cut off at its limit leaves pecia unable to tell which files are newly left out; one folder git
        # cannot open does not (R24-07). A coverage marker that appears or goes away changes what the newest snapshot
        # says, so it gets a snapshot of its own, as a file newly left out does (R16-02, R24-09).
        truncated = len(listed) >= _UNCOVERED_MAX
        gained = set() if truncated else now_paths - set(listed) - {UNLISTED_UNTRACKED}
        if not truncated and (UNLISTED_UNTRACKED in now_paths) != bool(more):
            gained.add(UNLISTED_UNTRACKED)
        if "(designated artifacts)" in listed and "(designated artifacts)" not in now_paths:
            gained.add("(designated artifacts)")
        # The same tree on another branch, or detached, is another line's record: switching branches or detaching at
        # the same commit with an edit carried gets a snapshot of the new line (R24-65).
        same_line = ((last or {}).get("branch") or "(detached or unborn)") == (branch or "(detached or unborn)") \
            and bool((last or {}).get("detached")) == detached_stop
        if (not force and last and last["tree"] == tree and last["parent"] == (head or "")
                and last["artifacts"] == art_digest and not gained and not excluded_gained and same_line
                and not _moved_since(repo, last, seen)):
            # Nothing new to store, but work that could not be stored is still reported, so an
            # unchanged result never implies that every current file is covered. A file newly left
            # out is recorded by a snapshot of its own, so recovery knows a version of it was never
            # stored (R16-02); one that went away is not, so a flapping file adds no snapshots (R15-04).
            return {"created": False, "status": "unchanged", "ref": last["ref"], "commit": last["commit"],
                    "stable": stable, "skipped": skipped, "uncovered": uncovered, "unmatched_patterns": unmatched,
                    "excluded_tracked": excluded_tracked}
        msg = "\n".join([
            f"pecia snapshot: {reason}", "",
            f"Pecia-Version: {VERSION}",
            f"Pecia-Reason: {reason}",
            f"Pecia-Agent: {agent or '-'}",
            f"Pecia-Worktree: {_one_line(fwd(repo.root))}",
            f"Pecia-Branch: {branch or '(detached or unborn)'}",
            *(["Pecia-Detached: yes"] if detached_stop else []),
            f"Pecia-Head: {head or '(unborn)'}",
            # Where HEAD's reflog stands, so latest can tell the history moves made after this snapshot (R24-87).
            f"Pecia-Reflog: {mark}",
            f"Pecia-Artifacts: {art_digest} {len(arts['files'])}",
            *([f"Pecia-Store: {_one_line(arts['store'])}"] if arts["files"] and arts.get("store") else []),
            f"Pecia-Skipped: {len(skipped)}",
            f"Pecia-Stable: {'yes' if stable else 'no'}",
            f"Pecia-Host: {_one_line(socket.gethostname())}",
            *_artifact_lines(arts["files"]),
            *_uncovered_lines(uncovered),
            *_excluded_lines(excluded_tracked),
            *staged, "",
        ])
        # The snapshot's time is its commit's: the clock now, never a date the caller's environment sets (R24-80).
        now_ = f"{int(time.time())} +0000"
        ident = {"GIT_AUTHOR_NAME": "pecia", "GIT_AUTHOR_EMAIL": "pecia@localhost",
                 "GIT_COMMITTER_NAME": "pecia", "GIT_COMMITTER_EMAIL": "pecia@localhost",
                 "GIT_AUTHOR_DATE": now_, "GIT_COMMITTER_DATE": now_}
        args = ["commit-tree", "--no-gpg-sign"]
        if head:
            args += ["-p", head]
        args += ["-F", "-", tree]
        commit = run_git(repo.root, args, env=ident, input_bytes=msg.encode("utf-8")).stdout.decode().strip()
        if arts["files"]:
            try:  # a cache; the commit's own list is authoritative
                atomic_write_json(store_root(repo, policy) / "manifests" / f"{commit}.json",
                                  {"version": 1, "created": iso(), "commit": commit, "files": arts["files"]})
            except (UnsafePath, OSError) as e:
                repo.log_event("manifest_write_failed", commit=commit, error=str(e))
        seq = (max((s["seq"] for s in snaps), default=0) + 1) % 10_000_000_000
        stamp = utcnow().strftime("%Y%m%dT%H%M%S%fZ")
        ref = f"{REF_ROOT}/{repo.worktree_id()}/{seq:010d}-{stamp}-{secrets.token_hex(3)}"
        run_git(repo.root, ["update-ref", "-m", f"pecia snapshot {reason}", ref, commit, repo.zero_oid()])
        if not getattr(repo, "_start_known", False):
            # Where the search of dropped commits made here starts: the place of the oldest snapshot this worktree has,
            # kept apart from snapshots, which retention removes (R24-137), with the commits it was taken on and every
            # local branch, whose work is searched too (R24-146).
            if _start_mark(repo) is None:
                oldest = min(snaps, key=lambda s_: s_["seq"]) if snaps else None
                tips = run_git(repo.root, ["for-each-ref", "--format=%(objectname)", "refs/heads/"], check=False)
                _record_start(repo, (oldest.get("reflog") or "none") if oldest else mark,
                              [(oldest["parent"] if oldest else head) or ""]
                              + (tips.stdout.decode("ascii", "replace").split() if tips.returncode == 0 else []))
            repo._start_known = True
        pruned = prune_snapshots(repo, policy, protect=ref)
        info = {"created": True, "status": "created", "ref": ref, "commit": commit, "reason": reason,
                "agent": agent, "artifacts": len(arts["files"]), "skipped": skipped, "pruned": pruned,
                "stable": stable, "repaired_objects": arts.get("repaired", []), "uncovered": uncovered,
                "unmatched_patterns": unmatched, "excluded_tracked": excluded_tracked}
        repo.log_event("snapshot", ref=ref, commit=commit, reason=reason, agent=agent,
                       artifacts=len(arts["files"]), skipped=skipped[:200], pruned=pruned, stable=stable)
        return info
    finally:
        _rmtree_at(tmpdir)


# ---------------------------------------------------------------- recovery

class UnsafePath(PeciaError):
    pass


_WIN_LINK_TAGS = (0xA0000003, 0xA000000C)  # IO_REPARSE_TAG_MOUNT_POINT (junction), IO_REPARSE_TAG_SYMLINK


def _is_link(p) -> bool:
    """True for a symlink, and on Windows for a junction too. os.path.isjunction exists only from
    Python 3.12, so the reparse tag is read directly; cloud placeholders, which are also reparse
    points, are not links."""
    p = str(p)
    if os.path.islink(p):
        return True
    isjunction = getattr(os.path, "isjunction", None)
    if isjunction and isjunction(p):
        return True
    if IS_WINDOWS:
        try:
            return getattr(os.lstat(p), "st_reparse_tag", 0) in _WIN_LINK_TAGS
        except OSError:
            return False
    return False


def _runtime_dir(repo: "Repo", name: str) -> Path:
    """A folder inside .pecia/runtime that pecia writes into; refused when it is a link."""
    d = repo.runtime / name
    if _is_link(d):
        raise PeciaError(f"{RUNTIME_REL}/{name} is a symlink or junction; pecia refuses to write through it. "
                         "Delete the link and rerun.")
    return d


def _safe_target(repo: Repo, rel: str) -> Path:
    """Refuse to write through a symlink or junction anywhere on the path, or outside the repo."""
    root = repo.root
    cur = root
    parts = rel.split("/")
    for part in parts[:-1]:
        if part in ("", ".", ".."):
            raise UnsafePath(f"{rel}: invalid path component")
        cur = cur / part
        if _is_link(cur):
            raise UnsafePath(f"{rel}: parent {cur.relative_to(root).as_posix()} is a symlink or junction")
        if os.path.lexists(cur) and not cur.is_dir():
            raise UnsafePath(f"{rel}: parent {cur.relative_to(root).as_posix()} is not a directory")
    target = root.joinpath(*parts)
    if _is_link(target):
        raise UnsafePath(f"{rel}: target is a symlink or junction")
    probe = target.parent
    while not probe.exists():
        probe = probe.parent
    if not probe.resolve().is_relative_to(root.resolve()):
        raise UnsafePath(f"{rel}: resolves outside the repository")
    return target


def _snapshot_tree(repo: Repo, commit: str) -> dict:
    if _MEMO is not None and _SHA_RE.fullmatch(commit or ""):
        return _memo_lru("tree", (str(repo.root), commit), lambda: _read_tree(repo, commit))
    return _read_tree(repo, commit)


def _read_tree(repo: Repo, commit: str) -> dict:
    out = run_git(repo.root, ["ls-tree", "-r", "-z", "--full-tree", commit]).stdout
    items = {}
    for rec in out.split(b"\0"):
        if not rec:
            continue
        meta, _, path = rec.partition(b"\t")
        mode, typ, oid = meta.decode().split(" ")
        items[path.decode("utf-8", "surrogateescape")] = (mode, typ, oid)
    return items


def _checkout_bytes(repo: Repo, spec: str) -> bytes:
    """Bytes git checkout would write for <rev>:<path>, smudge filters and eol conversion included."""
    return run_git(repo.root, ["cat-file", "--filters", spec]).stdout


def _raw_equals_base(repo: Repo, target: Path, base_spec: str) -> bool:
    """True only when the file on disk is byte-identical to the checkout of the base version.
    Comparing clean-filtered hashes is not enough: a clean filter can hide newer work."""
    try:
        return _read_regular(target) == _checkout_bytes(repo, base_spec)
    except (OSError, GitError):
        return False


def _delta_items(repo: Repo, parent: str, commit: str) -> tuple[dict, dict]:
    """(_delta, and the snapshot's (mode, type, ID) of each path it changed and still has), from one git call: the
    latest search plans every older snapshot, and the whole tree of each is not needed (R24-12)."""
    if not parent:
        items = _snapshot_tree(repo, commit)
        return {p: "A" for p in items}, items
    out = run_git(repo.root, ["diff-tree", "-r", "-z", "--no-renames", "--raw", parent, commit]).stdout
    parts = out.split(b"\0")
    delta, items = {}, {}
    for i in range(0, len(parts) - 1, 2):
        meta = parts[i].decode("ascii", "replace").lstrip(":").split(" ")
        path = parts[i + 1].decode("utf-8", "surrogateescape")
        if len(meta) < 5 or not path:
            continue
        status, mode, oid = meta[4][:1], meta[1], meta[3]
        delta[path] = status
        if status != "D":
            items[path] = (mode, "commit" if mode == "160000" else "blob", oid)
    return delta, items


def _delta(repo: Repo, parent: str, commit: str) -> dict:
    """Paths the snapshot changed relative to the commit it was taken on, mapped to A, M, T or D.
    Only these paths can hold recoverable work; everything else equals the base commit."""
    if not parent:
        return {p: "A" for p in _snapshot_tree(repo, commit)}
    out = run_git(repo.root, ["diff-tree", "-r", "-z", "--no-renames", "--name-status", parent, commit]).stdout
    parts = out.split(b"\0")
    delta = {}
    for i in range(0, len(parts) - 1, 2):
        status = parts[i].decode("ascii", "replace")[:1]
        path = parts[i + 1].decode("utf-8", "surrogateescape")
        if status and path:
            delta[path] = status
    return delta


_ANCESTOR_CACHE: dict = {}


def _base_relation(repo: Repo, parent: str, head: str, snap_branch: str, branch: str) -> tuple[str, set]:
    """same: taken on HEAD itself. ancestor: taken on an earlier commit of the same branch (for
    example before a partial commit); only paths untouched since then stay recoverable.
    other: another branch or rewritten history; never used implicitly."""
    if snap_branch != branch:
        return "other", set()
    if parent == head:
        return "same", set()
    if not parent or not head:
        return "other", set()
    key = (str(repo.root), parent, head)
    if key not in _ANCESTOR_CACHE:
        if run_git(repo.root, ["merge-base", "--is-ancestor", parent, head], check=False).returncode == 0:
            # Every path any commit since the snapshot's base touched, not only the net difference:
            # a path committed and then reverted was settled on purpose and must not come back.
            touched = set()
            for _, files in commits_with_files(repo, f"{parent}..{head}"):
                touched.update(files)
            _ANCESTOR_CACHE[key] = touched
        else:
            _ANCESTOR_CACHE[key] = None
    changed = _ANCESTOR_CACHE[key]
    return ("ancestor", changed) if changed is not None else ("other", set())


def _hash_paths_once(repo: Repo, paths: list[str]) -> dict:
    """hash_paths, once per file version while a latest search runs: each plan would hash every changed tracked file
    again (R24-42)."""
    if _MEMO is None or not paths:
        return hash_paths(repo, paths)
    memo = _MEMO.setdefault("git_hash", {})
    keys, todo = {}, []
    for p in paths:
        try:
            st = os.lstat(repo.path(p))
            keys[p] = (p, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        except OSError:
            keys[p] = None
        if keys[p] is None or keys[p] not in memo:
            todo.append(p)
    fresh = hash_paths(repo, todo) if todo else {}
    out = {}
    for p in paths:
        k = keys[p]
        if p in fresh:
            out[p] = fresh[p]
            if k is not None:
                memo[k] = fresh[p]
        elif k is not None and k in memo:
            out[p] = memo[k]
    return out


def _file_digest(target: Path) -> str:
    """sha256_file, read once per file version while a latest search runs: the search plans every older snapshot, and
    each plan would hash every designated file again (R24-25)."""
    if _MEMO is None:
        return sha256_file(target)
    st = os.lstat(target)
    k = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    memo = _MEMO.setdefault("file_digest", {})
    if k not in memo:
        memo[k] = sha256_file(target)
    return memo[k]


def _object_problem(objdirs, store_problem, digest: str):
    """Why an artifact's stored copy cannot be restored, or None when a copy whose bytes match its SHA-256 is found.
    While a latest search runs, each object is checked once (R24-25): pecia writes nothing to the store then."""
    if _MEMO is not None:
        memo = _MEMO.setdefault("object_problem", {})
        k = (tuple(str(d) for d in objdirs), store_problem, digest)
        if k not in memo:
            memo[k] = _object_problem_now(objdirs, store_problem, digest)
        return memo[k]
    return _object_problem_now(objdirs, store_problem, digest)


def _object_problem_now(objdirs, store_problem, digest: str):
    _, state = locate_object(objdirs, digest)
    if state == "missing":
        q = None
        for d in objdirs:
            q = q or quarantined_copy(d.parent, digest)
        if q:
            return f"artifact object was found corrupt by verify and moved to {fwd(q)}"
        return "artifact object missing from store" + (f" ({store_problem})" if store_problem else "")
    if state == "corrupt":
        return "artifact object corrupt in store (its bytes no longer match its SHA-256)"
    return None


def _presence(target: Path) -> str:
    """missing, file or other; an OSError other than absence, as from a folder this account cannot search, is raised,
    for the plan to report it rather than take the file for missing or die (R24-81)."""
    try:
        st = os.lstat(target)
    except (FileNotFoundError, NotADirectoryError):
        return "missing"
    return "file" if stat_mod.S_ISREG(st.st_mode) else "other"


def recover_plan(repo: Repo, snap: dict, policy: dict) -> dict:
    commit = snap["commit"]
    parent = snap.get("parent") or ""
    head = repo.head() or ""
    branch = _line_branch(repo) or "(detached or unborn)"
    snap_branch = _snap_line(snap, branch)
    delta, items = _delta_items(repo, parent, commit)
    message = _commit_message(repo, commit)
    inventory = artifact_inventory(repo, policy, commit, message)
    manifest = inventory["files"]
    objdirs, store_problem = snapshot_object_dirs(repo, policy, commit, message)
    base = _snapshot_tree(repo, parent) if parent else {}
    relation, changed_since = _base_relation(repo, parent, head, snap_branch, branch)
    plan = {"snapshot": snap["ref"], "commit": commit, "note": snap.get("note"),
            "older_versions": snap.get("older_versions", []), "snapshot_base": parent,
            "head": head, "snapshot_branch": snap_branch, "branch": branch, "relation": relation,
            "base_matches_head": relation in ("same", "ancestor"), "identical": [], "missing": [], "reverted": [],
            "differs": [], "unsupported": [], "unrecoverable": [], "unsafe": [], "before_move": [], "agent_replaced": [],
            "deleted_in_snapshot": sorted(p for p, st in delta.items() if st == "D"),
            "inventory_notices": inventory["notices"],
            "changed_since_snapshot": sorted(p for p in delta if p in changed_since)}
    for why in inventory["fatal"]:
        plan["unrecoverable"].append({"path": "(artifact list)", "why": why})

    # A designated file and git's entry for it are one file under the file system's spelling rules: git keeps a file
    # renamed only in case under its old spelling, while the artifact list names it as the walk found it (N-03).
    key = _path_key(repo)
    manifest_k = {key(p) for p in manifest}
    base_names = {key(p): p for p in base}
    changed_k = {key(p) for p in changed_since}

    def base_name(path):
        return path if path in base else base_names.get(key(path), path)

    def base_blob(path):
        b = base.get(base_name(path))
        return b if b and b[1] == "blob" and b[0] in ("100644", "100755") else None

    # open_(path): a file that may be at a version a commit since the snapshot wrote, and is then restorable at HEAD's
    # version as at the base's, since both stay in history. For a snapshot taken before history last moved, when latest
    # reports what it holds (moved), and for a file named exactly with --paths and --allow-other-base, which restores it
    # whatever commits did since (R24-87; R24-34 and R24-47 before). A path a commit since the snapshot touched is then a
    # candidate too.
    named = snap.get("named") or set()

    def open_(path):
        return bool(snap.get("moved")) or key(path) in named
    head_tree = _snapshot_tree(repo, head) if head and (snap.get("moved") or named) else {}
    head_names = {key(b): b for b, (mode, typ, _o) in head_tree.items() if typ == "blob" and mode in ("100644", "100755")}

    def head_spec(path, target, now_oid=None):
        name_ = head_names.get(key(path))
        if not name_ or (now_oid is not None and head_tree[name_][2] != now_oid):
            return None
        return f"{head}:{name_}" if _raw_equals_base(repo, target, f"{head}:{name_}") else None

    for path, meta in sorted(manifest.items()):
        if key(path) in changed_k and not open_(path):
            continue
        try:
            target = _safe_target(repo, path)
            kind = _presence(target)
        except UnsafePath as e:
            plan["unsafe"].append({"path": path, "why": str(e)})
            continue
        except OSError as e:
            plan["unsafe"].append({"path": path, "why": f"pecia cannot read where this file is: {e.strerror or e}"})
            continue

        def obj_state():
            return _object_problem(objdirs, store_problem, meta["sha256"])
        if kind == "missing":
            bad = obj_state()
            if bad:
                plan["unrecoverable"].append({"path": path, "why": bad, "now": "missing"})
            else:
                plan["missing"].append({"path": path, "source": "artifact", "sha256": meta["sha256"]})
        elif not target.is_file():
            plan["differs"].append({"path": path, "source": "artifact", "sha256": meta["sha256"]})
        elif _file_digest(target) == meta["sha256"]:
            plan["identical"].append({"path": path, "source": "artifact", "sha256": meta["sha256"]})
        elif base_blob(path) and _raw_equals_base(repo, target, f"{parent}:{base_name(path)}"):
            bad = obj_state()
            if bad:
                plan["unrecoverable"].append({"path": path, "why": bad, "now": "back"})
            else:
                plan["reverted"].append({"path": path, "source": "artifact", "sha256": meta["sha256"],
                                         "base_spec": f"{parent}:{base_name(path)}"})
        elif open_(path) and (spec := head_spec(path, target)):
            bad = obj_state()
            if bad:
                plan["unrecoverable"].append({"path": path, "why": bad, "now": "back"})
            else:
                plan["reverted"].append({"path": path, "source": "artifact", "sha256": meta["sha256"], "base_spec": spec})
        else:
            plan["differs"].append({"path": path, "source": "artifact", "sha256": meta["sha256"]})
    to_hash = []
    for path, status in sorted(delta.items()):
        # Paths changed in commits since the snapshot's base were settled by those commits
        # (committed, renamed or deleted on purpose) and are never candidates.
        if status == "D" or key(path) in manifest_k or path not in items or (path in changed_since and not open_(path)):
            continue
        mode, typ, oid = items[path]
        if mode == "160000":
            plan["unsupported"].append({"path": path, "why": "submodule entry"})
            continue
        if mode == "120000":
            plan["unsupported"].append({"path": path, "why": "symlink entry"})
            continue
        try:
            target = _safe_target(repo, path)
            kind = _presence(target)
        except UnsafePath as e:
            plan["unsafe"].append({"path": path, "why": str(e)})
            continue
        except OSError as e:
            plan["unsafe"].append({"path": path, "why": f"pecia cannot read where this file is: {e.strerror or e}"})
            continue
        if kind == "missing":
            plan["missing"].append({"path": path, "source": "git", "mode": mode, "oid": oid,
                                    "new": base_blob(path) is None})
        elif not target.is_file():
            plan["differs"].append({"path": path, "source": "git", "oid": oid})
        else:
            to_hash.append((path, oid))
    hashes = _hash_paths_once(repo, [p for p, _ in to_hash])
    for path, oid in to_hash:
        now = hashes.get(path)
        b = base_blob(path)
        if now is not None and now == oid:
            plan["identical"].append({"path": path, "source": "git"})
        elif b and now == b[2] and _raw_equals_base(repo, repo.path(path), f"{parent}:{path}"):
            # The file is byte-identical to the commit the snapshot was taken on, which stays in
            # history, so restoring loses nothing. Typical after git reset --hard.
            plan["reverted"].append({"path": path, "source": "git", "mode": items[path][0], "oid": oid,
                                     "base_spec": f"{parent}:{path}"})
        elif open_(path) and (spec := head_spec(path, repo.path(path), now)):
            plan["reverted"].append({"path": path, "source": "git", "mode": items[path][0], "oid": oid,
                                     "base_spec": spec})
        else:
            plan["differs"].append({"path": path, "source": "git", "oid": oid})
    # Files this snapshot reported as not covered: a version of them existed when it was taken and was
    # never stored. Chosen implicitly (latest), the snapshot must not restore an older version of such
    # a file, or report recovery complete while it is missing (R13-02). Named explicitly, it restores
    # what it holds, and the plan lists these files.
    own, more = _snap_uncovered(snap)
    plan["not_covered_when_taken"] = list(own)
    # Tracked files a default secret pattern kept out of this snapshot: it holds none of their changes, so recovery names
    # them rather than say nothing (XA1-13). What it restores, and whether it is complete, is unchanged.
    plan["excluded_tracked"] = [
        dict(i, why=f"tracked, and excluded by the default secret pattern {i['pattern']}: no snapshot holds it, so "
                    "changes made to it since its last commit cannot be restored")
        for i in _parse_excluded(message)]
    plan["never_stored"] = []
    # Work a further recover apply latest restores from an older snapshot taken since history last moved, once this
    # snapshot's is back: latest names it now and is not complete while it is outstanding (G1-09).
    plan["later_recovery"] = []
    for w in (snap.get("later_work") or []) if snap.get("implicit") else []:
        name = w["snapshot"].rsplit("/", 1)[-1]
        plan["later_recovery"].append(dict(
            w, command=f"recover apply {name} {_recover_path_option(w['path'])}",
            why=(f"{name}, an older snapshot taken since history last moved, holds a version of it that is not here now, "
                 "and this newer snapshot does not, as after a deletion, a rename or git restore made since; "
                 "recover apply latest restores it once this snapshot's work is back, and the command restores it now")))
    if snap.get("implicit"):
        key = _path_key(repo)
        # Losses a newer snapshot reported: this older snapshot never restores its version of those files, under
        # any spelling the file system takes for the same file (Y-02).
        for w in snap.get("withheld") or []:
            p, cat = w["path"], w["category"]
            if w.get("version") and not snap.get("report_only") and any(
                    key(i["path"]) == key(p) and _same_version(repo, w["version"], _item_version(i, commit))
                    for g in ("missing", "reverted") for i in plan[g]):
                continue  # this snapshot holds the very version the loss is about (R24-38): restoring it loses nothing
            moved = any(key(i["path"]) == key(p) for g in ("missing", "reverted") for i in plan[g])
            # Each path is reported once (R18-01): a designated file this snapshot holds at the committed version,
            # identical to the file now, is listed as the loss alone (N-01). Work taken before a move that a newer
            # version taken since does not hold is reported beside it, and the newer version is still restored (R24-155).
            if not w.get("beside"):
                for g in ("missing", "reverted", "identical"):
                    plan[g] = [i for i in plan[g] if key(i["path"]) != key(p)]
            if not any(key(u["path"]) == key(p) for u in plan[cat]):
                # A stored copy that cannot be restored says only what is wrong with it; reported with another
                # snapshot, it also says where the file is now and that nothing is lost if it was removed on purpose
                # (R24-26).
                now = {"missing": "; the file is missing now, so if you removed it on purpose, nothing is lost",
                       "back": "; the file is back at its committed version now, so if you restored it to that version "
                               "on purpose, nothing is lost"}.get(w.get("now"), "") if cat == "unrecoverable" else ""
                plan[cat].append({
                    "path": p, "held_here": moved, "snapshot": w["snapshot"],
                    **({"version": w["version"]} if w.get("version") else {}),
                    **({k_: w[k_] for k_ in ("ack", "ack_also", "commit", "also", "also_snapshots", "beside")
                        if w.get(k_)}),
                    "why": w["why"].replace("; this snapshot holds an earlier version", "")
                           + ("" if cat in ("before_move", "agent_replaced") or not w.get("snapshot") else
                              f" (reported by snapshot {w['snapshot'].rsplit('/', 1)[-1]})")
                           + (("; latest restores the newer captured version alongside this report"
                               if cat == "agent_replaced" else
                               "; a snapshot taken since the move holds a newer version of the file, which latest "
                               "restores, without this change" if w.get("beside") else
                               "; the snapshot chosen holds another version" if cat == "before_move" else
                               "; the snapshot chosen holds an earlier version")
                              if moved and not snap.get("report_only") and w["snapshot"] != snap["ref"] else "")
                           + now})
        lost = {p for p in own if p != "(designated artifacts)" and (key(p) not in changed_k or open_(p))}
        # Compared under the spelling rules of the file system: git keeps a file renamed only in case under its
        # old spelling, while the snapshot names it as it was when taken (J-02).
        lost_k = {key(x) for x in lost}
        # A snapshot that could not name everything it left out (artifact capture failed as a whole, or
        # more files than its list holds), this one or a newer one, makes older versions suspect: of
        # every designated file, or of every file (R14-02, R14-03).
        suspect = snap.get("suspect")
        held_here = set()
        # Across a history move, newer bytes cannot prove that a never-stored version survived (R24-240).
        # A fallback copy in this snapshot must not speak for the version it could not capture.
        for group in ("missing", "reverted") + (("identical", "differs") if snap.get("moved") else ()):
            for i in plan[group]:
                untracked = i.get("source") == "git" and base_blob(i["path"]) is None
                if (key(i["path"]) in lost_k or (suspect and i.get("source") == "artifact")
                        or (suspect == "all" and untracked) or suspect == "tracked"):
                    held_here.add(i["path"])
            plan[group] = [i for i in plan[group] if i["path"] not in held_here]
        listed = {key(i["path"]) for g in _PLAN_GROUPS for i in plan[g]}  # each path reported once (R18-01)
        for u in snap.get("unnamed_lost") or []:
            # This snapshot left out files it could not name (R16-01); an older one holds a version of
            # this file, which is missing now and absent from this snapshot.
            if key(u["path"]) not in listed and key(u["path"]) not in lost_k and not os.path.lexists(repo.path(u["path"])):
                listed.add(key(u["path"]))
                plan["never_stored"].append({
                    "path": u["path"], "held_here": False,
                    "why": "this snapshot could not list every file it left out, and this file, which an older "
                           "snapshot holds, is missing now; its newest version may never have been stored. If you "
                           "removed it on purpose, nothing is lost"})
        def back_at_base(p):
            # A tracked file whose newest version was never stored and that is now back at the version committed
            # on the snapshot's base, as after git restore or reset --hard, has lost that newer version as surely as
            # a deleted file has (C-02).
            try:
                target = _safe_target(repo, p)
                if base_blob(p) and _raw_equals_base(repo, target, f"{parent}:{base_name(p)}"):
                    return True
                # Or at HEAD's version, where a commit since the snapshot may have put it (R24-87).
                return open_(p) and head_spec(p, target) is not None
            except (UnsafePath, OSError):
                return False
        for p in sorted(lost | held_here):
            if any(key(u["path"]) == key(p) for g in _LOSS_GROUPS for u in plan[g]):
                continue
            gone = not os.path.lexists(repo.path(p))
            back = not gone and (p in held_here or (key(p) in lost_k and key(p) not in listed)) and back_at_base(p)
            uncertain = bool(snap.get("moved")) and key(p) in lost_k
            if p in held_here or (key(p) not in listed and (gone or back or uncertain)):
                cause = ("a newer version of this file existed and pecia never stored it (a snapshot reported it as "
                         "not covered)" if key(p) in lost_k else
                         "a newer snapshot could not list or store every file it should have, so a newer version of "
                         "this file may exist that pecia does not have")
                now = (", and the file is back at its committed version now" if back else
                       ", and the file is missing now" if gone else
                       ", and pecia cannot establish whether the file now holds that version")
                plan["never_stored"].append({
                    "path": p, "held_here": p in held_here,
                    "why": (cause + now
                            + ("; this snapshot holds an earlier version" if p in held_here else "")
                            + (". If you restored it to the committed version on purpose, nothing is lost" if back else
                               ". If you removed it on purpose, nothing is lost" if gone else
                               ". If you intentionally replaced that version, nothing is lost"))})
    if snap.get("report_only"):
        # latest found no snapshot taken since history last moved here: it restores nothing, and reports what the
        # snapshots taken before hold (R24-87).
        plan["missing"], plan["reverted"] = [], []
        plan["base_matches_head"] = True
    return plan


class NoAtomicPublish(PeciaError):
    pass


def _write_exclusive(target: Path, data_iter, want_sha256: str | None = None, executable: bool = False,
                     base: Path | None = None) -> None:
    """Write into a temporary file beside target, verify it, then publish without overwriting.
    An interruption leaves only a hidden temporary file, never a partial file at target. The folder
    is held from base (or the outermost trusted base), so no folder on the way can be swapped for a
    link between the check and the write (V-05)."""
    target = Path(target)
    if base is not None:
        names = list(target.relative_to(base).parts[:-1])
        held = _HeldDir(base, names, create=True)
    else:
        held = _held_dir(target.parent, create=True)
    with held as d:
        fd, tmp = d.new_temp(".pecia-restore-")
        try:
            h = hashlib.sha256()
            with os.fdopen(fd, "wb") as f:
                for chunk in data_iter:
                    h.update(chunk)
                    f.write(chunk)
                f.flush()
                os.fsync(f.fileno())
                if want_sha256 is not None and h.hexdigest() != want_sha256:
                    raise OSError("restored bytes failed the SHA-256 check; nothing was written")
                if executable and not IS_WINDOWS:
                    # Set on the temporary file before it is published, never on the target afterwards,
                    # which a link could replace meanwhile (R10-12).
                    os.fchmod(f.fileno(), os.fstat(f.fileno()).st_mode | 0o111)
                ident = _ident(os.fstat(f.fileno()))
            d.link_no_clobber(tmp, target.name)
        except BaseException:
            d.unlink_quietly(tmp)
            raise
        _check_published(d, target.name, ident, fwd(target), h.hexdigest())


def _object_chunks(obj: Path):
    with _open_regular(obj) as f:
        yield from iter(lambda: f.read(1 << 20), b"")


def _restore_reverted(repo: Repo, commit: str, item: dict, object_for) -> None:
    target = _safe_target(repo, item["path"])
    if item["source"] == "artifact":
        data = b"".join(_object_chunks(object_for(item["sha256"])))
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise OSError("artifact object failed its hash check")
    else:
        data = _checkout_bytes(repo, f"{commit}:{item['path']}")
    base_bytes = _checkout_bytes(repo, item["base_spec"])
    parts = item["path"].split("/")
    with _HeldDir(repo.root, parts[:-1]) as d:  # from the working tree root, following no link (V-05)
        name = parts[-1]
        try:
            st = d.lstat(name)
        except FileNotFoundError:
            raise FileExistsError(item["path"]) from None  # gone since the plan: leave it to the user
        if not stat_mod.S_ISREG(st.st_mode):
            raise FileExistsError(item["path"])
        fd, tmp = d.new_temp(".pecia-restore-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
                d.set_mode(f.fileno(), tmp, stat_mod.S_IMODE(st.st_mode))
                ident = _ident(os.fstat(f.fileno()))
            # Final byte comparison immediately before the swap. A residual window of a few
            # milliseconds remains; an edit landing inside it would be lost (documented limit).
            with d.open_read(name) as cur:
                same = cur.read(len(base_bytes) + 1) == base_bytes
            if not same:
                raise FileExistsError(item["path"])
            d.replace(tmp, name)
        except BaseException:
            d.unlink_quietly(tmp)
            raise
        _check_published(d, name, ident, fwd(target), hashlib.sha256(data).hexdigest())


def _path_selector(repo: Repo, plan: dict, path_globs):
    """(predicate, values that match no file of the snapshot). A --paths value that names a file of the
    snapshot exactly selects that file only, whatever characters it holds; any other value is a glob
    (R13-04). A value that matches nothing in the snapshot is reported, never taken for success."""
    if not path_globs:
        return (lambda path: True), []
    known = set(_snapshot_tree(repo, plan["commit"]))
    for g in _PLAN_GROUPS:
        known |= {i["path"] for i in plan.get(g, [])}
    known |= set(plan.get("changed_since_snapshot") or []) | set(plan.get("deleted_in_snapshot") or [])
    known |= {w["path"] for w in plan.get("later_recovery") or []}
    # A file is named under the file system's spelling rules: git and the artifact list can spell one file two ways
    # where case is ignored, and the plan may list it under either (N-03).
    key = _path_key(repo)
    known_k = {key(k) for k in known}
    literal = {g for g in path_globs if key(g) in known_k}
    literal_k = {key(g) for g in literal}
    globs = [g for g in path_globs if g not in literal]
    unmatched = [g for g in globs if not any(match_any(k, [g]) for k in known)]

    def picked(path):
        return key(path) in literal_k or match_any(path, globs)
    return picked, unmatched


def recover_apply(repo: Repo, snap: dict, policy: dict, path_globs=None, dry_run=False,
                  missing_only=False, allow_other_base=False) -> dict:
    # A file named exactly, with --allow-other-base, is restored whatever commits did since the snapshot, when it is
    # missing or at a committed version: the command latest gives for a version taken before history moved (R24-87).
    # Not for latest, which never restores across a history move nor over a version committed since (R24-103).
    named = ({_path_key(repo)(p) for p in (path_globs or [])} if allow_other_base and not snap.get("latest")
             else set())
    plan = recover_plan(repo, dict(snap, named=named) if named else snap, policy)
    if not plan["base_matches_head"] and not allow_other_base and not dry_run:
        raise PeciaError(
            f"snapshot {plan['snapshot'].rsplit('/', 1)[-1]} was taken on {(plan['snapshot_base'] or 'an unborn branch')[:12]} "
            f"({plan['snapshot_branch']}), but HEAD is now {(plan['head'] or 'unborn')[:12]} ({plan['branch']}). "
            "Files it holds may have been deleted on purpose "
            "since, or may belong to another branch. Review recover plan, then rerun with --allow-other-base "
            "if restoring is still right.")
    objdirs, _ = snapshot_object_dirs(repo, policy, plan["commit"])

    def object_for(digest):
        found, state = locate_object(objdirs, digest)
        if state != "ok":
            raise OSError(f"artifact object {state} in every store pecia knows of")
        return found
    picked, unmatched = _path_selector(repo, plan, path_globs)
    restored, conflicts, errors = [], [], []
    if not missing_only:
        for item in plan["reverted"]:
            path = item["path"]
            if not picked(path):
                continue
            if dry_run:
                restored.append(path)
                continue
            try:
                _restore_reverted(repo, plan["commit"], item, object_for)
                restored.append(path)
            except FileExistsError:
                conflicts.append(path)
            except (OSError, PeciaError) as e:
                errors.append({"path": path, "why": str(e)})
    for item in plan["missing"]:
        path = item["path"]
        if not picked(path):
            continue
        if dry_run:
            restored.append(path)
            continue
        try:
            target = _safe_target(repo, path)
            if item["source"] == "artifact":
                _write_exclusive(target, _object_chunks(object_for(item["sha256"])), item["sha256"],
                                 base=repo.root)
            else:
                _write_exclusive(target, [_checkout_bytes(repo, f"{plan['commit']}:{path}")],
                                 executable=item.get("mode") == "100755", base=repo.root)
            restored.append(path)
        except FileExistsError:
            conflicts.append(path)
        except (OSError, PeciaError) as e:
            errors.append({"path": path, "why": str(e)})
    untouched = [d["path"] for d in plan["differs"]] + conflicts

    def wanted(item):
        # An unreadable artifact list cannot be matched against globs, so it is always reported.
        return item["path"] == "(artifact list)" or picked(item["path"])
    unrecoverable = [u for u in plan["unrecoverable"] if wanted(u)]
    never_stored = [u for u in plan["never_stored"] if wanted(u)]
    before_move = [u for u in plan.get("before_move", []) if wanted(u)]
    agent_replaced = [u for u in plan["agent_replaced"] if wanted(u)]
    unsafe = [u for u in plan["unsafe"] if wanted(u)]
    unsupported = [u for u in plan["unsupported"] if wanted(u)]
    later_recovery = [u for u in plan.get("later_recovery") or [] if wanted(u)]
    # Restorable work the caller chose not to restore (--missing-only) is reported on its own.
    skipped_by_option = [d["path"] for d in plan["reverted"] if wanted(d)] if missing_only else []
    if (unrecoverable or never_stored or before_move or agent_replaced or unsafe or unsupported or errors or unmatched
            or later_recovery):
        result = "incomplete"
    elif skipped_by_option:
        result = "partial_by_request"
    else:
        result = "complete"
    report = {"snapshot": plan["snapshot"], "commit": plan["commit"], "note": plan.get("note"),
              "unmatched_paths": unmatched, "never_stored": never_stored, "before_move": before_move,
              "agent_replaced": agent_replaced, "later_recovery": later_recovery,
              "older_versions": plan.get("older_versions", []), "dry_run": dry_run,
              "base_matches_head": plan["base_matches_head"],
              "restored": restored, "left_untouched_differs": untouched, "skipped_by_option": skipped_by_option,
              "unsafe": unsafe, "unsupported": unsupported, "unrecoverable": unrecoverable, "errors": errors,
              "excluded_tracked": [u for u in plan.get("excluded_tracked") or [] if wanted(u)],
              # complete: everything the snapshot holds for the selected paths is now on disk, or was
              # left alone only because newer work is there. Anything else is partial_by_request (the
              # caller skipped restorable work) or incomplete (evidence could not be restored).
              "result": result, "complete": result == "complete",
              # Failed captures, listed until recover ack; a record alone does not make the result incomplete, its named
              # paths do through never_stored (RP-01; D1 with the R24-28 precedent).
              "capture_failures": capture_failures(repo)}
    if not dry_run:
        # Retention keeps what later_recovery names until a recovery completes (XA1-09).
        unrecorded = _note_later_recovery(repo, report, bool(snap.get("latest")), not path_globs)
        if unrecorded:
            report["note"] = (report["note"] + "; " if report.get("note") else "") + unrecorded
        repo.log_event("recover_apply", snapshot=plan["snapshot"], restored=restored,
                       untouched=report["left_untouched_differs"][:200], errors=errors,
                       unrecoverable=unrecoverable[:200], never_stored=never_stored[:200], before_move=before_move[:200],
                       unsafe=unsafe[:200], agent_replaced=agent_replaced[:200],
                       unsupported=unsupported[:200], later_recovery=[u["path"] for u in later_recovery][:200])
    return report


def recover_ack(repo: Repo, policy: dict) -> dict:
    """Acknowledge latest's reports from history moves and replacements by a different agent: each report, by its
    snapshot, file and version or commit, is not shown again (R24-110).
    A version not reported now, because history held it or it was still on disk, is reported whenever it is found lost
    later. The snapshots themselves are kept, and each can still be restored by naming it."""
    if os.environ.get("PECIA_LEASE_ID") or os.environ.get("PECIA_AGENT"):
        # It ends reports of lost versions: an agent pecia launched, told by the report that it would, must not.
        raise PeciaError("recover ack ends reports of lost versions, so pecia leaves it to "
                         "you: run it in a terminal of your own, outside the agent session pecia launched")
    if not list_snapshots(repo):
        return {"acknowledged": [], "snapshot": None, "note": "no snapshots exist for this working tree"}
    # A snapshot of the files as they are now first, so a version carried across the move and still on disk is held by a
    # snapshot taken since, and a later discard of it is reported (R24-95).
    take_snapshot(repo, "recover ack", None, policy, force=True)
    mine = list_snapshots(repo)
    with _search_memo():
        snap = _search_latest(repo, mine, policy)
        plan = recover_plan(repo, snap, policy)
    reported = [u for g in _LOSS_GROUPS + ("unsafe",) for u in plan[g] if u.get("ack")]
    # The failed captures latest lists end here, and only here: the record and its named paths' reports with it
    # (RP-01, C17 requirement 9).
    ended = [{"path": "(failed capture)", "snapshot": rec["ref"], "capture_failure": rec}
             for rec in _end_capture_failures(repo)]
    if not reported:
        if ended:
            return {"acknowledged": ended, "snapshot": None,
                    "note": f"acknowledged {len(ended)} failed capture(s); they are not reported again"}
        return {"acknowledged": [], "snapshot": None,
                "note": "no loss with an acknowledgement key is reported now, so nothing was acknowledged"}
    wid = repo.worktree_id(create=False)
    if not wid:
        raise PeciaError("this working tree has no pecia record of its own, so there is nothing to acknowledge here")
    refs = {s["ref"] for s in mine}
    # Keep what was acknowledged before, while its snapshot exists; a report from a commit has no snapshot.
    keep = {a for a in _acked_keys(repo) if a.split("\x1f", 1)[0] in refs or not a.split("\x1f", 1)[0]}
    new = {u["ack"] for u in reported}
    for u in reported:
        a_ = u.get("ack_also") or []
        new |= {a_} if isinstance(a_, str) else set(a_)
    # Where HEAD's reflog stands now, for each report acknowledged now: a commit HEAD holds again after it, and loses
    # again, is a later loss, and reported (R24-181).
    at = {a: m for a, m in _ack_marks(repo).items() if a in keep and a not in new}
    mark = _ack_mark(repo)
    at.update({a: mark for a in new if mark != "none"})
    keep |= new
    blob = run_git(repo.root, ["hash-object", "-w", "--stdin"],
                   input_bytes=json.dumps({"acked": sorted(keep), "at": dict(sorted(at.items()))},
                                          indent=1).encode()).stdout.decode().strip()
    run_git(repo.root, ["update-ref", f"{_ACK_ROOT}/{wid}", blob])
    repo.log_event("recover_ack", files=len(reported))
    def named(u):
        # Every commit the acknowledgement ends, those in the report's words and those it covers (R24-182).
        a_ = u.get("ack_also") or []
        keys = [a_] if isinstance(a_, str) else list(a_)
        found = [k_.rsplit("commit:", 1)[1] for k_ in keys + [u["ack"]] if "\x1fcommit:" in k_]
        return [c_ for c_ in dict.fromkeys(list(u.get("also") or []) + found) if c_ != u.get("commit")]

    def named_snaps(u):
        # And every snapshot it ends beside the report's own (R24-195).
        a_ = u.get("ack_also") or []
        keys = [a_] if isinstance(a_, str) else list(a_)
        found = [k_.split("\x1f", 1)[0] for k_ in keys if k_.split("\x1f", 1)[0]]
        return [s_ for s_ in dict.fromkeys(list(u.get("also_snapshots") or []) + found) if s_ != u.get("snapshot")]
    return {"acknowledged": [{"path": u["path"], "snapshot": u.get("snapshot"), "commit": u.get("commit"),
                              **({"also": named(u)} if named(u) else {}),
                              **({"also_snapshots": named_snaps(u)} if named_snaps(u) else {})} for u in reported]
            + ended,
            "snapshot": None,
            "note": (f"acknowledged {len(reported)} report(s) of work latest lists as lost (from snapshots taken before "
                     "history last moved here, from commits history no longer holds, or replaced by a different agent); "
                     "they are not shown again, a version not reported now is reported if it is found lost later, and "
                     "each snapshot can still be restored by naming it")}


def recover_inspect(repo: Repo, snap: dict, policy: dict) -> Path:
    """Check the snapshot out into a disposable worktree and copy in its stored artifacts. Only
    objects whose bytes hash to the recorded SHA-256 are copied; anything else is recorded as a
    problem, which inspect_problems returns and the CLI prints."""
    if snap.get("report_only"):
        raise PeciaError("no snapshot was taken since history last moved here, so latest names none to inspect; name "
                         "one, as in recover inspect SNAPSHOT")
    repo.ensure_runtime()
    base = _runtime_dir(repo, "recover")
    _held_dir(_runtime_dir(repo, "recover-meta"), create=True).close()
    _held_dir(base, create=True).close()
    stamp = utcnow().strftime('%Y%m%dT%H%M%S')
    # The record is created first, under a name nobody holds yet, so recover close removes only
    # folders pecia made: one without a record is never removed (V-03).
    for i in range(100):
        dest = base / (f"{snap['commit'][:10]}-{stamp}" + (f"-{i}" if i else ""))
        if os.path.lexists(dest):
            continue
        try:
            fd = _create_excl(_inspect_record(repo, dest))
        except FileExistsError:
            continue
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"commit": snap["commit"], "name": dest.name, "pending": True, "artifacts": {},
                       "problems": []}, f, indent=2, sort_keys=True)
        break
    else:
        raise PeciaError(f"no free name for an inspection worktree in {fwd(base)}; run recover close")
    try:
        # git creates the worktree inside the recover folder while pecia holds it. On Linux git runs in
        # that held folder itself (through /proc/self/fd) and is given a bare name, so a folder swapped for
        # a link meanwhile cannot send the checkout elsewhere; on Windows the held folders cannot be
        # swapped at all (R13-07). Hooks are off for every git call (_GIT_SAFE). The worktree's HEAD log is
        # created even where the repository turns reflogs off, so close can see commits made there (Y-01).
        with _held_dir(base) as held:
            cwd, target, fds = repo.root, str(dest), ()
            via = f"/proc/self/fd/{held.fd}" if held.fd is not None else None
            if via and os.path.isdir(via):
                cwd, target, fds = via, dest.name, (held.fd,)
            run_git(cwd, ["-c", "core.logAllRefUpdates=always", "worktree", "add", "--detach",
                          target, snap["commit"]], pass_fds=fds)
    except BaseException:
        if not os.path.lexists(dest):
            try:
                _unlink_at(_inspect_record(repo, dest))
            except (OSError, PeciaError):
                pass
        raise
    objdirs, store_problem = snapshot_object_dirs(repo, policy, snap["commit"])
    inventory = artifact_inventory(repo, policy, snap["commit"])
    copied, problems = {}, [{"path": "(artifact list)", "why": w} for w in inventory["fatal"]]
    withheld = set()
    if snap.get("implicit"):
        # Chosen by latest: what recovery would report as lost is reported here too, and an earlier version
        # recovery withholds is not copied in as if it were current (R18-03).
        plan = recover_plan(repo, snap, policy)
        for u in plan["never_stored"] + plan["unrecoverable"] + plan["before_move"] + plan["agent_replaced"]:
            if u["path"] != "(artifact list)" or not inventory["fatal"]:
                problems.append({"path": u["path"], "why": u["why"]})
            if not u.get("beside"):
                withheld.add(u["path"])
        # Checkout wrote the snapshot's whole tree, so a withheld earlier version kept in the tree itself (an
        # untracked file the snapshot stored) is there too. It is marked skip-worktree and removed, so the
        # inspection does not show it as current and close does not count its absence as an edit (X-01).
        wkey = _path_key(repo)
        held_k = {wkey(w) for w in withheld}
        in_tree = sorted(t for t in _snapshot_tree(repo, snap["commit"]) if wkey(t) in held_k) if withheld else []
        if in_tree:
            lit = {"GIT_LITERAL_PATHSPECS": "1"}
            hid = run_git(dest, ["update-index", "--skip-worktree", "-z", "--stdin"], env=lit,
                          input_bytes=nul_join(in_tree) + b"\0", check=False)
            for p in in_tree:
                f = dest.joinpath(*p.split("/"))
                try:
                    if hid.returncode != 0:
                        raise OSError("git could not mark it")
                    if os.path.lexists(f):
                        _unlink_at(f)
                except (OSError, PeciaError) as e:
                    problems.append({"path": p, "why": f"an earlier version that recovery withholds is in this "
                                                       f"inspection worktree and could not be removed ({e}); it is "
                                                       "not the current version"})
    wkey = _path_key(repo)
    held_k = {wkey(w) for w in withheld}
    for path, meta in inventory["files"].items():
        if wkey(path) in held_k:
            continue
        obj, state = locate_object(objdirs, meta["sha256"])
        if obj is None:
            problems.append({"path": path, "why": "artifact object missing from store; not copied"
                             + (f" ({store_problem})" if store_problem else "")})
            continue
        try:
            target = _safe_target(types.SimpleNamespace(root=dest), path)
            ok = _copy_verified(obj, target, meta["sha256"])  # its folder is held from the working tree root
        except UnsafePath as e:
            problems.append({"path": path, "why": f"not copied: {e}"})
            continue
        except OSError as e:
            problems.append({"path": path, "why": f"could not copy the stored object ({e})"})
            continue
        if not ok:
            problems.append({"path": path, "why": "artifact object corrupt in store (its bytes no longer match "
                                                  "its SHA-256); not copied"})
            continue
        copied[path] = meta["sha256"]
    # The bytes of every file checkout wrote. Once staged, an edit that git's own conversions undo (an ident field,
    # line endings, a working-tree encoding) leaves git status clean, so close compares bytes instead (C-01).
    written = {}
    copied_k = {wkey(c) for c in copied}  # a designated file copied in under another spelling of the same file (N-03)
    for path, (mode, _typ, _oid) in _snapshot_tree(repo, snap["commit"]).items():
        if mode not in ("100644", "100755") or wkey(path) in copied_k:
            continue
        try:
            written[path] = sha256_file(dest.joinpath(*path.split("/")))
        except OSError:
            pass  # not written: a withheld earlier version, or a file outside a sparse checkout
    # Record the actual executable bits, including the mode of a designated copy, which can differ from Git's.
    # Content hashes and Git status alone miss mode edits hidden by index flags or core.filemode (F1-01).
    exec_modes = {}
    for path in written.keys() | copied.keys():
        try:
            with _open_regular(dest.joinpath(*path.split("/"))) as f:
                exec_modes[path] = os.fstat(f.fileno()).st_mode & 0o111
        except OSError:
            exec_modes[path] = None  # no baseline: close must keep the inspection if that file remains
    # What inspect itself put there, so close can tell the user's own edits apart and keep them, and which folder
    # and which git worktree record it made: a later folder at the same name is not this one (Y-04).
    owned = {"commit": snap["commit"], "name": dest.name, "artifacts": copied, "problems": problems,
             "files": written, "exec_modes": exec_modes}
    try:
        owned["folder"] = list(_ident(os.lstat(dest)))
        admin, _ = _inspection_admin(repo, dest)
        if admin is not None:
            owned["admin"] = {"name": admin.name, "ident": list(_ident(os.lstat(admin)))}
            # A file system may give a later folder the number of one that was deleted, so a random token in
            # git's record of this worktree is what tells the one inspect made from a later one (R21-01).
            token = secrets.token_hex(16)
            _write_inspect_token(admin, token)
            owned["admin"]["token"] = token
    except OSError:
        pass
    atomic_write_json(_inspect_record(repo, dest), owned)
    repo.log_event("recover_inspect", snapshot=snap["ref"], path=fwd(dest), problems=problems[:200])
    return dest


def _inspect_record(repo: Repo, d: Path) -> Path:
    return _runtime_dir(repo, "recover-meta") / f"{d.name}.json"


def inspect_problems(repo: Repo, d: Path) -> list[dict]:
    rec = load_json(_inspect_record(repo, d), {}) or {}
    return rec.get("problems") if isinstance(rec.get("problems"), list) else []


_RUNTIME_OWN_FILES = frozenset({"events.jsonl", "coverage.json", "artifact-cache.json", "snapshot.lock",
                                "RESUME_PROMPT.md"})
_RUNTIME_OWN_DIRS = ("generated/", "backup/")


def _pecia_runtime_entry(rel: str) -> bool:
    """Whether rel, a path inside an inspection worktree's .pecia/runtime/, is a file pecia itself keeps there. Only
    those are left out of the changes close counts: every file in that folder used to be, so a notes file put there, or
    a nested inspection made by running inspect inside the inspection, with its edits, was deleted (G1-01)."""
    return rel == "" or rel in _RUNTIME_OWN_FILES or rel.startswith(_RUNTIME_OWN_DIRS)


def inspect_changes(repo: Repo, d: Path) -> list[str]:
    """Paths in an inspection worktree that differ from what recover inspect put there: edits to
    snapshot files, new files, changed or removed artifact copies, commits made there, and edits
    hidden behind assume-unchanged or skip-worktree flags. When anything cannot be checked, a
    placeholder entry is returned, so the worktree is kept."""
    rec = load_json(_inspect_record(repo, d), {}) or {}
    copied = rec.get("artifacts") if isinstance(rec.get("artifacts"), dict) else {}
    commit = rec.get("commit") if isinstance(rec.get("commit"), str) else None
    no_monitor = ["-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false"]
    changed = []

    key = _path_key(repo)
    copied_k = {key(c): want for c, want in copied.items()}

    def copy_intact(path):
        # git status names a copied designated file as git spells it, which can differ from the artifact list's
        # spelling where case is ignored (N-03).
        try:
            return key(path) in copied_k and sha256_file(d.joinpath(*path.split("/"))) == copied_k[key(path)]
        except OSError:
            return False

    seen_dirs = {}
    spellings: dict = {}  # git's own spellings of each name, per folder, under the key

    def names_in(folder):
        if folder not in seen_dirs:
            try:
                seen_dirs[folder] = set(os.listdir(folder))
            except OSError:
                seen_dirs[folder] = set()
        return seen_dirs[folder]

    def spelled(path):
        """Every name on the way to path is spelled as recorded. On a file system that ignores case the old
        spelling still opens a file or folder renamed only in case, and git status, which ignores the same
        difference, shows nothing (J-05); a renamed folder changes every path below it (N-02)."""
        folder, above = d, ""
        for part in path.split("/"):
            if part not in names_in(folder):
                # git's tree may itself spell one folder two ways (Docs/a.txt beside docs/b.txt); checkout then makes
                # one folder under either spelling, which is no rename.
                same = [n for n in names_in(folder) if key(n) == key(part)]
                ok = [n for n in same if n in spellings.get((above, key(part)), ())]
                if not ok:
                    return False
                part = ok[0]
            folder, above = folder / part, (above + "/" + key(part)) if above else key(part)
        return True

    head = run_git(d, ["rev-parse", "HEAD"], check=False)
    if commit is None or head.returncode != 0 or head.stdout.decode().strip() != commit:
        changed.append("(the inspection worktree is no longer at the snapshot commit, or its record is missing)")
    else:
        # HEAD can be moved back after a commit made here; the worktree's own reflog still shows it,
        # and once the worktree is removed nothing would reach that commit.
        walked = run_git(d, ["log", "-g", "--format=%H", "HEAD"], check=False)
        moves = walked.stdout.decode().split() if walked.returncode == 0 else []
        if any(c and c != commit for c in moves):
            changed.append("(HEAD moved in the inspection worktree: commits or checkouts were made there; "
                           "see git reflog in that folder)")
        elif not moves:
            # No HEAD log at all: with reflogs turned off, a commit made there and checked out again would
            # leave no trace, so the worktree is kept (Y-01).
            changed.append("(the inspection worktree has no HEAD history, so commits made there cannot be ruled "
                           "out; if you made none, --discard is safe)")
    p = run_git(d, [*no_monitor, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=traditional"],
                check=False)
    if p.returncode != 0:
        return changed + ["(git status failed in the inspection worktree; treating it as changed)"]
    entries = p.stdout.split(b"\0")
    i = 0
    while i < len(entries):
        e = entries[i]
        i += 1
        if len(e) < 4:
            continue
        code, path = e[:2].decode("ascii", "replace"), e[3:].decode("utf-8", "surrogateescape")
        if code[0] in "RC":
            i += 1  # the source path of a rename or copy follows
        if (path == RUNTIME_REL + "/" or path.startswith(RUNTIME_REL + "/")) and _pecia_runtime_entry(
                path[len(RUNTIME_REL) + 1:]):
            continue  # pecia's own state, never user work
        if copy_intact(path):
            continue
        changed.append(path)
    tree = run_git(d, ["ls-tree", "-r", "-z", "--full-tree", commit or "HEAD"], check=False)
    if tree.returncode != 0:
        return changed + ["(could not list the snapshot tree; treating the inspection worktree as changed)"]
    blobs, gitlinks, symlinks = {}, [], {}
    for item in tree.stdout.split(b"\0"):
        meta, _, path = item.partition(b"\t")
        if not path:
            continue
        mode, _, oid = meta.decode().split(" ")
        name = path.decode("utf-8", "surrogateescape")
        above = ""
        for part in name.split("/"):
            spellings.setdefault((above, key(part)), set()).add(part)
            above = (above + "/" + key(part)) if above else key(part)
        if mode == "160000":
            gitlinks.append(name)
        elif mode in ("100644", "100755"):
            blobs[name] = oid
        elif mode == "120000":
            symlinks[name] = oid
    # inspect never populates submodules, so anything inside a submodule folder was put there by hand,
    # and git status does not look inside it.
    for g in gitlinks:
        sub = d.joinpath(*g.split("/"))
        if sub.is_dir() and any(sub.iterdir()):
            changed.append(g + "/")
    # git status does not look at files flagged assume-unchanged or skip-worktree, so compare those
    # with the snapshot's own blobs directly. A flagged file that is absent, as sparse checkout leaves
    # files outside its cone, holds nothing that the snapshot commit does not.
    flags = run_git(d, ["ls-files", "-v", "-z"], check=False)
    if flags.returncode != 0:
        return changed + ["(could not read index flags in the inspection worktree; treating it as changed)"]
    hidden = []
    for rec_ in flags.stdout.split(b"\0"):
        if len(rec_) > 2 and (rec_[:1].islower() or rec_[:1] == b"S"):
            hidden.append(rec_[2:].decode("utf-8", "surrogateescape"))
    for path in hidden:
        f = d.joinpath(*path.split("/"))
        if copy_intact(path) or not os.path.lexists(f) or path in gitlinks:
            continue  # submodule folders have their own check above
        if path in symlinks and os.path.islink(f):
            target = run_git(d, ["cat-file", "blob", symlinks[path]], check=False)
            if target.returncode != 0 or os.fsencode(os.readlink(f)) != target.stdout:
                changed.append(path)
            continue
        want = blobs.get(path) or symlinks.get(path)  # a symlink checked out as a plain file holds its target
        h = run_git(d, ["hash-object", "--", path], check=False)
        if not f.is_file() or h.returncode != 0 or h.stdout.decode().strip() != want:
            changed.append(path)
    # Every file checkout wrote is compared byte for byte with what it wrote: once staged, an edit that git's own
    # conversions undo leaves git status clean (C-01). An inspection made before this record existed is kept.
    written = rec.get("files")
    if not isinstance(written, dict):
        changed.append("(this inspection worktree has no record of the bytes inspect wrote, as one made by an earlier "
                       "version has not, so an edit git status does not show cannot be ruled out; if you changed "
                       "nothing there, --discard is safe)")
    else:
        # A regular snapshot path absent from the complete byte baseline was withheld or not checked out.
        # Its later presence is new work, even when skip-worktree hides it and its bytes equal Git's (R24-248).
        present_k = {key(path) for path in written} | set(copied_k)
        for path in blobs:
            if key(path) not in present_k and os.path.lexists(d.joinpath(*path.split("/"))):
                changed.append(path + " (not present when this inspection was created)")
        listed = set(changed)
        for path, want in sorted(written.items()):
            if path in listed or not isinstance(want, str):
                continue
            f = d.joinpath(*path.split("/"))
            if not os.path.lexists(f):
                continue  # a removed file holds nothing the snapshot does not; git status reports a removal it sees
            if not spelled(path):
                changed.append(path + " (renamed: the spelling of its name or of a folder on its way changed)")
                listed.add(path)
                continue
            try:
                same = sha256_file(f) == want
            except OSError:
                same = False  # no longer a regular file
            if not same:
                changed.append(path)
                listed.add(path)
    # A clean filter can hide an edit from git status (a notebook filter that strips outputs, for
    # example), so files with a filter are compared byte for byte with what checkout wrote.
    if blobs:
        attrs = run_git(d, ["check-attr", "-z", "--stdin", "filter"],
                        input_bytes=b"\0".join(p.encode("utf-8", "surrogateescape") for p in blobs) + b"\0",
                        check=False)
        if attrs.returncode != 0:
            return changed + ["(could not read filter attributes; treating the inspection worktree as changed)"]
        parts = attrs.stdout.split(b"\0")
        for i in range(0, len(parts) - 2, 3):
            path, value = parts[i].decode("utf-8", "surrogateescape"), parts[i + 2]
            if value in (b"unspecified", b"unset") or path in changed or copy_intact(path):
                continue
            f = d.joinpath(*path.split("/"))
            if not f.is_file():
                continue  # git status already reports a deleted file
            want = run_git(d, ["cat-file", "--filters", f"{commit or 'HEAD'}:{path}"], check=False)
            try:
                same = want.returncode == 0 and f.read_bytes() == want.stdout
            except OSError:
                same = False
            if not same:
                # Kept rather than risked: an edit the clean filter hides looks the same here as a
                # smudge filter whose output varies, such as one that stamps the time.
                changed.append(f"{path} (differs from what checkout writes through its filter; if you made no "
                               "edit there, its filter output varies, and --discard is safe)")
    # A copied artifact is byte-exact evidence: it counts as unchanged only while its bytes hash to what inspect
    # copied, whatever git status says. Git compares a file with what checkout wrote, after normalizing it, so
    # an artifact copy edited back to checkout's line endings looked unchanged (X-02).
    for path in copied:
        if not copy_intact(path):
            changed.append(path)
        elif not spelled(path):
            changed.append(path + " (renamed: the spelling of its name or of a folder on its way changed)")
    if not IS_WINDOWS:
        modes = rec.get("exec_modes")
        if not isinstance(modes, dict):
            changed.append("(this inspection has no record of its original executable modes; "
                           "if you changed nothing there, --discard is safe)")
        else:
            expected = set(written if isinstance(written, dict) else {}) | set(copied)
            for path in sorted(expected):
                f = d.joinpath(*path.split("/"))
                if not os.path.lexists(f):
                    continue
                want = modes.get(path)
                try:
                    with _open_regular(f) as opened:
                        mode = os.fstat(opened.fileno()).st_mode & 0o111
                    intact = type(want) is int and not (want & ~0o111) and mode == want
                except OSError:
                    intact = False
                if not intact:
                    changed.append(path + " (executable mode changed or could not be checked)")
    return sorted(set(changed))


def _admin_names(admin: Path, d: Path) -> bool:
    """True when git's record of a worktree, the folder admin, names the folder d (by its last two
    names, so a record written before the repository was moved still matches)."""
    try:
        named = _admin_record(admin)
    except (OSError, ValueError):
        return False
    if os.path.lexists(named):
        # The record names an existing folder: it must be this one, not a copy someone repaired (R14-05).
        try:
            return os.path.samefile(named, d / ".git")
        except OSError:
            return False
    return named.name == ".git" and named.parent.name == d.name  # a repository moved since


def _inspection_admin(repo: Repo, d: Path):
    """(git's record of the inspection worktree d, or None; why d must be kept, or None). Its .git must
    be a file naming a worktree of this repository: a folder holding a repository of its own, or a
    worktree of another one, is never removed. A locked worktree is kept. After the repository was
    moved, the .git file names the old place; git's record of the worktree keeps its name (R13-09)."""
    gitfile = d / ".git"
    try:
        if _is_link(d) or not stat_mod.S_ISREG(os.lstat(gitfile).st_mode):
            return None, "its .git is not a worktree file; it is not a worktree of this repository, so pecia leaves it"
        line = _read_regular(gitfile, 4096).decode("utf-8").strip()
    except FileNotFoundError:
        line = None  # never finished, or emptied: nothing of git's to keep
    except (OSError, ValueError):
        return None, "its .git file cannot be read; pecia leaves it"
    worktrees = repo.common_dir() / "worktrees"
    if line is None:
        cand = worktrees / d.name
        if not _admin_names(cand, d):
            return None, None
        if os.path.lexists(cand / "locked"):  # R14-06
            return None, f"the worktree is locked (git worktree unlock {d.name} first)"
        return cand, None
    if not line.startswith("gitdir:"):
        return None, "its .git file names no git directory; pecia leaves it"
    named = Path(line[7:].strip())
    named = named if named.is_absolute() else d / named
    if os.path.lexists(named):
        try:
            ours = os.path.samefile(named.parent, worktrees)
        except OSError:
            ours = False
        if not ours:
            return None, "it is a worktree of another repository; pecia leaves it"
    admin = worktrees / named.name
    if not _admin_names(admin, d):
        return None, None  # git keeps no record of this folder, or the record is another worktree's
    if os.path.lexists(admin / "locked"):
        return None, f"the worktree is locked (git worktree unlock {fwd(d)} first)"
    return admin, None


def _not_the_inspection(rec: dict, d: Path, admin) -> str | None:
    """Why the folder d, or git's worktree record admin, is not the one recover inspect made and recorded, or
    None. recover_close never gets this far with a record that holds no identity (J-01)."""
    want = rec.get("folder")
    if isinstance(want, list):
        try:
            now = list(_ident(os.lstat(d)))
        except OSError:
            now = None
        if now != want:
            return "the folder inspect made was removed, and this is another folder at the same name"
        if admin is None and os.path.lexists(d):
            # inspect always makes a worktree, and its .git file outlives git's record of it (R21-01).
            try:
                worktree = stat_mod.S_ISREG(os.lstat(d / ".git").st_mode)
            except OSError:
                worktree = False
            if not worktree:
                return "the folder inspect made was removed, and this is another folder at the same name"
    made = rec.get("admin")
    if isinstance(made, dict) and admin is not None:
        try:
            now = list(_ident(os.lstat(admin)))
        except OSError:
            now = None
        if admin.name != made.get("name") or now != made.get("ident"):
            return "git's record of this worktree is not the one inspect made"
        token = made.get("token")
        if isinstance(token, str) and _read_inspect_token(admin) != token:
            return "git's record of this worktree is not the one inspect made"
    return None


_INSPECT_TOKEN = "pecia-inspect"


def _write_inspect_token(admin: Path, token: str) -> None:
    """Created exclusively through git's record of the worktree, held from the repository's bases. It was opened
    by its full path, so a folder on the way swapped for a link could send it elsewhere (M-01)."""
    fd = _create_excl(admin / _INSPECT_TOKEN)
    try:
        os.write(fd, token.encode("ascii"))
    finally:
        os.close(fd)


def _read_inspect_token(admin: Path) -> str | None:
    try:
        with _held_dir(admin) as d, d.open_read(_INSPECT_TOKEN) as f:
            return f.read(64).decode("ascii", "replace").strip()
    except (OSError, PeciaError):
        return None


def recover_close(repo: Repo, target: str | None, discard: bool = False) -> dict:
    """Remove inspection worktrees. One that holds changes of its own is kept unless discard is set,
    because edits made there exist nowhere else."""
    base = _runtime_dir(repo, "recover")
    res = {"closed": [], "kept": []}
    if not base.is_dir():
        return res
    for d in sorted(base.iterdir()):
        if target and target not in (d.name, str(d), fwd(d)):
            continue
        if _is_link(d):
            # git would resolve it and remove whatever worktree it points to (R6-02).
            res["kept"].append({"path": fwd(d), "link": True, "changes": [
                "(a symlink or junction, not an inspection worktree pecia made; pecia does not follow it, and "
                "--discard does not remove it. Delete the link itself by hand.)"]})
            continue
        rec = load_json(_inspect_record(repo, d), None)
        if not (isinstance(rec, dict) and isinstance(rec.get("commit"), str) and rec.get("name", d.name) == d.name):
            # Only folders recover inspect made are ever removed, even with --discard (V-03).
            res["kept"].append({"path": fwd(d), "unowned": True, "changes": [
                "(not an inspection worktree pecia made: it has no inspect record. pecia never removes it, "
                "with or without --discard. If it is yours, move it out of this folder.)"]})
            continue
        if rec.get("pending") or not isinstance(rec.get("folder"), list):
            # Nothing proves this folder is the one inspect made: inspect was interrupted before it recorded the
            # folder, or the record comes from 0.1.2rc9 or earlier. A folder is removed only on that proof, so a
            # later worktree at this name, with the work in it, is never taken for pecia's (J-01).
            res["kept"].append({"path": fwd(d), "unowned": True, "changes": [
                "(pecia holds no proof that this is the inspection worktree it made: inspect did not finish, or an "
                "earlier version made it. pecia never removes it, with or without --discard. If it is an unfinished "
                f"inspection you do not need, remove it with git worktree remove --force {fwd(d)}.)"]})
            continue
        admin, problem = _inspection_admin(repo, d) if os.path.lexists(d) else (None, None)
        if problem:
            res["kept"].append({"path": fwd(d), "final": True, "changes": [f"({problem})"]})
            continue
        stale = _not_the_inspection(rec, d, admin)
        if stale:
            # The record outlived the folder inspect made: removing this one, even with --discard, would delete
            # a folder or a worktree record pecia did not make (Y-04). Only the stale record goes.
            try:
                _unlink_at(_inspect_record(repo, d))
            except (OSError, PeciaError):
                pass
            res["kept"].append({"path": fwd(d), "unowned": True, "changes": [
                f"(not the inspection worktree pecia made at this name: {stale}. pecia never removes it, with or "
                "without --discard, and has dropped its out-of-date record. If it is yours, move it out of this folder.)"]})
            continue
        changes = inspect_changes(repo, d) if d.is_dir() else []
        if changes and not discard:
            res["kept"].append({"path": fwd(d), "changes": changes[:200]})
            continue
        # Removed by pecia itself inside the held recover folder, never through a path git would resolve:
        # a link swapped in after the checks above is removed as a link, never followed (R6-02, V-05).
        _rmtree_at(d)
        if os.path.lexists(d):
            res["kept"].append({"path": fwd(d), "final": True, "changes": [
                "(could not remove all of it; the rest is still there)"]})
            continue
        if admin is not None:
            # git's record of this one worktree only. git worktree prune would also drop the records of
            # other worktrees whose folders are missing right now, such as one on a drive that is not
            # mounted, with their staged work and history (R13-01).
            _rmtree_at(admin)
        try:
            _unlink_at(_inspect_record(repo, d))
        except (OSError, PeciaError):
            pass
        res["closed"].append(fwd(d))
    if res["closed"] or res["kept"]:
        repo.log_event("recover_close", closed=res["closed"], kept=res["kept"], discard=discard)
    return res


# ---------------------------------------------------------------- lock and guard

def pid_alive(pid) -> bool:
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if IS_WINDOWS:
        # os.kill(pid, 0) would terminate the process on Windows; query it instead.
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        k32.GetExitCodeProcess.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        h = k32.OpenProcess(0x1000, False, pid)
        if not h:
            return ctypes.get_last_error() == 5
        try:
            code = wintypes.DWORD()
            if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
                return True
            return code.value == 259
        finally:
            k32.CloseHandle(h)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def proc_token(pid):
    """A start-time token for a process, used to tell a live process from a recycled pid.
    Returns None when the platform offers no cheap way to read it."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return None
    if IS_WINDOWS:
        try:
            import ctypes
            from ctypes import wintypes
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            k32.OpenProcess.restype = wintypes.HANDLE
            k32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
            k32.GetProcessTimes.restype = wintypes.BOOL
            k32.CloseHandle.argtypes = [wintypes.HANDLE]
            h = k32.OpenProcess(0x1000, False, pid)
            if not h:
                return None
            try:
                t = [wintypes.FILETIME() for _ in range(4)]
                if not k32.GetProcessTimes(h, *[ctypes.byref(x) for x in t]):
                    return None
                return str((t[0].dwHighDateTime << 32) | t[0].dwLowDateTime)
            finally:
                k32.CloseHandle(h)
        except (OSError, AttributeError):
            return None
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read().decode("ascii", "replace")
        return data.rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def _is_zombie(pid) -> bool:
    try:
        with open(f"/proc/{int(pid)}/stat", "rb") as f:
            state = f.read().decode("ascii", "replace").rsplit(")", 1)[1].split()[0]
        return state in ("Z", "X")
    except (OSError, IndexError, ValueError):
        return False


def process_running(pid, token) -> bool:
    if not pid_alive(pid) or (not IS_WINDOWS and _is_zombie(pid)):
        return False
    if token is None:
        return True
    now = proc_token(pid)
    return now is None or now == token


def host_identity() -> str:
    """Machine plus process-table identity. Two sessions share a process table only when hostname,
    boot id and pid namespace all match; a container or WSL with the same hostname does not."""
    parts = [socket.gethostname()]
    if IS_WINDOWS:
        # No /proc here: those names would be read from the root of the current drive, where anyone may create them.
        return "|".join(parts + ["-", "windows"])
    try:
        parts.append(_read_regular(Path("/proc/sys/kernel/random/boot_id"), 256).decode("ascii", "replace").strip())
    except (OSError, ValueError):
        parts.append("-")
    try:
        parts.append(os.readlink("/proc/self/ns/pid"))
    except (OSError, AttributeError):
        parts.append("-")
    return "|".join(parts)


def _process_table():
    """{pid: ppid} for every process, or None when the platform offers no cheap way to read it."""
    if IS_WINDOWS:
        try:
            import ctypes
            from ctypes import wintypes

            class PROCESSENTRY32W(ctypes.Structure):
                _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                            ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                            ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                            ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
                            ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
            k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
            k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
            k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
            k32.CloseHandle.argtypes = [wintypes.HANDLE]
            snap = k32.CreateToolhelp32Snapshot(0x2, 0)
            if not snap or snap == wintypes.HANDLE(-1).value:
                return None
            table = {}
            try:
                e = PROCESSENTRY32W()
                e.dwSize = ctypes.sizeof(PROCESSENTRY32W)
                ok = k32.Process32FirstW(snap, ctypes.byref(e))
                while ok:
                    table[int(e.th32ProcessID)] = int(e.th32ParentProcessID)
                    ok = k32.Process32NextW(snap, ctypes.byref(e))
            finally:
                k32.CloseHandle(snap)
            return table or None
        except (OSError, AttributeError, ValueError):
            return None
    if os.path.isdir("/proc/self"):
        return None  # Linux reads parents lazily from /proc; see _parent_of
    try:
        ps = find_program("ps")  # never one in the current folder (G4-02)
        if ps is None:
            return None
        out = subprocess.run([ps, "-A", "-o", "pid=,ppid="], capture_output=True, timeout=10).stdout
        table = {}
        for line in out.decode().splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                table[int(parts[0])] = int(parts[1])
        return table or None
    except (OSError, subprocess.SubprocessError):
        return None


def _parent_of(pid: int, table):
    if table is not None:
        return table.get(pid)
    if IS_WINDOWS:
        return None  # /proc there would name a folder at the root of the current drive, which anyone may create
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            return int(f.read().decode("ascii", "replace").rsplit(")", 1)[1].split()[1])
    except (OSError, IndexError, ValueError):
        return None


def process_ancestors(limit: int = 32):
    """[(pid, start_token)] for every ancestor of this process, nearest first, or None when the
    platform cannot report parents. A chain is cut where a parent claims to have started after
    its child, which is how a recycled process ID shows itself."""
    table = _process_table()
    if table is None and (IS_WINDOWS or not os.path.isdir("/proc/self")):
        return None
    chain = []
    pid = os.getpid()
    tok = proc_token(pid)
    for _ in range(limit):
        ppid = _parent_of(pid, table)
        if not ppid or ppid == pid or ppid <= 0:
            break
        ptok = proc_token(ppid)
        if tok is not None and ptok is not None:
            try:
                if int(ptok) > int(tok):
                    break
            except ValueError:
                pass
        chain.append((ppid, ptok))
        pid, tok = ppid, ptok
    return chain


def lease_owner_in_ancestry(st: dict, hb: dict, ancestors) -> bool:
    owners = []
    for pid_key, tok_key, src in (("pid", "pid_token", st), ("child_pid", "child_token", st),
                                  ("pid", "pid_token", hb), ("child_pid", "child_token", hb)):
        pid = src.get(pid_key)
        if pid:
            owners.append((int(pid), src.get(tok_key)))
    for apid, atok in ancestors:
        for opid, otok in owners:
            if apid == opid and (otok is None or atok is None or str(otok) == str(atok)):
                return True
    return False


LEASE_NAMES = ("pecia", "lease")


def _lease_dir(repo: Repo, create: bool = False, legacy: bool = False) -> Path:
    """The folder of the lease files that govern repo, those of its coordination tree, the tree the guard judges
    it by (coordination_tree, K-02). Every lease file, the lock, the heartbeats, the takeover claim and the
    hooks-seen records, is found through here.

    They live in pecia's own folder in that tree's git directory, not in .pecia/runtime: git clean -fdx removes
    ignored files from the checkout, and with them a live lease, after which the guard admitted every session
    (K-05). The folder is reached and made through held folders from the repository's bases (the shared git
    directory registered first, so a linked tree's git directory is reached as a child of it), and a link at
    either level is refused, as for .pecia/runtime. legacy names .pecia/runtime, where launchers and claims from
    0.1.2rc11 and earlier keep theirs; a live lease there is still honored (lock_status). legacy may also be the
    lease folder of another worktree of this repository, given as a string, where a lease taken before that
    worktree moved inside this tree, or out of it, still lives (N-05)."""
    tree = coordination_tree(repo)
    state = tree.runtime  # a link at .pecia or .pecia/runtime is still refused here, and the guard fails closed (Q-04)
    if isinstance(legacy, str):
        return Path(legacy)
    if legacy:
        return state
    tree.common_dir()
    gitdir = tree.git_dir()
    folder = gitdir.joinpath(*LEASE_NAMES)
    for p in (gitdir / LEASE_NAMES[0], folder):
        if _is_link(p):
            raise PeciaError(f"{fwd(p)} is a symlink or junction. pecia refuses to keep its write lease through a "
                             "link that can point outside the repository. Replace it with a regular folder.")
    if create:
        _held_dir(folder, create=True).close()
    return folder


def _lock_path(repo: Repo, legacy: bool = False) -> Path:
    return _lease_dir(repo, legacy=legacy) / "lock.json"


def _heartbeat_path(repo: Repo, lease: str, legacy: bool = False) -> Path:
    # One file per lease, so a displaced launcher can never refresh another lease's heartbeat.
    safe = re.sub(r"[^A-Za-z0-9]", "", str(lease))[:64] or "none"
    return _lease_dir(repo, legacy=legacy) / f"heartbeat-{safe}.json"


def _heartbeat_record(repo: Repo, lease: str, legacy: bool = False) -> dict:
    hb = load_json(_heartbeat_path(repo, lease, legacy), None)
    return hb if isinstance(hb, dict) and hb.get("lease_id") == lease else {}


def _heartbeat_ts(repo: Repo, lease: str, legacy: bool = False):
    ts = _num(_heartbeat_record(repo, lease, legacy).get("ts"), -1)
    return ts if ts > 0 else None


def write_heartbeat(repo: Repo, lease: str, **extra):
    """Refresh this lease's heartbeat only while lock.json still names this lease. The heartbeat
    also carries the agent child pid, so recording it never waits on the takeover claim. Returns True when written,
    False when lock.json names another lease or none, and None when it cannot be read now, which says nothing about
    who holds the lease: the launcher then tries again at its next beat instead of giving the lease up (G2-09)."""
    data = _read_lock(repo)
    if isinstance(data, dict) and data.get("unreadable"):
        return None
    if not isinstance(data, dict) or data.get("lease_id") != lease:
        return False
    rec = _heartbeat_record(repo, lease)
    # The launcher identity is copied here so the guard can still bind a session to its process
    # tree when lock.json itself becomes unreadable.
    rec.update({"lease_id": lease, "ts": time.time(), "pid": data.get("pid"), "pid_token": data.get("pid_token"),
                "host_id": data.get("host_id")}, **extra)
    atomic_write_json(_heartbeat_path(repo, lease), rec)
    return True


def _read_lock(repo: Repo, legacy: bool = False):
    lp = _lock_path(repo, legacy)
    for _ in range(12):
        if not os.path.lexists(lp):
            return None
        data = load_json(lp, None)
        # A lock is valid only with a string lease and a numeric start time. Anything else is
        # treated as unreadable, which blocks, rather than as stale, which would allow.
        if (isinstance(data, dict) and isinstance(data.get("lease_id"), str) and data["lease_id"]
                and isinstance(data.get("started_epoch"), (int, float))
                and not isinstance(data.get("started_epoch"), bool)):
            return data
        time.sleep(0.025)
    # The file exists but cannot be read or validated: treat it as held by an unknown writer.
    return {"lease_id": None, "agent": "unknown (lock file unreadable)", "unreadable": True,
            "started": "unknown", "pid": None, "host": None}


def lock_status(repo: Repo, policy: dict | None = None) -> dict | None:
    """The lease that governs repo, or None. A live lease in the folder 0.1.2rc11 and earlier used is still a
    lease: a launcher or claim made by an older pecia may be running while this one judges (K-05). The record
    carries legacy True then, so its heartbeat is read from the same folder."""
    now = _lock_status_at(repo, policy, False)
    if now is not None and not now["stale"]:
        if not now.get("unreadable"):
            moved = _displaced_lease(repo, policy)
            if moved is not None and moved.get("lease_id") != now.get("lease_id"):
                # Two live leases govern this tree: its own, and one a worktree brought with it when git worktree move put
                # it inside this tree. The tree's own used to win alone, admitting its agent where the other lease holds
                # and blocking that lease's holder (G2-03). Neither wins: the guard blocks every session until one ends.
                return dict(now, conflict=moved)
        return now
    try:
        old = _lock_status_at(repo, policy, True)
    except PeciaError:
        old = None
    if old is not None and not old["stale"]:
        return old
    moved = _displaced_lease(repo, policy)
    if moved is not None:
        return moved
    if old is not None and now is None:
        return old
    return now


def _lease_where(st: dict):
    """Where a lease record from lock_status keeps its heartbeats: the legacy argument of the lease file helpers."""
    return st.get("displaced") or bool(st.get("legacy"))


def _admin_record(admin: Path) -> Path:
    """The .git file that git's record of a linked worktree, the folder admin, names. git 2.48 and later can write it
    relative to the record's own folder (worktree.useRelativePaths); it is resolved there, not against the folder a
    command runs in (N-05)."""
    line = _read_regular(admin / "gitdir", 4096).decode("utf-8").strip()
    if not line or "\0" in line:
        raise ValueError("git's record of this worktree names no folder")
    named = Path(line)
    return named if named.is_absolute() else Path(os.path.normpath(os.path.join(os.fspath(admin), line)))


def _worktree_records(repo: Repo) -> list:
    """(git directory, working tree root) for the main tree and every linked worktree git keeps a record of."""
    common = repo.common_dir()
    entries = [(common, common.parent)]
    wt = common / "worktrees"
    try:
        names = sorted(os.listdir(wt))
    except OSError:
        names = []
    for n in names:
        try:
            entries.append((wt / n, _admin_record(wt / n).parent))
        except (OSError, ValueError):
            continue
    return entries


def _displaced_lease(repo: Repo, policy: dict | None):
    """A live lease kept in the lease folder of another worktree that still governs this coordination tree: one taken
    for a worktree that now lies inside this tree (moved there with git worktree move), or one whose record names
    the git directory of this tree or of a worktree inside it (taken while that worktree lay inside another tree,
    which it has since left). The coordination tree a lease is kept under can change while the lease lives (N-05).
    A record that cannot be read there, or one for a worktree that no longer exists, governs nothing here: it is
    not this tree's lease. A record whose git directory no longer lies where it names, as after moving the main
    checkout, is matched by the token kept in that directory (E2-02). Returns the lease record, or None."""
    tree = coordination_tree(repo)
    try:
        own = os.path.normcase(os.path.normpath(str(_lease_dir(tree))))
        top = tree.root.resolve()
        entries = _worktree_records(tree)
    except (PeciaError, OSError, ValueError):
        return None

    def norm(p):
        return os.path.normcase(os.path.normpath(os.fspath(p)))

    def inside(root):
        try:
            r = Path(root).resolve()
        except (OSError, RuntimeError, ValueError):
            return False
        return r == top or top in r.parents
    candidates = [(g, r) for g, r in entries if norm(g.joinpath(*LEASE_NAMES)) != own
                  and os.path.lexists(g.joinpath(*LEASE_NAMES, "lock.json"))]
    if not candidates:
        return None
    governed_dirs = [g for g, r in entries if inside(r)]
    try:
        governed_dirs.append(tree.git_dir())
    except (PeciaError, OSError):
        pass
    governed = {norm(g) for g in governed_dirs}
    tokens: list = []

    def governed_token(kept: str) -> bool:
        # Moving the main checkout, with git worktree repair after it, moves every git directory, so the folder a
        # record names no longer exists; the token kept in that git directory moved with it (E2-02).
        if not tokens:
            tokens.append({t for t in (_worktree_token(Path(g)) for g in governed_dirs) if t})
        return kept in tokens[0]
    for gitdir, root in candidates:
        folder = gitdir.joinpath(*LEASE_NAMES)
        data = load_json(folder / "lock.json", None)
        if not (isinstance(data, dict) and isinstance(data.get("lease_id"), str) and data["lease_id"]
                and isinstance(data.get("started_epoch"), (int, float))):
            continue  # not a lease this pecia could read; it governs nothing here, and is not waited for
        moved_in = inside(root) and os.path.isdir(root)
        named, named_here = data.get("gitdir"), False
        if isinstance(named, str) and named and norm(named) in governed:
            # git reuses a removed worktree's record name, so the folder's identity must match as well when the
            # record kept it: a later worktree under that name is not the one the lease was taken in.
            kept_token, now_token = data.get("gitdir_token"), None
            if isinstance(kept_token, str) and kept_token:
                now_token = _worktree_token(Path(named))
            if now_token:
                named_here = now_token == kept_token
            else:
                kept = data.get("gitdir_id")
                try:
                    now = list(_ident(os.stat(named)))
                except (OSError, ValueError):
                    now = None
                named_here = not (isinstance(kept, list) and now is not None and kept != now)
        else:
            kept_token = data.get("gitdir_token")
            named_here = isinstance(kept_token, str) and bool(kept_token) and governed_token(kept_token)
        if not (moved_in or named_here):
            continue
        st = _lock_status_at(tree, policy, str(folder))
        if st is not None and not st["stale"] and not st.get("unreadable"):
            return st
    return None


def _lock_status_at(repo: Repo, policy: dict | None, legacy) -> dict | None:
    data = _read_lock(repo, legacy)
    if not data:
        return None
    data = dict(data, legacy=legacy is True, displaced=legacy if isinstance(legacy, str) else None,
                lock_path=fwd(_lock_path(repo, legacy)))
    if data.get("unreadable"):
        return dict(data, stale=False, stale_reasons=[], heartbeat_age=None)
    if data.get("mode") == "claimed":
        expires = _num(data.get("expires_epoch"), 0)
        reasons = [] if time.time() < expires else ["claim expired"]
        return dict(data, stale=bool(reasons), stale_reasons=reasons, heartbeat_age=None)
    policy = policy or load_policy(repo)
    stale_after = _num(policy.get("lock", {}).get("stale_after_seconds"), 120)
    beat = _heartbeat_ts(repo, data["lease_id"], legacy) or _num(data.get("started_epoch"), 0)
    age = time.time() - beat
    same_host = data.get("host_id") == host_identity() if data.get("host_id") else data.get("host") == socket.gethostname()
    hb = _heartbeat_record(repo, data["lease_id"], legacy)
    reasons = []
    if same_host:
        # On this machine, liveness is decided by processes, not clocks: the lease holds while the
        # launcher or the agent it started is running, even if the launcher was killed.
        launcher = process_running(data.get("pid"), data.get("pid_token"))
        child_pid = data.get("child_pid") or hb.get("child_pid")
        child_token = data.get("child_token") or hb.get("child_token")
        child = bool(child_pid) and process_running(child_pid, child_token)
        if not launcher and not child:
            reasons.append("neither the launcher nor its agent is running")
    elif age > stale_after:
        reasons.append(f"heartbeat from host {data.get('host')} is {int(age)} s old")
    data = dict(data)
    data["stale"] = bool(reasons)
    data["stale_reasons"] = reasons
    data["heartbeat_age"] = int(age)
    return data


def _held_message(st: dict) -> str:
    if st.get("unreadable"):
        return ("a lock file exists for this working tree but cannot be read. Inspect "
                f"{st.get('lock_path') or 'lock.json'}; delete it by hand only if no agent is running here.")
    return (f"the write lease for this working tree is held by {st.get('agent')} "
            f"(launcher pid {st.get('pid')} on {st.get('host')}, since {st.get('started')}). "
            "Wait for it to finish, or launch with --worktree NAME to work in an isolated worktree.")


_WORKTREE_TOKEN = "worktree-id"


def _worktree_token(gitdir: Path, create: bool = False) -> str | None:
    """A random token pecia keeps in pecia/ in a worktree's git directory, made the first time a lease is taken there.
    git keeps that folder through git worktree move and makes a new one for a later worktree it gives the same name,
    so the token tells them apart where a folder's number cannot: some file systems renumber a folder, others hand a
    removed folder's number to the next (R21-01, N-05)."""
    folder = Path(gitdir) / LEASE_NAMES[0]
    for _ in range(2):
        try:
            with _held_dir(folder) as d, d.open_read(_WORKTREE_TOKEN) as f:
                token = f.read(64).decode("ascii", "replace").strip()
            if re.fullmatch(r"[0-9a-f]{32}", token):
                return token
            return None
        except (OSError, PeciaError):
            if not create:
                return None
        try:
            _held_dir(folder, create=True).close()
            fd = _create_excl(folder / _WORKTREE_TOKEN)
        except FileExistsError:
            continue  # another process made it first: read that one
        except (OSError, PeciaError):
            return None
        token = secrets.token_hex(16)
        try:
            os.write(fd, token.encode("ascii"))
        finally:
            os.close(fd)
        return token
    return None


def _gitdir_fields(repo: Repo) -> dict:
    """The git directory of the worktree a lease is taken in, with that folder's token and identity, kept in its
    record: git keeps that folder through git worktree move, so the lease is still found after a move changes which
    tree governs it, and the token, or failing it the identity, tells it from a later worktree git gives the same
    name (N-05)."""
    try:
        g = repo.git_dir()
        out = {"gitdir": fwd(g), "gitdir_id": list(_ident(os.stat(g)))}
    except (PeciaError, OSError):
        return {"gitdir": None}
    token = _worktree_token(g, create=True)
    if token:
        out["gitdir_token"] = token
    return out


def _refuse_older_live_lease(repo: Repo, policy: dict | None) -> None:
    """A live lease that a launcher or claim from 0.1.2rc11 or earlier keeps in .pecia/runtime blocks a new one, as
    it would have there. It is never removed or taken over here: the pecia that made it releases it (K-05)."""
    try:
        old = _lock_status_at(repo, policy, True)
    except PeciaError:
        old = None
    if old is not None and not old["stale"]:
        raise LockHeld(_held_message(old))
    moved = _displaced_lease(repo, policy)
    if moved is not None:
        raise LockHeld(_held_message(moved))


def acquire_lock(repo: Repo, agent: str, policy: dict) -> str:
    _refuse_older_live_lease(repo, policy)
    _lease_dir(repo, create=True)
    lease = uuid.uuid4().hex
    record = {"lease_id": lease, "agent": agent, "pid": os.getpid(), "pid_token": proc_token(os.getpid()),
              "child_pid": None, "child_token": None, "host": socket.gethostname(), "host_id": host_identity(),
              "started": iso(),
              "started_epoch": time.time(), "worktree": fwd(repo.root), **_gitdir_fields(repo),
              "version": VERSION}
    lp = _lock_path(repo)
    claim = _lease_dir(repo) / "lock.takeover"
    for _ in range(200):
        try:
            fd = _create_excl(lp)
        except FileExistsError:
            st = lock_status(repo, policy)
            if st is None:
                continue
            if not st["stale"]:
                raise LockHeld(_held_message(st))
            # Stale: serialize takeovers through a claim file so two contenders cannot both win.
            try:
                cfd = _create_excl(claim)
            except FileExistsError:
                try:
                    if time.time() - claim.stat().st_mtime > 30:
                        _unlink_at(claim)
                except OSError:
                    pass
                time.sleep(0.05)
                continue
            try:
                os.close(cfd)
                again = lock_status(repo, policy)
                if again is not None and again.get("lease_id") == st.get("lease_id") and again["stale"]:
                    atomic_write_json(lp, record)
                    write_heartbeat(repo, lease)
                    repo.log_event("lock_stale_taken_over", previous=st.get("lease_id"),
                                   reasons=st["stale_reasons"], lease=lease, agent=agent)
                    return lease
            finally:
                try:
                    _unlink_at(claim)
                except OSError:
                    pass
            continue
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(record, f, indent=2, sort_keys=True)
        write_heartbeat(repo, lease)
        repo.log_event("lock_acquired", lease=lease, agent=agent)
        return lease
    raise PeciaError("could not acquire the write lease after repeated attempts")


def update_lock(repo: Repo, lease: str, **fields) -> None:
    """Read-modify-write under the takeover claim, so a concurrent takeover cannot be overwritten."""
    claim = _lease_dir(repo) / "lock.takeover"
    for _ in range(100):
        try:
            cfd = _create_excl(claim)
        except FileExistsError:
            try:
                if time.time() - claim.stat().st_mtime > 30:
                    _unlink_at(claim)
            except OSError:
                pass
            time.sleep(0.02)
            continue
        try:
            os.close(cfd)
            data = _read_lock(repo)
            if isinstance(data, dict) and data.get("lease_id") == lease:
                data.update(fields)
                atomic_write_json(_lock_path(repo), data)
            return
        finally:
            try:
                _unlink_at(claim)
            except OSError:
                pass
    raise OSError("could not update the lock: takeover claim busy")


def _with_takeover_claim(repo: Repo, fn, attempts: int = 250, legacy: bool = False):
    """Run fn while holding the lock.takeover claim, the same claim stale takeovers and lock
    updates use, so a release can never delete a lease another process has just taken over."""
    claim = _lease_dir(repo, legacy=legacy) / "lock.takeover"
    for _ in range(attempts):
        try:
            cfd = _create_excl(claim)
        except FileExistsError:
            try:
                if time.time() - claim.stat().st_mtime > 30:
                    _unlink_at(claim)
            except OSError:
                pass
            time.sleep(0.02)
            continue
        try:
            os.close(cfd)
            return fn()
        finally:
            try:
                _unlink_at(claim)
            except OSError:
                pass
    raise OSError("takeover claim stayed busy")


def release_lock(repo: Repo, lease: str) -> bool:
    def release():
        data = _read_lock(repo)
        if isinstance(data, dict) and data.get("lease_id") == lease:
            try:
                _unlink_at(_lock_path(repo))
            except OSError:
                return False
            repo.log_event("lock_released", lease=lease)
            return True
        return False
    try:
        released = _with_takeover_claim(repo, release)
    except OSError:
        released = False
    try:
        _unlink_at(_heartbeat_path(repo, lease))
    except OSError:
        pass
    return released


def _refuse_claim_without_sound_hooks(repo: Repo) -> None:
    """claim runs the hook checks launch runs (_hook_launch_problems), for both agents, before it takes the lease: a claim
    says other agents are blocked, which holds only where their hooks judge this tree. In a copied project folder the
    hooks name the original's runner and tree, so they judge the original's lease and admit every session in the copy
    (RP-10). Refuses, as launch does, naming the command that rewrites the hooks."""
    found: dict = {}
    for agent in HOOK_FILES:
        for tree, problems in _hook_launch_problems(repo, agent):
            found.setdefault(str(tree.root), (tree, set()))[1].update(problems)
    if not found:
        return
    lines = [p for _t, ps in found.values() for p in sorted(ps)]
    fixes = [f"{pecia_cmd(repo)}" + ("" if t.root == repo.root else f" --repo {fwd(t.root)}") +
             " init --apply --install-hooks --update-hooks" for t, _ps in found.values()]
    by_hand = any("fix that entry by hand" in ln for ln in lines)
    raise PeciaError("the pecia hooks here would not enforce a claim:\n  " + "\n  ".join(lines) +
                     "\nNo claim was taken: other agents would not be blocked. Rewrite the hooks with: " +
                     " ; ".join(fixes) + " (Codex then asks you to approve the changed hooks in /hooks), and claim "
                     "again." + (" That command leaves an entry that also runs a command of yours alone, so fix such "
                                 "an entry by hand." if by_hand else ""))


def claim_lease(repo: Repo, agent: str, hours: float, policy: dict) -> str:
    """A lease for sessions the launcher does not start, such as Claude Code inside the desktop
    app. The guard admits hook calls whose --agent matches until the claim expires or is released.
    Weaker than a launched lease: any session of that agent type in this working tree passes."""
    hours = float(hours)
    if not (0 < hours < float("inf")):
        # A claim lasts as long as asked; it was silently held for at least three minutes (K-04).
        raise PeciaError("--hours must be a positive number")
    _refuse_older_live_lease(repo, policy)
    _lease_dir(repo, create=True)
    lease = uuid.uuid4().hex
    record = {"lease_id": lease, "agent": agent, "mode": "claimed", "pid": None, "host": socket.gethostname(),
              "host_id": host_identity(), "started": iso(), "started_epoch": time.time(),
              "expires_epoch": time.time() + hours * 3600, "worktree": fwd(repo.root), **_gitdir_fields(repo),
              "version": VERSION}
    lp = _lock_path(repo)
    try:
        fd = _create_excl(lp)
    except FileExistsError:
        st = lock_status(repo, policy)
        if st is not None and not st["stale"]:
            raise LockHeld(_held_message(st))

        def swap():
            again = lock_status(repo, policy)
            if again is not None and not again["stale"]:
                raise LockHeld(_held_message(again))
            atomic_write_json(lp, record)
        _with_takeover_claim(repo, swap)
        repo.log_event("lease_claimed", lease=lease, agent=agent, hours=hours, replaced_stale=True)
        return lease
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        json.dump(record, f, indent=2, sort_keys=True)
    repo.log_event("lease_claimed", lease=lease, agent=agent, hours=hours)
    return lease


def _conflict_remedies(repo: Repo, st: dict) -> str:
    """What ends a conflict of two live leases (G2-03), naming only what works: release ends the lease that governs, and
    only when that is a claim; a launched session's lease ends with its launcher (IR31-07)."""
    other = st.get("conflict") or {}
    ways = []
    if st.get("mode") != "claimed" or other.get("mode") != "claimed":
        ways.append("stop the launcher of the launched session")
    if st.get("mode") == "claimed":
        ways.append(f"end the claim that governs here with {pecia_cmd(repo)} release, run in this tree")
    ways.append("or move the worktree back out")
    return "; ".join(ways)


def release_claim(repo: Repo) -> bool:
    def release(legacy=False):
        data = _read_lock(repo, legacy)
        if isinstance(data, dict) and data.get("mode") == "claimed":
            _unlink_at(_lock_path(repo, legacy))
            repo.log_event("lease_claim_released", lease=data.get("lease_id"), agent=data.get("agent"), legacy=legacy)
            return True
        if isinstance(data, dict) and not data.get("unreadable"):
            raise PeciaError("the current lease belongs to a launched session; it is released when that "
                               "launcher exits")
        return False
    governing = lock_status(repo)
    if (governing is not None and governing.get("mode") != "claimed" and not governing.get("stale")
            and not governing.get("unreadable")):
        # A live launched lease governs, wherever it is kept: release ends nothing, and an expired claim of the tree's
        # own does not stand in for it (R24-10).
        raise PeciaError("the current lease belongs to a launched session; it is released when that launcher exits")
    if (governing is not None and governing.get("mode") == "claimed" and not governing.get("stale")
            and not governing.get("unreadable")):
        # The live claim that governs this tree is the one release ends, wherever it is kept: an expired claim of
        # this tree's own must not stand in for a live one moved here with its worktree (E2-01).
        where = _lease_where(governing)
        return _with_takeover_claim(repo, lambda: release(where), legacy=where)
    if _with_takeover_claim(repo, release):
        return True
    if _read_lock(repo) is not None:
        return False
    moved = _displaced_lease(repo, None)
    if moved is not None and moved.get("mode") == "claimed" and moved.get("displaced"):
        # A claim taken for a worktree before it moved into or out of this tree is released from here (N-05).
        where = moved["displaced"]
        return _with_takeover_claim(repo, lambda: release(where), legacy=where)
    try:
        if not os.path.lexists(_lock_path(repo, legacy=True)):
            return False
    except PeciaError:
        return False
    # A claim made by 0.1.2rc11 or earlier is in .pecia/runtime; release ends it the way that pecia's release did.
    return _with_takeover_claim(repo, lambda: release(True), legacy=True)


def guard_decision(repo: Repo, env_lease: str | None, policy: dict, agent: str | None = None,
                   accepted: dict | None = None) -> tuple[bool, str]:
    """(allowed, message). accepted, when given, gets the lease ID this process presented once the guard has
    accepted it as the launched session's own: the hooks-seen record attests only to such a run (E2-03)."""
    def own(ok: bool, msg: str = "") -> tuple[bool, str]:
        if ok and accepted is not None:
            accepted["lease"] = env_lease
        return ok, msg
    st = lock_status(repo, policy)
    if st is not None and st.get("conflict"):
        other = st["conflict"]

        def who(x):
            return (f"{x.get('agent')} ({'a claim' if x.get('mode') == 'claimed' else 'a launched session'}, lease "
                    f"{str(x.get('lease_id'))[:8]})")
        repo.log_event("guard_lease_conflict", agent=agent, lease=st.get("lease_id"), other=other.get("lease_id"))
        return False, (f"pecia guard: two live write leases govern this working tree, {who(st)} and {who(other)}, the "
                       "second brought here by git worktree move with the worktree it was taken in. Every session "
                       f"here is blocked until one of them ends. Stop and tell the user: {_conflict_remedies(repo, st)}.")
    if st is None:
        if policy.get("guard", {}).get("require_lease"):
            return False, ("pecia guard: no write lease is held for this working tree and policy requires one. "
                           f"Start the session with {pecia_cmd(repo)} launch AGENT.")
        return True, ""
    if st.get("unreadable"):
        stale_after = _num(policy.get("lock", {}).get("stale_after_seconds"), 120)
        old = _lease_where(st)
        ts = _heartbeat_ts(repo, env_lease, old) if env_lease else None
        if ts is not None and time.time() - ts <= stale_after:
            gpol = policy.get("guard", {})
            if gpol.get("bind_process", True):
                hb = _heartbeat_record(repo, env_lease, old)
                hb_host = hb.get("host_id")
                foreign = bool(hb_host) and hb_host != host_identity()
                if foreign and gpol.get("allow_foreign_host_lease", False) is not True:
                    repo.log_event("guard_token_foreign_host", agent=agent, lease=env_lease, lock="unreadable")
                    return False, ("pecia guard: the lock file cannot be read, and the session holding this lease "
                                   "runs on another host or process namespace, so this process cannot be checked. "
                                   "Blocked. Stop and tell the user.")
                if not foreign:
                    # With the lock unreadable, the heartbeat is the only record of the owner, so
                    # ownership must be confirmed through the process tree or the session is blocked.
                    ancestors = process_ancestors()
                    if ancestors is None or not lease_owner_in_ancestry({}, hb, ancestors):
                        repo.log_event("guard_token_outside_session", agent=agent, lease=env_lease,
                                       lock="unreadable", ancestry="unavailable" if ancestors is None else "outside")
                        return False, ("pecia guard: the lock file cannot be read and this process cannot be "
                                       "confirmed as part of the session pecia launched, so it is blocked. Stop and "
                                       f"tell the user. Run {pecia_cmd(repo)} status.")
            return own(True, "pecia guard: lock file unreadable; allowing the session whose lease has a live heartbeat.")
        return False, ("pecia guard: a lock file exists for this working tree but cannot be read, so this "
                       "session is blocked as a precaution. Stop and tell the user.")
    if st["stale"]:
        why = "; ".join(st["stale_reasons"])
        if policy.get("guard", {}).get("require_lease"):
            # A stale lease is no lease: the policy that requires one still applies (D-02).
            return False, (f"pecia guard: the write lease for this working tree is stale ({why}), and policy requires "
                           f"a live one. Start the session with {pecia_cmd(repo)} launch AGENT, or claim it with "
                           f"{pecia_cmd(repo)} claim AGENT.")
        return True, "pecia guard: a stale lease exists (" + why + "); allowing."
    if st.get("mode") == "claimed":
        if agent and agent == st.get("agent"):
            return True, ""
        return False, (f"pecia guard: {st.get('agent')} has claimed the write lease for this working tree "
                       f"until {_dt.datetime.fromtimestamp(_num(st.get('expires_epoch'), 0)).strftime('%Y-%m-%d %H:%M')}. "
                       f"Stop and tell the user. The claim ends with: {pecia_cmd(repo)} release.")
    if env_lease and env_lease == st.get("lease_id"):
        gpol = policy.get("guard", {})
        if not gpol.get("bind_process", True):
            return own(True)
        same_host = st.get("host_id") == host_identity() if st.get("host_id") else True
        if not same_host:
            # The launcher that holds this lease runs on another machine, container or process
            # namespace, so this process cannot be its descendant and its ancestry cannot be checked.
            # A lease ID alone is a copyable string; it does not prove this process belongs to that
            # session. Cross-host sharing of one working tree is opt-in.
            # Only JSON true trusts a lease across hosts: a string such as "false" was truthy (G2-04).
            if gpol.get("allow_foreign_host_lease", False) is True:
                return own(True)
            repo.log_event("guard_token_foreign_host", agent=agent, lease=st.get("lease_id"),
                           lock_host=st.get("host"))
            return False, (f"pecia guard: this process presented the current lease ID, but the session that holds "
                           f"it runs on another host or process namespace ({st.get('host')}), so the process tree "
                           "cannot be checked and the ID alone does not prove ownership. Blocked. Stop and tell "
                           "the user. Run each agent on the machine whose launcher holds the lease, or set "
                           "guard.allow_foreign_host_lease to true to trust the lease ID across hosts.")
        ancestors = process_ancestors()
        if ancestors is None:
            return own(True)  # this platform cannot report process parents: the lease ID alone decides
        if lease_owner_in_ancestry(st, _heartbeat_record(repo, st["lease_id"], _lease_where(st)), ancestors):
            return own(True)
        repo.log_event("guard_token_outside_session", agent=agent, lease=st.get("lease_id"))
        return False, ("pecia guard: this process presented the current lease ID but does not run inside the "
                       "session pecia launched, so it is blocked. Stop and tell the user.")
    return False, (f"pecia guard: the write lease for this working tree is held by {st.get('agent')} "
                   f"(launcher pid {st.get('pid')}, since {st.get('started')}), and this session does not hold it. "
                   "Stop and tell the user. Do not work around this block. "
                   f"Parallel work belongs in a separate worktree: {pecia_cmd(repo)} launch AGENT --worktree NAME.")


# ---------------------------------------------------------------- templates

STATE_TEMPLATE = """# Project State

This file is the authoritative state record for every agent working in this repository.
Update NEXT, DECISIONS, and SCOPE in the same commit as the work they describe.
Never write the SHA of the commit you are creating. Cite earlier commits only.

## GOAL
- (current phase goal and its acceptance criteria)

## SCOPE
Globs for the paths the current task touches. The consistency check uses them to decide
whether later commits affect this state. Leave the list empty to treat every path as in scope.
- (example: src/**)

## NEXT
- (one concrete next action that a reader with no context can execute)

## DONE
- (completed steps, citing earlier commit SHAs or commit subjects)

## DECISIONS
- (choice, with the reason for it)

## REJECTED
- (approach already tried, with why it failed)

## OPEN
Write each item as ID: text, for example OBL-2: prove lemma 3 holds for n = 0. An ID may also be **OBL-2**
or a trailing (OBL-2). Items without an ID cannot be tracked. Close an item only by adding a DISCHARGED line
to REVIEW.md whose evidence begins with an existing commit SHA or an existing file in this repository.
An item in parentheses, like the example below, is not an obligation; replace it with real ones, or leave it.
- (example: [ ] OBL-1: an unresolved claim, proof obligation, or defect)

## VERIFY
- Command: (exact command)
- Last result: (pass or fail, with date)
"""

REVIEW_TEMPLATE = """# Review Record

## ACCEPTED
- (finding ID, summary, evidence)

## REJECTED
- (finding ID, summary, reason)

## OUTSTANDING
- (defect ID, summary)

## DISCHARGES
Each closed obligation needs one line in this shape. The evidence must BEGIN with an existing commit SHA or an
existing file in this repository (not AGENTS.md, CLAUDE.md, README, or anything under .pecia/). Commit the line
together with the change that closes the obligation. Agreement between models is not evidence.
DISCHARGED <ID>: evidence=<commit SHA or file path, then any description>; by=<agent or person>; date=<YYYY-MM-DD>
"""

AGENTS_BLOCK = """<!-- pecia:begin v0.1 -->
## Cross-agent protocol (pecia)

This repository is worked on by more than one AI agent. The files in .pecia/ are the authoritative record. No conversation transcript is.

1. At session start, run python .pecia/bin/pecia.py check and report the verdict before editing anything.
2. If the verdict is NEEDS_RECONCILIATION, reconcile .pecia/STATE.md with the listed commits and uncommitted files first, then commit that reconciliation.
3. Keep .pecia/STATE.md current. Update NEXT, DECISIONS, and SCOPE in the same commit as the work they describe. Never write the SHA of the commit being created.
4. Never close an OPEN obligation without a DISCHARGED line in .pecia/REVIEW.md that cites evidence. Agreement between models is not evidence.
5. Never run git reset --hard, git clean, git checkout -- PATH, git restore, or git stash on work you did not create in this session. To recover interrupted work, run python .pecia/bin/pecia.py recover plan latest, then recover apply, which never overwrites newer work.
6. Do not edit anything under .pecia/runtime/ or any ref under refs/pecia/.
7. If a write is blocked by the pecia guard, another agent holds the write lease for this working tree. Stop and report it. Do not work around the block.
<!-- pecia:end -->
"""

CLAUDE_MD_TEMPLATE = """@AGENTS.md

## Claude Code
The pecia protocol above applies to every session in this repository.
"""

RESUME_TEMPLATE = """# Resume protocol for {agent}

Generated {ts} by pecia launch in {root}.

Consistency check at launch: {verdict}
{findings}

Steps, in order:
1. Read .pecia/STATE.md and .pecia/REVIEW.md in full.
2. Run python .pecia/bin/pecia.py check and confirm the verdict above still holds.
3. If the verdict is NEEDS_RECONCILIATION, inspect the listed commits and uncommitted files, update STATE.md to match reality, and commit before other work. For interrupted work, run python .pecia/bin/pecia.py recover plan latest, then recover apply, which never overwrites newer work. List in your report every file it names as taken before history moved; acknowledging those is for the user, not you.
4. Run the VERIFY command from STATE.md and report the result.
5. Execute NEXT. Keep OPEN obligations open unless discharged with evidence in REVIEW.md.

Report in one paragraph: the verdict, the verify result, and what you will do next. Then proceed.
"""

# cmd.exe looks for python in the current folder, the repository, before PATH; the variable stops that (G4-02).
SHIM_CMD = "@echo off\r\nsetlocal\r\nset NoDefaultCurrentDirectoryInExePath=1\r\npython \"%~dp0pecia.py\" %*\r\n"
_OLD_SHIMS = ("@echo off\r\npython \"%~dp0pecia.py\" %*\r\n",)  # what earlier versions wrote, replaced by init


def runner_dir(repo: Repo) -> Path:
    return repo.common_dir() / "pecia" / "runner"


def runner_script(repo: Repo) -> Path:
    return runner_dir(repo) / "pecia.py"


def pecia_cmd(repo: Repo) -> str:
    """How to run pecia on this checkout: its own .pecia/bin/pecia.py, or the hook runner on a checkout
    that has none, such as a commit from before init (R4-07)."""
    if repo.path(BIN_REL + "/pecia.py").is_file():
        return f"python {BIN_REL}/pecia.py"
    try:
        r = runner_script(repo)
        if _runner_looks_sound(r):
            return f"python {fwd(r)}"
    except (PeciaError, OSError):
        pass
    return "python pecia.py"


def hook_specs(repo: Repo, python: str) -> tuple[dict, dict]:
    """The hooks run the copy of pecia.py kept in the git directory (install_runner), never the copy in
    the working tree. The hook files are untracked, so they stay when another branch or an older commit
    is checked out, and a checkout without .pecia/bin/pecia.py, or with an older one, must not block every
    prompt or drop the guard (IR-15). --repo pins the working tree, as the script's own location did."""
    return _hook_tables(fwd(python), fwd(runner_script(repo)), fwd(repo.root))


def _hook_tables(py: str, script: str, root: str) -> tuple[dict, dict]:
    pre = [script, "--repo", root]

    def claude_cmd(*args):
        return {"type": "command", "command": py, "args": [*pre, *args], "timeout": 120}

    claude = {"hooks": {
        "UserPromptSubmit": [{"hooks": [claude_cmd("hook", "guard", "--agent", "claude")]}],
        "PreToolUse": [{"matcher": "^(Edit|Write|MultiEdit|NotebookEdit|Bash|PowerShell|EnterWorktree|ExitWorktree|Task|Agent|mcp__.*)$",
                        "hooks": [claude_cmd("hook", "guard", "--agent", "claude")]}],
        "Stop": [{"hooks": [claude_cmd("hook", "snapshot", "--event", "stop", "--agent", "claude")]}],
        "PreCompact": [{"hooks": [claude_cmd("hook", "snapshot", "--event", "precompact", "--agent", "claude")]}],
        "StopFailure": [{"hooks": [claude_cmd("hook", "snapshot", "--event", "stopfailure", "--agent", "claude")]}],
    }}

    def codex_cmd(*args):
        # Codex 0.160 on Windows runs commandWindows through powershell.exe (observed in Q1). A quoted
        # program path is a string expression to PowerShell, so the line starts with the call operator,
        # and single quotes keep $ and backticks literal. The POSIX line goes through sh.
        toks = (py, *pre, *args)
        ps = "& " + " ".join("'" + a.replace("'", "''") + "'" for a in toks)
        sh = " ".join(shlex.quote(a) for a in toks)
        return {"type": "command", "command": sh, "commandWindows": ps, "timeout": 120}

    # Each Codex guard line names its event, so a block is given in the form that event needs even when the hook
    # input cannot be read (D-01): a prompt is blocked with a decision, a tool call with a permission decision.
    codex = {"hooks": {
        "UserPromptSubmit": [{"hooks": [codex_cmd("hook", "guard", "--agent", "codex", "--format", "codex",
                                                  "--event", "prompt")]}],
        "PreToolUse": [{"matcher": "^(Bash|apply_patch|Edit|Write|exec_command|shell|shell_command|mcp__.*)$",
                        "hooks": [codex_cmd("hook", "guard", "--agent", "codex", "--format", "codex",
                                            "--event", "tool")]}],
        "Stop": [{"hooks": [codex_cmd("hook", "snapshot", "--event", "stop", "--agent", "codex")]}],
        "PreCompact": [{"hooks": [codex_cmd("hook", "snapshot", "--event", "precompact", "--agent", "codex")]}],
    }}
    return claude, codex


def _local_exclude_path(repo: Repo) -> Path:
    info = repo.common_dir() / "info"
    path = info / "exclude"
    _refuse_linked_dirs(info)
    if _is_link(path) or (os.path.lexists(path) and not path.is_file()):
        raise UnsafePath(f"{fwd(path)} is a symlink, a junction, or not a file; pecia refuses to write through it. "
                         "Replace it with a regular file.")
    return path


def _argv_run_here(entry: dict) -> list:
    """The argument vector of a hook entry as this machine runs it: on Windows the PowerShell line
    when the entry has one, otherwise the command (with args)."""
    if IS_WINDOWS and isinstance(entry.get("commandWindows"), str):
        forms = _hook_argv({"commandWindows": entry["commandWindows"]})
    else:
        forms = _hook_argv({k: entry[k] for k in ("command", "args") if k in entry})
    return forms[0] if forms and forms[0] else []


def _main_working_tree(repo: Repo):
    """The main working tree when this is a linked worktree whose repository keeps its git directory
    in the usual .git folder; otherwise None. git worktree list cannot be trusted for this: with a
    separate git directory, a submodule, or a bare repository it does not name the main tree first."""
    try:
        common, own = repo.common_dir().resolve(), repo.git_dir()
    except (OSError, PeciaError):
        return None
    if own == common or common.name != ".git" or not common.parent.is_dir():
        return None
    return Repo(common.parent)


def _same_repository(repo: Repo, folder: str) -> bool:
    """Whether folder is in a working tree of repo's repository (the same common git directory). A folder in no
    repository is not; one that cannot be examined counts as the same, so a passing check is never invented and
    a transient error adds no refusal of its own (F2-02)."""
    try:
        other = Repo.discover(folder)
        return other.common_dir().resolve() == repo.common_dir().resolve()
    except PeciaError:
        return False
    except (OSError, ValueError):
        return True


def _hook_launch_problems(repo: Repo, agent: str) -> list:
    """Reasons the pecia hooks this agent may run cannot start (R6-04): an interpreter that does not
    exist, a runner path that is not this repository's (the folder was moved or copied after init),
    a working tree that no longer exists (a worktree moved after init), or no command for this
    system. Those hooks fail on every event, and Codex on Windows then runs unguarded. The launched
    tree's own hook file is checked, and in a linked worktree also the main working tree's, which the
    agents run there. Returns (tree, problems) for each tree with problems."""
    rel = HOOK_FILES.get(agent)
    if not rel:
        return []
    trees = [repo]
    main = _main_working_tree(repo)
    if main is not None:
        trees.append(main)
    runner = os.path.normcase(os.path.normpath(fwd(runner_script(repo))))
    found_all = []
    for tree in trees:
        p = tree.path(rel)
        if not p.is_file():
            continue
        try:
            cfg = json.loads(read_text(p))
        except (ValueError, RecursionError, OSError):
            continue
        hooks = cfg.get("hooks") if isinstance(cfg, dict) and isinstance(cfg.get("hooks"), dict) else {}
        label = rel if tree is repo else f"{fwd(tree.root)}/{rel}"
        out = []
        for groups in hooks.values():
            for g in groups if isinstance(groups, list) else []:
                for h in (g.get("hooks") if isinstance(g, dict) and isinstance(g.get("hooks"), list) else []):
                    m, mixed = _pecia_hook_match(h), ""
                    if not m and isinstance(h, dict) and h.get("type", "command") == "command":
                        # The line this system runs is pecia's guard though another line of the entry is the user's:
                        # the entry stays the user's for init, but launch still checks the guard line that will run,
                        # and says the entry must be fixed by hand (N-08).
                        active = _argv_run_here(h)
                        m = _pecia_argv_match(active) if "guard" in active else None
                        mixed = (" (in an entry that also runs a command of yours, which init leaves alone: fix that "
                                 "entry by hand)")
                    if not m:
                        continue
                    argv = _argv_run_here(h)
                    if not argv:
                        out.append(f"{label}: a pecia hook has no command for this system")
                        continue
                    # Judge the command this system runs. _pecia_hook_match names the first pecia command of the entry,
                    # which on Windows is the POSIX line while the PowerShell line is the one that runs (F2-02).
                    m = _pecia_argv_match(argv) or m
                    prog = argv[0]
                    if os.path.isabs(prog) or "/" in prog or "\\" in prog:
                        ok = os.path.isfile(os.path.join(str(tree.root), prog))  # relative: from the project folder
                    else:
                        # Looked up as pecia looks up its own programs, never in the current folder (G4-02, IR31 S-3).
                        ok = find_program(prog) is not None
                    if not ok:
                        out.append(f"{label}: the hooks run the interpreter {prog}, which does not exist{mixed}")
                    if m[0] != "runner":
                        continue
                    if os.path.normcase(os.path.normpath(m[1])) != runner:
                        out.append(f"{label}: the hooks run {m[1]}, not this repository's hook runner "
                                   f"{fwd(runner_script(repo))} (the folder was moved or copied after init){mixed}")
                    if m[2] and not os.path.isdir(m[2]):
                        out.append(f"{label}: the hooks name the working tree {m[2]}, which no longer exists (it "
                                   f"was moved after init){mixed}")
                    elif m[2] and not _same_repository(repo, m[2]):
                        out.append(f"{label}: the hooks name the working tree {m[2]}, which is not a working tree of "
                                   f"this repository, so they judge another repository's lease{mixed}")
        if out:
            found_all.append((tree, sorted(set(out))))
    return found_all


def _shared_objects(store: Path, limit: int = 1000) -> list:
    """Store objects that share their data with another name through a hard link (U-04)."""
    found = []
    objects = store / "objects"
    try:
        if _is_link(store) or _is_link(objects) or not objects.is_dir():
            return found
        for sub in objects.iterdir():
            if _is_link(sub) or not sub.is_dir():
                continue
            for o in sub.iterdir():
                try:
                    st = os.lstat(o)
                except OSError:
                    continue
                if stat_mod.S_ISREG(st.st_mode) and st.st_nlink > 1:
                    found.append(o)
                    if len(found) >= limit:
                        return found
    except OSError:
        pass
    return found


def _private_git_links(repo: Repo) -> list:
    """pecia's own paths in the git directory that are links, which pecia refuses to use (T-01 to T-07)."""
    found = []
    try:
        common = repo.common_dir()
        cands = [repo.git_dir() / "pecia-tmp", common / "pecia", common / "info", common / "info" / "exclude"]
        own = coordination_tree(repo).git_dir()
        cands += [c for c in (own / LEASE_NAMES[0], own.joinpath(*LEASE_NAMES)) if c not in cands]  # the lease (K-05)
        try:
            configured = _configured_store(load_policy(repo))
        except (PeciaError, AttributeError):
            configured = ""
        store = common / "pecia" / "artifacts"
        if configured:  # read the repository id without creating it: doctor writes nothing
            rid = _read_stable_id(common / "pecia-repo-id", common.parent.name)
            base = Path(os.path.expandvars(os.path.expanduser(configured)))
            store = base / rid if rid and base.is_absolute() else None
        if store is not None:
            cands += [store] + [store / n for n in ("objects", "manifests", "quarantine")]
            objects = store / "objects"
            if objects.is_dir() and not _is_link(objects) and not _is_link(store):
                for sub in sorted(objects.iterdir()):
                    cands.append(sub)
                    if not _is_link(sub) and sub.is_dir():  # single objects that are links too (U-06)
                        try:
                            cands += [o for o in sub.iterdir() if _is_link(o)]
                        except OSError:
                            pass
        for d in cands:
            if _is_link(d) and d not in found:
                found.append(d)
    except (OSError, PeciaError):
        pass
    return found


def _ensure_local_exclude(repo: Repo, lines: list[str]) -> list[str]:
    """Add lines to the repository's info/exclude. A link at info or info/exclude is refused (T-04),
    and the file is rewritten by replacing its directory entry, so nothing outside is touched."""
    path = _local_exclude_path(repo)
    # Bytes throughout: the existing rules are kept byte for byte whatever their encoding, and only
    # pecia's own lines are appended (V-06).
    raw = _read_regular(path, _TEXT_LIMIT) if os.path.lexists(path) else b""
    existing = {ln.strip() for ln in raw.splitlines()}
    added = [ln for ln in lines if ln.encode("utf-8") not in existing]
    if added:
        new = raw + (b"\n" if raw and not raw.endswith(b"\n") else b"") + "\n".join(added).encode("utf-8") + b"\n"
        _atomic_write_bytes(path, new)
    return added


# ---------------------------------------------------------------- init / doctor

_PS_TOKEN = re.compile(r"'((?:[^']|'')*)'")


def _hook_argv(entry) -> list[list[str]]:
    """The argument vectors a hook entry runs, parsed the way pecia writes them: Claude Code's
    command plus args, a POSIX command line, and a PowerShell line of single-quoted tokens after &."""
    out = []
    cmd, args, win = entry.get("command"), entry.get("args"), entry.get("commandWindows")
    if isinstance(cmd, str) and isinstance(args, list) and all(isinstance(a, str) for a in args):
        out.append([cmd, *args])
    elif isinstance(cmd, str):
        try:
            out.append(shlex.split(cmd))
        except ValueError:
            pass
    if isinstance(win, str) and win.startswith("& "):
        rest = win[2:]
        toks = _PS_TOKEN.findall(rest)
        if " ".join("'" + t + "'" for t in toks) == rest.strip():
            out.append([t.replace("''", "'") for t in toks])
    return out


def _pecia_hook_match(entry):
    """For a hook command this kit installed, (form, script, repo); otherwise None. The form is
    runner for the form this version writes, the hook runner in the git directory followed by --repo
    and the working tree, then hook guard or hook snapshot exactly as init writes them. It is
    checkout for the form 0.1.2rc3 and earlier wrote, a path ending in .pecia/bin/pecia.py followed
    by the same arguments; that form runs whatever pecia.py the checkout holds. A command that merely
    mentions those words, such as an echo, matches neither."""
    if not isinstance(entry, dict):
        return None
    if entry.get("type", "command") != "command":
        # init writes command hooks only. An entry of another type, such as a prompt hook that keeps the command
        # fields of one pecia wrote, is the user's and is never replaced or removed (N-07).
        return None
    # Every command the entry holds must be pecia's: an entry whose POSIX line is pecia's but whose Windows line
    # runs something else is the user's, and replacing it would drop that command (D-04).
    found = None
    for argv in _hook_fields(entry):
        m = _pecia_argv_match(argv)
        if m is None:
            return None
        found = found or m
    return found


def _pecia_argv_match(argv):
    """(form, script, repo) when one command line is a hook command this kit wrote (see _pecia_hook_match)."""
    tails = _known_hook_tails()
    if not argv or len(argv) < 3 or not _is_python_program(argv[0]):
        return None
    script = argv[1].replace("\\", "/")
    if (script.endswith("/pecia/runner/pecia.py") and len(argv) >= 5 and argv[2] == "--repo"
            and tuple(argv[4:]) in tails):
        return ("runner", script, argv[3].replace("\\", "/"))
    if script.endswith("/.pecia/bin/pecia.py") and tuple(argv[2:]) in tails:
        return ("checkout", script, None)
    return None


def _hook_fields(entry) -> list:
    """Each command a hook entry holds (Claude Code's command with its args, a POSIX command line, a Windows
    PowerShell line), as the argument vector pecia would have written, or None for one not in that form."""
    out = []
    cmd, args, win = entry.get("command"), entry.get("args"), entry.get("commandWindows")
    # An empty command runs nothing and is no one's; launch reports it when it is the one this system runs (R8-05).
    if isinstance(cmd, str) and not cmd.strip() and not args:
        cmd = None
    if isinstance(win, str) and not win.strip():
        win = None
    if isinstance(cmd, str) and isinstance(args, list) and all(isinstance(a, str) for a in args):
        out.append([cmd, *args])
    elif isinstance(cmd, str):
        try:
            out.append(shlex.split(cmd))
        except ValueError:
            out.append(None)
    elif cmd is not None:
        out.append(None)
    if win is not None:
        parsed = None
        if isinstance(win, str) and win.startswith("& "):
            rest = win[2:]
            toks = _PS_TOKEN.findall(rest)
            if " ".join("'" + t + "'" for t in toks) == rest.strip():
                parsed = [t.replace("''", "'") for t in toks]
        out.append(parsed)
    return out


_PYTHON_NAME = re.compile(r"(?i)(c?python|pypy|graalpy)w?[0-9.]*[a-z]?"
                          r"(?:[-_](?:d|dbg|debug|intel64|arm64|universal2|x86_64|x86|amd64))*w?(\.exe)?")


def _is_python_program(prog: str) -> bool:
    """init writes the interpreter that ran it. An entry whose program is anything else, such as an
    echo given pecia's arguments, is not pecia's and is never replaced or removed (T-06)."""
    name = prog.replace("\\", "/").rsplit("/", 1)[-1]
    if _PYTHON_NAME.fullmatch(name):
        return True
    try:
        return bool(sys.executable) and os.path.normcase(os.path.abspath(prog)) == os.path.normcase(
            os.path.abspath(sys.executable))
    except (TypeError, ValueError):
        return False


def _is_pecia_hook(entry) -> bool:
    return _pecia_hook_match(entry) is not None


_HOOK_TAILS: set = set()
# The Codex guard lines 0.1.2rc10 and earlier wrote, without --event: still pecia's, so --update-hooks replaces them.
_LEGACY_HOOK_TAILS = {("hook", "guard", "--agent", "codex", "--format", "codex")}


def _known_hook_tails() -> set:
    """The exact argument lists, after the program, the script, and --repo with its value, of every
    hook init writes. An entry with anything more, such as && another-command or a second --repo,
    is not pecia's."""
    if not _HOOK_TAILS:
        for spec in _hook_tables("python", "/stub/pecia/runner/pecia.py", "/stub"):
            for groups in spec["hooks"].values():
                for g in groups:
                    for h in g["hooks"]:
                        for argv in _hook_argv(h):
                            _HOOK_TAILS.add(tuple(argv[4:]))
        _HOOK_TAILS.update(_LEGACY_HOOK_TAILS)
    return _HOOK_TAILS


def _pecia_hook_matches(cfg) -> list:
    hooks = cfg.get("hooks") if isinstance(cfg, dict) and isinstance(cfg.get("hooks"), dict) else {}
    found = []
    for groups in hooks.values():
        for g in groups if isinstance(groups, list) else []:
            for h in (g.get("hooks") if isinstance(g, dict) and isinstance(g.get("hooks"), list) else []):
                m = _pecia_hook_match(h)
                if m:
                    found.append(m)
    return found


def _all_hook_matches(repo: Repo) -> list:
    out = []
    for rel in HOOK_FILES.values():
        p = repo.path(rel)
        if p.is_file():
            try:
                out += _pecia_hook_matches(json.loads(read_text(p)))
            except (ValueError, RecursionError, OSError):
                pass
    return out


def _worktree_roots(repo: Repo) -> list[Path]:
    """Every working tree of this repository that still exists on disk, the main one first. A bare
    repository entry has no working tree and is left out."""
    p = run_git(repo.root, ["worktree", "list", "--porcelain", "-z"], check=False)
    sep, end = b"\0", b""
    if p.returncode != 0:  # -z needs git 2.36
        p, sep = run_git(repo.root, ["worktree", "list", "--porcelain"], check=False), b"\n"
        if p.returncode != 0:
            return []
    roots, path, bare = [], None, False
    for field in p.stdout.split(sep) + [end]:
        field = field.rstrip(b"\r")
        if field == end:
            if path is not None and not bare and path.is_dir():
                roots.append(path.resolve())
            path, bare = None, False
        elif field.startswith(b"worktree "):
            path = Path(field[9:].decode("utf-8", "surrogateescape"))
        elif field == b"bare":
            bare = True
    return roots


def _containing_tree(repo: Repo, roots: list) -> Repo:
    """A working tree nested inside another working tree of the same repository is judged as the
    outermost tree that contains it. Claude Code's EnterWorktree puts worktrees under .claude/worktrees/
    inside the project, and pecia's inspection worktrees live under .pecia/runtime/recover/. Judging
    them on their own let a session blocked by the main tree's lease move into one and write freely
    (R5-01), and blocked the lease holder in pecia's own inspection folder (R5-02)."""
    best = None
    for w in roots:
        if (w == repo.root or w in repo.root.parents) and (best is None or len(w.parts) < len(best.parts)):
            best = w
    return Repo(best) if best is not None and best != repo.root else repo


def coordination_tree(repo: Repo) -> Repo:
    """The working tree whose lease governs repo: repo itself, or the outermost tree of this repository that
    contains it (_containing_tree). The guard judges a nested tree by that tree, so claim, launch, release, status,
    the heartbeat and the hooks-seen records all use it too. A lease taken in a nested tree's own folder was never
    checked, and excluded nobody (K-02)."""
    tree = getattr(repo, "_coord", None)
    if tree is None:
        try:
            tree = _containing_tree(repo, _worktree_roots(repo))
        except (PeciaError, OSError):
            tree = repo
        tree._coord = tree
        repo._coord = tree
    return tree


def _tree_holding(repo: Repo, folder: Path) -> Repo | None:
    """The working tree of repo's repository whose folder holds folder, or None. A folder in a repository nested
    inside one of those trees, made with git init, as a submodule or as a cloned copy, is still in that tree."""
    try:
        where = folder.resolve()
        roots = _worktree_roots(repo)
    except (OSError, PeciaError):
        return None
    held = [w for w in roots if w == where or w in where.parents]
    return Repo(max(held, key=lambda w: len(w.parts))) if held else None


def _has_legacy_guard_lines(cfg) -> bool:
    """True when a hooks file holds pecia guard lines in the form 0.1.2rc10 and earlier wrote, without --event."""
    hooks = cfg.get("hooks") if isinstance(cfg, dict) and isinstance(cfg.get("hooks"), dict) else {}
    for groups in hooks.values():
        for g in groups if isinstance(groups, list) else []:
            for h in (g.get("hooks") if isinstance(g, dict) and isinstance(g.get("hooks"), list) else []):
                if _pecia_hook_match(h) and any(argv and tuple(argv[-6:]) in _LEGACY_HOOK_TAILS
                                                 for argv in _hook_fields(h)):
                    return True
    return False


def _checkout_form_hook_files(repo: Repo) -> list[str]:
    """Hook files whose pecia entries still run the pecia.py inside the working tree."""
    out = []
    for rel in HOOK_FILES.values():
        p = repo.path(rel)
        if p.is_file():
            try:
                cfg = json.loads(read_text(p))
            except (ValueError, RecursionError, OSError):
                continue
            if any(m[0] == "checkout" for m in _pecia_hook_matches(cfg)):
                out.append(rel)
    return out


def _file_version(path: Path) -> str:
    try:
        m = re.search(rb'(?m)^VERSION = "([^"\r\n]{1,40})"', _read_regular(path)[:8192])
    except OSError:
        return "unknown"
    return m.group(1).decode("ascii", "replace") if m else "unknown"


RUNNER_SHA = "pecia.py.sha256"


def _version_key(v: str):
    """An ordering key for pecia's versions: X.Y.Z, X.Y.ZrcN and X.Y.Z.devN, where a development build
    comes before the release candidates and the release of the same version, as in PEP 440."""
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:rc(\d+)|\.dev(\d+))?", v or "")
    if not m:
        return None
    a, b, c, rc, dev = m.groups()
    phase, n = (0, dev) if dev is not None else (1, rc) if rc is not None else (2, 0)
    return (int(a), int(b), int(c), phase, int(n))


_RUNNER_MARKS = (b"def do_guard(", b"def do_hook(", b"def hook_specs(")


def _recorded_runner_sha(script: Path):
    try:
        return _read_regular(script.parent / RUNNER_SHA).decode("ascii").strip()
    except (OSError, ValueError):
        return None


def _runner_looks_sound(script: Path) -> bool:
    """A cheap check for messages: a regular file, not reached through a link, that holds pecia's hook
    entry points and matches its recorded SHA-256."""
    try:
        if any(_is_link(x) for x in (script.parent.parent, script.parent, script)) or not script.is_file():
            return False
        data = _read_regular(script)
    except OSError:
        return False
    rec = _recorded_runner_sha(script)
    return all(m in data for m in _RUNNER_MARKS) and (not rec or hashlib.sha256(data).hexdigest() == rec)


def runner_health(repo: Repo) -> tuple[str, str]:
    """(ok | missing | unreadable | damaged, detail). Damaged covers a runner reached through a link,
    one that no longer matches the SHA-256 recorded when it was installed, one whose recorded SHA-256
    cannot be read, one without pecia's hook entry points, and one that does not compile, such as a
    truncated copy: a hook that cannot start exits 1, which neither agent treats as a block (R4-05).
    This detects damage, not tampering by someone who can write the git directory."""
    script = runner_script(repo)
    if any(_is_link(x) for x in (script.parent.parent, script.parent)):
        return "damaged", f"{fwd(script.parent)} is reached through a symlink or junction"
    if not os.path.lexists(script):
        return "missing", fwd(script)
    if _is_link(script) or not script.is_file():
        return "damaged", f"{fwd(script)} is not a regular file"
    try:
        data = _read_regular(script)
    except OSError as e:
        return "unreadable", f"{fwd(script)}: {e.strerror or e}"
    rec = _recorded_runner_sha(script)
    if rec is None and os.path.lexists(script.parent / RUNNER_SHA):
        return "damaged", f"its recorded SHA-256, {fwd(script.parent / RUNNER_SHA)}, cannot be read"
    if rec and hashlib.sha256(data).hexdigest() != rec:
        return "damaged", f"{fwd(script)} no longer matches the SHA-256 recorded when it was installed"
    if not all(m in data for m in _RUNNER_MARKS):
        return "damaged", f"{fwd(script)} lacks pecia's hook entry points"
    try:
        compile(data, str(script), "exec")
    except (SyntaxError, ValueError) as e:
        return "damaged", f"{fwd(script)} does not compile ({type(e).__name__}: {e})"
    return "ok", f"{fwd(script)} (v{_file_version(script)})"


def install_runner(repo: Repo, apply: bool, note, verb: str = "", upgrade_only: bool = False,
                   record_policy: str = "replace") -> bool:
    """Keep the copy of pecia.py that the agent hooks run in <git-common-dir>/pecia/runner, with its
    SHA-256, and record this working tree's policy beside it. Checking out another branch or an older
    commit never changes that folder. A missing, unreadable, or damaged runner is always replaced.
    init (upgrade_only False) replaces a healthy runner whenever its bytes differ from this copy, and
    says so when that installs an older version: init is an explicit request, and refusing it let a
    runner that only claimed a high version stay in place (R5-03). launch and worktree creation
    (upgrade_only True) replace a healthy runner only with a version they can compare and know to be
    newer, so they never swap it silently (R4-03). record_policy is replace (init), if_missing (worktree
    creation) or never (launch, T-08). A dry run writes nothing, not even this tree's id (T-03).
    Returns False when the folder is refused or cannot be written."""
    try:
        d = runner_dir(repo)
        recorded = recorded_policy_path(repo, create=apply and record_policy != "never")
        script, digest = d / "pecia.py", d / RUNNER_SHA
        for p in (d.parent, d, script, digest) + ((recorded,) if recorded is not None else ()):
            folder = p in (d.parent, d)
            if _is_link(p) or (os.path.lexists(p) and (not p.is_dir() if folder else not os.path.isfile(p))):
                note(f"REFUSED {fwd(p)}: it is a symlink, a junction, or not a {'folder' if folder else 'file'}, so the "
                     "hook runner was not installed. Replace it with a regular one and rerun init.")
                return False
        src = Path(__file__).resolve().read_bytes()
        state, detail = runner_health(repo)
        have_v = _file_version(script) if state == "ok" else ""
        if state != "ok":
            install = True
            why = "" if state == "missing" else f" (replacing a {state} copy: {detail})"
        elif _read_regular(script) == src:
            install, why = False, ""
        else:
            have, mine = _version_key(have_v), _version_key(VERSION)
            newer = bool(have and mine and mine > have)
            if upgrade_only and not newer:
                install = False
                if not (have and mine and mine == have):
                    note(f"kept the hook runner v{have_v}; this copy of pecia (v{VERSION}) replaces it only with a "
                         f"version it knows to be newer. Run init --apply to install this copy instead.")
            else:
                install = True
                older = bool(have and mine and mine < have) or not (have and mine)
                why = (f" (replacing v{have_v}, which may be newer)" if older and have_v != VERSION
                       else f" (replacing v{have_v})")
        if install:
            note(f"{verb}install the hook runner {fwd(script)} (v{VERSION}){why}; the agent hooks run this copy, "
                 "so checking out a branch or commit without .pecia/ cannot break them")
            if apply:
                _atomic_write_bytes(script, src)
                _atomic_write_bytes(digest, (hashlib.sha256(src).hexdigest() + "\n").encode("ascii"))
        pol = repo.path(POLICY_REL)
        if record_policy == "never":
            return True
        if pol.is_file() and not _is_link(pol) and (record_policy == "replace" or recorded is None
                                                     or not recorded.exists()):
            data = _read_regular(pol, _TEXT_LIMIT)
            try:
                valid = isinstance(json.loads(data.decode("utf-8")), dict)
            except (ValueError, UnicodeDecodeError, RecursionError):
                valid = False
            if not valid:
                note(f"{POLICY_REL} is not a valid JSON object; the copy recorded for checkouts without it is unchanged")
            elif recorded is None or not recorded.exists() or _read_regular(recorded, _TEXT_LIMIT) != data:
                note(f"{verb}record {POLICY_REL} for this working tree beside the hook runner, for checkouts that "
                     f"have no {POLICY_REL}")
                if apply and recorded is not None:
                    _atomic_write_bytes(recorded, data)
        return True
    except OSError as e:
        note(f"REFUSED hook runner: {e}. The hook runner was not installed or updated.")
        return False


def _unrecognized_pecia_mentions(cfg: dict) -> int:
    """Hook entries that mention pecia.py without being in the form pecia installs. They are kept
    as they are and reported, never removed."""
    hooks = cfg.get("hooks") if isinstance(cfg, dict) and isinstance(cfg.get("hooks"), dict) else {}
    n = 0
    for groups in hooks.values():
        for g in groups if isinstance(groups, list) else []:
            for h in (g.get("hooks") if isinstance(g, dict) and isinstance(g.get("hooks"), list) else []):
                if not _is_pecia_hook(h) and "pecia.py" in json.dumps(h):
                    n += 1
    return n


def _pecia_entries(cfg: dict) -> list:
    hooks = cfg.get("hooks") if isinstance(cfg, dict) and isinstance(cfg.get("hooks"), dict) else {}
    found = []
    for event, groups in hooks.items():
        for g in groups if isinstance(groups, list) else []:
            if isinstance(g, dict) and isinstance(g.get("hooks"), list):
                found += [(event, str(g.get("matcher")), json.dumps(h, sort_keys=True))
                          for h in g["hooks"] if _is_pecia_hook(h)]
    return sorted(found)


def merge_pecia_hooks(existing: dict, spec: dict) -> dict:
    """Return existing with every pecia hook command removed and the current pecia hooks added.
    Other keys, other events and other hook commands are kept as they are."""
    out = json.loads(json.dumps(existing))
    if "hooks" in out and not isinstance(out["hooks"], dict):
        raise ValueError("its hooks value is not a JSON object")
    hooks = out.get("hooks") or {}
    for event in spec["hooks"]:
        if event in hooks and not isinstance(hooks[event], list):
            raise ValueError(f"its hooks.{event} value is not a list")
    for event in list(hooks):
        if not isinstance(hooks[event], list):
            continue  # not a shape pecia writes; left exactly as it is
        groups = hooks[event]
        kept = []
        for g in groups:
            if isinstance(g, dict) and isinstance(g.get("hooks"), list):
                inner = [h for h in g["hooks"] if not _is_pecia_hook(h)]
                if inner:
                    kept.append(dict(g, hooks=inner))
                elif not g["hooks"]:
                    kept.append(g)
            else:
                kept.append(g)
        if kept:
            hooks[event] = kept
        else:
            del hooks[event]
    for event, groups in spec["hooks"].items():
        hooks.setdefault(event, []).extend(json.loads(json.dumps(groups)))
    out["hooks"] = hooks
    return out


def do_init(repo: Repo, apply: bool, append_agents_block: bool, install_hooks: bool,
            update_hooks: bool = False) -> list[str]:
    actions: list[str] = []
    verb = "" if apply else "would "

    def note(msg):
        actions.append(msg)

    repo.runtime  # refuses a linked or tracked state folder before anything is written
    try:
        _local_exclude_path(repo)
        exclude_ok = True
    except UnsafePath as e:
        exclude_ok = False
        note(f"REFUSED the local git exclude file: {e} No exclude entries were added, so pecia's state folder "
             "and hook files may show as untracked.")

    def safe(rel):
        """Every path init writes must be a regular file inside the repository, reached without a
        symlink or junction; otherwise writing to it could change a file somewhere else."""
        try:
            target = _safe_target(repo, rel)
            try:
                mode = os.lstat(target).st_mode
            except FileNotFoundError:
                return target
            if not stat_mod.S_ISREG(mode):
                # A pipe, socket, device or folder: never opened, so init cannot hang on it (R10-13).
                raise UnsafePath(f"{rel}: it is not a regular file")
            return target
        except UnsafePath as e:
            note(f"REFUSED {rel}: {e}. Nothing was written there. Replace it with a regular file or folder "
                 "and rerun init.")
            return None

    src = Path(__file__).resolve()
    dest = safe(BIN_REL + "/pecia.py")
    if dest is not None and (not dest.exists() or (dest.resolve() != src and _readable_differs(dest, src))):
        note(f"{verb}install {BIN_REL}/pecia.py (v{VERSION})")
        if apply:
            _atomic_write_bytes(dest, src.read_bytes())
    shim = safe(BIN_REL + "/pecia.cmd")
    if shim is not None and not shim.exists():
        note(f"{verb}create {BIN_REL}/pecia.cmd (Windows shim)")
        if apply:
            _atomic_write_bytes(shim, SHIM_CMD.encode())
    elif shim is not None and _old_shim(shim):
        # Only the exact bytes an earlier version wrote are replaced; a shim the user changed is kept.
        note(f"{verb}update {BIN_REL}/pecia.cmd (the Windows shim no longer runs a python from the current folder)")
        if apply:
            _atomic_write_bytes(shim, SHIM_CMD.encode())
    for rel, content in ((STATE_REL, STATE_TEMPLATE), (REVIEW_REL, REVIEW_TEMPLATE),
                         (POLICY_REL, json.dumps(DEFAULT_POLICY, indent=2) + "\n")):
        path = safe(rel)
        if path is None:
            continue
        if path.exists():
            note(f"keep existing {rel}")
        else:
            note(f"{verb}create {rel}")
            if apply:
                _atomic_write_bytes(path, content.encode("utf-8"))
    excl = [".pecia/runtime/", ".pecia-restore-*"]
    if exclude_ok:
        note(f"{verb}add {', '.join(excl)} to the local git exclude file (no tracked file is modified)")
    if apply and exclude_ok:
        _ensure_local_exclude(repo, excl)
    seed = _head_log_to_seed(repo)
    if seed:
        # Where git keeps no reflog for HEAD, as with core.logAllRefUpdates false, recovery cannot tell a version a
        # history move discarded from the newest one; HEAD's log is started, the setting left as it is (RP-13).
        if not apply:
            note("would start HEAD's reflog in the git directory with one entry that moves nothing, so recovery can see "
                 "history moves (core.logAllRefUpdates is left as it is)")
        elif _seed_head_log(repo, seed):
            note("start HEAD's reflog in the git directory with one entry that moves nothing, so recovery can see "
                 "history moves (core.logAllRefUpdates is left as it is)")
        else:
            note("WARNING HEAD's reflog could not be started in the git directory (the error is in pecia's event log); "
                 "with reflogs off, recovery cannot tell a version a history move discarded from the newest one")
    runner_ok = install_runner(repo, apply, note, verb)
    agents, claude_md = safe("AGENTS.md"), safe("CLAUDE.md")
    if agents is None:
        pass
    elif not agents.exists():
        note(f"{verb}create AGENTS.md containing the pecia protocol block")
        if apply:
            _atomic_write_bytes(agents, ("# Agent instructions\n\n" + AGENTS_BLOCK).encode("utf-8"))
    else:
        text = read_text(agents)
        if "<!-- pecia:begin" in text:
            note("AGENTS.md already contains the pecia protocol block")
        elif append_agents_block:
            note(f"{verb}append the pecia protocol block to existing AGENTS.md")
            if apply:
                # Replacing the directory entry, never appending in place: a hard-linked AGENTS.md would
                # otherwise change a file outside the repository.
                raw = _read_regular(agents, _TEXT_LIMIT)  # the file's own bytes, whatever its encoding (R10-08)
                _atomic_write_bytes(agents, raw + (b"\n" if raw.endswith(b"\n") else b"\n\n") + AGENTS_BLOCK.encode("utf-8"))
        else:
            note("AGENTS.md exists and lacks the pecia block; left untouched. Rerun with --append-agents-block to add it.")
    if claude_md is None:
        pass
    elif not claude_md.exists():
        note(f"{verb}create CLAUDE.md that imports AGENTS.md")
        if apply:
            _atomic_write_bytes(claude_md, CLAUDE_MD_TEMPLATE.encode("utf-8"))
    else:
        if re.search(r"(?m)^\s*@AGENTS\.md\s*$", read_text(claude_md)):
            note("CLAUDE.md already imports AGENTS.md")
        else:
            note("CLAUDE.md exists without an @AGENTS.md line; left untouched. Add the line @AGENTS.md at its top by hand.")
    claude_hooks, codex_hooks = hook_specs(repo, sys.executable)
    gen_claude = safe(RUNTIME_REL + "/generated/claude-settings.local.json")
    gen_codex = safe(RUNTIME_REL + "/generated/codex-hooks.json")
    if gen_claude is not None and gen_codex is not None:
        note(f"{verb}write hook configurations for review under {RUNTIME_REL}/generated/")
        if apply:
            atomic_write_json(gen_claude, claude_hooks)
            atomic_write_json(gen_codex, codex_hooks)
    if install_hooks and not runner_ok:
        note("hook files left untouched, because hooks without their runner would fail")
    elif install_hooks:
        for rel, spec in ((".claude/settings.local.json", claude_hooks), (".codex/hooks.json", codex_hooks)):
            path = safe(rel)
            if path is None:
                continue
            if path.exists():
                try:
                    # Strict UTF-8: a file pecia could not decode exactly is left alone, never rewritten
                    # with replacement characters (V-06).
                    existing = json.loads(_read_regular(path, _TEXT_LIMIT).decode("utf-8"))
                    if not isinstance(existing, dict):
                        raise ValueError("not a JSON object")
                except (ValueError, RecursionError) as e:
                    note(f"{rel} exists but is not valid JSON ({e}); left untouched. "
                         f"Merge {RUNTIME_REL}/generated/ by hand.")
                    continue
                try:
                    merged = merge_pecia_hooks(existing, spec)
                    json.dumps(merged, allow_nan=False)  # a number beyond JSON's range would come back as Infinity (G2-08)
                except ValueError as e:
                    note(f"{rel} exists but {e}; left untouched. Merge {RUNTIME_REL}/generated/ by hand.")
                    continue
                odd = _unrecognized_pecia_mentions(existing)
                if odd:
                    note(f"{rel}: kept {odd} hook entr{'y' if odd == 1 else 'ies'} that mention pecia.py but are not "
                         "in the form pecia installs; review them by hand")
                if _pecia_entries(existing) == _pecia_entries(spec):
                    note(f"{rel} already has the current pecia hooks")
                elif not update_hooks:
                    note(f"{rel} exists and its pecia hooks are missing or out of date; left untouched. "
                         "Rerun with --update-hooks to rewrite only the pecia entries (a backup is kept), "
                         f"or merge {RUNTIME_REL}/generated/ by hand.")
                else:
                    note(f"{verb}update the pecia entries in {rel}, keeping every other setting and hook"
                         + (" (Codex asks to approve changed hooks again in /hooks)" if rel.startswith(".codex") else ""))
                    backup_rel = f"{RUNTIME_REL}/backup/{Path(rel).name}.{utcnow().strftime('%Y%m%dT%H%M%S%fZ')}"
                    backup = safe(backup_rel)
                    if backup is None:
                        continue
                    if apply:
                        # The copy is no more readable than the file it keeps: a 0600 settings file may hold tokens,
                        # and a new file was 0644 (G2-05).
                        try:
                            src_mode = os.lstat(path).st_mode & 0o777
                        except OSError:
                            src_mode = 0o600
                        _write_replacing(Path(backup), _read_regular(path, _TEXT_LIMIT), keep_mode=False, mode=src_mode)
                        atomic_write_json(path, merged)
                        if exclude_ok:
                            _ensure_local_exclude(repo, [rel])
                        note(f"previous {rel} saved as {RUNTIME_REL}/backup/{backup.name}")
            else:
                note(f"{verb}create {rel} with pecia hooks and exclude it locally (it holds machine paths)")
                if apply:
                    atomic_write_json(path, spec)
                    if exclude_ok:
                        _ensure_local_exclude(repo, [rel])
    if install_hooks:
        roots = _worktree_roots(repo)
        if roots and roots[0] != repo.root:
            note(f"this is a linked worktree: Codex runs the main working tree's {HOOK_FILES['codex']} here, so install "
                 f"the hooks there too: {pecia_cmd(repo)} --repo {fwd(roots[0])} init --apply --install-hooks")
    if install_hooks and apply:
        # Recorded in the git directory, so doctor, status and launch notice when git clean -fdx or git stash --all
        # removes these ignored files, and launch writes them again (RP-09).
        try:
            if record_installed_hooks(repo, _held_hook_files(repo), "init", replace=True):
                note(f"record the hook files that hold pecia hooks in {fwd(_hooks_record_path(repo))}, so doctor, "
                     "status and launch notice when git clean -fdx or git stash --all removes them")
        except (OSError, PeciaError) as e:
            note(f"WARNING the hook files could not be recorded ({e}); doctor, status and launch will not notice when "
                 "they are removed")
    if update_hooks and not install_hooks:
        # It rewrites the pecia entries of the hook files only with --install-hooks; alone it did nothing, silently (G2-06).
        note(f"--update-hooks changes nothing without --install-hooks; the hook files were not touched. Run "
             f"{pecia_cmd(repo)} init --apply --install-hooks --update-hooks")
    if not apply:
        note("dry run only; rerun with --apply to make these changes")
    else:
        repo.log_event("init", version=VERSION, actions=actions)
    return actions


MIN_GIT = (2, 27)


def git_version_tuple(text: str) -> tuple:
    m = re.search(r"(\d+)\.(\d+)", text)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def codex_project_trust(repo: Repo) -> tuple[str, str]:
    """Read-only look at the Codex user config: is this working tree, or a folder above it,
    marked trusted? Codex loads project hooks only for a trusted project. Returns
    (trusted|untrusted|unknown, detail)."""
    home = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex")
    cfg = home / "config.toml"
    if not cfg.exists():
        return "unknown", f"no Codex config at {fwd(cfg)}"
    try:
        import tomllib  # Python 3.11+
        data = tomllib.loads(read_text(cfg))
        projects = data.get("projects") or {}
        table = {k: (v or {}).get("trust_level") for k, v in projects.items() if isinstance(v, dict)}
    except ImportError:
        table = {}
        for m in re.finditer(r"""(?m)^\[projects\.(?:'([^']*)'|"((?:[^"\\]|\\.)*)")\]\s*$((?:\n(?!\[).*)*)""",
                             read_text(cfg)):
            key = m.group(1) if m.group(1) is not None else m.group(2).encode().decode("unicode_escape")
            tl = re.search(r'(?m)^\s*trust_level\s*=\s*"([^"]*)"', m.group(3))
            table[key] = tl.group(1) if tl else None
    except Exception as e:
        return "unknown", f"could not read {fwd(cfg)}: {type(e).__name__}"

    def norm(x: str) -> str:
        x = str(x).replace("\\", "/").rstrip("/")
        if x.startswith("//?/"):
            x = x[4:]
        return x.lower() if IS_WINDOWS or re.match(r"^[A-Za-z]:", x) else x
    # Codex 0.160 applies a parent folder's entry to the projects below it (observed in the
    # zero-usage end-to-end run, scenario E5), so the nearest entry at or above the tree decides.
    here = norm(str(repo.root))
    best = None
    for key, level in table.items():
        k = norm(key)
        if (here == k or here.startswith(k + "/")) and (best is None or len(k) > len(norm(best[0]))):
            best = (key, level)
    if best is None:
        return "untrusted", "no projects entry for this working tree or a folder above it"
    via = "" if norm(best[0]) == here else ", inherited from a parent folder"
    return ("trusted" if best[1] == "trusted" else "untrusted"), f"{best[0]} = {best[1]}{via}"


def do_doctor(repo: Repo) -> list[str]:
    gv = git_text(repo.root, "version")
    out = [f"pecia {VERSION}", f"repo: {fwd(repo.root)}", f"python: {sys.version.split()[0]} at {fwd(sys.executable)}",
           f"git: {gv}", f"object format: {repo.object_format()}"]
    if git_version_tuple(gv) < MIN_GIT:
        out.append(f"WARNING git {'.'.join(map(str, MIN_GIT))} or later is required; snapshots may fail")
    for tool in ("codex", "claude"):
        exe = find_program(tool)
        if not exe:
            out.append(f"{tool}: not found on PATH")
            continue
        try:
            v = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=30).stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            v = "(version check failed)"
        out.append(f"{tool}: {v}")
    for rel in (STATE_REL, REVIEW_REL, POLICY_REL, BIN_REL + "/pecia.py", "AGENTS.md", "CLAUDE.md"):
        problem = _policy_problem(repo) if rel == POLICY_REL and repo.path(rel).exists() else None
        out.append(f"WARNING {rel}: {problem}" if problem else f"{'ok ' if repo.path(rel).exists() else 'MISSING '}{rel}")
    for rec in capture_failures(repo):  # listed until recover ack (RP-01, C17 requirement 8)
        out.append(_gap_line(rec))
    if repo.path("CLAUDE.md").exists():
        try:
            ok = re.search(r"(?m)^\s*@AGENTS\.md\s*$", read_text(repo.path("CLAUDE.md")))
            out.append("CLAUDE.md imports AGENTS.md" if ok else "WARNING CLAUDE.md does not import AGENTS.md")
        except OSError as e:  # doctor reports what it cannot read instead of failing (R10-13)
            out.append(f"WARNING CLAUDE.md cannot be read as a regular file: {e.strerror or e}")
    tracked_rt = run_git(repo.root, ["ls-files", "-z", "--", RUNTIME_REL], check=False).stdout.strip(b"\0")
    if tracked_rt:
        out.append(f"WARNING files under {RUNTIME_REL} are tracked by git; untrack them with "
                   f"git rm -r --cached {RUNTIME_REL} and commit")
    probe = run_git(repo.root, ["check-ignore", "-q", RUNTIME_REL + "/probe"], check=False)
    out.append("runtime directory is ignored" if probe.returncode == 0 else "WARNING runtime directory is not ignored")
    try:
        pol = load_policy(repo)
        configured = _configured_store(pol)
        try:
            store = store_root(repo, pol, write=False)
        except UnsafePath as e:
            out.append(f"WARNING {e} Until then, snapshots report every designated file as not covered.")
            raise PeciaError("reported") from None
        if store.name == "pecia-no-repository-id-yet":
            out.append(f"artifact store: a folder inside {fwd(store.parent)}, named when the first snapshot stores "
                       "an artifact")
        else:
            out.append(f"artifact store: {fwd(store)}" + ("" if store.is_dir() else " (created at the first snapshot "
                                                                                     "that stores an artifact)"))
        if configured:
            base = store.parent
            inside = _store_in_worktree(repo, base)
            if inside is not None:
                out.append(f"WARNING artifacts.store ({fwd(base)}) is inside the working tree {fwd(inside)}. pecia "
                           "refuses to store artifacts there, because snapshots would commit them into git, so "
                           "snapshots report every designated file as not covered. Set a folder outside every "
                           "working tree; move any objects already there with it.")
            if not base.is_dir():
                out.append(f"WARNING the artifacts.store location {fwd(base)} cannot be reached (a drive that is not "
                           "mounted, or a link to a missing folder). Snapshots still record the working tree, but "
                           "report every designated file as not covered until it is back.")
            old = repo.common_dir() / "pecia" / "artifacts" / "objects"
            if old.is_dir() and not _is_link(old) and any(True for _ in old.glob("*/*")):
                out.append(f"WARNING {fwd(old)} still holds objects from before artifacts.store was set. pecia now "
                           f"reads and writes only {fwd(store)}, so recovery cannot use those objects until you "
                           "move the old store's contents there.")
    except (PeciaError, OSError):
        pass
    try:
        shared = _shared_objects(store_root(repo, load_policy(repo), write=False))
    except (PeciaError, OSError):
        shared = []
    if shared:
        out.append(f"WARNING {len(shared)} artifact store object(s) share their data with another file through a hard "
                   f"link, for example {fwd(shared[0])}. pecia never touches them; the next snapshot that needs one "
                   "stores a fresh copy in its place.")
    ev = repo.path(RUNTIME_REL) / "events.jsonl"
    try:
        est = os.lstat(ev)
        if not stat_mod.S_ISREG(est.st_mode) or est.st_nlink > 1:
            out.append(f"WARNING {RUNTIME_REL}/events.jsonl is not a regular file with a single name (a link, a hard "
                       "link or a pipe), so pecia does not write its event log. Delete it; pecia creates a new one.")
    except OSError:
        pass
    try:  # pattern lists given in a form pecia reads differently than written
        psrc = policy_source(repo)
        if psrc is not None:
            raw = json.loads(_read_regular(psrc, _TEXT_LIMIT).decode("utf-8"))
            merged = json.loads(json.dumps(DEFAULT_POLICY))
            if isinstance(raw, dict):
                warned, refused = _mistyped_sections(raw)
                for msg in refused + warned:
                    out.append(f"WARNING {msg}")
                deep_merge(merged, raw)
                for msg in _normalize_pattern_lists(merged):
                    out.append(f"WARNING {msg}")
                globs_ = merged["artifacts"].get("include_globs")
                if globs_ and not isinstance(globs_, _UnreadableDesignation) and not refused:
                    pats_ = [g for g in globs_ if isinstance(g, str)]
                    prune_ = [g for g in (merged["artifacts"].get("prune_dirs") or []) if isinstance(g, str)]
                    walked_ = list(walk_artifact_candidates(repo, pats_, prune_))
                    for pat in _unmatched_patterns(pats_, walked_):
                        out.append(_unmatched_line(pat))
                gp = merged.get("guard") if isinstance(merged.get("guard"), dict) else {}
                for name, default in DEFAULT_POLICY["guard"].items():
                    if name in gp and not isinstance(gp[name], bool):
                        # A value that is not JSON true or false: allow_foreign_host_lease then stays off, and the
                        # others act on the value's truth, so "false" acts as true (G2-04).
                        treated = False if name == "allow_foreign_host_lease" else bool(gp[name])
                        out.append(f"WARNING guard.{name} is {json.dumps(gp[name])[:40]}, not true or false; it is "
                                   f"treated as {str(treated).lower()}; write true or false")
    except (OSError, ValueError, RecursionError, TypeError, AttributeError, PeciaError):
        pass
    try:
        locks = [(repo.git_dir() / LEASE_NAMES[0] / "snapshot.lock", fwd(repo.git_dir() / LEASE_NAMES[0]) + "/snapshot.lock")]
    except (OSError, PeciaError):
        locks = []
    for lockp, shown in locks + [(repo.path(RUNTIME_REL) / "snapshot.lock", f"{RUNTIME_REL}/snapshot.lock")]:
        try:
            lst = os.lstat(lockp)
            if not stat_mod.S_ISREG(lst.st_mode) or lst.st_nlink > 1:
                out.append(f"WARNING {shown} is not a regular file with a single name. pecia leaves it alone and locks "
                           "snapshots on another name in that folder; delete it when no snapshot is running.")
        except OSError:
            pass
    for d in _private_git_links(repo):
        out.append(f"WARNING {fwd(d)} is a symlink or junction. pecia refuses to write or delete through it, so "
                   "the commands that would (snapshots with artifacts, verify, init) stop until it is replaced by a "
                   f"regular folder or file. To keep the artifact store elsewhere, set artifacts.store in {POLICY_REL}.")
    cmd = pecia_cmd(repo)
    src = policy_source(repo)
    out.append("policy: " + ("built-in defaults" if src is None else POLICY_REL if src == repo.path(POLICY_REL) else
                             f"the copy recorded beside the hook runner, {fwd(src)}, because this checkout has no "
                             f"{POLICY_REL}"))
    runner = runner_script(repo)
    fix_hooks = (f"Run {cmd} init --apply --install-hooks --update-hooks to rewrite only the pecia entries "
                 "(a backup is kept).")
    state, detail = runner_health(repo)
    if state == "ok":
        rv = _file_version(runner)
        out.append(f"hook runner: {detail}")
        tracked = repo.path(BIN_REL + "/pecia.py")
        try:
            differs = tracked.is_file() and _read_regular(tracked) != _read_regular(runner)
        except OSError:
            differs = False
        if differs:
            tv = _file_version(tracked)
            rk, tk = _version_key(rv), _version_key(tv)
            if rk and tk and tk > rk:
                out.append(f"WARNING the hooks run pecia {rv}, older than {tv} in this checkout's {BIN_REL}/pecia.py. "
                           f"Run {cmd} init --apply, or start a session with {cmd} launch, to update the runner.")
            elif rk and tk and tk < rk:
                out.append(f"note: the hooks run pecia {rv}, newer than {tv} in this checkout's {BIN_REL}/pecia.py, "
                           "and launch keeps the newer runner. If you did not install that version, run "
                           f"{cmd} init --apply to replace it with this checkout's copy.")
            else:
                out.append(f"WARNING the hooks run a pecia.py (v{rv}) that differs from this checkout's {BIN_REL}/pecia.py "
                           f"(v{tv}). Run {cmd} init --apply to replace the runner with this checkout's copy.")
    elif state != "missing" or any(repo.path(r).exists() for r in HOOK_FILES.values()):
        out.append(f"WARNING hook runner {state}: {detail}. Hooks that run it fail; Codex on Windows treats that as "
                   f"non-blocking and runs unguarded. Run {cmd} init --apply, or start a session with {cmd} launch, "
                   "to reinstall it.")
    if runner_dir(repo).is_dir() and repo.path(POLICY_REL).is_file():
        try:
            rec = recorded_policy_path(repo, create=False)
            if rec is None or not rec.is_file() or _read_regular(rec, _TEXT_LIMIT) != _read_regular(
                    repo.path(POLICY_REL), _TEXT_LIMIT):
                out.append(f"WARNING the policy recorded for checkouts of this working tree that have no {POLICY_REL} "
                           f"differs from {POLICY_REL}. Run {cmd} init --apply to record the current one.")
        except OSError:
            pass
    same = (lambda a, b: a.lower() == b.lower()) if IS_WINDOWS else (lambda a, b: a == b)
    try:
        gone = {g["file"]: g for g in hook_files_gone(repo)}
    except (OSError, PeciaError):
        gone = {}
    for rel in (".claude/settings.local.json", ".codex/hooks.json"):
        p = repo.path(rel)
        if p.exists():
            try:
                txt = read_text(p)
            except OSError as e:
                out.append(f"WARNING {rel} cannot be read as a regular file ({e.strerror or e}); the agent's hooks "
                           "cannot run from it. Replace it with a regular file: init --apply --install-hooks.")
                continue
            out.append(f"{rel}: {'pecia hooks present' if 'hook' in txt and 'pecia.py' in txt else 'no pecia hooks'}")
            try:
                matches = _pecia_hook_matches(json.loads(txt))
            except (ValueError, RecursionError):
                matches = []
            try:
                legacy = _has_legacy_guard_lines(json.loads(txt))
            except (ValueError, RecursionError):
                legacy = False
            if legacy:
                out.append(f"WARNING {rel} holds Codex guard lines from 0.1.2rc10 or earlier, which do not name their "
                           "event; when Codex's hook input cannot be read, the prompt guard then answers in the form "
                           "of a tool call, which may not block the prompt. " + fix_hooks)
            if any(m[0] == "checkout" for m in matches):
                out.append(f"WARNING {rel} runs the pecia.py inside the working tree, the form 0.1.2rc3 and earlier "
                           "installed. On a checkout without that file, such as another branch or a commit from "
                           "before init, every hook fails: Claude Code, and Codex on Linux, then block every prompt, "
                           "and Codex on Windows runs unguarded. " + fix_hooks)
            elif (any(not (same(m[1], fwd(runner)) and same(m[2], fwd(repo.root))) for m in matches)
                  or ("pecia.py" in txt and not matches and fwd(repo.root) not in txt)):
                out.append(f"WARNING {rel} points at a different repository path. " + fix_hooks)
        elif rel in gone:
            # pecia installed hooks there, and git clean -fdx or git stash --all removed the file (RP-09).
            out.append(_hook_gone_warning(repo, gone.pop(rel)))
        else:
            out.append(f"{rel}: absent (snapshot loop still protects launched sessions)")
    for g in gone.values():
        out.append(_hook_gone_warning(repo, g))
    roots = _worktree_roots(repo)
    main_root = roots[0] if roots else None
    if main_root is not None and main_root != repo.root:
        codex_main = main_root / HOOK_FILES["codex"]
        try:
            main_forms = [m[0] for m in _pecia_hook_matches(json.loads(read_text(codex_main)))] if codex_main.is_file() else []
        except (ValueError, RecursionError, OSError):
            main_forms = []
        if "runner" not in main_forms:
            out.append(f"WARNING Codex in this linked worktree runs the main working tree's {HOOK_FILES['codex']} "
                       f"({fwd(codex_main)}), not this tree's, and that file has no pecia hooks in the current form "
                       "(observed with Codex 0.160). A Codex session here is not guarded. Run "
                       f"{cmd} --repo {fwd(main_root)} init --apply --install-hooks --update-hooks.")
        if not repo.path(HOOK_FILES["codex"]).exists():
            out.append(f"WARNING this linked worktree has no {HOOK_FILES['codex']}. Codex 0.160 runs no project hooks "
                       "in a linked worktree without a .codex folder of its own (observed on Linux), so a Codex session "
                       f"here is not guarded. Run {cmd} init --apply --install-hooks here; {cmd} launch AGENT "
                       "--worktree NAME does this for the worktrees it creates.")
    for w in roots:
        if w == repo.root:
            continue
        for rel in _checkout_form_hook_files(Repo(w)):
            out.append(f"WARNING worktree {fwd(w)}: {rel} runs the pecia.py inside that working tree. Run "
                       f"{cmd} --repo {fwd(w)} init --apply --install-hooks --update-hooks.")
    for agent, rel in HOOK_FILES.items():
        if not repo.path(rel).exists():
            continue
        seen = hooks_seen(repo, agent)
        cur = _hooks_file_sha(repo, agent)
        current = bool(seen) and cur is not None and seen.get("hooks_sha256") == cur
        guard = seen["guard_events"] if current else {}
        snap_ev = seen["snapshot_events"] if current else {}
        fix = ("Codex runs project hooks only when the project is trusted and each hook is approved in /hooks; "
               "open codex in this folder, run /hooks, and approve every pecia hook."
               if agent == "codex" else
               "Open claude in this folder once and accept the hooks if Claude Code asks you to review them.")
        if guard:
            ago = int(time.time() - max(_num(v, 0) for v in guard.values()))
            out.append(f"{agent} guard hooks: seen running {ago} s ago ({', '.join(sorted(guard))}) "
                       "with the current hooks file")
            missing = [e for e in GUARD_EVENTS if e not in guard]
            if missing:
                out.append(f"WARNING {agent} {', '.join(missing)} guard not seen running yet. It runs on the first "
                           "prompt or tool call; if the session has already made one, it is not running. " + fix)
        else:
            why = "since the hooks file was written or changed" if seen and not current else "yet"
            only = (f" Only the snapshot hook ran ({', '.join(sorted(snap_ev))}), which does not show that the "
                    "guard runs." if snap_ev else "")
            out.append(f"WARNING {agent} guard hooks have not been seen running {why}.{only} {fix}"
                       " Until then a session started directly is not blocked by the lease.")
        if snap_ev:
            out.append(f"{agent} snapshot hooks: seen running ({', '.join(sorted(snap_ev))})")
    try:
        bind = load_policy(repo).get("guard", {}).get("bind_process", True)
    except PeciaError:
        bind = True
    if bind:
        try:
            binding = process_ancestors() is not None
        except Exception:
            binding = False
        out.append("process binding: available; the guard refuses a lease ID presented from outside the "
                   "launched session" if binding else
                   "WARNING process binding: this platform cannot report process parents, so a lease ID alone "
                   "passes the guard")
    if repo.path(HOOK_FILES["codex"]).exists():
        trust, detail = codex_project_trust(repo)
        out.append(f"codex project trust: {trust} ({detail})" if trust == "trusted" else
                   f"{'WARNING ' if trust == 'untrusted' else ''}codex project trust: {trust} ({detail}). "
                   "Codex ignores .codex/hooks.json in an untrusted project.")
    if IS_WINDOWS and not (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")):
        try:
            import urllib.request
            sysproxy = urllib.request.getproxies().get("https")
        except Exception:
            sysproxy = None
        if sysproxy:
            out.append(f"note: Windows has a system proxy ({sysproxy}) and HTTPS_PROXY is not set. Claude Code "
                       "does not read the Windows system proxy, so its connections bypass it.")
    st = lock_status(repo)
    out.append("lease: none" if not st else
               f"lease: held by {st.get('agent')} since {st.get('started')}{' (STALE)' if st['stale'] else ''}")
    snaps = list_snapshots(repo)
    out.append(f"snapshots for this worktree: {len(snaps)}" +
               (f", newest {int(time.time() - snaps[0]['time'])} s ago" if snaps else ""))
    out.append("note: claude import codex --dry-run is safe for inventory. Without --dry-run it appends a one-time "
               "copy of AGENTS.md into CLAUDE.md, which creates a second copy that drifts.")
    return out


# ---------------------------------------------------------------- launcher

def agent_argv(agent: str, policy: dict) -> list[str]:
    key = "PECIA_AGENT_CMD_" + re.sub(r"[^A-Z0-9]", "_", agent.upper())
    raw = os.environ.get(key)
    if raw:
        argv = json.loads(raw) if raw.strip().startswith("[") else shlex.split(raw, posix=not IS_WINDOWS)
    else:
        argv = policy["agents"].get(agent)
        if isinstance(argv, str):
            argv = shlex.split(argv, posix=not IS_WINDOWS)
    if not argv:
        raise PeciaError(f"unknown agent {agent}; define it under agents in {POLICY_REL}")
    # A bare name is looked up on PATH only, never in the current folder, which is the repository (G4-02); a name
    # with a folder in it is the path the user gave.
    bare = "/" not in argv[0] and "\\" not in argv[0]
    exe = find_program(argv[0]) if bare or os.path.isabs(argv[0]) else (argv[0] if Path(argv[0]).is_file() else None)
    if not exe:
        raise PeciaError(f"cannot find {argv[0]} on PATH")
    return [exe, *argv[1:]]


def ensure_worktree(repo: Repo, name: str, python: str) -> Repo:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,60}", name):
        raise PeciaError("worktree name must be letters, digits, dot, dash, or underscore")
    if not repo.head():
        raise PeciaError("cannot create a worktree before the first commit")
    # Beside the outermost tree that holds this one: from a worktree nested in another tree, such as Claude Code's
    # under .claude/worktrees, a holder beside the nested one would lie inside that tree and share its lease (E2-04).
    outer = coordination_tree(repo)
    holder = outer.root.parent / f"{outer.root.name}.wt"
    path = holder / name
    for p in (holder, path):
        # A link here could lead to any folder, another repository included (V-02).
        if _is_link(p) or (os.path.lexists(p) and not p.is_dir()):
            raise PeciaError(f"{fwd(p)} is a symlink, a junction or not a folder. pecia creates and uses worktrees "
                             "only in real folders there, so nothing was installed or started. Move it aside.")
    branch = f"pecia/{name}"
    created = not os.path.lexists(path)
    if created:
        exists = run_git(repo.root, ["rev-parse", "--verify", "-q", f"refs/heads/{branch}"], check=False).returncode == 0
        rev = f"refs/heads/{branch}" if exists else "HEAD"
        for rel in (STATE_REL, BIN_REL + "/pecia.py"):
            # A new worktree checks out a commit, not the index, so a file only staged would be missing there
            # (D-05). Only a new one: the check ran before reuse too, and refused a worktree already set up
            # whenever this checkout's own commit lacked .pecia/ (K-03).
            kind = run_git(repo.root, ["cat-file", "-t", f"{rev}:{rel}"], check=False)
            if kind.returncode != 0 or kind.stdout.strip() != b"blob":
                where = "" if rev == "HEAD" else f" on branch {branch}, which the worktree would check out"
                raise PeciaError(f"{rel} is not committed{where}; commit .pecia/ before creating worktrees")
        args = ["worktree", "add", str(path), branch] if exists else ["worktree", "add", "-b", branch, str(path), "HEAD"]
        run_git(repo.root, args)
    # The Repo is made first and the checks run on the folder it holds: the folder checked is the one every
    # later write goes to, and a swap after the check is refused when pecia next writes (R13-05).
    wt = Repo(path)
    problem = None
    if os.path.normcase(str(wt.root)) != os.path.normcase(os.path.abspath(str(path))):
        problem = f"resolves to {fwd(wt.root)} through a link"
    try:  # cached now, so every later write uses the git directories that were checked
        common, own = wt.common_dir().resolve(), wt.git_dir()
    except (OSError, PeciaError):
        common = own = None
        problem = problem or "has no readable git directory"
    problem = problem or _foreign_worktree(repo, wt.root)
    if not problem and (common != repo.common_dir().resolve() or own.parent != common / "worktrees"):
        problem = "belongs to another repository"
    if problem:
        raise PeciaError(f"{fwd(path)} {problem}. pecia installs hooks and starts agents only in a worktree of "
                         f"this repository that git lists for it, so nothing was installed or started there. "
                         "Move that folder aside, or pick another --worktree name.")
    # The hooks the user installed may live in the tree launch runs in, in the tree that holds it, or in the main working
    # tree: from Claude Code's nested worktree or from a sibling made with git worktree add, the launching tree has none
    # of its own, and the new worktree was left without them, so a Codex session started there ran unguarded (G2-01).
    sources = [repo, outer] + [t for t in (_main_working_tree(repo),) if t is not None]

    def installed(rel):
        return any(t.path(rel).exists() for t in sources)

    if any(installed(rel) and not wt.path(rel).exists() for rel in HOOK_FILES.values()):
        notes: list[str] = []
        ok = install_runner(wt, True, notes.append, upgrade_only=True,
                            record_policy="if_missing" if created else "never")
        for n in notes:
            print(f"pecia: {n}", file=sys.stderr)
        if not ok:
            raise PeciaError(notes[-1])
    for rel in (".claude/settings.local.json", ".codex/hooks.json"):
        if installed(rel) and not wt.path(rel).exists():
            claude_hooks, codex_hooks = hook_specs(wt, python)
            atomic_write_json(wt.path(rel), claude_hooks if rel.startswith(".claude") else codex_hooks)
    try:
        _ensure_local_exclude(wt, [".pecia/runtime/", ".pecia-restore-*"])
    except UnsafePath as e:
        print(f"pecia: WARNING {e} The state folder was not added to the local exclude file.", file=sys.stderr)
    return wt


def _foreign_worktree(repo: Repo, path: Path):
    """Why path is not a working tree of this repository, or None. It must be the top of a working
    tree (not a folder inside one), share this repository's git directory, and be listed by
    git worktree list; a folder that merely sits where pecia would put a worktree is not one (V-02)."""
    if _is_link(path) or not path.is_dir():
        return "is a symlink, a junction or not a folder"
    top = run_git(path, ["rev-parse", "--show-toplevel"], check=False)
    if top.returncode != 0:
        return "is not a git working tree"
    here = Path(top.stdout.decode("utf-8", "surrogateescape").strip()).resolve()
    if os.path.normcase(str(here)) != os.path.normcase(str(path.resolve())):
        return f"is inside the working tree {fwd(here)}, not the top of one"
    common = run_git(path, ["rev-parse", "--git-common-dir"], check=False)
    if common.returncode != 0:
        return "has no readable git directory"
    c = Path(common.stdout.decode("utf-8", "surrogateescape").strip())
    c = (c if c.is_absolute() else path / c).resolve()
    if os.path.normcase(str(c)) != os.path.normcase(str(repo.common_dir().resolve())):
        return "belongs to another repository"
    listed = {os.path.normcase(str(r)) for r in _worktree_roots(repo)}
    if os.path.normcase(str(path.resolve())) not in listed:
        return "is not listed by git worktree list for this repository"
    return None


def do_launch(repo: Repo, agent: str, extra: list[str], worktree: str | None, interval: float | None,
              kickoff: bool) -> int:
    policy = load_policy(repo)
    if worktree is not None:  # an empty name is refused like every other invalid one, not taken for none (G2-02)
        repo = ensure_worktree(repo, worktree, sys.executable)
        policy = load_policy(repo)
        print(f"pecia: using worktree {fwd(repo.root)}")
    argv = agent_argv(agent, policy)
    interval = float(interval or policy["snapshot"]["interval_seconds"])
    for rel in _checkout_form_hook_files(repo):
        print(f"pecia: WARNING {rel} runs the pecia.py inside the working tree. Checking out a branch or commit "
              "without it would make every hook fail. Run "
              f"{pecia_cmd(repo)} init --apply --install-hooks --update-hooks once to fix this.", file=sys.stderr)
    # Hook files pecia installed that git clean -fdx or git stash --all removed are written again here, before the agent
    # starts, and never while a session runs; one that a stash entry holds is left for git stash pop (RP-09, D7).
    try:
        gone = hook_files_gone(repo)
    except (OSError, PeciaError):
        gone = []
    restore = [g["file"] for g in gone if g["scope"] == "tree-root" and not g["stash"]]
    runner_hooks = any(m[0] == "runner" for m in _all_hook_matches(repo))
    if os.path.lexists(runner_dir(repo)) or runner_hooks or restore:
        notes: list[str] = []
        install_runner(repo, True, notes.append, upgrade_only=True, record_policy="never")
        for n in notes:
            print(f"pecia: {n}", file=sys.stderr)
    if restore:
        written = _reinstall_hook_files(repo, restore)
        gone = [g for g in gone if g["file"] not in written]
        runner_hooks = any(m[0] == "runner" for m in _all_hook_matches(repo))
    for g in gone:
        print("pecia: " + _hook_gone_warning(repo, g), file=sys.stderr)
    try:
        record_installed_hooks(repo, _held_hook_files(repo), "launch", replace=False)
    except (OSError, PeciaError) as e:
        print(f"pecia: WARNING the hook files installed here could not be recorded ({e}), so pecia cannot tell when "
              "they are removed.", file=sys.stderr)
    recorded = [e["file"] for e in _hooks_record(repo) if e["scope"] == "tree-root"]
    missing = {g["file"] for g in gone}
    dead = _hook_launch_problems(repo, agent)
    if dead:
        lines = [d for _, ds in dead for d in ds]
        fixes = [f"{pecia_cmd(repo)}" + ("" if t is repo else f" --repo {fwd(t.root)}") +
                 " init --apply --install-hooks --update-hooks" for t, _ in dead]
        by_hand = any("fix that entry by hand" in ln for ln in lines)
        raise PeciaError("the pecia hooks for " + agent + " cannot start:\n  " + "\n  ".join(lines) +
                         f"\n{agent} was not started. Rewrite them with: " + " ; ".join(fixes) +
                         " (Codex then asks you to approve the changed hooks in /hooks)."
                         + (" That command leaves an entry that also runs a command of yours alone, so fix such an "
                            "entry by hand." if by_hand else ""))
    if runner_hooks:
        state, detail = runner_health(repo)
        if state != "ok":
            # The hooks would fail to start, which lets Codex on Windows run unguarded (T-05).
            raise PeciaError(f"the hook runner is {state} ({detail}) and could not be repaired, so the agent hooks "
                             f"cannot run. {agent} was not started. Fix {fwd(runner_dir(repo))} as the message "
                             f"above says, then run {pecia_cmd(repo)} init --apply")
    res = run_check(repo)
    print(format_check(res))
    held = coordination_tree(repo)
    if held.root != repo.root:
        print(f"pecia: {fwd(repo.root)} lies inside the working tree {fwd(held.root)}, so the write lease is "
              "that tree's and covers both.")
    lease = acquire_lock(repo, agent, policy)
    launched_at = time.time()
    live = _LivePolicy(repo, policy)  # read again when it changes during the run (T-02)
    stop = threading.Event()
    threads = []
    proc = None
    try:
        try:
            first = take_snapshot(repo, "launch-start", agent, policy)
        except Exception as e:
            record_capture_failure(repo, "launch-start", agent, e)  # RP-01; the launch still stops here, loudly
            raise
        snapshot_nested(repo, "launch-start", agent)
        print(f"pecia: snapshot {first['status']} ({first['ref'].rsplit('/', 1)[-1]})")
        if first.get("uncovered"):
            print("pecia: " + uncovered_warning(first["uncovered"], 10), file=sys.stderr)
        if first.get("excluded_tracked"):
            print("pecia: " + excluded_tracked_warning(first["excluded_tracked"], 10), file=sys.stderr)
        findings = "\n".join(f"- [{f['level']}] {f['code']}: {f['message']}" for f in res["findings"]) or "- no findings"
        resume = RESUME_TEMPLATE.format(agent=agent, ts=iso(), root=fwd(repo.root), verdict=res["verdict"],
                                        findings=findings)
        _atomic_write_bytes(repo.runtime / "RESUME_PROMPT.md", resume.encode("utf-8"))

        def heartbeat():
            hb = _num(policy["lock"].get("heartbeat_seconds"), 15)
            while not stop.wait(hb):
                try:
                    beat = write_heartbeat(repo, lease)
                    if beat is None:
                        # lock.json cannot be read for the moment, as while it is being replaced or on a share that
                        # fails a read: one such beat used to end the heartbeat for good, so a guard that judges the
                        # lease by its heartbeat later took it for stale while the agent ran (G2-09).
                        repo.log_event("heartbeat_lock_unreadable", lease=lease, agent=agent)
                        continue
                    if not beat:
                        repo.log_event("lease_lost", lease=lease, agent=agent)
                        print(f"\npecia: WARNING this launcher no longer holds the write lease for {fwd(repo.root)}. "
                              "Another session took it over; the guard now blocks edits from this session.",
                              file=sys.stderr)
                        return
                except (OSError, PeciaError) as e:
                    try:
                        repo.log_event("heartbeat_failed", error=str(e))
                    except Exception:  # noqa: BLE001
                        pass

        def hook_files_check():
            # A recorded hook file removed while the session runs, as git clean -fdx and git stash --all do, is reported
            # once, and never written again during the session: a stash may hold it, and git stash pop would then refuse
            # to put it back (RP-09, D7). The next launch writes it again.
            for rel in recorded:
                there = os.path.lexists(repo.path(rel))
                if not there and rel not in missing:
                    missing.add(rel)
                    repo.log_event("hook_files_gone", file=rel, agent=agent, lease=lease)
                    who = _AGENT_NAMES.get(next((a for a, r in HOOK_FILES.items() if r == rel), ""), "an agent")
                    print(f"\npecia: WARNING {rel} was removed while this session runs (git clean -fdx and git stash "
                          f"--all remove it). Until it is back, a {who} session started directly in {fwd(repo.root)} "
                          "loads no pecia guard and is not blocked by this lease. pecia does not write it while the "
                          "session runs, because a stash may hold it; the next launch writes it again, unless a stash "
                          "entry holds it, which git stash pop puts back.", file=sys.stderr)
                elif there:
                    missing.discard(rel)

        def snapshots():
            tick, due, sig = 0, time.monotonic() + interval, _history_signature(repo)
            while not stop.wait(min(interval, _HISTORY_POLL)):
                try:
                    hook_files_check()
                except Exception:  # noqa: BLE001 - the loop never stops over this
                    pass
                now_sig = _history_signature(repo)
                moved = now_sig != sig
                if not moved and time.monotonic() < due:
                    continue
                sig, due = now_sig, time.monotonic() + interval
                tick += 0 if moved else 1
                try:
                    # Every tenth tick rehashes artifacts, so no cached digest can stay stale for long
                    # even where ctime and inode cannot reveal a same-size rewrite (Windows). A commit, reset or other
                    # step that writes HEAD gets a snapshot at once, so uncommitted work beside it is held (R24-93).
                    take_snapshot(repo, "history" if moved else "timer", agent, live.get(),
                                  rehash=(not moved and tick % 10 == 0))
                except Exception as e:  # keep looping; never take the agent down
                    repo.log_event("snapshot_error", error=str(e))
                    rec = record_capture_failure(repo, "history" if moved else "timer", agent, e)  # RP-01
                    if rec is None or rec.get("new"):
                        print("\n" + _capture_failure_message(repo, rec, e), file=sys.stderr)
                snapshot_nested(repo, "history" if moved else "timer", agent, rehash=(not moved and tick % 10 == 0))

        for fn in (heartbeat, snapshots):
            t = threading.Thread(target=fn, daemon=True)
            t.start()
            threads.append(t)
        env = dict(os.environ, PECIA_LEASE_ID=lease, PECIA_AGENT=agent, PECIA_REPO=fwd(repo.root))
        full = list(argv) + list(extra)
        if kickoff:
            full.append("Read .pecia/runtime/RESUME_PROMPT.md and follow it exactly before doing anything else.")
        print(f"pecia: lease {lease[:8]} held for {agent}; snapshots every {int(interval)} s. Starting {Path(argv[0]).name}.")
        proc = subprocess.Popen(full, cwd=str(repo.root), env=env)
        child_info = {"child_pid": proc.pid, "child_token": proc_token(proc.pid)}
        try:
            write_heartbeat(repo, lease, **child_info)
        except OSError as e:
            repo.log_event("heartbeat_child_failed", error=str(e))
        try:
            update_lock(repo, lease, **child_info)
        except OSError as e:  # never abandon a running agent over bookkeeping
            repo.log_event("lock_update_failed", error=str(e))
        old = None
        if not IS_WINDOWS:
            old = signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            while True:
                try:
                    proc.wait()
                    break
                except KeyboardInterrupt:
                    continue
        finally:
            if old is not None:
                signal.signal(signal.SIGINT, old)
        return proc.returncode
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=5)
        try:
            final = take_snapshot(repo, "launch-exit", agent, live.get())
            snapshot_nested(repo, "launch-exit", agent)
            print(f"pecia: final snapshot {final['status']} ({final['ref'].rsplit('/', 1)[-1]})")
            if final.get("uncovered"):
                print("pecia: " + uncovered_warning(final["uncovered"], 10), file=sys.stderr)
        except Exception as e:
            print(f"pecia: final snapshot failed: {e}", file=sys.stderr)
            if record_capture_failure(repo, "launch-exit", agent, e) is not None:  # RP-01
                print("pecia: the failed capture is recorded; status, doctor and recover report it until recover ack",
                      file=sys.stderr)
        release_lock(repo, lease)
        rc = proc.returncode if proc is not None else None
        repo.log_event("launch_exit", agent=agent, lease=lease, returncode=rc)
        if agent in HOOK_FILES and repo.path(HOOK_FILES[agent]).exists() and proc is not None:
            seen = hooks_seen(repo, agent)
            mine = (seen or {}).get("leases") if isinstance((seen or {}).get("leases"), dict) else {}
            if not seen or _num(mine.get(lease), 0) < launched_at:
                repo.log_event("hooks_not_seen", agent=agent, lease=lease)
                print(f"pecia: WARNING {agent} did not run this kit's guard hooks during the session. "
                      "The lease and snapshots still worked, but a session started directly would not be "
                      "blocked. Run " + pecia_cmd(repo) + " doctor for the fix.", file=sys.stderr)
        try:
            still_gone = hook_files_gone(repo)
        except Exception:  # noqa: BLE001 - the exit report never fails over this
            still_gone = []
        for g in still_gone:
            repo.log_event("hook_files_gone_at_exit", file=g["file"], agent=agent, lease=lease)
            print("pecia: " + _hook_gone_warning(repo, g, when=" as this session ends"), file=sys.stderr)
        post = run_check(repo)
        print(format_check(post))
        other = "claude" if agent == "codex" else "codex"
        print(f"pecia: lease released. To continue in the other agent: {pecia_cmd(repo)} launch {other} --kickoff")


_HISTORY_POLL = 1.0


class _LivePolicy:
    """The policy a long-running loop snapshots with: launch's timer and its final snapshot, and watch. Loaded once at
    start, a designation added during a run was never stored, and recovery then said complete without the file (T-02).
    On each use the policy file is read again (its source and bytes, no git call); when they changed, the policy is
    loaded as every command loads it and used if it parses and validates. Otherwise the last good policy stays in use
    and a warning is printed once for those bytes, so a merge conflict in policy.json still leaves timer snapshots
    running. The interval between snapshots stays as read at start."""

    _UNSEEN = object()

    def __init__(self, repo: Repo, policy: dict):
        self.repo, self.policy, self.seen = repo, policy, self._UNSEEN  # compared on first use: an edit since start
        self._lock = threading.Lock()

    def _read(self):
        p = policy_source(self.repo)
        if p is None:
            return None
        try:
            return (str(p), _read_regular(p, _TEXT_LIMIT))
        except OSError as e:
            return (str(p), f"unreadable: {e}")

    def get(self) -> dict:
        with self._lock:
            now = self._read()
            if now == self.seen:
                return self.policy
            self.seen = now
            try:
                pol = load_policy(self.repo)
                for sec in ("snapshot", "artifacts"):  # the sections a snapshot reads as objects
                    if not isinstance(pol.get(sec), dict):
                        raise PeciaError(f"its {sec} section is not an object")
            except (PeciaError, OSError) as e:
                name = POLICY_REL if now and now[0] == str(self.repo.path(POLICY_REL)) else fwd(now[0]) if now else ""
                self.repo.log_event("policy_reload_refused", policy=name, error=str(e))
                print(f"pecia: WARNING the policy {name} cannot be used ({e}); snapshots go on with the last policy "
                      "that could be read until it is fixed", file=sys.stderr)
                return self.policy
            if pol != self.policy:
                self.repo.log_event("policy_reloaded")
            self.policy = pol
            return pol


def _history_signature(repo: Repo) -> tuple:
    """What changes when git writes HEAD, HEAD's branch, HEAD's reflog or the stash: the size, time and file number of
    HEAD, HEAD's log, the branch file HEAD names, packed-refs and the stash's log, read without running git, so the
    snapshot loops can poll it each second and snapshot at once after a commit, reset, stash or other step (R24-93).
    Other branches' files are not read. A reftable repository keeps every reference in files any update rewrites,
    pecia's own snapshot refs included, so there the newest entries of HEAD's and the stash's reflogs are read with git
    (R24-120, R24-133)."""
    out = []
    try:
        gd, cd = repo.git_dir(), repo.common_dir()
        if _ref_format(repo) == "reftable":
            return tuple(run_git(repo.root, ["log", "-g", "-1", "--date=unix", "--format=%H %gd %gs", ref],
                                 check=False).stdout for ref in ("HEAD", "refs/stash"))
    except Exception:  # noqa: BLE001 - the loops never stop over this
        return ()
    paths = [gd / "HEAD", gd / "logs" / "HEAD", cd / "packed-refs", cd / "logs" / "refs" / "stash"]
    try:
        head = (gd / "HEAD").read_text(encoding="utf-8", errors="replace").strip()
        if head.startswith("ref: "):
            paths.append(cd / head[5:])
        out.append(head)
    except OSError:
        out.append(None)
    for f in paths:
        try:
            st = os.stat(f)
            out.append((st.st_size, st.st_mtime_ns, st.st_ino))
        except OSError:
            out.append(None)
    return tuple(out)


def do_watch(repo: Repo, interval: float | None, agent: str | None) -> int:
    policy = load_policy(repo)
    interval = float(interval or policy["snapshot"]["interval_seconds"])
    live = _LivePolicy(repo, policy)  # read again when it changes during the run (T-02)
    print(f"pecia: watching {fwd(repo.root)}; snapshot every {int(interval)} s. Ctrl+C to stop.")
    reported = None
    reported_excluded: list = []
    tick, moved = 0, False
    try:
        while True:
            tick += 0 if moved else 1
            sig = _history_signature(repo)  # read before the snapshot, so a step during it still counts
            try:
                # Every tenth snapshot rehashes artifacts, as the launcher's timer does, so no cached digest can
                # stay stale for long even where the file system cannot reveal a same-size rewrite (L-02). A step
                # that writes HEAD gets a snapshot at once (R24-93).
                r = take_snapshot(repo, "history" if moved else "watch", agent, live.get(),
                                  rehash=(not moved and tick % 10 == 0))
                snapshot_nested(repo, "history" if moved else "watch", agent, rehash=(not moved and tick % 10 == 0))
                if r["created"]:
                    print(f"{iso()} snapshot {r['ref'].rsplit('/', 1)[-1]}")
                now_uncovered = sorted(s["path"] for s in r.get("uncovered", []))
                if now_uncovered != reported:
                    if now_uncovered:
                        print(f"{iso()} " + uncovered_warning(r["uncovered"], 10), file=sys.stderr)
                    elif reported:
                        print(f"{iso()} every file is covered again")
                    reported = now_uncovered
                if (r.get("excluded_tracked") or []) != reported_excluded:
                    reported_excluded = r.get("excluded_tracked") or []
                    if reported_excluded:
                        print(f"{iso()} " + excluded_tracked_warning(reported_excluded, 10), file=sys.stderr)
            except Exception as e:
                # Recorded, so the next snapshot does not erase the gap (RP-01); any other error still ends watch.
                rec = record_capture_failure(repo, "history" if moved else "watch", agent, e)
                print(f"{iso()} snapshot failed: {e}" + ("; the failed capture is recorded, and status, doctor and recover "
                                                        "report it until recover ack" if rec else ""), file=sys.stderr)
                if not isinstance(e, PeciaError):
                    raise
            due, moved = time.monotonic() + interval, False
            while time.monotonic() < due:
                time.sleep(min(interval, _HISTORY_POLL))
                if _history_signature(repo) != sig:
                    moved = True
                    break
    except KeyboardInterrupt:
        return EXIT_OK


# ---------------------------------------------------------------- hooks entry

def _read_hook_stdin():
    """The hook's JSON payload, or {} when there is none. None when it cannot be read or parsed: the guard then
    blocks (Y-03). A parser error such as RecursionError on deeply nested input once ended the guard with exit
    1, which both agents treat as nonblocking."""
    if sys.stdin is None or sys.stdin.isatty():
        return {}
    try:
        raw = sys.stdin.buffer.read()
        return json.loads(raw.decode("utf-8", "replace")) if raw.strip() else {}
    except Exception:  # noqa: BLE001 - any failure here must reach the guard's fail-closed path
        return None


def _codex_deny(reason: str, event: str | None = "PreToolUse") -> int:
    """Codex reads a JSON decision from stdout on exit 0. Exit 0 survives the powershell.exe
    wrapper Codex uses on Windows, which turns a blocking exit 2 into a nonblocking exit 1
    (observed in Q1: Codex logged the hook as Failed and sent the prompt to the model).
    UserPromptSubmit takes the decision/reason shape; PreToolUse takes hookSpecificOutput."""
    if event == "UserPromptSubmit":
        out = {"decision": "block", "reason": reason}
    else:
        out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                      "permissionDecisionReason": reason}}
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()
    print(reason, file=sys.stderr)
    return 0


HOOK_FILES = {"claude": ".claude/settings.local.json", "codex": ".codex/hooks.json"}


def _hooks_file_sha(repo: Repo, agent: str | None) -> str | None:
    """Bind observations to both configurations that can supply hooks in a linked working tree."""
    rel = HOOK_FILES.get(agent or "")
    if not rel:
        return None
    try:
        own = hashlib.sha256(_read_regular(repo.path(rel), _TEXT_LIMIT)).hexdigest()
        main = _main_working_tree(repo)
        if main is None:
            return own
        parent = hashlib.sha256(_read_regular(main.path(rel), _TEXT_LIMIT)).hexdigest()
        return hashlib.sha256((own + "\0" + parent).encode("ascii")).hexdigest()
    except OSError:
        return None


GUARD_EVENTS = ("UserPromptSubmit", "PreToolUse")


def mark_hooks_seen(repo: Repo, agent: str | None, kind: str, event: str | None) -> None:
    """Record that the agent ran one of this kit's hooks, per kind (guard or snapshot) and event.
    Codex skips project hooks silently until the project is trusted and each hook is approved in
    /hooks, one approval per hook, so a snapshot hook running says nothing about the guard. The
    record restarts whenever the hooks file changes, because changed hooks need approving again.
    Never raises."""
    if agent not in HOOK_FILES:
        return
    try:
        path = _lease_dir(repo) / f"hooks-seen-{agent}.json"
        sha = _hooks_file_sha(repo, agent)
        rec = load_json(path, None)
        if not isinstance(rec, dict) or rec.get("hooks_sha256") != sha or not isinstance(rec.get("events"), dict):
            rec = {"agent": agent, "hooks_sha256": sha, "events": {}}
        now = time.time()
        rec["events"][f"{kind}:{event or 'unknown'}"] = now
        rec.update(ts=now, event=event, kind=kind, pid=os.getpid())
        if kind == "guard":
            rec["guard_ts"] = now
        atomic_write_json(path, rec)
    except Exception:
        pass


def mark_guard_lease(repo: Repo, agent: str | None, lease: str | None) -> None:
    """Record that the guard ran for the launched session holding lease: the launcher counts only its own agent's
    guard, so a guard another session ran meanwhile cannot hide that its own agent ran none (N-09). Only a lease the
    guard accepted as this process's own is recorded; a lease ID copied into a process outside that session's
    process tree is refused by the guard and attests to nothing (E2-03). Never raises."""
    if agent not in HOOK_FILES or not (isinstance(lease, str) and re.fullmatch(r"[0-9a-f]{8,64}", lease)):
        return
    try:
        path = _lease_dir(repo) / f"hooks-seen-{agent}.json"
        rec = load_json(path, None)
        if not isinstance(rec, dict) or not isinstance(rec.get("events"), dict):
            return  # mark_hooks_seen writes the record first; without it there is nothing to add to
        leases = rec.get("leases") if isinstance(rec.get("leases"), dict) else {}
        leases[lease] = time.time()
        rec["leases"] = dict(sorted(leases.items(), key=lambda kv: _num(kv[1], 0))[-20:])
        atomic_write_json(path, rec)
    except Exception:
        pass


def hooks_seen(repo: Repo, agent: str) -> dict | None:
    """The hooks-seen record, or None. guard_events maps each guard event seen to its last time."""
    rec = load_json(_lease_dir(repo) / f"hooks-seen-{agent}.json", None)
    if not isinstance(rec, dict):
        return None
    events = rec.get("events") if isinstance(rec.get("events"), dict) else {}
    rec["guard_events"] = {k.split(":", 1)[1]: v for k, v in events.items() if k.startswith("guard:")}
    rec["snapshot_events"] = {k.split(":", 1)[1]: v for k, v in events.items() if k.startswith("snapshot:")}
    return rec


HOOKS_RECORD = "hooks-installed.json"
_AGENT_NAMES = {"claude": "Claude Code", "codex": "Codex"}


def _hooks_record_path(repo: Repo) -> Path:
    """Where pecia records the hook files it installed for this working tree (RP-09): pecia's folder in the tree's own git
    directory, beside the lease folder, which git clean -fdx and git stash --all never touch, while the hook files are
    ignored files at the tree root that both remove. A link at that folder is refused, as for the lease."""
    folder = repo.git_dir() / LEASE_NAMES[0]
    if _is_link(folder):
        raise PeciaError(f"{fwd(folder)} is a symlink or junction. pecia refuses to keep its records through a link "
                         "that can point outside the repository. Replace it with a regular folder.")
    return folder / HOOKS_RECORD


def _hooks_record(repo: Repo) -> list:
    """The hook locations recorded for this working tree. The record lists locations, so it can name several: scope
    tree-root, with file relative to the tree's root, is the only kind this version writes, and only for the two hook
    files pecia installs; an entry of any other scope names an absolute path, is kept and checked, and is never
    written. An unreadable record counts as none."""
    try:
        rec = load_json(_hooks_record_path(repo), None)
    except (OSError, PeciaError):
        return []
    locs = rec.get("locations") if isinstance(rec, dict) else None
    out = []
    for e in locs if isinstance(locs, list) else []:
        if not isinstance(e, dict) or not isinstance(e.get("scope"), str):
            continue
        if e["scope"] == "tree-root":
            if e.get("file") in HOOK_FILES.values():
                out.append(e)
        elif isinstance(e.get("path"), str) and os.path.isabs(e["path"]):
            out.append(e)
    return out


def _held_hook_files(repo: Repo) -> list:
    """The hook files at the tree root that exist now and hold pecia hook entries."""
    out = []
    for rel in HOOK_FILES.values():
        p = repo.path(rel)
        try:
            if p.is_file() and _pecia_hook_matches(json.loads(read_text(p))):
                out.append(rel)
        except (ValueError, RecursionError, OSError):
            pass
    return out


def record_installed_hooks(repo: Repo, rels: list, by: str, replace: bool) -> bool:
    """Record that pecia hooks are installed in the tree-root hook files rels (RP-09). With replace, as init does, the
    tree-root entries become exactly rels; otherwise, as launch does, rels are added. Entries of another scope are kept
    as they are. Returns whether the record changed; raises OSError or PeciaError when it cannot be written."""
    path = _hooks_record_path(repo)
    old = load_json(path, None)
    old_locs = old.get("locations") if isinstance(old, dict) and isinstance(old.get("locations"), list) else []
    old_locs = [e for e in old_locs if isinstance(e, dict)]
    tree = {e["file"]: e for e in old_locs if e.get("scope") == "tree-root" and e.get("file") in HOOK_FILES.values()}
    others = [e for e in old_locs if e.get("scope") != "tree-root"]
    before = set(tree)
    if replace:
        tree = {rel: e for rel, e in tree.items() if rel in rels}
    agent_of = {rel: a for a, rel in HOOK_FILES.items()}
    for rel in rels:
        if rel not in tree:
            tree[rel] = {"scope": "tree-root", "agent": agent_of[rel], "file": rel, "path": fwd(repo.path(rel)),
                         "recorded": iso(), "by": by}
    if set(tree) == before:
        return False  # unchanged, or nothing to record in a tree where none was kept: no file is written
    locs = [tree[rel] for rel in HOOK_FILES.values() if rel in tree] + others
    atomic_write_json(path, {"format": 1, "locations": locs,
                             "about": "hook files pecia installed for this working tree; doctor, status and launch warn "
                                      "when one is gone, and launch writes a tree-root one again. Delete this file "
                                      "to keep hook files you removed on purpose removed."})
    return True


def _stash_holders(repo: Repo, rels: list) -> dict:
    """For each tree-root path in rels that a stash entry holds among its untracked files, the newest such entry, as
    stash@{n}. git stash --all and git stash -u keep untracked and ignored files in the entry's third parent, and git
    stash pop puts them back only where no file of that name exists, so pecia must not write one there first (D7)."""
    found: dict = {}
    if not rels:
        return found
    try:
        entries = _stashes(repo)
    except (OSError, PeciaError):
        return found
    for n, (_w, parents) in enumerate(entries):
        left = [r for r in rels if r not in found]
        if not left:
            break
        if len(parents) < 3:
            continue
        r = run_git(repo.root, ["ls-tree", "-z", "--name-only", "--full-tree", parents[2], "--", *left], check=False)
        names = {x.decode("utf-8", "surrogateescape") for x in r.stdout.split(b"\0") if x} if r.returncode == 0 else set()
        for rel in left:
            if rel in names:
                found[rel] = f"stash@{{{n}}}"
    return found


def hook_files_gone(repo: Repo, stash: bool = True) -> list:
    """The recorded hook locations whose file is gone (RP-09), each {"agent", "file", "scope", "stash"}: file is the path
    relative to the tree root for scope tree-root, otherwise the recorded absolute path; stash names the stash entry
    that holds a tree-root file, or None."""
    out = []
    for e in _hooks_record(repo):
        tree_root = e["scope"] == "tree-root"
        shown = e["file"] if tree_root else e["path"]
        if os.path.lexists(repo.path(shown) if tree_root else Path(shown)):
            continue
        out.append({"agent": e.get("agent") if e.get("agent") in HOOK_FILES else None, "file": shown,
                    "scope": e["scope"], "stash": None})
    if stash:
        held = _stash_holders(repo, [g["file"] for g in out if g["scope"] == "tree-root"])
        for g in out:
            g["stash"] = held.get(g["file"]) if g["scope"] == "tree-root" else None
    return out


def _hook_gone_warning(repo: Repo, g: dict, when: str = "") -> str:
    """The warning for a recorded hook file that is gone, as doctor, status and the launcher give it."""
    who = _AGENT_NAMES.get(g.get("agent"), "an agent")
    if g["scope"] != "tree-root":
        return (f"WARNING {g['file']} is gone{when}, though pecia recorded hooks there ({g['scope']}). Until it is back, a "
                f"{who} session that loads its hooks from there is not blocked by the lease. This pecia never writes "
                "hook files there.")
    cmd = pecia_cmd(repo)
    s = (f"WARNING {g['file']} is gone{when}, though pecia installed its hooks there: git clean -fdx and git stash --all "
         f"remove it, as an ignored file. Until it is back, a {who} session started directly in this tree loads no pecia "
         "guard and is not blocked by the lease. ")
    if g.get("stash"):
        return s + (f"{g['stash']} holds it: git stash pop puts it back, and launch does not write it while a stash "
                    "holds it.")
    try:
        record = fwd(_hooks_record_path(repo))
    except PeciaError:
        record = f"pecia/{HOOKS_RECORD} in the git directory"
    return s + (f"The next {cmd} launch writes it again with pecia's hooks only, or run {cmd} init --apply "
                f"--install-hooks now. If you removed it on purpose, delete {record} and pecia leaves it removed.")


def _reinstall_hook_files(repo: Repo, rels: list) -> list:
    """Write again the recorded tree-root hook files that are gone and that no stash entry holds (RP-09, D7), with pecia's
    hooks only, as init writes an absent file, and only while the runner they run is sound. launch does this before its
    agent starts; nothing is written while a session runs. Returns the files written."""
    state, detail = runner_health(repo)
    if state != "ok":
        print(f"pecia: WARNING {', '.join(rels)} not written again: the hook runner is {state} ({detail}), and hooks "
              "without a usable runner would fail.", file=sys.stderr)
        return []
    claude_hooks, codex_hooks = hook_specs(repo, sys.executable)
    written = []
    for rel in rels:
        try:
            path = _safe_target(repo, rel)
            if os.path.lexists(path):
                continue  # it came back meanwhile; never replaced
            atomic_write_json(path, claude_hooks if rel == HOOK_FILES["claude"] else codex_hooks)
            written.append(rel)
        except (OSError, PeciaError) as e:
            print(f"pecia: WARNING {rel} could not be written again: {e}", file=sys.stderr)
            continue
        try:
            _ensure_local_exclude(repo, [rel])
        except (OSError, PeciaError) as e:
            print(f"pecia: WARNING {rel} was written again but not added to the local exclude file: {e}",
                  file=sys.stderr)
    if written:
        repo.log_event("hook_files_reinstalled", files=written)
        print(f"pecia: wrote {', '.join(written)} again with pecia's hooks: pecia installed them there and they were gone "
              "(git clean -fdx and git stash --all remove them). Settings of your own a removed file held are not "
              "restored." + (" If Codex asks, approve the hooks again in /hooks." if HOOK_FILES["codex"] in written
                             else ""), file=sys.stderr)
    return written


def _hook_tree(repo_arg, payload, report: dict | None = None, coordinate: bool = True) -> Repo:
    """The working tree a hook judges. Codex runs the main tree's .codex/hooks.json even in a linked
    worktree, and Claude Code runs the main tree's hooks there too, so --repo alone can name the wrong
    tree (R4-01). The session's own folder decides, the hook input's cwd or else the process's, when it
    lies in a working tree of the same repository. A folder in another repository is judged by the tree of this
    one that holds it, when one does (K-01), and otherwise leaves --repo to decide.
    A cwd that is in no repository at all, or does not exist, falls back to the process's folder; when that
    is in none either, report["settled"] is False and the guard applies every tree's lease (D-03). A tree
    nested inside another is then judged as the tree that contains it (_containing_tree)."""
    pinned = Repo.discover(repo_arg)
    cwd = payload.get("cwd") if isinstance(payload, dict) else None
    places = ([cwd] if isinstance(cwd, str) and cwd else []) + [os.getcwd()]
    chosen, settled = pinned, False
    for where in places:
        try:
            cand = Repo.discover(where)
        except (PeciaError, OSError, ValueError):
            continue
        settled = True
        if cand.common_dir().resolve() == pinned.common_dir().resolve():
            if cand.root != pinned.root:
                chosen = cand
        else:
            # A repository of its own inside one of this repository's working trees leaves the session in that
            # tree; keeping --repo there let a session inside a leased linked worktree pass (K-01).
            chosen = _tree_holding(pinned, cand.root) or pinned
        break
    if report is not None:
        report.update(settled=settled, cwd=cwd)
    # coordinate=False gives the tree that holds the session's folder, which the snapshot hook records (G1-05).
    return coordination_tree(chosen) if coordinate else chosen


_FILE_TOOLS = {"Edit": ("file_path",), "Write": ("file_path",), "MultiEdit": ("file_path",),
               "NotebookEdit": ("notebook_path", "file_path")}
_PATCH_HEADER = re.compile(r"(?m)^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+?)\s*$")


def _target_paths(payload) -> list[str]:
    """Files a tool call says it will write: Claude Code's file tools name them in tool_input, and a
    Codex apply_patch names them in its patch headers. Shell commands are not parsed."""
    if not isinstance(payload, dict):
        return []
    tool, ti = payload.get("tool_name"), payload.get("tool_input")
    out = []
    if tool in _FILE_TOOLS and isinstance(ti, dict):
        out += [ti[k] for k in _FILE_TOOLS[tool] if isinstance(ti.get(k), str) and ti.get(k)]
    elif tool == "apply_patch":
        texts = [ti] if isinstance(ti, str) else [v for v in ti.values() if isinstance(v, str)] if isinstance(ti, dict) else []
        if isinstance(ti, dict):
            texts += [x for v in ti.values() if isinstance(v, list) for x in v if isinstance(x, str)]
        for t in texts:
            out += _PATCH_HEADER.findall(t)
    return out


def _target_trees(tree: Repo, payload) -> list:
    """The other working trees of this repository that a tool call writes into, outermost first."""
    paths = _target_paths(payload)
    if not paths:
        return []
    roots = _worktree_roots(tree)
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) and payload.get("cwd") else None
    if cwd is None or not os.path.isdir(cwd):
        # A relative path is taken from the folder the hook runs in, the one _hook_tree falls back to as well, when
        # the input names no folder that exists. The root of the tree judged is not where the session works, and
        # taking paths from there pointed the check at the wrong file (N-06).
        cwd = os.getcwd()
    found = []
    for raw in paths:
        try:
            t = Path(raw) if os.path.isabs(raw) else Path(cwd) / raw
            t = Path(os.path.abspath(t))
            probe = t
            while not probe.exists() and probe != probe.parent:
                probe = probe.parent
            t = probe.resolve() / t.relative_to(probe) if probe != t else t.resolve()
        except (OSError, ValueError):
            continue
        holders = [w for w in roots if w == t or w in t.parents]
        if not holders:
            continue
        outer = min(holders, key=lambda w: len(w.parts))
        if outer != tree.root and all(outer != f.root for f in found):
            found.append(Repo(outer))
    return found


_GUARD_EVENTS = {"prompt": "UserPromptSubmit", "tool": "PreToolUse"}


def do_guard(repo_arg, agent: str, fmt: str = "exit", line_event: str | None = None) -> int:
    """Claude Code format: exit 0 allows, exit 2 blocks with the reason on stderr.
    Codex format: always exit 0, with a JSON deny decision on stdout to block.
    Any internal failure blocks, because hook runners treat other exit codes as nonblocking. The event a hook line
    is registered for (--event) decides the form of a Codex block, so input that cannot be read still gets the
    form its event needs (D-01)."""
    event, repo = _GUARD_EVENTS.get(line_event or ""), None

    def block(reason: str) -> int:
        return _codex_deny(reason, event) if fmt == "codex" else (print(reason, file=sys.stderr) or 2)
    try:
        payload = _read_hook_stdin()
        if not isinstance(payload, dict):
            raise ValueError("the hook input could not be read as a JSON object")
        if event is None:
            event = payload.get("hook_event_name") if isinstance(payload.get("hook_event_name"), str) else None
        where: dict = {}
        repo = _hook_tree(repo_arg, payload, where)
        mark_hooks_seen(repo, agent, "guard", event)
        policy = load_policy(repo)
        accepted: dict = {}
        if event == "UserPromptSubmit" and not policy.get("guard", {}).get("block_prompts", True):
            # Prompts are not blocked here, but whether this is the launched session's own guard is still asked, so
            # its launcher does not warn that its agent ran none.
            try:
                guard_decision(repo, os.environ.get("PECIA_LEASE_ID"), policy, agent, accepted)
            except Exception:  # noqa: BLE001 - advisory only: the user chose not to block prompts (R24-19)
                accepted = {}
            mark_guard_lease(repo, agent, accepted.get("lease"))
            return 0
        allowed, msg = guard_decision(repo, os.environ.get("PECIA_LEASE_ID"), policy, agent, accepted)
        mark_guard_lease(repo, agent, accepted.get("lease"))
        if allowed and not where.get("settled", True):
            # Neither the folder the hook input names nor this process's folder lies in a working tree of this
            # repository, so which tree the session works in is unknown, and every tree's lease applies (D-03).
            for root in _worktree_roots(repo):
                if root == repo.root:
                    continue
                other = Repo(root)
                ok, why = guard_decision(other, os.environ.get("PECIA_LEASE_ID"), load_policy(other), agent)
                if not ok:
                    allowed, repo = False, other
                    msg = (f"{why} (pecia cannot tell which working tree this session works in: the folder its hook "
                           f"input names, {where.get('cwd')!r}, is not in a working tree of this repository, so the "
                           "lease of every working tree applies.)")
                    break
        if allowed and event != "UserPromptSubmit":
            # A write into another working tree of this repository must also pass that tree's lease
            # (R5-01): a session working in one worktree cannot edit a leased tree by its path.
            for other in _target_trees(repo, payload):
                ok, why = guard_decision(other, os.environ.get("PECIA_LEASE_ID"), load_policy(other), agent)
                if not ok:
                    allowed, msg = False, f"{why} (The tool call writes into {fwd(other.root)}.)"
                    repo = other
                    break
        if allowed:
            if msg:
                print(msg, file=sys.stderr)
            return 0
        repo.log_event("guard_blocked", agent=agent, tool=payload.get("tool_name") if isinstance(payload, dict) else None)
        return block(msg)
    except BaseException as e:  # noqa: B036 - fail closed on anything, including bad policy or lock data
        how = pecia_cmd(repo) if repo is not None else "pecia"
        return block(f"pecia guard: internal error ({type(e).__name__}: {e}); blocking as a precaution. "
                     f"Run {how} status and tell the user.")


def do_hook(repo_arg, kind: str, agent: str, event: str | None) -> int:
    """A snapshot hook. Once running, it always exits 0: Claude Code reads exit 2 from a Stop hook as keep going and
    from PreCompact as do not compact, and a snapshot must never steer the agent (R4-04)."""
    payload = _read_hook_stdin()
    if not isinstance(payload, dict):
        payload = {}
    try:
        own = _hook_tree(repo_arg, payload, coordinate=False)
        repo = coordination_tree(own)
    except BaseException:  # noqa: B036 - not even a working tree to log into
        return 0
    mark_hooks_seen(repo, agent, "snapshot", payload.get("hook_event_name") or event)
    # The session's own tree first: a worktree nested in the tree that holds it, such as Claude Code's under
    # .claude/worktrees/, is one entry of the containing tree's snapshot, so none of its files were ever recorded
    # (G1-05). pecia's own inspection worktrees are not snapshotted (IR-24). The containing tree follows, as before,
    # and then every other worktree nested in it, as the launcher and watch take them: work a session leaves in one
    # while its own folder is the containing tree, as a subagent's in worktree isolation, is recorded too (IR31-02).
    trees = ([own] if own.root != repo.root and not _is_inspection_tree(repo, own) else []) + [repo]
    try:
        mine = own.root.resolve()
        trees += [t for t in nested_worktrees(repo) if t.root.resolve() != mine]
    except (OSError, PeciaError):
        pass
    for tree in trees:
        policy = None
        try:
            policy = load_policy(tree)
            if event == "stopfailure" and tree is repo:
                repo.log_event("stop_failure", agent=agent, error_type=payload.get("error_type"),
                               error=payload.get("error"), message=str(payload.get("error_message", ""))[:500])
            take_snapshot(tree, f"hook-{event}", agent, policy)
        except BaseException as e:  # noqa: B036 - a snapshot hook must never interfere with the agent
            try:
                tree.log_event("hook_snapshot_error", hook_event=event, error=str(e))
            except BaseException:  # noqa: B036
                pass
            # The failed capture is recorded and the hook says so in one line, still exiting 0 (IR-19): it passed
            # without a word, and the next snapshot erased the gap (A1a-01, XA1-15, T-05; RP-01, C17 requirements 1, 8).
            rec = record_capture_failure(tree, f"hook-{event}", agent, e, policy_cause=policy is None)
            try:
                print(_capture_failure_message(tree, rec, e), file=sys.stderr)
            except BaseException:  # noqa: B036
                pass
    return 0


def _is_inspection_tree(outer: Repo, tree: Repo) -> bool:
    """Whether tree lies in pecia's own runtime folder of outer, or of any working tree of the same repository, where
    recover inspect makes its worktrees: one made in a nested worktree is under that tree's runtime folder (IR31-08)."""
    try:
        here = tree.root.resolve()
        runtimes = {outer.path(RUNTIME_REL).resolve()}
    except OSError:
        return True
    try:
        runtimes |= {(w / RUNTIME_REL).resolve() for w in _worktree_roots(outer)}
    except (OSError, PeciaError):
        pass  # the outer tree's own folder is still known; a tree is snapshotted rather than skipped on a doubt
    return any(here == rt or rt in here.parents for rt in runtimes)


def nested_worktrees(repo: Repo) -> list:
    """The working trees of repo's repository that lie inside repo's own folder, other than pecia's inspection
    worktrees: Claude Code's under .claude/worktrees/, or any made with git worktree add there. Their files are not
    part of repo's snapshots, so the launcher and watch snapshot each of them as well (G1-05). Never raises."""
    try:
        top = repo.root.resolve()
        out = []
        for w in _worktree_roots(repo):
            if w != top and top in w.parents:
                t = Repo(w)
                if not _is_inspection_tree(repo, t):
                    out.append(t)
        return out
    except (OSError, PeciaError):
        return []


def snapshot_nested(repo: Repo, reason: str, agent, rehash: bool = False) -> None:
    """Snapshot every worktree nested in repo (nested_worktrees), each with its own policy; a failure is logged in
    that tree and never stops the caller."""
    for t in nested_worktrees(repo):
        policy = None
        try:
            policy = load_policy(t)
            take_snapshot(t, reason, agent, policy, rehash=rehash)
        except Exception as e:  # noqa: BLE001 - a nested tree must never take the launcher down
            try:
                t.log_event("snapshot_error", error=str(e))
            except Exception:  # noqa: BLE001
                pass
            # Recorded in that tree, and said once per record: watch took no snapshot of it and printed nothing (T-10).
            rec = record_capture_failure(t, reason, agent, e, policy_cause=policy is None)
            if rec is None or rec.get("new"):
                try:
                    print(_capture_failure_message(t, rec, e), file=sys.stderr)
                except Exception:  # noqa: BLE001
                    pass


# ---------------------------------------------------------------- CLI

def _print_json(obj) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pecia", description="Evidence-preserving continuity for repositories that several AI agents work on in turn.")
    ap.add_argument("--repo", help="path inside the target git working tree")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="install the kit into a repository (dry run unless --apply)")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--append-agents-block", action="store_true")
    p.add_argument("--install-hooks", action="store_true")
    p.add_argument("--update-hooks", action="store_true",
                   help="with --install-hooks: rewrite the pecia entries in existing hook files, keeping the rest")
    sub.add_parser("doctor", help="diagnose installation and environment")
    p = sub.add_parser("check", help="scope-aware consistency check of STATE.md")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("status", help="lease, snapshots, and check summary")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("snapshot", help="take one snapshot now")
    p.add_argument("--reason", default="manual", help="recorded with the snapshot (default: manual)")
    p.add_argument("--agent")
    p.add_argument("--force", action="store_true")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("snapshots", help="list snapshots")
    p.add_argument("--all", action="store_true", help="include every worktree")
    p.add_argument("--limit", type=int, default=20, help="how many to list (default: 20)")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("launch", help="run an agent under a write lease with background snapshots")
    p.add_argument("agent")
    p.add_argument("--worktree")
    p.add_argument("--interval", type=float, help="seconds between snapshots (default: snapshot.interval_seconds)")
    p.add_argument("--kickoff", action="store_true", help="pass the resume instruction as the initial prompt")
    p.epilog = "Arguments after a standalone -- are passed to the agent unchanged."
    p = sub.add_parser("watch", help="snapshot loop for sessions started outside launch")
    p.add_argument("--interval", type=float, help="seconds between snapshots (default: snapshot.interval_seconds)")
    p.add_argument("--agent")
    rec = sub.add_parser("recover", help="non-destructive recovery").add_subparsers(dest="action", required=True)
    p = rec.add_parser("plan")
    p.add_argument("snapshot", nargs="?", default="latest")
    p.add_argument("--json", action="store_true")
    p = rec.add_parser("apply")
    p.add_argument("snapshot", nargs="?", default="latest")
    p.add_argument("--paths", nargs="+")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--missing-only", action="store_true", help="skip files reverted to the committed base")
    p.add_argument("--allow-other-base", action="store_true",
                   help="restore from a snapshot taken on another branch or on rewritten history, and restore a file "
                        "named exactly with --paths whatever commits did since; one taken on an earlier commit of this "
                        "branch needs no flag and restores only paths no later commit touched")
    p.add_argument("--json", action="store_true")
    p = rec.add_parser("inspect")
    p.add_argument("snapshot", nargs="?", default="latest")
    p = rec.add_parser("ack", help="acknowledge what latest reports from snapshots taken before history last moved, "
                                   "from commits history no longer holds, or as work replaced by a different agent")
    p.add_argument("--json", action="store_true")
    p = rec.add_parser("close")
    p.add_argument("target", nargs="?")
    p.add_argument("--discard", action="store_true",
                   help="also delete inspection worktrees that hold changes of their own")
    sub.add_parser("prune", help="apply snapshot retention now")
    p = sub.add_parser("claim", help="hold the write lease for sessions the launcher does not start")
    p.add_argument("agent", help="agent name its hooks pass, such as claude or codex")
    p.add_argument("--hours", type=float, default=4.0, help="how long the claim lasts, in hours (default: 4)")
    sub.add_parser("release", help="end a claim made with pecia claim")
    p = sub.add_parser("verify", help="check every snapshot's artifact list, and the SHA-256 of every object they "
                                      "reference in the store set now")
    p.add_argument("--json", action="store_true")
    hk = sub.add_parser("hook", help="entry points for agent hooks").add_subparsers(dest="kind", required=True)
    p = hk.add_parser("guard")
    p.add_argument("--agent", default="unknown")
    p.add_argument("--format", choices=["exit", "codex"], default="exit")
    p.add_argument("--event", choices=sorted(_GUARD_EVENTS), help="the hook event this line is registered for")
    p = hk.add_parser("snapshot")
    p.add_argument("--agent", default="unknown")
    p.add_argument("--event", default="stop")
    sub.add_parser("version")
    return ap


def main(argv=None) -> int:
    if sys.version_info < (3, 10):
        print("pecia: Python 3.10 or later is required", file=sys.stderr)
        return EXIT_ERROR
    # A character the console cannot show, such as one in a file name on a Windows code page, is printed as
    # an escape rather than ending the command or losing the line.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass
    argv = list(sys.argv[1:] if argv is None else argv)
    agent_extra: list[str] = []
    if "launch" in argv and "--" in argv[argv.index("launch"):]:
        cut = argv.index("--", argv.index("launch"))
        agent_extra, argv = argv[cut + 1:], argv[:cut]
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as e:
        if "guard" in argv and "hook" in argv and e.code not in (0, None):
            # A malformed guard invocation must still block, in the format its runner understands. --help is not
            # malformed: argparse leaves with code 0 after printing it, and that exit stands (L-01).
            if "codex" in argv:
                at = argv.index("--event") + 1 if "--event" in argv else 0
                ev = _GUARD_EVENTS.get(argv[at]) if 0 < at < len(argv) else None
                if ev is None:
                    got = _read_hook_stdin()
                    ev = got.get("hook_event_name") if isinstance(got, dict) else None
                return _codex_deny("pecia guard: malformed hook command; blocking as a precaution.", ev)
            return 2
        raise e
    if args.cmd == "version":
        print(VERSION)
        return EXIT_OK
    if args.cmd == "hook" and args.kind == "guard":
        return do_guard(args.repo, args.agent, args.format, args.event)
    if args.cmd == "hook":
        return do_hook(args.repo, args.kind, args.agent, getattr(args, "event", None))
    try:
        repo = Repo.discover(args.repo)
        if args.cmd == "init":
            lines = do_init(repo, args.apply, args.append_agents_block, args.install_hooks, args.update_hooks)
            for line in lines:
                print(line)
            return EXIT_ATTENTION if any(line.startswith("REFUSED") for line in lines) else EXIT_OK
        if args.cmd == "doctor":
            print("\n".join(do_doctor(repo)))
            return EXIT_OK
        if args.cmd == "check":
            res = run_check(repo)
            _print_json(res) if args.json else print(format_check(res))
            return EXIT_OK if res["verdict"] == "CURRENT" else EXIT_ATTENTION
        if args.cmd == "status":
            res = run_check(repo)
            st = lock_status(repo)
            snaps = list_snapshots(repo)
            cov = load_json(repo.runtime / "coverage.json", {}) or {}
            des = load_json(repo.runtime / "designation.json", {}) or {}
            unmatched = [p for p in (des.get("unmatched") or []) if isinstance(p, str)] if isinstance(des, dict) else []
            gaps = capture_failures(repo, snaps)
            try:
                gone = hook_files_gone(repo)
            except (OSError, PeciaError):
                gone = []
            data = {"check": res, "lease": st, "snapshots": len(snaps), "latest": _snap_public(snaps[0]) if snaps else None,
                    "not_covered": cov.get("items", []), "excluded_tracked": cov.get("excluded_tracked") or [],
                    "unmatched_patterns": unmatched, "capture_failures": gaps, "hook_files_gone": gone}
            if args.json:
                _print_json(data)
            else:
                print(format_check(res))
                print("lease: none" if not st else f"lease: {st.get('agent')} since {st.get('started')}"
                      + (" (STALE: " + "; ".join(st["stale_reasons"]) + ")" if st["stale"] else ""))
                if st and st.get("conflict"):
                    c = st["conflict"]
                    print(f"WARNING a second live lease also governs this tree: {c.get('agent')} since "
                          f"{c.get('started')} (brought here by git worktree move); the guard blocks every session "
                          f"here until one of them ends: {_conflict_remedies(repo, st)}")
                for g in gone:
                    print(_hook_gone_warning(repo, g))
                print(f"snapshots: {len(snaps)}" + (f", latest {snaps[0]['ref'].rsplit('/', 1)[-1]} ({snaps[0]['reason']})" if snaps else ""))
                if cov.get("items"):
                    print(uncovered_warning(cov["items"], 10) + " (as of the last snapshot attempt)")
                if cov.get("excluded_tracked"):
                    print(excluded_tracked_warning(cov["excluded_tracked"], 10) + " (as of the last snapshot attempt)")
                for pat in unmatched:
                    print(_unmatched_line(pat) + " (as of the last snapshot attempt)")
                for rec in gaps:
                    print(_gap_line(rec))
            return EXIT_OK
        if args.cmd == "snapshot":
            r = take_snapshot(repo, args.reason, args.agent, force=args.force)
            if args.json:
                _print_json(r)
            else:
                print(f"{r['status']}: {r['ref']}")
                named = {i["path"] for i in r.get("excluded_tracked") or []}
                for s in r.get("skipped", [])[:20]:
                    if s.get("why") in _DELIBERATE_SKIPS and s.get("path") not in named:
                        print(f"  skipped {s['path']} ({s['why']})")
                if r.get("excluded_tracked"):
                    print(excluded_tracked_warning(r["excluded_tracked"]))
                if r.get("uncovered"):
                    print(uncovered_warning(r["uncovered"]))
                for pat in r.get("unmatched_patterns") or []:
                    print(_unmatched_line(pat))
            return EXIT_ATTENTION if r.get("uncovered") else EXIT_OK
        if args.cmd == "snapshots":
            snaps = list_snapshots(repo, args.all)[: args.limit]
            if args.json:
                _print_json([_snap_public(s_) for s_ in snaps])
            else:
                for i, s in enumerate(snaps):
                    when = _dt.datetime.fromtimestamp(s["time"], _dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                    print(f"{i:>3} {when}Z {s['commit'][:10]} {s['reason']:<14} {s['agent']:<8} head {s['head'][:10]} "
                          f"artifacts {s['artifacts'][:8]} skipped {s['skipped']}")
            return EXIT_OK
        if args.cmd == "launch":
            rc = do_launch(repo, args.agent, agent_extra, args.worktree, args.interval, args.kickoff)
            return rc if isinstance(rc, int) else EXIT_OK
        if args.cmd == "watch":
            return do_watch(repo, args.interval, args.agent)
        if args.cmd == "recover":
            policy = load_policy(repo)
            if args.action == "close":
                res = recover_close(repo, args.target, getattr(args, "discard", False))
                for c in res["closed"]:
                    print(f"closed {c}")
                for k in res["kept"]:
                    print(f"kept {k['path']}:")
                    for c in k["changes"][:20]:
                        print(f"  {c}")
                    if not (k.get("link") or k.get("unowned") or k.get("final")):
                        print("  Copy anything you need out of it, then rerun with --discard to delete it.")
                return EXIT_ATTENTION if res["kept"] else EXIT_OK
            if args.action == "ack":
                res = recover_ack(repo, policy)
                if args.json:
                    _print_json(res)
                else:
                    print(res["note"])
                    for u in res["acknowledged"]:
                        # Every snapshot and commit each acknowledgement ends, not only the first (R24-195).
                        print(f"  {u['path']}: " + "; ".join(_named_in(u)))
                return EXIT_OK
            snap = resolve_snapshot(repo, args.snapshot, policy)
            if args.action == "plan":
                plan = recover_plan(repo, snap, policy)
                plan["capture_failures"] = capture_failures(repo)  # listed until recover ack (RP-01)
                if args.json:
                    _print_json(plan)
                else:
                    print(f"snapshot {snap['ref']} ({snap['reason']}, head {snap['head'][:10]})")
                    if plan.get("note"):
                        print(f"note: {plan['note']}")
                    if not plan["base_matches_head"]:
                        print(f"WARNING: taken on {(plan['snapshot_base'] or 'an unborn branch')[:12]} ({plan['snapshot_branch']}), "
                              f"HEAD is now {(plan['head'] or 'unborn')[:12]} ({plan['branch']}). "
                              "apply requires --allow-other-base.")
                    if plan["deleted_in_snapshot"]:
                        print(f"deleted in the snapshot (never deleted by recovery): {len(plan['deleted_in_snapshot'])}")
                    if plan.get("changed_since_snapshot"):
                        # Settled by commits made since the snapshot, so never candidates; the README promises the list
                        # in the plan itself, not only in --json (G-04).
                        print(f"changed by commits since the snapshot (never restored): "
                              f"{len(plan['changed_since_snapshot'])}")
                        for path in plan["changed_since_snapshot"][:50]:
                            print(f"  {path}")
                    labels = {"missing": "missing now (restorable)",
                              "reverted": "byte-identical to the committed base (restorable, base stays in history)",
                              "differs": "differs from snapshot (never overwritten)",
                              "unsafe": "refused: path runs through a symlink or leaves the repository",
                              "unsupported": "unsupported", "unrecoverable": "unrecoverable",
                              "never_stored": "missing or back at its committed version, and its newest version was "
                                              "never stored (if you removed or restored it on purpose, nothing is "
                                              "lost)",
                              "agent_replaced": "earlier work replaced by a different agent (recover ack ends the report)",
                              "before_move": "missing or at a committed version, and a version of its own is in a "
                                             "snapshot taken before history last moved here, or in a commit history "
                                             "no longer holds (each entry gives the command that restores it, or what "
                                             "to make again by hand where newer work or a later change of history is "
                                             "in the way; recover ack ends the report)"}
                    at_head = (plan["head"] or "-") + ":"
                    for k, label in labels.items():
                        print(f"{label}: {len(plan[k])}")
                        loss = k in ("unsafe", "unrecoverable", "never_stored", "before_move", "agent_replaced")
                        for it in plan[k] if loss else plan[k][:50]:
                            # A file named with --paths can be restorable at HEAD's version, not the base's (R24-87).
                            where = (", at the version committed on HEAD, which stays in history"
                                     if str(it.get("base_spec", "")).startswith(at_head) else "")
                            print(f"  {it['path']}  [{it.get('source') or it.get('why')}{where}]")
                            if loss:
                                _print_also(it)
                    print(f"identical: {len(plan['identical'])}")
                    if plan.get("excluded_tracked"):
                        print(f"tracked files the default secret patterns exclude, which no snapshot holds (changes "
                              f"made to them since their last commit cannot be restored): {len(plan['excluded_tracked'])}")
                        for u in plan["excluded_tracked"]:
                            print(f"  {u['path']} ({u['pattern']})")
                    if plan.get("later_recovery"):
                        print(f"restored by a further recover apply latest, once this snapshot's work is back, from an "
                              f"older snapshot taken since that holds a version this one does not (as after a deletion, "
                              f"a rename or git restore; the command restores it now): {len(plan['later_recovery'])}")
                        for u in plan["later_recovery"]:
                            print(f"  {u['path']}  [{u['command']}]")
                    for n in plan.get("inventory_notices", []):
                        print(f"note: {n}")
                    if plan["capture_failures"]:
                        print(f"failed captures, which recover ack ends: {len(plan['capture_failures'])}")
                        for rec in plan["capture_failures"]:
                            print(f"  {_gap_line(rec)}")
                    print("recover apply restores missing and reverted paths only. Paths that differ hold newer "
                          "work and are never overwritten; use recover inspect to compare them.")
                    if (plan["unrecoverable"] or plan["unsafe"] or plan["unsupported"] or plan["never_stored"]
                            or plan["before_move"] or plan["agent_replaced"]):
                        print("ATTENTION: some evidence in this snapshot cannot be restored; see the lists above.")
                    elif plan.get("later_recovery"):
                        print("ATTENTION: one recover apply latest does not restore everything; see the list above.")
                return (EXIT_ATTENTION if plan["unrecoverable"] or plan["unsafe"] or plan["unsupported"]
                        or plan["never_stored"] or plan["before_move"] or plan["agent_replaced"]
                        or plan.get("later_recovery") else EXIT_OK)
            if args.action == "apply":
                rep = recover_apply(repo, snap, policy, args.paths, args.dry_run, args.missing_only,
                                    args.allow_other_base)
                if args.json:
                    _print_json(rep)
                else:
                    label = "would restore" if args.dry_run else "restored"
                    if rep.get("note"):
                        print(f"note: {rep['note']}")
                    print(f"snapshot: {rep['snapshot']}")
                    print(f"{label}: {len(rep['restored'])}")
                    for p in rep["restored"][:100]:
                        print(f"  {p}")
                    print(f"left untouched because current content differs: {len(rep['left_untouched_differs'])}")
                    for p in rep["left_untouched_differs"][:100]:
                        print(f"  {p}")
                    if rep["unsafe"]:
                        print(f"refused because the path runs through a symlink or leaves the repository: {len(rep['unsafe'])}")
                        for u in rep["unsafe"]:
                            print(f"  {u['path']}: {u['why']}")
                            _print_also(u)
                    if rep.get("unmatched_paths"):
                        print(f"--paths values that match no file in this snapshot: {len(rep['unmatched_paths'])}")
                        for g in rep["unmatched_paths"]:
                            print(f"  {g}")
                    if rep["never_stored"]:
                        print(f"NOT restored because its newest version was never stored (if you removed it on purpose, "
                              f"nothing is lost): {len(rep['never_stored'])}")
                        for u in rep["never_stored"]:
                            print(f"  {u['path']}")
                            _print_also(u)
                    if rep["before_move"]:
                        print(f"NOT restored because a version of its own is in a snapshot taken before history last "
                              f"moved here, or in a commit history no longer holds (each entry gives the command that "
                              f"restores it, or what to make again by hand where newer work or a later change of "
                              f"history is in the way; recover ack ends the report): {len(rep['before_move'])}")
                        for u in rep["before_move"]:
                            print(f"  {u['path']}: {u['why']}")
                            _print_also(u)
                    if rep.get("later_recovery"):
                        print(f"NOT restored yet: a further recover apply latest restores these from an older snapshot "
                              f"taken since that holds a version this one does not (as after a deletion, a rename or git "
                              f"restore); the command restores each now: {len(rep['later_recovery'])}")
                        for u in rep["later_recovery"]:
                            print(f"  {u['path']}  [{u['command']}]")
                    if rep["agent_replaced"]:
                        print(f"NOT restored: earlier work replaced by a different agent: {len(rep['agent_replaced'])}")
                        for u in rep["agent_replaced"]:
                            print(f"  {u['path']}: {u['why']}")
                            _print_also(u)
                    if rep["unrecoverable"]:
                        print(f"NOT restored because no stored copy can be restored: {len(rep['unrecoverable'])}")
                        for u in rep["unrecoverable"]:
                            print(f"  {u['path']}: {u['why']}")
                            _print_also(u)
                    if rep["unsupported"]:
                        print(f"NOT restored because recovery does not handle this entry type: {len(rep['unsupported'])}")
                        for u in rep["unsupported"][:50]:
                            print(f"  {u['path']}: {u['why']}")
                    if rep["errors"]:
                        print(f"failed while restoring: {len(rep['errors'])}")
                    for e in rep["errors"]:
                        print(f"  error {e['path']}: {e['why']}")
                    if rep["skipped_by_option"]:
                        print(f"not restored because of --missing-only: {len(rep['skipped_by_option'])}")
                        for p_ in rep["skipped_by_option"][:100]:
                            print(f"  {p_}")
                    if rep.get("capture_failures"):
                        print(f"failed captures, which recover ack ends: {len(rep['capture_failures'])}")
                        for rec in rep["capture_failures"]:
                            print(f"  {_gap_line(rec)}")
                    if rep.get("excluded_tracked"):
                        print(f"in no snapshot: tracked files the default secret patterns exclude (changes made to them "
                              f"since their last commit cannot be restored): {len(rep['excluded_tracked'])}")
                        for u in rep["excluded_tracked"]:
                            print(f"  {u['path']} ({u['pattern']})")
                    if rep["result"] == "complete":
                        print("result: complete" if rep["restored"] or rep["left_untouched_differs"]
                              else "result: complete (nothing needed restoring)")
                    elif rep["result"] == "partial_by_request":
                        print("result: PARTIAL, as requested. Restorable work listed above was left as it is; "
                              "rerun without --missing-only to restore it.")
                    elif rep.get("later_recovery") and not (
                            rep["unrecoverable"] or rep["never_stored"] or rep["before_move"] or rep["agent_replaced"]
                            or rep["unsafe"] or rep["unsupported"] or rep["errors"] or rep.get("unmatched_paths")):
                        if args.paths or args.missing_only:
                            # The same snapshot is chosen again while its own work is left, so the same options
                            # would name these files for good (IR31-06).
                            print("result: INCOMPLETE. A further recover apply latest without --paths or --missing-only "
                                  "restores the files listed above, once this snapshot's work is restored; with the "
                                  "same options it would not. The command each gives restores it now.")
                        else:
                            print("result: INCOMPLETE. A further recover apply latest restores the files listed above; "
                                  "run it again, or the command each gives.")
                    else:
                        print("result: INCOMPLETE. Some evidence from this snapshot was not restored; see above.")
                return EXIT_OK if rep["complete"] else EXIT_ATTENTION
            if args.action == "inspect":
                dest = recover_inspect(repo, snap, policy)
                problems = inspect_problems(repo, dest)
                if snap.get("note"):
                    print(f"note: {snap['note']}")
                print(f"snapshot checked out for comparison at: {fwd(dest)}")
                if problems:
                    print(f"INCOMPLETE: {len(problems)} stored artifact(s) could not be copied in, or are reported lost:")
                    for pr in problems[:50]:
                        print(f"  {pr['path']}: {pr['why']}")
                print("artifacts from the byte-exact store are copied into it. It is a separate, disposable "
                      f"worktree: edit your real files, not these. Close with: {pecia_cmd(repo)} recover close "
                      "(it refuses to delete a worktree you changed unless you add --discard)")
                return EXIT_ATTENTION if problems else EXIT_OK
        if args.cmd == "prune":
            print(f"pruned {prune_snapshots(repo, load_policy(repo))} snapshot(s)")
            return EXIT_OK
        if args.cmd == "claim":
            _refuse_claim_without_sound_hooks(repo)
            lease = claim_lease(repo, args.agent, args.hours, load_policy(repo))
            held = coordination_tree(repo)
            try:
                ends = " until " + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() + args.hours * 3600))
            except (OverflowError, OSError, ValueError):
                ends = ""
            print(f"{args.agent} holds the write lease for {fwd(held.root)}{ends} ({args.hours:g} hour(s), "
                  f"lease {lease[:8]}). Other agents are blocked. End it with: {pecia_cmd(repo)} release")
            if held.root != repo.root:
                print(f"pecia: {fwd(repo.root)} lies inside that working tree, so one lease covers both.")
            return EXIT_OK
        if args.cmd == "release":
            print("claim released" if release_claim(repo) else "no claim was held")
            return EXIT_OK
        if args.cmd == "verify":
            rep = verify_store(repo, load_policy(repo))
            if args.json:
                _print_json(rep)
            else:
                print(f"snapshots checked: {rep['snapshots']}; objects checked: {rep['checked']}; ok: {rep['ok']}; "
                      f"corrupt: {len(rep['corrupt'])}; missing: {len(rep['missing'])}; "
                      f"artifact lists unreadable: {len(rep['inventory_problems'])}")
                for k in ("corrupt", "missing"):
                    for it in rep[k][:50]:
                        print(f"  {k}: {it['sha256'][:16]} used by {', '.join(it['paths'][:3])}")
                for it in rep["inventory_problems"][:50]:
                    print(f"  artifact list: snapshot {it['snapshot'][:12]}: {it['why']}")
                if rep["manifests_restored"]:
                    print(f"manifest files rebuilt from their snapshot commits: {len(rep['manifests_restored'])} "
                          "(something deleted them; the snapshot commits hold the same lists)")
            bad = rep["corrupt"] or rep["missing"] or rep["inventory_problems"] or rep["manifests_restored"]
            return EXIT_ATTENTION if bad else EXIT_OK
    except PeciaError as e:
        print(f"pecia: {e}", file=sys.stderr)
        return e.exit_code
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
