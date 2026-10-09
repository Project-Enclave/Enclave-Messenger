"""
migrate.py — copy a pre-1.1 install (~/.enclave-messenger) to the per-user
platform directories (see paths.py).

Guarantees
  * The original is NEVER modified or deleted by migrating. Only COPIED.
  * Everything is copied into a staging folder first and checked file-by-file
    (size, SHA-256, permission bits, symlinks) before anything is moved into
    place. If anything differs, the staging copy is discarded and nothing in
    the new location changes.
  * The new registry.json is written LAST. "registry.json exists" therefore
    means "migration finished", so an interrupted run is simply redone.
  * Encrypted identity keys are copied byte-for-byte, keeping their 0600
    permissions. Nothing is re-encrypted; the passphrase is not needed.
  * Old registries store each profile's data_dir as an absolute path into the
    old location. Those are rewritten to the relative form `profiles/<dir>`.

Entry points: auto() (called automatically on first launch), run() (the
`pe-em migrate` command), cleanup_legacy() (`pe-em migrate --cleanup-legacy`).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from enclave_messenger import paths

MARKER_NAME = ".migrated-from"
_DEFAULT_TRANSPORT_PORT = 43100


class MigrationError(Exception):
    """Raised with a message that is safe to show to the user."""


# ---------------------------------------------------------------- detection

def legacy_present() -> bool:
    d = paths.legacy_dir()
    if not d.is_dir():
        return False
    if (d / "registry.json").is_file():
        return True
    prof = d / "profiles"
    return prof.is_dir() and any(prof.iterdir())


def new_initialised() -> bool:
    return paths.registry_file().is_file()


def needs_migration() -> bool:
    return paths.env_home() is None and legacy_present() and not new_initialised()


def _marker_file() -> Path:
    return paths.data_dir() / MARKER_NAME


# ----------------------------------------------------------------- scanning

def _walk(root: Path):
    """Yield (relpath, kind, size, sha256|None, mode) for everything under root."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        base = Path(dirpath)
        for name in sorted(dirnames + filenames):
            p = base / name
            rel = p.relative_to(root).as_posix()
            if p.is_symlink():
                yield rel, "link", 0, os.readlink(p), 0
            elif p.is_dir():
                yield rel, "dir", 0, None, p.stat().st_mode & 0o777
            else:
                h = hashlib.sha256()
                with open(p, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                st = p.stat()
                yield rel, "file", st.st_size, h.hexdigest(), st.st_mode & 0o777


def _snapshot(path: Path):
    if path.is_symlink():
        return [(".", "link", 0, os.readlink(path), 0)]
    if path.is_file():
        h = hashlib.sha256(path.read_bytes()).hexdigest()
        return [(".", "file", path.stat().st_size, h, path.stat().st_mode & 0o777)]
    return list(_walk(path))


def _same(a, b) -> list[str]:
    """Return a list of human-readable differences between two snapshots."""
    problems = []
    da = {x[0]: x for x in a}
    db = {x[0]: x for x in b}
    for rel in sorted(set(da) | set(db)):
        if rel not in db:
            problems.append(f"missing in copy: {rel}")
        elif rel not in da:
            problems.append(f"unexpected in copy: {rel}")
        else:
            x, y = da[rel], db[rel]
            if x[1] != y[1] or x[2] != y[2] or x[3] != y[3]:
                problems.append(f"content differs: {rel}")
            elif sys.platform != "win32" and x[1] != "link" and x[4] != y[4]:
                problems.append(f"permissions differ: {rel} ({oct(x[4])} vs {oct(y[4])})")
    return problems


# ---------------------------------------------------------------- the plan

def _entries() -> list[Path]:
    """Top-level things in the old home that get copied (registry is special)."""
    return [p for p in sorted(paths.legacy_dir().iterdir()) if p.name != "registry.json"]


def plan() -> dict:
    legacy = paths.legacy_dir()
    files = nbytes = 0
    for e in (_entries() if legacy.is_dir() else []):
        for rel, kind, size, _, _ in _snapshot(e):
            if kind == "file":
                files += 1
                nbytes += size
    reg = _read_legacy_registry() if legacy_present() else {"profiles": {}}
    return {
        "legacy": str(legacy),
        "data": str(paths.data_dir()),
        "config": str(paths.config_dir()),
        "needs_migration": needs_migration(),
        "legacy_present": legacy_present(),
        "new_initialised": new_initialised(),
        "profiles": sorted(reg.get("profiles", {})),
        "files": files,
        "bytes": nbytes,
    }


def _read_legacy_registry() -> dict:
    f = paths.legacy_dir() / "registry.json"
    if not f.is_file():
        return {"active": None, "profiles": {}}
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise MigrationError(f"the old registry.json is unreadable ({e}); not migrating")


def _running_ports(reg: dict) -> list[int]:
    """Transport ports (Enclave-specific, unlike web ports) that answer on loopback."""
    ports = {_DEFAULT_TRANSPORT_PORT}
    for meta in reg.get("profiles", {}).values():
        if isinstance(meta, dict) and isinstance(meta.get("transport_port"), int):
            ports.add(meta["transport_port"])
    busy = []
    for port in sorted(ports):
        s = socket.socket()
        s.settimeout(0.2)
        try:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                busy.append(port)
        finally:
            s.close()
    return busy


def _rewrite_registry(reg: dict, legacy: Path) -> tuple[dict, list[str]]:
    notes = []
    out = json.loads(json.dumps(reg))
    old_profiles = os.path.normcase(str(legacy / "profiles"))
    for name, meta in out.get("profiles", {}).items():
        if not isinstance(meta, dict):
            continue
        dd = meta.get("data_dir")
        if not dd or not os.path.isabs(dd):
            continue
        norm = os.path.normcase(os.path.normpath(dd))
        if os.path.dirname(norm) == old_profiles:
            meta["data_dir"] = "profiles/" + os.path.basename(norm)
        else:
            notes.append(f"profile '{name}' stores data outside the old home ({dd}); left as is")
    return out, notes


# -------------------------------------------------------------------- lock

class _Lock:
    def __init__(self):
        self.path = paths.state_dir() / "migrate.lock"

    def __enter__(self):
        paths.make_private_dir(paths.state_dir())
        deadline = time.time() + 60
        while True:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                return self
            except FileExistsError:
                try:
                    age = time.time() - self.path.stat().st_mtime
                except OSError:
                    continue
                if age > 600:                       # stale (crashed run)
                    try:
                        self.path.unlink()
                    except OSError:
                        pass
                    continue
                if time.time() > deadline:
                    raise MigrationError("another Enclave process is migrating; try again in a minute")
                time.sleep(0.2)

    def __exit__(self, *exc):
        try:
            self.path.unlink()
        except OSError:
            pass


# --------------------------------------------------------------------- run

def run(dry_run: bool = False, force: bool = False, log=print) -> dict:
    """Copy + verify. Returns a summary dict. Raises MigrationError on any problem."""
    if paths.env_home() is not None and not force:
        raise MigrationError("ENCLAVE_HOME is set, so the platform directories are not in use")
    if not legacy_present():
        raise MigrationError(f"nothing to migrate: no old data at {paths.legacy_dir()}")

    p = plan()
    if dry_run:
        p["dry_run"] = True
        return p

    legacy = paths.legacy_dir()
    with _Lock():
        if new_initialised() and not force:
            return {**plan(), "already_done": True}

        reg = _read_legacy_registry()
        busy = _running_ports(reg)
        if busy and not force:
            raise MigrationError(
                f"an Enclave instance appears to be running (port {busy[0]} is open). "
                "Close it and try again, or pass --force to copy anyway.")

        data = paths.make_private_dir(paths.data_dir())
        paths.make_private_dir(paths.config_dir())
        stage = data / ".staging"
        if stage.exists():
            shutil.rmtree(stage)                  # leftover from an interrupted run
        stage.mkdir(mode=0o700)

        # Remove what an interrupted earlier run may have already moved into place.
        marker = paths.state_dir() / "migration.json"
        if marker.is_file():
            try:
                for name in json.loads(marker.read_text()).get("entries", []):
                    tgt = data / name
                    if tgt.is_dir() and not tgt.is_symlink():
                        shutil.rmtree(tgt)
                    elif tgt.exists() or tgt.is_symlink():
                        tgt.unlink()
            except (OSError, ValueError):
                pass

        entries = _entries()
        marker.write_text(json.dumps({"from": str(legacy), "started": time.time(),
                                      "entries": [e.name for e in entries]}))
        try:
            log(f"copying {len(entries)} item(s) from {legacy} ...")
            for e in entries:
                dst = stage / e.name
                if e.is_symlink():
                    os.symlink(os.readlink(e), dst)
                elif e.is_dir():
                    shutil.copytree(e, dst, symlinks=True, copy_function=shutil.copy2)
                else:
                    shutil.copy2(e, dst)

            log("verifying every file ...")
            problems = []
            for e in entries:
                problems += [f"{e.name}/{x}" for x in _same(_snapshot(e), _snapshot(stage / e.name))]
            if problems:
                raise MigrationError("verification failed, nothing was changed:\n  " +
                                     "\n  ".join(problems[:10]))

            for e in entries:                      # conflicts are checked before moving anything
                tgt = data / e.name
                if tgt.exists() or tgt.is_symlink():
                    if tgt.is_dir() and not any(tgt.iterdir()):
                        tgt.rmdir()
                    else:
                        raise MigrationError(
                            f"{tgt} already exists and is not empty; refusing to overwrite it")
            for e in entries:
                os.replace(stage / e.name, data / e.name)

            new_reg, notes = _rewrite_registry(reg, legacy)
            tmp = paths.config_dir() / "registry.json.tmp"
            tmp.write_text(json.dumps(new_reg, indent=2), encoding="utf-8")
            os.replace(tmp, paths.registry_file())     # commit point

            nfiles = sum(1 for e in entries for x in _snapshot(data / e.name) if x[1] == "file")
            (data / MARKER_NAME).write_text(json.dumps({
                "from": str(legacy),
                "at": datetime.now(timezone.utc).isoformat(),
                "files": nfiles, "version": 1,
            }, indent=2))
        except BaseException:
            shutil.rmtree(stage, ignore_errors=True)
            raise
        finally:
            shutil.rmtree(stage, ignore_errors=True)
        try:
            marker.unlink()
        except OSError:
            pass

    return {**p, "migrated": True, "files_verified": nfiles, "notes": notes}


def auto(announce=None) -> bool:
    """First-launch hook: migrate if (and only if) it is needed. True if it ran."""
    if not needs_migration():
        return False
    say = announce or (lambda m: print(m, file=sys.stderr, flush=True))
    say(f"[enclave] Found existing data at {paths.legacy_dir()}.")
    say(f"[enclave] Copying it to {paths.data_dir()} - the original is left untouched.")
    try:
        res = run(log=lambda m: say("[enclave] " + m))
    except MigrationError as e:
        if not needs_migration():
            return False                           # another process finished it meanwhile
        raise MigrationError(
            f"Could not copy your existing Enclave data: {e}\n"
            f"Your original data in {paths.legacy_dir()} is safe and unchanged.\n"
            "Fix the problem and run `pe-em migrate`, or run with ENCLAVE_HOME set to "
            "use a different location.") from e
    if res.get("migrated"):
        say(f"[enclave] Done: {res['files_verified']} files copied and verified. "
            "Once you are happy, `pe-em migrate --cleanup-legacy` removes the old copy.")
    return bool(res.get("migrated"))


def cleanup_legacy() -> int:
    """Delete the OLD copy. Only allowed after a completed migration. Returns bytes freed."""
    if not _marker_file().is_file():
        raise MigrationError("no completed migration found; refusing to delete the old data")
    legacy = paths.legacy_dir()
    if not legacy.is_dir():
        return 0
    freed = sum(x[2] for x in _snapshot(legacy) if x[1] == "file")
    shutil.rmtree(legacy)
    return freed
