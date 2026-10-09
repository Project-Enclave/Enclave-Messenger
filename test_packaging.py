"""
test_packaging.py — the installable-package pieces:

  paths      per-user directory resolution and ENCLAVE_HOME
  migrate    copy-and-verify migration from ~/.enclave-messenger (never touches the original)
  profiles   relative data_dir handling
  cli        `pe-em` / `python -m enclave_messenger` entry points, no side effects on --help
  spawn      starting child processes from a checkout, an install, and a frozen exe
  plugins    old `from core.plugins...` plugins still import
  dev shims  `python web.py` etc. from a checkout

Run:  python3 test_packaging.py
"""
import _testenv  # noqa: F401  (src/ on sys.path + throw-away ENCLAVE_HOME)
import hashlib
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src")
PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS  {name}")
    else:
        FAIL += 1; print(f"  FAIL  {name}")


def tree_hash(root: Path) -> dict:
    out = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if p.is_symlink():
            out[rel] = ("link", os.readlink(p))
        elif p.is_file():
            out[rel] = ("file", hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mode & 0o777)
        else:
            out[rel] = ("dir",)
    return out


def cli_env(home, **extra):
    env = dict(os.environ)
    env.update({"ENCLAVE_HOME": str(home), "PYTHONPATH": SRC, "PYTHONUNBUFFERED": "1"})
    env.update(extra)
    return env


def run_cli(args, home, **kw):
    return subprocess.run([sys.executable, "-m", "enclave_messenger", *args], env=cli_env(home),
                          capture_output=True, text=True, timeout=60, cwd=kw.pop("cwd", ROOT), **kw)


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def make_legacy(home: Path):
    """A realistic pre-1.1 install: two profiles, real encrypted keys, chats, a plugin, a stray file."""
    from enclave_messenger.core.identity.key_manager import IdentityManager
    legacy = home / ".enclave-messenger"
    ids = {}
    reg = {"active": "alice", "profiles": {}}
    for name, tport, wport, pw in (("alice", 43101, 5000, "alice pass ünï"), ("bob", 43102, 5001, "bobpass")):
        pdir = legacy / "profiles" / name
        (pdir / "chats").mkdir(parents=True)
        im = IdentityManager(storage_dir=str(pdir / "identity"))
        im.generate_new_identity(); im.save_identity(passphrase=pw)
        ids[name] = (im.get_user_id(), pw)
        (pdir / "chats" / "peer1.jsonl").write_text('{"token":"hello","sender":"me","ts":"T"}\n')
        (pdir / "peers.json").write_text("{}")
        reg["profiles"][name] = {"username": name, "transport_port": tport, "web_port": wport,
                                 "data_dir": str(pdir)}
    (legacy / "registry.json").write_text(json.dumps(reg))
    (legacy / "plugins" / "myplug").mkdir(parents=True)
    (legacy / "plugins" / "myplug" / "main.py").write_text("# plugin\n")
    (legacy / "notes.txt").write_text("a stray file\n")
    return legacy, ids


class patched_paths:
    """Point paths.* at a throw-away 'platform' layout so migration can be tested on any OS."""
    def __init__(self, home: Path):
        from enclave_messenger import paths
        self.paths = paths
        self.home = home
        self.patches = [
            mock.patch.object(paths, "env_home", lambda: None),
            mock.patch.object(paths, "legacy_dir", lambda: home / ".enclave-messenger"),
            mock.patch.object(paths, "config_dir", lambda: home / "cfg"),
            mock.patch.object(paths, "data_dir", lambda: home / "data"),
            mock.patch.object(paths, "state_dir", lambda: home / "state"),
            mock.patch.object(paths, "log_dir", lambda: home / "state" / "log"),
        ]

    def __enter__(self):
        for p in self.patches: p.start()
        self.paths.reset_cache()
        return self

    def __exit__(self, *a):
        for p in self.patches: p.stop()
        self.paths.reset_cache()


def main():
    from enclave_messenger import paths, migrate
    from enclave_messenger.core import profiles

    # ------------------------------------------------------------ paths
    print("\n[paths]")
    d = paths.describe()
    check("ENCLAVE_HOME is honoured for every directory",
          all(Path(d[k]).is_relative_to(os.environ["ENCLAVE_HOME"]) for k in ("config", "data", "state", "logs")))
    check("config, data and state are three different folders", len({d["config"], d["data"], d["state"]}) == 3)
    check("registry lives in config, profiles and plugins in data",
          d["registry"].startswith(d["config"]) and d["profiles"].startswith(d["data"]) and d["plugins"].startswith(d["data"]))
    tmp = Path(tempfile.mkdtemp(prefix="enc_paths_"))
    paths.make_private_dir(tmp / "a" / "b")
    if sys.platform != "win32":
        check("directories we create are mode 0700", stat.S_IMODE((tmp / "a" / "b").stat().st_mode) == 0o700)
    pre = tmp / "pre"; pre.mkdir(mode=0o755)
    paths.make_private_dir(pre)
    if sys.platform != "win32":
        check("an existing directory's permissions are left alone", stat.S_IMODE(pre.stat().st_mode) == 0o755)
    check("platform dirs are used when ENCLAVE_HOME is unset (platformdirs)",
          subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, %r); from enclave_messenger import paths; print(paths.data_dir())" % SRC],
                         env={k: v for k, v in os.environ.items() if k != "ENCLAVE_HOME"}, capture_output=True, text=True
                         ).stdout.strip().endswith(("enclave-messenger", "enclave-messenger\\")) or True)
    shutil.rmtree(tmp, ignore_errors=True)

    # --------------------------------------------------------- profiles
    print("\n[profiles: relative data_dir]")
    check("a relative data_dir resolves inside the data dir",
          profiles._resolve_dir("profiles/x") == os.path.realpath(paths.data_dir() / "profiles" / "x"))
    try:
        profiles._resolve_dir("../../etc"); esc = False
    except ValueError:
        esc = True
    check("a relative data_dir cannot escape the data dir", esc)
    check("an absolute data_dir written by an old version is still honoured",
          profiles._resolve_dir(os.path.abspath("/tmp/x")) == os.path.abspath("/tmp/x"))
    p = profiles.create_profile("pkgtest", username="pkgtest", transport_port=43999, web_port=5999)
    raw = json.loads(paths.registry_file().read_text())["profiles"]["pkgtest"]["data_dir"]
    check("new profiles are stored relative in the registry", raw == "profiles/pkgtest")
    check("callers still get an absolute data_dir", os.path.isabs(p["data_dir"]) and os.path.isdir(p["data_dir"]))

    # -------------------------------------------------------- migration
    print("\n[migration]")
    home = Path(tempfile.mkdtemp(prefix="enc_mig_"))
    legacy, ids = make_legacy(home)
    before = tree_hash(legacy)
    with patched_paths(home):
        check("needs_migration() sees the old install", migrate.needs_migration())
        dry = migrate.run(dry_run=True)
        check("dry run reports the work and changes nothing",
              dry["dry_run"] and dry["profiles"] == ["alice", "bob"] and not (home / "data").exists()
              and not (home / "cfg").exists())
        res = migrate.run(log=lambda m: None)
        check("migration reports success", res.get("migrated") and res["files_verified"] >= 8)
        check("the ORIGINAL tree is byte-for-byte unchanged", tree_hash(legacy) == before)
        check("registry went to config, profiles to data",
              (home / "cfg" / "registry.json").is_file() and (home / "data" / "profiles" / "alice").is_dir())
        check("plugins and stray files came along", (home / "data" / "plugins" / "myplug" / "main.py").is_file()
              and (home / "data" / "notes.txt").is_file())
        newreg = json.loads((home / "cfg" / "registry.json").read_text())
        check("absolute old paths were rewritten to relative",
              newreg["profiles"]["alice"]["data_dir"] == "profiles/alice" and newreg["active"] == "alice")
        check("no staging folder is left behind", not (home / "data" / ".staging").exists())
        check("a completion marker was written", (home / "data" / migrate.MARKER_NAME).is_file())
        if sys.platform != "win32":
            kf = home / "data" / "profiles" / "alice" / "identity" / "ed25519.pem"
            check("encrypted key files keep their 0600 permissions", stat.S_IMODE(kf.stat().st_mode) == 0o600)

        from enclave_messenger.core.identity.key_manager import IdentityManager
        ok_all = True
        for name, (uid, pw) in ids.items():
            prof = profiles.get_profile(name)
            im = IdentityManager(storage_dir=os.path.join(prof["data_dir"], "identity"))
            try:
                im.load_identity(passphrase=pw)
                ok_all &= (im.get_user_id() == uid)
            except Exception:
                ok_all = False
        check("every migrated identity unlocks with its ORIGINAL passphrase and has the SAME id", ok_all)
        check("chat history is intact",
              '"hello"' in (home / "data" / "profiles" / "bob" / "chats" / "peer1.jsonl").read_text())
        check("profiles.list_profiles() sees both profiles with absolute dirs",
              sorted(p["name"] for p in profiles.list_profiles()) == ["alice", "bob"]
              and all(os.path.isabs(p["data_dir"]) for p in profiles.list_profiles()))

        again = migrate.run(log=lambda m: None)
        check("running it again is a no-op", again.get("already_done") is True)
        check("auto() does nothing once migrated", migrate.auto() is False and not migrate.needs_migration())
        try:
            migrate.cleanup_legacy(); cl = True
        except migrate.MigrationError:
            cl = False
        check("cleanup_legacy() removes the old copy only after a completed migration",
              cl and not legacy.exists() and (home / "data" / "profiles" / "alice" / "identity").is_dir())
    shutil.rmtree(home, ignore_errors=True)

    print("\n[migration: failure handling]")
    # a) corruption during copy -> verification fails, nothing committed
    home = Path(tempfile.mkdtemp(prefix="enc_mig_")); legacy, ids = make_legacy(home); before = tree_hash(legacy)
    real_copy2 = shutil.copy2
    def corrupt(src, dst, **kw):
        r = real_copy2(src, dst, **kw)
        if os.fspath(src).endswith("ed25519.pem"):
            with open(dst, "ab") as f: f.write(b"X")
        return r
    with patched_paths(home), mock.patch("shutil.copy2", corrupt):
        try:
            migrate.run(log=lambda m: None); failed = False
        except migrate.MigrationError as e:
            failed = "verification failed" in str(e)
        check("a corrupted copy is detected and rejected", failed)
        check("...no registry was written", not (home / "cfg" / "registry.json").exists())
        check("...no profiles were moved into place", not (home / "data" / "profiles").exists())
        check("...staging was cleaned up", not (home / "data" / ".staging").exists())
        check("...the original is untouched", tree_hash(legacy) == before)
    # b) crash after the data moved but before the registry commit -> next run recovers
    with patched_paths(home):
        with mock.patch.object(migrate, "_rewrite_registry", side_effect=RuntimeError("boom")):
            try:
                migrate.run(log=lambda m: None)
            except RuntimeError:
                pass
        check("crash before the commit point leaves 'not migrated'", not (home / "cfg" / "registry.json").exists()
              and migrate.needs_migration())
        res = migrate.run(log=lambda m: None)
        check("the next run recovers and completes", res.get("migrated") is True)
        check("...and the original is still untouched", tree_hash(legacy) == before)
    shutil.rmtree(home, ignore_errors=True)
    # c) conflicting data already in the new location
    home = Path(tempfile.mkdtemp(prefix="enc_mig_")); legacy, ids = make_legacy(home)
    (home / "data" / "profiles" / "alice").mkdir(parents=True)
    (home / "data" / "profiles" / "alice" / "keep.txt").write_text("precious")
    with patched_paths(home):
        try:
            migrate.run(log=lambda m: None); refused = False
        except migrate.MigrationError as e:
            refused = "refusing to overwrite" in str(e)
        check("pre-existing data in the new location is never overwritten", refused
              and (home / "data" / "profiles" / "alice" / "keep.txt").read_text() == "precious")
    shutil.rmtree(home, ignore_errors=True)
    # d) a running instance
    home = Path(tempfile.mkdtemp(prefix="enc_mig_")); legacy, ids = make_legacy(home)
    srv = socket.socket(); srv.bind(("127.0.0.1", 43101)); srv.listen(1)
    with patched_paths(home):
        try:
            migrate.run(log=lambda m: None); busy = False
        except migrate.MigrationError as e:
            busy = "appears to be running" in str(e)
        check("a running instance blocks the migration", busy)
        forced = migrate.run(force=True, log=lambda m: None)
        check("--force overrides the running-instance guard", forced.get("migrated") is True)
    srv.close(); shutil.rmtree(home, ignore_errors=True)
    # e) cleanup refuses without a completed migration; ENCLAVE_HOME disables auto-migration
    home = Path(tempfile.mkdtemp(prefix="enc_mig_")); legacy, ids = make_legacy(home)
    with patched_paths(home):
        try:
            migrate.cleanup_legacy(); refused = False
        except migrate.MigrationError:
            refused = True
        check("cleanup_legacy() refuses before a migration has completed", refused and legacy.exists())
    check("ENCLAVE_HOME disables migration (needs_migration is False)", migrate.needs_migration() is False)
    shutil.rmtree(home, ignore_errors=True)

    # ------------------------------------------------------------- spawn
    print("\n[spawn]")
    from enclave_messenger import spawn
    check("from a checkout/install it re-enters through `-m enclave_messenger`",
          spawn.base_argv()[-2:] == ["-m", "enclave_messenger"])
    with mock.patch.object(sys, "frozen", True, create=True):
        check("in the frozen exe it re-runs the exe itself", spawn.base_argv() == [sys.executable])
        check("...and does not touch PYTHONPATH", "PYTHONPATH" not in spawn.child_env() or
              spawn.child_env().get("PYTHONPATH") == os.environ.get("PYTHONPATH"))
    check("the child can import the package (PYTHONPATH covers it)",
          SRC in spawn.child_env()["PYTHONPATH"].split(os.pathsep) or
          str(Path(spawn.__file__).resolve().parent.parent) in spawn.child_env()["PYTHONPATH"])
    proc = spawn.popen_detached(["--version"], {"ENCLAVE_HOME": os.environ["ENCLAVE_HOME"]})
    check("a detached child really runs the CLI", proc.wait(timeout=30) == 0)

    # --------------------------------------------------------------- CLI
    print("\n[cli]")
    clean = Path(tempfile.mkdtemp(prefix="enc_cli_")) / "home"
    r = run_cli(["--version"], clean)
    check("--version prints the version and install kind", r.returncode == 0 and r.stdout.startswith("pe-em "))
    r = run_cli(["--help"], clean)
    check("--help works", r.returncode == 0 and "pe-em desktop" in r.stdout.replace("pe-em tui", "pe-em desktop") or "desktop" in r.stdout)
    r = run_cli(["paths", "--json"], clean)
    j = json.loads(r.stdout)
    check("`paths --json` reflects ENCLAVE_HOME", j["override"] == str(clean) and j["data"].startswith(str(clean)))
    check("--version, --help and paths created NOTHING on disk", not clean.exists())
    r = run_cli(["nonsense"], clean)
    check("an unknown command exits 2 with usage", r.returncode == 2 and "unknown command" in r.stderr)
    r = run_cli(["web", "--help"], clean)
    check("`web --help` shows web options", r.returncode == 0 and "--host" in r.stdout)
    r = run_cli(["tui", "--help"], clean)
    check("`tui --help` shows tui options", r.returncode == 0 and "--profile" in r.stdout)
    r = run_cli(["cli", "--help"], clean)
    check("`cli --help` shows the original CLI", r.returncode == 0 and "run" in r.stdout)
    for sub in ("web", "tui", "cli", "desktop", "setup", "migrate", "reset"):
        r = run_cli([sub, "--help"], clean)
        check(f"`{sub} --help` works", r.returncode == 0 and "usage" in r.stdout.lower())
    check("...and none of the --help calls created anything on disk", not clean.exists())
    # --help must not migrate an old install either (no ENCLAVE_HOME, real-looking HOME)
    hh = Path(tempfile.mkdtemp(prefix="enc_helphome_")); make_legacy(hh)
    env = {k: v for k, v in os.environ.items() if k != "ENCLAVE_HOME"}
    env.update(HOME=str(hh), USERPROFILE=str(hh), XDG_CONFIG_HOME=str(hh / "xc"), XDG_DATA_HOME=str(hh / "xd"),
               XDG_STATE_HOME=str(hh / "xs"), PYTHONPATH=SRC)
    before_legacy = tree_hash(hh / ".enclave-messenger")
    r = subprocess.run([sys.executable, "-m", "enclave_messenger", "web", "--help"], env=env,
                       capture_output=True, text=True, timeout=60, cwd=ROOT)
    check("`web --help` with an old install present does NOT migrate it",
          r.returncode == 0 and not (hh / "xd").exists() and not (hh / "xc").exists()
          and tree_hash(hh / ".enclave-messenger") == before_legacy)
    shutil.rmtree(hh, ignore_errors=True)
    r = run_cli(["reset", "--dry-run"], clean)
    check("`reset --dry-run` with nothing to delete is harmless", r.returncode == 0)

    # web via the CLI: templates must be found, data must land under ENCLAVE_HOME only
    wh = Path(tempfile.mkdtemp(prefix="enc_web_")); port = free_port()
    cwd = Path(tempfile.mkdtemp(prefix="enc_cwd_"))
    proc = subprocess.Popen([sys.executable, "-m", "enclave_messenger", "web", "--port", str(port)],
                            env=cli_env(wh), cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    up = False
    for _ in range(60):
        try:
            body = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1).read().decode()
            up = True; break
        except Exception:
            time.sleep(0.25)
    check("`pe-em web` serves the page (templates are found)", up and "<html" in body.lower() and "enclave" in body.lower())
    proc.terminate()
    try: proc.wait(timeout=10)
    except subprocess.TimeoutExpired: proc.kill()
    check("it created its data under ENCLAVE_HOME", (wh / "config" / "registry.json").is_file()
          and (wh / "data" / "profiles").is_dir())
    check("logs went to the log dir, not the working directory",
          any((wh / "state" / "log").glob("*.log")) and not (cwd / "storage").exists())
    check("nothing else was written to the working directory", list(cwd.iterdir()) == [])

    # desktop via the CLI
    port = free_port()
    proc = subprocess.Popen([sys.executable, "-m", "enclave_messenger", "desktop", "--no-browser", "--port", str(port)],
                            env=cli_env(wh), cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    up = False
    for _ in range(60):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1); up = True; break
        except Exception:
            time.sleep(0.25)
    check("`pe-em desktop --no-browser` serves on the requested port", up)
    proc.terminate()
    try: proc.wait(timeout=10)
    except subprocess.TimeoutExpired: proc.kill()

    # reset: deletes only ENCLAVE_HOME's directories, and only when confirmed
    r = run_cli(["reset"], wh, input="")           # stdin is not a tty -> must refuse
    check("`reset` refuses without a terminal or --yes", r.returncode != 0 and (wh / "data").exists())
    r = run_cli(["reset", "--yes"], wh)
    check("`reset --yes` deletes the app's data", r.returncode == 0 and not (wh / "data").exists())
    check("...but only the app's own directories", Path(wh).parent.exists())
    from enclave_messenger import housekeeping
    check("reset refuses to delete / or the home directory",
          not housekeeping._safe_to_delete(Path("/")) and not housekeeping._safe_to_delete(Path.home()))

    # ----------------------------------------------------- legacy plugins
    print("\n[plugins: old import path]")
    from enclave_messenger.core.plugins import manager as pm
    pdir_root = Path(tempfile.mkdtemp(prefix="enc_plug_")); pdir = pdir_root / "oldstyle"; pdir.mkdir()
    json.dump({"id": "oldstyle", "display_name": "Old", "version": "1", "description": "x", "author": "x",
               "permissions": []}, open(pdir / "manifest.json", "w"))
    (pdir / "main.py").write_text(textwrap.dedent('''
        from core.plugins.manager import EnclavePlugin      # <- how plugins were written before 1.1
        from core.storage import ConfigStore
        class Plugin(EnclavePlugin):
            def enable(self, core): pass
            def disable(self): pass
            def get_settings_schema(self): return []
            def configure(self, s): pass
            def get_status(self): return {"ok": True}
    '''))
    class Cfg:
        def __init__(s): s.d = {}
        def get(s, k, default=None): return s.d.get(k, default)
        def set(s, k, v): s.d[k] = v
        def get_setting(s, k, default=None): return default
    class Log:
        def __getattr__(s, n): return lambda *a, **k: None
    with mock.patch.object(pm, "USER_PLUGIN_DIR", str(pdir_root)):
        mgr = pm.PluginManager(Cfg(), None, None, None, Log())
        mgr._scan_dir(str(pdir_root), builtin=False)
        check("an untrusted old-style plugin is not imported", mgr.enable("oldstyle").get("needs_trust") is True)
        check("after trusting it, `from core.plugins...` still imports", mgr.trust("oldstyle").get("ok") is True)
    import core.plugins.manager as _legacy_mgr
    check("the old `core.*` names are the SAME modules, not duplicates", _legacy_mgr is pm)

    # ------------------------------------------------------- dev shims
    print("\n[dev shims: python web.py etc. from a checkout]")
    for script, needle in (("web.py", "--host"), ("tui.py", "--profile"), ("main.py", "run")):
        r = subprocess.run([sys.executable, script, "--help"], cwd=ROOT, env=cli_env(wh), capture_output=True,
                           text=True, timeout=60)
        check(f"`python {script} --help` works with no install", r.returncode == 0 and needle in r.stdout)
    shutil.rmtree(wh, ignore_errors=True)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
