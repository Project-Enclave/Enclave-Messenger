#!/usr/bin/env python3
"""
run_all.py - run EVERY test file in test/ and report one summary.

    python test/run_all.py             # all of them
    python test/run_all.py at_rest     # only files whose name contains "at_rest"
    python test/run_all.py --list      # show what would run

Two kinds of test live here and both are handled:
  * files that contain pytest functions (`def test_...`) are run with `python -m pytest`;
  * every other file is a script (a `main()` that prints PASS/FAIL lines) and is run with
    python, judged by its exit code.
Anything named test_*.py is picked up automatically, so a new test file never needs to be
registered anywhere, in CI or here. Files run one after another on purpose: several of them
start real servers on fixed ports.
"""
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def is_script(path):
    text = open(path, encoding="utf-8").read()
    return re.search(r"^\s*(async\s+)?def test_", text, re.M) is None


def main(argv):
    names = [a for a in argv if not a.startswith("-")]
    files = sorted(f for f in os.listdir(HERE) if f.startswith("test_") and f.endswith(".py"))
    if names:
        files = [f for f in files if any(n in f for n in names)]
    if "--list" in argv:
        for f in files:
            print(("script  " if is_script(os.path.join(HERE, f)) else "pytest  ") + f)
        return 0
    if not files:
        print("no test files matched")
        return 1

    results = []
    for f in files:
        path = os.path.join(HERE, f)
        cmd = [sys.executable, path] if is_script(path) else [sys.executable, "-m", "pytest", "-q", path]
        t0 = time.time()
        print(f"\n=== {f}", flush=True)
        r = subprocess.run(cmd, cwd=ROOT)
        results.append((f, r.returncode, time.time() - t0))

    print("\n" + "=" * 60)
    for f, code, dt in results:
        print(f"{'PASS' if code == 0 else 'FAIL'}  {f:<34} {dt:6.1f}s")
    failed = [f for f, code, _ in results if code != 0]
    print(f"\n{len(results) - len(failed)}/{len(results)} test files passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
