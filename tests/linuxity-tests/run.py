#!/usr/bin/env python3
"""Run the linuxity test suite.

  python3 run.py                       everything
  python3 run.py process memory        whole areas
  python3 run.py process/fork          one module
  python3 run.py '*pty*' fork_tree     names or globs (matched against area/module:name)
  python3 run.py -j8                   8 tests at once (timing-sensitive ones still run alone)
  python3 run.py --list                show what would run
  python3 run.py --json out.json       save results
  python3 run.py --compare native.json show where this run differs from a saved one
  python3 run.py -v                    print each failure's traceback and output

Each test runs in its own forked process group with a deadline. Scratch files
go under $LXT_ROOT (default /root/lxt-scratch when writable, else /tmp).
Exit status: 0 if nothing failed, 1 otherwise.
"""
import argparse
import fnmatch
import importlib
import json
import os
import select
import shutil
import signal
import sys
import tempfile
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import lxt  # noqa: E402

AREAS = ["kernel", "process", "memory", "filesystem", "networking", "terminal", "tools"]
COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
PAINT = {"PASS": "32", "FAIL": "31", "CRASH": "31;1", "TIMEOUT": "35", "SKIP": "33"}


def paint(s, verdict):
    return f"\033[{PAINT[verdict]}m{s}\033[0m" if COLOR else s


def discover():
    for area in AREAS:
        d = os.path.join(HERE, area)
        for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            if f.endswith(".py") and not f.startswith("_"):
                importlib.import_module(f"{area}.{f[:-3]}")
    return lxt.REGISTRY


def select_cases(cases, pats):
    if not pats:
        return cases
    out = []
    for c in cases:
        keys = (c.id, c.area, f"{c.area}/{c.module}", c.name)
        if any(k == p or fnmatch.fnmatch(k, p) for p in pats for k in keys):
            out.append(c)
    return out


def rm_tree(path):
    """rm -rf that also gets through dirs a test chmod'ed to 0000."""
    for top, dirs, _ in os.walk(path):
        for d in dirs:
            p = os.path.join(top, d)
            try:
                if not os.path.islink(p):
                    os.chmod(p, 0o700)
            except OSError:
                pass
    shutil.rmtree(path, ignore_errors=True)


# ------------------------------------------------------------- one child

def start(case, root):
    """Fork the test into its own process group. Returns the running state."""
    r, w = os.pipe()
    out = tempfile.TemporaryFile()
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        res = {"verdict": "FAIL", "info": "?"}
        try:
            os.setpgid(0, 0)
            # a backgrounded sh starts us with SIGINT/SIGQUIT ignored, and
            # ignored signals survive exec, so reset them all. SIGPIPE and
            # SIGXFSZ stay as python set them.
            keep = (signal.SIGKILL, signal.SIGSTOP, signal.SIGPIPE, signal.SIGXFSZ)
            for s in signal.valid_signals():
                if s not in keep:
                    try:
                        signal.signal(s, signal.SIG_DFL)
                    except (OSError, ValueError):
                        pass
            os.dup2(out.fileno(), 1)
            os.dup2(out.fileno(), 2)
            d = os.path.join(root, case.id.replace("/", "_").replace(":", "_"))
            rm_tree(d)
            os.makedirs(d, exist_ok=True)
            os.chdir(d)
            if case.root and os.getuid() != 0:
                raise lxt.Skip("needs root")
            info = case.fn()
            res = {"verdict": "PASS", "info": str(info or "")}
        except lxt.Skip as e:
            res = {"verdict": "SKIP", "info": str(e)}
        except BaseException as e:
            tb = traceback.extract_tb(e.__traceback__)
            mine = [f for f in tb if f.filename == case.fn.__code__.co_filename]
            where = f" [{os.path.basename(mine[-1].filename)}:{mine[-1].lineno}]" if mine else ""
            res = {"verdict": "FAIL", "info": f"{type(e).__name__}: {e}{where}",
                   "trace": traceback.format_exc()}
        try:
            os.write(w, json.dumps(res).encode())
        finally:
            os._exit(0)
    os.close(w)
    os.set_blocking(r, False)
    return {"case": case, "pid": pid, "pipe": r, "out": out, "buf": b"",
            "t0": time.monotonic(), "status": None}


def drain(st):
    try:
        while (d := os.read(st["pipe"], 65536)):
            st["buf"] += d
    except BlockingIOError:
        pass


def finish(st, timed_out):
    case = st["case"]
    try:
        os.killpg(st["pid"], signal.SIGKILL)   # stragglers the test left behind
    except OSError:
        pass
    if timed_out:
        try:
            os.waitpid(st["pid"], 0)
        except ChildProcessError:
            pass
    drain(st)
    os.close(st["pipe"])
    st["out"].seek(0)
    output = st["out"].read().decode(errors="replace")
    st["out"].close()
    secs = time.monotonic() - st["t0"]
    if timed_out:
        res = {"verdict": "TIMEOUT", "info": f"no result after {case.timeout}s"}
    elif not st["buf"]:
        s = st["status"]
        why = f"signal {signal.Signals(-s).name}" if s < 0 else f"exit {s}"
        res = {"verdict": "CRASH", "info": f"test process died: {why}"}
    else:
        res = json.loads(st["buf"])
    res.update(id=case.id, secs=round(secs, 3), host=case.host, output=output)
    return res


# ------------------------------------------------------------- scheduler

def run_all(cases, root, jobs, report):
    pending = list(cases)
    running = []
    results = []
    wake_r, wake_w = os.pipe()
    for x in (wake_r, wake_w):
        os.set_blocking(x, False)
    old = signal.signal(signal.SIGCHLD, lambda *_: None)
    signal.set_wakeup_fd(wake_w)
    try:
        while pending or running:
            # serial tests only start on an empty floor and keep it to themselves
            while pending and len(running) < jobs:
                nxt = pending[0]
                if nxt.serial and running:
                    break
                if running and running[0]["case"].serial:
                    break
                running.append(start(pending.pop(0), root))
                if nxt.serial:
                    break
            deadline = min(st["t0"] + st["case"].timeout for st in running)
            fds = [st["pipe"] for st in running] + [wake_r]
            try:
                select.select(fds, [], [], max(0.0, deadline - time.monotonic()))
            except InterruptedError:
                pass
            try:
                while os.read(wake_r, 4096):
                    pass
            except BlockingIOError:
                pass
            now = time.monotonic()
            for st in list(running):
                drain(st)
                p, s = os.waitpid(st["pid"], os.WNOHANG)
                if p:
                    st["status"] = os.waitstatus_to_exitcode(s)
                    res = finish(st, False)
                elif now >= st["t0"] + st["case"].timeout:
                    res = finish(st, True)
                else:
                    continue
                running.remove(st)
                results.append(res)
                report(res)
    finally:
        signal.set_wakeup_fd(-1)
        signal.signal(signal.SIGCHLD, old)
        for st in running:
            try:
                os.killpg(st["pid"], signal.SIGKILL)
            except OSError:
                pass
        os.close(wake_r)
        os.close(wake_w)
    return results


# ------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("patterns", nargs="*")
    ap.add_argument("-j", "--jobs", type=int, default=1)
    ap.add_argument("-l", "--list", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--json", metavar="FILE")
    ap.add_argument("--compare", metavar="FILE")
    ap.add_argument("--timeout-scale", type=float, default=1.0,
                    help="multiply every deadline (slow devices)")
    a = ap.parse_args()

    cases = select_cases(discover(), a.patterns)
    if not cases:
        print("no tests match", " ".join(a.patterns))
        return 2
    if a.list:
        for c in cases:
            tags = "".join(f" [{t}]" for t, on in (("serial", c.serial), ("host", c.host), ("root", c.root)) if on)
            print(f"{c.id}{tags}  {c.doc}")
        return 0
    for c in cases:
        c.timeout = c.timeout * a.timeout_scale

    root = os.environ.get("LXT_ROOT")
    if not root:
        for cand in ("/root/lxt-scratch", os.path.join(tempfile.gettempdir(), "lxt-scratch")):
            try:
                os.makedirs(cand, exist_ok=True)
                root = cand
                break
            except OSError:
                continue
    os.makedirs(root, exist_ok=True)
    e = lxt.ENV
    print(f"LINUXITY TESTS  {e['kernel']} {e['machine']}  python {e['python']}  "
          f"{e['cpus']} cpus  uid {e['uid']}  env: {e['kind']}")
    if e["host_kernel"]:
        print("  note: this is not a bare kernel, so tests marked [host] report what the "
              "HOST kernel allows,\n        passed through, not an ability of this environment itself.")
    print(f"  {len(cases)} tests, -j{a.jobs}, scratch {root}\n", flush=True)

    width = max(len(c.id) for c in cases)
    counts = {}

    def report(r):
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        tag = " [host]" if r["host"] and e["host_kernel"] else ""
        v = r["verdict"]
        print(f"  {paint(f'{v:<7}', v)} {r['id']:<{width}} {r['secs']:6.2f}s  {r['info']}{tag}",
              flush=True)
        if a.verbose and r["verdict"] in ("FAIL", "CRASH", "TIMEOUT"):
            for blob in (r.get("trace", ""), r.get("output", "")):
                for ln in blob.rstrip().splitlines():
                    print(f"        | {ln}")

    t0 = time.monotonic()
    try:
        results = run_all(cases, root, max(1, a.jobs), report)
    finally:
        rm_tree(root)
    secs = time.monotonic() - t0

    bad = sum(counts.get(v, 0) for v in ("FAIL", "CRASH", "TIMEOUT"))
    print(f"\n{counts.get('PASS', 0)} passed, {bad} failed, {counts.get('SKIP', 0)} skipped "
          f"of {len(results)} in {secs:.1f}s"
          + "".join(f"  ({v.lower()}: {n})" for v, n in counts.items() if v in ("CRASH", "TIMEOUT")))

    if a.json:
        with open(a.json, "w") as f:
            json.dump({"env": e, "results": results}, f, indent=1)
        print(f"wrote {a.json}")
    if a.compare:
        with open(a.compare) as f:
            ref = json.load(f)
        old = {r["id"]: r for r in ref["results"]}
        diffs = [(r, old[r["id"]]) for r in results
                 if r["id"] in old and r["verdict"] != old[r["id"]]["verdict"]]
        print(f"\ncompared with {a.compare} ({ref['env']['kind']}, {ref['env']['kernel']}): "
              f"{len(diffs)} differ")
        for r, o in diffs:
            print(f"  {r['id']}: {o['verdict']} there, {r['verdict']} here  {r['info']}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
