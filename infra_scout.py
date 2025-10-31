#!/usr/bin/env python3
# SentryKit — quick supply checks in one CLI (deps drift, secrets, image CVEs, canaries)
# Prints to console and writes a .txt report.
# Demo: `python sentrykit.py demo run` sets up a local playground and runs everything.

import argparse, json, os, re, shutil, subprocess, sys, tempfile, time, http.server, socketserver, threading, statistics
from pathlib import Path

# ---------------------------
# Utilities
# ---------------------------

def write_and_print(report_path: Path, text: str):
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(text)
    print(text)

def load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""

def classify_bump(old_v: str, new_v: str) -> str:
    # naive semver-ish classifier: "major/minor/patch/other"
    def split(v):
        nums = re.findall(r"\d+", v)
        return [int(x) for x in nums[:3]] + [0]*(3-len(nums))
    try:
        o1,o2,o3 = split(old_v)
        n1,n2,n3 = split(new_v)
    except Exception:
        return "other"
    if (n1,n2,n3) == (o1,o2,o3): return "none"
    if n1 != o1: return "major"
    if n2 != o2: return "minor"
    if n3 != o3: return "patch"
    return "other"

def parse_requirements(text: str):
    pkgs = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        if "==" in line:
            name, ver = line.split("==", 1)
        else:
            # very light parse: try to split off common spec
            m = re.match(r"^([A-Za-z0-9_.\-]+)(.*)$", line)
            if not m: continue
            name, tail = m.group(1), m.group(2)
            verm = re.search(r"(\d+\.\d+(?:\.\d+)*)", tail)
            ver = verm.group(1) if verm else ""
        pkgs[name.lower()] = ver
    return pkgs

def shannon_entropy(s: str) -> float:
    # rough entropy detector
    from math import log2
    if not s: return 0.0
    probs = [s.count(c)/len(s) for c in set(s)]
    return -sum(p*log2(p) for p in probs)

def run_cmd(cmd, cwd=None, capture=True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=capture, check=False)

# ---------------------------
# Deps drift
# ---------------------------

def deps_check(manifest_path: Path, snapshot_path: Path):
    old = {}
    if snapshot_path.exists():
        old = json.loads(load_text(snapshot_path)) or {}
    new = parse_requirements(load_text(manifest_path))
    added, removed, upgraded, downgraded, majors = [], [], [], [], []

    for n,v in new.items():
        if n not in old:
            added.append((n,v))
        else:
            ov = old[n]
            if v and ov and v != ov:
                bump = classify_bump(ov, v)
                if bump == "major": majors.append((n, ov, v))
                elif bump == "minor": upgraded.append((n, ov, v))
                elif bump == "patch": upgraded.append((n, ov, v))
                else: upgraded.append((n, ov, v))
            elif (not ov) and v:
                upgraded.append((n, ov, v))
    for n,v in old.items():
        if n not in new:
            removed.append((n,v))

    # update snapshot
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    snapshot_path.write_text(json.dumps(new, indent=2), encoding="utf-8")

    lines = []
    status = "OK"
    if majors: status = "WARN"
    lines.append("[Deps Drift]")
    if added:    lines.append("Added: " + ", ".join(f"{n}=={v or '?'}" for n,v in added))
    if removed:  lines.append("Removed: " + ", ".join(f"{n}=={v or '?'}" for n,v in removed))
    if upgraded: lines.append("Changed: " + ", ".join(f"{n} {o or '?'} -> {v or '?'}" for n,o,v in upgraded))
    if majors:   lines.append("MAJOR bumps: " + ", ".join(f"{n} {o} -> {v}" for n,o,v in majors))
    if not (added or removed or upgraded or majors):
        lines.append("No changes.")
    return status, "\n".join(lines)

# ---------------------------
# Secrets scan (diff-based)
# ---------------------------

DEFAULT_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret (base64-ish)", r"(?i)aws(.{0,20})?(secret|key).{0,5}[=:]\s*[A-Za-z0-9/+=]{32,}"),
    ("Generic 40-hex", r"\b[a-f0-9]{40}\b"),
    ("Slack token", r"xox[baprs]-[A-Za-z0-9-]{10,48}"),
    ("GitHub token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
]

ALLOW_EXT = {".py",".js",".ts",".json",".yaml",".yml",".env",".tf",".toml",".ini",".cfg",".sh",".ps1",".go",".java",".rb",".php",".cs",".md"}  # include md for demo visibility

def secrets_check(repo_dir: Path, diff_range: str):
    # get changed text files
    r = run_cmd(["git", "diff", "--name-only", diff_range], cwd=repo_dir)
    files = [Path(repo_dir, f) for f in r.stdout.splitlines() if f.strip()]
    files = [f for f in files if f.suffix.lower() in ALLOW_EXT and f.exists()]
    findings = []
    for f in files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for i, line in enumerate(content.splitlines(), start=1):
            # entropy tokens (length >= 20)
            for token in re.findall(r"[A-Za-z0-9/\+=]{20,}", line):
                if shannon_entropy(token) >= 4.0 and not re.fullmatch(r"[A-Za-z0-9]{20,}\.md", token):
                    findings.append((str(f.relative_to(repo_dir)), i, "High-entropy", token[:12]+"…"))
                    break
            # regex patterns
            for name, pat in DEFAULT_PATTERNS:
                if re.search(pat, line):
                    findings.append((str(f.relative_to(repo_dir)), i, name, line.strip()[:80]))
    status = "OK" if not findings else "FAIL"
    lines = ["[Secrets Scan]"]
    if findings:
        for fn, ln, kind, snip in findings:
            lines.append(f"{fn}:{ln}  [{kind}]  {snip}")
    else:
        lines.append("No findings in diff.")
    return status, "\n".join(lines)

# ---------------------------
# Image scan (Trivy wrapper or sample JSON)
# ---------------------------

def parse_trivy_json(txt: str):
    crit = hi = med = low = unk = 0
    top = []
    try:
        data = json.loads(txt)
    except Exception:
        return 0,0,0,0,0, []
    results = data if isinstance(data, list) else data.get("Results", [])
    for res in results:
        vulns = res.get("Vulnerabilities") or []
        for v in vulns:
            sev = (v.get("Severity") or "").upper()
            if sev == "CRITICAL": crit += 1
            elif sev == "HIGH": hi += 1
            elif sev == "MEDIUM": med += 1
            elif sev == "LOW": low += 1
            else: unk += 1
            if len(top) < 5:
                top.append(f"{v.get('VulnerabilityID','?')} ({sev}) {v.get('PkgName','?')} {v.get('InstalledVersion','?')} -> {v.get('FixedVersion','-')}")
    return crit, hi, med, low, unk, top

def image_check(image: str=None, sample_json: Path=None):
    raw = ""
    if image:
        # try trivy
        proc = run_cmd(["trivy","image","--quiet","--format","json", image], capture=True)
        if proc.returncode == 0 and proc.stdout:
            raw = proc.stdout
        else:
            return "WARN", "[Image Scan]\nTrivy not available or failed; provide --sample-json for demo."
    elif sample_json and sample_json.exists():
        raw = load_text(sample_json)
    else:
        return "WARN", "[Image Scan]\nNo image or sample JSON provided."
    crit, hi, med, low, unk, top = parse_trivy_json(raw)
    status = "OK" if crit == 0 else "FAIL"
    lines = [f"[Image Scan] CRITICAL:{crit} HIGH:{hi} MED:{med} LOW:{low} UNK:{unk}"]
    if top:
        lines.append("Top findings:")
        lines.extend(f"- {x}" for x in top)
    return status, "\n".join(lines)

# ---------------------------
# Canary (HTTP check; demo server)
# ---------------------------

class DemoHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/healthz"):
            time.sleep(0.05)
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        elif self.path.startswith("/admin"):
            time.sleep(0.02)
            self.send_response(401); self.end_headers(); self.wfile.write(b"unauthorized")
        else:
            self.send_response(404); self.end_headers(); self.wfile.write(b"not found")
    def log_message(self, *args, **kwargs):
        pass

def start_demo_server(port):
    httpd = socketserver.TCPServer(("127.0.0.1", port), DemoHandler)
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    return httpd

def http_probe(url, timeout):
    import urllib.request
    t0 = time.time()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=timeout) as r:
            code = r.getcode()
            body = r.read()[:64]
    except Exception as e:
        return None, int((time.time()-t0)*1000), str(e)
    return code, int((time.time()-t0)*1000), body.decode(errors="ignore")

def canary_check(targets, probes=3, timeout=3.0):
    lines = ["[Canary]"]
    failures = 0
    for t in targets:
        url = t["url"]
        expect = int(t.get("expect_status", 200))
        max_p50 = int(t.get("max_ms_p50", 300))
        max_p95 = int(t.get("max_ms_p95", 800))
        lat = []
        codes = []
        errs = 0
        for _ in range(probes):
            code, ms, err = http_probe(url, timeout)
            if code is None:
                errs += 1
                lat.append(ms)
                codes.append("ERR")
            else:
                lat.append(ms)
                codes.append(code)
        p50 = int(statistics.median(lat)) if lat else -1
        p95 = int(statistics.quantiles(lat, n=20)[18]) if len(lat) >= 2 else p50
        ok_status = (codes.count(expect) >= (probes - 0))  # accept minor flakiness
        ok_latency = (p50 <= max_p50 and p95 <= max_p95)
        if not (ok_status and ok_latency):
            failures += 1
        lines.append(f"{url} status_ok={ok_status} latency_ok={ok_latency} codes={codes} p50={p50}ms p95={p95}ms")
    status = "OK" if failures == 0 else "FAIL"
    return status, "\n".join(lines)

# ---------------------------
# Demo workspace
# ---------------------------

def demo_setup(workdir: Path):
    if workdir.exists(): shutil.rmtree(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    # requirements: old vs new
    (workdir/"requirements.txt").write_text("requests==2.28.1\nurllib3==1.26.18\nflask==2.3.2\n", encoding="utf-8")
    (workdir/".cache").mkdir(parents=True, exist_ok=True)
    (workdir/".cache/dep_last.json").write_text(json.dumps({"requests":"2.27.0","urllib3":"1.26.18"}, indent=2), encoding="utf-8")

    # tiny repo with a fake secret in diff
    run_cmd(["git","init"], cwd=workdir)
    (workdir/"README.md").write_text("# Demo repo\n", encoding="utf-8")
    run_cmd(["git","add","README.md"], cwd=workdir)
    run_cmd(["git","commit","-m","init"], cwd=workdir)
    (workdir/"config.env").write_text("API_KEY=AKIAABCDEFGHIJKLMNOP\nNOT_SECRET=hello\n", encoding="utf-8")
    run_cmd(["git","checkout","-b","feature/demo"], cwd=workdir)
    run_cmd(["git","add","config.env"], cwd=workdir)
    run_cmd(["git","commit","-m","add env with demo key"], cwd=workdir)
    # set range as previous commit..HEAD
    diff_range = "HEAD~1..HEAD"

    # sample trivy JSON
    sample = {
      "Results": [
        {"Target":"alpine:3.18","Vulnerabilities":[
          {"VulnerabilityID":"CVE-2024-0001","PkgName":"musl","InstalledVersion":"1.2.3","FixedVersion":"1.2.4","Severity":"CRITICAL"},
          {"VulnerabilityID":"CVE-2024-0002","PkgName":"openssl","InstalledVersion":"3.0.0","FixedVersion":"3.0.1","Severity":"HIGH"},
          {"VulnerabilityID":"CVE-2023-9999","PkgName":"busybox","InstalledVersion":"1.36","FixedVersion":"-","Severity":"MEDIUM"}
        ]}
      ]
    }
    (workdir/"trivy_sample.json").write_text(json.dumps(sample, indent=2), encoding="utf-8")

    # demo canary server (port chosen later)
    return diff_range

# ---------------------------
# Main CLI
# ---------------------------

def build_parser():
    p = argparse.ArgumentParser(prog="sentrykit", description="SentryKit: deps drift, secrets, image CVEs, canaries — demo friendly.")
    p.add_argument("--out", default="reports/report.txt", help="Path to write the .txt report.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("deps", help="Dependency drift check")
    sp.add_argument("--manifest", default="requirements.txt")
    sp.add_argument("--snapshot", default=".cache/dep_last.json")

    sp2 = sub.add_parser("secrets", help="Secrets scan on a git diff range")
    sp2.add_argument("--repo", default=".")
    sp2.add_argument("--range", default="origin/main..HEAD", help="git diff range (e.g., HEAD~1..HEAD)")

    sp3 = sub.add_parser("image", help="Container image scan (trivy) or sample JSON")
    sp3.add_argument("--image", help="e.g., alpine:latest")
    sp3.add_argument("--sample-json", help="Use a sample Trivy JSON file")

    sp4 = sub.add_parser("canary", help="HTTP canary checks")
    sp4.add_argument("--targets", help="JSON list of targets: [{url, expect_status, max_ms_p50, max_ms_p95}]")
    sp4.add_argument("--probes", type=int, default=3)
    sp4.add_argument("--timeout", type=float, default=3.0)

    sp5 = sub.add_parser("run", help="Run all checks with simple defaults")
    sp5.add_argument("--manifest", default="requirements.txt")
    sp5.add_argument("--snapshot", default=".cache/dep_last.json")
    sp5.add_argument("--repo", default=".")
    sp5.add_argument("--range", default="origin/main..HEAD")
    sp5.add_argument("--image")
    sp5.add_argument("--sample-json")
    sp5.add_argument("--targets")

    sp6 = sub.add_parser("demo", help="Demo helpers")
    sp6_sub = sp6.add_subparsers(dest="demo_cmd", required=True)
    d1 = sp6_sub.add_parser("setup", help="Create a local demo workspace")
    d1.add_argument("--dir", default="demo_workspace")
    d2 = sp6_sub.add_parser("run", help="Setup and run everything locally")
    d2.add_argument("--dir", default="demo_workspace")
    return p

def main():
    args = build_parser().parse_args()
    out = Path(args.out)
    if args.cmd == "deps":
        status, text = deps_check(Path(args.manifest), Path(args.snapshot))
        write_and_print(out, f"{text}\nStatus: {status}\n")
    elif args.cmd == "secrets":
        status, text = secrets_check(Path(args.repo), args.range)
        write_and_print(out, f"{text}\nStatus: {status}\n")
    elif args.cmd == "image":
        status, text = image_check(args.image, Path(args.sample_json) if args.sample_json else None)
        write_and_print(out, f"{text}\nStatus: {status}\n")
    elif args.cmd == "canary":
        if args.targets:
            targets = json.loads(args.targets)
        else:
            targets = [{"url":"http://127.0.0.1:9999/healthz","expect_status":200,"max_ms_p50":300,"max_ms_p95":800},
                       {"url":"http://127.0.0.1:9999/admin","expect_status":401,"max_ms_p50":300,"max_ms_p95":800}]
        status, text = canary_check(targets, probes=args.probes, timeout=args.timeout)
        write_and_print(out, f"{text}\nStatus: {status}\n")
    elif args.cmd == "run":
        report_sections = []
        s1, t1 = deps_check(Path(args.manifest), Path(args.snapshot)); report_sections += [t1, f"Status(deps): {s1}"]
        s2, t2 = secrets_check(Path(args.repo), args.range);        report_sections += [t2, f"Status(secrets): {s2}"]
        s3, t3 = image_check(args.image, Path(args.sample_json) if args.sample_json else None); report_sections += [t3, f"Status(image): {s3}"]
        if args.targets: targets = json.loads(args.targets)
        else: targets = [{"url":"http://127.0.0.1:9999/healthz","expect_status":200,"max_ms_p50":300,"max_ms_p95":800},
                         {"url":"http://127.0.0.1:9999/admin","expect_status":401,"max_ms_p50":300,"max_ms_p95":800}]
        s4, t4 = canary_check(targets); report_sections += [t4, f"Status(canary): {s4}"]
        overall = "OK" if all(s in ("OK","WARN") for s in [s1,s2,s3,s4]) and "FAIL" not in [s1,s2,s3,s4] else "FAIL"
        write_and_print(out, "\n\n".join(report_sections) + f"\n\nOverall: {overall}\n")
        sys.exit(0 if overall=="OK" else 1)
    elif args.cmd == "demo":
        workdir = Path(args.dir)
        if args.demo_cmd == "setup":
            diff_range = demo_setup(workdir)
            print(f"Demo workspace created at {workdir.resolve()}")
            print(f"Try:\n  python sentrykit.py deps --manifest {workdir/'requirements.txt'} --snapshot {workdir/'.cache/dep_last.json'} --out {workdir/'report_deps.txt'}")
            print(f"  python sentrykit.py secrets --repo {workdir} --range {diff_range} --out {workdir/'report_secrets.txt'}")
            print(f"  python sentrykit.py image --sample-json {workdir/'trivy_sample.json'} --out {workdir/'report_image.txt'}")
            print(f"  (start canary server with: python sentrykit.py demo run)")
        elif args.demo_cmd == "run":
            # full demo: setup + start canary + run all
            diff_range = demo_setup(workdir)
            port = 9999
            server = start_demo_server(port)
            try:
                targets = json.dumps([
                    {"url": f"http://127.0.0.1:{port}/healthz", "expect_status":200, "max_ms_p50":300, "max_ms_p95":800},
                    {"url": f"http://127.0.0.1:{port}/admin",   "expect_status":401, "max_ms_p50":300, "max_ms_p95":800}
                ])
                # run all
                run_args = [
                    sys.executable, __file__, "run",
                    "--manifest", str(workdir/"requirements.txt"),
                    "--snapshot", str(workdir/".cache/dep_last.json"),
                    "--repo", str(workdir),
                    "--range", diff_range,
                    "--sample-json", str(workdir/"trivy_sample.json"),
                    "--targets", targets,
                    "--out", str(workdir/"report_all.txt")
                ]
                print("Starting local canary server on 127.0.0.1:9999 …")
                time.sleep(0.3)
                subprocess.run(run_args, check=False)
                print(f"\nDemo complete. See {workdir/'report_all.txt'}")
            finally:
                server.shutdown()
    else:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
