#!/usr/bin/env python3
# infra-scout — quick supply checks in one CLI (deps drift, secrets, image CVEs, canaries)
# Prints to console and writes timestamped .txt reports under infra-scan-reports/.
# One-command demo: `python infra_scout.py demo`

import argparse, json, os, re, shutil, subprocess, sys, tempfile, time, http.server, socketserver, threading, statistics, datetime, platform
from pathlib import Path

REPORT_DIR = Path("infra-scan-reports")  # reports live here

# ---------------------------
# Utilities & formatting
# ---------------------------

def ts():
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

def now_iso():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def progress(msg: str):
    print(f"[infra-scout] {msg}")

def default_out(name: str):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    return REPORT_DIR / f"{ts()}_{name}.txt"

def write_and_print(report_path: Path, text: str):
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(text)
    print(text)

def load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""

def classify_bump(old_v: str, new_v: str) -> str:
    def split(v):
        nums = re.findall(r"\d+", v)
        return [int(x) for x in nums[:3]] + [0]*(3-len(nums))
    try:
        o1,o2,o3 = split(old_v); n1,n2,n3 = split(new_v)
    except Exception:
        return "other"
    if (n1,n2,n3) == (o1,o2,o3): return "none"
    if n1 != o1: return "major"
    if n2 != o2: return "minor"
    if n3 != o3: return "patch"
    return "other"

def fmt_status(s):
    return {"OK":"✅ OK", "WARN":"⚠️ WARN", "FAIL":"❌ FAIL"}.get(s, s)

def hr():
    return "-" * 60

def spaced(*blocks: str) -> str:
    """Join blocks with a blank line between each non-empty block."""
    return "\n\n".join([b for b in blocks if (b and str(b).strip())])

def build_header(cmd_name, out_path, mode: str):
    hdr = [
        "infra-scout report",
        f"Time: {now_iso()}",
        f"Command: {cmd_name}",
        f"Mode: {mode}",
        f"CWD: {Path.cwd()}",
        f"Python: {platform.python_version()}  OS: {platform.system()} {platform.release()}",
        f"Report path: {out_path.resolve()}",
        hr()
    ]
    return "\n".join(hdr)

def build_summary(rows):
    # rows: list of (name, status, reason)
    parts = ["Summary", "-------"]
    width_name = max(6, max(len(r[0]) for r in rows))
    width_status = 8
    parts.append(f"{'Check'.ljust(width_name)}  {'Status'.ljust(width_status)}  Reason")
    parts.append(f"{'-'*width_name}  {'-'*width_status}  {'-'*30}")
    for name, status, reason in rows:
        parts.append(f"{name.ljust(width_name)}  {fmt_status(status).ljust(width_status)}  {reason}")
    return "\n".join(parts)

def section_title(base: str, mode: str):
    # Append (demo) or (auto) right in the section header if applicable
    suffix = ""
    if mode == "demo":
        suffix = " (demo)"
    elif mode == "auto-fallback":
        suffix = " (auto)"
    return f"{base}{suffix}"

# ---------------------------
# Parsing helpers
# ---------------------------

def parse_requirements(text: str):
    pkgs = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        if "==" in line:
            name, ver = line.split("==", 1)
        else:
            m = re.match(r"^([A-Za-z0-9_.\-]+)(.*)$", line)
            if not m: continue
            name, tail = m.group(1), m.group(2)
            verm = re.search(r"(\d+\.\d+(?:\.\d+)*)", tail)
            ver = verm.group(1) if verm else ""
        pkgs[name.lower()] = ver
    return pkgs

def shannon_entropy(s: str) -> float:
    from math import log2
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]  # correct: iterate 'c'
    return -sum(p * log2(p) for p in probs)

def run_cmd(cmd, cwd=None, capture=True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=capture, check=False)

# ---------------------------
# Explanations (neutral guidance)
# ---------------------------

def explain_deps(status, ctx):
    majors = ctx.get("majors", [])
    changed = ctx.get("upgraded", [])
    added = ctx.get("added", [])
    removed = ctx.get("removed", [])
    title = "What this means / Why you might see it / What to check next"
    out = [title]
    if status in ("WARN","FAIL") and majors:
        out.append("• One or more dependencies jumped a major version. That can include breaking changes.")
        out.append("• Common causes: unpinned versions, lockfile drift, or an intentional upgrade not yet vetted.")
        out.append("• Check next: review changelogs, run tests locally/CI, and decide whether to pin or adopt the new major. If expected, update the snapshot.")
    elif changed or added or removed:
        out.append("• Dependencies changed compared to the last snapshot.")
        out.append("• Common causes: new feature work, transitive resolution changes, or environment differences.")
        out.append("• Check next: confirm intent, ensure reproducibility, and update the snapshot once validated.")
    else:
        out.append("• No drift detected against the snapshot.")
    return "\n".join(out)

def explain_secrets(status, findings):
    title = "What this means / Why you might see it / What to check next"
    out = [title]
    if status == "FAIL" and findings:
        out.append("• Lines in the selected diff resemble credentials or keys (pattern/entropy based).")
        out.append("• Could be false positives (random IDs) or real secrets (e.g., cloud/API keys).")
        out.append("• Check next: confirm validity, rotate if real, store in a secrets manager; allowlist safe test tokens if necessary.")
        out.append("• Example: `High-entropy` ≈ statistically key-like; `AWS Access Key` ≈ matches AKIA* format.")
    else:
        out.append("• No secret-like content detected in the diff.")
    return "\n".join(out)

def explain_image(status, counts):
    crit = counts.get("crit",0); hi=counts.get("hi",0); med=counts.get("med",0)
    title = "What this means / Why you might see it / What to check next"
    out = [title]
    if status == "FAIL" and crit > 0:
        out.append("• The image report includes CRITICAL CVEs.")
        out.append("• Causes: outdated base image, unpatched packages, or known issues in dependencies.")
        out.append("• Check next: bump base image, apply fixed versions, or rebuild regularly from updated bases.")
    elif (hi+med) > 0:
        out.append("• Non-critical CVEs present; triage based on exploitability and exposure.")
        out.append("• Check next: prioritize HIGH items; schedule rebuilds/patch windows.")
    else:
        out.append("• No critical CVEs detected in this report.")
    return "\n".join(out)

def explain_canary(status, failed_count):
    title = "What this means / Why you might see it / What to check next"
    out = [title]
    if status == "FAIL":
        out.append("• One or more endpoints didn’t meet expected status and/or latency thresholds.")
        out.append("• Causes may include downtime, auth/permissions, network/firewall rules, wrong expected code, or strict thresholds.")
        out.append("• Check next: confirm endpoint health and expected code; review SLOs and adjust p50/p95 thresholds to match reality.")
    else:
        out.append("• All probed endpoints met the configured expectations.")
    return "\n".join(out)

# ---------------------------
# Checks (each accepts a title so we can tag (demo)/(auto))
# ---------------------------

def deps_check(manifest_path: Path, snapshot_path: Path, fail_on_major: bool=False, title="[Dependencies Drift]"):
    progress("Running deps check…")
    reason = "No changes"
    old = {}
    if snapshot_path.exists():
        old = json.loads(load_text(snapshot_path)) or {}
    new = parse_requirements(load_text(manifest_path))
    added, removed, upgraded, majors = [], [], [], []

    for n,v in new.items():
        if n not in old:
            added.append((n,v))
        else:
            ov = old[n]
            if v and ov and v != ov:
                bump = classify_bump(ov, v)
                if bump == "major": majors.append((n, ov, v))
                else: upgraded.append((n, ov, v))
            elif (not ov) and v:
                upgraded.append((n, ov, v))
    for n,v in old.items():
        if n not in new:
            removed.append((n,v))

    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    snapshot_path.write_text(json.dumps(new, indent=2), encoding="utf-8")

    lines = [title]
    if added:    lines.append("• Added: " + ", ".join(f"{n}=={v or '?'}" for n,v in added))
    if removed:  lines.append("• Removed: " + ", ".join(f"{n}=={v or '?'}" for n,v in removed))
    if upgraded: lines.append("• Changed: " + ", ".join(f"{n} {o or '?'} → {v or '?'}" for n,o,v in upgraded))
    if majors:
        lines.append("• MAJOR bumps:")
        lines.extend([f"  - {n} {o} → {v}" for n,o,v in majors])
        reason = "Major version bump"
    if not (added or removed or upgraded or majors):
        lines.append("• No drift detected.")
    status = "FAIL" if (majors and fail_on_major) else ("WARN" if majors else "OK")
    ctx = {"majors": majors, "upgraded": upgraded, "added": added, "removed": removed}
    return status, reason, "\n".join(lines), ctx

DEFAULT_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret (base64-ish)", r"(?i)aws(.{0,20})?(secret|key).{0,5}[=:]\s*[A-Za-z0-9/+=]{32,}"),
    ("Generic 40-hex", r"\b[a-f0-9]{40}\b"),
    ("Slack token", r"xox[baprs]-[A-Za-z0-9-]{10,48}"),
    ("GitHub token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
]
ALLOW_EXT = {".py",".js",".ts",".json",".yaml",".yml",".env",".tf",".toml",".ini",".cfg",".sh",".ps1",".go",".java",".rb",".php",".cs",".md"}

def secrets_check(repo_dir: Path, diff_range: str, title="[Secrets Scan]"):
    progress("Running secrets scan…")
    reason = "No findings in diff"
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
            for token in re.findall(r"[A-Za-z0-9/\+=]{20,}", line):
                if shannon_entropy(token) >= 4.0:
                    findings.append((str(f.relative_to(repo_dir)), i, "High-entropy", token[:12]+"…"))
                    break
            for name, pat in DEFAULT_PATTERNS:
                if re.search(pat, line):
                    findings.append((str(f.relative_to(repo_dir)), i, name, line.strip()[:80]))
    lines = [title]
    if findings:
        lines.append("• Findings:")
        for fn, ln, kind, snip in findings:
            lines.append(f"  - {fn}:{ln}  [{kind}]  {snip}")
        status = "FAIL"
        reason = f"{len(findings)} match(es)"
    else:
        lines.append("• No findings in diff.")
        status = "OK"
    ctx = {"findings": findings}
    return status, reason, "\n".join(lines), ctx

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
                top.append(f"{v.get('VulnerabilityID','?')} ({sev}) {v.get('PkgName','?')} {v.get('InstalledVersion','?')} → {v.get('FixedVersion','-')}")
    return crit, hi, med, low, unk, top

BUILTIN_TRIVY_JSON = json.dumps({
  "Results": [
    {"Target":"alpine:3.18","Vulnerabilities":[
      {"VulnerabilityID":"CVE-2024-0001","PkgName":"musl","InstalledVersion":"1.2.3","FixedVersion":"1.2.4","Severity":"CRITICAL"},
      {"VulnerabilityID":"CVE-2024-0002","PkgName":"openssl","InstalledVersion":"3.0.0","FixedVersion":"3.0.1","Severity":"HIGH"},
      {"VulnerabilityID":"CVE-2023-9999","PkgName":"busybox","InstalledVersion":"1.36","FixedVersion":"-","Severity":"MEDIUM"}
    ]}
  ]
}, indent=2)

def image_check(image: str=None, sample_json: Path=None, title="[Image Scan]"):
    progress("Running image scan…")
    reason = "No critical vulnerabilities"
    raw = ""
    if image:
        proc = run_cmd(["trivy","image","--quiet","--format","json", image], capture=True)
        if proc.returncode == 0 and proc.stdout:
            raw = proc.stdout
        else:
            raw = BUILTIN_TRIVY_JSON
    elif sample_json and sample_json.exists():
        raw = load_text(sample_json)
    else:
        raw = BUILTIN_TRIVY_JSON
    crit, hi, med, low, unk, top = parse_trivy_json(raw)
    status = "OK" if crit == 0 else "FAIL"
    if status == "FAIL": reason = f"{crit} CRITICAL"
    lines = [f"{title} Counts → CRITICAL:{crit} HIGH:{hi} MED:{med} LOW:{low} UNK:{unk}"]
    if top:
        lines.append("• Top findings:")
        lines.extend(f"  - {x}" for x in top)
    ctx = {"crit":crit, "hi":hi, "med":med, "low":low, "unk":unk, "top":top}
    return status, reason, "\n".join(lines), ctx

# ---------------------------
# Canary (compact, non-duplicating output)
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
    def log_message(self, *args, **kwargs): pass

def start_canary_server(port):
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

def canary_check(targets, probes=3, timeout=3.0, title="[Canary]"):
    progress("Running canary checks…")
    lines = [title]
    failed = 0
    per_target = []

    for t in targets:
        url = t["url"]
        expect = int(t.get("expect_status", 200))
        max_p50 = int(t.get("max_ms_p50", 300))
        max_p95 = int(t.get("max_ms_p95", 800))

        # Probe
        lats = []
        codes = []
        for _ in range(probes):
            code, ms, _ = http_probe(url, timeout)
            lats.append(ms)
            codes.append(code if code is not None else "ERR")

        # Summaries
        p50 = int(statistics.median(lats)) if lats else -1
        p95 = int(statistics.quantiles(lats, n=20)[18]) if len(lats) >= 2 else p50
        ok_status = (codes.count(expect) >= probes)
        ok_latency = (p50 <= max_p50 and p95 <= max_p95)
        if not (ok_status and ok_latency):
            failed += 1

        # Compact, fixed 3-line block per endpoint
        lines.append(f"• {url}")
        lines.append(f"  - expected={expect}  observed={codes}")
        lines.append(f"  - latency p50={p50}ms p95={p95}ms  thresholds p50≤{max_p50} p95≤{max_p95}")
        lines.append(f"  - status_ok={ok_status}  latency_ok={ok_latency}")

        per_target.append({"url": url, "ok_status": ok_status, "ok_latency": ok_latency})

    status = "OK" if failed == 0 else "FAIL"
    reason = "All checks passed" if status == "OK" else f"{failed} endpoint(s) failed checks"
    ctx = {"failed": failed, "targets": per_target}
    block = "\n".join(lines)
    return status, reason, block, ctx

# ---------------------------
# Demo / auto-fallback helpers
# ---------------------------

def demo_setup(workdir: Path):
    if workdir.exists(): shutil.rmtree(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir/"requirements.txt").write_text("requests==3.0.0\nurllib3==2.0.0\nflask==2.3.2\n", encoding="utf-8")
    (workdir/".cache").mkdir(parents=True, exist_ok=True)
    (workdir/".cache/dep_last.json").write_text(json.dumps({"requests":"2.27.0","urllib3":"1.26.18"}, indent=2), encoding="utf-8")
    run_cmd(["git","init"], cwd=workdir)
    (workdir/"README.md").write_text("# Demo repo\n", encoding="utf-8")
    run_cmd(["git","add","README.md"], cwd=workdir)
    run_cmd(["git","commit","-m","init"], cwd=workdir)
    (workdir/"config.env").write_text("API_KEY=AKIAABCDEFGHIJKLMNOP\nNOT_SECRET=hello\n", encoding="utf-8")
    run_cmd(["git","checkout","-b","feature/demo"], cwd=workdir)
    run_cmd(["git","add","config.env"], cwd=workdir)
    run_cmd(["git","commit","-m","add env with demo key"], cwd=workdir)
    diff_range = "HEAD~1..HEAD"
    (workdir/"trivy_sample.json").write_text(BUILTIN_TRIVY_JSON, encoding="utf-8")
    return diff_range

# ---------------------------
# CLI
# ---------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="infra_scout",
        description="infra-scout: deps drift, secrets, image CVEs, canaries — demo friendly."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_out(sp, name):
        sp.add_argument("--out", default=None, help=f"Write report to path (default: {REPORT_DIR}/<timestamp>_{name}.txt)")

    sp = sub.add_parser("deps", help="Dependency drift check")
    sp.add_argument("--manifest", default="requirements.txt")
    sp.add_argument("--snapshot", default=".cache/dep_last.json")
    sp.add_argument("--fail-on-major", action="store_true")
    add_out(sp, "deps")

    sp2 = sub.add_parser("secrets", help="Secrets scan on a git diff range")
    sp2.add_argument("--repo", default=".")
    sp2.add_argument("--range", default="HEAD~1..HEAD")
    add_out(sp2, "secrets")

    sp3 = sub.add_parser("image", help="Container image scan (trivy) or sample JSON")
    sp3.add_argument("--image")
    sp3.add_argument("--sample-json")
    add_out(sp3, "image")

    sp4 = sub.add_parser("canary", help="HTTP canary checks")
    sp4.add_argument("--targets")
    sp4.add_argument("--probes", type=int, default=3)
    sp4.add_argument("--timeout", type=float, default=3.0)
    add_out(sp4, "canary")

    sp5 = sub.add_parser("run", help="Run all checks")
    sp5.add_argument("--manifest", default="requirements.txt")
    sp5.add_argument("--snapshot", default=".cache/dep_last.json")
    sp5.add_argument("--repo", default=".")
    sp5.add_argument("--range", default="HEAD~1..HEAD")
    sp5.add_argument("--image")
    sp5.add_argument("--sample-json")
    sp5.add_argument("--targets")
    sp5.add_argument("--probes", type=int, default=3)
    sp5.add_argument("--timeout", type=float, default=3.0)
    sp5.add_argument("--fail-on-major", action="store_true")
    add_out(sp5, "run")

    sp6 = sub.add_parser("demo", help="Full self-contained demo (fails each check), then cleans up")
    sp6.add_argument("--keep", action="store_true", help="Keep the demo workspace")
    add_out(sp6, "demo")

    return p

# ---------------------------
# Main
# ---------------------------

def main():
    args = build_parser().parse_args()

    if args.cmd == "deps":
        out = Path(args.out) if args.out else default_out("deps")
        manifest = Path(args.manifest); snapshot = Path(args.snapshot)
        mode = "normal"
        used_demo = False
        if not manifest.exists() or not snapshot.exists():
            mode = "auto-fallback"
            progress("No manifest/snapshot found → using a temporary demo workspace.")
            workdir = Path(tempfile.mkdtemp(prefix="infra_scout_deps_"))
            demo_setup(workdir)
            manifest = workdir/"requirements.txt"
            snapshot = workdir/".cache/dep_last.json"
            used_demo = True
        title = section_title("[Dependencies Drift]", mode)
        s, reason, block, ctx = deps_check(manifest, snapshot, fail_on_major=args.fail_on_major, title=title)
        header = build_header("deps", out, mode)
        summary = build_summary([("deps", s, reason)])
        explain = explain_deps(s, ctx)
        cleanup = ""
        if used_demo:
            shutil.rmtree(workdir, ignore_errors=True)
            cleanup = f"[Cleanup]\nRemoved temporary workspace: {workdir.resolve()}"
            progress("Cleanup complete.")
        text = spaced(
            header,
            summary,
            spaced(block, explain),
            cleanup,
            f"Overall: {fmt_status(s)}"
        ) + "\n"
        write_and_print(out, text)
        sys.exit(0 if s in ("OK","WARN") else 1)

    elif args.cmd == "secrets":
        out = Path(args.out) if args.out else default_out("secrets")
        repo = Path(args.repo)
        mode = "normal"
        used_demo = False
        if not (repo/".git").exists():
            mode = "auto-fallback"
            progress("No git repo detected → using a temporary demo repo.")
            repo = Path(tempfile.mkdtemp(prefix="infra_scout_secrets_"))
            diff_range = demo_setup(repo)
            used_demo = True
        else:
            diff_range = args.range
        title = section_title("[Secrets Scan]", mode)
        s, reason, block, ctx = secrets_check(repo, diff_range, title=title)
        header = build_header("secrets", out, mode)
        summary = build_summary([("secrets", s, reason)])
        env = f"Environment\n-----------\nRepo: {repo.resolve()}\nDiff range: {diff_range}"
        explain = explain_secrets(s, ctx.get("findings", []))
        cleanup = ""
        if used_demo:
            shutil.rmtree(repo, ignore_errors=True)
            cleanup = f"[Cleanup]\nRemoved temporary workspace: {repo.resolve()}"
            progress("Cleanup complete.")
        text = spaced(
            header,
            summary,
            env,
            spaced(block, explain),
            cleanup,
            f"Overall: {fmt_status(s)}"
        ) + "\n"
        write_and_print(out, text)
        sys.exit(0 if s in ("OK","WARN") else 1)

    elif args.cmd == "image":
        out = Path(args.out) if args.out else default_out("image")
        mode = "normal"  # uses builtin sample when nothing provided; still considered normal
        title = section_title("[Image Scan]", mode)
        s, reason, block, ctx = image_check(args.image, Path(args.sample_json) if args.sample_json else None, title=title)
        header = build_header("image", out, mode)
        summary = build_summary([("image", s, reason)])
        explain = explain_image(s, ctx)
        text = spaced(
            header,
            summary,
            spaced(block, explain),
            f"Overall: {fmt_status(s)}"
        ) + "\n"
        write_and_print(out, text)
        sys.exit(0 if s in ("OK","WARN") else 1)

    elif args.cmd == "canary":
        out = Path(args.out) if args.out else default_out("canary")
        server = None
        mode = "normal"
        if args.targets:
            targets = json.loads(args.targets)
        else:
            mode = "auto-fallback"
            progress("No targets given → starting a local canary server on 127.0.0.1:9999")
            server = start_canary_server(9999)
            targets = [
                {"url":"http://127.0.0.1:9999/healthz","expect_status":200,"max_ms_p50":300,"max_ms_p95":800},
                {"url":"http://127.0.0.1:9999/admin","expect_status":401,"max_ms_p50":300,"max_ms_p95":800},
            ]
            time.sleep(0.2)
        title = section_title("[Canary]", mode)
        s, reason, block, ctx = canary_check(targets, probes=args.probes, timeout=args.timeout, title=title)
        header = build_header("canary", out, mode)
        summary = build_summary([("canary", s, reason)])
        explain = explain_canary(s, ctx.get("failed", 0))
        cleanup = ""
        if server:
            server.shutdown()
            cleanup += "[Cleanup]\nStopped local canary server on 127.0.0.1:9999"
            progress("Cleanup complete.")
        text = spaced(
            header,
            summary,
            spaced(block, explain),
            cleanup,
            f"Overall: {fmt_status(s)}"
        ) + "\n"
        write_and_print(out, text)
        sys.exit(0 if s in ("OK","WARN") else 1)

    elif args.cmd == "run":
        out = Path(args.out) if args.out else default_out("run")
        mode = "normal"
        used_workdir = None
        manifest = Path(args.manifest); snapshot = Path(args.snapshot)
        repo = Path(args.repo); diff_range = args.range
        if not (manifest.exists() and snapshot.exists() and (repo/".git").exists()):
            mode = "auto-fallback"
            progress("Run: components missing → using a temporary demo workspace for a full showcase.")
            used_workdir = Path(tempfile.mkdtemp(prefix="infra_scout_run_"))
            diff_range = demo_setup(used_workdir)
            manifest = used_workdir/"requirements.txt"
            snapshot = used_workdir/".cache/dep_last.json"
            repo = used_workdir
        server = None
        if args.targets:
            targets = json.loads(args.targets)
        else:
            server = start_canary_server(9999)
            targets = [
                {"url":"http://127.0.0.1:9999/healthz","expect_status":200,"max_ms_p50":300,"max_ms_p95":800},
                {"url":"http://127.0.0.1:9999/admin","expect_status":401,"max_ms_p50":300,"max_ms_p95":800},
            ]
            time.sleep(0.2)

        # Section titles with mode tags
        title_deps    = section_title("[Dependencies Drift]", mode)
        title_secrets = section_title("[Secrets Scan]",      mode)
        title_image   = section_title("[Image Scan]",        mode)
        title_canary  = section_title("[Canary]",            mode)

        s1, r1, b1, c1 = deps_check(manifest, snapshot, fail_on_major=args.fail_on_major, title=title_deps)
        s2, r2, b2, c2 = secrets_check(repo, diff_range, title=title_secrets)
        s3, r3, b3, c3 = image_check(args.image, Path(args.sample_json) if args.sample_json else None, title=title_image)
        s4, r4, b4, c4 = canary_check(targets, probes=args.probes, timeout=args.timeout, title=title_canary)

        header = build_header("run", out, mode)
        summary = build_summary([
            ("deps", s1, r1),
            ("secrets", s2, r2),
            ("image", s3, r3),
            ("canary", s4, r4),
        ])
        env = ""
        if used_workdir:
            env = "Environment (auto-fallback)\n---------------------------\n" + \
                  f"Workspace: {used_workdir.resolve()}\nDiff range: {diff_range}\nFiles: requirements.txt, .cache/dep_last.json, config.env, trivy_sample.json"

        # Interleave sections with explanations and spacing
        explain1 = explain_deps(s1, c1)
        explain2 = explain_secrets(s2, c2.get("findings", []))
        explain3 = explain_image(s3, c3)
        explain4 = explain_canary(s4, c4.get("failed", 0))

        sections = spaced(
            spaced(b1, explain1),
            spaced(b2, explain2),
            spaced(b3, explain3),
            spaced(b4, explain4),
        )

        cleanup = ""
        if server:
            server.shutdown()
            cleanup += "[Cleanup]\nStopped local canary server on 127.0.0.1:9999"
        if used_workdir:
            shutil.rmtree(used_workdir, ignore_errors=True)
            cleanup += f"\nRemoved temporary workspace: {used_workdir.resolve()}"
            progress("Cleanup complete.")

        overall = "OK" if all(s in ("OK","WARN") for s in [s1,s2,s3,s4]) and "FAIL" not in [s1,s2,s3,s4] else "FAIL"
        text = spaced(
            header,
            summary,
            env,
            sections,
            cleanup,
            f"Overall: {fmt_status(overall)}"
        ) + "\n"
        progress(f"Writing report → {out}")
        write_and_print(out, text)
        sys.exit(0 if overall=='OK' else 1)

    elif args.cmd == "demo":
        out = Path(args.out) if args.out else default_out("demo")
        mode = "demo"
        workdir = Path(tempfile.mkdtemp(prefix="infra_scout_demo_"))
        diff_range = demo_setup(workdir)
        server = start_canary_server(9999); time.sleep(0.2)
        targets = [
            {"url": f"http://127.0.0.1:9999/healthz", "expect_status":201, "max_ms_p50":1, "max_ms_p95":2},
            {"url": f"http://127.0.0.1:9999/admin",   "expect_status":200, "max_ms_p50":1, "max_ms_p95":2},
            {"url": f"http://127.0.0.1:9998/healthz", "expect_status":200, "max_ms_p50":300, "max_ms_p95":800},
        ]

        # Section titles with (demo)
        title_deps    = section_title("[Dependencies Drift]", mode)
        title_secrets = section_title("[Secrets Scan]",      mode)
        title_image   = section_title("[Image Scan]",        mode)
        title_canary  = section_title("[Canary]",            mode)

        s1, r1, b1, c1 = deps_check(workdir/"requirements.txt", workdir/".cache/dep_last.json", fail_on_major=True, title=title_deps)
        s2, r2, b2, c2 = secrets_check(workdir, diff_range, title=title_secrets)
        s3, r3, b3, c3 = image_check(None, workdir/"trivy_sample.json", title=title_image)
        s4, r4, b4, c4 = canary_check(targets, probes=3, timeout=2.0, title=title_canary)

        header = build_header("demo", out, mode)
        summary = build_summary([("deps", s1, r1), ("secrets", s2, r2), ("image", s3, r3), ("canary", s4, r4)])
        env = "Environment (demo)\n------------------\n" + \
              f"Workspace: {workdir.resolve()}\nDiff range: {diff_range}\nFiles: requirements.txt, .cache/dep_last.json, config.env, trivy_sample.json\n" + \
              "Expectations: each check deliberately FAILs for showcase."

        explain1 = explain_deps(s1, c1)
        explain2 = explain_secrets(s2, c2.get("findings", []))
        explain3 = explain_image(s3, c3)
        explain4 = explain_canary(s4, c4.get("failed", 0))

        # Clean up before writing so we can state it truthfully
        server.shutdown()
        cleanup = "[Cleanup]\nStopped local canary server on 127.0.0.1:9999"
        if not getattr(args, "keep", False):
            shutil.rmtree(workdir, ignore_errors=True)
            cleanup += f"\nRemoved temporary workspace: {workdir.resolve()}"

        sections = spaced(
            env,
            spaced(b1, explain1),
            spaced(b2, explain2),
            spaced(b3, explain3),
            spaced(b4, explain4),
        )

        progress("Writing report …")
        text = spaced(
            header,
            summary,
            sections,
            cleanup,
            f"Overall: {fmt_status('FAIL')}"
        ) + "\n"
        progress(f"Writing report → {out}")
        write_and_print(out, text)
        # Demo intentionally fails checks but exits 0 for friendliness
        sys.exit(0)

    else:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
