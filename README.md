# infra-scout

**A tiny, demo-friendly CLI that runs four quick supply checks** (dependency drift, secrets in diffs, container image CVEs and HTTP canaries) and writes a timestamped **.txt** report to `infra-scan-reports/`.

* **Fast demo:** `python infra_scout.py demo`
  * Spins up a throwaway workspace and a tiny local HTTP server, deliberately **fails each check** (for showcase), writes a timestamped report and **cleans up** afterward.
* **Production-ish runs:** run each subcommand directly (or `run` to do all) against your own manifests/repos/targets.

## Why this script exists

When you hand someone a utility, you want them to **see it work immediately** without pointing it at live infra:

* **Demo-first:** Everything can self-provision for a believable dry run.
* **Plaintext reports:** Stakeholders can scan a single `.txt` file; no dashboards needed.
* **Neutral explanations:** Each section adds a short, context-free "What this means / Why you might see it / What to check next" block. These aren’t verdicts; they’re **decision aids** that translate a signal to action, without pretending to know your environment.

## Features

* **Deps drift:** Compares `requirements.txt` to a cached snapshot; highlights major/minor/patch changes.
* **Secrets in diffs:** Sscans a git diff range for high-entropy strings and common token patterns.
* **Image CVEs:** Wraps Trivy JSON output if available, otherwise uses a realistic built-in sample.
* **HTTP canaries:** Probes endpoints for status code and latency (p50/p95) against thresholds.
* **Modes in headers:** Section headers are tagged with `(demo)` or `(auto)` when using synthetic inputs.
* **Timestamped reports:** Saved under `infra-scan-reports/YYYYMMDD-HHMMSS_<cmd>.txt`.
* **Self-cleanup:** Demo/auto workspaces and local HTTP server are stopped/removed at the end.

## Quick start

```bash
python infra_scout.py demo
# Creates a temp workspace, runs all checks (failing by design for demo), writes a report, cleans up.
```

You’ll also see progress in the console:

```
[infra-scout] Running deps check…
[infra-scout] Running secrets scan…
[infra-scout] Running image scan…
[infra-scout] Running canary checks…
[infra-scout] Writing report → infra-scan-reports\YYYYMMDD-HHMMSS_demo.txt
```

## Installation

* **Python:** 3.10+
* **Optional:** [Trivy](https://github.com/aquasecurity/trivy) on PATH if you want real image scans (`image` falls back to a built-in sample JSON if Trivy is missing).
* No third-party Python deps. Just the single script.

## CLI overview

```
usage: infra_scout {deps|secrets|image|canary|run|demo} [options]
```

### Global output option (per subcommand)

* `--out <path>`: Write the report to a specific file. If omitted, writes to `infra-scan-reports/<timestamp>_<cmd>.txt`.

### Subcommands & arguments

#### 1) `deps` [dependency drift]

Checks differences between the current `requirements.txt` and a JSON snapshot.

*Args:*

* `--manifest <path>` (default `requirements.txt`)
* `--snapshot <path>` (default `.cache/dep_last.json`)
* `--fail-on-major` (flag): Mark as **FAIL** if any major version bump is detected (otherwise it’s a **WARN**).

*Behavior:*

* *Updates/creates the snapshot after the run.*
* *If manifest/snapshot are missing, runs in **auto-fallback** with a temporary demo workspace and labels the section `(auto)`.*

---

#### 2) `secrets` [secret-like content in a git diff]

Scans only the files touched in a diff range.

*Args:*

* `--repo <path>` (default `.`)
* `--range <git diff range>` (default `HEAD~1..HEAD`, e.g. "last commit")

  * *Example: `origin/main..HEAD`*

*Behavior:*

* *Looks for **high-entropy tokens** and common credential formats (AWS Access Key, Slack, GitHub, etc.) in allowed text-like extensions.*
* *If `--repo` isn’t a git repo, runs a **demo repo** in **auto-fallback** and labels the section `(auto)`.*

---

#### 3) `image` [container image CVEs (Trivy JSON)]

Parses Trivy JSON (real or sample) and counts CRITICAL/HIGH/MED/LOW/UNK. Shows top items.

*Args:*

* `--image <name:tag>` e.g. `alpine:latest`
* `--sample-json <path>`: Path to a saved Trivy JSON report

*Behavior:*

* *If Trivy is installed and `--image` is provided, it uses real Trivy output.*
* *If not, it uses the **built-in realistic sample** so the section is still meaningful.*
* *No special mode tag; sample usage is considered "normal" for report readability.*

---

### 4) `canary` [HTTP status & latency probes]

Pings one or more endpoints and checks:

- **Status:** observed codes vs expected
- **Latency:** p50/p95 vs thresholds

***Args:***

- `--targets`: accepts **either**
  - a JSON string literal, **or**
  - a path to a `.json` file that contains the list
- **Examples (string or file):**
   ```bash
   # JSON string
   python infra_scout.py canary --targets '[{"url":"https://example.com/health","expect_status":200,"max_ms_p50":300,"max_ms_p95":800}]'
   
   # JSON file
   python infra_scout.py canary --targets targets.json
   ````

**Schema per target:**

```json
{
  "url": "https://example.com/health",
  "expect_status": 200,
  "max_ms_p50": 300,
  "max_ms_p95": 800
}
```

* `--probes <int>` (default **3**) — how many times to ping each endpoint
* `--timeout <float>` seconds (default **3.0**) — per-request timeout

***Behavior:** If `--targets` is omitted, infra-scout starts a **local demo canary server** on `127.0.0.1:9999` in **auto-fallback** mode and labels the section `(auto)`.
  The server is **stopped** at the end of the run.*

---

#### 5) `run` [run all checks together]

Runs `deps`, `secrets`, `image` and `canary` in one go.

*Args:*

* `--manifest`, `--snapshot`, `--fail-on-major` (same as `deps`)
* `--repo`, `--range` (same as `secrets`)
* `--image`, `--sample-json` (same as `image`)
* `--targets`, `--probes`, `--timeout` (same as `canary`)

*Behavior: If some inputs are missing (no repo, no manifest, etc.), it **auto-provisions** a demo workspace/server and labels sections `(auto)`. Cleans up afterward.*

---

#### 6) `demo` [self-contained showcase (fails checks by design)]

No args by default. Optional: `--keep` to keep the temporary demo workspace (by default it’s removed).

*What it does:*

* *Creates a temp git repo with a fake secret in the diff, a deps drift scenario (including **major** bumps) and a sample Trivy JSON with a **CRITICAL** item.*
* *Starts a local HTTP server and probes three endpoints with **impossible** expectations so the canary section fails (to demonstrate failure reporting).*
* *Writes a full report, then **stops the server** and **removes** the temp workspace (unless `--keep`).*

## Output & report structure

* **Location:** `infra-scan-reports/` (automatically created)
* **Filename:** `YYYYMMDD-HHMMSS_<cmd>.txt`
* **Header:** timestamp, command, mode, CWD, Python/OS, report path
* **Summary table:** one row per check with status & short reason
* **Sections:** one per check. Each one includes:
  * A compact bullet list of **findings**
  * An **explanation** block: *"**What this means** / **Why you might see it** / **What to check next**"*

### Why explanations?

You don’t always run tools from the same context. The explanations explicitly avoid claiming root cause. They’re **guardrails** to move from a signal to next steps:

* **Deps drift:** Prompts you to validate intent and reproducibility (pin or adopt).
* **Secrets:** Differentiates between likely credential patterns and **false positives** (random IDs). Suggests key rotation & vaults.
* **Image CVEs:** Nudges toward patch/baseline refresh cycles.
* **Canary:** Ties failures to SLOs and asks whether expectations/auth/network are set correctly.

The philosophy: **Help a human decide quickly** without pretending the script knows the whole story.

## Examples

Run all checks with auto-fallback if inputs are missing:

```bash
python infra_scout.py run
```

Strict deps major bump policy:

```bash
python infra_scout.py deps --fail-on-major
```

Scan a specific diff:

```bash
python infra_scout.py secrets --repo . --range origin/main..HEAD
```

Image with real Trivy:

```bash
python infra_scout.py image --image alpine:3.18
```

Custom canaries:

```bash
python infra_scout.py canary --targets '[{"url":"https://example.com/health","expect_status":200,"max_ms_p50":250,"max_ms_p95":600}]'
```

Write to a custom file:

```bash
python infra_scout.py run --out reports/today.txt
```

## Exit codes

* **OK / WARN:** exit code **0**
* **FAIL:** non-zero exit (**1**)
* **`demo`:** always exits **0** (intentionally friendly for showcase)

## What each check actually looks for

* **Deps drift**
  * Parses `requirements.txt` into `{name → version}` (lightweight parsing).
  * Compares against `.cache/dep_last.json`.
  * Classifies changes as **major/minor/patch** using a semver-ish numeric diff (`x.y.z` best-effort).
  * Updates the snapshot after each run to "pin state".
  * **Rationale:** catching unexpected upgrades early prevents "works on my machine / broken in prod" drift.
* **Secrets in diffs**
  * Limits scope to files in the given **git diff range**.
  * Matches:
    * **High-entropy** tokens (e.g., Base64-ish or random-looking strings)
    * Common token **regexes** (AWS Access Key, Slack, GitHub, etc.)
  * **Rationale:** We rarely need to scan entire repos on every run. Diff scope keeps noise low and makes findings actionable.
* **Image CVEs**
  * Consumes **Trivy JSON**: Counts by severity and shows top 5 items with installed vs fixed versions.
  * Falls back to an embedded sample JSON so demos aren’t blocked by missing Trivy.
  * **Rationale:** You want a **quick signal**, not a full SCA audit, to inform whether a rebuild/bump is warranted.
* **HTTP canaries**
  * Probes N times (default 3), collects codes and latencies, computes **p50/p95**.
  * Compares against **expected status** and **latency thresholds**.
  * **Rationale:** It’s a rough  *"are we up and within SLO?"* pulse. The explanations remind you to check reachability/auth/SLO realism before assuming outage.

## Limitations & expectations

* Secrets scanning uses heuristics so **false positives are expected**. Treat it as *"investigate this line"*, **not** a *"breach"*!
* Deps parsing is intentionally light. Exotic specifiers may be treated as "changed/other".
* CVE output depends on Trivy freshness if you use `--image`. The built-in sample is illustrative.
* Canary thresholds are **yours to set**. Defaults are reasonable for demos, not production SLOs.

## Troubleshooting

* **"Not a git repo"** on `secrets`:
  * Either supply a real repo via `--repo` or rely on **auto-fallback** (it will create a demo repo and label the section `(auto)`).
* **No Trivy installed** on `image`:
  * Provide `--sample-json` or let it use the built-in sample. If you want live scans, install Trivy.
* **Canary timeouts**:
  * Increase `--timeout`, lower your thresholds or confirm network/firewall/SSL behavior.
