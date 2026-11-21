# kev-triage

**Which of these CVEs do I patch first?** `kev-triage` answers that question with data instead of gut feeling: CISA's Known Exploited Vulnerabilities catalog, FIRST's EPSS exploitation probability, and NVD's CVSS severity, folded into a `P0`–`P3` action priority with a remediation deadline.

- **Standard library only.** No `pip install` of dependencies, nothing to audit, works on an air-gapped runner once the cache is warm.
- **Degrades instead of dying.** A dead source falls back to its cached copy and says so in the output.
- **Machine-readable.** `--format json` for pipelines, `--fail-on P1` to break a build, `markdown` to paste into a ticket.

[![python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](pyproject.toml)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

---

## Why three sources

A CVSS score tells you how bad a bug *would* be, not whether anyone is using it. The two facts that change a patch order are:

| Question | Source | Why it matters |
| --- | --- | --- |
| Is it being exploited in the wild? | CISA KEV | A KEV listing is evidence, not a prediction. It also carries a federal remediation due date. |
| How likely is exploitation in the next 30 days? | FIRST EPSS | Separates the 4% of CVEs that get exploited from the 96% that never do — the reason a CVSS 9.8 with a 0.1% EPSS should not jump the queue. |
| How bad is it technically? | NVD CVSS | Tie-breaker and severity label, plus the vector for the report. |

`kev-triage` queries all three, in that order of authority.

## Install

```bash
pipx install git+https://github.com/dohyeontech/kev-triage   # or:
pip install git+https://github.com/dohyeontech/kev-triage
```

From a checkout, without installing anything (Python 3.10+):

```bash
git clone https://github.com/dohyeontech/kev-triage
cd kev-triage
python3 -m kev_triage check CVE-2026-123890
```

## Usage

### `check` — triage one or more CVE IDs

```console
$ python3 -m kev_triage check CVE-2026-123890 CVE-2026-40217 CVE-2021-44228
2026-11-21 13:46 UTC · KEV: live (catalog 2026.11.20) · EPSS: live (3 CVE(s)) · NVD: live (3/3 lookups ok)

PRI  CVE              KEV  DUE                  EPSS   CVSS  ASSET                    SIGNAL
P0   CVE-2021-44228   yes  2021-12-24 (-1793d)  100%   10    Apache Log4j2            KEV · due 1793d over · ransomware · EPSS 100% · CVSS 10
P0   CVE-2026-123890  yes  2026-11-23 (2d)      0.84%  9.8   Broadcom VMware vCenter  KEV · due 2d · EPSS 0.84% · CVSS 9.8
P1   CVE-2026-40217   yes  2026-12-02 (11d)     68.9%  8.8   BerriAI LiteLLM          KEV · due 11d · EPSS 68.9% · CVSS 8.8

P0 2 · P1 1 · P2 0 · P3 0 · KEV listed 3/3
```

`EPSS` is the 30-day exploitation probability, `DUE` is the CISA due date with the days remaining, `ASSET` is the vendor/product from KEV (or the NVD description when the CVE is not listed).

### `recent` — what CISA added this week

```console
$ python3 -m kev_triage recent --days 3
2026-11-21 13:46 UTC · KEV: cache, 0.0h old · 4 addition(s) in 3d

ADDED       CVE              VENDOR / PRODUCT         DUE         RANSOMWARE
2026-11-20  CVE-2026-76466   Cisco Expressway Series  2026-11-23  Unknown
2026-11-20  CVE-2026-129448  Apache Roller            2026-11-23  Unknown
2026-11-20  CVE-2026-123890  Broadcom VMware vCenter  2026-11-23  Unknown
2026-11-20  CVE-2025-42884   SAP NetWeaver            2026-11-23  Unknown
```

`--days N` is the look-back window, `--limit N` truncates the list. This is the command to put in a Monday-morning cron.

### `file` — triage whatever you already have

```console
$ python3 -m kev_triage file advisory.txt --no-nvd
$ sed -n '1,200p' scan.log | python3 -m kev_triage file -
$ python3 -m kev_triage file "backlog: CVE-2026-40217, CVE-2023-4863, CVE-2026-999999"
```

Every CVE ID in a file, on stdin (`-`), or in a literal string is extracted, de-duplicated, and triaged. Conversely, an argument that names an existing file is read as a file, so no quoting traps.

### Output formats

```bash
kev-triage check CVE-2026-40217 --format table      # default, aligned for terminals
kev-triage check CVE-2026-40217 --format json       # stable schema for automation
kev-triage check CVE-2026-40217 --format markdown   # table + action items for a ticket
```

JSON carries everything the table drops: KEV `required_action`, CWEs, the CVSS vector, publication dates, per-source status with cache age, and `data_gaps`.

### Exit codes and the CI gate

| Code | Meaning |
| --- | --- |
| `0` | Triage completed (including a degraded run where a source was unreachable) |
| `2` | No usable data: every source failed and nothing was cached |
| `3` | `--fail-on` threshold was met |
| `4` | Bad input: invalid CVE ID, no CVE ID found, invalid `--days` |

```bash
# Fail the build when a dependency audit turns up anything that needs patching now.
python3 -m kev_triage file audit.txt --fail-on P0 --quiet
```

`--fail-on P1` triggers on `P0` too; `--fail-on none` (the default) never gates.

## The priority model

`P0`–`P3` is a decision table, not a hidden score. Given `days_to_due` from KEV and the EPSS/CVSS thresholds:

| Priority | Rule | Action |
| --- | --- | --- |
| **P0** | In KEV **and** (due within 7 days, overdue, or known ransomware use) | Patch or mitigate within 72 hours; assume exploitation |
| **P1** | In KEV with a later due date, **or** not in KEV with EPSS ≥ 10% **and** CVSS ≥ 9.0 | Patch within 7 days, or apply the vendor mitigation now |
| **P2** | Not in KEV, with EPSS ≥ 1% **or** CVSS ≥ 7.0 | Next patch cycle (30 days) |
| **P3** | Everything else | Routine maintenance |

Deliberate consequences:

- **KEV beats EPSS.** EPSS answers "will it be exploited", KEV answers "it is". A KEV entry is `P1` even at an EPSS of 0.1%.
- **A high CVSS alone never reaches `P1`.** A 9.8 with a 0.02% EPSS is `P2` — that is the ranking triage exists to fix.
- **Unknown is not safe.** A CVE no source knows is `P3` with an explicit `no public data` signal and `data_gaps` in JSON. Absence of data is reported, never scored as low risk.
- **Thresholds are visible.** `EPSS_P1`, `EPSS_P2`, `CVSS_P1`, `CVSS_P2` and `DUE_SOON_DAYS` live at the top of `kev_triage/priority.py` if your organisation patches on a different clock.

Each finding also carries a one-line rationale (`KEV · due 2d · EPSS 0.84% · CVSS 9.8`) and the timestamped government deadline, so a priority can be defended in a change board.

## Data sources, caching and rate limits

| Source | Endpoint | Cache TTL | Notes |
| --- | --- | --- | --- |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | 6 h | One 1.8 MB JSON document; the whole catalog is fetched once per run and indexed in memory. |
| FIRST EPSS | `api.first.org/data/v1/epss` | 6 h | Batched, 100 CVEs per request. CVEs with no EPSS score are simply absent. |
| NVD CVE API 2.0 | `services.nvd.nist.gov/rest/json/cves/2.0` | 24 h | One request per CVE. Without a key NVD allows 5 requests / 30 s, so calls are spaced 6 s apart; set `NVD_API_KEY` and the spacing drops to 0.6 s. Use `--no-nvd` for fast KEV+EPSS triage. |

Cache lives in `~/.cache/kev-triage` (or `$XDG_CACHE_HOME/kev-triage`), one JSON file per key, written atomically.

- `--refresh` ignores fresh entries and refetches.
- `--offline` never touches the network; cached data is used and labelled `STALE` with its age.
- On a network failure the tool falls back to the cached copy automatically and prints `warning: kev stale (...)` to stderr; `--quiet` silences it.
- `kev-triage cache info | clear | path` inspects and empties the cache.

The header of every report states what actually answered — `KEV: live (catalog 2026.11.20) · EPSS: cache, 2.0h old · NVD: live (3/3 lookups ok)` — so a stale number can never pass as a fresh one.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `NVD_API_KEY` | unset | NVD API key; raises the rate limit and shortens the spacing |
| `KEV_TRIAGE_CACHE_DIR` | `~/.cache/kev-triage` | Cache location |
| `KEV_TRIAGE_TIMEOUT` | `30` | Per-request timeout in seconds |
| `KEV_TRIAGE_KEV_URL` / `KEV_TRIAGE_EPSS_URL` / `KEV_TRIAGE_NVD_URL` | upstream | Point at a mirror or a test server |
| `KEV_TRIAGE_NVD_MIN_INTERVAL` | `6` (`0.6` with a key) | Minimum seconds between NVD calls |
| `NO_COLOR` | unset | Disable ANSI colour (colour is already off when stdout is not a TTY) |

## Automation

Weekly KEV digest in CI, with the job failing when something is due:

```yaml
name: kev-digest
on:
  schedule: [{ cron: "0 0 * * 1" }]      # Mondays 09:00 KST
  workflow_dispatch:

jobs:
  digest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install git+https://github.com/dohyeontech/kev-triage
      - name: New KEV entries this week
        run: kev-triage recent --days 7
      - name: Gate on the audit output
        run: kev-triage file audit.txt --fail-on P1 --format markdown > triage.md
```

## Development

```bash
python3 -m unittest discover -v              # 111 tests (3 live ones skipped), no network, < 2 s
KEV_TRIAGE_LIVE=1 python3 -m unittest tests.test_live_smoke -v   # real CISA + EPSS + NVD
```

The suite runs the CLI end to end against a local HTTP server (`tests/support.py`) that serves recorded CISA/EPSS/NVD payloads, so caching, retry, stale-fallback and rate-limit paths are exercised without touching the internet. The live smoke test hits the real endpoints and is opt-in.

```
kev_triage/
  cli.py        argument parsing, exit codes, the --fail-on gate
  service.py    wiring: what each command fetches, how a finding is assembled
  sources.py    HTTP with retries, KEV/EPSS/NVD clients, cache-first logic
  priority.py   the P0-P3 decision table
  report.py     table / markdown / json renderers
  model.py      dataclasses shared by all of the above
  cache.py      TTL JSON cache with stale fallback
  cve.py        CVE ID normalisation and extraction
  config.py     environment-driven settings
```

## Limitations

- KEV only lists vulnerabilities with observed exploitation; a CVE missing from it is not evidence of safety, which is why the tool layers EPSS and CVSS instead of treating KEV as the answer.
- EPSS is a 30-day probability from a statistical model, not an asset-specific risk. Exposure, reachability and business impact belong to your own context.
- The NVD analyzer is slower than the CVEs are published; `NVD: no CVSS` is normal for very recent CVEs and is reported as a data gap rather than guessed.
- The priority rules are opinionated defaults following KEV's own remediation order. Tune the thresholds in `priority.py` to your patching clock.

---

MIT licensed. Built alongside the daily vulnerability briefings at [dohyeontech.github.io](https://dohyeontech.github.io/), where the free browser tools live in [`/tools/`](https://dohyeontech.github.io/tools/).
