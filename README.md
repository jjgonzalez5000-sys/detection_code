# detection_code

[![detections](https://github.com/jjgonzalez5000-sys/detection_code/actions/workflows/ci.yml/badge.svg)](https://github.com/jjgonzalez5000-sys/detection_code/actions/workflows/ci.yml)

Detection-as-code for network (Suricata) and file (YARA) detections: every rule is versioned, mapped to MITRE ATT&CK, and tested in CI against traffic or samples that must trigger it and benign look-alikes that must not.

## Why

A detection that has never been tested is a guess. Mapping rules to ATT&CK techniques says what you *intend* to cover; it does not say what actually fires. In practice the gap is large: rules break when an engine is upgraded, a field name changes, or a "small" tuning change silently kills a match.

This repository treats detections like code:

- **Every rule has a positive test.** CI fails if a rule has no capture or sample that is expected to trigger it.
- **Every rule has negative tests.** Benign look-alikes guard against false positives.
- **Every rule carries ATT&CK metadata.** CI fails if `mitre_technique_id` is missing, so coverage reports stay honest.
- **Test data is generated, not committed.** Captures are built deterministically with Scapy and YARA samples are synthetic, so the repo stays small, reviewable, and free of real malware.

## Layout

```
rules/
  suricata/local.rules      Suricata rules (SID range 9000000-9000999)
  yara/*.yar                YARA rules
tools/
  gen_pcaps.py              Builds a deterministic pcap per test scenario
tests/
  cases.yaml                Suricata cases: pcap -> expected / forbidden SIDs
  run_suricata_tests.py     Syntax check, coverage checks, replays every pcap
  yara_cases.yaml           YARA cases: synthetic sample -> expected / forbidden rules
  run_yara_tests.py         Compiles rules, coverage checks, scans every sample
.github/workflows/ci.yml    Runs everything on each push and pull request
```

## Current coverage

| Engine | ID | Detection | ATT&CK |
|---|---|---|---|
| Suricata | 9000001 | Cloud instance metadata (IMDS) IAM credential path requested | T1552.005 |
| Suricata | 9000002 | DNS tunneling: unusually long query name | T1071.004 |
| Suricata | 9000003 | Stratum mining protocol subscribe (cryptojacking) | T1496 |
| Suricata | 9000004 | Webshell command execution in PHP request | T1505.003 |
| YARA | DAC_PHP_Webshell_Command_Exec | PHP evaluating decoded input or passing request parameters to OS commands | T1505.003 |
| YARA | DAC_PowerShell_EncodedCommand | PowerShell launched with a long Base64 `-EncodedCommand` | T1059.001 |

## Running locally

Requirements: Python 3.10+, and either Suricata installed locally or Docker (the runner uses the `jasonish/suricata` image automatically when `suricata` is not on the path).

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
make test                 # pcaps + Suricata tests + YARA tests
make test ENGINE=docker   # force Docker for Suricata
```

Example output:

```
Result  Case                                 Fired                Detail
PASS    IMDS IAM credential request          [9000001]
PASS    IMDS benign metadata request         []
PASS    DNS tunneling via long TXT query     [9000002]
PASS    Normal DNS query                     []
...
All Suricata tests passed.
```

## Adding a detection

1. Add the rule to `rules/suricata/local.rules` (next free SID) or a new `.yar` file in `rules/yara/`, including `mitre_technique_id` metadata.
2. Add a scenario to `tools/gen_pcaps.py` (Suricata) that reproduces the behaviour, plus at least one benign look-alike.
3. Add the cases to `tests/cases.yaml` or `tests/yara_cases.yaml` with `expect` and `forbid`.
4. Run `make test`. CI enforces the same checks on the pull request.

## Roadmap

- Sigma rules with conversion and tests against sample log events
- Coverage report generated from rule metadata (ATT&CK Navigator layer)
- Performance checks: rule profiling on larger captures

## License

MIT
