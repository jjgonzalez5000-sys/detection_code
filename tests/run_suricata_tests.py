"""Run every Suricata test case and check which rules fire.

For each case in tests/cases.yaml, Suricata replays the capture against
rules/suricata/local.rules and the alerts in eve.json are compared with the
expected and forbidden SIDs. The run fails if:
  - a rule does not compile,
  - a rule has no MITRE ATT&CK technique metadata,
  - a rule has no positive test case,
  - an expected SID does not fire, or a forbidden SID fires.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULE_RE = re.compile(r"^\s*(alert|drop|reject|pass)\s.*\bsid:(\d+);", re.MULTILINE)


def parse_rules(path: Path):
    rules = {}
    for line in path.read_text().splitlines():
        m = RULE_RE.match(line)
        if not m:
            continue
        sid = int(m.group(2))
        msg = re.search(r'msg:"([^"]+)"', line)
        technique = re.search(r"mitre_technique_id\s+([T\d.]+)", line)
        rules[sid] = {
            "msg": msg.group(1) if msg else "",
            "technique": technique.group(1) if technique else None,
        }
    return rules


class Suricata:
    def __init__(self, engine: str, image: str):
        if engine == "auto":
            engine = "local" if shutil.which("suricata") else "docker"
        self.engine = engine
        self.image = image

    def run(self, args, log_dir: Path):
        if self.engine == "local":
            cmd = ["suricata", *args]
        else:
            # The image only lets root read its config, so run as root and hand the logs back to the caller.
            script = f'suricata "$@"; rc=$?; chown -R {os.getuid()}:{os.getgid()} "{log_dir}"; exit $rc'
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{ROOT}:{ROOT}", "-w", str(ROOT),
                "--entrypoint", "sh", self.image, "-c", script, "suricata", *args,
            ]
        return subprocess.run(cmd, capture_output=True, text=True)


def alerts_from(eve: Path):
    sids = set()
    if not eve.exists():
        return sids
    for line in eve.read_text().splitlines():
        event = json.loads(line)
        if event.get("event_type") == "alert":
            sids.add(event["alert"]["signature_id"])
    return sids


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rules", default=str(ROOT / "rules/suricata/local.rules"))
    parser.add_argument("--cases", default=str(ROOT / "tests/cases.yaml"))
    parser.add_argument("--pcaps", default=str(ROOT / "build/pcaps"))
    parser.add_argument("--out", default=str(ROOT / "build/out"))
    parser.add_argument("--engine", choices=["auto", "local", "docker"], default="auto")
    parser.add_argument("--image", default="jasonish/suricata:latest")
    args = parser.parse_args()

    rules_path, out_dir = Path(args.rules), Path(args.out)
    rules = parse_rules(rules_path)
    cases = yaml.safe_load(Path(args.cases).read_text())
    suricata = Suricata(args.engine, args.image)
    failures = []

    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True)

    print(f"Engine: {suricata.engine} | rules: {len(rules)} | cases: {len(cases)}\n")

    check_dir = out_dir / "_syntax"
    check_dir.mkdir()
    result = suricata.run(["-T", "-S", str(rules_path), "-l", str(check_dir)], check_dir)
    if result.returncode != 0:
        print(result.stdout + result.stderr)
        sys.exit("Rule syntax check failed")
    print("Syntax check: OK")

    for sid, rule in sorted(rules.items()):
        if not rule["technique"]:
            failures.append(f"sid {sid}: missing mitre_technique_id metadata")
        if not any(sid in c.get("expect", []) for c in cases):
            failures.append(f"sid {sid}: no positive test case")

    print(f"\n{'Result':<6}  {'Case':<36} {'Fired':<20} Detail")
    for i, case in enumerate(cases, 1):
        name, pcap = case["name"], Path(args.pcaps) / f"{case['pcap']}.pcap"
        log_dir = out_dir / f"{i:02d}_{case['pcap']}"
        log_dir.mkdir()
        result = suricata.run(["-r", str(pcap), "-S", str(rules_path), "-l", str(log_dir), "-k", "none"], log_dir)
        if result.returncode != 0:
            failures.append(f"{name}: suricata exited with {result.returncode}: {result.stderr.strip()[-300:]}")
            print(f"{'ERROR':<6}  {name:<36}")
            continue
        fired = alerts_from(log_dir / "eve.json")
        missing = set(case.get("expect", [])) - fired
        unwanted = set(case.get("forbid", [])) & fired
        ok = not missing and not unwanted
        detail = []
        if missing:
            detail.append(f"missing {sorted(missing)}")
            failures.append(f"{name}: expected {sorted(missing)} did not fire")
        if unwanted:
            detail.append(f"false positive {sorted(unwanted)}")
            failures.append(f"{name}: forbidden {sorted(unwanted)} fired")
        print(f"{'PASS' if ok else 'FAIL':<6}  {name:<36} {str(sorted(fired)):<20} {'; '.join(detail)}")

    print("\nCoverage (MITRE ATT&CK):")
    for sid, rule in sorted(rules.items()):
        print(f"  {sid}  {rule['technique'] or '-':<10} {rule['msg']}")

    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("\nAll Suricata tests passed.")


if __name__ == "__main__":
    main()
