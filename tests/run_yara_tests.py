"""Compile every YARA rule and check it against synthetic samples.

Fails if a rule does not compile, has no MITRE ATT&CK metadata, has no positive
test case, misses an expected sample, or matches a benign one.
"""

import argparse
import re
import sys
from pathlib import Path

import yaml
import yara_x

ROOT = Path(__file__).resolve().parent.parent
RULE_RE = re.compile(r"^rule\s+(\w+)\s*\{(.*?)^\}", re.MULTILINE | re.DOTALL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", default=str(ROOT / "rules/yara"))
    parser.add_argument("--cases", default=str(ROOT / "tests/yara_cases.yaml"))
    args = parser.parse_args()

    compiler = yara_x.Compiler()
    rule_meta = {}
    for path in sorted(Path(args.rules).glob("*.yar")):
        text = path.read_text()
        compiler.add_source(text, origin=str(path))
        for match in RULE_RE.finditer(text):
            name, body = match.group(1), match.group(2)
            rule_meta[name] = "mitre_technique_id" in body
    rules = compiler.build()
    cases = yaml.safe_load(Path(args.cases).read_text())
    failures = []

    print(f"YARA rules: {len(rule_meta)} | cases: {len(cases)}\n")
    for name, has_mitre in sorted(rule_meta.items()):
        if not has_mitre:
            failures.append(f"{name}: missing mitre_technique_id metadata")
        if not any(name in c.get("expect", []) for c in cases):
            failures.append(f"{name}: no positive test case")

    print(f"{'Result':<6}  {'Case':<48} Matched")
    for case in cases:
        matched = {r.identifier for r in rules.scan(case["content"].encode()).matching_rules}
        missing = set(case.get("expect", [])) - matched
        unwanted = set(case.get("forbid", [])) & matched
        if missing:
            failures.append(f"{case['name']}: expected {sorted(missing)} did not match")
        if unwanted:
            failures.append(f"{case['name']}: forbidden {sorted(unwanted)} matched")
        status = "PASS" if not missing and not unwanted else "FAIL"
        print(f"{status:<6}  {case['name']:<48} {sorted(matched)}")

    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("\nAll YARA tests passed.")


if __name__ == "__main__":
    main()
