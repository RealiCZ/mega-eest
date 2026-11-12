#!/usr/bin/env python3
"""Generate the reverse lookup from slice rule citations to cases.

Usage: python3 -I tools/rule_index.py [--check]

Only cases selected by slice/index.json participate. Each citation resolves against its
case's own registry. The newest source commit timestamp among referenced Satin snapshots
selects the registry for the uncited-rule list. No Git checkout or network is needed.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def digest(value: dict) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass
class Snapshot:
    directory: Path
    descriptor: dict
    rules: dict

    def committed(self) -> datetime:
        date = datetime.fromisoformat(self.descriptor["source"]["committed"].replace("Z", "+00:00"))
        if date.tzinfo is None:
            raise ValueError(f"{self.directory.name}: source commit time has no timezone")
        return date


@dataclass
class Case:
    case_id: str
    path: Path
    status: str
    snapshot: Snapshot
    citations: list[str]


def read_cases(root: Path) -> list[Case]:
    snapshots = {}
    for path in sorted((root / "specs").glob("*/descriptor.json")):
        descriptor = load(path)
        snapshots.setdefault(digest(descriptor), (path.parent, descriptor))
    resolved = {}
    index = load(root / "slice/index.json")
    cases = []
    seen = set()
    for group, status in (("cases", "gating"), ("quarantine", "quarantined")):
        for entry in index[group]:
            path = root / "slice" / entry["file"]
            document = load(path)
            case_id = document["caseId"]
            if case_id != entry["caseId"] or case_id in seen:
                raise ValueError(f"{entry['file']}: mismatched or duplicate caseId {case_id}")
            seen.add(case_id)
            citations = sorted(document["rules"])
            if citations != sorted(entry["rules"]):
                raise ValueError(f"{case_id}: rules differ between index and case")
            spec = document["specRef"]
            if spec != entry.get("spec", index["spec"]):
                raise ValueError(f"{case_id}: spec differs between index and case")
            key = spec["descriptor"]
            if key not in resolved:
                if key not in snapshots:
                    raise ValueError(f"{case_id}: no bundled descriptor for {key}")
                directory, descriptor = snapshots[key]
                registry = load(directory / "rules.json")
                if digest(registry) != descriptor["registry"]:
                    raise ValueError(f"{directory.name}: registry digest differs from descriptor")
                resolved[key] = Snapshot(directory, descriptor, registry["rules"])
            snapshot = resolved[key]
            if spec["name"] != snapshot.descriptor["name"]:
                raise ValueError(f"{case_id}: spec name differs from descriptor")
            for citation in citations:
                rule_id, slash, row = citation.partition("/")
                rule = snapshot.rules.get(rule_id)
                if rule is None or rule["status"] != "active":
                    raise ValueError(f"{case_id}: {citation} is not active in {snapshot.directory.name}")
                if slash and row not in rule["rows"]:
                    raise ValueError(f"{case_id}: unknown row {citation} in {snapshot.directory.name}")
            cases.append(Case(case_id, path, status, snapshot, citations))
    return sorted(cases, key=lambda case: case.case_id)


def render(root: Path) -> tuple[str, int, int]:
    cases = read_cases(root)
    snapshots = {case.snapshot.directory.name: case.snapshot for case in cases}
    satin = [s for s in snapshots.values() if s.descriptor["name"] == "megaeth/Satin"]
    if not satin:
        raise ValueError("no indexed case references a Satin registry")
    # The path breaks ties between snapshots committed at the same instant, independently of
    # filesystem timestamps and the order of cases or directories.
    newest = max(satin, key=lambda s: (s.committed(), s.directory.name))
    by_rule = defaultdict(list)
    for case in cases:
        grouped = defaultdict(list)
        for citation in case.citations:
            grouped[citation.split("/", 1)[0]].append(citation)
        for rule_id, citations in grouped.items():
            by_rule[rule_id].append((case, citations))
    uncited = sorted(set(newest.rules) - by_rule.keys())
    active = sum(newest.rules[r]["status"] == "active" for r in uncited)
    gating = sum(case.status == "gating" for case in cases)
    source = newest.descriptor["source"]
    lines = [
        "# Rule-to-case index", "",
        "Generated by `python3 -I tools/rule_index.py` from [the slice index](../slice/index.json)",
        "and its gating and quarantined case files. Do not edit this file by hand.", "",
        f"Uncited-rule registry: [{newest.directory.name}], source commit `{source['commit']}`",
        f"(committed `{source['committed']}`). This is the newest source commit timestamp among",
        "the Satin snapshots these cases reference; equal timestamps are ordered by snapshot name.", "",
        f"Cases: **{len(cases)}** ({gating} gating, {len(cases) - gating} quarantined).",
        f"Cited rule IDs: **{len(by_rule)}**. Uncited rule IDs in that registry: **{len(uncited)}**",
        f"({active} active, {len(uncited) - active} retired).", "",
        "Each case resolves its citations against its own pinned registry, linked in its row.",
        "The citation column preserves row qualifiers; an unqualified citation is shown as `unqualified`.",
        "This is a citation lookup, not approval or executed-rule coverage. Older citations do not",
        "establish coverage of a newer rule's wording. Deliberately wrong negative cases are excluded.", "",
        "## Cited rules", "",
    ]
    for rule_id, references in sorted(by_rule.items()):
        lines += [f"### {rule_id}", "", "| Case | Status | Citation | Registry |",
                  "| --- | --- | --- | --- |"]
        for case, citations in references:
            labels = ["unqualified" if c == rule_id else "`" + c.replace("|", r"\|") + "`" for c in citations]
            lines.append(f"| [{case.case_id}] | {case.status} | {'; '.join(labels)} | [{case.snapshot.directory.name}] |")
        lines.append("")
    lines += [
        "## Rules with no citing case", "",
        f"These IDs from [{newest.directory.name}] are cited by neither gating nor quarantined cases.",
        "Retired rules are labeled separately from active rules; their absence is not an active-rule gap.", "",
        "| Rule | Status | Specification page at the pinned commit |", "| --- | --- | --- |",
    ]
    for rule_id in uncited:
        rule = newest.rules[rule_id]
        url = f"{source['repository'].rstrip('/')}/blob/{source['commit']}/{source['root']}/{quote(rule['page'], safe='/')}"
        lines.append(f"| `{rule_id}` | {rule['status']} | [{rule['page']}]({url}) |")
    lines.append("")
    for case in cases:
        lines.append(f"[{case.case_id}]: ../{quote(case.path.relative_to(root).as_posix(), safe='/')}")
    for name, snapshot in sorted(snapshots.items()):
        path = (snapshot.directory / "rules.json").relative_to(root).as_posix()
        lines.append(f"[{name}]: ../{quote(path, safe='/')}")
    return "\n".join(lines) + "\n", len(by_rule), len(uncited)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if docs/rule-index.md differs")
    args = parser.parse_args()
    try:
        text, cited, uncited = render(ROOT)
        output = ROOT / "docs/rule-index.md"
        expected = text.encode("utf-8")
        if args.check:
            if not output.is_file() or output.read_bytes() != expected:
                print("rule_index: docs/rule-index.md is stale; run python3 -I tools/rule_index.py", file=sys.stderr)
                return 1
        else:
            output.write_bytes(expected)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"rule_index: {error}", file=sys.stderr)
        return 1
    action = "checked" if args.check else "wrote"
    print(f"rule_index: {action} docs/rule-index.md; {cited} rules cited, {uncited} rules uncited")
    return 0


if __name__ == "__main__":
    sys.exit(main())
