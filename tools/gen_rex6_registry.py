#!/usr/bin/env python3
"""Generate the rule registry snapshot of the frozen Rex6 specification.

Rex6 is specified by the pages of mega-evm's `docs/spec/` whose front matter says `spec: Rex6`
(the EVM, system-contract and index pages; the upgrade pages under `upgrades/` carry no such
field and are summaries). Its text has no rule ids, so this script assigns them, and the
assignment is the definition docs/spec-identity.md states:

- A rule is a normative block of a page's `## Specification` section: a paragraph or a
  top-level list item that uses a BCP 14 keyword in capitals (MUST, MUST NOT, SHALL, SHOULD,
  REQUIRED, RECOMMENDED, MAY), together with the table or fenced block that directly follows
  it; a table that uses a keyword and follows no such block is a rule of its own.
- Its id is `REX6-<AREA>-<NNN>`: `AREA` is the page's code in `AREAS`, `NNN` the block's ordinal
  among the page's rules, from 001, in the order of the text.
- Its text is the block's lines, trailing whitespace removed, joined with `\\n`; its digest is
  the SHA-256 of that text's UTF-8 bytes, as for Satin.

Rex6 is frozen, so the ordinals are stable for this snapshot; the specification itself names no
ids, and a citation is resolved only against this registry. Every Rex6 rule is active: a frozen
spec retires nothing.

The pages are read from git objects at the commit. Output, as `tools/gen_registry.py` writes it
for Satin: `rules.json`, `sources.json`, `descriptor.json`.

Usage:
    tools/gen_rex6_registry.py <mega-evm-checkout> <commit> <out-dir> [--members <file>] [--check]

Standard library only. Requires `git` on PATH.
"""

from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gen_registry as satin  # noqa: E402  (the shared helpers: git, digests, rows, output)

ROOT = "docs/spec"
SPEC_NAME = "megaeth/Rex6"
REPOSITORY = "https://github.com/megaeth-labs/mega-evm"
BASE = "Optimism Isthmus (Ethereum Prague), as the Rex6 overview states"

# The area code of each page that states rules. A page with normative text and no code here is an
# error, so a new page cannot be skipped silently.
AREAS = {
    "evm/compute-gas.md": "COMP",
    "evm/contract-limits.md": "CLIM",
    "evm/dual-gas-model.md": "GAS",
    "evm/gas-detention.md": "DET",
    "evm/gas-forwarding.md": "FWD",
    "evm/overview.md": "EVM",
    "evm/precompiles.md": "PCMP",
    "evm/resource-accounting.md": "ACCT",
    "evm/resource-limits.md": "LIM",
    "evm/selfdestruct.md": "SD",
    "glossary.md": "GLOS",
    "hardfork-spec.md": "SPEC",
    "overview.md": "OVW",
    "system-contracts/high-precision-timestamp.md": "HPTS",
    "system-contracts/interception.md": "ICPT",
    "system-contracts/keyless-deploy.md": "KEY",
    "system-contracts/mega-access-control.md": "MAC",
    "system-contracts/mega-limit-control.md": "MLC",
    "system-contracts/oracle.md": "ORCL",
    "system-contracts/overview.md": "SYSC",
    "system-contracts/sequencer-registry.md": "REG",
    "system-contracts/system-tx.md": "MST",
}

KEYWORD = re.compile(r"\b(MUST|SHALL|SHOULD|REQUIRED|RECOMMENDED|MAY)\b")
LIST_ITEM = re.compile(r"^(?:[-*+] |\d+\. )")
FRONT_SPEC = re.compile(r"^spec:\s*(\S+)\s*$", re.M)


def blocks(lines: list[str]):
    """Yield (kind, lines, heading path) for each block of the `## Specification` section."""
    headings: list[tuple[int, str]] = []
    in_spec = False
    i = 0
    while i < len(lines):
        line = lines[i]
        heading = satin.HEADING.match(line)
        if heading:
            level = len(heading.group(1))
            if level <= 2:
                in_spec = level == 2 and heading.group(2).strip() == "Specification"
            headings = [h for h in headings if h[0] < level] + [(level, heading.group(2))]
            i += 1
            continue
        if not in_spec or not line.strip():
            i += 1
            continue
        start = i
        if line.lstrip().startswith("```"):
            kind = "fence"
            i += 1
            while i < len(lines) and not lines[i].lstrip().startswith("```"):
                i += 1
            i += 1
        elif line.startswith("|"):
            kind = "table"
            while i < len(lines) and lines[i].startswith("|"):
                i += 1
        else:
            kind = "item" if LIST_ITEM.match(line) else "paragraph"
            i += 1
            while i < len(lines):
                current = lines[i]
                if not current.strip() or satin.HEADING.match(current):
                    break
                if current.startswith("|") or current.lstrip().startswith("```"):
                    break
                if LIST_ITEM.match(current):  # a new top-level item
                    break
                i += 1
        path = " > ".join(h[1] for h in headings if h[0] > 1)
        yield kind, [b.rstrip() for b in lines[start:i]], path


def page_rules(text: str):
    """The rule blocks of one page, in order: (block lines, heading path)."""
    out: list[tuple[list[str], str]] = []
    pending: tuple[list[str], str] | None = None  # the last normative block, open for attachment
    for kind, block, path in blocks(text.split("\n")):
        normative = bool(KEYWORD.search("\n".join(block)))
        if kind in ("table", "fence") and pending is not None and pending[1] == path:
            pending[0].extend([""] + block)
            continue
        if pending is not None:
            out.append(pending)
            pending = None
        if normative:
            pending = (list(block), path)
    if pending is not None:
        out.append(pending)
    return out


def build(repo: str, commit: str, members: dict | None):
    full = satin.git(repo, "rev-parse", "--verify", f"{commit}^{{commit}}").decode().strip()
    committed = satin.git(repo, "show", "-s", "--format=%cI", full).decode().strip()
    names = satin.git(repo, "ls-tree", "-r", "--name-only", full, ROOT).decode().split("\n")
    errors: list[str] = []
    sources: dict[str, str] = {}
    rules: dict[str, dict] = {}
    for path in sorted(n for n in names if n.endswith(".md")):
        data = satin.git(repo, "show", f"{full}:{path}")
        text = data.decode("utf-8")
        front = FRONT_SPEC.search(text.split("\n---", 1)[0]) if text.startswith("---") else None
        if not front or front.group(1) != "Rex6":
            continue
        rel = path[len(ROOT) + 1:]
        sources[rel] = satin.sha256(data)
        found = page_rules(text)
        if found and rel not in AREAS:
            errors.append(f"{rel}: normative text but no area code")
            continue
        for n, (block, section) in enumerate(found, 1):
            rule_id = f"REX6-{AREAS[rel]}-{n:03d}"
            body = "\n".join(block)
            rows = satin.table_rows(block)
            rules[rule_id] = {
                "status": "active",
                "page": rel,
                "section": section,
                "rows": sorted(r for r in set(rows) if rows.count(r) == 1 and "/" not in r),
                "replacedBy": [],
                "text": body,
                "textDigest": satin.sha256(body.encode("utf-8")),
            }
    if not rules:
        errors.append(f"no Rex6 rules found under {ROOT} at {full}")
    source = {"repository": REPOSITORY, "commit": full, "committed": committed, "root": ROOT}
    registry = {
        "format": satin.REGISTRY_FORMAT,
        "schemaVersion": satin.SCHEMA_VERSION,
        "spec": SPEC_NAME,
        "source": source,
        "rules": dict(sorted(rules.items())),
    }
    source_list = {
        "format": "mega-spec-sources",
        "schemaVersion": satin.SCHEMA_VERSION,
        "source": source,
        "pages": dict(sorted(sources.items())),
    }
    descriptor = {
        "format": satin.DESCRIPTOR_FORMAT,
        "schemaVersion": satin.SCHEMA_VERSION,
        "name": SPEC_NAME,
        "maturity": "frozen",
        "base": BASE,
        "ruleIds": "assigned by tools/gen_rex6_registry.py: REX6-<page area>-<ordinal of the normative block>",
        "source": source,
        "registry": satin.sha256(satin.canonical(registry)),
        "sources": satin.sha256(satin.canonical(source_list)),
    }
    satin.add_members(descriptor, members, errors)
    return registry, source_list, descriptor, errors


def main(argv: list[str]) -> int:
    argv, members = satin.load_members(argv)
    args = [a for a in argv[1:] if not a.startswith("--")]
    check = "--check" in argv[1:]
    if len(args) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    repo, commit, out = args
    registry, source_list, descriptor, errors = build(repo, commit, members)
    if errors:
        for error in errors:
            print(f"gen_rex6_registry: {error}", file=sys.stderr)
        return 1
    files = {
        "rules.json": satin.pretty(registry),
        "sources.json": satin.pretty(source_list),
        "descriptor.json": satin.pretty(descriptor),
    }
    if check:
        stale = []
        for name, text in files.items():
            try:
                with open(os.path.join(out, name), encoding="utf-8") as f:
                    if f.read() != text:
                        stale.append(name)
            except FileNotFoundError:
                stale.append(name)
        if stale:
            print(f"gen_rex6_registry: out of date: {', '.join(stale)}", file=sys.stderr)
            return 1
        print(f"gen_rex6_registry: {out} is up to date")
        return 0
    os.makedirs(out, exist_ok=True)
    for name, text in files.items():
        with open(os.path.join(out, name), "w", encoding="utf-8") as f:
            f.write(text)
    areas: dict[str, int] = {}
    for rule_id in registry["rules"]:
        areas[rule_id.split("-")[1]] = areas.get(rule_id.split("-")[1], 0) + 1
    print(
        f"gen_rex6_registry: {len(registry['rules'])} ids in {len(areas)} areas -> {out}; "
        f"registry {descriptor['registry']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
