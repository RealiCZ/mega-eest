#!/usr/bin/env python3
"""Generate the rule registry snapshot of a specification commit.

The registry is the offline answer to "what does a rule id in a fixture's `rules` mean": every
rule id of the specification section at one commit, whether it is active or retired at that
commit, the page and section that state it, the names of its table rows, the rule's text and the
SHA-256 digest of that text. Fixtures cite rules by id; a consumer resolves a citation against
the registry bundled with the fixture's spec descriptor, never against a live checkout.

The script reads the pages from git objects at the pinned commit (`git show <commit>:<path>`),
so the working tree of the checkout does not matter. It writes three files into the output
directory:

    rules.json        the registry
    sources.json      every page read, with the SHA-256 digest of its bytes
    descriptor.json   the spec descriptor that fixtures reference by digest

The rule text and its boundaries are defined in docs/rule-registry.md; this script is the
reference implementation of that definition. The script fails, writing nothing, when an id is
stated twice, when the ids it finds differ from the specification's own generated index
(`rules.md`), or when the commit does not resolve.

Usage:
    tools/gen_registry.py <spec-checkout> <commit> <out-dir>
    tools/gen_registry.py <spec-checkout> <commit> <out-dir> --check

Standard library only. Requires `git` on PATH.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys

SECTION = "docs/spec/satin"
INDEX_PAGE = "rules.md"
STUB = "This page is a stub."
SPEC_NAME = "megaeth/Satin"
REPOSITORY = "https://github.com/RealiCZ/mega-evm-satin-spec"
REGISTRY_FORMAT = "mega-rule-registry"
DESCRIPTOR_FORMAT = "mega-spec-descriptor"
SCHEMA_VERSION = "1.0"

RULE = re.compile(r"^\s*(?:[-*] |\d+\. )?`([A-Z][A-Z0-9]*-[A-Z][A-Z0-9]*-\d{3})`\s+(\S.*)$")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
MD_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
INDEX_ID = re.compile(r"`([A-Z][A-Z0-9]*-[A-Z][A-Z0-9]*-\d{3})`")
REPLACED = re.compile(r"(?:replaced by|merged into) ((?:`[A-Z][A-Z0-9]*-[A-Z][A-Z0-9]*-\d{3}`(?:,\s*|\s+and\s+)?)+)")


def git(repo: str, *args: str) -> bytes:
    return subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True).stdout


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical(value) -> bytes:
    """Canonical JSON bytes (docs/canonical-json.md): sorted keys, no whitespace, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def row_name(cell: str) -> str:
    return MD_LINK.sub(r"\1", cell).replace("`", "").strip()


def rule_blocks(lines: list[str]):
    """Yield (rule_id, start_line_index, block_lines, heading_path) for every rule on a page."""
    headings: list[tuple[int, str]] = []
    in_fence = False
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            i += 1
            continue
        if in_fence:
            i += 1
            continue
        heading = HEADING.match(line)
        if heading:
            level = len(heading.group(1))
            headings = [h for h in headings if h[0] < level] + [(level, heading.group(2))]
            i += 1
            continue
        match = RULE.match(line)
        if not match:
            i += 1
            continue
        block = [line]
        j = i + 1
        fence = False
        while j < len(lines):
            current = lines[j]
            if fence:
                block.append(current)
                if current.lstrip().startswith("```"):
                    fence = False
                j += 1
                continue
            if current.lstrip().startswith("```"):
                fence = True
                block.append(current)
                j += 1
                continue
            if HEADING.match(current) or RULE.match(current):
                break
            if current.strip() and not current[0].isspace() and not current.startswith("|"):
                break
            block.append(current)
            j += 1
        block = [b.rstrip() for b in block]
        while block and not block[-1]:
            block.pop()
        path = " > ".join(h[1] for h in headings if h[0] > 1)
        yield match.group(1), match.group(2), block, path
        i = j


def table_rows(block: list[str]) -> list[str]:
    """First cells of the body rows of every table inside a rule block."""
    rows: list[str] = []
    header_seen = False
    for line in block:
        stripped = line.strip()
        if not stripped.startswith("|"):
            header_seen = False
            continue
        cells = stripped.strip("|").split("|")
        first = cells[0].strip()
        if not header_seen:
            header_seen = True  # the header row
            continue
        if re.fullmatch(r":?-{3,}:?", first):
            continue
        rows.append(row_name(first))
    return rows


def build(repo: str, commit: str):
    full = git(repo, "rev-parse", "--verify", f"{commit}^{{commit}}").decode().strip()
    committed = git(repo, "show", "-s", "--format=%cI", full).decode().strip()
    names = git(repo, "ls-tree", "-r", "--name-only", full, SECTION).decode().split("\n")
    pages = sorted(n for n in names if n.endswith(".md"))
    sources: dict[str, str] = {}
    rules: dict[str, dict] = {}
    errors: list[str] = []
    index_ids: set[str] = set()
    for path in pages:
        data = git(repo, "show", f"{full}:{path}")
        rel = path[len(SECTION) + 1:]
        sources[rel] = sha256(data)
        text = data.decode("utf-8")
        if rel == INDEX_PAGE:
            index_ids = set(INDEX_ID.findall(text))
            continue
        if STUB in text:
            continue
        lines = text.split("\n")
        for rule_id, first, block, section in rule_blocks(lines):
            if rule_id in rules:
                errors.append(f"{rule_id} is stated twice ({rules[rule_id]['page']} and {rel})")
                continue
            retired = "retired" in section.lower() or first.lower().startswith("retired")
            body = "\n".join(block)
            rows = table_rows(block)
            citable = sorted(r for r in set(rows) if rows.count(r) == 1 and "/" not in r)
            replaced: list[str] = []
            for group in REPLACED.findall(body):
                replaced += INDEX_ID.findall(group)
            rules[rule_id] = {
                "status": "retired" if retired else "active",
                "page": rel,
                "section": section,
                "rows": citable,
                "replacedBy": sorted(set(replaced)),
                "text": body,
                "textDigest": sha256(body.encode("utf-8")),
            }
    found = set(rules)
    if index_ids and found != index_ids:
        errors.append(
            "ids differ from the specification's own index: "
            f"missing {sorted(index_ids - found)}, extra {sorted(found - index_ids)}"
        )
    if not index_ids:
        errors.append(f"{SECTION}/{INDEX_PAGE} not found at {full}")
    source = {"repository": REPOSITORY, "commit": full, "committed": committed, "root": SECTION}
    registry = {
        "format": REGISTRY_FORMAT,
        "schemaVersion": SCHEMA_VERSION,
        "spec": SPEC_NAME,
        "source": source,
        "rules": dict(sorted(rules.items())),
    }
    source_list = {
        "format": "mega-spec-sources",
        "schemaVersion": SCHEMA_VERSION,
        "source": source,
        "pages": dict(sorted(sources.items())),
    }
    descriptor = {
        "format": DESCRIPTOR_FORMAT,
        "schemaVersion": SCHEMA_VERSION,
        "name": SPEC_NAME,
        "maturity": "unstable",
        "base": "Optimism Karst (Ethereum Osaka), as SATIN-BASE-001 states",
        "source": source,
        "registry": sha256(canonical(registry)),
        "sources": sha256(canonical(source_list)),
    }
    return registry, source_list, descriptor, errors


def pretty(value) -> str:
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    check = "--check" in argv[1:]
    if len(args) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    repo, commit, out = args
    registry, source_list, descriptor, errors = build(repo, commit)
    if errors:
        for error in errors:
            print(f"gen_registry: {error}", file=sys.stderr)
        return 1
    files = {
        "rules.json": pretty(registry),
        "sources.json": pretty(source_list),
        "descriptor.json": pretty(descriptor),
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
            print(f"gen_registry: out of date: {', '.join(stale)}", file=sys.stderr)
            return 1
        print(f"gen_registry: {out} is up to date")
        return 0
    os.makedirs(out, exist_ok=True)
    for name, text in files.items():
        with open(os.path.join(out, name), "w", encoding="utf-8") as f:
            f.write(text)
    active = sum(1 for r in registry["rules"].values() if r["status"] == "active")
    print(
        f"gen_registry: {len(registry['rules'])} ids ({active} active, "
        f"{len(registry['rules']) - active} retired) -> {out}; registry {descriptor['registry']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
