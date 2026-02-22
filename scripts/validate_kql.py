#!/usr/bin/env python3
"""
KQL Syntax Validator — Extraction Layer

Scans all runbook markdown files, extracts KQL code blocks,
writes them to a temp directory as individual .kql files,
then invokes the .NET KqlValidator for syntax checking.

Exit codes:
  0  All queries passed validation
  1  One or more queries have syntax errors
  2  Script-level error (missing files, bad arguments, etc.)
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# Regex: fenced code block with ```kql ... ```
KQL_BLOCK_RE = re.compile(
    r"^```kql\s*\n(.*?)^```",
    re.MULTILINE | re.DOTALL,
)


def extract_kql_blocks(md_path: Path) -> list[dict]:
    """Extract all KQL code blocks from a markdown file.

    Returns a list of dicts with keys:
      - file: relative path to the markdown file
      - block_index: 0-based index of the block within the file
      - line: 1-based line number where the block starts
      - code: the KQL source code
    """
    text = md_path.read_text(encoding="utf-8")
    blocks = []
    for i, match in enumerate(KQL_BLOCK_RE.finditer(text)):
        # Calculate the line number of the opening fence
        line_no = text[: match.start()].count("\n") + 1
        code = match.group(1)
        # Skip trivially empty blocks
        stripped = code.strip()
        if not stripped or stripped == "//":
            continue
        blocks.append(
            {
                "file": str(md_path),
                "block_index": i,
                "line": line_no,
                "code": code,
            }
        )
    return blocks


def scan_runbooks(docs_dir: Path) -> list[dict]:
    """Walk all runbook markdown files and extract KQL blocks."""
    runbook_dir = docs_dir / "runbooks"
    if not runbook_dir.is_dir():
        print(f"ERROR: Runbooks directory not found: {runbook_dir}", file=sys.stderr)
        sys.exit(2)

    all_blocks = []
    for md_file in sorted(runbook_dir.rglob("*.md")):
        # Skip index/gallery pages (no KQL queries)
        if md_file.name in ("index.md", "gallery.md"):
            continue
        blocks = extract_kql_blocks(md_file)
        all_blocks.extend(blocks)

    return all_blocks


def write_manifest(blocks: list[dict], out_dir: Path) -> Path:
    """Write extracted KQL blocks to individual .kql files and a manifest.

    Returns the path to the manifest JSON file.
    """
    manifest = []
    for idx, block in enumerate(blocks):
        kql_file = out_dir / f"query_{idx:04d}.kql"
        kql_file.write_text(block["code"], encoding="utf-8")
        manifest.append(
            {
                "id": idx,
                "file": block["file"],
                "block_index": block["block_index"],
                "line": block["line"],
                "kql_file": str(kql_file),
            }
        )

    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest_path


def run_validator(validator_path: Path, manifest_path: Path) -> dict:
    """Invoke the .NET KQL validator and return parsed results."""
    result = subprocess.run(
        ["dotnet", "run", "--project", str(validator_path), "--", str(manifest_path)],
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode == 2:
        print(f"ERROR: Validator crashed:\n{result.stderr}", file=sys.stderr)
        sys.exit(2)

    # Validator outputs JSON to stdout
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"ERROR: Could not parse validator output:\n{result.stdout}", file=sys.stderr)
        print(f"STDERR: {result.stderr}", file=sys.stderr)
        sys.exit(2)


def print_results(results: dict, blocks: list[dict]) -> int:
    """Print validation results in a human-readable format.

    Returns exit code: 0 if all passed, 1 if any failed.
    """
    errors = results.get("errors", [])
    total = results.get("total", len(blocks))
    passed = results.get("passed", total - len(errors))

    print(f"\n{'=' * 60}")
    print(f"KQL Validation Results: {passed}/{total} queries passed")
    print(f"{'=' * 60}")

    if not errors:
        print("\nAll KQL queries are syntactically valid.")
        return 0

    print(f"\n{len(errors)} query(ies) with syntax errors:\n")
    for err in errors:
        query_id = err.get("id", "?")
        source_file = err.get("file", "unknown")
        line = err.get("line", "?")
        message = err.get("message", "unknown error")
        # Make path relative for readability
        try:
            rel_path = Path(source_file).relative_to(Path.cwd())
        except ValueError:
            rel_path = source_file
        print(f"  FAIL  {rel_path}:{line}")
        print(f"        Block #{err.get('block_index', '?')}: {message}")
        print()

    return 1


def main():
    parser = argparse.ArgumentParser(description="KQL Syntax Validator for runbooks")
    parser.add_argument(
        "--docs-dir",
        type=Path,
        default=Path("docs"),
        help="Path to the docs directory (default: docs)",
    )
    parser.add_argument(
        "--validator",
        type=Path,
        default=Path("scripts/KqlValidator"),
        help="Path to the .NET KqlValidator project (default: scripts/KqlValidator)",
    )
    parser.add_argument(
        "--extract-only",
        action="store_true",
        help="Only extract KQL blocks (skip .NET validation)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory for extracted .kql files (default: temp dir)",
    )
    args = parser.parse_args()

    # Step 1: Extract KQL blocks
    print(f"Scanning runbooks in {args.docs_dir}/runbooks/ ...")
    blocks = scan_runbooks(args.docs_dir)
    print(f"Found {len(blocks)} KQL code blocks across runbook files.")

    if not blocks:
        print("No KQL blocks found. Nothing to validate.")
        return 0

    # Step 2: Write to temp directory
    if args.output_dir:
        out_dir = args.output_dir
        out_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = write_manifest(blocks, out_dir)
    else:
        with tempfile.TemporaryDirectory(prefix="kql_validate_") as tmp:
            out_dir = Path(tmp)
            manifest_path = write_manifest(blocks, out_dir)

            if args.extract_only:
                # Copy manifest to a persistent location for inspection
                print(f"\nExtracted {len(blocks)} queries to {out_dir}")
                print(f"Manifest: {manifest_path}")
                # Print summary
                files_seen = set()
                for b in blocks:
                    files_seen.add(b["file"])
                print(f"Source files: {len(files_seen)}")
                return 0

            # Step 3: Run .NET validator
            print(f"\nRunning KQL syntax validation...")
            results = run_validator(args.validator, manifest_path)

            # Step 4: Print results
            return print_results(results, blocks)

    # If output_dir was specified, still run validation
    if args.extract_only:
        print(f"\nExtracted {len(blocks)} queries to {out_dir}")
        print(f"Manifest: {manifest_path}")
        return 0

    print(f"\nRunning KQL syntax validation...")
    results = run_validator(args.validator, manifest_path)
    return print_results(results, blocks)


if __name__ == "__main__":
    sys.exit(main())
