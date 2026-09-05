from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import secrets
import shutil
import sys
from datetime import datetime
from pathlib import Path


APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "scanner_data"
SIGNATURE_FILE = DATA_DIR / "signatures.json"
BASELINE_FILE = DATA_DIR / "baseline.json"
QUARANTINE_DIR = APP_DIR / "quarantine"
REPORT_DIR = APP_DIR / "reports"

CHUNK_SIZE = 1024 * 1024
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "quarantine", "reports"}
RISK_EXTENSIONS = {".exe", ".bat", ".cmd", ".scr", ".ps1", ".vbs", ".js", ".jar", ".dll"}
DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt"}
SCRIPT_WORDS = [b"powershell", b"encodedcommand", b"cmd.exe", b"wscript", b"mshta", b"autorun.inf"]


def stamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def file_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_folders() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    QUARANTINE_DIR.mkdir(exist_ok=True)
    REPORT_DIR.mkdir(exist_ok=True)


def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def save_json(path: Path, data) -> None:
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_signatures() -> dict:
    data = load_json(SIGNATURE_FILE, {"version": "1.0", "sha256": {}})
    data.setdefault("sha256", {})
    return data


def iter_files(target: Path):
    target = target.resolve()
    if target.is_file():
        yield target
        return

    for path in target.rglob("*"):
        if path.is_dir():
            continue
        parts = {p.lower() for p in path.parts}
        if parts.intersection(SKIP_DIRS):
            continue
        yield path


def hash_file(path: Path) -> dict:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    total = 0

    with path.open("rb") as handle:
        while True:
            block = handle.read(CHUNK_SIZE)
            if not block:
                break
            sha256.update(block)
            md5.update(block)
            total += len(block)

    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest(), "bytes": total}


def read_start(path: Path, limit: int = 65536) -> bytes:
    with path.open("rb") as handle:
        return handle.read(limit)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    result = 0.0
    length = len(data)
    for count in counts:
        if count:
            probability = count / length
            result -= probability * math.log2(probability)
    return round(result, 3)


def has_pe_header(path: Path) -> bool:
    try:
        return read_start(path, 2) == b"MZ"
    except OSError:
        return False


def find_heuristics(path: Path, size: int) -> list[str]:
    reasons = []
    suffixes = [s.lower() for s in path.suffixes]
    final_suffix = suffixes[-1] if suffixes else ""

    if len(suffixes) >= 2 and suffixes[-2] in DOCUMENT_EXTENSIONS and final_suffix in RISK_EXTENSIONS:
        reasons.append("double extension name")

    if has_pe_header(path) and final_suffix not in {".exe", ".dll", ".scr"}:
        reasons.append("executable header with unusual extension")

    try:
        start = read_start(path)
    except OSError:
        return reasons

    lowered = start.lower()
    found_words = [word.decode("ascii") for word in SCRIPT_WORDS if word in lowered]
    if found_words and final_suffix in {".txt", ".js", ".vbs", ".bat", ".cmd", ".ps1", ""}:
        reasons.append("script keywords: " + ", ".join(found_words[:3]))

    entropy = shannon_entropy(start)
    if size > 4096 and entropy >= 7.4 and final_suffix in RISK_EXTENSIONS:
        reasons.append(f"high entropy ({entropy})")

    return reasons


def make_finding(path: Path, signatures: dict) -> dict:
    hashes = hash_file(path)
    sha = hashes["sha256"]
    sig = signatures.get("sha256", {}).get(sha)
    reasons = []
    status = "clean"
    threat = ""
    severity = ""

    if sig:
        status = "malicious"
        threat = sig.get("name", "Known signature")
        severity = sig.get("severity", "high")
        reasons.append("sha256 signature match")

    heuristic_reasons = find_heuristics(path, hashes["bytes"])
    if heuristic_reasons and status == "clean":
        status = "suspicious"
        severity = "medium"
    reasons.extend(heuristic_reasons)

    return {
        "path": str(path),
        "file_name": path.name,
        "status": status,
        "threat": threat,
        "severity": severity,
        "reasons": reasons,
        "sha256": sha,
        "md5": hashes["md5"],
        "bytes": hashes["bytes"],
        "checked_at": stamp(),
    }


def load_quarantine_index() -> dict:
    return load_json(QUARANTINE_DIR / "index.json", {})


def save_quarantine_index(index: dict) -> None:
    save_json(QUARANTINE_DIR / "index.json", index)


def quarantine_file(path: Path, finding: dict) -> str:
    ensure_folders()
    index = load_quarantine_index()
    qid = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(3)}"
    stored = QUARANTINE_DIR / f"{qid}.quar"

    shutil.move(str(path), stored)
    index[qid] = {
        "original_path": str(path),
        "stored_path": str(stored),
        "file_name": path.name,
        "status": finding["status"],
        "threat": finding["threat"],
        "reasons": finding["reasons"],
        "sha256": finding["sha256"],
        "quarantined_at": stamp(),
    }
    save_quarantine_index(index)
    return qid


def save_scan_report(target: Path, findings: list[dict], csv_report: bool) -> Path:
    ensure_folders()
    report = {
        "target": str(target.resolve()),
        "created_at": stamp(),
        "summary": summarize(findings),
        "findings": findings,
    }
    json_path = REPORT_DIR / f"scan_{file_stamp()}.json"
    save_json(json_path, report)

    if csv_report:
        csv_path = REPORT_DIR / f"scan_{file_stamp()}.csv"
        with csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["file_name", "path", "status", "threat", "severity", "reasons", "sha256", "bytes"],
            )
            writer.writeheader()
            for item in findings:
                row = item.copy()
                row["reasons"] = "; ".join(row["reasons"])
                writer.writerow({key: row.get(key, "") for key in writer.fieldnames})

    return json_path


def summarize(findings: list[dict]) -> dict:
    summary = {"scanned": len(findings), "clean": 0, "suspicious": 0, "malicious": 0, "errors": 0}
    for item in findings:
        summary[item.get("status", "errors")] = summary.get(item.get("status", "errors"), 0) + 1
    return summary


def print_scan_result(findings: list[dict], report_path: Path) -> None:
    summary = summarize(findings)
    print("\nScan finished")
    print(f"Files scanned : {summary['scanned']}")
    print(f"Clean         : {summary['clean']}")
    print(f"Suspicious    : {summary['suspicious']}")
    print(f"Malicious     : {summary['malicious']}")
    print(f"Errors        : {summary['errors']}")

    hits = [item for item in findings if item["status"] != "clean"]
    if hits:
        print("\nFindings:")
        for item in hits:
            label = item["status"].upper()
            name = f" - {item['threat']}" if item["threat"] else ""
            print(f"[{label}] {item['path']}{name}")
            for reason in item["reasons"]:
                print(f"  -> {reason}")
            if item.get("quarantine_id"):
                print(f"  -> quarantine id: {item['quarantine_id']}")

    print(f"Report saved  : {report_path}")


def scan_target(args) -> None:
    ensure_folders()
    target = Path(args.target)
    if not target.exists():
        raise SystemExit("Target path not found.")

    signatures = load_signatures()
    findings = []

    for path in iter_files(target):
        try:
            finding = make_finding(path, signatures)
            should_quarantine = args.quarantine and finding["status"] == "malicious"
            if args.quarantine_suspicious and finding["status"] == "suspicious":
                should_quarantine = True
            if should_quarantine:
                finding["quarantine_id"] = quarantine_file(path, finding)
            findings.append(finding)
        except OSError as exc:
            findings.append(
                {
                    "path": str(path),
                    "file_name": path.name,
                    "status": "errors",
                    "threat": "",
                    "severity": "",
                    "reasons": [str(exc)],
                    "sha256": "",
                    "md5": "",
                    "bytes": 0,
                    "checked_at": stamp(),
                }
            )

    report_path = save_scan_report(target, findings, args.csv)
    print_scan_result(findings, report_path)


def make_snapshot(target: Path) -> dict:
    files = {}
    root = target.resolve()

    for path in iter_files(root):
        try:
            rel = path.relative_to(root) if root.is_dir() else Path(path.name)
            hashes = hash_file(path)
            files[str(rel)] = {
                "sha256": hashes["sha256"],
                "bytes": hashes["bytes"],
                "modified": datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            }
        except OSError:
            continue

    return {"target": str(root), "created_at": stamp(), "files": files}


def build_baseline(args) -> None:
    target = Path(args.target)
    if not target.exists():
        raise SystemExit("Target path not found.")

    snapshot = make_snapshot(target)
    save_json(BASELINE_FILE, snapshot)
    print(f"Baseline saved for {len(snapshot['files'])} files.")
    print(f"File: {BASELINE_FILE}")


def check_baseline(args) -> None:
    baseline = load_json(BASELINE_FILE, None)
    if not baseline:
        raise SystemExit("No baseline found. Run baseline command first.")

    target = Path(args.target or baseline["target"])
    current = make_snapshot(target)
    old_files = baseline.get("files", {})
    new_files = current.get("files", {})

    added = sorted(set(new_files) - set(old_files))
    missing = sorted(set(old_files) - set(new_files))
    changed = sorted(name for name in set(old_files).intersection(new_files) if old_files[name]["sha256"] != new_files[name]["sha256"])

    result = {
        "checked_at": stamp(),
        "target": str(target.resolve()),
        "added": added,
        "missing": missing,
        "changed": changed,
        "unchanged": len(set(old_files).intersection(new_files)) - len(changed),
    }
    report_path = REPORT_DIR / f"baseline_check_{file_stamp()}.json"
    save_json(report_path, result)

    print("\nBaseline check")
    print(f"Added     : {len(added)}")
    print(f"Missing   : {len(missing)}")
    print(f"Changed   : {len(changed)}")
    print(f"Unchanged : {result['unchanged']}")

    for label, values in [("Added", added), ("Missing", missing), ("Changed", changed)]:
        if values:
            print(f"{label}:")
            for value in values[:15]:
                print(f"  -> {value}")
            if len(values) > 15:
                print("  -> more saved in report")

    print(f"Report saved: {report_path}")


def add_signature(args) -> None:
    path = Path(args.file)
    if not path.exists() or not path.is_file():
        raise SystemExit("File not found.")

    data = load_signatures()
    item_hash = hash_file(path)["sha256"]
    data["sha256"][item_hash] = {
        "name": args.name,
        "severity": args.severity,
        "category": args.category,
        "added_at": stamp(),
    }
    save_json(SIGNATURE_FILE, data)

    print("Signature added.")
    print(f"Name   : {args.name}")
    print(f"SHA256 : {item_hash}")


def list_quarantine(_args) -> None:
    index = load_quarantine_index()
    if not index:
        print("Quarantine is empty.")
        return

    print("\nQuarantine")
    for qid, item in index.items():
        print(f"{qid} | {item.get('file_name')} | {item.get('status')} | {item.get('quarantined_at')}")


def restore_quarantine(args) -> None:
    index = load_quarantine_index()
    item = index.get(args.id)
    if not item:
        raise SystemExit("Quarantine id not found.")

    stored = Path(item["stored_path"])
    original = Path(item["original_path"])

    if not stored.exists():
        raise SystemExit("Stored quarantine file is missing.")
    if original.exists() and not args.force:
        raise SystemExit("Original path already exists. Use --force to replace it.")

    original.parent.mkdir(parents=True, exist_ok=True)
    if original.exists() and args.force:
        original.unlink()

    shutil.move(str(stored), original)
    del index[args.id]
    save_quarantine_index(index)
    print(f"Restored: {original}")


def show_menu(_args) -> None:
    while True:
        print("\nBasic Antivirus Simulation")
        print("1. Scan folder")
        print("2. Scan folder and quarantine known malware")
        print("3. Build file baseline")
        print("4. Check file baseline")
        print("5. List quarantine")
        print("6. Exit")
        choice = input("Enter choice: ").strip()

        if choice == "1":
            target = input("Folder/file path: ").strip() or "."
            scan_target(argparse.Namespace(target=target, quarantine=False, quarantine_suspicious=False, csv=False))
        elif choice == "2":
            target = input("Folder/file path: ").strip() or "."
            scan_target(argparse.Namespace(target=target, quarantine=True, quarantine_suspicious=False, csv=False))
        elif choice == "3":
            target = input("Folder/file path: ").strip() or "."
            build_baseline(argparse.Namespace(target=target))
        elif choice == "4":
            target = input("Folder/file path (blank = saved target): ").strip() or None
            check_baseline(argparse.Namespace(target=target))
        elif choice == "5":
            list_quarantine(None)
        elif choice == "6":
            break
        else:
            print("Invalid choice.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Basic Antivirus Simulation with quarantine and integrity checking.")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan a file or folder")
    scan.add_argument("target", nargs="?", default=".")
    scan.add_argument("--quarantine", action="store_true", help="move signature matches to quarantine")
    scan.add_argument("--quarantine-suspicious", action="store_true", help="also quarantine heuristic findings")
    scan.add_argument("--csv", action="store_true", help="also create a CSV report")
    scan.set_defaults(func=scan_target)

    baseline = sub.add_parser("baseline", help="save current file hashes")
    baseline.add_argument("target", nargs="?", default=".")
    baseline.set_defaults(func=build_baseline)

    check = sub.add_parser("check", help="compare files against saved baseline")
    check.add_argument("target", nargs="?")
    check.set_defaults(func=check_baseline)

    add = sub.add_parser("add-signature", help="add a file hash to the signature database")
    add.add_argument("file")
    add.add_argument("name")
    add.add_argument("--severity", default="high", choices=["low", "medium", "high"])
    add.add_argument("--category", default="user-added")
    add.set_defaults(func=add_signature)

    quarantine = sub.add_parser("quarantine", help="manage quarantine")
    qsub = quarantine.add_subparsers(dest="qcommand")
    qlist = qsub.add_parser("list", help="show quarantined files")
    qlist.set_defaults(func=list_quarantine)
    restore = qsub.add_parser("restore", help="restore a quarantined file")
    restore.add_argument("id")
    restore.add_argument("--force", action="store_true")
    restore.set_defaults(func=restore_quarantine)

    menu = sub.add_parser("menu", help="open simple menu")
    menu.set_defaults(func=show_menu)

    return parser


def main() -> None:
    ensure_folders()
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(1)
