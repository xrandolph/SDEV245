import argparse
import os
import re
import logging

PATTERNS = [
    ("Private Key (PEM)", r"-----BEGIN .*PRIVATE KEY-----[\s\S]+?-----END .*PRIVATE KEY-----"),
    ("AWS Access Key ID", r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    ("Google API Key", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ("GitHub Token", r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    ("Hardcoded Password", r"(password|passwd|pwd|secret)\s*[:=]\s*['\"][^'\"]{4,}['\"]"),
    
]

DEFAULT_IGNORES = (".git", "node_modules", ".venv", "venv", "__pycache__", "build", "dist")

def is_ignored(path, extra_excludes):
    p = os.path.normpath(path).lower()
    for ignore in DEFAULT_IGNORES:
        if os.sep + ignore + os.sep in p or p.endswith(os.sep + ignore):
            return True
    for ex in extra_excludes:
        if ex.lower() in p:
            return True
    return False

def scan_file(path):
    results = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, start=1):
                for name, pattern in PATTERNS:
                    for m in re.finditer(pattern, line, flags=re.IGNORECASE):
                        results.append({
                            "file": path,
                            "line": line_no,
                            "type": name,
                            "match": m.group(0).strip()
                        })
    except PermissionError as pe:
        logging.debug("Permission denied reading %s: %s", path, pe)
    except Exception as e:
        logging.warning("Could not read %s: %s", path, e)
    return results

def scan_paths(paths, exts=None, excludes=None):
    findings = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                if is_ignored(root, excludes):
                    continue
                for fname in files:
                    full = os.path.join(root, fname)
                    if is_ignored(full, excludes):
                        continue
                    if exts and not any(fname.lower().endswith(ext.lower()) for ext in exts):
                        continue
                    findings.extend(scan_file(full))
        else:
            if not is_ignored(p, excludes):
                if exts and not any(p.lower().endswith(ext.lower()) for ext in exts):
                    continue
                findings.extend(scan_file(p))
    return findings

def print_table(findings):
    if not findings:
        print("No potential secrets found.")
        return
    print("File,Line,Type,Match")
    for f in findings:
        print(f"{f['file']},{f['line']},{f['type']},{f['match']}")

def main():
    parser = argparse.ArgumentParser(description="Simple secret scanner (updated).")
    parser.add_argument("paths", nargs="*", help="Files or folders to scan (default: current directory)")
    parser.add_argument("--ext", nargs="*", default=None, help="Only scan files with these extensions (e.g., .py .js .env)")
    parser.add_argument("--exclude", nargs="*", default=[], help="Substring patterns to exclude (simple matching)")
    parser.add_argument("--log-level", default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO))

    paths = args.paths if args.paths else ["."]
    logging.info("Starting scan... Paths: %s", paths)
    findings = scan_paths(paths, exts=args.ext, excludes=args.exclude)
    logging.info("Scan complete. Findings: %d", len(findings))
    print_table(findings)
    return 1 if findings else 0

if __name__ == "__main__":
    raise SystemExit(main())
