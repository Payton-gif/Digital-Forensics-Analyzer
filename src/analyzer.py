import argparse
import csv
import hashlib
import mimetypes
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def analyze_file(path, root):
    stat = path.stat()
    created = getattr(stat, "st_birthtime", None)

    def timestamp(value):
        if value is None:
            return ""
        return datetime.fromtimestamp(
            value, timezone.utc
        ).isoformat()

    return {
        "file_name": path.name,
        "relative_path": str(path.relative_to(root)),
        "file_type": mimetypes.guess_type(path.name)[0] or "unknown",
        "size_bytes": stat.st_size,
        "created_time": timestamp(created),
        "modified_time": timestamp(stat.st_mtime),
        "accessed_time": timestamp(stat.st_atime),
        "metadata_changed_time": timestamp(stat.st_ctime),
        "sha256": sha256_file(path),
    }


def scan_folder(folder):
    root = Path(folder).expanduser().resolve()

    if not root.is_dir():
        raise ValueError(f"Folder does not exist: {root}")

    results = []

    for path in sorted(root.rglob("*")):
        if path.is_file():
            try:
                results.append(analyze_file(path, root))
            except OSError as error:
                print(f"Warning: Could not read {path}: {error}")

    return sorted(results, key=lambda item: item["modified_time"])


def export_csv(results, output):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "file_name", "relative_path", "file_type", "size_bytes",
        "created_time", "modified_time", "accessed_time",
        "metadata_changed_time", "sha256"
    ]

    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)


def main():
    parser = argparse.ArgumentParser(
        description="Forensic Evidence Timeline Analyzer"
    )
    parser.add_argument("evidence_folder")
    parser.add_argument("--search", help="Filter by filename")
    parser.add_argument("--output", default="reports/timeline.csv")
    args = parser.parse_args()

    try:
        results = scan_folder(args.evidence_folder)
    except (ValueError, OSError) as error:
        parser.error(str(error))

    if args.search:
        results = [
            item for item in results
            if args.search.casefold() in item["file_name"].casefold()
        ]

    export_csv(results, args.output)

    print(f"\nFiles analyzed: {len(results)}")
    print(f"Report saved to: {args.output}")

    for item in results:
        print(
            f"{item['modified_time']} | {item['file_name']} | "
            f"{item['size_bytes']} bytes"
        )


if __name__ == "__main__":
    main()
