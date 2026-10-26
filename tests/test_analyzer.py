
import unittest
import sys
import csv
import subprocess
from pathlib import Path
import tempfile
import hashlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from analyzer import sha256_file, analyze_file


class TestAnalyzer(unittest.TestCase):

    def test_sha256_hash(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "sample.txt"
            content = b"forensic evidence"
            file_path.write_bytes(content)

            expected = hashlib.sha256(content).hexdigest()
            actual = sha256_file(file_path)

            self.assertEqual(actual, expected)

    def test_file_size(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "sample.txt"
            content = b"sample evidence"
            file_path.write_bytes(content)

            result = analyze_file(file_path, Path(temp_dir))

            self.assertEqual(result["size_bytes"], len(content))

    def test_analyze_file_metadata(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "evidence.txt"
            content = b"forensic evidence"
            file_path.write_bytes(content)

            result = analyze_file(file_path, Path(temp_dir))

            self.assertEqual(result["file_name"], "evidence.txt")
            self.assertEqual(result["size_bytes"], len(content))
            self.assertEqual(
                result["sha256"],
                hashlib.sha256(content).hexdigest()
            )

    def test_sha256_hash_length(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "hash_test.txt"
            file_path.write_text("forensic evidence")

            result = analyze_file(file_path, Path(temp_dir))

            self.assertEqual(len(result["sha256"]), 64)

    def test_csv_report_generation(self):
        project_dir = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            evidence_dir = temp_path / "evidence"
            evidence_dir.mkdir()

            file_path = evidence_dir / "sample.txt"
            content = b"CSV forensic test"
            file_path.write_bytes(content)

            output_path = temp_path / "timeline.csv"

            subprocess.run(
                [
                    sys.executable,
                    str(project_dir / "src" / "analyzer.py"),
                    str(evidence_dir),
                    "--output",
                    str(output_path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            with output_path.open(
                newline="", encoding="utf-8"
            ) as csv_file:
                rows = list(csv.DictReader(csv_file))

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["file_name"], "sample.txt")
            self.assertEqual(
                rows[0]["sha256"],
                hashlib.sha256(content).hexdigest()
            )


    def test_hash_changes_when_file_modified(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "integrity.txt"

            file_path.write_text("Original evidence")
            original_hash = sha256_file(file_path)

            file_path.write_text("Modified evidence")
            modified_hash = sha256_file(file_path)

            self.assertNotEqual(original_hash, modified_hash)

if __name__ == "__main__":
    unittest.main()

