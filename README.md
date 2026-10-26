# Digital-Forensics-Analyzer
# Digital Forensics Timeline Analyzer

## Project Overview

The Digital Forensics Timeline Analyzer is a Python tool that helps investigators organize digital evidence. It scans an evidence folder, collects file metadata, calculates SHA-256 hashes, and exports the results to a CSV timeline report.

## Features

- Recursively scans an evidence directory.
- Records file names and relative paths.
- Identifies file types using MIME type guessing.
- Collects file sizes and available timestamps.
- Calculates SHA-256 hashes to help verify file integrity.
- Searches files by filename.
- Exports results to a CSV report.
- Includes automated unit tests.

## Requirements

- Python 3
- No additional packages required.

## Project Structure

```text
Digital-Forensics-Analyzer/
├── src/
│   └── analyzer.py
├── tests/
│   └── test_analyzer.py
├── evidence/
├── reports/
├── docs/
└── README.md
```

## Setup

Clone the repository and open a terminal in the project directory. Confirm Python 3 is installed:

```bash
python3 --version
```

## Usage

Analyze the evidence directory:

```bash
python3 src/analyzer.py evidence
```

Search for files with a matching filename:

```bash
python3 src/analyzer.py evidence --search sample
```

The CSV report is saved to `reports/timeline.csv` by default.

## Running the Tests

Run the automated tests:

```bash
python3 -m unittest discover -s tests -v
```

## Results

The analyzer displays the number of files analyzed and the location of the generated CSV report. The report contains file metadata and SHA-256 hashes for the analyzed evidence.

## Limitations

Some timestamps may not be available on every operating system. SHA-256 hashes help identify changes to file contents but do not independently prove when or how evidence was collected. This project is intended for educational use.

## Future Improvements

- Add filtering by date and file type.
- Improve timestamp handling across operating systems.
- Add timeline visualization.
- Expand automated testing.

## Contributors

- Payton Slabaugh
- Dani Ojeda