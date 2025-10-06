
# GCP Metadata Extractor via Remote Command Injection

## Overview

This tool is designed to extract Google Cloud Platform (GCP) Compute Engine instance metadata remotely by leveraging a command injection vulnerability in a target URL. It automates querying the GCP metadata server endpoints to collect extensive information about the target VM instance, project, network, disks, and more.

By providing a specially crafted URL that executes injected commands remotely, this script fetches metadata paths, cleans and parses the data, and optionally saves it locally in a structured JSON file hierarchy.

---

## Features

- Supports multiple metadata categories including:
  - Project information (project ID, numeric ID, attributes)
  - Instance details (hostname, machine type, tags, scheduling)
  - Disk configuration
  - Network interfaces and external IPs
  - Shielded instance security features
  - Service accounts and tokens
- Recursive fetching of directory-style metadata paths
- Intelligent content-type detection and file saving (JSON, YAML, shell scripts, systemd services)
- Cleans HTML or non-metadata content from responses
- Retry mechanism for trailing slash variations
- Outputs JSON to console or saves organized files for offline analysis
- Command injection abstraction with placeholder replacement for flexibility
- Debug prints for request tracing and file saves

---

## Prerequisites

- Python 3.6+
- `requests` library (`pip install requests`)

---

## Installation

1. Clone or download this repository.
2. Ensure Python 3 and `requests` are installed.
3. Run the script directly via command line.

---

## Usage

```bash
python gcp_metadata_extractor.py --url <TARGET_URL> [options]
```

### Required Arguments

- `--url`  
  Target URL with a placeholder `CHECK` indicating where the injected command will be inserted.  
  Example:  
  `http://34.42.232.208/?cmd=CHECK`

### Optional Arguments

- `--category`  
  Fetch metadata for a specific category (e.g., `instance`, `project`, `network`)  
  If unspecified, you must use either `--path` or `--all`.

- `--path`  
  Fetch a specific metadata path overriding the category selection.  
  Example: `instance/hostname`

- `--all`  
  Fetch all metadata paths across all categories.

- `--save`  
  Save all fetched data into JSON and other relevant files locally instead of printing.  

- `--project`  
  Name of the GCP project used to organize saved output files. Required if `--save` is set.

---

## Example Commands

Fetch instance metadata category and print to console:

```bash
python gcp_metadata_extractor.py --url "http://target.com/?cmd=CHECK" --category instance
```

Fetch a specific path and save results under a project folder:

```bash
python gcp_metadata_extractor.py --url "http://target.com/?cmd=CHECK" --path "instance/hostname" --save --project my-gcp-project
```

Fetch all metadata available and save locally:

```bash
python gcp_metadata_extractor.py --url "http://target.com/?cmd=CHECK" --all --save --project my-gcp-project
```

---

## How It Works

- The script replaces the `CHECK` placeholder in the provided URL with a `curl` command targeting GCP's internal metadata server (`http://metadata.google.internal/computeMetadata/v1`).
- It sends an HTTP GET request to the target URL which is assumed to execute the command and return metadata output.
- The response is cleaned, parsed, and recursively processed if directories are detected.
- Data is either printed in pretty JSON or saved into a structured directory tree matching metadata categories and paths.
- Supports smart filename sanitization and file type detection based on content heuristics.

---

## Directory Structure When Saved

Outputs saved with `--save` are organized as:

```
<ProjectName>/<TargetIP>/
  ├─ instance/
  │   ├─ hostname.txt
  │   ├─ disks/
  │   │   └─ 0_device-name.txt
  ├─ project/
  │   ├─ project-id.txt
  └─ network/
      └─ network-interfaces/
          └─ 0_external-ip.txt
```

Each file contains the raw or parsed metadata content corresponding to the path.

---

## Limitations & Security Notes

- Requires that the target URL is vulnerable to command injection and executes the injected command, returning its output.
- Only tested against GCP Compute Engine metadata endpoints.
- Make sure to have permission to test the target system to avoid legal issues.
- Network errors, timeouts, or unexpected response formats may cause incomplete results.

---

## Contributing

Contributions and improvements are welcome! Please submit pull requests or open issues for feature requests or bugs.

---

## License

MIT License © 2025 Your Name or Organization

