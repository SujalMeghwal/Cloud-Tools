# GCP VM Inspector

A Red Team and Security Assessment utility for **Google Cloud Platform (GCP)** that automates discovery and inspection of Compute Engine virtual machines (VMs).

It uses the `gcloud` CLI under the hood to fetch configuration, metadata, service accounts, disks, IPs, startup scripts, and more — useful for **cloud security auditing**, **post-compromise reconnaissance**, and **configuration validation**.

---

# Features

- Automatically discovers all GCE instances within a project.
- Supports both interactive and non-interactive execution.
- Retrieves:
  - Service account details and scopes
  - Internal and external IPs
  - Attached disks and boot configuration
  - Firewall tags
  - VM metadata (with smart parsing and separation of long/encoded data)
  - Startup scripts
- Auto-saves each result in structured JSON/text format.
- Detects file type from metadata values (`.sh`, `.yaml`, `.json`, `.crt`, `.env`, etc.)
- Pings external IPs for live host detection.
- Pretty CLI output using `rich` tables, syntax highlighting, and color.

---

# Example Use Cases

- **Red Team Recon**: Quickly extract all GCP VM details after gaining project-level or service account access.
- **Blue Team Auditing**: Validate VM configurations, service accounts, and metadata exposure.
- **Incident Response**: Rapidly enumerate metadata for leaked credentials or sensitive startup scripts.

---

# Requirements

- Python 3.8+
- Google Cloud SDK (`gcloud`) installed and authenticated (`gcloud auth login`)
- Active GCP project with Compute Engine API enabled.

---

# Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/gcp-vm-inspector.git
cd gcp-vm-inspector
```

# Install dependencies
```bash
pip install -r requirements.txt
```


# Usage

Basic command (run all checks for a project):

```bash
python gcp_vm_inspector.py --project PROJECT_ID --all
```

Selective checks:
```bash
python gcp_vm_inspector.py --project PROJECT_ID --checks sa,ips,metadata
```

Available checks:
- `sa`            Service Account Info
- `ips`           Public & Internal IPs
- `tags`          Firewall Tags
- `disks`         Attached Disks
- `metadata`      Full Metadata (raw JSON)
- `startup_script` Startup Script (raw)

Specify output directory:
```bash
python gcp_vm_inspector.py --project PROJECT_ID --all --output-dir results
```

Output layout produced by the tool:
```bash
results/
 └── PROJECT_ID/
     ├── instance_zone/
     │    ├── metadata/
     │    │    ├── metadata.json
     │    │    └── extracted/
     │    │         ├── key1.sh
     │    │         └── key2.yaml
     │    ├── sa.json
     │    ├── ips.json
     │    └── startup_script.txt
```

Interactive mode
----------------
If you run the tool without specifying checks:
```bash
python gcp_vm_inspector.py --project PROJECT_ID
```

It will:
- Display all available instances.
- Prompt you to choose which VMs to inspect (enter indexes or 'all').
- Prompt for output folder.

Example interactive session:

```bash
python gcp_vm_inspector.py --project=my-cloud-project
```

Available Instances:

```bash
1) web-1
2) db-1
3) bastion
```

Enter instance index(es) separated by comma, or type all to inspect all: 1,3
Enter base output folder [output]: results

Example output snippet
----------------------
Inspecting VM: webserver-1 (zone: us-central1-a)

Service Account Info
--------------------
Email: webserver-sa@project.iam.gserviceaccount.com
Scopes: storage-full, compute-readonly

Metadata extraction logic
-------------------------
- Short metadata values are saved in JSON summaries.
- Long or complex values are saved as separate files under: `/metadata/extracted/`
- Automatic detection of file types:

```bash
- .sh    shell scripts / startup scripts
- `.yaml  Kubernetes / cloud configs
- .json  structured data
- .crt   base64/certificate-like blobs
- .env / .conf environment-style configs
```

Dependencies
------------
- rich (for colored and table-based console output)
- argparse, subprocess, json, os, re, base64, platform (Python standard library)

Notes
-----
- Requires gcloud authentication with appropriate permissions (Viewer or Compute Viewer may suffice for enumeration).
- For Red Team use, authenticated service accounts or tokens can be used with gcloud auth activate-service-account or equivalent.
- Use responsibly and in accordance with applicable law and organizational policy.

License
-------
MIT License © 2025 — Security Research & Red Teaming Utility.