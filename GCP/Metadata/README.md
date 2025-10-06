GCP Metadata Extractor via Remote Command Injection
------------------------
This Python script allows you to extract Google Cloud Platform (GCP) metadata from a target server by leveraging a remote command injection vulnerability. It fetches metadata such as project information, instance details, network configuration, disks, shielded instance settings, and service account data. The results can be saved as JSON files for further analysis.


Features
------------
- Fetch metadata for specific categories or paths.
- Recursive fetching for directory-like metadata paths.
- Automatic file type detection for saving outputs (`.json`, `.yaml`, `.sh`, `.txt`, `.service`).
- Cleans HTML responses for better parsing.
- Handles both string and JSON metadata responses.
- Retry mechanism for paths with or without trailing slashes.
- Save structured metadata to a local folder organized by category and path.

Requirements
------------

- Python 3.7+
- `requests` library

Install dependencies via pip:

```bash
pip install requests
```

Usage
-----
```bash
python gcp_metadata_extractor.py --url "http://target.com/?cmd=CHECK" [options]
```
Arguments
---------
`--url` (required): Target URL with CHECK placeholder for command injection, e.g., `http://example.com/?cmd=CHECK`.

`--category`: Metadata category to fetch (e.g., instance, project).

`--path`: Specific metadata path to fetch (overrides --category).

`--all`: Fetch all metadata paths across all categories.

`--save`: Save output(s) to JSON files.

`--project`: Project name (required if --save is set).

Examples
--------
Fetch all instance metadata:
```bash
python gcp_metadata_extractor.py --url "http://target.com/?cmd=CHECK" --category instance
```

Fetch a specific metadata path:
```bash
python gcp_metadata_extractor.py --url "http://target.com/?cmd=CHECK" --path "instance/hostname"
```

Fetch all metadata and save it locally:
```bash
python gcp_metadata_extractor.py --url "http://target.com/?cmd=CHECK" --all --save --project MyProject
```

The output will be saved under `./MyProject/<target_ip>/`.

Metadata Categories
-------------------
project: Project ID, numeric project ID, project number, project attributes.

`instance`: Hostname, ID, name, zone, machine type, description, tags, creation timestamp, CPU platform, scheduling, maintenance events, and attributes.

`disks`: Disk details including device name, index, type, and interface.

`network`: Network interface information such as IP, network, subnetmask, gateway, and external IP.

`shielded-instance`: Shielded VM settings.

`service-accounts`: Default service account details including email, scopes, aliases, and token.

Notes
-----
Large metadata values are automatically saved as files to avoid overwhelming the terminal.