# GCP IAM & Service Account Enumerator

A Python script to enumerate Google Cloud Platform (GCP) projects, list service accounts, and retrieve IAM policies for each project using an OAuth2 access token. Useful for auditing permissions and understanding access control in GCP environments.

## Requirements

- Python 3.x
- `requests` library

Install the required package:

```bash
pip install requests
```

Configuration
-------------

Obtain a GCP OAuth2 access token or a short-lived service account token.
Save the token in a file named token.txt in the same directory as the script.

Example using gcloud:
```bash
gcloud auth print-access-token > token.txt
```

Ensure the token has the necessary scopes:
`https://www.googleapis.com/auth/cloud-platform`
`https://www.googleapis.com/auth/iam`


Usage
-----
Run the script
```bash
python gcp_iam_enum.py
```

The script will:
- Show token information.
- List all projects accessible to the token.
- List service accounts for each project.
- Print IAM policies for each project.

```bash
[*] Token info:
{
  "email": "user@example.com",
  "scope": "...",
  ...
}
[*] Found 2 projects:
  - my-project-1: My First Project
  - my-project-2: My Second Project
  [*] Service accounts in project my-project-1:
    - sa1@my-project-1.iam.gserviceaccount.com
  [*] IAM Policy for project my-project-1:
    Role: roles/viewer
      Member: user:user@example.com
```

Notes
-----
- Requires a valid token with sufficient permissions to read project and IAM information.
- Only projects accessible by the token will be enumerated.
- IAM policies returned follow GCP's standard format.