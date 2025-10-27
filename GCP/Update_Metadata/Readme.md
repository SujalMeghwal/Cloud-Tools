# GCP SSH Metadata Updater

A utility to **add or update SSH keys in Google Compute Engine (GCE) instance metadata**. This tool allows you to attach an SSH key to a specified username on a VM by updating its `ssh-keys` metadata item via the Google Compute Engine REST API.

It can generate a new SSH keypair or use an existing public key, format it correctly for GCE, and update the instance metadata. This is useful for **Red Team operations**, **DevOps automation**, or **administrative access management** in GCP.

## Features

- Generate new RSA 2048-bit SSH keypair for a given username.
- Format the public key for GCP metadata.
- Update `ssh-keys` metadata for a specific GCE instance.
- Verify that the key has been uploaded.
- Logging via Python’s `logging` module.
- Works with both generated keys and existing keypairs.

## Requirements

- Python 3.8+
- `requests` library (`pip install requests`)
- Access to GCP API with sufficient IAM permissions.
- Network access to Google Compute Engine API.
- Optional: `ssh-keygen` installed for key generation.

## IAM / Permissions

The caller must have the following permissions:

- `compute.instances.get` — to read instance metadata.
- `compute.instances.setMetadata` — to update metadata.

Roles that contain these permissions include:

- `roles/compute.instanceAdmin.v1` (full control)
- `roles/compute.admin` (admin access)
- Or custom roles with above permissions.

> **Important:** Unauthorized modification of SSH metadata can compromise instance security. Only run on projects and instances you have explicit authorization to manage.

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/yourusername/gcp-ssh-metadata-updater.git
cd gcp-ssh-metadata-updater
python -m venv .venv
source .venv/bin/activate   #Windows:venvScriptsactivate
pip3 install -r requirements.txt
```

Authentication:
---------------

The script requires a Google OAuth2 access token. You can generate one via gcloud:
bashgcloud auth print-access-token > token.txt
Or use a short-lived service account token. Ensure the token has the required scopes:
https://www.googleapis.com/auth/compute

Usage
-----

Generate a new SSH keypair and upload:
```bash
python gcp_ssh_metadata_updater.py --project PROJECT_ID --zone us-central1-b --instance INSTANCE_NAME --token token.txt --username bob --key-path ~/.ssh/bob 
    --generate
```

- `--generate` tells the script to create a new keypair at the specified `--key-path`.
- The script expects `~/.ssh/bob.pub` to exist if `--generate` is not used.

The public key will be uploaded in the format:
```text
username:ssh-rsa AAAA... username
```

Use an existing SSH key:
```bash
python gcp_ssh_metadata_updater.py --project PROJECT_ID --zone us-central1-b --instance INSTANCE_NAME --token token.txt --username bob --key-path ~/.ssh/bob
```

Script Flow
-----------
1. Read Access Token from file.
2. Generate SSH keypair (optional) using `ssh-keygen`.
3. Format Public Key for GCP metadata (`username:ssh-rsa AAAA... username`).
4. Fetch Metadata Fingerprint from instance.
5. Update Metadata via setMetadata API call.
6. Verify Key presence in instance metadata.

Output / Verification
---------------------
After running the script, console logs will indicate success or errors.
```bash
text2025-10-05 12:00:00 - INFO - SSH key generated.
2025-10-05 12:00:01 - INFO - SSH key formatted for GCP.
2025-10-05 12:00:02 - INFO - Fingerprint acquired: abc123
2025-10-05 12:00:03 - INFO - Metadata updated successfully.
```

Verification will print the uploaded key:
```bash
SSH key successfully uploaded:
bob:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... bob
```

Important Security Notes
------------------------
- The script replaces existing ssh-keys metadata by default. Any existing SSH keys may be overwritten. Backup metadata before running.
- Metadata propagation may take a few seconds; verification might not be immediate.
- Only use with authorized accounts and tokens.
- Do not store access tokens or private keys in public repositories.