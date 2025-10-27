import requests
import json
import logging
from pathlib import Path
import argparse
import subprocess
import sys
import getpass
import os

# === LOGGING SETUP ===
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# === CONSTANT HEADERS ===
HEADERS = {
    "Content-Type": "application/json"
}

# === FUNCTIONS ===

def generate_ssh_keypair(username, output_path, passphrase):
    """Generate an SSH keypair using ssh-keygen."""
    priv_key_path = Path(output_path).expanduser()
    pub_key_path = priv_key_path.with_name(priv_key_path.name + ".pub")

    if priv_key_path.exists() or pub_key_path.exists():
        logging.warning(f"Key already exists at {priv_key_path} and/or {pub_key_path}. Use a different path or delete existing keys.")
        return str(pub_key_path)

    logging.info(f"Generating SSH keypair for user '{username}'...")

    cmd = [
        "ssh-keygen",
        "-t", "rsa",
        "-b", "2048",
        "-f", str(priv_key_path),
        "-C", f"{username}",
        "-N", passphrase
    ]

    try:
        subprocess.run(cmd, check=True)
        logging.info("SSH key generated.")
        return str(pub_key_path)
    except subprocess.CalledProcessError as e:
        logging.error(f"SSH keygen failed: {e}")
        sys.exit(1)


def format_ssh_key_for_gcp(pub_key_path, username):
    try:
        key_data = Path(pub_key_path).read_text().strip()
        key_parts = key_data.split()
        if len(key_parts) < 2:
            logging.error("Invalid SSH public key format.")
            sys.exit(1)

        key_type = key_parts[0]
        key_body = key_parts[1]
        formatted_key = f"{username}:{key_type} {key_body} {username}"
        logging.info("SSH key formatted for GCP.")
        return formatted_key
    except Exception as e:
        logging.error(f"Failed to read or format SSH key: {e}")
        sys.exit(1)



def read_token(file_path):
    """Read the access token from a file."""
    try:
        token = Path(file_path).read_text().strip()
        logging.info("Access token loaded.")
        return token
    except Exception as e:
        logging.error(f"Failed to read token: {e}")
        sys.exit(1)


def get_instance_metadata(token, project, zone, instance):
    """Fetch the metadata of the GCP instance."""
    uri = f"https://compute.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instances/{instance}"
    headers = {**HEADERS, "Authorization": f"Bearer {token}"}

    response = requests.get(uri, headers=headers)

    if response.status_code != 200:
        logging.error(f"Failed to get instance metadata: {response.text}")
        sys.exit(1)

    metadata = response.json().get("metadata", {})
    fingerprint = metadata.get("fingerprint")
    if not fingerprint:
        logging.error("No metadata fingerprint found.")
        sys.exit(1)

    logging.info(f"Fingerprint acquired: {fingerprint}")
    return fingerprint


def update_instance_metadata(token, project, zone, instance, fingerprint, ssh_key):
    """Update the metadata of the GCP instance with the provided SSH key."""
    uri = f"https://compute.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instances/{instance}/setMetadata"
    headers = {**HEADERS, "Authorization": f"Bearer {token}"}

    payload = {
        "fingerprint": fingerprint,
        "items": [
            {
                "key": "ssh-keys",
                "value": ssh_key
            }
        ]
    }

    response = requests.post(uri, headers=headers, json=payload)

    if response.status_code == 200:
        logging.info("Metadata updated successfully.")
    else:
        logging.error(f"Failed to update metadata: {response.status_code} - {response.text}")
        sys.exit(1)

def verify_key_uploaded(token, project, zone, instance, username):
    """Fetch the metadata and confirm SSH key is present."""
    uri = f"https://compute.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instances/{instance}"
    headers = {**HEADERS, "Authorization": f"Bearer {token}"}

    response = requests.get(uri, headers=headers)
    if response.status_code != 200:
        logging.error(f"Failed to verify metadata: {response.text}")
        return

    metadata = response.json().get("metadata", {})
    items = metadata.get("items", [])

    for item in items:
        if item.get("key") == "ssh-keys":
            ssh_keys = item.get("value", "")
            keys = ssh_keys.strip().split('\n')
            for key in keys:
                if key.startswith(f"{username}:"):
                    print("\n SSH key successfully uploaded:")
                    print(key)
                    return
            logging.warning("SSH key not found in metadata (might take a few seconds to propagate).")
            return

    logging.warning("No ssh-keys metadata found.")


# === MAIN ===

def main():
    parser = argparse.ArgumentParser(description="Update SSH metadata on a GCP VM instance.")
    parser.add_argument("--project", required=True, help="GCP Project ID")
    parser.add_argument("--zone", required=True, help="GCP Zone (e.g., us-central1-b)")
    parser.add_argument("--instance", required=True, help="GCP Instance name")
    parser.add_argument("--token", required=True, help="Path to access token file")
    parser.add_argument("--username", required=True, help="Username to attach to the SSH key (e.g., bob)")
    parser.add_argument("--key-path", required=True, help="Path to private key (will generate if missing)")
    parser.add_argument("--generate", action="store_true", help="Generate new SSH keypair")

    args = parser.parse_args()

    token = read_token(args.token)

    # Generate key if needed
    if args.generate:
        passphrase = getpass.getpass("Enter passphrase for new SSH key (leave blank for none): ")
        pub_key_path = generate_ssh_keypair(args.username, args.key_path, passphrase)
    else:
        pub_key_path = Path(args.key_path).with_suffix(".pub")
        if not pub_key_path.exists():
            logging.error(f"Public key not found at {pub_key_path}. Use --generate to create it.")
            sys.exit(1)

    formatted_key = format_ssh_key_for_gcp(pub_key_path, args.username)
    fingerprint = get_instance_metadata(token, args.project, args.zone, args.instance)
    update_instance_metadata(token, args.project, args.zone, args.instance, fingerprint, formatted_key)
    verify_key_uploaded(token, args.project, args.zone, args.instance, args.username)

if __name__ == "__main__":
    main()
