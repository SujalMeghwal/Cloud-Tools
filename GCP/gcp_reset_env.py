#!/usr/bin/env python3

import os
import platform
import shutil
from pathlib import Path


def remove_path(target: Path, description: str):
    try:
        if target.is_file():
            target.unlink()
            print(f"[+] Removed file: {description}")
        elif target.is_dir():
            shutil.rmtree(target, ignore_errors=True)
            print(f"[+] Removed directory: {description}")
        else:
            print(f"[-] Path does not exist: {description}")
    except Exception as e:
        print(f"[!] Failed to remove {description}: {e}")


def get_gcloud_path():
    if platform.system() == "Windows":
        base = os.environ.get("APPDATA", "")
        return Path(base) / "gcloud"
    else:
        return Path.home() / ".config" / "gcloud"


def nuke_gcloud_config():
    gcloud_dir = get_gcloud_path()
    remove_path(gcloud_dir, str(gcloud_dir))


def nuke_adc_credentials():
    creds_file = get_gcloud_path() / "application_default_credentials.json"
    remove_path(creds_file, str(creds_file))


def main():
    print("[*] Starting GCP environment cleanup...")
    nuke_gcloud_config()
    nuke_adc_credentials()
    print("[*] Cleanup complete. GCP environment reset.\n")


if __name__ == "__main__":
    main()
