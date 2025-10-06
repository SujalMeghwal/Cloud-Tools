import argparse
import subprocess
import os
import json
import re
import base64
import platform

from rich import print
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax

console = Console()

LONG_VALUE_THRESHOLD = 3500  # Threshold to determine "long" values, adjust as needed


# All available checks
CHECKS = {
    "sa": {
        "description": "Service Account Info",
        "cmd": (
            "gcloud compute instances describe {instance} "
            "--zone={zone} --project={project} "
            '--format="json(serviceAccounts)"'
        )
    },
    "ips": {
        "description": "Public & Internal IPs",
        "cmd": (
            "gcloud compute instances describe {instance} "
            "--zone={zone} --project={project} "
            '--format="value(networkInterfaces[0].networkIP,networkInterfaces[0].accessConfigs[0].natIP)"'
        )
    },
    "tags": {
        "description": "Firewall Tags",
        "cmd": (
            "gcloud compute instances describe {instance} "
            "--zone={zone} --project={project} "
            '--format="value(tags.items)"'
        )
    },
    "disks": {
        "description": "Attached Disks",
        "cmd": (
            "gcloud compute instances describe {instance} "
            "--zone={zone} --project={project} "
            '--format="table(disks.deviceName,disks.boot,disks.source)"'
        )
    },
        "startup_script": {
        "description": "Startup Script (raw)",
        "cmd": (
            "gcloud compute instances describe {instance} "
            "--zone={zone} --project={project} "
            '--flatten=metadata.items[] '
            '--format="table[no-heading](metadata.items.key, metadata.items.value)"'
        )
    },
    "metadata": {
        "description": "Full Metadata (raw JSON)",
        "cmd": (
            "gcloud compute instances describe {instance} "
            "--zone={zone} --project={project} "
            '--format="json(metadata)"'
        )
    },
}

def run_subprocess(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[red]Error: {e.stderr.strip()}[/red]")
        return None


def ping_host(ip, count=1, timeout=1):
    system = platform.system().lower()
    if system == "windows":
        cmd = f"ping -n {count} -w {timeout * 1000} {ip}"
    else:
        cmd = f"ping -c {count} -W {timeout} {ip}"
    try:
        subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False



def sanitize_filename(name):
    clean = re.sub(r'[\\/*?:"<>|]', "_", name)
    clean = clean.strip().replace(" ", "_").lower()
    return clean

def detect_extension(value):
    stripped = value.strip()

    # Shebang or shell scripts
    if stripped.startswith("#!") or "bash" in stripped or "sh " in stripped:
        return ".sh"

    # Kubernetes YAML
    if stripped.startswith("apiVersion") or "kind:" in stripped or re.search(r"\bmetadata:\b", stripped):
        return ".yaml"

    # JSON
    if stripped.startswith("{") or stripped.startswith("["):
        return ".json"

    # GCP/GKE-style key=value string (comma-separated or semicolon-separated)
    if re.fullmatch(r"(?:[\w\-/\.]+=[^\n=]+[,;\n]?)+", stripped):
        return ".env"

    # Environment-style config (KEY: value)
    if re.search(r"^[A-Z0-9_]+:\s+.+", stripped, re.MULTILINE):
        return ".yaml"

    # Multi-line KUBELET_ARGS or long ENV config blocks
    if re.search(r"--[a-z0-9-]+=.*", stripped):
        return ".conf"

    # Looks like a certificate or base64 blob
    if len(stripped) > 100 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n" for c in stripped):
        try:
            base64.b64decode(stripped, validate=True)
            return ".crt"
        except Exception:
            pass

    return ".txt"


def save_metadata_separately(metadata_dict, base_output_dir):
    metadata_folder = os.path.join(base_output_dir, "metadata")
    extracted_dir = os.path.join(metadata_folder, "extracted")
    os.makedirs(extracted_dir, exist_ok=True)

    short_items = []

    items = metadata_dict.get("items", [])

    for item in items:
        key = item.get("key")
        value = item.get("value", "")

        if len(value) > 100:  # You can change threshold if needed
            ext = detect_extension(value)
            filename = sanitize_filename(key) + ext
            filepath = os.path.join(extracted_dir, filename)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(value)
            print(f"[blue]Extracted: {key} ➜ {filepath}[/blue]")
        else:
            short_items.append({"key": key, "value": value})

    return {"fingerprint": metadata_dict.get("fingerprint", ""), "items": short_items}





def run_command(label, command, silent=False):
    console.rule(f"[bold blue]{label}")
    try:
        result = subprocess.run(
            command, shell=True, check=True, capture_output=True, text=True
        )
        output = result.stdout.strip()

        if not output:
            if not silent:
                print("[yellow]No data returned.[/yellow]")
            return ""
        if silent:
            return output

        if label.lower() == "service account info":
            try:
                data = json.loads(output)
                accounts = data.get("serviceAccounts", [])
                if not accounts:
                    print("[yellow]No service accounts found.[/yellow]")
                    return output

                table = Table("Email", "Scopes", show_lines=True, expand=True)
                for sa in accounts:
                    email = sa.get("email", "")
                    scopes = sa.get("scopes", [])
                    scopes_str = ", ".join([s.split("/")[-1] for s in scopes])
                    table.add_row(email, scopes_str)
                console.print(table)
                return output
            except Exception as e:
                print(f"[red]Failed to parse service account info: {e}[/red]")
                print(output)
                return output

        if label.lower() == "public & internal ips":
            parts = output.split()
            if len(parts) >= 2:
                data = {"internal_ip": parts[0], "external_ip": parts[1]}
                table = Table("Internal IP", "External IP", show_lines=True, expand=True)
                table.add_row(data["internal_ip"], data["external_ip"])
                console.print(table)
                return data  # return dict instead of string

        if label.lower() == "firewall tags":
            tags = output.splitlines()
            if tags:
                table = Table("Firewall Tags", show_lines=True, expand=True)
                for tag in tags:
                    table.add_row(tag)
                console.print(table)
                return tags  # return list instead of string

        if label.lower() == "attached disks":
            disks = {}
            for line in output.splitlines():
                m = re.match(r"(\w+): \[(.*)\]", line)
                if m:
                    key = m.group(1)
                    items_raw = m.group(2)
                    items = [x.strip().strip("'\"") for x in items_raw.split(",")]
                    disks[key] = items

            if disks:
                keys = list(disks.keys())
                num_rows = len(disks[keys[0]])
                table = Table(*keys, show_lines=True, expand=True)
                for i in range(num_rows):
                    row = [disks[key][i] if i < len(disks[key]) else "" for key in keys]
                    table.add_row(*row)
                console.print(table)
                return disks  # return dict

        # Try pretty print JSON output as fallback
        try:
            parsed_json = json.loads(output)
            syntax = Syntax(
                json.dumps(parsed_json, indent=2),
                "json",
                theme="monokai",
                word_wrap=True
            )
            console.print(syntax)
            return output
        except json.JSONDecodeError:
            pass

        print(output)
        return output

    except subprocess.CalledProcessError as e:
        if not silent:
            print(f"[red]Error running command:[/red] {e.stderr.strip()}")
        return f"ERROR: {e.stderr.strip()}"

def main():
    parser = argparse.ArgumentParser(
        description="GCP VM Inspector - Auto-discover and inspect multiple VMs"
    )

    parser.add_argument("--project", required=True, help="GCP project ID")
    parser.add_argument(
        "--checks",
        help=f"Comma-separated list of checks to run ({', '.join(CHECKS.keys())})"
    )
    parser.add_argument("--all", action="store_true", help="Run all checks")
    parser.add_argument("--output-dir", help="Directory to save output files")

    args = parser.parse_args()
    project = args.project
    if args.all:
        selected_checks = list(CHECKS.keys())
    elif args.checks:
        selected_checks = args.checks.split(",")
    else:
        # Default to all checks if no args passed, so interactive works
        selected_checks = list(CHECKS.keys())

    invalid = [chk for chk in selected_checks if chk not in CHECKS]
    if invalid:
        print(f"[red]Invalid check(s): {', '.join(invalid)}[/red]")
        print(f"Available checks: {', '.join(CHECKS.keys())}")
        return

    # Step 1: Fetch instance list
    list_cmd = f"gcloud compute instances list --project={project} --format=json"
    raw_output = run_subprocess(list_cmd)
    if not raw_output:
        print("[red]Failed to retrieve instance list.[/red]")
        return

    try:
        instances = json.loads(raw_output)
    except Exception as e:
        print(f"[red]Failed to parse instance list: {e}[/red]")
        return

    if not instances:
        print("[yellow]No instances found.[/yellow]")
        return

    # Step 2: Display table
    table = Table(title="Available Instances", show_lines=True, expand=True)
    table.add_column("Index", justify="left")
    table.add_column("Name")
    table.add_column("Zone")
    table.add_column("Status")
    table.add_column("Internal IP")
    table.add_column("External IP")
    table.add_column("Ping")
    table.add_column("Machine Type")
    table.add_column("Preemptible")

    index_map = {}
    for idx, inst in enumerate(instances, 1):
        name = inst["name"]
        zone = inst["zone"].split("/")[-1]
        status = inst.get("status", "")
        int_ip = inst.get("networkInterfaces", [{}])[0].get("networkIP", "")
        ext_ip = inst.get("networkInterfaces", [{}])[0].get("accessConfigs", [{}])[0].get("natIP", "")
        machine_type = inst.get("machineType", "").split("/")[-1] if inst.get("machineType") else "Unknown"
        scheduling = inst.get("scheduling", {})
        preemptible = scheduling.get("preemptible", False)

        ping_status = "-"
        if ext_ip:
            ping_status = "[green]Yes[/green]" if ping_host(ext_ip) else "[red]No[/red]"

        table.add_row(
            str(idx),
            name,
            zone,
            status,
            int_ip,
            ext_ip,
            ping_status,
            machine_type,
            "Yes" if preemptible else "No"
        )

        index_map[str(idx)] = {"name": name, "zone": zone}

    console.print(table)

    # Step 3: Ask user which VMs to inspect
    choices = Prompt.ask(
        "Enter instance index(es) separated by comma, or type [bold green]all[/bold green] to inspect all",
        default="all"
    )

    selected_instances = []
    if choices.strip().lower() == "all":
        selected_instances = list(index_map.values())
    else:
        for choice in choices.split(","):
            entry = index_map.get(choice.strip())
            if entry:
                selected_instances.append(entry)

    if not selected_instances:
        print("[red]No valid instances selected.[/red]")
        return

    # Step 4: Ask for output directory
    output_dir = args.output_dir or Prompt.ask("Enter base output folder", default="output")


    for inst in selected_instances:
        name = inst["name"]
        zone = inst["zone"]

        print(f"\n[bold blue]Inspecting VM: {name} (zone: {zone})[/bold blue]")

        for check_key in selected_checks:  # ← THIS must be inside the instance loop
            info = CHECKS[check_key]
            command = info["cmd"].format(instance=name, zone=zone, project=project)
            description = info["description"]
            silent = check_key in ["metadata", "startup_script"]
            result = run_command(description, command, silent=silent)

            if not result:
                print(f"[yellow]No data to save for {check_key}[/yellow]")
                continue

            vm_folder = f"{name}_{zone}"
            save_path = os.path.join(output_dir, project, vm_folder)
            os.makedirs(save_path, exist_ok=True)
            metadata_dir = os.path.join(save_path, "metadata")
            os.makedirs(metadata_dir, exist_ok=True)

            if check_key == "metadata":
                # Try parsing raw JSON string
                try:
                    parsed = json.loads(result)
                    metadata = parsed.get("metadata", {})
                except Exception as e:
                    print(f"[red]Failed to parse metadata: {e}[/red]")
                    continue

                # Save long values separately and keep short ones in summary
                cleaned_metadata = save_metadata_separately(metadata, save_path)

                # Save summary to metadata/metadata.json
                metadata_dir = os.path.join(save_path, "metadata")
                os.makedirs(metadata_dir, exist_ok=True)

                summary_path = os.path.join(metadata_dir, "metadata.json")
                with open(summary_path, "w", encoding="utf-8") as f:
                    json.dump({"metadata": cleaned_metadata}, f, indent=2)

                print(f"[green]Saved metadata summary ➜ {summary_path}[/green]")
                continue  # skip the normal save block

            elif check_key == "startup_script":
                # Your existing saving logic for startup_script (just save raw)
                filepath = os.path.join(save_path, "startup_script.txt")
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(result if isinstance(result, str) else str(result))
                print(f"[green]Saved startup_script output to: {filepath}[/green]")

            else:
                # For all other checks, save as JSON or text as before
                ext = ".json"
                safe_check = check_key.replace("-", "_")
                filename = f"{safe_check}{ext}"
                filepath = os.path.join(save_path, filename)

                with open(filepath, "w", encoding="utf-8") as f:
                    if isinstance(result, (dict, list)):
                        json.dump(result, f, indent=2)
                    else:
                        try:
                            parsed = json.loads(result)
                            json.dump(parsed, f, indent=2)
                        except json.JSONDecodeError:
                            f.write(result)

                print(f"[green]Saved {check_key} output to: {filepath}[/green]")

if __name__ == "__main__":
    main()