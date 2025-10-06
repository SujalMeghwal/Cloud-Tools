import requests
import json

# --- Config ---
TOKEN_FILE = "token.txt"  # Your token file path

# --- Read token ---
with open(TOKEN_FILE, "r") as f:
    ACCESS_TOKEN = f.read().strip()

HEADERS = {
    "Authorization": f"Bearer {ACCESS_TOKEN}"
}

def who_am_i():
    url = f"https://oauth2.googleapis.com/tokeninfo?access_token={ACCESS_TOKEN}"
    resp = requests.get(url)
    if resp.status_code == 200:
        info = resp.json()
        print("[*] Token info:")
        print(json.dumps(info, indent=2))
    else:
        print("[!] Failed to get token info:", resp.text)

def list_projects():
    url = "https://cloudresourcemanager.googleapis.com/v1/projects"
    resp = requests.get(url, headers=HEADERS)
    if resp.status_code == 200:
        projects = resp.json().get("projects", [])
        print(f"[*] Found {len(projects)} projects:")
        for p in projects:
            print(f"  - {p['projectId']}: {p.get('name', '')}")
        return projects
    else:
        print("[!] Failed to list projects:", resp.text)
        return []

def list_service_accounts(project_id):
    url = f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts"
    resp = requests.get(url, headers=HEADERS)
    if resp.status_code == 200:
        accounts = resp.json().get("accounts", [])
        print(f"  [*] Service accounts in project {project_id}:")
        for a in accounts:
            print(f"    - {a['email']}")
    else:
        print(f"  [!] Failed to list service accounts for {project_id}: {resp.text}")

def get_iam_policy(project_id):
    url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:getIamPolicy"
    resp = requests.post(url, headers=HEADERS)
    if resp.status_code == 200:
        policy = resp.json()
        print(f"  [*] IAM Policy for project {project_id}:")
        bindings = policy.get("bindings", [])
        for b in bindings:
            role = b.get("role")
            members = b.get("members", [])
            print(f"    Role: {role}")
            for m in members:
                print(f"      Member: {m}")
    else:
        print(f"  [!] Failed to get IAM policy for {project_id}: {resp.text}")

def main():
    who_am_i()
    projects = list_projects()
    for p in projects:
        pid = p["projectId"]
        list_service_accounts(pid)
        get_iam_policy(pid)

if __name__ == "__main__":
    main()
