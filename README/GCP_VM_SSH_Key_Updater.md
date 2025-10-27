# 🖥️ GCP VM SSH Key Updater Script

A Python script to automate **generating SSH keys** and **injecting them into GCP VM instance metadata** via **Compute Engine API**.

---

## 📂 Features
- Generate **SSH key pairs** using `ssh-keygen`.
- Format SSH keys in **GCP-compliant** structure.
- Add/update SSH keys in **instance metadata**.
- Verify that keys were successfully uploaded.
- Use existing **access tokens** (no `gcloud` dependency).

---

## 📋 Requirements
- Python 3.x
- `requests` library (`pip install requests`)
- `ssh-keygen` command available (Linux/Mac by default)
- GCP OAuth 2.0 Access Token with **Compute Engine API** permissions.

---

## 🧑‍💻 Usage Instructions

### 1️⃣ Obtain Access Token
```bash
gcloud auth print-access-token > token.txt
```

### 2️⃣ Generate New SSH Key and Upload
```bash
python update_ssh_metadata.py \
  --project <PROJECT_ID> \
  --zone <ZONE> \
  --instance <INSTANCE_NAME> \
  --token token.txt \
  --username <YOUR_USERNAME> \
  --key-path ~/.ssh/<KEY_NAME> \
  --generate
```

### 3️⃣ Upload Existing SSH Key
```bash
python update_ssh_metadata.py \
  --project <PROJECT_ID> \
  --zone <ZONE> \
  --instance <INSTANCE_NAME> \
  --token token.txt \
  --username <YOUR_USERNAME> \
  --key-path ~/.ssh/<EXISTING_KEY>
```

---

## 🧩 Script Flow
```mermaid
flowchart TD
    A[Read Access Token] --> B{Generate SSH Key?}
    B -- Yes --> C[Generate SSH Keypair]
    B -- No --> D[Load Existing SSH Key]
    D --> E[Format SSH Key for GCP]
    C --> E
    E --> F[Fetch Instance Metadata (Fingerprint)]
    F --> G[Update Metadata with SSH Key]
    G --> H[Verify SSH Key Uploaded]
    H --> I[Done]
```

---

## 🛠️ Functions Breakdown
| Function                          | Purpose                                                                                       |
|------------------------------------|------------------------------------------------------------------------------------------------|
| `generate_ssh_keypair`             | Creates SSH keypair using `ssh-keygen` with optional passphrase.                              |
| `format_ssh_key_for_gcp`           | Formats the public key to GCP's metadata format (`username:ssh-rsa AAAA... username`).        |
| `read_token`                       | Reads the OAuth 2.0 access token from a file.                                                  |
| `get_instance_metadata`            | Retrieves instance metadata and fingerprint for safe updates.                                 |
| `update_instance_metadata`         | Updates VM metadata to inject the SSH key via GCP API.                                         |
| `verify_key_uploaded`              | Verifies that the SSH key was successfully uploaded to instance metadata.                     |

---

## > ⚠️ Important Notes
> - The script will **replace** all existing `ssh-keys` metadata.
> - Ensure your access token has **compute.instances.setMetadata** scope.
> - Changes may take a few seconds to propagate.
> - This does **NOT manage OS Login users** — only instance-level SSH keys.

---

## 🔧 Example Use Cases
- Temporary SSH key injection in CI/CD pipelines.
- Emergency access without using `gcloud` CLI.
- Automating SSH key distribution across ephemeral VMs.

---

## 📄 License
MIT License.
