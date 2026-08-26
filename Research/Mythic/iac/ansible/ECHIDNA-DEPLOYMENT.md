# Echidna Smart Contract Fuzzing - Deployment Guide

## Overview
Echidna is an advanced smart contract property-based fuzzer for finding Ethereum/EVM contract vulnerabilities.

**Use Case:** Offensive security testing of blockchain applications, contract exploitation research, and vulnerability discovery.

## Deployment

### Enable Echidna
Add to your inventory or command line:
```bash
ansible-playbook 0-site.yml -i inventory/production.ini -e enable_echidna=true -t echidna
```

### Post-Deployment Setup

```bash
# SSH to target VM
ssh localuser@10.23.20.10

# Verify Echidna installation
echidna --version

# Workspace location
cd /var/echidna

# Directory structure
ls -la
# contracts/     - Place target smart contracts here
# config.yaml    - Fuzzing configuration
# corpus/        - Test corpus and findings
```

## Usage

### Run Fuzzing on a Contract
```bash
echidna contracts/MyContract.sol --contract MyContract --config config.yaml
```

### Output
- Violation findings
- Property test results
- Corpus (test cases that triggered bugs)
- Coverage metrics

## Integration with Mythic

Echidna runs on the same infrastructure as Mythic C2:
- **Mythic (10.23.20.10):** Main C2 server + Echidna fuzzer
- **Redirector (192.168.36.117):** Callback routing

Use Mythic's payload delivery to deploy contracts to target environments, then use Echidna for automated vulnerability discovery.

## Configuration
Edit `/var/echidna/config.yaml`:
```yaml
testLimit: 50000          # Number of transactions to test
timeout: 30               # Timeout per property
workers: 4                # Parallel workers
seed: 1337                # Random seed
```

## Advanced Features
- Property-based testing
- Corpus minimization
- Coverage analysis
- Custom test oracles
- Corpus seeding from previous runs
