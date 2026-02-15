#!/bin/bash
# SOCFortress CoPilot SIEM/SOAR Deployment Script
# Usage: ./deploy.sh [vm1|vm2|vm3|all]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IAC_DIR="$(dirname "$SCRIPT_DIR")"
ANSIBLE_DIR="$IAC_DIR/ansible"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

usage() {
    echo "Usage: $0 [OPTIONS] [TARGET]"
    echo ""
    echo "Targets:"
    echo "  vm1     Deploy SIEM-Data (Wazuh Indexer)"
    echo "  vm2     Deploy SIEM-CoPilot-Detect (Wazuh Manager, Graylog, MISP)"
    echo "  vm3     Deploy SIEM-CoPilot-Mgmt (CoPilot, Grafana, Velociraptor)"
    echo "  all     Deploy all VMs (default)"
    echo ""
    echo "Options:"
    echo "  -c, --check    Run in check mode (dry run)"
    echo "  -v, --verbose  Enable verbose output"
    echo "  -t, --tags     Run only tasks with specific tags"
    echo "  -h, --help     Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 all                    # Deploy entire stack"
    echo "  $0 vm1                    # Deploy only VM1"
    echo "  $0 -c vm2                 # Dry run VM2 deployment"
    echo "  $0 -t misp vm2            # Deploy only MISP on VM2"
}

# Parse arguments
CHECK_MODE=""
VERBOSE=""
TAGS=""
TARGET="all"

while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--check)
            CHECK_MODE="--check"
            shift
            ;;
        -v|--verbose)
            VERBOSE="-vvv"
            shift
            ;;
        -t|--tags)
            TAGS="--tags $2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        vm1|vm2|vm3|all)
            TARGET="$1"
            shift
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
done

# Check prerequisites
log "Checking prerequisites..."
command -v ansible-playbook >/dev/null 2>&1 || error "Ansible not installed. Run: pip install ansible"

# Determine limit
case $TARGET in
    vm1)
        LIMIT="vm1_siem_data"
        ;;
    vm2)
        LIMIT="vm2_siem_detect"
        ;;
    vm3)
        LIMIT="vm3_siem_mgmt"
        ;;
    all)
        LIMIT=""
        ;;
esac

# Build command
CMD="ansible-playbook -i $ANSIBLE_DIR/inventory/hosts.yml $ANSIBLE_DIR/site.yml"
[[ -n "$LIMIT" ]] && CMD="$CMD --limit $LIMIT"
[[ -n "$CHECK_MODE" ]] && CMD="$CMD $CHECK_MODE"
[[ -n "$VERBOSE" ]] && CMD="$CMD $VERBOSE"
[[ -n "$TAGS" ]] && CMD="$CMD $TAGS"

log "Deploying target: $TARGET"
log "Running: $CMD"
echo ""

# Execute
$CMD

log "Deployment complete!"
