#!/usr/bin/env bash
#
# RED TEAM DEMO - Setup Script
# ============================
# Sets up the environment for the supply chain attack demonstration.
#
# Usage:
#     ./setup.sh              # Full setup
#     ./setup.sh --deps-only  # Only install dependencies
#     ./setup.sh --clean      # Cleanup demo artifacts
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$DEMO_ROOT/.venv"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

banner() {
    echo -e "${RED}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              RED TEAM DEMO - Setup Script                    ║"
    echo "║           Supply Chain Attack Demonstration                  ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║         FOR EDUCATIONAL PURPOSES ONLY                        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[!]${NC} $1"
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing=()
    
    # Python 3
    if ! command -v python3 &> /dev/null; then
        missing+=("python3")
    fi
    
    # pip
    if ! command -v pip3 &> /dev/null; then
        missing+=("pip3")
    fi
    
    # curl
    if ! command -v curl &> /dev/null; then
        missing+=("curl")
    fi
    
    # xxd (usually comes with vim)
    if ! command -v xxd &> /dev/null; then
        missing+=("xxd (vim)")
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing dependencies: ${missing[*]}"
        echo "Please install them before continuing."
        exit 1
    fi
    
    log_success "All dependencies found"
}

setup_venv() {
    log_info "Setting up Python virtual environment..."
    
    if [ -d "$VENV_DIR" ]; then
        log_warn "Virtual environment already exists"
    else
        python3 -m venv "$VENV_DIR"
        log_success "Virtual environment created: $VENV_DIR"
    fi
    
    # Activate and install dependencies
    source "$VENV_DIR/bin/activate"
    
    log_info "Installing Python packages..."
    pip install --quiet --upgrade pip
    pip install --quiet flask requests
    
    log_success "Python packages installed"
}

setup_demo_project() {
    log_info "Setting up demo Xcode project..."
    
    DEMO_PROJECT="$DEMO_ROOT/demo_project"
    
    if [ -d "$DEMO_PROJECT" ]; then
        log_warn "Demo project already exists, skipping"
        return
    fi
    
    # Check if we have the extracted_zip from the original exercise
    ORIGINAL_PROJECT="$(dirname "$DEMO_ROOT")/extracted_zip/starter-project"
    
    if [ -d "$ORIGINAL_PROJECT" ]; then
        log_info "Copying original project..."
        cp -r "$ORIGINAL_PROJECT" "$DEMO_PROJECT"
        log_success "Demo project created from original"
    else
        log_warn "Original project not found, creating minimal structure"
        mkdir -p "$DEMO_PROJECT/DemoApp.xcodeproj/xcuserdata"
        
        # Create minimal project.pbxproj
        cat > "$DEMO_PROJECT/DemoApp.xcodeproj/project.pbxproj" << 'PBXPROJ'
// !$*UTF8*$!
{
    archiveVersion = 1;
    classes = { };
    objectVersion = 56;
    objects = {
/* Begin PBXNativeTarget section */
        DEMO123456789 /* DemoApp */ = {
            isa = PBXNativeTarget;
            buildConfigurationList = DEMO_CONFIG_LIST;
            buildPhases = (
                DEMO_SOURCES /* Sources */,
                DEMO_FRAMEWORKS /* Frameworks */,
            );
            name = DemoApp;
            productName = DemoApp;
            productType = "com.apple.product-type.application";
        };
/* End PBXNativeTarget section */
/* Begin PBXTargetDependency section */
/* End PBXTargetDependency section */
/* Begin XCBuildConfiguration section */
        DEMO_DEBUG /* Debug */ = {
            isa = XCBuildConfiguration;
            buildSettings = {
                ENABLE_TESTABILITY = YES;
                ENABLE_USER_SCRIPT_SANDBOXING = YES;
            };
            name = Debug;
        };
/* End XCBuildConfiguration section */
    };
    rootObject = DEMO_PROJECT;
}
PBXPROJ
        log_success "Minimal demo project created"
    fi
}

create_demo_artifacts_dir() {
    log_info "Creating demo artifacts directory..."
    
    mkdir -p /tmp/redteam_demo
    chmod 777 /tmp/redteam_demo
    
    log_success "Demo artifacts directory: /tmp/redteam_demo"
}

generate_scripts() {
    log_info "Making scripts executable..."
    
    chmod +x "$DEMO_ROOT/c2_server/c2_server.py" 2>/dev/null || true
    chmod +x "$DEMO_ROOT/payloads/payload_generator.py" 2>/dev/null || true
    chmod +x "$DEMO_ROOT/payloads/obfuscator.py" 2>/dev/null || true
    chmod +x "$DEMO_ROOT/xcode_implant/implant_xcode_project.py" 2>/dev/null || true
    chmod +x "$DEMO_ROOT/gitea_server/gitea_simulator.py" 2>/dev/null || true
    chmod +x "$DEMO_ROOT/git_hooks/git_implanter.py" 2>/dev/null || true
    chmod +x "$DEMO_ROOT/scripts/"*.sh 2>/dev/null || true
    
    log_success "Scripts made executable"
}

print_quickstart() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                     SETUP COMPLETE                            ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Quick Start Options:"
    echo ""
    echo -e "${CYAN}=== OPTION A: Xcode Supply Chain Attack ===${NC}"
    echo ""
    echo "  1. Start C2 Server:"
    echo -e "     ${YELLOW}source $VENV_DIR/bin/activate${NC}"
    echo -e "     ${YELLOW}python3 $DEMO_ROOT/c2_server/c2_server.py${NC}"
    echo ""
    echo "  2. Implant Demo Project (new terminal):"
    echo -e "     ${YELLOW}python3 $DEMO_ROOT/xcode_implant/implant_xcode_project.py \\${NC}"
    echo -e "     ${YELLOW}    --project $DEMO_ROOT/demo_project/*.xcodeproj \\${NC}"
    echo -e "     ${YELLOW}    --c2 http://localhost:8888${NC}"
    echo ""
    echo "  3. Open Xcode project and build (Cmd+B)"
    echo ""
    echo -e "${CYAN}=== OPTION B: Malicious Git Server Attack ===${NC}"
    echo ""
    echo "  1. Start C2 Server (terminal 1):"
    echo -e "     ${YELLOW}python3 $DEMO_ROOT/c2_server/c2_server.py${NC}"
    echo ""
    echo "  2. Start Gitea Simulator (terminal 2):"
    echo -e "     ${YELLOW}python3 $DEMO_ROOT/gitea_server/gitea_simulator.py --port 8080${NC}"
    echo ""
    echo "  3. Victim visits: http://localhost:8080/jargal.karlsen/starter-project"
    echo "     and downloads the trojanized ZIP"
    echo ""
    echo -e "${CYAN}=== OPTION C: Git Hooks Attack ===${NC}"
    echo ""
    echo "  1. Start C2 Server"
    echo "  2. Implant hooks into target repo:"
    echo -e "     ${YELLOW}python3 $DEMO_ROOT/git_hooks/git_implanter.py \\${NC}"
    echo -e "     ${YELLOW}    --repo /path/to/victim/repo --all --c2 http://localhost:8888${NC}"
    echo ""
    echo "  3. Hooks trigger on: git clone, git pull, git commit, git push"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  C2 Dashboard: http://localhost:8888/admin"
    echo "  Demo Artifacts: /tmp/redteam_demo/"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
}

cleanup() {
    log_info "Cleaning up demo artifacts..."
    
    # Remove demo artifacts
    rm -rf /tmp/redteam_demo
    rm -f /tmp/.demo_response.txt
    rm -f /tmp/.o.txt
    
    # Remove virtual environment
    if [ -d "$VENV_DIR" ]; then
        rm -rf "$VENV_DIR"
        log_success "Removed virtual environment"
    fi
    
    # Remove demo project
    if [ -d "$DEMO_ROOT/demo_project" ]; then
        rm -rf "$DEMO_ROOT/demo_project"
        log_success "Removed demo project"
    fi
    
    log_success "Cleanup complete"
}

# Parse arguments
case "${1:-}" in
    --deps-only)
        banner
        check_dependencies
        setup_venv
        ;;
    --clean)
        banner
        cleanup
        ;;
    --help|-h)
        banner
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --deps-only    Only install dependencies"
        echo "  --clean        Cleanup all demo artifacts"
        echo "  --help, -h     Show this help message"
        echo ""
        ;;
    *)
        banner
        check_dependencies
        setup_venv
        setup_demo_project
        create_demo_artifacts_dir
        generate_scripts
        print_quickstart
        ;;
esac
