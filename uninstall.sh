#!/bin/bash

# Script version
VERSION="1.0.0"
START_TIME=$(date +%s)

# Enable debug mode with --debug flag
DEBUG_MODE=0
[ "$1" = "--debug" ] && DEBUG_MODE=1

# Define colors
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
RESET=$(tput sgr0)

# Variables
TOOLS_DIR="$HOME/tools"
VENV_DIR="$HOME/bugbounty_venv"
LOG_FILE="$HOME/chaathan_uninstall.log"
GO_PATH="/usr/local/go"
BASH_PROFILE="$HOME/.bash_profile"

# Centralized logging function with levels
log() {
    local level="$1" msg="$2"
    local color timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        INFO)  color="$GREEN" ;;
        WARN)  color="$YELLOW" ;;
        ERROR) color="$RED" ;;
        DEBUG) color="$BLUE" ;;
        *)     color="$RESET" ;;
    esac
    
    # Only log DEBUG if debug mode is enabled
    [ "$level" = "DEBUG" ] && [ "$DEBUG_MODE" -ne 1 ] && return
    
    # Plain text to log file
    echo "$timestamp [$level] $msg" >> "$LOG_FILE"
    # Colored output to console (stdout)
    printf "${color}%s${RESET}\n" "$timestamp [$level] $msg"
}

# Trap unexpected errors
trap 'log ERROR "Unexpected error occurred at line $LINENO. Exiting."; exit 1' ERR

# Execute command with error handling
execute() {
    local cmd="$1" desc="$2"
    log DEBUG "Executing command: $cmd for $desc"
    
    if eval "$cmd" >>"$LOG_FILE" 2>&1; then
        log INFO "$desc completed successfully"
        return 0
    else
        log WARN "$desc failed, continuing..."
        return 1
    fi
}

# Display banner
banner() {
    log INFO "Starting Chaathan Tools Uninstallation v$VERSION"
    echo "${RED} ######################################################### ${RESET}"
    echo "${RED} #              UNINSTALL TOOLS FOR BUG BOUNTY           # ${RESET}"
    echo "${RED} ######################################################### ${RESET}"
    echo "${BLUE}
      _____ _    _                 _______ _    _          _   _
     / ____| |  | |   /\        /\|__   __| |  | |   /\   | \ | |
    | |    | |__| |  /  \      /  \  | |  | |__| |  /  \  |  \| |
    | |    |  __  | / /\ \    / /\ \ | |  |  __  | / /\ \ |     |
    | |____| |  | |/ ____ \  / ____ \| |  | |  | |/ ____ \| |\  |
     \_____|_|  |_/_/    \_\/_/    \_\_|  |_|  |_/_/    \_\_| \_|

    ${RESET}"
    echo "${GREEN} Removing tools installed by the InfoSec Community script ${RESET}"
    echo "${GREEN}                   Cleaning up!                           ${RESET}"
}

# Uninstall tools
uninstall_tools() {
    log INFO "Starting uninstallation process"
    
    # Remove tools directory
    if [ -d "$TOOLS_DIR" ]; then
        execute "rm -rf $TOOLS_DIR" "Removing tools directory $TOOLS_DIR"
    else
        log INFO "Tools directory $TOOLS_DIR does not exist, skipping"
    fi
    
    # Remove virtual environment
    if [ -d "$VENV_DIR" ]; then
        execute "rm -rf $VENV_DIR" "Removing virtual environment $VENV_DIR"
    else
        log INFO "Virtual environment $VENV_DIR does not exist, skipping"
    fi
    
    # Remove Go installation
    if [ -d "$GO_PATH" ]; then
        execute "sudo rm -rf $GO_PATH" "Removing Go installation at $GO_PATH"
    else
        log INFO "Go installation at $GO_PATH does not exist, skipping"
    fi
    
    # Clean up Go binaries in $HOME/go/bin
    if [ -d "$HOME/go/bin" ]; then
        execute "rm -rf $HOME/go/bin" "Removing Go binaries in $HOME/go/bin"
    else
        log INFO "Go binaries directory $HOME/go/bin does not exist, skipping"
    fi
    
    # Remove specific binaries from /usr/local/bin
    local binaries=(
        "massdns" "subjack" "SubOver" "gobuster" "ffuf" "dalfox" "CORS-Scanner"
        "githound" "findomain" "subjs" "hakrawler" "gau" "gospider" "pdtm"
        "cf-check" "urlprobe" "amass" "knockknock" "metabigor"
    )
    for bin in "${binaries[@]}"; do
        if [ -f "/usr/local/bin/$bin" ]; then
            execute "sudo rm -f /usr/local/bin/$bin" "Removing $bin from /usr/local/bin"
        else
            log DEBUG "$bin not found in /usr/local/bin, skipping"
        fi
    done
    
    # Remove Go environment variables from bash_profile
    if [ -f "$BASH_PROFILE" ]; then
        log INFO "Cleaning up Go environment variables from $BASH_PROFILE"
        execute "sed -i '/# Set Go environment variables/,/export PATH=\$PATH:\$GOROOT\/bin:\$GOPATH\/bin/d' $BASH_PROFILE" "Removing Go env vars from $BASH_PROFILE"
        # Reload bash_profile to apply changes immediately (optional)
        source "$BASH_PROFILE" || log WARN "Failed to reload $BASH_PROFILE"
    else
        log WARN "$BASH_PROFILE not found, skipping environment cleanup"
    fi
    
    # Remove installed packages (optional, requires manual confirmation for safety)
    log INFO "Note: System-wide packages (e.g., apt, pip, gem, npm) are not removed by default to avoid breaking dependencies."
    log INFO "To remove them manually, run:"
    log INFO "  sudo apt remove apt-transport-https curl git jq ruby-full build-essential ..."
    log INFO "  pip3 uninstall py-altdns dirsearch spyse.py ..."
    log INFO "  gem uninstall XSpear wpscan ..."
    log INFO "  npm uninstall -g broken-link-checker ..."
}

# Main function
main() {
    banner
    uninstall_tools
    
    # Summary
    END_TIME=$(date +%s)
    ELAPSED=$((END_TIME - START_TIME))
    log INFO "Uninstallation completed in $((ELAPSED / 60)) minutes and $((ELAPSED % 60)) seconds"
    log INFO "Check $LOG_FILE for details"
    log INFO "Manually verify and remove any remaining system packages if needed"
}

# Run main
main