#!/bin/bash

# Script version
VERSION="1.1.1"
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
GO_VERSION="1.24.1"
LOG_FILE="$HOME/chaathan_install.log"
APT_PACKAGES="apt-transport-https curl git jq ruby-full build-essential libcurl4-openssl-dev libssl-dev libxml2-dev libxslt1-dev libgmp-dev zlib1g-dev libffi-dev python3-dev python3-pip python3-venv npm nmap perl parallel ffuf wfuzz"
FAILED_TOOLS=()
SUCCESSFUL_TOOLS=()

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

# Execute command with retries
execute() {
    local cmd="$1" desc="$2" retries=${3:-3}
    local attempt=1 rc=0
    log DEBUG "Executing command: $cmd for $desc"
    
    while [ $attempt -le $retries ]; do
        if eval "$cmd" >>"$LOG_FILE" 2>&1; then
            log INFO "$desc completed successfully"
            return 0
        fi
        rc=$?
        log WARN "$desc failed on attempt $attempt/$retries (exit code: $rc)"
        ((attempt++))
        sleep 5
    done
    log ERROR "$desc failed after $retries retries, skipping..."
    return 1
}

# Check for critical dependencies
check_prerequisites() {
    local deps=("git" "curl" "python3" "pip3")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            log ERROR "Missing critical dependency: $dep. Please install it manually."
            exit 1
        fi
        log DEBUG "$dep is installed"
    done
}

# Setup Python environment
setup_environment() {
    local os
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        os=$ID
        log INFO "Detected OS: $os"
    else
        os="unknown"
        log WARN "Cannot detect OS, defaulting to system Python"
    fi
    
    if [ "$os" = "ubuntu" ]; then
        log INFO "Setting up virtual environment for Ubuntu"
        execute "python3 -m venv $VENV_DIR" "Creating virtual environment in $VENV_DIR" || return 1
        source "$VENV_DIR/bin/activate" || { log ERROR "Failed to activate virtual environment"; return 1; }
        PIP_CMD="$VENV_DIR/bin/pip"
        PYTHON_CMD="$VENV_DIR/bin/python3"
        execute "$PIP_CMD install --upgrade pip setuptools" "Upgrading pip and installing setuptools in venv" || return 1
    else
        log INFO "Using system Python for $os"
        execute "python3 -m ensurepip --upgrade && python3 -m pip install --upgrade pip setuptools" "Ensuring pip and setuptools for system Python" || return 1
        PIP_CMD="pip3"
        PYTHON_CMD="python3"
    fi
    OS="$os"
}

# Install packages
install_packages() {
    local type="$1" packages="$2" desc="$3"
    local install_desc="Installing $packages via $type ($desc)"
    
    case $type in
        apt) execute "sudo apt -y install $packages" "$install_desc" ;;
        pip) execute "$PIP_CMD install $packages" "$install_desc" ;;
        gem) execute "sudo gem install $packages" "$install_desc" ;;
        npm) execute "sudo npm install -g $packages" "$install_desc" ;;
        go)
            execute "go install -v $packages@latest" "$install_desc" && \
            if [ -f "$HOME/go/bin/$(basename $packages)" ]; then
                execute "sudo cp $HOME/go/bin/$(basename $packages) /usr/local/bin/" "Copying $(basename $packages) to /usr/local/bin" || \
                log WARN "Failed to copy $(basename $packages) to /usr/local/bin"
        fi ;;
    esac
    [ $? -eq 0 ] && SUCCESSFUL_TOOLS+=("$desc") || FAILED_TOOLS+=("$desc")
}

# Clone and setup Git repo
clone_and_setup() {
    local repo="$1" dir="$2" setup_cmd="$3"
    local clone_desc="Cloning $repo to $dir"
    local setup_desc="Setting up $dir"
    
    if [ -d "$dir" ]; then
        log INFO "Removing existing directory $dir for fresh clone"
        execute "rm -rf $dir" "Removing directory $dir" || return 1
    fi
    if execute "git clone $repo $dir" "$clone_desc"; then
        SUCCESSFUL_TOOLS+=("$clone_desc")
        if [ -n "$setup_cmd" ]; then
            cd "$dir" || { log ERROR "Failed to cd into $dir"; FAILED_TOOLS+=("$setup_desc"); return 1; }
            execute "$setup_cmd" "$setup_desc" && SUCCESSFUL_TOOLS+=("$setup_desc") || FAILED_TOOLS+=("$setup_desc")
            cd - >/dev/null || log WARN "Failed to return to previous directory"
        fi
    else
        FAILED_TOOLS+=("$clone_desc")
    fi
}

# Display banner
banner() {
    log INFO "Starting Chaathan Tools Installation v$VERSION"
    echo "${RED} ######################################################### ${RESET}"
    echo "${RED} #                 TOOLS FOR BUG BOUNTY                  # ${RESET}"
    echo "${RED} ######################################################### ${RESET}"
    echo "${BLUE}
      _____ _    _                 _______ _    _          _   _
     / ____| |  | |   /\        /\|__   __| |  | |   /\   | \ | |
    | |    | |__| |  /  \      /  \  | |  | |__| |  /  \  |  \| |
    | |    |  __  | / /\ \    / /\ \ | |  |  __  | / /\ \ |     |
    | |____| |  | |/ ____ \  / ____ \| |  | |  | |/ ____ \| |\  |
     \_____|_|  |_/_/    \_\/_/    \_\_|  |_|  |_/_/    \_\_| \_|

    ${RESET}"
    echo "${GREEN} Tools created by the best people in the InfoSec Community ${RESET}"
    echo "${GREEN}                   Thanks to everyone!                     ${RESET}"
}

# Install all tools
install_tools() {
    log INFO "Installing base dependencies and tools"
    
    execute "sudo apt -y update && sudo apt -y upgrade" "Updating and upgrading system packages"
    install_packages apt "$APT_PACKAGES" "Base dependencies installation"
    execute "curl -sL https://git.io/vokNn | sudo bash -" "Installing apt-fast"
    
    # Install Go
    if [ ! -d "/usr/local/go" ]; then
        execute "wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz -O go.tar.gz" "Downloading Go $GO_VERSION"
        execute "sudo tar -C /usr/local -xzf go.tar.gz && rm go.tar.gz" "Extracting Go to /usr/local"
        echo '# Set Go environment variables
        export GOROOT=/usr/local/go
        export GOPATH=$HOME/go
        export PATH=$PATH:$GOROOT/bin:$GOPATH/bin' > ~/.bash_profile
        export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    else
        log INFO "Golang is already installed"
    fi
    [ -f ~/.bash_profile ] && source ~/.bash_profile || log WARN "bash_profile not found, PATH not updated"
    
    mkdir -p "$TOOLS_DIR" && cd "$TOOLS_DIR" || { log ERROR "Failed to create tools directory"; return 1; }
    
    log INFO "#################### Installing Tools ####################"
    
    # Basic Tools
    install_packages pip "py-altdns" "py-altdns installation"
    install_packages apt "nmap sqlmap" "nmap and sqlmap installation"
    clone_and_setup "https://github.com/guelfoweb/knock.git" "knockpy" "$PYTHON_CMD setup.py install"
    install_packages go "github.com/harleo/knockknock" "knockknock installation"
    clone_and_setup "https://github.com/yassineaboukir/asnlookup.git" "asnlookup" "$PIP_CMD install -r requirements.txt"
    install_packages go "github.com/j3ssie/metabigor" "metabigor installation"
    
    # Fuzzing Tools
    install_packages go "github.com/OJ/gobuster/v3" "gobuster installation"
    install_packages go "github.com/ffuf/ffuf" "ffuf installation"
    install_packages pip "dirsearch" "dirsearch installation"
    
    # Domain Enum Tools
    clone_and_setup "https://github.com/nsonaniya2010/SubDomainizer.git" "SubDomainizer" "$PIP_CMD install -r requirements.txt"
    clone_and_setup "https://github.com/eldraco/domain_analyzer.git" "domain_analyzer" ""
    clone_and_setup "https://github.com/blechschmidt/massdns.git" "massdns" "make && sudo cp bin/massdns /usr/local/bin/"
    clone_and_setup "https://github.com/cihanmehmet/sub.sh.git" "subsh" "chmod +x sub.sh"
    install_packages go "github.com/haccer/subjack" "subjack installation"
    clone_and_setup "https://github.com/aboul3la/Sublist3r.git" "Sublist3r" "$PIP_CMD install -r requirements.txt"
    install_packages go "github.com/Ice3man543/SubOver" "SubOver installation"
    install_packages pip "spyse.py" "spyse.py installation"
    
    # CORS Tools
    clone_and_setup "https://github.com/s0md3v/Corsy.git" "corsy" "$PIP_CMD install -r requirements.txt"
    clone_and_setup "https://github.com/chenjj/CORScanner.git" "corscanner" "$PIP_CMD install -r requirements.txt"
    install_packages go "github.com/Tanmay-N/CORS-Scanner" "CORS-Scanner installation"
    
    # XSS Tools
    clone_and_setup "https://github.com/hahwul/dalfox.git" "dalfox" "go build && sudo cp dalfox /usr/local/bin/"
    clone_and_setup "https://github.com/s0md3v/XSStrike.git" "XSStrike" "$PIP_CMD install -r requirements.txt"
    install_packages gem "XSpear colorize selenium-webdriver terminal-table progress_bar" "XSpear and dependencies"
    clone_and_setup "https://github.com/M4cs/traxss.git" "traxss" "$PIP_CMD install -r requirements.txt"
    
    # Cloud Workflow Tools
    if command -v aws >/dev/null 2>&1 || [ -d "/usr/local/aws-cli" ]; then
        log INFO "AWS CLI is already installed, skipping installation"
    else
        log INFO "Installing AWS CLI"
        execute "curl -s https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip && unzip -o -q awscliv2.zip && sudo ./aws/install && rm -rf aws awscliv2.zip" "Installing AWS CLI"
    fi
    clone_and_setup "https://github.com/gwen001/s3-buckets-finder.git" "s3-buckets-finder" ""
    clone_and_setup "https://github.com/nahamsec/lazys3.git" "lazys3" ""
    clone_and_setup "https://github.com/securing/DumpsterDiver.git" "DumpsterDiver" "$PIP_CMD install -r requirements.txt"
    clone_and_setup "https://github.com/sa7mon/S3Scanner.git" "S3Scanner" "$PIP_CMD install -r requirements.txt"
    clone_and_setup "https://github.com/christophetd/CloudFlair.git" "CloudFlair" "$PIP_CMD install -r requirements.txt"
    clone_and_setup "https://github.com/greycatz/CloudUnflare.git" "CloudUnflare" ""
    clone_and_setup "https://github.com/fellchase/flumberboozle.git" "flumberboozle" ""
    clone_and_setup "https://github.com/RhinoSecurityLabs/GCPBucketBrute.git" "GCPBucketBrute" "$PIP_CMD install -r requirements.txt"
    
    # CMS Tools
    clone_and_setup "https://github.com/Dionach/CMSmap.git" "CMS/CMSmap" "$PIP_CMD install ."
    clone_and_setup "https://github.com/jekyc/wig.git" "CMS/wig" "$PYTHON_CMD setup.py install"
    clone_and_setup "https://github.com/rezasp/joomscan.git" "CMS/Joomscan" ""
    install_packages gem "wpscan" "wpscan installation"
    install_packages pip "droopescan" "droopescan installation"
    clone_and_setup "https://github.com/immunIT/drupwn.git" "CMS/drupwn" "$PYTHON_CMD setup.py install"
    clone_and_setup "https://github.com/0ang3el/aem-hacker.git" "CMS/aem-hacker" ""
    
    # Git Tools
    clone_and_setup "https://github.com/HightechSec/git-scanner.git" "GIT/git-scanner" "chmod +x gitscanner.sh"
    clone_and_setup "https://github.com/hisxo/gitGraber.git" "GIT/gitGraber" "$PIP_CMD install -r requirements.txt"
    clone_and_setup "https://github.com/tillson/git-hound.git" "GIT/git-hound" "go build -o githound main.go && sudo cp githound /usr/local/bin/"
    clone_and_setup "https://github.com/gwen001/github-search.git" "GIT/github-search" "$PIP_CMD install -r requirements.txt"
    
    # Frameworks
    clone_and_setup "https://github.com/1N3/Sn1per.git" "Frameworks/Sn1per" ""
    clone_and_setup "https://github.com/j3ssie/Osmedeus.git" "Frameworks/osmedeus" ""
    clone_and_setup "https://github.com/WhaleShark-Team/cobra.git" "Frameworks/Cobra" ""
    clone_and_setup "https://github.com/0xinfection/tidos-framework.git" "Frameworks/TIDoS-Framework" "chmod +x install"
    clone_and_setup "https://github.com/1N3/BlackWidow.git" "Frameworks/BlackWidow" ""
    clone_and_setup "https://github.com/screetsec/Sudomy.git" "Frameworks/Sudomy" "$PIP_CMD install -r requirements.txt && sudo npm i -g wappalyzer"
    execute "wget -q https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux -O findomain && chmod +x findomain && sudo mv findomain /usr/local/bin/" "Installing findomain"
    
    # Other Tools
    clone_and_setup "https://github.com/swisskyrepo/SSRFmap.git" "SSRFMap" "$PIP_CMD install -r requirements.txt"
    install_packages pip "xsrfprobe" "xsrfprobe installation"
    clone_and_setup "https://github.com/nahamsec/JSParser.git" "JSParser" "$PYTHON_CMD setup.py install"
    install_packages go "github.com/lc/subjs" "subjs installation"
    install_packages npm "broken-link-checker" "broken-link-checker installation"
    install_packages pip "pwncat" "pwncat installation"
    clone_and_setup "https://github.com/s0md3v/Photon.git" "Photon" "$PIP_CMD install -r requirements.txt"
    install_packages go "github.com/hakluke/hakrawler" "hakrawler installation" && sudo cp ~/go/bin/hakrawler /usr/local/bin/
    clone_and_setup "https://github.com/EnableSecurity/wafw00f.git" "wafw00f" "$PYTHON_CMD setup.py install"
    clone_and_setup "https://github.com/devanshbatham/ParamSpider.git" "ParamSpider" "$PIP_CMD install -r requirements.txt"
    clone_and_setup "https://github.com/joaomatosf/jexboss.git" "jexboss" "$PIP_CMD install -r requires.txt"
    clone_and_setup "https://github.com/1N3/Goohak.git" "Goohak" "chmod +x goohak"
    install_packages pip "webtech" "webtech installation"
    install_packages go "github.com/lc/gau/v2/cmd/gau" "gau installation"
    install_packages go "github.com/jaeles-project/gospider" "gospider installation"
    clone_and_setup "https://github.com/GerbenJavado/LinkFinder.git" "LinkFinder" "$PIP_CMD install -r requirements.txt && $PYTHON_CMD setup.py install"
    clone_and_setup "https://github.com/m4ll0k/SecretFinder.git" "SecretFinder" "$PIP_CMD install -r requirements.txt"
    
    # Wordlists
    for repo in "assetnote/commonspeak2-wordlists" "fuzzdb-project/fuzzdb" "1N3/IntruderPayloads" "swisskyrepo/PayloadsAllTheThings" "danielmiessler/SecLists"; do
        clone_and_setup "https://github.com/$repo.git" "Wordlists/$(basename $repo)" ""
    done
    cd Wordlists/SecLists/Discovery/DNS && execute "cat dns-Jhaddix.txt | head -n -14 > clean-jhaddix-dns.txt" "Cleaning jhaddix DNS list" && cd ../../..
    
    # Tomnomnom Tools
    for tool in meg assetfinder waybackurls gf httprobe "hacks/concurl" unfurl "hacks/anti-burl" "hacks/filter-resolved" qsreplace; do
        install_packages go "github.com/tomnomnom/$tool" "$tool installation"
    done
    
    # Additional Tools
    install_packages pip "arjun bbot" "arjun and bbot installation"
    install_packages go "github.com/dwisiswant0/cf-check" "cf-check installation"
    install_packages go "github.com/1ndianl33t/urlprobe" "urlprobe installation"
    install_packages go "github.com/owasp-amass/amass/v4/..." "amass installation"
    clone_and_setup "https://github.com/SecureAuthCorp/impacket.git" "impacket" "$PIP_CMD install -r requirements.txt && $PIP_CMD install ."
    clone_and_setup "https://github.com/six2dez/reconftw.git" "reconftw" "sudo ./install.sh"
    install_packages go "github.com/projectdiscovery/pdtm/cmd/pdtm" "pdtm installation"
    cd ~/go/bin && execute "./pdtm --install-all" "Installing pdtm tools" && cd ..
    clone_and_setup "https://github.com/xnl-h4ck3r/waymore.git" "waymore" "$PYTHON_CMD setup.py install"
}

# Main function
main() {
    banner
    check_prerequisites
    setup_environment || { log ERROR "Environment setup failed, aborting"; exit 1; }
    install_tools
    
    # Summary
    END_TIME=$(date +%s)
    ELAPSED=$((END_TIME - START_TIME))
    log INFO "Installation completed in $((ELAPSED / 60)) minutes and $((ELAPSED % 60)) seconds"
    log INFO "Successful installations: ${#SUCCESSFUL_TOOLS[@]}"
    [ ${#SUCCESSFUL_TOOLS[@]} -gt 0 ] && log DEBUG "Successful tools: ${SUCCESSFUL_TOOLS[*]}"
    log INFO "Failed installations: ${#FAILED_TOOLS[@]}"
    [ ${#FAILED_TOOLS[@]} -gt 0 ] && log ERROR "Failed tools: ${FAILED_TOOLS[*]}"
    
    log INFO "Use 'source ~/.bash_profile' to enable shell functions"
    log INFO "ALL THE TOOLS ARE MADE BY THE BEST PEOPLE OF THE INFOSEC COMMUNITY"
    log INFO "                I AM JUST A SCRIPT-KIDDIE ;)"
    
    [ "$OS" = "ubuntu" ] && deactivate
}

# Run main
main