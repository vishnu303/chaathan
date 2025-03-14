#!/bin/bash

# Exit on error
set -e

# Define colors
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
BLUE=$(tput setaf 4)
RESET=$(tput sgr0)

# variables
TOOLS_DIR="$HOME/tools"
VENV_DIR="$HOME/bugbounty_venv"
GO_VERSION="1.21.7"
LOG_FILE="$HOME/chaathan_install.log"
APT_PACKAGES="apt-transport-https curl git jq ruby-full build-essential libcurl4-openssl-dev libssl-dev libxml2-dev libxslt1-dev libgmp-dev zlib1g-dev libffi-dev python3-dev python3-pip npm nmap perl parallel ffuf wfuzz"

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Function to execute commands with retries
execute() {
    local cmd="$1" desc="$2" retries=${3:-3} attempt=1
    while [ $attempt -le $retries ]; do
        if eval "$cmd"; then
            log "${GREEN}[+] $desc succeeded${RESET}"
            return 0
        fi
        log "${RED}[-] Attempt $attempt/$retries failed for $desc${RESET}"
        ((attempt++))
        sleep 5
    done
    log "${RED}Error: $desc failed after $retries retries${RESET}"
    return 1
}

# Function to detect OS and set Python environment
setup_environment() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        log "${GREEN}Detected OS: $OS${RESET}"
    else
        OS="unknown"
        log "${RED}Cannot detect OS, defaulting to system Python${RESET}"
    fi

    if [ "$OS" = "ubuntu" ]; then
        log "${GREEN}[+] Setting up virtual environment for Ubuntu${RESET}"
        execute "python3 -m venv $VENV_DIR" "Virtual environment creation" || exit 1
        source "$VENV_DIR/bin/activate"
        PIP_CMD="$VENV_DIR/bin/pip"
        PYTHON_CMD="$VENV_DIR/bin/python3"
    else
        log "${GREEN}[+] Using system Python for $OS${RESET}"
        execute "python3 -m ensurepip --upgrade && python3 -m pip install --upgrade pip" "pip setup" || exit 1
        PIP_CMD="pip3"
        PYTHON_CMD="python3"
    fi
}

# Function to install packages
install_packages() {
    local type="$1" packages="$2" desc="$3"
    case $type in
        apt) execute "sudo apt -y install $packages" "$desc" ;;
        pip) execute "$PIP_CMD install $packages" "$desc" ;;
        gem) execute "sudo gem install $packages" "$desc" ;;
        npm) execute "sudo npm install -g $packages" "$desc" ;;
        go) execute "go install -v $packages@latest" "$desc" && [ -f "$HOME/go/bin/$(basename $packages)" ] && sudo cp "$HOME/go/bin/$(basename $packages)" /usr/local/bin/ ;;
    esac
}

# Function to clone and setup Git repo
clone_and_setup() {
    local repo="$1" dir="$2" setup_cmd="$3"
    execute "git clone $repo $dir" "Cloning $repo" || return 1
    if [ -n "$setup_cmd" ]; then
        cd "$dir" || return 1
        execute "$setup_cmd" "Setting up $dir" || return 1
        cd - || return 1
    fi
}

# Display banner 
banner() {
    log "${RED} ######################################################### ${RESET}"
    log "${RED} #                 TOOLS FOR BUG BOUNTY                  # ${RESET}"
    log "${RED} ######################################################### ${RESET}"
    echo "${BLUE}
              
 .----------------.  .----------------.  .----------------.  .----------------.  .----------------.  .----------------.  .----------------.  .-----------------.
| .--------------. || .--------------. || .--------------. || .--------------. || .--------------. || .--------------. || .--------------. || .--------------. |
| |     ______   | || |  ____  ____  | || |      __      | || |      __      | || |  _________   | || |  ____  ____  | || |      __      | || | ____  _____  | |
| |   .' ___  |  | || | |_   ||   _| | || |     /  \     | || |     /  \     | || | |  _   _  |  | || | |_   ||   _| | || |     /  \     | || ||_   \|_   _| | |
| |  / .'   \_|  | || |   | |__| |   | || |    / /\ \    | || |    / /\ \    | || | |_/ | | \_|  | || |   | |__| |   | || |    / /\ \    | || |  |   \ | |   | |
| |  | |         | || |   |  __  |   | || |   / ____ \   | || |   / ____ \   | || |     | |      | || |   |  __  |   | || |   / ____ \   | || |  | |\ \| |   | |
| |  \ `.___.'\  | || |  _| |  | |_  | || | _/ /    \ \_ | || | _/ /    \ \_ | || |    _| |_     | || |  _| |  | |_  | || | _/ /    \ \_ | || | _| |_\   |_  | |
| |   `._____.'  | || | |____||____| | || ||____|  |____|| || ||____|  |____|| || |   |_____|    | || | |____||____| | || ||____|  |____|| || ||_____|\____| | |
| |              | || |              | || |              | || |              | || |              | || |              | || |              | || |              | |
| '--------------' || '--------------' || '--------------' || '--------------' || '--------------' || '--------------' || '--------------' || '--------------' |
 '----------------'  '----------------'  '----------------'  '----------------'  '----------------'  '----------------'  '----------------'  '----------------'  ${RESET}"
    log "${GREEN} Tools created by the best people in the InfoSec Community ${RESET}"
    log "${GREEN}                   Thanks to everyone!                     ${RESET}"
}

# Main installation logic
main() {
    banner
    setup_environment

    # Update system and install base dependencies
    execute "sudo apt -y update && sudo apt -y upgrade" "System update/upgrade" || exit 1
    install_packages apt "$APT_PACKAGES" "Base dependencies installation" || exit 1
    execute "curl -sL https://git.io/vokNn | sudo bash -" "apt-fast installation" || exit 1

    # Install Go
    if [ ! -d "/usr/local/go" ]; then
        execute "wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz -O go.tar.gz && sudo tar -C /usr/local -xzf go.tar.gz && rm go.tar.gz" "Go installation" || exit 1
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bash_profile
        export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    else
        log "${BLUE}Golang is already installed${RESET}"
    fi
    source ~/.bash_profile

    # Set bash aliases
    execute "curl -s https://raw.githubusercontent.com/unethicalnoob/aliases/master/bashprofile > ~/.bash_profile" "Downloading aliases" || log "${BLUE}Aliases download failed, set manually${RESET}"
    source ~/.bash_profile || log "${BLUE}If aliases don’t work, set them manually${RESET}"

    # Create tools directory
    mkdir -p "$TOOLS_DIR" && cd "$TOOLS_DIR" || exit 1

    # Install tools
    log "${RED} #################### Installing Tools #################### ${RESET}"

    # Basic Tools
    install_packages pip "py-altdns" "py-altdns installation"
    install_packages apt "nmap sqlmap" "nmap and sqlmap installation"
    clone_and_setup "https://github.com/jobertabma/virtual-host-discovery.git" "vhd"
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
    clone_and_setup "https://github.com/eldraco/domain_analyzer.git" "domain_analyzer"
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
    execute "curl -s https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip && unzip -q awscliv2.zip && sudo ./aws/install && rm -rf aws awscliv2.zip" "AWS CLI installation"
    clone_and_setup "https://github.com/gwen001/s3-buckets-finder.git" "s3-buckets-finder"
    clone_and_setup "https://github.com/nahamsec/lazys3.git" "lazys3"
    clone_and_setup "https://github.com/securing/DumpsterDiver.git" "DumpsterDiver" "$PIP_CMD install -r requirements.txt"
    clone_and_setup "https://github.com/sa7mon/S3Scanner.git" "S3Scanner" "$PIP_CMD install -r requirements.txt"
    clone_and_setup "https://github.com/christophetd/CloudFlair.git" "CloudFlair" "$PIP_CMD install -r requirements.txt"
    clone_and_setup "https://github.com/greycatz/CloudUnflare.git" "CloudUnflare"
    clone_and_setup "https://github.com/fellchase/flumberboozle.git" "flumberboozle"
    clone_and_setup "https://github.com/RhinoSecurityLabs/GCPBucketBrute.git" "GCPBucketBrute" "$PIP_CMD install -r requirements.txt"

    # CMS Tools
    clone_and_setup "https://github.com/Dionach/CMSmap.git" "CMS/CMSmap" "$PIP_CMD install ."
    clone_and_setup "https://github.com/jekyc/wig.git" "CMS/wig" "$PYTHON_CMD setup.py install"
    clone_and_setup "https://github.com/rezasp/joomscan.git" "CMS/Joomscan"
    install_packages gem "wpscan" "wpscan installation"
    install_packages pip "droopescan" "droopescan installation"
    clone_and_setup "https://github.com/immunIT/drupwn.git" "CMS/drupwn" "$PYTHON_CMD setup.py install"
    clone_and_setup "https://github.com/0ang3el/aem-hacker.git" "CMS/aem-hacker"

    # Git Tools
    clone_and_setup "https://github.com/HightechSec/git-scanner.git" "GIT/git-scanner" "chmod +x gitscanner.sh"
    clone_and_setup "https://github.com/hisxo/gitGraber.git" "GIT/gitGraber" "$PIP_CMD install -r requirements.txt"
    clone_and_setup "https://github.com/tillson/git-hound.git" "GIT/git-hound" "go build -o githound main.go && sudo cp githound /usr/local/bin/"
    clone_and_setup "https://github.com/gwen001/github-search.git" "GIT/github-search" "$PIP_CMD install -r requirements.txt"

    # Frameworks
    clone_and_setup "https://github.com/1N3/Sn1per.git" "Frameworks/Sn1per"
    clone_and_setup "https://github.com/j3ssie/Osmedeus.git" "Frameworks/osmedeus"
    clone_and_setup "https://github.com/WhaleShark-Team/cobra.git" "Frameworks/Cobra"
    clone_and_setup "https://github.com/0xinfection/tidos-framework.git" "Frameworks/TIDoS-Framework" "chmod +x install"
    clone_and_setup "https://github.com/1N3/BlackWidow.git" "Frameworks/BlackWidow"
    clone_and_setup "https://github.com/screetsec/Sudomy.git" "Frameworks/Sudomy" "$PIP_CMD install -r requirements.txt && sudo npm i -g wappalyzer"
    execute "wget -q https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux -O findomain && chmod +x findomain && sudo mv findomain /usr/local/bin/" "findomain installation"

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
        clone_and_setup "https://github.com/$repo.git" "Wordlists/$(basename $repo)"
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

    # Instructions
    log "${GREEN}Use 'source ~/.bash_profile' to enable shell functions${RESET}"
    log "${GREEN}ALL THE TOOLS ARE MADE BY THE BEST PEOPLE OF THE INFOSEC COMMUNITY${RESET}"
    log "${GREEN}                I AM JUST A SCRIPT-KIDDIE ;)                 ${RESET}"

    # Deactivate virtual environment if on Ubuntu
    [ "$OS" = "ubuntu" ] && deactivate
}

# Run main function
main