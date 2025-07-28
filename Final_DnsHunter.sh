#!/usr/bin/env bash
# Fail on error and prevent errors in pipelines from being hidden.
set -e -o pipefail

#==============================================================================
#
#   ██████╗ ███╗   ██╗██╗  ██╗██╗    ██╗██╗   ██╗████████╗██╗███████╗██████╗
#  ██╔═══██╗████╗  ██║██║  ██║██║    ██║██║   ██║╚══██╔══╝██║██╔════╝██╔══██╗
#  ██║  ██║██╔██╗ ██║███████║██║    ██║██║   ██║    ██║   ██║█████╗  ██████╔╝
#  ██║  ██║██║╚██╗██║██╔══██║██║    ██║██║   ██║    ██║   ██║██╔══╝  ██╔══██╗
#  ╚██████╔╝██║ ╚████║██║  ██║╚██████╔╝╚██████╔╝    ██║   ██║███████╗██║  ██║
#   ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝      ╚═╝   ╚═╝╚══════╝╚═╝  ╚═╝
#
#             Phoenix v3.1 '9x07yda' - The Ultimate Recon Suite
#
#==============================================================================

# --- CONFIG & SETUP ---
SCRIPT_VERSION="3.1 'Supernova Pro'"
DEFAULT_CONFIG_PATH="${HOME}/.config/dnshunter/dnshunter.conf"
DEFAULT_WORDLIST="/usr/share/wordlists/dns/dns-Jhaddix.txt"
DEFAULT_RESOLVERS="${HOME}/.config/dnshunter/resolvers.txt" # New default resolver list

# Default values for configuration (will be overridden by config file/CLI)
VERBOSE="false"
QUIET="false"
RATE_LIMIT="1000"
TIMEOUT="30"
MAX_RETRIES="3"
CONCURRENCY="10"
OUTPUT_DIRECTORY="./dnshunter_results"

# Phase toggles
PHASE_ENUMERATION="true"
PHASE_DNS_BRUTEFORCE="true"
PHASE_PERMUTATION="true"
PHASE_VERIFICATION="true"
PHASE_PORTSCAN="true"
PHASE_WEB_CRAWLING="true"
PHASE_VULNERABILITY_SCAN="true"
PHASE_SCREENSHOT="true"
PHASE_REPORTING="true"
PHASE_TAKEOVER_CHECK="true" # New phase
PHASE_WAF_CDN_DETECTION="true" # New phase
PHASE_CONTENT_DISCOVERY="true" # New phase

# Advanced Features
AI_ANALYSIS="false"
DEEP_SCAN="false"
STEALTH_MODE="false"
LIVE_UPDATES="true"
AUTO_WORDLIST_UPDATE="true" # New feature config

# Tool Configurations (with defaults)
HTTPX_THREADS="100"
HTTPX_RATE_LIMIT="150"
DNS_WORDLIST="${DEFAULT_WORDLIST}"
PUREDNS_RESOLVERS="${DEFAULT_RESOLVERS}" # New: Puredns resolver list
NAABU_PORTS="top-1000"
NAABU_RATE="1000"
NUCLEI_TEMPLATES="~/nuclei-templates/"
SCREENSHOT_QUALITY="high"
GOBUSTER_WORDLIST="/usr/share/wordlists/dirb/common.txt" # New: Gobuster wordlist
GOBUSTER_EXTENSIONS="php,html,js,json,txt,xml" # New: Gobuster extensions

# Wordlists & Resources
declare -a CUSTOM_WORDLISTS=(
    "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    "/usr/share/wordlists/seclists/Discovery/DNS/fierce-hostlist.txt"
    "/usr/share/wordlists/amass/subdomains.lst"
)

# Intelligence Sources (APIs)
ENABLE_SHODAN="false"
SHODAN_API_KEY=""
ENABLE_CENSYS="false"
CENSYS_API_ID=""
CENSYS_API_SECRET=""
ENABLE_VIRUSTOTAL="false"
VIRUSTOTAL_API_KEY=""
CHAOS_API_KEY="" # For chaos tool

# Notifications
NOTIFY_ENABLED="false"
NOTIFY_WEBHOOK_URL=""
NOTIFY_SLACK_WEBHOOK=""
NOTIFY_DISCORD_WEBHOOK=""
NOTIFY_EMAIL="" # Future: Could use mailx or a Python script

# Output Formats
GENERATE_JSON="true"
GENERATE_CSV="true"
GENERATE_XML="false" # Not yet implemented
COMPRESS_RESULTS="true"

# Security & Evasion
declare -a USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0"
)
RANDOM_DELAY_MIN="1"
RANDOM_DELAY_MAX="5"
PROXY_LIST="" # New: Path to a list of proxies (HTTP/S, SOCKS5)

# --- ENHANCED COLORS & SYMBOLS ---
C_BLUE='\033[94m'
C_GREEN='\033[92m'
C_YELLOW='\033[93m'
C_RED='\033[91m'
C_CYAN='\033[96m'
C_MAGENTA='\033[95m'
C_WHITE='\033[97m'
C_BOLD='\033[1m'
C_DIM='\033[2m'
C_UNDERLINE='\033[4m'
C_END='\033[0m'

# Unicode symbols for better visual feedback
SYM_SUCCESS="✅"
SYM_ERROR="❌"
SYM_WARNING="⚠️"
SYM_INFO="ℹ️"
SYM_PROGRESS="🔄"
SYM_ROCKET="🚀"
SYM_TARGET="🎯"
SYM_SHIELD="🛡️"
SYM_BUG="🐛"
SYM_SPIDER="🕷️"

# --- PERFORMANCE TRACKING ---
START_TIME=$(date +%s)
declare -A PHASE_TIMES
declare -A DOMAIN_STATS
declare -A DOMAIN_PROGRESS # To track completed phases for resume

# --- ENHANCED HELPER FUNCTIONS ---
display_banner() {
    # Only clear if not in help mode
    if [[ "$1" != "--no-clear" ]]; then
        clear
    fi
    echo -e "${C_CYAN}${C_BOLD}"
    echo '   ██████╗ ███╗   ██╗██╗  ██╗██╗    ██╗██╗   ██╗████████╗██╗███████╗██████╗ '
    echo '  ██╔═══██╗████╗  ██║██║  ██║██║    ██║██║   ██║╚══██╔══╝██║██╔════╝██╔══██╗'
    echo '  ██║  ██║██╔██╗ ██║███████║██║    ██║██║   ██║    ██║   ██║█████╗  ██████╔╝'
    echo '  ██║  ██║██║╚██╗██║██╔══██║██║    ██║██║   ██║    ██║   ██║██╔══╝  ██╔══██╗'
    echo '  ╚██████╔╝██║ ╚████║██║  ██║╚██████╔╝╚██████╔╝    ██║   ██║███████╗██║  ██║'
    echo '   ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝      ╚═╝   ╚═╝╚══════╝╚═╝  ╚═╝'
    echo -e "${C_END}"
    echo -e "         ${C_YELLOW}${C_BOLD}Phoenix v${SCRIPT_VERSION} - Ultimate Recon Suite${C_END}"
    echo -e "         ${C_DIM}Crafted with ${C_RED}♥${C_DIM} for the security community${C_END}"
    echo ""
}

show_help() {
    display_banner --no-clear # Prevent clearing when showing help
    echo -e "${C_BOLD}${C_WHITE}DESCRIPTION:${C_END}"
    echo "  The most advanced DNS reconnaissance pipeline with AI-powered analysis,"
    echo "  vulnerability detection, and comprehensive reporting capabilities."
    echo ""
    echo -e "${C_BOLD}${C_WHITE}USAGE:${C_END}"
    echo "  $0 -l <domains.txt> [OPTIONS]"
    echo ""
    echo -e "${C_BOLD}${C_WHITE}CORE OPTIONS:${C_END}"
    echo -e "  ${C_CYAN}-h, --help${C_END}        Display this enhanced help menu"
    echo -e "  ${C_CYAN}--init${C_END}            Generate optimized configuration file"
    echo -e "  ${C_CYAN}-l, --list <file>${C_END} Target domains file (one per line)"
    echo -e "  ${C_CYAN}--resume <dir>${C_END}    Resume previous scan session"
    echo ""
    echo -e "${C_BOLD}${C_YELLOW}ADVANCED OPTIONS:${C_END}"
    echo -e "  ${C_GREEN}-o, --output <dir>${C_END}  Output directory (default: ./dnshunter_results)"
    echo -e "  ${C_GREEN}-c, --concurrency <N>${C_END} Parallel domain processing (default: 10)"
    echo -e "  ${C_GREEN}-r, --rate-limit <N>${C_END} Requests per second (default: 1000)"
    echo -e "  ${C_GREEN}--timeout <N>${C_END}      Request timeout in seconds (default: 30)"
    echo -e "  ${C_GREEN}--retries <N>${C_END}      Max retry attempts (default: 3)"
    echo -e "  ${C_GREEN}--config <file>${C_END}    Custom configuration file"
    echo ""
    echo -e "${C_BOLD}${C_MAGENTA}INTELLIGENCE OPTIONS:${C_END}"
    echo -e "  ${C_MAGENTA}--ai-analysis${C_END}    Enable AI-powered subdomain analysis"
    echo -e "  ${C_MAGENTA}--vuln-scan${C_END}      Run vulnerability assessments"
    echo -e "  ${C_MAGENTA}--deep-scan${C_END}      Enable comprehensive deep scanning (incl. perms, crawl)"
    echo -e "  ${C_MAGENTA}--stealth${C_END}        Use stealth mode for evasion (low rate limits, etc.)"
    echo -e "  ${C_MAGENTA}--takeover-check${C_END}  Check for subdomain takeovers"
    echo -e "  ${C_MAGENTA}--waf-cdn-detect${C_END}  Detect WAFs and CDNs"
    echo -e "  ${C_MAGENTA}--content-discover${C_END} Run content discovery on live hosts"
    echo ""
    echo -e "${C_BOLD}${C_BLUE}OUTPUT & DEBUGGING:${C_END}"
    echo -e "  ${C_BLUE}-v, --verbose${C_END}      Verbose output with detailed logs"
    echo -e "  ${C_BLUE}-q, --quiet${C_END}        Minimal output mode"
    echo -e "  ${C_BLUE}--json${C_END}            Output results in JSON format"
    echo -e "  ${C_BLUE}--csv${C_END}             Output results in CSV format"
    echo -e "  ${C_BLUE}--live-updates${C_END}    Real-time progress updates (disables quiet mode)"
    echo ""
    echo -e "${C_BOLD}${C_RED}EXAMPLES:${C_END}"
    echo -e "  ${C_DIM}# Basic scan${C_END}"
    echo -e "  $0 -l domains.txt"
    echo -e "  ${C_DIM}# Advanced scan with AI analysis and vulnerability scan${C_END}"
    echo -e "  $0 -l domains.txt --ai-analysis --vuln-scan -c 20"
    echo -e "  ${C_DIM}# Stealth mode with custom rate limiting and deep scan${C_END}"
    echo -e "  $0 -l domains.txt --stealth -r 100 --timeout 60 --deep-scan"
    echo ""
}

# Enhanced logging with performance metrics
log() {
    local level="$1" message="$2" color="$3" symbol="$4"
    
    # Do not log DEBUG if verbose is false
    [[ "$level" == "DEBUG" && "$VERBOSE" != "true" ]] && return
    
    # Do not log INFO/WARNING/SUCCESS if quiet is true, unless it's an ERROR/FATAL
    if [[ "$QUIET" == "true" && "$level" != "ERROR" && "$level" != "FATAL" ]]; then
        return
    fi
    
    local timestamp elapsed_time
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    elapsed_time=$(($(date +%s) - START_TIME))
    
    if [[ -n "$symbol" ]]; then
        echo -e "${color}${symbol} ${C_BOLD}[${level}]${C_END} ${C_DIM}[${timestamp}] [+${elapsed_time}s]${C_END} ${message}" >&2
    else
        echo -e "${color}${C_BOLD}[${level}]${C_END} ${C_DIM}[${timestamp}] [+${elapsed_time}s]${C_END} ${message}" >&2
    fi
}

# Progress bar function (updated for better quiet/live updates interaction)
show_progress() {
    local current="$1" total="$2" message="$3"
    
    # Only show progress if not in quiet mode and live updates are enabled
    if [[ "$QUIET" == "true" || "$LIVE_UPDATES" != "true" ]]; then
        return
    fi

    local percent=$((current * 100 / total))
    local filled=$((percent / 2))
    local empty=$((50 - filled))
    
    printf "\r${C_CYAN}${SYM_PROGRESS} ${message} ${C_END}["
    printf "%${filled}s" | tr ' ' '█'
    printf "%${empty}s" | tr ' ' '░'
    printf "] ${percent}%% (${current}/${total})"
}

# System resource monitoring
check_system_resources() {
    local cpu_usage memory_usage disk_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    memory_usage=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
    disk_usage=$(df -h . | awk 'NR==2 {print $5}' | sed 's/%//')
    
    log "INFO" "System Resources - CPU: ${cpu_usage}%, Memory: ${memory_usage}%, Disk: ${disk_usage}%" "${C_BLUE}" "${SYM_INFO}"
    
    # Warning thresholds
    if [[ $(echo "$cpu_usage > 80" | bc -l 2>/dev/null || echo 0) -eq 1 ]]; then
        log "WARNING" "High CPU usage detected (${cpu_usage}%)" "${C_YELLOW}" "${SYM_WARNING}"
    fi
    if [[ $(echo "$memory_usage > 85" | bc -l 2>/dev/null || echo 0) -eq 1 ]]; then
        log "WARNING" "High memory usage detected (${memory_usage}%)" "${C_YELLOW}" "${SYM_WARNING}"
    fi
}

# --- ENHANCED DEPENDENCY MANAGEMENT ---
manage_dependencies() {
    log "INFO" "Performing comprehensive dependency check..." "${C_BLUE}" "${SYM_SHIELD}"
    local missing_deps=0
    local core_deps=("subfinder" "assetfinder" "amass" "massdns" "httpx_live" "jq" "naabu" "puredns" "gowitness")
    local advanced_deps=("nuclei" "katana" "alterx" "dnsx" "notify" "uncover" "chaos" "subzy" "wafw00f" "gobuster")
    local system_deps=("curl" "wget" "git" "go" "python3" "pip3")
    
    # Check system dependencies
    log "INFO" "Checking system dependencies..." "${C_CYAN}" "${SYM_INFO}"
    for tool in "${system_deps[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log "ERROR" "System dependency missing: '$tool'. Please install it manually." "${C_RED}" "${SYM_ERROR}"
            missing_deps=1
        fi
    done
    
    # Check core tools
    log "INFO" "Checking core reconnaissance tools..." "${C_CYAN}" "${SYM_INFO}"
    for tool in "${core_deps[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log "WARNING" "Core tool not found: '$tool'." "${C_YELLOW}" "${SYM_WARNING}"
            if [[ "$tool" == "massdns" ]]; then
                log "WARNING" "'massdns' requires manual compilation and cannot be auto-installed by this script." "${C_YELLOW}" "${SYM_WARNING}"
                log "INFO" "    Please run: ${C_BOLD}git clone https://github.com/blechschmidt/massdns.git && cd massdns && make && sudo make install${C_END}" "${C_CYAN}"
                log "INFO" "    Proceeding without massdns, but puredns will be slower without it." "${C_YELLOW}"
                # We don't increment missing_deps for massdns as it's a specific case and can be skipped
                # if the user understands the performance impact. puredns will still work, just slower.
            elif install_tool "$tool"; then
                log "SUCCESS" "'$tool' installed successfully." "${C_GREEN}" "${SYM_SUCCESS}"
            else
                missing_deps=1 # Increment for other critical tools
            fi
        else
            log "DEBUG" "Found: $tool"
        fi
    done
    
    # Check advanced tools
    log "INFO" "Checking advanced tools (optional)..." "${C_CYAN}" "${SYM_INFO}"
    for tool in "${advanced_deps[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log "INFO" "Advanced tool not found: '$tool'. Attempting to install..." "${C_YELLOW}" "${SYM_INFO}"
            install_tool "$tool" "optional" # Mark as optional installation
        else
            log "DEBUG" "Found: $tool"
        fi
    done
    
    if [[ $missing_deps -eq 1 ]]; then
        log "FATAL" "Critical dependencies missing. Please install them and try again." "${C_RED}" "${SYM_ERROR}"
        exit 1
    fi
    
    log "SUCCESS" "All dependencies verified and installed (or noted)." "${C_GREEN}" "${SYM_SUCCESS}"
    check_system_resources
}

# Locate the 'install_tool' function and apply these changes.

install_tool() {
    local tool="$1" optional="$2"
    log "INFO" "Installing '$tool'... Please wait." "${C_CYAN}" "${SYM_PROGRESS}"
    
    local install_status=0
    case "$tool" in
        "puredns")       go install github.com/d3mondev/puredns/v2@latest ;;
        "gowitness")     go install github.com/sensepost/gowitness@latest ;;
        "nuclei")        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest ;;
        "katana")        go install github.com/projectdiscovery/katana/cmd/katana@latest ;;
        "alterx")        go install github.com/projectdiscovery/alterx/cmd/alterx@latest ;;
        "dnsx")          go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest ;;
        "notify")        go install -v github.com/projectdiscovery/notify/cmd/notify@latest ;;
        "uncover")       go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest ;;
        "chaos")         go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest ;;
        "subfinder")     go install -v github.com/projectdiscovery/subfinder/v2@latest ;;
        "assetfinder")   go install -v github.com/tomnomnom/assetfinder@latest ;;
        "amass")         go install -v github.com/owasp-amass/amass/v4/...@master ;;
        "httpx")         go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest ;;
        "naabu")         go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest ;;
        "subzy")         go install -v github.com/LukaSikic/subzy@latest ;;
        "wafw00f")
            # wafw00f is Python-based
            if command -v pip3 &> /dev/null; then
                pip3 install wafw00f || install_status=1
            else
                log "ERROR" "pip3 not found, cannot install wafw00f." "${C_RED}" "${SYM_ERROR}"
                install_status=1
            fi
            ;;
        "gobuster")
            go install github.com/OJ/gobuster/v3@latest || install_status=1
            ;;
        "jq")
            # jq is usually installed via package manager
            # Ensuring the message is a single argument for log function
            log "INFO" "'jq' is typically installed via your system\'s package manager (e.g., apt install jq, pacman -S jq)." "${C_CYAN}"
            install_status=1 # Mark as failed for go install, but provide instructions
            ;;
        *)
            # Generic case for ProjectDiscovery tools that follow the /cmd/tool structure
            go install -v "github.com/projectdiscovery/${tool}/cmd/${tool}@latest" || install_status=1
            ;;
    esac
    
    # Ensuring robust conditional checks for command existence and status
    if [[ "$install_status" -eq 0 && $(command -v "$tool" &>/dev/null; echo $?) -eq 0 ]]; then
        return 0
    elif [[ "$optional" == "optional" ]]; then
        log "WARNING" "Optional tool '$tool' installation failed. Functionality might be limited." "${C_YELLOW}" "${SYM_WARNING}"
        return 0
    else
        log "ERROR" "Installation of '$tool' failed." "${C_RED}" "${SYM_ERROR}"
        return 1
    fi
}

# --- ENHANCED CONFIGURATION MANAGEMENT ---
generate_default_config() {
    log "INFO" "Generating enhanced configuration file: $1" "${C_BLUE}" "${SYM_INFO}"
    mkdir -p "$(dirname "$1")"
    cat > "$1" <<EOF
# DNSHunter Phoenix v3.1 'Supernova Pro' Configuration File
# Enhanced configuration with advanced features

# === CORE SETTINGS ===
CONCURRENCY="10"
OUTPUT_DIRECTORY="./dnshunter_results"
VERBOSE="false"
QUIET="false"
RATE_LIMIT="1000"
TIMEOUT="30"
MAX_RETRIES="3"

# === SCAN PHASES ===
PHASE_ENUMERATION="true"
PHASE_DNS_BRUTEFORCE="true"
PHASE_PERMUTATION="true"
PHASE_VERIFICATION="true"
PHASE_PORTSCAN="true"
PHASE_WEB_CRAWLING="true"
PHASE_VULNERABILITY_SCAN="true"
PHASE_SCREENSHOT="true"
PHASE_REPORTING="true"
PHASE_TAKEOVER_CHECK="true" # Enable subdomain takeover checks
PHASE_WAF_CDN_DETECTION="true" # Enable WAF/CDN detection
PHASE_CONTENT_DISCOVERY="true" # Enable content discovery (dir/file brute-force)

# === ADVANCED FEATURES ===
AI_ANALYSIS="false"
DEEP_SCAN="false"
STEALTH_MODE="false"
LIVE_UPDATES="true"
AUTO_WORDLIST_UPDATE="true" # Automatically update common wordlists (requires internet)

# === TOOL CONFIGURATIONS ===
HTTPX_THREADS="100"
HTTPX_RATE_LIMIT="150"
DNS_WORDLIST="${DEFAULT_WORDLIST}" # Path to DNS brute-force wordlist
PUREDNS_RESOLVERS="${DEFAULT_RESOLVERS}" # Path to a list of trusted DNS resolvers (e.g., 1.1.1.1, 8.8.8.8)
NAABU_PORTS="top-1000" # Common ports: top-100, top-1000, or a custom list (e.g., 80,443,8080)
NAABU_RATE="1000"
NUCLEI_TEMPLATES="~/nuclei-templates/" # Path to Nuclei templates directory
SCREENSHOT_QUALITY="high" # gowitness screenshot quality
GOBUSTER_WORDLIST="/usr/share/wordlists/dirb/common.txt" # Wordlist for gobuster
GOBUSTER_EXTENSIONS="php,html,js,json,txt,xml,zip,tar.gz,bak" # Extensions for gobuster

# === WORDLISTS & RESOURCES ===
# List of additional wordlists for DNS brute-force, will be combined with DNS_WORDLIST
CUSTOM_WORDLISTS=(
    "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    "/usr/share/wordlists/seclists/Discovery/DNS/fierce-hostlist.txt"
    "/usr/share/wordlists/amass/subdomains.lst"
)

# === INTELLIGENCE SOURCES (API Keys) ===
# IMPORTANT: Enter your API keys here for enhanced intelligence.
# Get API keys from respective platforms.
ENABLE_SHODAN="false"
SHODAN_API_KEY=""
ENABLE_CENSYS="false"
CENSYS_API_ID=""
CENSYS_API_SECRET=""
ENABLE_VIRUSTOTAL="false"
VIRUSTOTAL_API_KEY=""
CHAOS_API_KEY="" # ProjectDiscovery Chaos API key

# === NOTIFICATIONS ===
NOTIFY_ENABLED="false" # Set to true to enable notifications
NOTIFY_WEBHOOK_URL="" # Generic webhook URL
NOTIFY_SLACK_WEBHOOK="" # Slack webhook URL
NOTIFY_DISCORD_WEBHOOK="" # Discord webhook URL
NOTIFY_EMAIL="" # Not implemented yet: Email address for notification

# === OUTPUT FORMATS ===
GENERATE_JSON="true" # Generate JSON report
GENERATE_CSV="true" # Generate CSV report
GENERATE_XML="false" # Not implemented yet
COMPRESS_RESULTS="true" # Compress output directory into a tar.gz archive

# === SECURITY & EVASION ===
# User-Agent strings for HTTP requests. A random one will be picked if stealth mode is enabled.
USER_AGENTS=(
    "Mozilla/5.5 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36"
    "Mozilla/5.5 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15"
    "Mozilla/5.5 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36"
    "Mozilla/5.5 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0"
)
RANDOM_DELAY_MIN="1" # Minimum random delay between requests in stealth mode (seconds)
RANDOM_DELAY_MAX="5" # Maximum random delay between requests in stealth mode (seconds)
PROXY_LIST="" # Path to a file containing a list of proxies (one per line, e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:9050)
EOF
    log "SUCCESS" "Enhanced configuration file created successfully!" "${C_GREEN}" "${SYM_SUCCESS}"
    echo -e "\n${C_YELLOW}${SYM_INFO} Configuration Tips:${C_END}"
    echo "  • Add your API keys for enhanced intelligence gathering (Shodan, Censys, VirusTotal, Chaos)."
    echo "  • Configure notification webhooks for real-time alerts."
    echo "  • Adjust rate limits based on your network capacity."
    echo "  • Enable stealth mode for sensitive targets (will override some rate limits)."
    echo "  • Create a custom resolver list for Puredns (${DEFAULT_RESOLVERS}) for faster and more reliable DNS resolution."
}

# Function to update wordlists (simple example, can be expanded)
update_wordlists() {
    if [[ "$AUTO_WORDLIST_UPDATE" == "true" ]]; then
        log "INFO" "Attempting to update common wordlists (this may take some time)..." "${C_BLUE}" "${SYM_PROGRESS}"
        # Example: Update SecLists. You'd need to clone it first or use specific wget commands.
        # This is a placeholder; a robust updater would check for existence and pull updates.
        local seclists_path="/usr/share/wordlists/seclists"
        if [[ -d "$seclists_path/.git" ]]; then
            log "INFO" "Updating SecLists repository..." "${C_DIM}"
            git -C "$seclists_path" pull &>/dev/null
        else
            log "WARNING" "SecLists not found at $seclists_path. Please clone it manually: git clone https://github.com/danielmiessler/SecLists.git $seclists_path" "${C_YELLOW}" "${SYM_WARNING}"
        fi
        # You can add more wordlist updates here
        log "SUCCESS" "Wordlist update process completed." "${C_GREEN}" "${SYM_SUCCESS}"
    fi
}


load_config() {
    local config_file_path="$1"
    
    # Load defaults first
    # (No need to explicitly set them here again as they are set globally at the top)

    if [[ -f "$config_file_path" ]]; then
        log "DEBUG" "Loading configuration from: $config_file_path"
        # shellcheck source=/dev/null
        source "$config_file_path"
        log "INFO" "Configuration loaded from ${config_file_path}." "${C_BLUE}" "${SYM_SUCCESS}"
    else
        log "WARNING" "Config file not found at ${config_file_path}. Using optimized hardcoded defaults." "${C_YELLOW}" "${SYM_WARNING}"
    fi

    # Apply stealth mode overrides if enabled
    if [[ "$STEALTH_MODE" == "true" ]]; then
        log "INFO" "Stealth mode enabled. Adjusting rate limits and concurrency." "${C_YELLOW}" "${SYM_INFO}"
        RATE_LIMIT="100"
        HTTPX_RATE_LIMIT="20"
        CONCURRENCY="5"
        # Can add proxy settings here if PROXY_LIST is defined
    fi
    
    log "DEBUG" "Active config - Concurrency: ${CONCURRENCY}, Rate: ${RATE_LIMIT}/s, Timeout: ${TIMEOUT}s, Retries: ${MAX_RETRIES}"
}

# --- ENHANCED NOTIFICATION SYSTEM ---
send_notification() {
    local session_dir="$1" message="$2" priority="$3"
    [[ "$NOTIFY_ENABLED" != "true" ]] && return
    
    local session_name total_domains total_subs live_hosts total_vulns duration_str
    session_name=$(basename "$session_dir")
    total_domains=$(wc -l < "${session_dir}/target_list.txt" 2>/dev/null || echo "0")
    total_subs=$(find "${session_dir}" -name "all_subs.final.txt" -exec wc -l {} + 2>/dev/null | awk '{s+=$1} END {print s}' || echo "0")
    live_hosts=$(find "${session_dir}" -name "live_urls.txt" -exec wc -l {} + 2>/dev/null | awk '{s+=$1} END {print s}' || echo "0")
    total_vulns=$(find "${session_dir}" -name "nuclei_results.json" -exec wc -l {} + 2>/dev/null | awk '{s+=$1} END {print s}' || echo "0")
    
    local end_time=$(date +%s)
    local total_duration=$((end_time - START_TIME))
    duration_str=$(printf '%02dh:%02dm:%02ds\n' $((total_duration/3600)) $((total_duration%3600/60)) $((total_duration%60)))
    
    local notification_content
    notification_content=$(cat <<EOF
🚀 **DNSHunter Phoenix v3.1 Report**
📊 **Session:** \`${session_name}\`
🎯 **Targets Scanned:** ${total_domains}
🔍 **Subdomains Found:** ${total_subs}
🌐 **Live Hosts:** ${live_hosts}
🐛 **Vulnerabilities:** ${total_vulns}
⏱️ **Scan Duration:** ${duration_str}
${message:+📝 **Note:** ${message}}
EOF
)
    
    log "INFO" "Sending notifications..." "${C_CYAN}" "${SYM_PROGRESS}"
    # Send to multiple channels
    if [[ -n "$NOTIFY_WEBHOOK_URL" ]]; then
        send_webhook_notification "$NOTIFY_WEBHOOK_URL" "$notification_content" "Generic Webhook"
    fi
    if [[ -n "$NOTIFY_SLACK_WEBHOOK" ]]; then
        send_slack_notification "$notification_content"
    fi
    if [[ -n "$NOTIFY_DISCORD_WEBHOOK" ]]; then
        send_discord_notification "$notification_content"
    fi

    log "SUCCESS" "Notifications sent successfully." "${C_GREEN}" "${SYM_SUCCESS}"
}

send_webhook_notification() {
    local url="$1" content="$2" type="$3"
    log "DEBUG" "Sending notification to ${type}..."
    curl -s -X POST -H "Content-Type: application/json" \
             -d "{\"content\": \"$content\"}" "$url" &>/dev/null
    if [[ $? -eq 0 ]]; then
        log "DEBUG" "${type} notification sent."
    else
        log "ERROR" "Failed to send ${type} notification." "${C_RED}" "${SYM_ERROR}"
    fi
}

send_slack_notification() {
    local content="$1"
    log "DEBUG" "Sending notification to Slack..."
    curl -s -X POST -H "Content-Type: application/json" \
             -d "{\"text\": \"$content\"}" "$NOTIFY_SLACK_WEBHOOK" &>/dev/null
    if [[ $? -eq 0 ]]; then
        log "DEBUG" "Slack notification sent."
    else
        log "ERROR" "Failed to send Slack notification." "${C_RED}" "${SYM_ERROR}"
    fi
}

send_discord_notification() {
    local content="$1"
    log "DEBUG" "Sending notification to Discord..."
    curl -s -X POST -H "Content-Type: application/json" \
             -d "{\"content\": \"$content\"}" "$NOTIFY_DISCORD_WEBHOOK" &>/dev/null
    if [[ $? -eq 0 ]]; then
        log "DEBUG" "Discord notification sent."
    else
        log "ERROR" "Failed to send Discord notification." "${C_RED}" "${SYM_ERROR}"
    fi
}


# --- ADVANCED ENUMERATION FUNCTIONS ---
run_advanced_enumeration() {
    local domain="$1" target_dir="$2"
    log "INFO" "[${domain}] Running advanced enumeration suite..." "${C_CYAN}" "${SYM_ROCKET}"
    
    local sources_dir="${target_dir}/sources"
    mkdir -p "$sources_dir"
    
    local pids=()
    
    if command -v subfinder &> /dev/null; then
        subfinder -d "$domain" -silent -all -o "${sources_dir}/subfinder.txt" &
        pids+=($!)
    else
        log "WARNING" "[${domain}] subfinder not found, skipping." "${C_YELLOW}" "${SYM_WARNING}"
    fi
    
    if command -v assetfinder &> /dev/null; then
        assetfinder --subs-only "$domain" > "${sources_dir}/assetfinder.txt" &
        pids+=($!)
    else
        log "WARNING" "[${domain}] assetfinder not found, skipping." "${C_YELLOW}" "${SYM_WARNING}"
    fi
    
    if command -v amass &> /dev/null; then
        amass enum -passive -d "$domain" -o "${sources_dir}/amass.txt" &
        pids+=($!)
    else
        log "WARNING" "[${domain}] amass not found, skipping." "${C_YELLOW}" "${SYM_WARNING}"
    fi
    
    if command -v chaos &> /dev/null && [[ -n "$CHAOS_API_KEY" ]]; then
        chaos -d "$domain" -key "$CHAOS_API_KEY" -silent > "${sources_dir}/chaos.txt" &
        pids+=($!)
    elif command -v chaos &> /dev/null; then
        log "WARNING" "[${domain}] CHAOS_API_KEY not set, skipping Chaos enumeration." "${C_YELLOW}" "${SYM_WARNING}"
    fi
    
    if command -v uncover &> /dev/null; then
        # Uncover can also query Shodan, Censys, etc. using their API keys directly
        # You'd need to pass API keys to uncover if they are set
        echo "$domain" | uncover -engine shodan,censys,fofa -silent > "${sources_dir}/uncover.txt" &
        pids+=($!)
    else
        log "WARNING" "[${domain}] uncover not found, skipping." "${C_YELLOW}" "${SYM_WARNING}"
    fi

    # Certificate transparency
    if command -v curl &> /dev/null && command -v jq &> /dev/null; then
        curl -s "https://crt.sh/?q=%25.${domain}&output=json" | \
            jq -r '.[].name_value' 2>/dev/null | \
            sed 's/\*\.//g' | sort -u > "${sources_dir}/crtsh.txt" &
        pids+=($!)
    else
        log "WARNING" "[${domain}] curl or jq not found, skipping crt.sh enumeration." "${C_YELLOW}" "${SYM_WARNING}"
    fi # <-- FIXED: Changed 'FId' to 'fi'
    
    wait "${pids[@]}" # Wait for all passive enumeration to complete

    # Combine and deduplicate results
    cat "${sources_dir}"/*.txt 2>/dev/null | \
        grep -E "^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.${domain}$" | \
        sort -u > "${target_dir}/subs.passive.txt"
    
    local passive_count=$(wc -l < "${target_dir}/subs.passive.txt" 2>/dev/null || echo "0")
    log "SUCCESS" "[${domain}] Found ${passive_count} subdomains via passive enumeration" "${C_GREEN}" "${SYM_SUCCESS}"
}

run_dns_bruteforce() {
    local domain="$1" target_dir="$2"
    
    if [[ ! -f "$DNS_WORDLIST" ]]; then
        log "WARNING" "[${domain}] Main DNS wordlist not found: ${DNS_WORDLIST}. Skipping brute-force." "${C_YELLOW}" "${SYM_WARNING}"
        return
    fi

    if ! command -v puredns &> /dev/null; then
        log "WARNING" "[${domain}] puredns not found, skipping DNS brute-force." "${C_YELLOW}" "${SYM_WARNING}"
        return
    fi
    
    log "INFO" "[${domain}] Initiating DNS brute-force attack..." "${C_CYAN}" "${SYM_TARGET}"
    
    local combined_wordlist="${target_dir}/combined_wordlist.txt"
    
    # Combine multiple wordlists
    {
        [[ -f "$DNS_WORDLIST" ]] && cat "$DNS_WORDLIST"
        for wordlist in "${CUSTOM_WORDLISTS[@]}"; do
            [[ -f "$wordlist" ]] && cat "$wordlist"
        done
    } | sort -u > "$combined_wordlist"
    
    local puredns_options=""
    if [[ -f "$PUREDNS_RESOLVERS" ]]; then
        puredns_options+=" -r ${PUREDNS_RESOLVERS}"
    else
        log "WARNING" "[${domain}] Puredns resolvers list not found at ${PUREDNS_RESOLVERS}. Using default resolvers, which may be slower." "${C_YELLOW}" "${SYM_WARNING}"
    fi

    # Run brute-force with rate limiting
    puredns bruteforce "$combined_wordlist" "$domain" \
        ${puredns_options} \
        --rate-limit "${RATE_LIMIT}" \
        --quiet \
        --write "${target_dir}/subs.brute.txt"
    
    local brute_count=$(wc -l < "${target_dir}/subs.brute.txt" 2>/dev/null || echo "0")
    log "SUCCESS" "[${domain}] Brute-force discovered ${brute_count} subdomains" "${C_GREEN}" "${SYM_SUCCESS}"
}

run_permutation_attack() {
    local domain="$1" target_dir="$2"
    [[ "$PHASE_PERMUTATION" != "true" ]] && return
    
    if ! command -v alterx &> /dev/null; then
        log "WARNING" "[${domain}] alterx not found, skipping permutation attack." "${C_YELLOW}" "${SYM_WARNING}"
        return
    fi
    if ! command -v puredns &> /dev/null; then
        log "WARNING" "[${domain}] puredns not found (needed for resolving permuted subs), skipping permutation attack." "${C_YELLOW}" "${SYM_WARNING}"
        return
    fi

    log "INFO" "[${domain}] Running permutation attack..." "${C_CYAN}" "${SYM_TARGET}"
    
    if [[ -s "${target_dir}/subs.passive.txt" ]]; then
        # Generate permutations based on found subdomains
        alterx -l "${target_dir}/subs.passive.txt" -o "${target_dir}/subs.permuted.txt" -silent
        
        # Resolve permutations
        if [[ -s "${target_dir}/subs.permuted.txt" ]]; then
            local puredns_options=""
            if [[ -f "$PUREDNS_RESOLVERS" ]]; then
                puredns_options+=" -r ${PUREDNS_RESOLVERS}"
            fi
            puredns resolve "${target_dir}/subs.permuted.txt" \
                --write "${target_dir}/subs.permuted.resolved.txt" \
                ${puredns_options} \
                --quiet
        fi
        
        local perm_count=$(wc -l < "${target_dir}/subs.permuted.resolved.txt" 2>/dev/null || echo "0")
        log "SUCCESS" "[${domain}] Permutation attack found ${perm_count} additional subdomains" "${C_GREEN}" "${SYM_SUCCESS}"
    else
        log "INFO" "[${domain}] No passive subdomains found, skipping permutation attack." "${C_YELLOW}" "${SYM_INFO}"
    fi
}

# --- NEW: Subdomain Takeover Check ---
run_subdomain_takeover_check() {
    local domain="$1" target_dir="$2"
    [[ "$PHASE_TAKEOVER_CHECK" != "true" ]] && return
    [[ ! -s "${target_dir}/all_subs.final.txt" ]] && return

    if ! command -v subzy &> /dev/null; then
        log "WARNING" "[${domain}] subzy not found, skipping subdomain takeover check." "${C_YELLOW}" "${SYM_WARNING}"
        return
    fi

    log "INFO" "[${domain}] Checking for subdomain takeovers..." "${C_CYAN}" "${SYM_BUG}"
    local takeover_dir="${target_dir}/takeovers"
    mkdir -p "${takeover_dir}"

    subzy run --targets "${target_dir}/all_subs.final.txt" \
              --concurrency "${CONCURRENCY}" \
              --timeout "${TIMEOUT}" \
              --output "${takeover_dir}/subzy_results.json" \
              --hide-fails >/dev/null 2>&1 # Redirect stdout to /dev/null, stderr too

    local takeover_count=$(jq -r '. | length' "${takeover_dir}/subzy_results.json" 2>/dev/null || echo "0")

    if [[ "$takeover_count" -gt 0 ]]; then
        log "WARNING" "[${domain}] Found ${takeover_count} potential subdomain takeovers!" "${C_RED}" "${SYM_WARNING}"
        jq -r '.[] | .url' "${takeover_dir}/subzy_results.json" > "${takeover_dir}/potential_takeovers.txt" 2>/dev/null
    else
        log "SUCCESS" "[${domain}] No subdomain takeovers detected." "${C_GREEN}" "${SYM_SUCCESS}"
    fi
}

# --- NEW: WAF/CDN Detection ---
run_waf_cdn_detection() {
    local domain="$1" target_dir="$2"
    [[ "$PHASE_WAF_CDN_DETECTION" != "true" ]] && return
    [[ ! -s "${target_dir}/live_urls.txt" ]] && return

    if ! command -v wafw00f &> /dev/null; then
        log "WARNING" "[${domain}] wafw00f not found, skipping WAF/CDN detection." "${C_YELLOW}" "${SYM_WARNING}"
        return
    fi

    log "INFO" "[${domain}] Detecting WAFs and CDNs..." "${C_CYAN}" "${SYM_SHIELD}"
    local waf_cdn_dir="${target_dir}/waf_cdn"
    mkdir -p "${waf_cdn_dir}"

    while IFS= read -r url; do
        log "DEBUG" "[${domain}] Checking WAF for: ${url}"
        wafw00f "$url" 2>/dev/null | grep -E "is behind|No WAF detected" | \
            sed "s/^/${url} - /" >> "${waf_cdn_dir}/wafw00f_results.txt"
    done < "${target_dir}/live_urls.txt"

    local waf_count=$(grep -c "is behind" "${waf_cdn_dir}/wafw00f_results.txt" 2>/dev/null || echo "0")
    if [[ "$waf_count" -gt 0 ]]; then
        log "WARNING" "[${domain}] WAF/CDN detected on ${waf_count} live hosts!" "${C_YELLOW}" "${SYM_WARNING}"
    else
        log "SUCCESS" "[${domain}] No WAF/CDN detected on live hosts." "${C_GREEN}" "${SYM_SUCCESS}"
    fi
}


# --- ENHANCED VULNERABILITY SCANNING ---
run_vulnerability_scan() {
    local domain="$1" target_dir="$2"
    [[ "$PHASE_VULNERABILITY_SCAN" != "true" ]] && return
    [[ ! -s "${target_dir}/httpx.results.json" ]] && return
    
    if ! command -v nuclei &> /dev/null; then
        log "WARNING" "[${domain}] nuclei not found, skipping vulnerability assessment." "${C_YELLOW}" "${SYM_WARNING}"
        return
    fi
    
    log "INFO" "[${domain}] Launching vulnerability assessment..." "${C_CYAN}" "${SYM_SHIELD}"
    local vuln_dir="${target_dir}/vulnerabilities"
    mkdir -p "${vuln_dir}"
    
    # Extract live URLs for scanning
    jq -r '.url' "${target_dir}/httpx.results.json" > "${vuln_dir}/live_urls_for_nuclei.txt"
    
    # Ensure Nuclei templates are accessible
    local nuclei_templates_path="${NUCLEI_TEMPLATES}"
    if [[ "$nuclei_templates_path" == "~/"* ]]; then
        nuclei_templates_path="${HOME}/${nuclei_templates_path:2}"
    fi

    if [[ ! -d "$nuclei_templates_path" ]]; then
        log "WARNING" "[${domain}] Nuclei templates directory not found: ${nuclei_templates_path}. Please ensure it's installed and configured. Skipping Nuclei scan." "${C_YELLOW}" "${SYM_WARNING}"
        return
    fi

    # Pick a random user agent for stealth mode if enabled
    local current_user_agent=""
    if [[ "$STEALTH_MODE" == "true" && ${#USER_AGENTS[@]} -gt 0 ]]; then
        current_user_agent="${USER_AGENTS[$(( RANDOM % ${#USER_AGENTS[@]} ))]}"
    fi

    local proxy_option=""
    if [[ "$STEALTH_MODE" == "true" && -n "$PROXY_LIST" && -f "$PROXY_LIST" ]]; then
        proxy_option="-proxy $(shuf -n 1 "$PROXY_LIST")" # Pick a random proxy
        log "DEBUG" "[${domain}] Using proxy for Nuclei: ${proxy_option}"
    fi

    nuclei -list "${vuln_dir}/live_urls_for_nuclei.txt" \
           -t "$nuclei_templates_path" \
           -severity critical,high,medium,low \
           -rate-limit "${RATE_LIMIT}" \
           -timeout "${TIMEOUT}" \
           -retries "${MAX_RETRIES}" \
           -json -o "${vuln_dir}/nuclei_results.json" \
           -silent \
           ${proxy_option} \
           ${current_user_agent:+-H "User-Agent: ${current_user_agent}"} # Add user-agent header if set
    
    # Generate vulnerability summary
    if [[ -s "${vuln_dir}/nuclei_results.json" ]]; then
        local vuln_count=$(wc -l < "${vuln_dir}/nuclei_results.json" 2>/dev/null || echo "0")
        log "SUCCESS" "[${domain}] Vulnerability scan completed - ${vuln_count} issues found" "${C_GREEN}" "${SYM_SUCCESS}"
        
        # Extract critical vulnerabilities
        jq -r 'select(.info.severity == "critical") | .info.name + " (" + .matched_at + ")" ' "${vuln_dir}/nuclei_results.json" 2>/dev/null | \
            sort -u > "${vuln_dir}/critical_vulns.txt"
        
        # Extract all findings (name and URL)
        jq -r '. | .info.name + " (" + .info.severity + "): " + .matched_at' "${vuln_dir}/nuclei_results.json" 2>/dev/null | \
            sort -u > "${vuln_dir}/all_vulns_summary.txt"

    else
        log "INFO" "[${domain}] Nuclei scan found no vulnerabilities." "${C_BLUE}"
    fi
}

# --- ENHANCED WEB CRAWLING (CONTINUATION) ---
run_web_crawling() {
    local domain="$1" target_dir="$2"
    [[ "$PHASE_WEB_CRAWLING" != "true" ]] && return
    [[ ! -s "${target_dir}/httpx.results.json" ]] && return
    
    if ! command -v katana &> /dev/null; then
        log "WARNING" "[${domain}] katana not found, skipping web crawling." "${C_YELLOW}" "${SYM_WARNING}"
        return
    fi
    
    log "INFO" "[${domain}] Starting web crawling and endpoint discovery..." "${C_CYAN}" "${SYM_SPIDER}"
    local crawl_dir="${target_dir}/crawling"
    mkdir -p "${crawl_dir}"
    
    # Extract live URLs for crawling
    jq -r '.url' "${target_dir}/httpx.results.json" > "${crawl_dir}/live_urls_for_katana.txt"
    
    local current_user_agent=""
    if [[ "$STEALTH_MODE" == "true" && ${#USER_AGENTS[@]} -gt 0 ]]; then
        current_user_agent="${USER_AGENTS[$(( RANDOM % ${#USER_AGENTS[@]} ))]}"
    fi

    local proxy_option=""
    if [[ "$STEALTH_MODE" == "true" && -n "$PROXY_LIST" && -f "$PROXY_LIST" ]]; then
        proxy_option="-proxy $(shuf -n 1 "$PROXY_LIST")" # Pick a random proxy
        log "DEBUG" "[${domain}] Using proxy for Katana: ${proxy_option}"
    fi

    # Run katana for deep crawling
    katana -list "${crawl_dir}/live_urls_for_katana.txt" \
           -depth 3 \
           -rate-limit "${RATE_LIMIT}" \
           -timeout "${TIMEOUT}" \
           -silent \
           -output "${crawl_dir}/endpoints.txt" \
           ${proxy_option} \
           ${current_user_agent:+-H "User-Agent: ${current_user_agent}"} # Add user-agent header if set
    
    # Extract unique paths and parameters
    if [[ -s "${crawl_dir}/endpoints.txt" ]]; then
        grep -oP 'https?://[^/]+\K/[^?\s]*' "${crawl_dir}/endpoints.txt" | sort -u > "${crawl_dir}/paths.txt"
        grep -oP '\?[^#\s]*' "${crawl_dir}/endpoints.txt" | sort -u > "${crawl_dir}/parameters.txt"
        local endpoint_count=$(wc -l < "${crawl_dir}/endpoints.txt" 2>/dev/null || echo "0")
        log "SUCCESS" "[${domain}] Web crawling discovered ${endpoint_count} endpoints" "${C_GREEN}" "${SYM_SUCCESS}"
    else
        log "INFO" "[${domain}] Katana found no endpoints." "${C_BLUE}"
    fi
}

# --- NEW: Content Discovery ---
run_content_discovery() {
    local domain="$1" target_dir="$2"
    [[ "$PHASE_CONTENT_DISCOVERY" != "true" ]] && return
    [[ ! -s "${target_dir}/live_urls.txt" ]] && return

    if ! command -v gobuster &> /dev/null; then
        log "WARNING" "[${domain}] gobuster not found, skipping content discovery." "${C_YELLOW}" "${SYM_WARNING}"
        return
    fi
    if [[ ! -f "$GOBUSTER_WORDLIST" ]]; then
        log "WARNING" "[${domain}] Gobuster wordlist not found: ${GOBUSTER_WORDLIST}. Skipping content discovery." "${C_YELLOW}" "${SYM_WARNING}"
        return
    fi

    log "INFO" "[${domain}] Starting content discovery with Gobuster..." "${C_CYAN}" "${SYM_SPIDER}"
    local content_dir="${target_dir}/content_discovery"
    mkdir -p "${content_dir}"

    local current_user_agent=""
    if [[ "$STEALTH_MODE" == "true" && ${#USER_AGENTS[@]} -gt 0 ]]; then
        current_user_agent="${USER_AGENTS[$(( RANDOM % ${#USER_AGENTS[@]} ))]}"
    fi

    local proxy_option=""
    if [[ "$STEALTH_MODE" == "true" && -n "$PROXY_LIST" && -f "$PROXY_LIST" ]]; then
        proxy_option="--proxy $(shuf -n 1 "$PROXY_LIST")" # gobuster uses --proxy for proxy
        log "DEBUG" "[${domain}] Using proxy for Gobuster: ${proxy_option}"
    fi

    local gobuster_found_count=0
    while IFS= read -r url; do
        log "DEBUG" "[${domain}] Running Gobuster for: ${url}"
        # gobuster dir mode
        gobuster dir -u "$url" \
                     -w "$GOBUSTER_WORDLIST" \
                     -x "$GOBUSTER_EXTENSIONS" \
                     -t "${CONCURRENCY}" \
                     -k \
                     -q \
                     -o "${content_dir}/gobuster_results_$(echo "$url" | sed 's/[^a-zA-Z0-9]//g').txt" \
                     ${current_user_agent:+-a "${current_user_agent}"} \
                     ${proxy_option} >/dev/null 2>&1
        local found_in_file=$(wc -l < "${content_dir}/gobuster_results_$(echo "$url" | sed 's/[^a-zA-Z0-9]//g').txt" 2>/dev/null || echo "0")
        gobuster_found_count=$((gobuster_found_count + found_in_file))
    done < "${target_dir}/live_urls.txt"
    
    if [[ "$gobuster_found_count" -gt 0 ]]; then
        log "SUCCESS" "[${domain}] Content discovery found ${gobuster_found_count} items." "${C_GREEN}" "${SYM_SUCCESS}"
    else
        log "INFO" "[${domain}] Content discovery found no new items." "${C_BLUE}"
    fi
}


# --- ENHANCED PORT SCANNING ---
run_port_scan() {
    local domain="$1" target_dir="$2"
    [[ "$PHASE_PORTSCAN" != "true" ]] && return
    [[ ! -s "${target_dir}/all_subs.final.txt" ]] && return
    
    if ! command -v naabu &> /dev/null; then
        log "WARNING" "[${domain}] naabu not found, skipping port scanning." "${C_YELLOW}" "${SYM_WARNING}"
        return
    fi

    log "INFO" "[${domain}] Initiating port scanning phase..." "${C_CYAN}" "${SYM_TARGET}"
    local portscan_dir="${target_dir}/portscan"
    mkdir -p "${portscan_dir}"
    
    local proxy_option=""
    if [[ "$STEALTH_MODE" == "true" && -n "$PROXY_LIST" && -f "$PROXY_LIST" ]]; then
        proxy_option="-proxy-socks5 $(shuf -n 1 "$PROXY_LIST")" # Naabu supports socks5 proxy
        log "DEBUG" "[${domain}] Using proxy for Naabu: ${proxy_option}"
    fi

    naabu -list "${target_dir}/all_subs.final.txt" \
            -ports "${NAABU_PORTS:-top-1000}" \
            -rate "${NAABU_RATE:-1000}" \
            -timeout "$TIMEOUT" \
            -retries "${MAX_RETRIES}" \
            -silent \
            -json -o "${portscan_dir}/naabu_results.json" \
            ${proxy_option}
    
    if [[ -s "${portscan_dir}/naabu_results.json" ]]; then
        # Extract open ports summary
        jq -r 'select(.ports | length > 0) | "\(.host): \(.ports | join(","))"' "${portscan_dir}/naabu_results.json" > "${portscan_dir}/open_ports.txt"
        local port_count=$(wc -l < "${portscan_dir}/open_ports.txt" 2>/dev/null || echo "0")
        log "SUCCESS" "[${domain}] Port scan found ${port_count} unique hosts with open ports" "${C_GREEN}" "${SYM_SUCCESS}"
    else
        log "INFO" "[${domain}] Naabu found no open ports." "${C_BLUE}"
    fi
}

# --- SCREENSHOT CAPTURE ---
run_screenshot_capture() {
    local domain="$1" target_dir="$2"
    [[ "$PHASE_SCREENSHOT" != "true" ]] && return
    [[ ! -s "${target_dir}/httpx.results.json" ]] && return
    
    if ! command -v gowitness &> /dev/null; then
        log "WARNING" "[${domain}] gowitness not found, skipping screenshot capture." "${C_YELLOW}" "${SYM_WARNING}"
        return
    fi
    
    log "INFO" "[${domain}] Capturing screenshots..." "${C_CYAN}" "${SYM_ROCKET}"
    local screenshot_dir="${target_dir}/screenshots"
    mkdir -p "${screenshot_dir}"
    
    # Extract URLs for screenshots
    jq -r '.url' "${target_dir}/httpx.results.json" > "${screenshot_dir}/urls.txt"
    
    # Capture screenshots
    gowitness file -f "${screenshot_dir}/urls.txt" \
                     --destination "$screenshot_dir" \
                     --threads "$(($CONCURRENCY > 10 ? 10 : $CONCURRENCY))" \
                     --timeout "${TIMEOUT}" \
                     --resolution-x 1920 \
                     --resolution-y 1080 \
                     --quality "${SCREENSHOT_QUALITY}" >/dev/null 2>&1 # Suppress gowitness verbose output
    
    local screenshot_count=$(find "${screenshot_dir}" -name "*.png" | wc -l 2>/dev/null || echo "0")
    log "SUCCESS" "[${domain}] Captured ${screenshot_count} screenshots" "${C_GREEN}" "${SYM_SUCCESS}"
}

# --- AI ANALYSIS FUNCTION ---
run_ai_analysis() {
    local domain="$1" target_dir="$2"
    [[ "$AI_ANALYSIS" != "true" ]] && return
    [[ ! -s "${target_dir}/all_subs.final.txt" ]] && return

    log "INFO" "[${domain}] Running AI-powered analysis..." "${C_MAGENTA}" "${SYM_SHIELD}"
    
    local ai_dir="${target_dir}/ai_analysis"
    mkdir -p "${ai_dir}"
    
    # Analyze subdomain patterns (e.g., dev.example.com, test.example.com -> example.com pattern)
    awk -F. '{if (NF>2) {print $(NF-2)"."$(NF-1)"."$NF} else {print $0}}' "${target_dir}/all_subs.final.txt" | sort | uniq -c | sort -nr > "${ai_dir}/domain_patterns.txt"
    
    # Identify interesting subdomains (common keywords)
    grep -E -i "\b(admin|test|dev|staging|api|mail|ftp|vpn|git|jenkins|grafana|kibana|prometheus|dashboard|portal|internal|beta)\b" "${target_dir}/all_subs.final.txt" > "${ai_dir}/interesting_subs.txt" 2>/dev/null || true
    
    # Subdomain length analysis
    awk '{print length($0)}' "${target_dir}/all_subs.final.txt" | sort -n | uniq -c > "${ai_dir}/length_analysis.txt"

    # Analyze common web technologies from httpx results
    if [[ -s "${target_dir}/httpx.results.json" ]]; then
        jq -r 'select(.technologies != null) | .technologies[] | .name' "${target_dir}/httpx.results.json" | sort | uniq -c | sort -nr > "${ai_dir}/technologies_summary.txt"
        jq -r 'select(.webserver != null) | .webserver' "${target_dir}/httpx.results.json" | sort | uniq -c | sort -nr > "${ai_dir}/webservers_summary.txt"
        jq -r 'select(.status_code != null) | .status_code' "${target_dir}/httpx.results.json" | sort | uniq -c | sort -nr > "${ai_dir}/status_codes_summary.txt"
    fi

    log "SUCCESS" "[${domain}] AI analysis completed. Results in ${ai_dir}" "${C_GREEN}" "${SYM_SUCCESS}"
}

# --- MAIN DOMAIN PROCESSING ---
process_domain() {
    local domain="$1" session_dir="$2"
    local target_dir="${session_dir}/${domain}"
    
    # Check if this domain is already fully processed in a resumed session
    if [[ -f "${target_dir}/.PHOENIX_COMPLETED" ]]; then
        log "INFO" "[${domain}] Skipping - already completed in a previous session." "${C_DIM}"
        # Update DOMAIN_STATS from existing files for reporting purposes
        DOMAIN_STATS["${domain}_subdomains"]=$(wc -l < "${target_dir}/all_subs.final.txt" 2>/dev/null || echo "0")
        DOMAIN_STATS["${domain}_live_hosts"]=$(wc -l < "${target_dir}/live_urls.txt" 2>/dev/null || echo "0")
        DOMAIN_STATS["${domain}_vulnerabilities"]=$(wc -l < "${target_dir}/vulnerabilities/nuclei_results.json" 2>/dev/null || echo "0")
        DOMAIN_STATS["${domain}_takeovers"]=$(jq -r '. | length' "${target_dir}/takeovers/subzy_results.json" 2>/dev/null || echo "0")
        return
    fi

    log "INFO" "[${domain}] Starting comprehensive reconnaissance..." "${C_CYAN}" "${SYM_ROCKET}"
    mkdir -p "$target_dir"
    
    local phase_start
    
    # Phase 1: Advanced Enumeration
    if [[ "$PHASE_ENUMERATION" == "true" && ! -f "${target_dir}/.phase_enumeration_completed" ]]; then
        phase_start=$(date +%s)
        run_advanced_enumeration "$domain" "$target_dir"
        PHASE_TIMES["${domain}_enumeration"]=$(( $(date +%s) - phase_start ))
        touch "${target_dir}/.phase_enumeration_completed"
    else
        log "DEBUG" "[${domain}] Skipping enumeration (already completed or disabled)."
    fi
    
    # Phase 2: DNS Brute-Force
    if [[ "$PHASE_DNS_BRUTEFORCE" == "true" && ! -f "${target_dir}/.phase_bruteforce_completed" ]]; then
        phase_start=$(date +%s)
        run_dns_bruteforce "$domain" "$target_dir"
        PHASE_TIMES["${domain}_bruteforce"]=$(( $(date +%s) - phase_start ))
        touch "${target_dir}/.phase_bruteforce_completed"
    else
        log "DEBUG" "[${domain}] Skipping brute-force (already completed or disabled)."
    fi
    
    # Phase 3: Permutation Attack
    if [[ "$PHASE_PERMUTATION" == "true" && ! -f "${target_dir}/.phase_permutation_completed" ]]; then
        phase_start=$(date +%s)
        run_permutation_attack "$domain" "$target_dir"
        PHASE_TIMES["${domain}_permutation"]=$(( $(date +%s) - phase_start ))
        touch "${target_dir}/.phase_permutation_completed"
    else
        log "DEBUG" "[${domain}] Skipping permutation (already completed or disabled)."
    fi
    
    # Combine all subdomain results (always run to ensure combined file is fresh)
    {
        [[ -f "${target_dir}/subs.passive.txt" ]] && cat "${target_dir}/subs.passive.txt"
        [[ -f "${target_dir}/subs.brute.txt" ]] && cat "${target_dir}/subs.brute.txt"
        [[ -f "${target_dir}/subs.permuted.resolved.txt" ]] && cat "${target_dir}/subs.permuted.resolved.txt"
    } | sort -u > "${target_dir}/all_subs.combined.txt"
    
    # Phase 4: DNS Resolution & Verification
    if [[ "$PHASE_VERIFICATION" == "true" && ! -f "${target_dir}/.phase_verification_completed" ]]; then
        if [[ -s "${target_dir}/all_subs.combined.txt" ]]; then
            phase_start=$(date +%s)
            log "INFO" "[${domain}] Verifying and resolving subdomains..." "${C_CYAN}" "${SYM_PROGRESS}"
            
            local puredns_options=""
            if [[ -f "$PUREDNS_RESOLVERS" ]]; then
                puredns_options+=" -r ${PUREDNS_RESOLVERS}"
            fi

            puredns resolve "${target_dir}/all_subs.combined.txt" \
                --write "${target_dir}/all_subs.resolved.txt" \
                --write-wildcards "${target_dir}/wildcards.txt" \
                ${puredns_options} \
                --quiet
            
            # Remove wildcards from final results
            if [[ -f "${target_dir}/wildcards.txt" ]]; then
                grep -vFf "${target_dir}/wildcards.txt" "${target_dir}/all_subs.resolved.txt" > "${target_dir}/all_subs.final.txt" 2>/dev/null || cp "${target_dir}/all_subs.resolved.txt" "${target_dir}/all_subs.final.txt"
            else
                cp "${target_dir}/all_subs.resolved.txt" "${target_dir}/all_subs.final.txt"
            fi
            PHASE_TIMES["${domain}_verification"]=$(( $(date +%s) - phase_start ))
        else
            log "INFO" "[${domain}] No subdomains found for verification, skipping." "${C_YELLOW}"
        fi
        touch "${target_dir}/.phase_verification_completed"
    else
        log "DEBUG" "[${domain}] Skipping verification (already completed or disabled)."
    fi
    
    # Phase 5: HTTP Probe
    if [[ ! -f "${target_dir}/.phase_httpprobe_completed" ]]; then
        if [[ -s "${target_dir}/all_subs.final.txt" ]]; then
            phase_start=$(date +%s)
            log "INFO" "[${domain}] Probing for live web services..." "${C_CYAN}" "${SYM_PROGRESS}"
            
            local current_user_agent=""
            if [[ "$STEALTH_MODE" == "true" && ${#USER_AGENTS[@]} -gt 0 ]]; then
                current_user_agent="${USER_AGENTS[$(( RANDOM % ${#USER_AGENTS[@]} ))]}"
            fi

            local proxy_option=""
            if [[ "$STEALTH_MODE" == "true" && -n "$PROXY_LIST" && -f "$PROXY_LIST" ]]; then
                # httpx supports -proxy; assumes file contains one proxy per line
                proxy_option="-proxy $(shuf -n 1 "$PROXY_LIST")" 
                log "DEBUG" "[${domain}] Using proxy for httpx: ${proxy_option}"
            fi

            httpx_live -list "${target_dir}/all_subs.final.txt" \
                    -threads "${HTTPX_THREADS:-100}" \
                    -rate-limit "${HTTPX_RATE_LIMIT:-150}" \
                    -timeout "$TIMEOUT" \
                    -retries "${MAX_RETRIES}" \
                    -json -o "${target_dir}/httpx.results.json" \
                    -silent \
                    ${proxy_option} \
                    ${current_user_agent:+-H "User-Agent: ${current_user_agent}"}
            
            if [[ -s "${target_dir}/httpx.results.json" ]]; then
                jq -r '.url' "${target_dir}/httpx.results.json" > "${target_dir}/live_urls.txt"
                local live_count=$(wc -l < "${target_dir}/live_urls.txt" 2>/dev/null || echo "0")
                log "SUCCESS" "[${domain}] Found ${live_count} live web services" "${C_GREEN}" "${SYM_SUCCESS}"
            else
                log "INFO" "[${domain}] httpx found no live web services." "${C_BLUE}"
            fi
            PHASE_TIMES["${domain}_http_probe"]=$(( $(date +%s) - phase_start ))
        else
            log "INFO" "[${domain}] No final subdomains to probe, skipping HTTP probe." "${C_YELLOW}"
        fi
        touch "${target_dir}/.phase_httpprobe_completed"
    else
        log "DEBUG" "[${domain}] Skipping HTTP probe (already completed)."
    fi

    # --- NEW PHASE: WAF/CDN Detection ---
    if [[ "$PHASE_WAF_CDN_DETECTION" == "true" && ! -f "${target_dir}/.phase_waf_cdn_completed" ]]; then
        phase_start=$(date +%s)
        run_waf_cdn_detection "$domain" "$target_dir"
        PHASE_TIMES["${domain}_waf_cdn_detection"]=$(( $(date +%s) - phase_start ))
        touch "${target_dir}/.phase_waf_cdn_completed"
    else
        log "DEBUG" "[${domain}] Skipping WAF/CDN detection (already completed or disabled)."
    fi

    # Phase 6: Port Scanning
    if [[ "$PHASE_PORTSCAN" == "true" && ! -f "${target_dir}/.phase_portscan_completed" ]]; then
        phase_start=$(date +%s)
        run_port_scan "$domain" "$target_dir"
        PHASE_TIMES["${domain}_portscan"]=$(( $(date +%s) - phase_start ))
        touch "${target_dir}/.phase_portscan_completed"
    else
        log "DEBUG" "[${domain}] Skipping port scan (already completed or disabled)."
    fi
    
    # Phase 7: Web Crawling
    if [[ "$PHASE_WEB_CRAWLING" == "true" && ! -f "${target_dir}/.phase_crawling_completed" ]]; then
        phase_start=$(date +%s)
        run_web_crawling "$domain" "$target_dir"
        PHASE_TIMES["${domain}_crawling"]=$(( $(date +%s) - phase_start ))
        touch "${target_dir}/.phase_crawling_completed"
    else
        log "DEBUG" "[${domain}] Skipping web crawling (already completed or disabled)."
    fi

    # --- NEW PHASE: Content Discovery ---
    if [[ "$PHASE_CONTENT_DISCOVERY" == "true" && ! -f "${target_dir}/.phase_content_discovery_completed" ]]; then
        phase_start=$(date +%s)
        run_content_discovery "$domain" "$target_dir"
        PHASE_TIMES["${domain}_content_discovery"]=$(( $(date +%s) - phase_start ))
        touch "${target_dir}/.phase_content_discovery_completed"
    else
        log "DEBUG" "[${domain}] Skipping content discovery (already completed or disabled)."
    fi
    
    # Phase 8: Vulnerability Scanning
    if [[ "$PHASE_VULNERABILITY_SCAN" == "true" && ! -f "${target_dir}/.phase_vulnscan_completed" ]]; then
        phase_start=$(date +%s)
        run_vulnerability_scan "$domain" "$target_dir"
        PHASE_TIMES["${domain}_vuln_scan"]=$(( $(date +%s) - phase_start ))
        touch "${target_dir}/.phase_vulnscan_completed"
    else
        log "DEBUG" "[${domain}] Skipping vulnerability scan (already completed or disabled)."
    fi

    # --- NEW PHASE: Subdomain Takeover Check ---
    if [[ "$PHASE_TAKEOVER_CHECK" == "true" && ! -f "${target_dir}/.phase_takeover_completed" ]]; then
        phase_start=$(date +%s)
        run_subdomain_takeover_check "$domain" "$target_dir"
        PHASE_TIMES["${domain}_takeover_check"]=$(( $(date +%s) - phase_start ))
        touch "${target_dir}/.phase_takeover_completed"
    else
        log "DEBUG" "[${domain}] Skipping subdomain takeover check (already completed or disabled)."
    fi
    
    # Phase 9: Screenshot Capture
    if [[ "$PHASE_SCREENSHOT" == "true" && ! -f "${target_dir}/.phase_screenshots_completed" ]]; then
        phase_start=$(date +%s)
        run_screenshot_capture "$domain" "$target_dir"
        PHASE_TIMES["${domain}_screenshots"]=$(( $(date +%s) - phase_start ))
        touch "${target_dir}/.phase_screenshots_completed"
    else
        log "DEBUG" "[${domain}] Skipping screenshot capture (already completed or disabled)."
    fi
    
    # Phase 10: AI Analysis
    if [[ "$AI_ANALYSIS" == "true" && ! -f "${target_dir}/.phase_ai_analysis_completed" ]]; then
        phase_start=$(date +%s)
        run_ai_analysis "$domain" "$target_dir"
        PHASE_TIMES["${domain}_ai_analysis"]=$(( $(date +%s) - phase_start ))
        touch "${target_dir}/.phase_ai_analysis_completed"
    else
        log "DEBUG" "[${domain}] Skipping AI analysis (already completed or disabled)."
    fi
    
    # Calculate domain statistics
    local total_subs live_hosts vuln_count takeover_count
    total_subs=$(wc -l < "${target_dir}/all_subs.final.txt" 2>/dev/null || echo "0")
    live_hosts=$(wc -l < "${target_dir}/live_urls.txt" 2>/dev/null || echo "0")
    vuln_count=$(wc -l < "${target_dir}/vulnerabilities/nuclei_results.json" 2>/dev/null || echo "0")
    takeover_count=$(jq -r '. | length' "${target_dir}/takeovers/subzy_results.json" 2>/dev/null || echo "0")
    
    DOMAIN_STATS["${domain}_subdomains"]="${total_subs}"
    DOMAIN_STATS["${domain}_live_hosts"]="${live_hosts}"
    DOMAIN_STATS["${domain}_vulnerabilities"]="${vuln_count}"
    DOMAIN_STATS["${domain}_takeovers"]="${takeover_count}"
    
    log "SUCCESS" "[${domain}] Reconnaissance completed - ${total_subs} subs, ${live_hosts} live, ${vuln_count} vulns, ${takeover_count} takeovers" "${C_GREEN}" "${SYM_SUCCESS}"
    
    # Mark domain as fully completed for resume
    touch "${target_dir}/.PHOENIX_COMPLETED"
}

# --- ENHANCED REPORTING ---
generate_comprehensive_report() {
    local session_dir="$1"
    log "INFO" "Generating comprehensive reconnaissance report..." "${C_CYAN}" "${SYM_PROGRESS}"
    local report_dir="${session_dir}/reports"
    mkdir -p "$report_dir"
    
    # Generate summary report (Markdown)
    {
        echo "# DNSHunter Phoenix v3.1 'Supernova Pro' - Reconnaissance Report"
        echo "Generated: $(date)"
        echo "Session: $(basename "$session_dir")"
        local end_time=$(date +%s)
        local total_duration=$((end_time - START_TIME))
        local duration_str=$(printf '%02dh:%02dm:%02ds\n' $((total_duration/3600)) $((total_duration%3600/60)) $((total_duration%60)))
        echo "Duration: ${duration_str}"
        echo ""
        
        echo "## Executive Summary"
        local total_domains total_subs total_live total_vulns total_takeovers
        total_domains=$(wc -l < "${session_dir}/target_list.txt" 2>/dev/null || echo "0")
        total_subs=0
        total_live=0
        total_vulns=0
        total_takeovers=0
        
        # Iterate over all domains processed (even if resumed)
        while IFS= read -r domain; do
            [[ -z "$domain" ]] && continue
            total_subs=$((total_subs + DOMAIN_STATS["${domain}_subdomains"]:-0))
            total_live=$((total_live + DOMAIN_STATS["${domain}_live_hosts"]:-0))
            total_vulns=$((total_vulns + DOMAIN_STATS["${domain}_vulnerabilities"]:-0))
            total_takeovers=$((total_takeovers + DOMAIN_STATS["${domain}_takeovers"]:-0))
        done < "${session_dir}/target_list.txt"
        
        echo "- **Domains Scanned:** ${total_domains}"
        echo "- **Subdomains Discovered:** ${total_subs}"
        echo "- **Live Hosts Found:** ${total_live}"
        echo "- **Vulnerabilities Detected:** ${total_vulns}"
        echo "- **Potential Subdomain Takeovers:** ${total_takeovers}"
        echo ""
        
        echo "## Domain Statistics"
        while IFS= read -r domain; do
            [[ -z "$domain" ]] && continue
            echo "### ${domain}"
            echo "- Subdomains: ${DOMAIN_STATS["${domain}_subdomains"]:-0}"
            echo "- Live Hosts: ${DOMAIN_STATS["${domain}_live_hosts"]:-0}"
            echo "- Vulnerabilities: ${DOMAIN_STATS["${domain}_vulnerabilities"]:-0}"
            echo "- Takeovers: ${DOMAIN_STATS["${domain}_takeovers"]:-0}"
            echo ""
            
            if [[ -s "${session_dir}/${domain}/live_urls.txt" ]]; then
                echo "#### Live URLs"
                echo '```'
                cat "${session_dir}/${domain}/live_urls.txt"
                echo '```'
                echo ""
            fi

            if [[ -s "${session_dir}/${domain}/vulnerabilities/all_vulns_summary.txt" ]]; then
                echo "#### Vulnerability Summary"
                echo '```'
                cat "${session_dir}/${domain}/vulnerabilities/all_vulns_summary.txt"
                echo '```'
                echo ""
            fi

            if [[ -s "${session_dir}/${domain}/takeovers/potential_takeovers.txt" ]]; then
                echo "#### Potential Takeovers"
                echo '```'
                cat "${session_dir}/${domain}/takeovers/potential_takeovers.txt"
                echo '```'
                echo ""
            fi

        done < "${session_dir}/target_list.txt"

        echo "## Performance Metrics (per domain & phase)"
        for phase_key in "${!PHASE_TIMES[@]}"; do
            echo "- ${phase_key}: ${PHASE_TIMES[${phase_key}]}s"
        done
        echo ""
    } > "${report_dir}/summary_report.md"
    
    # Generate JSON report
    if [[ "$GENERATE_JSON" == "true" ]]; then
        generate_json_report "$session_dir" "${report_dir}/report.json"
    fi
    
    # Generate CSV report
    if [[ "$GENERATE_CSV" == "true" ]]; then
        generate_csv_report "$session_dir" "${report_dir}/report.csv"
    fi
    
    # Compress results if enabled
    if [[ "$COMPRESS_RESULTS" == "true" ]]; then
        log "INFO" "Compressing results..." "${C_CYAN}" "${SYM_PROGRESS}"
        tar -czf "${session_dir}.tar.gz" -C "$(dirname "$session_dir")" "$(basename "$session_dir")"
        log "SUCCESS" "Results compressed to ${session_dir}.tar.gz" "${C_GREEN}" "${SYM_SUCCESS}"
    fi
    log "SUCCESS" "Comprehensive report generated successfully!" "${C_GREEN}" "${SYM_SUCCESS}"
}

generate_json_report() {
    local session_dir="$1" output_file="$2"
    
    {
        echo "{"
        echo "  \"session\": \"$(basename "$session_dir")\","
        echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
        local end_time=$(date +%s)
        local total_duration=$((end_time - START_TIME))
        echo "  \"duration_seconds\": ${total_duration},"
        echo "  \"domains\": ["
        
        local first_domain=true
        while IFS= read -r domain; do
            [[ -z "$domain" ]] && continue
            if [[ "$first_domain" == false ]]; then
                echo ","
            fi
            first_domain=false
            
            local domain_target_dir="${session_dir}/${domain}"
            local domain_subs=$(wc -l < "${domain_target_dir}/all_subs.final.txt" 2>/dev/null || echo "0")
            local domain_live_hosts=$(wc -l < "${domain_target_dir}/live_urls.txt" 2>/dev/null || echo "0")
            local domain_vulns=$(wc -l < "${domain_target_dir}/vulnerabilities/nuclei_results.json" 2>/dev/null || echo "0")
            local domain_takeovers=$(jq -r '. | length' "${domain_target_dir}/takeovers/subzy_results.json" 2>/dev/null || echo "0")

            echo "    {"
            echo "      \"domain\": \"$domain\","
            echo "      \"subdomains_found\": ${domain_subs},"
            echo "      \"live_hosts\": ${domain_live_hosts},"
            echo "      \"vulnerabilities_found\": ${domain_vulns},"
            echo "      \"potential_takeovers\": ${domain_takeovers},"
            echo "      \"details_path\": \"$(basename "$session_dir")/${domain}\""
            # You can add more detailed paths or extracted data here
            echo -n "    }"
        done < "${session_dir}/target_list.txt"
        
        echo ""
        echo "  ]"
        echo "}"
    } > "$output_file"
}

generate_csv_report() {
    local session_dir="$1" output_file="$2"
    
    {
        echo "Domain,Subdomains,Live_Hosts,Vulnerabilities,Potential_Takeovers"
        while IFS= read -r domain; do
            [[ -z "$domain" ]] && continue
            local domain_target_dir="${session_dir}/${domain}"
            local domain_subs=$(wc -l < "${domain_target_dir}/all_subs.final.txt" 2>/dev/null || echo "0")
            local domain_live_hosts=$(wc -l < "${domain_target_dir}/live_urls.txt" 2>/dev/null || echo "0")
            local domain_vulns=$(wc -l < "${domain_target_dir}/vulnerabilities/nuclei_results.json" 2>/dev/null || echo "0")
            local domain_takeovers=$(jq -r '. | length' "${domain_target_dir}/takeovers/subzy_results.json" 2>/dev/null || echo "0")

            echo "${domain},${domain_subs},${domain_live_hosts},${domain_vulns},${domain_takeovers}"
        done < "${session_dir}/target_list.txt"
    } > "$output_file"
}

# --- SESSION MANAGEMENT ---
create_session() {
    local output_dir="$1"
    local session_name="dnshunter_$(date +%Y%m%d_%H%M%S)"
    local session_dir="${output_dir}/${session_name}"
    
    mkdir -p "$session_dir"
    echo "$session_name" > "${session_dir}/.session_info"
    echo "$session_dir" # Return the session directory path
}

resume_session() {
    local session_dir="$1"
    if [[ ! -d "$session_dir" ]]; then
        log "ERROR" "Session directory not found: ${session_dir}" "${C_RED}" "${SYM_ERROR}"
        exit 1
    fi
    
    log "INFO" "Resuming session: $(basename "$session_dir")" "${C_BLUE}" "${SYM_INFO}"
    
    # Reload existing config if present
    local resume_config_path="${session_dir}/dnshunter.conf"
    if [[ -f "$resume_config_path" ]]; then
        load_config "$resume_config_path"
        log "INFO" "Loaded configuration from resumed session." "${C_BLUE}"
    else
        log "WARNING" "No config file found in session directory. Using current defaults/CLI args." "${C_YELLOW}"
    fi

    # Populate DOMAIN_STATS for already processed domains
    if [[ -f "${session_dir}/target_list.txt" ]]; then
        while IFS= read -r domain; do
            local domain_target_dir="${session_dir}/${domain}"
            if [[ -f "${domain_target_dir}/.PHOENIX_COMPLETED" ]]; then
                DOMAIN_STATS["${domain}_subdomains"]=$(wc -l < "${domain_target_dir}/all_subs.final.txt" 2>/dev/null || echo "0")
                DOMAIN_STATS["${domain}_live_hosts"]=$(wc -l < "${domain_target_dir}/live_urls.txt" 2>/dev/null || echo "0")
                DOMAIN_STATS["${domain}_vulnerabilities"]=$(wc -l < "${domain_target_dir}/vulnerabilities/nuclei_results.json" 2>/dev/null || echo "0")
                DOMAIN_STATS["${domain}_takeovers"]=$(jq -r '. | length' "${domain_target_dir}/takeovers/subzy_results.json" 2>/dev/null || echo "0")
                log "DEBUG" "[${domain}] Found previous completion status."
            fi
        done < "${session_dir}/target_list.txt"
    fi
}

# --- MAIN EXECUTION FLOW ---
main() {
    local domains_file="" output_dir_cli="" config_file_cli=""
    local resume_dir_cli="" concurrency_cli="" rate_limit_cli="" timeout_cli="" retries_cli=""
    local ai_analysis_cli="false" vuln_scan_cli="false" deep_scan_cli="false" stealth_cli="false"
    local json_cli="false" csv_cli="false" live_updates_cli="false"
    local takeover_check_cli="false" waf_cdn_detect_cli="false" content_discover_cli="false"

    # Save original arguments for possible re-application if config loads
    local original_args=("$@")

    # Parse command line arguments first to determine config path
    while [[ $# -gt 0 ]]; do
        case $1 in
            --config)
                config_file_cli="$2"
                shift 2
                ;;
            *)
                shift # Consume arg, will re-parse for actual settings later
                ;;
        esac
    done

    # Determine which config file to load
    local final_config_path="${DEFAULT_CONFIG_PATH}"
    if [[ -n "$config_file_cli" ]]; then
        final_config_path="$config_file_cli"
    fi
    load_config "$final_config_path" # Load defaults and then custom config

    # Re-parse command line arguments to override loaded config values
    set -- "${original_args[@]}" # Reset positional parameters to original arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            --init)
                generate_default_config "$DEFAULT_CONFIG_PATH"
                exit 0
                ;;
            -l|--list)
                domains_file="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIRECTORY="$2" # Overrides config
                shift 2
                ;;
            -c|--concurrency)
                CONCURRENCY="$2" # Overrides config
                shift 2
                ;;
            -r|--rate-limit)
                RATE_LIMIT="$2" # Overrides config
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2" # Overrides config
                shift 2
                ;;
            --retries)
                MAX_RETRIES="$2" # Overrides config
                shift 2
                ;;
            --config) # Already handled, consume again
                shift 2
                ;;
            --resume)
                resume_dir_cli="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE="true" # Overrides config
                shift
                ;;
            -q|--quiet)
                QUIET="true" # Overrides config
                LIVE_UPDATES="false" # Quiet mode disables live updates
                shift
                ;;
            --ai-analysis)
                AI_ANALYSIS="true" # Overrides config
                shift
                ;;
            --vuln-scan)
                PHASE_VULNERABILITY_SCAN="true" # Overrides config
                shift
                ;;
            --deep-scan)
                DEEP_SCAN="true" # Overrides config
                PHASE_PERMUTATION="true"
                PHASE_WEB_CRAWLING="true"
                PHASE_CONTENT_DISCOVERY="true" # Deep scan also enables content discovery
                shift
                ;;
            --stealth)
                STEALTH_MODE="true" # This flag will trigger overrides in load_config
                RATE_LIMIT="100"       # Explicitly set low limits if CLI --stealth is used
                HTTPX_RATE_LIMIT="20"
                CONCURRENCY="5"
                shift
                ;;
            --json)
                GENERATE_JSON="true" # Overrides config
                shift
                ;;
            --csv)
                GENERATE_CSV="true" # Overrides config
                shift
                ;;
            --live-updates)
                LIVE_UPDATES="true" # Overrides config
                # If quiet is set, this might be overridden back to false by quiet, but CLI takes precedence
                if [[ "$QUIET" == "true" ]]; then
                    log "WARNING" "--live-updates conflicts with --quiet. Live updates will be disabled." "${C_YELLOW}" "${SYM_WARNING}"
                    LIVE_UPDATES="false"
                fi
                shift
                ;;
            --takeover-check)
                PHASE_TAKEOVER_CHECK="true"
                shift
                ;;
            --waf-cdn-detect)
                PHASE_WAF_CDN_DETECTION="true"
                shift
                ;;
            --content-discover)
                PHASE_CONTENT_DISCOVERY="true"
                shift
                ;;
            *)
                log "ERROR" "Unknown option: $1" "${C_RED}" "${SYM_ERROR}"
                show_help
                exit 1
                ;;
        esac
    done

    # --- Script Entry & Initialization ---
    display_banner # Call after initial config load to ensure banner is correctly colored
    manage_dependencies

    # Create a default resolvers.txt if it doesn't exist
    if [[ ! -f "$DEFAULT_RESOLVERS" ]]; then
        log "INFO" "Creating default resolvers file at ${DEFAULT_RESOLVERS}" "${C_BLUE}"
        echo "1.1.1.1" > "$DEFAULT_RESOLVERS"
        echo "8.8.8.8" >> "$DEFAULT_RESOLVERS"
        echo "9.9.9.9" >> "$DEFAULT_RESOLVERS"
        echo "208.67.222.222" >> "$DEFAULT_RESOLVERS"
        log "INFO" "Consider populating ${DEFAULT_RESOLVERS} with more high-performance resolvers." "${C_BLUE}"
    fi

    if [[ -n "$AUTO_WORDLIST_UPDATE" && "$AUTO_WORDLIST_UPDATE" == "true" ]]; then
        update_wordlists
    fi

    if [[ -z "$domains_file" && -z "$resume_dir_cli" ]]; then
        log "FATAL" "No domain list provided. Use -l <file> or --resume <dir>." "${C_RED}" "${SYM_ERROR}"
        show_help
        exit 1
    fi

    local session_dir
    if [[ -n "$resume_dir_cli" ]]; then
        session_dir="$resume_dir_cli"
        resume_session "$session_dir"
        # Ensure target_list.txt exists in resumed session
        domains_file="${session_dir}/target_list.txt"
        [[ ! -f "$domains_file" ]] && { log "FATAL" "Cannot find target_list.txt in resumed session: ${domains_file}. Aborting." "${C_RED}" "${SYM_ERROR}"; exit 1; }
    else
        session_dir=$(create_session "$OUTPUT_DIRECTORY")
        if [[ -z "$session_dir" ]]; then
            log "FATAL" "Failed to create session directory. Aborting." "${C_RED}" "${SYM_ERROR}"
            exit 1
        fi
        # Copy and clean the initial domains file to the session directory
        sed '/^\s*$/d' "$domains_file" > "${session_dir}/target_list.txt"
        domains_file="${session_dir}/target_list.txt"
        # Save current effective config for resume
        declare -p CONCURRENCY OUTPUT_DIRECTORY VERBOSE QUIET RATE_LIMIT TIMEOUT MAX_RETRIES \
            PHASE_ENUMERATION PHASE_DNS_BRUTEFORCE PHASE_PERMUTATION PHASE_VERIFICATION \
            PHASE_PORTSCAN PHASE_WEB_CRAWLING PHASE_VULNERABILITY_SCAN PHASE_SCREENSHOT \
            PHASE_REPORTING PHASE_TAKEOVER_CHECK PHASE_WAF_CDN_DETECTION PHASE_CONTENT_DISCOVERY \
            AI_ANALYSIS DEEP_SCAN STEALTH_MODE LIVE_UPDATES AUTO_WORDLIST_UPDATE \
            HTTPX_THREADS HTTPX_RATE_LIMIT DNS_WORDLIST PUREDNS_RESOLVERS NAABU_PORTS NAABU_RATE \
            NUCLEI_TEMPLATES SCREENSHOT_QUALITY GOBUSTER_WORDLIST GOBUSTER_EXTENSIONS \
            ENABLE_SHODAN SHODAN_API_KEY ENABLE_CENSYS CENSYS_API_ID CENSYS_API_SECRET \
            ENABLE_VIRUSTOTAL VIRUSTOTAL_API_KEY CHAOS_API_KEY \
            NOTIFY_ENABLED NOTIFY_WEBHOOK_URL NOTIFY_SLACK_WEBHOOK NOTIFY_DISCORD_WEBHOOK NOTIFY_EMAIL \
            GENERATE_JSON GENERATE_CSV GENERATE_XML COMPRESS_RESULTS \
            RANDOM_DELAY_MIN RANDOM_DELAY_MAX PROXY_LIST > "${session_dir}/dnshunter.conf" 2>/dev/null \
            || log "WARNING" "Failed to save current configuration to session directory." "${C_YELLOW}" "${SYM_WARNING}"
    fi

    local total_domains
    total_domains=$(wc -l < "$domains_file")
    log "SUCCESS" "Session started: $(basename "$session_dir")" "${C_GREEN}" "${SYM_SUCCESS}"
    log "INFO" "Scanning ${C_YELLOW}${total_domains}${C_END} domains with concurrency of ${C_YELLOW}${CONCURRENCY}${C_END}." "${C_BLUE}" "${SYM_INFO}"

    # --- Concurrent Domain Processing ---
    local pids=()
    local domain_counter=0 # Use different name to avoid conflict with domain_count in show_progress
    trap 'log "WARNING" "Scan interrupted! Cleaning up child processes..." "${C_YELLOW}" "${SYM_WARNING}"; kill $(jobs -p) &>/dev/null; exit 1' EXIT

    while IFS= read -r domain || [[ -n "$domain" ]]; do
        [[ -z "$domain" ]] && continue
        domain_counter=$((domain_counter + 1))

        process_domain "$domain" "$session_dir" &
        pids+=($!)
        
        if [[ "$QUIET" != "true" && "$LIVE_UPDATES" == "true" ]]; then
            show_progress "$domain_counter" "$total_domains" "Processing Domains"
        fi

        if (( ${#pids[@]} >= CONCURRENCY )); then
            wait -n
            # Remove finished PIDs from the array
            local new_pids=()
            for pid in "${pids[@]}"; do
                if kill -0 "$pid" 2>/dev/null; then
                    new_pids+=("$pid")
                fi
            done
            pids=("${new_pids[@]}")
        fi
    done < "$domains_file"

    log "INFO" "Waiting for all reconnaissance tasks to finish..." "${C_CYAN}" "${SYM_PROGRESS}"
    wait # Wait for any remaining background processes
    echo # Newline after progress bar

    # --- Finalization and Reporting ---
    local end_time total_duration
    end_time=$(date +%s)
    total_duration=$((end_time - START_TIME))
    log "SUCCESS" "All domains processed in ${total_duration} seconds." "${C_GREEN}" "${SYM_SUCCESS}"

    if [[ "$PHASE_REPORTING" == "true" ]]; then
        generate_comprehensive_report "$session_dir"
    fi

    send_notification "$session_dir" "Scan complete!" "high"
    log "INFO" "DNSHunter Phoenix run has finished. Results are in: ${session_dir}" "${C_BLUE}" "${SYM_ROCKET}"
    check_system_resources
}

# --- SCRIPT ENTRY POINT ---
if [[ $EUID -eq 0 ]]; then
    log "ERROR" "This script should not be run as root to prevent potential system modifications by tools." "${C_RED}" "${SYM_ERROR}"
    exit 1
fi

main "$@"
