#!/bin/bash
#
# DNSHunter - A comprehensive DNS enumeration tool for bug bounty hunters
#
# Features:
# - Integration with multiple subdomain discovery tools:
#   * Subfinder
#   * Assetfinder
#   * Findomain
#   * Sublist3r
#   * GoBuster DNS
#   * Dnscan
#   * Aiodnsbrute
# - Certificate Transparency logs search (crt.sh)
# - SecurityTrails API integration
# - Shodan API integration
# - GitHub subdomain discovery
# - DNS record queries (A, AAAA, CNAME, MX, TXT, NS, SOA, etc.)
# - Zone transfers
# - Wildcard detection
# - Reverse DNS lookups
# - Domain takeover checks
# - DNS cache snooping
# - DNS alterations and permutations
# - Export results to multiple formats
# - Color-coded output for better readability

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
UNDERLINE='\033[4m'
NC='\033[0m' # No Color

# Temporary files/directories
TEMP_DIR="/tmp/dnshunter-$(date +%s)"
RESULTS_FILE="$TEMP_DIR/results.txt"
ALL_SUBDOMAINS="$TEMP_DIR/all_subdomains.txt"
VERIFIED_SUBDOMAINS="$TEMP_DIR/verified_subdomains.txt"
TAKEOVERS_FILE="$TEMP_DIR/potential_takeovers.txt"
NAMESERVERS_FILE="$TEMP_DIR/nameservers.txt"
SOURCES_DIR="$TEMP_DIR/sources"

# Set default values
MAX_THREADS=10
TIMEOUT=2
USE_EXTERNAL_TOOLS=true
PERFORM_ALTERATIONS=false
PERFORM_PERMUTATIONS=false
OUTPUT_FORMAT="txt"
VERBOSE=false
TARGET_DOMAIN=""
GITHUB_TOKEN=""
SECURITYTRAILS_API=""
SHODAN_API=""
OUTPUT_FILE=""
CUSTOM_DNS=""

# Function to display the banner
print_banner() {
    echo -e "${BLUE}██████╗ ███╗   ██╗███████╗${CYAN}██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ "
    echo -e "${BLUE}██╔══██╗████╗  ██║██╔════╝${CYAN}██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗"
    echo -e "${BLUE}██║  ██║██╔██╗ ██║███████╗${CYAN}███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝"
    echo -e "${BLUE}██║  ██║██║╚██╗██║╚════██║${CYAN}██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗"
    echo -e "${BLUE}██████╔╝██║ ╚████║███████║${CYAN}██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║"
    echo -e "${BLUE}╚═════╝ ╚═╝  ╚═══╝╚══════╝${CYAN}╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"
    echo -e ""
    echo -e "${GREEN}${BOLD}The Ultimate DNS Reconnaissance Tool for Bug Hunters${NC}"
    echo -e "${YELLOW}Version 3.0 | https://github.com/dnshunter${NC}"
    echo ""
}

# Function to print messages
print_success() {
    echo -e "${GREEN}[+] $1${NC}"
}

print_info() {
    echo -e "${BLUE}[*] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

print_error() {
    echo -e "${RED}[-] $1${NC}"
}

print_detail() {
    echo -e "${CYAN}    - $1${NC}"
}

# Function to check command availability
check_command() {
    command -v "$1" >/dev/null 2>&1
}

# Function to initialize the environment
init_environment() {
    mkdir -p "$TEMP_DIR"
    mkdir -p "$SOURCES_DIR"
    touch "$ALL_SUBDOMAINS"
    touch "$VERIFIED_SUBDOMAINS"
    touch "$TAKEOVERS_FILE"
    touch "$NAMESERVERS_FILE"
}

# Function to clean up temporary files
cleanup() {
    if [ "$VERBOSE" = true ]; then
        print_info "Cleaning up temporary files..."
    fi
    rm -rf "$TEMP_DIR"
}

# Set trap to clean up on exit
trap cleanup EXIT

# Function to show help
show_help() {
    echo "Usage: $0 [options] domain"
    echo ""
    echo "Options:"
    echo "  -h, --help                Show this help message and exit"
    echo "  -t, --threads N           Number of threads (default: 10)"
    echo "  -o, --output FILE         Output file to save results"
    echo "  -f, --format FORMAT       Output format: txt, json, csv (default: txt)"
    echo "  -T, --timeout SECONDS     DNS timeout in seconds (default: 2)"
    echo "  -n, --no-external-tools   Don't use external tools (subfinder, amass, etc.)"
    echo "  -g, --github-token TOKEN  GitHub API token for subdomain search"
    echo "  -s, --securitytrails-api KEY  SecurityTrails API key"
    echo "  -S, --shodan-api KEY      Shodan API key"
    echo "  -a, --alterations         Generate and check DNS alterations"
    echo "  -p, --permutations        Generate and check permutations"
    echo "  -v, --verbose             Verbose output"
    echo "  -d, --dns-server SERVER   Custom DNS server to use for queries"
    echo "  --version                 Show version information and exit"
    echo ""
    echo "Example:"
    echo "  $0 -t 20 -o results.txt -f json -S YOUR_SHODAN_API example.com"
    exit 0
}

# Function to show version
show_version() {
    echo "DNSHunter v3.0"
    exit 0
}

# Function to parse arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                ;;
            -t|--threads)
                MAX_THREADS="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -f|--format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -T|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -n|--no-external-tools)
                USE_EXTERNAL_TOOLS=false
                shift
                ;;
            -g|--github-token)
                GITHUB_TOKEN="$2"
                shift 2
                ;;
            -s|--securitytrails-api)
                SECURITYTRAILS_API="$2"
                shift 2
                ;;
            -S|--shodan-api)
                SHODAN_API="$2"
                shift 2
                ;;
            -a|--alterations)
                PERFORM_ALTERATIONS=true
                shift
                ;;
            -p|--permutations)
                PERFORM_PERMUTATIONS=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -d|--dns-server)
                CUSTOM_DNS="$2"
                shift 2
                ;;
            --version)
                show_version
                ;;
            *)
                if [[ "$1" == -* ]]; then
                    print_error "Unknown option: $1"
                    show_help
                else
                    TARGET_DOMAIN="$1"
                    shift
                fi
                ;;
        esac
    done

    # Check if TARGET_DOMAIN is provided
    if [[ -z "$TARGET_DOMAIN" ]]; then
        print_error "No target domain specified."
        show_help
    fi
}

# Function to get nameservers
get_nameservers() {
    print_info "Getting nameservers for $TARGET_DOMAIN"
    
    local dns_option=""
    if [[ -n "$CUSTOM_DNS" ]]; then
        dns_option="@$CUSTOM_DNS"
    fi
    
    nameservers=$(dig $dns_option NS "$TARGET_DOMAIN" +short)
    
    if [[ -z "$nameservers" ]]; then
        print_error "Failed to get nameservers"
        return 1
    fi
    
    echo "$nameservers" > "$NAMESERVERS_FILE"
    
    count=$(echo "$nameservers" | wc -l)
    print_success "Found $count nameservers"
    
    while read -r ns; do
        print_detail "$ns"
    done < "$NAMESERVERS_FILE"
    
    return 0
}

# Function to attempt zone transfer
attempt_zone_transfer() {
    print_info "Attempting zone transfer"
    
    transferred=false
    
    while read -r ns; do
        print_info "Attempting zone transfer from $ns"
        
        # Remove trailing dot if present
        ns=${ns%*.}
        
        zone_result=$(dig @"$ns" "$TARGET_DOMAIN" AXFR +noall +answer)
        
        if [[ -n "$zone_result" ]] && ! echo "$zone_result" | grep -q "Transfer failed"; then
            print_success "Zone transfer successful from $ns!"
            transferred=true
            
            # Extract subdomains from zone transfer
            echo "$zone_result" | grep -v "^;" | awk '{print $1}' | sort -u | while read -r name; do
                if [[ "$name" != "$TARGET_DOMAIN." ]] && [[ "$name" == *"$TARGET_DOMAIN"* ]]; then
                    # Remove trailing dot
                    subdomain=${name%*.}
                    echo "$subdomain" >> "$TEMP_DIR/zone_transfer.txt"
                    echo "$subdomain" >> "$ALL_SUBDOMAINS"
                    print_detail "$subdomain"
                fi
            done
        else
            print_error "Zone transfer failed from $ns"
        fi
    done < "$NAMESERVERS_FILE"
    
    if [[ "$transferred" == true ]]; then
        print_success "Zone transfer completed"
        sort -u "$TEMP_DIR/zone_transfer.txt" -o "$TEMP_DIR/zone_transfer.txt"
        mv "$TEMP_DIR/zone_transfer.txt" "$SOURCES_DIR/zone_transfer.txt"
    fi
    
    return $transferred
}

# Function to check for wildcard DNS
check_wildcard() {
    print_info "Checking for wildcard DNS"
    
    # Generate a random subdomain name
    random_string=$(head /dev/urandom | tr -dc 'a-z0-9' | head -c 16)
    random_subdomain="wildcard-check-$random_string.$TARGET_DOMAIN"
    
    local dns_option=""
    if [[ -n "$CUSTOM_DNS" ]]; then
        dns_option="@$CUSTOM_DNS"
    fi
    
    # Try to resolve the random subdomain
    dig_result=$(dig $dns_option A "$random_subdomain" +short)
    
    if [[ -n "$dig_result" ]]; then
        print_warning "Wildcard DNS detected! This may generate false positives."
        echo "$dig_result" > "$TEMP_DIR/wildcard_ips.txt"
        return 0
    else
        print_success "No wildcard DNS detected."
        return 1
    fi
}

# Function to run subfinder
run_subfinder() {
    if ! check_command "subfinder"; then
        print_error "subfinder not found. Please install it: https://github.com/projectdiscovery/subfinder"
        return 1
    fi
    
    print_info "Running subfinder for subdomain discovery"
    
    subfinder -d "$TARGET_DOMAIN" -silent > "$SOURCES_DIR/subfinder.txt"
    
    count=$(wc -l < "$SOURCES_DIR/subfinder.txt")
    print_success "Subfinder discovered $count subdomains"
    
    # Add results to all subdomains
    cat "$SOURCES_DIR/subfinder.txt" >> "$ALL_SUBDOMAINS"
    
    return 0
}

# Function to run assetfinder
run_assetfinder() {
    if ! check_command "assetfinder"; then
        print_error "assetfinder not found. Please install it: https://github.com/tomnomnom/assetfinder"
        return 1
    fi
    
    print_info "Running assetfinder for subdomain discovery"
    
    assetfinder --subs-only "$TARGET_DOMAIN" > "$SOURCES_DIR/assetfinder.txt"
    
    # Filter only relevant subdomains
    grep "$TARGET_DOMAIN$" "$SOURCES_DIR/assetfinder.txt" > "$SOURCES_DIR/assetfinder_filtered.txt"
    mv "$SOURCES_DIR/assetfinder_filtered.txt" "$SOURCES_DIR/assetfinder.txt"
    
    count=$(wc -l < "$SOURCES_DIR/assetfinder.txt")
    print_success "Assetfinder discovered $count subdomains"
    
    # Add results to all subdomains
    cat "$SOURCES_DIR/assetfinder.txt" >> "$ALL_SUBDOMAINS"
    
    return 0
}

# Function to run DNSRecon
run_dnsrecon() {
    if ! check_command "dnsrecon"; then
        print_error "dnsrecon not found. Please install it: https://github.com/darkoperator/dnsrecon"
        return 1
    fi
    
    print_info "Running DNSRecon for comprehensive subdomain discovery"
    
    # Run dnsrecon with multiple techniques
    # -d: domain
    # -t: type of enumeration (std = standard, rvl = reverse lookup, brt = brute force)
    # -D: dictionary file for brute force
    # --threads: number of threads
    # -j: write output to JSON file
    
    # Check for common wordlists
    wordlist="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    if [[ ! -f "$wordlist" ]]; then
        wordlist="/usr/share/wordlists/dirb/common.txt"
        if [[ ! -f "$wordlist" ]]; then
            wordlist="/usr/share/dirb/wordlists/common.txt"
            if [[ ! -f "$wordlist" ]]; then
                print_warning "No suitable wordlist found for DNSRecon brute force"
                # Continue without brute force if no wordlist found
                dnsrecon -d "$TARGET_DOMAIN" -t std,rvl --threads "$MAX_THREADS" -j "$SOURCES_DIR/dnsrecon_output.json"
                # Extract only subdomains from the results
                jq -r '.[] | select(.type=="A" or .type=="CNAME") | .name' "$SOURCES_DIR/dnsrecon_output.json" | grep "$TARGET_DOMAIN$" > "$SOURCES_DIR/dnsrecon.txt"
                rm "$SOURCES_DIR/dnsrecon_output.json"
                
                count=$(wc -l < "$SOURCES_DIR/dnsrecon.txt")
                print_success "DNSRecon discovered $count subdomains (without brute force)"
                
                # Add results to all subdomains
                cat "$SOURCES_DIR/dnsrecon.txt" >> "$ALL_SUBDOMAINS"
                return 0
            fi
        fi
    fi
    
    # Run with brute force if wordlist found
    print_info "Running DNSRecon with brute force using wordlist: $wordlist"
    dnsrecon -d "$TARGET_DOMAIN" -t std,rvl,brt -D "$wordlist" --threads "$MAX_THREADS" -j "$SOURCES_DIR/dnsrecon_output.json"
    
    # Extract only subdomains from the results
    jq -r '.[] | select(.type=="A" or .type=="CNAME") | .name' "$SOURCES_DIR/dnsrecon_output.json" | grep "$TARGET_DOMAIN$" > "$SOURCES_DIR/dnsrecon.txt"
    rm "$SOURCES_DIR/dnsrecon_output.json"
    
    count=$(wc -l < "$SOURCES_DIR/dnsrecon.txt")
    print_success "DNSRecon discovered $count subdomains"
    
    # Add results to all subdomains
    cat "$SOURCES_DIR/dnsrecon.txt" >> "$ALL_SUBDOMAINS"
    
    # Run zone transfers through DNSRecon as well (more thorough)
    print_info "Running DNSRecon zone transfer check"
    dnsrecon -d "$TARGET_DOMAIN" -t axfr -j "$SOURCES_DIR/dnsrecon_zonexfer.json"
    
    # Check if we got any new results from zone transfers
    if [[ -f "$SOURCES_DIR/dnsrecon_zonexfer.json" ]]; then
        jq -r '.[] | select(.type=="A" or .type=="CNAME") | .name' "$SOURCES_DIR/dnsrecon_zonexfer.json" | grep "$TARGET_DOMAIN$" >> "$SOURCES_DIR/dnsrecon.txt"
        rm "$SOURCES_DIR/dnsrecon_zonexfer.json"
        
        # Remove duplicates and update
        sort -u "$SOURCES_DIR/dnsrecon.txt" -o "$SOURCES_DIR/dnsrecon.txt"
        
        # Add results to all subdomains
        cat "$SOURCES_DIR/dnsrecon.txt" >> "$ALL_SUBDOMAINS"
    fi
    
    return 0
}

# Function to run findomain
run_findomain() {
    if ! check_command "findomain"; then
        print_error "findomain not found. Please install it: https://github.com/Findomain/Findomain"
        return 1
    fi
    
    print_info "Running findomain for subdomain discovery"
    
    findomain -t "$TARGET_DOMAIN" -q -o "$SOURCES_DIR/findomain.txt"
    
    count=$(wc -l < "$SOURCES_DIR/findomain.txt")
    print_success "Findomain discovered $count subdomains"
    
    # Add results to all subdomains
    cat "$SOURCES_DIR/findomain.txt" >> "$ALL_SUBDOMAINS"
    
    return 0
}

# Function to run Sublist3r
run_sublist3r() {
    if ! check_command "sublist3r"; then
        print_error "sublist3r not found. Please install it: https://github.com/aboul3la/Sublist3r"
        return 1
    fi
    
    print_info "Running Sublist3r for subdomain discovery"
    
    # Run sublist3r with output file
    sublist3r -d "$TARGET_DOMAIN" -o "$SOURCES_DIR/sublist3r.txt" > /dev/null 2>&1
    
    # Check if output file exists
    if [[ -f "$SOURCES_DIR/sublist3r.txt" ]]; then
        count=$(wc -l < "$SOURCES_DIR/sublist3r.txt")
        print_success "Sublist3r discovered $count subdomains"
        
        # Add results to all subdomains
        cat "$SOURCES_DIR/sublist3r.txt" >> "$ALL_SUBDOMAINS"
    else
        print_error "Sublist3r didn't generate output"
    fi
    
    return 0
}

# Function to run gobuster DNS
run_gobuster_dns() {
    if ! check_command "gobuster"; then
        print_error "gobuster not found. Please install it: https://github.com/OJ/gobuster"
        return 1
    fi
    
    print_info "Running gobuster DNS for subdomain discovery"
    
    # Check for common wordlists
    wordlist="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    if [[ ! -f "$wordlist" ]]; then
        wordlist="/usr/share/wordlists/dirb/common.txt"
        if [[ ! -f "$wordlist" ]]; then
            wordlist="/usr/share/dirb/wordlists/common.txt"
            if [[ ! -f "$wordlist" ]]; then
                print_error "No suitable wordlist found for gobuster DNS"
                return 1
            fi
        fi
    fi
    
    gobuster dns -d "$TARGET_DOMAIN" -w "$wordlist" -q > "$SOURCES_DIR/gobuster_dns_raw.txt"
    
    # Extract discovered subdomains
    grep "Found:" "$SOURCES_DIR/gobuster_dns_raw.txt" | awk '{print $2}' > "$SOURCES_DIR/gobuster_dns.txt"
    rm "$SOURCES_DIR/gobuster_dns_raw.txt"
    
    count=$(wc -l < "$SOURCES_DIR/gobuster_dns.txt")
    print_success "Gobuster DNS discovered $count subdomains"
    
    # Add results to all subdomains
    cat "$SOURCES_DIR/gobuster_dns.txt" >> "$ALL_SUBDOMAINS"
    
    return 0
}

# Function to query crt.sh
query_crtsh() {
    print_info "Querying crt.sh for certificate transparency logs"
    
    # Query crt.sh for the domain
    curl -s "https://crt.sh/?q=%25.$TARGET_DOMAIN&output=json" | jq -r '.[].name_value' 2>/dev/null | 
    sed 's/\*\.//g' | sort -u > "$SOURCES_DIR/crtsh_raw.txt"
    
    # Filter only relevant subdomains
    grep "$TARGET_DOMAIN$" "$SOURCES_DIR/crtsh_raw.txt" > "$SOURCES_DIR/crtsh.txt"
    rm "$SOURCES_DIR/crtsh_raw.txt"
    
    count=$(wc -l < "$SOURCES_DIR/crtsh.txt")
    print_success "Certificate transparency logs revealed $count subdomains"
    
    # Add results to all subdomains
    cat "$SOURCES_DIR/crtsh.txt" >> "$ALL_SUBDOMAINS"
    
    return 0
}

# Function to query SecurityTrails API
query_securitytrails() {
    if [[ -z "$SECURITYTRAILS_API" ]]; then
        print_error "SecurityTrails API key not provided. Skipping SecurityTrails search."
        return 1
    fi
    
    print_info "Querying SecurityTrails API for subdomains"
    
    # Query the SecurityTrails API
    response=$(curl -s -X GET "https://api.securitytrails.com/v1/domain/$TARGET_DOMAIN/subdomains" \
        -H "APIKEY: $SECURITYTRAILS_API" \
        -H "Content-Type: application/json")
    
    # Check if the API returned an error
    if echo "$response" | grep -q "error"; then
        error_message=$(echo "$response" | jq -r '.message' 2>/dev/null)
        print_error "SecurityTrails API query failed: $error_message"
        if echo "$response" | grep -q "401"; then
            print_error "API key may be invalid or expired"
        fi
        return 1
    fi
    
    # Extract subdomains
    echo "$response" | jq -r '.subdomains[]' 2>/dev/null | 
    awk -v domain=".$TARGET_DOMAIN" '{print $0 domain}' > "$SOURCES_DIR/securitytrails.txt"
    
    count=$(wc -l < "$SOURCES_DIR/securitytrails.txt")
    print_success "SecurityTrails revealed $count subdomains"
    
    # Add results to all subdomains
    cat "$SOURCES_DIR/securitytrails.txt" >> "$ALL_SUBDOMAINS"
    
    return 0
}

# Function to query Shodan API
query_shodan() {
    if [[ -z "$SHODAN_API" ]]; then
        print_error "Shodan API key not provided. Skipping Shodan search."
        return 1
    fi
    
    print_info "Querying Shodan API for subdomains"
    
    # Query the Shodan API for domain information
    response=$(curl -s "https://api.shodan.io/dns/domain/$TARGET_DOMAIN?key=$SHODAN_API")
    
    # Check if the API returned an error
    if echo "$response" | grep -q "error"; then
        error_message=$(echo "$response" | jq -r '.error' 2>/dev/null)
        print_error "Shodan API query failed: $error_message"
        if echo "$response" | grep -q "401"; then
            print_error "API key may be invalid or expired"
        fi
        return 1
    fi
    
    # Extract subdomains
    echo "$response" | jq -r '.subdomains[]' 2>/dev/null | 
    awk -v domain=".$TARGET_DOMAIN" '{print $0 domain}' > "$SOURCES_DIR/shodan.txt"
    
    # Also try host search for the domain
    host_query=$(curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_API&query=hostname:$TARGET_DOMAIN")
    echo "$host_query" | jq -r '.matches[].hostnames[]' 2>/dev/null | 
    grep "$TARGET_DOMAIN$" >> "$SOURCES_DIR/shodan.txt"
    
    # Remove duplicates
    sort -u "$SOURCES_DIR/shodan.txt" -o "$SOURCES_DIR/shodan.txt"
    
    count=$(wc -l < "$SOURCES_DIR/shodan.txt")
    print_success "Shodan revealed $count subdomains"
    
    # Add results to all subdomains
    cat "$SOURCES_DIR/shodan.txt" >> "$ALL_SUBDOMAINS"
    
    return 0
}

# Function to search GitHub for subdomains
search_github() {
    if [[ -z "$GITHUB_TOKEN" ]]; then
        print_error "GitHub API token not provided. Skipping GitHub search."
        print_error "To use GitHub search, provide a token with --github-token"
        return 1
    fi
    
    print_info "Searching GitHub for exposed subdomains"
    
    # Search for domain in code
    query=$(echo -n "$TARGET_DOMAIN" | jq -sRr @uri)
    response=$(curl -s -H "Authorization: token $GITHUB_TOKEN" -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com/search/code?q=\"$query\"%20language:any&per_page=100")
    
    # Check if the API returned an error
    if echo "$response" | grep -q "message"; then
        error_message=$(echo "$response" | jq -r '.message' 2>/dev/null)
        print_error "GitHub API query failed: $error_message"
        if echo "$response" | grep -q "401"; then
            print_error "GitHub token may be invalid or expired"
        elif echo "$response" | grep -q "403"; then
            print_error "GitHub API rate limit exceeded. Try again later."
        fi
        return 1
    fi
    
    # Get total count of results
    total_count=$(echo "$response" | jq -r '.total_count' 2>/dev/null)
    print_success "Found $total_count GitHub code results for '$TARGET_DOMAIN'"
    
    # Extract download URLs from items
    echo "$response" | jq -r '.items[].url' 2>/dev/null > "$TEMP_DIR/github_files.txt"
    
    # Process each file URL to get raw content
    while read -r file_url; do
        # Get the file data to find the download URL
        file_data=$(curl -s -H "Authorization: token $GITHUB_TOKEN" -H "Accept: application/vnd.github.v3+json" "$file_url")
        download_url=$(echo "$file_data" | jq -r '.download_url' 2>/dev/null)
        
        if [[ -n "$download_url" && "$download_url" != "null" ]]; then
            # Get the raw content and extract subdomains
            raw_content=$(curl -s "$download_url")
            echo "$raw_content" | grep -o "[a-zA-Z0-9][-a-zA-Z0-9]*\.$TARGET_DOMAIN" | sort -u >> "$SOURCES_DIR/github.txt"
        fi
    done < "$TEMP_DIR/github_files.txt"
    
    # Remove duplicates
    if [[ -f "$SOURCES_DIR/github.txt" ]]; then
        sort -u "$SOURCES_DIR/github.txt" -o "$SOURCES_DIR/github.txt"
        
        count=$(wc -l < "$SOURCES_DIR/github.txt")
        print_success "GitHub search revealed $count subdomains"
        
        # Add results to all subdomains
        cat "$SOURCES_DIR/github.txt" >> "$ALL_SUBDOMAINS"
    else
        print_error "No subdomains found from GitHub search"
        touch "$SOURCES_DIR/github.txt"
    fi
    
    return 0
}

# Function to generate DNS alterations
generate_alterations() {
    if [[ "$PERFORM_ALTERATIONS" != true ]]; then
        return 0
    fi
    
    print_info "Generating DNS alterations"
    
    # Common prefixes for alterations
    prefixes=("dev" "stage" "test" "qa" "prod" "staging" "api" "app" "admin" 
              "portal" "beta" "alpha" "vpn" "internal" "demo" "old" "new")
    
    # Get the first 100 subdomains to avoid explosion
    head -100 "$VERIFIED_SUBDOMAINS" > "$TEMP_DIR/alteration_base.txt"
    
    # Extract base subdomain names
    while read -r subdomain; do
        # Extract the first part of the subdomain
        base=$(echo "$subdomain" | awk -F'.' '{print $1}')
        
        # Generate alterations with each prefix
        for prefix in "${prefixes[@]}"; do
            echo "$prefix-$base.$TARGET_DOMAIN" >> "$TEMP_DIR/alterations.txt"
            echo "$prefix.$base.$TARGET_DOMAIN" >> "$TEMP_DIR/alterations.txt"
        done
    done < "$TEMP_DIR/alteration_base.txt"
    
    # Remove duplicates
    sort -u "$TEMP_DIR/alterations.txt" -o "$TEMP_DIR/alterations.txt"
    
    count=$(wc -l < "$TEMP_DIR/alterations.txt")
    print_success "Generated $count DNS alterations"
    
    return 0
}

# Function to generate permutations
generate_permutations() {
    if [[ "$PERFORM_PERMUTATIONS" != true ]]; then
        return 0
    fi
    
    print_info "Generating permutations of discovered subdomains"
    
    # Get the first 50 subdomains to avoid explosion
    head -50 "$VERIFIED_SUBDOMAINS" > "$TEMP_DIR/permutation_base.txt"
    
    # Extract base subdomain names
    while read -r subdomain; do
        # Extract the first part of the subdomain
        base=$(echo "$subdomain" | awk -F'.' '{print $1}')
        
        # Generate permutations with numbers
        for i in {1..4}; do
            echo "$base$i.$TARGET_DOMAIN" >> "$TEMP_DIR/permutations.txt"
            echo "$base-$i.$TARGET_DOMAIN" >> "$TEMP_DIR/permutations.txt"
            echo "$base.$i.$TARGET_DOMAIN" >> "$TEMP_DIR/permutations.txt"
            echo "$base_$i.$TARGET_DOMAIN" >> "$TEMP_DIR/permutations.txt"
            echo "$i$base.$TARGET_DOMAIN" >> "$TEMP_DIR/permutations.txt"
            echo "$i-$base.$TARGET_DOMAIN" >> "$TEMP_DIR/permutations.txt"
            echo "$i.$base.$TARGET_DOMAIN" >> "$TEMP_DIR/permutations.txt"
            echo "$i_$base.$TARGET_DOMAIN" >> "$TEMP_DIR/permutations.txt"
        done
    done < "$TEMP_DIR/permutation_base.txt"
    
    # Remove duplicates
    sort -u "$TEMP_DIR/permutations.txt" -o "$TEMP_DIR/permutations.txt"
    
    count=$(wc -l < "$TEMP_DIR/permutations.txt")
    print_success "Generated $count permutations"
    
    return 0
}

# Function to verify if a subdomain resolves and collect its DNS records
verify_subdomain() {
    local subdomain="$1"
    local dns_option=""
    if [[ -n "$CUSTOM_DNS" ]]; then
        dns_option="@$CUSTOM_DNS"
    fi
    
    # Check A record
    a_record=$(dig $dns_option +short A "$subdomain")
    
    if [[ -n "$a_record" ]]; then
        # Check if this is a wildcard response
        if [[ -f "$TEMP_DIR/wildcard_ips.txt" ]]; then
            while read -r wildcard_ip; do
                if echo "$a_record" | grep -q "$wildcard_ip"; then
                    if [[ "$VERBOSE" = true ]]; then
                        print_detail "Skipping wildcard response for $subdomain"
                    fi
                    return 1
                fi
            done < "$TEMP_DIR/wildcard_ips.txt"
        fi
        
        # Verified real subdomain
        echo "$subdomain" >> "$VERIFIED_SUBDOMAINS"
        echo "$subdomain:A:$a_record" >> "$RESULTS_FILE"
        
        # Also check for CNAME
        cname=$(dig $dns_option +short CNAME "$subdomain")
        if [[ -n "$cname" ]]; then
            echo "$subdomain:CNAME:$cname" >> "$RESULTS_FILE"
            
            # Check for common domain takeover signatures
            if echo "$cname" | grep -q -E '(s3\.amazonaws\.com|github\.io|heroku|azurewebsites\.net|cloudapp\.net|pantheon\.io|zendesk\.com|shopify\.com|unbouncepages\.com)'; then
                # If CNAME exists but doesn't resolve, potential takeover
                cname_resolve=$(dig $dns_option +short A "$cname")
                if [[ -z "$cname_resolve" ]]; then
                    echo "$subdomain -> $cname (NOT RESOLVING!)" >> "$TAKEOVERS_FILE"
                fi
            fi
        fi
        
        # Check other common record types
        # MX Records
        mx=$(dig $dns_option +short MX "$subdomain")
        if [[ -n "$mx" ]]; then
            echo "$subdomain:MX:$mx" >> "$RESULTS_FILE"
        fi
        
        # TXT Records
        txt=$(dig $dns_option +short TXT "$subdomain")
        if [[ -n "$txt" ]]; then
            echo "$subdomain:TXT:$txt" >> "$RESULTS_FILE"
        fi
        
        return 0
    fi
    
    return 1
}

# Function to verify all collected subdomains
verify_subdomains() {
    print_info "Verifying discovered subdomains"
    
    # Remove duplicates from all subdomains
    sort -u "$ALL_SUBDOMAINS" -o "$ALL_SUBDOMAINS"
    
    total=$(wc -l < "$ALL_SUBDOMAINS")
    print_info "Total of $total unique subdomains to verify"
    
    # Set up parallel processing if available
    if check_command "parallel"; then
        print_info "Using GNU Parallel for subdomain verification"
        export -f verify_subdomain print_detail
        export TEMP_DIR VERIFIED_SUBDOMAINS RESULTS_FILE TAKEOVERS_FILE VERBOSE CUSTOM_DNS
        cat "$ALL_SUBDOMAINS" | parallel -j "$MAX_THREADS" --bar verify_subdomain
    else
        print_info "GNU Parallel not found, falling back to serial processing"
        count=0
        while read -r subdomain; do
            count=$((count + 1))
            if [[ "$VERBOSE" = true ]]; then
                print_detail "Verifying $count/$total: $subdomain"
            else
                # Print progress every 50 subdomains
                if (( count % 50 == 0 )); then
                    print_info "Progress: $count/$total"
                fi
            fi
            
            verify_subdomain "$subdomain"
        done < "$ALL_SUBDOMAINS"
    fi
    
    # Count verified subdomains
    verified_count=$(wc -l < "$VERIFIED_SUBDOMAINS")
    print_success "Verified $verified_count live subdomains out of $total discovered"
    
    # Count potential takeovers
    if [[ -f "$TAKEOVERS_FILE" ]]; then
        takeover_count=$(wc -l < "$TAKEOVERS_FILE")
        if [[ $takeover_count -gt 0 ]]; then
            print_warning "Found $takeover_count potential subdomain takeovers!"
        fi
    fi
    
    return 0
}

# Function to verify alterations and permutations
verify_extra_domains() {
    if [[ "$PERFORM_ALTERATIONS" = true ]] && [[ -f "$TEMP_DIR/alterations.txt" ]]; then
        print_info "Verifying DNS alterations"
        
        total=$(wc -l < "$TEMP_DIR/alterations.txt")
        print_info "Verifying $total alterations"
        
        # Verify each alteration
        while read -r alteration; do
            verify_subdomain "$alteration"
        done < "$TEMP_DIR/alterations.txt"
        
        print_success "Completed verification of alterations"
    fi
    
    if [[ "$PERFORM_PERMUTATIONS" = true ]] && [[ -f "$TEMP_DIR/permutations.txt" ]]; then
        print_info "Verifying permutations"
        
        total=$(wc -l < "$TEMP_DIR/permutations.txt")
        print_info "Verifying $total permutations"
        
        # Verify each permutation
        while read -r permutation; do
            verify_subdomain "$permutation"
        done < "$TEMP_DIR/permutations.txt"
        
        print_success "Completed verification of permutations"
    fi
    
    return 0
}

# Function to check for domain takeover vulnerabilities
check_takeovers() {
    print_info "Checking for potential subdomain takeovers"
    
    # If takeovers file exists and has content
    if [[ -f "$TAKEOVERS_FILE" ]] && [[ -s "$TAKEOVERS_FILE" ]]; then
        takeover_count=$(wc -l < "$TAKEOVERS_FILE")
        print_warning "Found $takeover_count potential subdomain takeovers!"
        
        while read -r takeover; do
            print_detail "$takeover"
        done < "$TAKEOVERS_FILE"
    else
        print_success "No potential subdomain takeovers found"
    fi
    
    return 0
}

# Function to perform DNS cache snooping
perform_dns_cache_snooping() {
    print_info "Performing DNS cache snooping on nameservers"
    
    # Common domains to check for in cache
    cache_domains=("google.com" "facebook.com" "apple.com" "microsoft.com" "amazon.com")
    
    while read -r ns; do
        # Remove trailing dot if present
        ns=${ns%*.}
        
        print_info "Testing nameserver: $ns"
        
        for domain in "${cache_domains[@]}"; do
            # Try to query with +norecurse to check if it's in cache
            result=$(dig @"$ns" "$domain" +norecurse +tries=1 +time=2)
            
            if echo "$result" | grep -q "status: NOERROR" && ! echo "$result" | grep -q "ANSWER: 0"; then
                print_warning "Domain $domain found in cache of $ns"
            fi
        done
    done < "$NAMESERVERS_FILE"
    
    return 0
}
# Add this function right before the format_results function

# Function to export only subdomains to a file
export_subdomains_only() {
    print_info "Exporting list of subdomains only"
    
    # Create the subdomain-only file
    subdomain_file="$TARGET_DOMAIN-subdomains.txt"
    
    # Extract only unique subdomain names from verified subdomains
    sort -u "$VERIFIED_SUBDOMAINS" > "$subdomain_file"
    
    count=$(wc -l < "$subdomain_file")
    print_success "Exported $count unique subdomains to $subdomain_file"
    
    return 0
}

# Modify the format_results function by adding a call to export_subdomains_only at the beginning
format_results() {
    print_info "Formatting and saving results"
    
    # Always export subdomains-only regardless of format
    export_subdomains_only
    
    # Rest of the format_results function remains unchanged
    # Copy verified subdomains to output format
    case "$OUTPUT_FORMAT" in
        json)
            # Create JSON structure
            echo "{" > "$TEMP_DIR/output.json"
            echo "  \"target\": \"$TARGET_DOMAIN\"," >> "$TEMP_DIR/output.json"
            echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"," >> "$TEMP_DIR/output.json"
            echo "  \"total_discovered\": $(wc -l < "$ALL_SUBDOMAINS")," >> "$TEMP_DIR/output.json"
            echo "  \"total_verified\": $(wc -l < "$VERIFIED_SUBDOMAINS")," >> "$TEMP_DIR/output.json"
            
            # Convert takeovers to JSON array
            echo "  \"potential_takeovers\": [" >> "$TEMP_DIR/output.json"
            if [[ -f "$TAKEOVERS_FILE" ]] && [[ -s "$TAKEOVERS_FILE" ]]; then
                first=true
                while read -r takeover; do
                    if [[ "$first" = true ]]; then
                        first=false
                    else
                        echo "," >> "$TEMP_DIR/output.json"
                    fi
                    # Escape for JSON
                    takeover=$(echo "$takeover" | sed 's/"/\\"/g')
                    echo -n "    \"$takeover\"" >> "$TEMP_DIR/output.json"
                done < "$TAKEOVERS_FILE"
                echo "" >> "$TEMP_DIR/output.json"
            fi
            echo "  ]," >> "$TEMP_DIR/output.json"
            
            # Add nameservers
            echo "  \"nameservers\": [" >> "$TEMP_DIR/output.json"
            first=true
            while read -r ns; do
                if [[ "$first" = true ]]; then
                    first=false
                else
                    echo "," >> "$TEMP_DIR/output.json"
                fi
                # Remove trailing dot and escape for JSON
                ns=${ns%*.}
                echo -n "    \"$ns\"" >> "$TEMP_DIR/output.json"
            done < "$NAMESERVERS_FILE"
            echo "" >> "$TEMP_DIR/output.json"
            echo "  ]," >> "$TEMP_DIR/output.json"
            
            # Add subdomains with records
            echo "  \"subdomains\": [" >> "$TEMP_DIR/output.json"
            first=true
            while read -r line; do
                subdomain=$(echo "$line" | cut -d':' -f1)
                record_type=$(echo "$line" | cut -d':' -f2)
                record_value=$(echo "$line" | cut -d':' -f3-)
                
                if [[ "$first" = true ]]; then
                    first=false
                else
                    echo "," >> "$TEMP_DIR/output.json"
                fi
                
                echo "    {" >> "$TEMP_DIR/output.json"
                echo "      \"subdomain\": \"$subdomain\"," >> "$TEMP_DIR/output.json"
                echo "      \"record_type\": \"$record_type\"," >> "$TEMP_DIR/output.json"
                # Escape for JSON
                record_value=$(echo "$record_value" | sed 's/"/\\"/g')
                echo "      \"value\": \"$record_value\"" >> "$TEMP_DIR/output.json"
                echo -n "    }" >> "$TEMP_DIR/output.json"
            done < "$RESULTS_FILE"
            echo "" >> "$TEMP_DIR/output.json"
            echo "  ]" >> "$TEMP_DIR/output.json"
            echo "}" >> "$TEMP_DIR/output.json"
            
            # Set output file
            if [[ -z "$OUTPUT_FILE" ]]; then
                OUTPUT_FILE="$TARGET_DOMAIN-$(date +%Y%m%d%H%M%S).json"
            elif [[ ! "$OUTPUT_FILE" =~ \.json$ ]]; then
                OUTPUT_FILE="$OUTPUT_FILE.json"
            fi
            
            # Copy to output file
            cp "$TEMP_DIR/output.json" "$OUTPUT_FILE"
            ;;
            
        csv)
            # Create CSV header
            echo "subdomain,record_type,value" > "$TEMP_DIR/output.csv"
            
            # Add subdomains with records
            while read -r line; do
                subdomain=$(echo "$line" | cut -d':' -f1)
                record_type=$(echo "$line" | cut -d':' -f2)
                record_value=$(echo "$line" | cut -d':' -f3-)
                
                # Escape commas in CSV
                record_value=$(echo "$record_value" | sed 's/,/\\,/g')
                
                echo "$subdomain,$record_type,\"$record_value\"" >> "$TEMP_DIR/output.csv"
            done < "$RESULTS_FILE"
            
            # Set output file
            if [[ -z "$OUTPUT_FILE" ]]; then
                OUTPUT_FILE="$TARGET_DOMAIN-$(date +%Y%m%d%H%M%S).csv"
            elif [[ ! "$OUTPUT_FILE" =~ \.csv$ ]]; then
                OUTPUT_FILE="$OUTPUT_FILE.csv"
            fi
            
            # Copy to output file
            cp "$TEMP_DIR/output.csv" "$OUTPUT_FILE"
            ;;
            
        *)
            # Default to TXT format
            echo "DNSHunter Results for $TARGET_DOMAIN" > "$TEMP_DIR/output.txt"
            echo "Generated on $(date)" >> "$TEMP_DIR/output.txt"
            echo "------------------------" >> "$TEMP_DIR/output.txt"
            echo "" >> "$TEMP_DIR/output.txt"
            
            echo "Summary:" >> "$TEMP_DIR/output.txt"
            echo "- Total subdomains discovered: $(wc -l < "$ALL_SUBDOMAINS")" >> "$TEMP_DIR/output.txt"
            echo "- Total verified live subdomains: $(wc -l < "$VERIFIED_SUBDOMAINS")" >> "$TEMP_DIR/output.txt"
            
            if [[ -f "$TAKEOVERS_FILE" ]] && [[ -s "$TAKEOVERS_FILE" ]]; then
                takeover_count=$(wc -l < "$TAKEOVERS_FILE")
                echo "- Potential subdomain takeovers: $takeover_count" >> "$TEMP_DIR/output.txt"
            else
                echo "- No potential subdomain takeovers found" >> "$TEMP_DIR/output.txt"
            fi
            
            echo "" >> "$TEMP_DIR/output.txt"
            echo "Nameservers:" >> "$TEMP_DIR/output.txt"
            cat "$NAMESERVERS_FILE" >> "$TEMP_DIR/output.txt"
            
            echo "" >> "$TEMP_DIR/output.txt"
            echo "Verified Subdomains:" >> "$TEMP_DIR/output.txt"
            
            while read -r line; do
                subdomain=$(echo "$line" | cut -d':' -f1)
                record_type=$(echo "$line" | cut -d':' -f2)
                record_value=$(echo "$line" | cut -d':' -f3-)
                
                echo "- $subdomain ($record_type): $record_value" >> "$TEMP_DIR/output.txt"
            done < "$RESULTS_FILE"
            
            if [[ -f "$TAKEOVERS_FILE" ]] && [[ -s "$TAKEOVERS_FILE" ]]; then
                echo "" >> "$TEMP_DIR/output.txt"
                echo "Potential Subdomain Takeovers:" >> "$TEMP_DIR/output.txt"
                cat "$TAKEOVERS_FILE" >> "$TEMP_DIR/output.txt"
            fi
            
            # Set output file
            if [[ -z "$OUTPUT_FILE" ]]; then
                OUTPUT_FILE="$TARGET_DOMAIN-$(date +%Y%m%d%H%M%S).txt"
            elif [[ ! "$OUTPUT_FILE" =~ \.(txt|text)$ ]]; then
                OUTPUT_FILE="$OUTPUT_FILE.txt"
            fi
            
            # Copy to output file
            cp "$TEMP_DIR/output.txt" "$OUTPUT_FILE"
            ;;
    esac
    
    print_success "Results saved to $OUTPUT_FILE"
    print_success "Subdomain-only list saved to $TARGET_DOMAIN-subdomains.txt"
    
    return 0
}


# Function to format and save results
format_results() {
    print_info "Formatting and saving results"
    
    # Copy verified subdomains to output format
    case "$OUTPUT_FORMAT" in
        json)
            # Create JSON structure
            echo "{" > "$TEMP_DIR/output.json"
            echo "  \"target\": \"$TARGET_DOMAIN\"," >> "$TEMP_DIR/output.json"
            echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"," >> "$TEMP_DIR/output.json"
            echo "  \"total_discovered\": $(wc -l < "$ALL_SUBDOMAINS")," >> "$TEMP_DIR/output.json"
            echo "  \"total_verified\": $(wc -l < "$VERIFIED_SUBDOMAINS")," >> "$TEMP_DIR/output.json"
            
            # Convert takeovers to JSON array
            echo "  \"potential_takeovers\": [" >> "$TEMP_DIR/output.json"
            if [[ -f "$TAKEOVERS_FILE" ]] && [[ -s "$TAKEOVERS_FILE" ]]; then
                first=true
                while read -r takeover; do
                    if [[ "$first" = true ]]; then
                        first=false
                    else
                        echo "," >> "$TEMP_DIR/output.json"
                    fi
                    # Escape for JSON
                    takeover=$(echo "$takeover" | sed 's/"/\\"/g')
                    echo -n "    \"$takeover\"" >> "$TEMP_DIR/output.json"
                done < "$TAKEOVERS_FILE"
                echo "" >> "$TEMP_DIR/output.json"
            fi
            echo "  ]," >> "$TEMP_DIR/output.json"
            
            # Add nameservers
            echo "  \"nameservers\": [" >> "$TEMP_DIR/output.json"
            first=true
            while read -r ns; do
                if [[ "$first" = true ]]; then
                    first=false
                else
                    echo "," >> "$TEMP_DIR/output.json"
                fi
                # Remove trailing dot and escape for JSON
                ns=${ns%*.}
                echo -n "    \"$ns\"" >> "$TEMP_DIR/output.json"
            done < "$NAMESERVERS_FILE"
            echo "" >> "$TEMP_DIR/output.json"
            echo "  ]," >> "$TEMP_DIR/output.json"
            
            # Add subdomains with records
            echo "  \"subdomains\": [" >> "$TEMP_DIR/output.json"
            first=true
            while read -r line; do
                subdomain=$(echo "$line" | cut -d':' -f1)
                record_type=$(echo "$line" | cut -d':' -f2)
                record_value=$(echo "$line" | cut -d':' -f3-)
                
                if [[ "$first" = true ]]; then
                    first=false
                else
                    echo "," >> "$TEMP_DIR/output.json"
                fi
                
                echo "    {" >> "$TEMP_DIR/output.json"
                echo "      \"subdomain\": \"$subdomain\"," >> "$TEMP_DIR/output.json"
                echo "      \"record_type\": \"$record_type\"," >> "$TEMP_DIR/output.json"
                # Escape for JSON
                record_value=$(echo "$record_value" | sed 's/"/\\"/g')
                echo "      \"value\": \"$record_value\"" >> "$TEMP_DIR/output.json"
                echo -n "    }" >> "$TEMP_DIR/output.json"
            done < "$RESULTS_FILE"
            echo "" >> "$TEMP_DIR/output.json"
            echo "  ]" >> "$TEMP_DIR/output.json"
            echo "}" >> "$TEMP_DIR/output.json"
            
            # Set output file
            if [[ -z "$OUTPUT_FILE" ]]; then
                OUTPUT_FILE="$TARGET_DOMAIN-$(date +%Y%m%d%H%M%S).json"
            elif [[ ! "$OUTPUT_FILE" =~ \.json$ ]]; then
                OUTPUT_FILE="$OUTPUT_FILE.json"
            fi
            
            # Copy to output file
            cp "$TEMP_DIR/output.json" "$OUTPUT_FILE"
            ;;
            
        csv)
            # Create CSV header
            echo "subdomain,record_type,value" > "$TEMP_DIR/output.csv"
            
            # Add subdomains with records
            while read -r line; do
                subdomain=$(echo "$line" | cut -d':' -f1)
                record_type=$(echo "$line" | cut -d':' -f2)
                record_value=$(echo "$line" | cut -d':' -f3-)
                
                # Escape commas in CSV
                record_value=$(echo "$record_value" | sed 's/,/\\,/g')
                
                echo "$subdomain,$record_type,\"$record_value\"" >> "$TEMP_DIR/output.csv"
            done < "$RESULTS_FILE"
            
            # Set output file
            if [[ -z "$OUTPUT_FILE" ]]; then
                OUTPUT_FILE="$TARGET_DOMAIN-$(date +%Y%m%d%H%M%S).csv"
            elif [[ ! "$OUTPUT_FILE" =~ \.csv$ ]]; then
                OUTPUT_FILE="$OUTPUT_FILE.csv"
            fi
            
            # Copy to output file
            cp "$TEMP_DIR/output.csv" "$OUTPUT_FILE"
            ;;
            
        *)
            # Default to TXT format
            echo "DNSHunter Results for $TARGET_DOMAIN" > "$TEMP_DIR/output.txt"
            echo "Generated on $(date)" >> "$TEMP_DIR/output.txt"
            echo "------------------------" >> "$TEMP_DIR/output.txt"
            echo "" >> "$TEMP_DIR/output.txt"
            
            echo "Summary:" >> "$TEMP_DIR/output.txt"
            echo "- Total subdomains discovered: $(wc -l < "$ALL_SUBDOMAINS")" >> "$TEMP_DIR/output.txt"
            echo "- Total verified live subdomains: $(wc -l < "$VERIFIED_SUBDOMAINS")" >> "$TEMP_DIR/output.txt"
            
            if [[ -f "$TAKEOVERS_FILE" ]] && [[ -s "$TAKEOVERS_FILE" ]]; then
                takeover_count=$(wc -l < "$TAKEOVERS_FILE")
                echo "- Potential subdomain takeovers: $takeover_count" >> "$TEMP_DIR/output.txt"
            else
                echo "- No potential subdomain takeovers found" >> "$TEMP_DIR/output.txt"
            fi
            
            echo "" >> "$TEMP_DIR/output.txt"
            echo "Nameservers:" >> "$TEMP_DIR/output.txt"
            cat "$NAMESERVERS_FILE" >> "$TEMP_DIR/output.txt"
            
            echo "" >> "$TEMP_DIR/output.txt"
            echo "Verified Subdomains:" >> "$TEMP_DIR/output.txt"
            
            while read -r line; do
                subdomain=$(echo "$line" | cut -d':' -f1)
                record_type=$(echo "$line" | cut -d':' -f2)
                record_value=$(echo "$line" | cut -d':' -f3-)
                
                echo "- $subdomain ($record_type): $record_value" >> "$TEMP_DIR/output.txt"
            done < "$RESULTS_FILE"
            
            if [[ -f "$TAKEOVERS_FILE" ]] && [[ -s "$TAKEOVERS_FILE" ]]; then
                echo "" >> "$TEMP_DIR/output.txt"
                echo "Potential Subdomain Takeovers:" >> "$TEMP_DIR/output.txt"
                cat "$TAKEOVERS_FILE" >> "$TEMP_DIR/output.txt"
            fi
            
            # Set output file
            if [[ -z "$OUTPUT_FILE" ]]; then
                OUTPUT_FILE="$TARGET_DOMAIN-$(date +%Y%m%d%H%M%S).txt"
            elif [[ ! "$OUTPUT_FILE" =~ \.(txt|text)$ ]]; then
                OUTPUT_FILE="$OUTPUT_FILE.txt"
            fi
            
            # Copy to output file
            cp "$TEMP_DIR/output.txt" "$OUTPUT_FILE"
            ;;
    esac
    
    print_success "Results saved to $OUTPUT_FILE"
    print_success "Results saved to $OUTPUT_FILE"
    print_success "Subdomain-only list saved to $TARGET_DOMAIN-subdomains.txt"
    
    return 0
}

# Main function
main() {
    print_banner
    parse_arguments "$@"
    init_environment
    
    print_info "Starting DNS reconnaissance for $TARGET_DOMAIN"
    
    # Get nameservers
    get_nameservers
    
    # Check for zone transfer
    attempt_zone_transfer
    
    # Check for wildcard DNS
    check_wildcard
    
    # Run various subdomain discovery tools
    if [[ "$USE_EXTERNAL_TOOLS" = true ]]; then
        print_info "Running external tools for subdomain discovery"
        
        run_subfinder
        run_assetfinder
        run_amass
        run_findomain
        run_sublist3r
        run_gobuster_dns
    fi
    
    # Query other sources
    query_crtsh
    query_securitytrails
    query_shodan
    search_github
    
    # Verify discovered subdomains
    verify_subdomains
    
    # Generate and verify alterations and permutations
    generate_alterations
    generate_permutations
    verify_extra_domains
    
    # Check for takeovers
    check_takeovers
    
    # Perform DNS cache snooping
    perform_dns_cache_snooping
    
    # Format and save results
    format_results
    
    print_success "DNS reconnaissance completed for $TARGET_DOMAIN"
    
    return 0
}

# Run main function with all arguments
main "$@"    
    
