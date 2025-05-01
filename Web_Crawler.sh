#!/bin/bash

# Set colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
RESET='\033[0m'

# Default values
DEFAULT_DEPTH=2
DEFAULT_THREADS=10
DEFAULT_TIMEOUT=10
DEFAULT_WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

# Create output directory if it doesn't exist
OUTPUT_DIR="results"
mkdir -p "$OUTPUT_DIR"

# Usage function
usage() {
  echo -e "${BLUE}Web Application Crawler and Endpoint Discovery${RESET}"
  echo -e "${YELLOW}Usage:${RESET} $0 -i <input_file> [-o <output_dir>] [-d <depth>] [-t <threads>] [-T <timeout>] [-w <wordlist>]"
  echo -e "${YELLOW}Options:${RESET}"
  echo -e "  -i <input_file>  : Input file containing list of subdomains, one per line"
  echo -e "  -o <output_dir>  : Output directory for results (default: '$OUTPUT_DIR')"
  echo -e "  -d <depth>       : Crawl depth (default: $DEFAULT_DEPTH)"
  echo -e "  -t <threads>     : Number of concurrent threads (default: $DEFAULT_THREADS)"
  echo -e "  -T <timeout>     : Timeout in seconds (default: $DEFAULT_TIMEOUT)"
  echo -e "  -w <wordlist>    : Path to wordlist for directory bruteforcing (default: system wordlist)"
  echo -e "  -h               : Show this help message"
  exit 1
}

# Parse command line arguments
while getopts "i:o:d:t:T:w:h" opt; do
  case "$opt" in
    i) INPUT_FILE="$OPTARG" ;;
    o) OUTPUT_DIR="$OPTARG" ;;
    d) DEPTH="$OPTARG" ;;
    t) THREADS="$OPTARG" ;;
    T) TIMEOUT="$OPTARG" ;;
    w) WORDLIST="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

# Check if input file is provided
if [[ -z "$INPUT_FILE" ]]; then
  echo -e "${RED}[!] Error: Input file is required.${RESET}"
  usage
fi

# Check if input file exists
if [[ ! -f "$INPUT_FILE" ]]; then
  echo -e "${RED}[!] Error: Input file '$INPUT_FILE' does not exist.${RESET}"
  exit 1
fi

# Set default values if not provided
DEPTH=${DEPTH:-$DEFAULT_DEPTH}
THREADS=${THREADS:-$DEFAULT_THREADS}
TIMEOUT=${TIMEOUT:-$DEFAULT_TIMEOUT}

# Check if wordlist exists (if specified)
if [[ -n "$WORDLIST" && ! -f "$WORDLIST" ]]; then
  echo -e "${RED}[!] Error: Wordlist '$WORDLIST' does not exist.${RESET}"
  exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Function to check if Katana is installed
check_katana() {
  if ! command -v katana &> /dev/null; then
    echo -e "${RED}[!] Error: Katana is not installed. Please install it first.${RESET}"
    echo -e "${YELLOW}    Installation: go install github.com/projectdiscovery/katana/cmd/katana@latest${RESET}"
    return 1
  fi
  return 0
}

# Function to check if Gospider is installed
check_gospider() {
  if ! command -v gospider &> /dev/null; then
    echo -e "${RED}[!] Error: Gospider is not installed. Please install it first.${RESET}"
    echo -e "${YELLOW}    Installation: go install github.com/jaeles-project/gospider@latest${RESET}"
    return 1
  fi
  return 0
}

# Function to fetch data using Katana crawler
fetch_katana_data() {
  local subdomain=$1
  local depth=$2
  local threads=$3

  echo -e "\n${PURPLE}============================================================${RESET}"
  echo -e "${BLUE}[+] Processing subdomain: ${GREEN}$subdomain${RESET} (Katana Crawler)"
  echo -e "${PURPLE}============================================================${RESET}"

  # Check if Katana is installed
  if ! check_katana; then
    echo "Katana not installed. Skipping Katana crawling for $subdomain" >> "$OUTPUT_DIR/errors.log"
    return 1
  fi

  # Create URL with protocol
  local url="https://$subdomain"

  echo -e "${GREEN}[+] Crawling $url with Katana (depth: $depth, threads: $threads)${RESET}"

  # Run Katana and capture output
  output=$(katana -u "$url" -d "$depth" -c "$threads" -jc -o /dev/null 2>/dev/null)
  
  # If no output or error, try http instead of https
  if [[ -z "$output" ]]; then
    url="http://$subdomain"
    echo -e "${YELLOW}[!] HTTPS failed, trying HTTP: $url${RESET}"
    output=$(katana -u "$url" -d "$depth" -c "$threads" -jc -o /dev/null 2>/dev/null)
  fi

  # Check if we got any results
  if [[ -z "$output" ]]; then
    echo -e "${YELLOW}[!] No Katana results for: $subdomain${RESET}"
    return 0
  fi

  # Process JSON output (one JSON object per line)
  echo "$output" | while read -r line; do
    # Extract URL from JSON
    crawled_url=$(echo "$line" | jq -r '.request.url' 2>/dev/null)
    
    if [[ -n "$crawled_url" && "$crawled_url" != "null" ]]; then
      echo "$crawled_url" >> "$OUTPUT_DIR/katana_urls.txt"
      echo "$crawled_url" >> "$OUTPUT_DIR/all_urls.txt"
      
      # Extract endpoint from URL
      endpoint=$(echo "$crawled_url" | awk -F/ '{if (NF > 3) {path=""; for(i=4;i<=NF;i++){path=path"/"$i} print path}}')
      
      if [[ -n "$endpoint" ]]; then
        echo "$subdomain,$endpoint" >> "$OUTPUT_DIR/subdomain_to_endpoint.csv"
        echo "$endpoint" >> "$OUTPUT_DIR/all_endpoints.txt"
      fi
    fi
  done

  # Count unique URLs discovered
  url_count=$(sort -u "$OUTPUT_DIR/katana_urls.txt" | wc -l)
  echo -e "${GREEN}[+] Katana discovered $url_count unique URLs for $subdomain${RESET}"

  return 0
}

# Function to fetch data using Gospider - a more powerful crawler
fetch_gospider_data() {
  local subdomain=$1
  local depth=$2
  local threads=$3
  local timeout=$4

  echo -e "\n${PURPLE}============================================================${RESET}"
  echo -e "${BLUE}[+] Processing subdomain: ${GREEN}$subdomain${RESET} (Gospider - Advanced Crawler)"
  echo -e "${PURPLE}============================================================${RESET}"

  # Check if Gospider is installed
  if ! check_gospider; then
    echo "Gospider not installed. Skipping Gospider crawling for $subdomain" >> "$OUTPUT_DIR/errors.log"
    return 1
  fi

  # Create output file for this subdomain
  gospider_output="$OUTPUT_DIR/gospider_${subdomain}.txt"
  
  # Create URL with protocol
  local url="https://$subdomain"

  echo -e "${GREEN}[+] Crawling $url with Gospider (depth: $depth, threads: $threads)${RESET}"

  # Run Gospider with various options
  # -s: site to crawl
  # -d: depth to crawl
  # -c: number of concurrent requests
  # -t: timeout in seconds
  # -a: include subdomains
  # --robots: parse robots.txt
  # --sitemap: parse sitemap.xml
  # --other-source: include other sources to crawl
  # --include-subs: include subdomains
  # --include-other-source: include other sources
  gospider -s "$url" -d "$depth" -c "$threads" -t "$timeout" -a --robots --sitemap --other-source --include-subs --include-other-source > "$gospider_output" 2>/dev/null
  
  # If no output or error, try http instead of https
  if [[ ! -s "$gospider_output" ]]; then
    url="http://$subdomain"
    echo -e "${YELLOW}[!] HTTPS failed, trying HTTP: $url${RESET}"
    gospider -s "$url" -d "$depth" -c "$threads" -t "$timeout" -a --robots --sitemap --other-source --include-subs --include-other-source > "$gospider_output" 2>/dev/null
  fi

  # Check if we got any results
  if [[ ! -s "$gospider_output" ]]; then
    echo -e "${YELLOW}[!] No Gospider results for: $subdomain${RESET}"
    return 0
  fi

  # Process output to extract URLs and endpoints
  grep -Eo '(http|https)://[^[:space:]]+' "$gospider_output" | sort -u > "$OUTPUT_DIR/gospider_urls_${subdomain}.txt"
  
  # Count discovered URLs
  url_count=$(wc -l < "$OUTPUT_DIR/gospider_urls_${subdomain}.txt")
  echo -e "${GREEN}[+] Gospider discovered $url_count unique URLs for $subdomain${RESET}"
  
  # Add to all_urls.txt
  cat "$OUTPUT_DIR/gospider_urls_${subdomain}.txt" >> "$OUTPUT_DIR/all_urls.txt"
  
  # Extract endpoints from URLs
  while IFS= read -r crawled_url; do
    # Extract domain from URL to check if it matches our subdomain
    url_domain=$(echo "$crawled_url" | awk -F/ '{print $3}')
    
    # Extract endpoint from URL
    endpoint=$(echo "$crawled_url" | awk -F/ '{if (NF > 3) {path=""; for(i=4;i<=NF;i++){path=path"/"$i} print path}}')
    
    if [[ -n "$endpoint" ]]; then
      # If the URL belongs to our subdomain, add to the mapping
      if [[ "$url_domain" == "$subdomain" ]]; then
        echo "$subdomain,$endpoint" >> "$OUTPUT_DIR/subdomain_to_endpoint.csv"
      fi
      
      echo "$endpoint" >> "$OUTPUT_DIR/all_endpoints.txt"
    fi
  done < "$OUTPUT_DIR/gospider_urls_${subdomain}.txt"
  
  # Check for interesting findings
  echo -e "${CYAN}[+] Checking for interesting findings...${RESET}"
  
  # Check for potential API endpoints
  api_endpoints=$(grep -i "/api/" "$OUTPUT_DIR/gospider_urls_${subdomain}.txt" | sort -u)
  if [[ -n "$api_endpoints" ]]; then
    echo -e "${GREEN}[+] Found potential API endpoints:${RESET}"
    echo "$api_endpoints" | while read -r api_url; do
      echo -e "${CYAN}    - $api_url${RESET}"
      endpoint=$(echo "$api_url" | awk -F/ '{if (NF > 3) {path=""; for(i=4;i<=NF;i++){path=path"/"$i} print path}}')
      echo "$subdomain,$endpoint,api" >> "$OUTPUT_DIR/sensitive_paths.csv"
    done
  fi
  
  # Check for potential admin/dashboard paths
  admin_paths=$(grep -iE '/(admin|dashboard|console|portal|login|auth|backend)/' "$OUTPUT_DIR/gospider_urls_${subdomain}.txt" | sort -u)
  if [[ -n "$admin_paths" ]]; then
    echo -e "${GREEN}[+] Found potential admin/dashboard paths:${RESET}"
    echo "$admin_paths" | while read -r admin_url; do
      echo -e "${CYAN}    - $admin_url${RESET}"
      endpoint=$(echo "$admin_url" | awk -F/ '{if (NF > 3) {path=""; for(i=4;i<=NF;i++){path=path"/"$i} print path}}')
      echo "$subdomain,$endpoint,admin" >> "$OUTPUT_DIR/sensitive_paths.csv"
    done
  fi
  
  # Check for JS files that might contain secrets
  js_files=$(grep -E '\.js(\?|$)' "$OUTPUT_DIR/gospider_urls_${subdomain}.txt" | sort -u)
  if [[ -n "$js_files" ]]; then
    js_count=$(echo "$js_files" | wc -l)
    echo -e "${GREEN}[+] Found $js_count JavaScript files${RESET}"
    echo "$js_files" > "$OUTPUT_DIR/${subdomain}_js_files.txt"
  fi

  return 0
}

# Function to check if endpoints are live
check_live_endpoints() {
  local subdomain=$1
  local threads=$2
  local timeout=$3

  echo -e "\n${PURPLE}============================================================${RESET}"
  echo -e "${BLUE}[+] Checking live endpoints for: ${GREEN}$subdomain${RESET}"
  echo -e "${PURPLE}============================================================${RESET}"

  # Create temporary file with endpoints for this subdomain
  temp_file=$(mktemp)
  grep "^$subdomain," "$OUTPUT_DIR/subdomain_to_endpoint.csv" | cut -d',' -f2 | sort -u > "$temp_file"

  endpoint_count=$(wc -l < "$temp_file")
  
  if [[ $endpoint_count -eq 0 ]]; then
    echo -e "${YELLOW}[!] No endpoints to check for: $subdomain${RESET}"
    rm "$temp_file"
    return 0
  fi

  echo -e "${GREEN}[+] Checking $endpoint_count endpoints for: $subdomain${RESET}"
  
  # Progress counter
  checked=0
  live=0

  # Check each endpoint
  while IFS= read -r endpoint; do
    # Construct URL to check
    check_url="https://$subdomain$endpoint"
    
    # Increment counter
    checked=$((checked + 1))
    
    # Show progress
    if [[ $((checked % 10)) -eq 0 ]]; then
      echo -e "${CYAN}    Progress: $checked/$endpoint_count${RESET}"
    fi

    # Check if the endpoint is live (allow redirects, respect timeout)
    status_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$timeout" -L "$check_url")

    # If status code is 200-399, consider it live
    if [[ $status_code -ge 200 && $status_code -lt 400 ]]; then
      echo -e "${GREEN}    - [LIVE] $endpoint ($status_code)${RESET}"
      echo "$subdomain,$endpoint,$status_code" >> "$OUTPUT_DIR/live_endpoints.csv"
      live=$((live + 1))
    fi

  done < "$temp_file"

  # Clean up temporary file
  rm "$temp_file"

  echo -e "${GREEN}[+] Found $live live endpoint(s) out of $endpoint_count for $subdomain${RESET}"

  return 0
}

# Function to use feroxbuster for advanced path discovery (if installed)
fetch_feroxbuster_data() {
  local subdomain=$1
  local threads=$2
  local timeout=$3
  local wordlist=$4  # Path to wordlist, default will be set if not provided

  echo -e "\n${PURPLE}============================================================${RESET}"
  echo -e "${BLUE}[+] Processing subdomain: ${GREEN}$subdomain${RESET} (Feroxbuster - Advanced Path Discovery)"
  echo -e "${PURPLE}============================================================${RESET}"

  # Check if Feroxbuster is installed
  if ! command -v feroxbuster &> /dev/null; then
    echo -e "${RED}[!] Error: Feroxbuster is not installed. Please install it first.${RESET}"
    echo -e "${YELLOW}    Installation: https://github.com/epi052/feroxbuster#installation${RESET}"
    return 1
  fi

  # Set default wordlist if not provided
  if [[ -z "$wordlist" ]]; then
    if [[ -f "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" ]]; then
      wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    elif [[ -f "/usr/share/seclists/Discovery/Web-Content/common.txt" ]]; then
      wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt"
    else
      echo -e "${RED}[!] Error: No default wordlist found. Please specify a wordlist.${RESET}"
      return 1
    fi
  fi

  # Create output file for this subdomain
  ferox_output="$OUTPUT_DIR/feroxbuster_${subdomain}.txt"
  
  # Create URL with protocol
  local url="https://$subdomain"

  echo -e "${GREEN}[+] Running Feroxbuster on $url (wordlist: $(basename "$wordlist"), threads: $threads)${RESET}"

  # Run Feroxbuster with various options
  feroxbuster --url "$url" \
              --wordlist "$wordlist" \
              --threads "$threads" \
              --timeout "$timeout" \
              --silent \
              --collect-extensions \
              --extract-links \
              --no-state \
              --smart \
              --auto-tune \
              --status-codes "200,204,301,302,307,308,401,403,405" \
              --output "$ferox_output" > /dev/null 2>&1

  # If no output or error, try http instead of https
  if [[ ! -s "$ferox_output" ]]; then
    url="http://$subdomain"
    echo -e "${YELLOW}[!] HTTPS failed, trying HTTP: $url${RESET}"
    feroxbuster --url "$url" \
                --wordlist "$wordlist" \
                --threads "$threads" \
                --timeout "$timeout" \
                --silent \
                --collect-extensions \
                --extract-links \
                --no-state \
                --smart \
                --auto-tune \
                --status-codes "200,204,301,302,307,308,401,403,405" \
                --output "$ferox_output" > /dev/null 2>&1
  fi

  # Check if we got any results
  if [[ ! -s "$ferox_output" ]]; then
    echo -e "${YELLOW}[!] No Feroxbuster results for: $subdomain${RESET}"
    return 0
  fi

  # Extract discovered URLs
  grep "^200" "$ferox_output" | awk '{print $2}' | sort -u > "$OUTPUT_DIR/feroxbuster_urls_${subdomain}.txt"
  
  # Count discovered URLs
  url_count=$(wc -l < "$OUTPUT_DIR/feroxbuster_urls_${subdomain}.txt")
  echo -e "${GREEN}[+] Feroxbuster discovered $url_count unique URLs for $subdomain${RESET}"
  
  # Add to all_urls.txt
  cat "$OUTPUT_DIR/feroxbuster_urls_${subdomain}.txt" >> "$OUTPUT_DIR/all_urls.txt"
  
  # Extract endpoints from URLs
  while IFS= read -r crawled_url; do
    # Extract endpoint from URL
    endpoint=$(echo "$crawled_url" | awk -F/ '{if (NF > 3) {path=""; for(i=4;i<=NF;i++){path=path"/"$i} print path}}')
    
    if [[ -n "$endpoint" ]]; then
      echo "$subdomain,$endpoint" >> "$OUTPUT_DIR/subdomain_to_endpoint.csv"
      echo "$endpoint" >> "$OUTPUT_DIR/all_endpoints.txt"
    fi
  done < "$OUTPUT_DIR/feroxbuster_urls_${subdomain}.txt"
  
  # Check for interesting status codes
  echo -e "${CYAN}[+] Checking for interesting status codes...${RESET}"
  
  # Find 403 Forbidden paths
  forbidden=$(grep "^403" "$ferox_output" | awk '{print $2}')
  if [[ -n "$forbidden" ]]; then
    echo -e "${GREEN}[+] Found paths returning 403 Forbidden:${RESET}"
    echo "$forbidden" | while read -r url; do
      echo -e "${CYAN}    - $url${RESET}"
      endpoint=$(echo "$url" | awk -F/ '{if (NF > 3) {path=""; for(i=4;i<=NF;i++){path=path"/"$i} print path}}')
      echo "$subdomain,$endpoint,403_forbidden" >> "$OUTPUT_DIR/sensitive_paths.csv"
    done
  fi

  return 0
}

# Initialize output files
echo -e "${BLUE}[+] Initializing output files...${RESET}"
touch "$OUTPUT_DIR/katana_urls.txt"
touch "$OUTPUT_DIR/all_urls.txt"
touch "$OUTPUT_DIR/all_endpoints.txt"
touch "$OUTPUT_DIR/subdomain_to_endpoint.csv"
touch "$OUTPUT_DIR/live_endpoints.csv"
touch "$OUTPUT_DIR/sensitive_paths.csv"
touch "$OUTPUT_DIR/errors.log"

# Add headers to CSV files
echo "Subdomain,Path" > "$OUTPUT_DIR/subdomain_to_endpoint.csv"
echo "Subdomain,Path,StatusCode" > "$OUTPUT_DIR/live_endpoints.csv"
echo "Subdomain,Path,Source" > "$OUTPUT_DIR/sensitive_paths.csv"

# Print banner and information
echo -e "\n${PURPLE}============================================================${RESET}"
echo -e "${BLUE}[+] Web Application Crawler and Endpoint Discovery${RESET}"
echo -e "${PURPLE}============================================================${RESET}"
echo -e "${GREEN}[+] Input file: $INPUT_FILE${RESET}"
echo -e "${GREEN}[+] Output directory: $OUTPUT_DIR${RESET}"
echo -e "${GREEN}[+] Crawl depth: $DEPTH${RESET}"
echo -e "${GREEN}[+] Threads: $THREADS${RESET}"
echo -e "${GREEN}[+] Timeout: $TIMEOUT seconds${RESET}"
if [[ -n "$WORDLIST" ]]; then
  echo -e "${GREEN}[+] Wordlist: $WORDLIST${RESET}"
else
  echo -e "${GREEN}[+] Wordlist: Using system default${RESET}"
fi
echo -e "${PURPLE}============================================================${RESET}"

# Count the number of subdomains
SUBDOMAIN_COUNT=$(wc -l < "$INPUT_FILE")
echo -e "${BLUE}[+] Processing $SUBDOMAIN_COUNT subdomains...${RESET}"

# Process each subdomain
CURRENT=0
while IFS= read -r subdomain; do
  # Skip empty lines and comments
  if [[ -z "$subdomain" || "$subdomain" =~ ^# ]]; then
    continue
  fi
  
  CURRENT=$((CURRENT + 1))
  echo -e "\n${PURPLE}============================================================${RESET}"
  echo -e "${BLUE}[+] Processing subdomain $CURRENT/$SUBDOMAIN_COUNT: ${GREEN}$subdomain${RESET}"
  echo -e "${PURPLE}============================================================${RESET}"
  
  # Run Katana crawler
  fetch_katana_data "$subdomain" "$DEPTH" "$THREADS"
  
  # Run Gospider - more powerful crawler
  fetch_gospider_data "$subdomain" "$DEPTH" "$THREADS" "$TIMEOUT"
  
  # Run Feroxbuster for advanced path discovery
  fetch_feroxbuster_data "$subdomain" "$THREADS" "$TIMEOUT" "$WORDLIST"
  
  # Check if endpoints are live
  check_live_endpoints "$subdomain" "$THREADS" "$TIMEOUT"
  
done < "$INPUT_FILE"

# Final cleanup and summary
echo -e "\n${PURPLE}============================================================${RESET}"
echo -e "${BLUE}[+] Finalizing results...${RESET}"
echo -e "${PURPLE}============================================================${RESET}"

# Remove duplicate entries from files
echo -e "${GREEN}[+] Removing duplicate entries...${RESET}"
sort -u "$OUTPUT_DIR/all_urls.txt" -o "$OUTPUT_DIR/all_urls.txt"
sort -u "$OUTPUT_DIR/all_endpoints.txt" -o "$OUTPUT_DIR/all_endpoints.txt"
sort -u "$OUTPUT_DIR/subdomain_to_endpoint.csv" -o "$OUTPUT_DIR/subdomain_to_endpoint.csv"
sort -u "$OUTPUT_DIR/live_endpoints.csv" -o "$OUTPUT_DIR/live_endpoints.csv"
sort -u "$OUTPUT_DIR/sensitive_paths.csv" -o "$OUTPUT_DIR/sensitive_paths.csv"

# Count unique results
URL_COUNT=$(wc -l < "$OUTPUT_DIR/all_urls.txt")
ENDPOINT_COUNT=$(wc -l < "$OUTPUT_DIR/all_endpoints.txt")
LIVE_COUNT=$(grep -v "^Subdomain" "$OUTPUT_DIR/live_endpoints.csv" | wc -l)
SENSITIVE_COUNT=$(grep -v "^Subdomain" "$OUTPUT_DIR/sensitive_paths.csv" | wc -l)

# Print summary
echo -e "${GREEN}[+] Total unique URLs discovered: $URL_COUNT${RESET}"
echo -e "${GREEN}[+] Total unique endpoints: $ENDPOINT_COUNT${RESET}"
echo -e "${GREEN}[+] Total live endpoints: $LIVE_COUNT${RESET}"
echo -e "${GREEN}[+] Total sensitive paths: $SENSITIVE_COUNT${RESET}"

echo -e "\n${BLUE}[+] All results saved to: $OUTPUT_DIR${RESET}"
echo -e "${BLUE}[+] Script completed!${RESET}"
echo -e "${PURPLE}============================================================${RESET}"

exit 0
