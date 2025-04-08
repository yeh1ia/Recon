#!/bin/bash

# Function to fetch data and extract IPs and endpoints for a domain
fetch_domain_data() {
  local domain=$1
  local vt_api_key_index=$2
  local vt_api_key
  
  if [ $vt_api_key_index -eq 1 ]; then
    vt_api_key="key-1"
  elif [ $vt_api_key_index -eq 2 ]; then
    vt_api_key="key-2"
  else
    vt_api_key="key-3"
  fi
  
  local VT_URL="https://www.virustotal.com/vtapi/v2/domain/report?apikey=$vt_api_key&domain=$domain"
  
  echo -e "\n==============================================="
  echo -e "Fetching data for domain: \033[1;34m$domain\033[0m (using VirusTotal API key $vt_api_key_index)"
  echo -e "==============================================="
  
  response=$(curl -s "$VT_URL")
  if [[ $? -ne 0 ]]; then
    echo -e "\033[1;31mError fetching VirusTotal data for domain: $domain\033[0m"
    return
  fi

  # Extract IP addresses from VirusTotal
  echo -e "\n\033[1;32m[+] IP addresses associated with domain (VirusTotal): $domain\033[0m"
  ip_addresses=$(echo "$response" | jq -r '.resolutions[].ip_address // empty')
  if [[ -z "$ip_addresses" ]]; then
    echo -e "\033[1;33mNo IP addresses found in VirusTotal for domain: $domain\033[0m"
  else
    echo "$ip_addresses" | sort -u
    
    # Save IP addresses to file
    echo "$ip_addresses" | sort -u >> "ips_$domain.txt"
    echo -e "\033[1;36mIP addresses saved to: ips_$domain.txt\033[0m"
  fi

  # Extract undetected URLs and their endpoints
  undetected_urls=$(echo "$response" | jq -r '.undetected_urls[][0] // empty')
  if [[ -z "$undetected_urls" ]]; then
    echo -e "\n\033[1;33mNo undetected URLs found for domain: $domain\033[0m"
  else
    echo -e "\n\033[1;32m[+] Undetected URLs for domain: $domain\033[0m"
    echo "$undetected_urls"
    
    # Save undetected URLs to file
    echo "$undetected_urls" >> "urls_$domain.txt"
    echo -e "\033[1;36mUndetected URLs saved to: urls_$domain.txt\033[0m"
    
    # Extract endpoints (paths) from URLs
    echo -e "\n\033[1;32m[+] Endpoints extracted from URLs for domain: $domain\033[0m"
    # Extract paths from URLs and remove empty paths
    endpoints=$(echo "$undetected_urls" | awk -F/ '{if (NF > 3) {path=""; for(i=4;i<=NF;i++){path=path"/"$i} print path}}' | sort -u)
    
    if [[ -z "$endpoints" ]]; then
      echo -e "\033[1;33mNo endpoints found in the URLs for domain: $domain\033[0m"
    else
      echo "$endpoints"
      
      # Save endpoints to file
      echo "$endpoints" >> "endpoints_$domain.txt"
      echo -e "\033[1;36mEndpoints saved to: endpoints_$domain.txt\033[0m"
    fi
  fi
  
  # Extract subdomains
  echo -e "\n\033[1;32m[+] Subdomains of: $domain\033[0m"
  subdomains=$(echo "$response" | jq -r '.subdomains[]? // empty')
  if [[ -z "$subdomains" ]]; then
    echo -e "\033[1;33mNo subdomains found for domain: $domain\033[0m"
  else
    echo "$subdomains" | sort -u
    
    # Save subdomains to file
    echo "$subdomains" | sort -u >> "subdomains_$domain.txt"
    echo -e "\033[1;36mSubdomains saved to: subdomains_$domain.txt\033[0m"
  fi
  
  # Now query Shodan for origin IPs
  if [[ ! -z "$SHODAN_API_KEY" ]]; then
    echo -e "\n\033[1;32m[+] Querying Shodan for additional information on domain: $domain\033[0m"
    
    # Query for the domain directly
    shodan_domain_info=$(curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=hostname:$domain")
    shodan_matches=$(echo "$shodan_domain_info" | jq -r '.matches // empty')
    
    # If we have IP addresses from VirusTotal, query each of those as well
    shodan_ip_results=""
    if [[ ! -z "$ip_addresses" ]]; then
      echo -e "\n\033[1;32m[+] Checking Shodan for detailed IP information from VirusTotal results\033[0m"
      while IFS= read -r ip; do
        echo -e "  \033[1;36mQuerying Shodan for IP: $ip\033[0m"
        shodan_ip_info=$(curl -s "https://api.shodan.io/shodan/host/$ip?key=$SHODAN_API_KEY")
        if [[ $(echo "$shodan_ip_info" | jq -r '.error? // empty') ]]; then
          echo -e "  \033[1;33mNo Shodan information found for IP: $ip\033[0m"
        else
          # Extract useful info from Shodan response
          ip_ports=$(echo "$shodan_ip_info" | jq -r '.ports[]? // empty' | sort -n | tr '\n' ',' | sed 's/,$//')
          ip_org=$(echo "$shodan_ip_info" | jq -r '.org? // "Unknown"')
          ip_isp=$(echo "$shodan_ip_info" | jq -r '.isp? // "Unknown"')
          ip_country=$(echo "$shodan_ip_info" | jq -r '.country_name? // "Unknown"')
          ip_asn=$(echo "$shodan_ip_info" | jq -r '.asn? // "Unknown"')
          
          echo -e "  \033[1;32mShodan info for IP $ip:\033[0m"
          echo -e "    Organization: $ip_org"
          echo -e "    ISP: $ip_isp"
          echo -e "    Country: $ip_country"
          echo -e "    ASN: $ip_asn"
          echo -e "    Open Ports: $ip_ports"
          
          # Save the detailed IP information
          {
            echo "IP: $ip"
            echo "Organization: $ip_org"
            echo "ISP: $ip_isp"
            echo "Country: $ip_country"
            echo "ASN: $ip_asn"
            echo "Open Ports: $ip_ports"
            echo "------------------------"
          } >> "shodan_ip_details_$domain.txt"
          
          # Extract origin servers from HTTP headers if available
          origin_servers=$(echo "$shodan_ip_info" | jq -r '.data[]? | select(.http?) | .http.headers? | (.["X-Served-By"]? // .["X-Origin"]? // .["Origin"]? // .["Server"]? // empty)')
          if [[ ! -z "$origin_servers" ]]; then
            echo -e "    \033[1;33mPossible origin servers: $origin_servers\033[0m"
            echo "Origin Servers: $origin_servers" >> "shodan_ip_details_$domain.txt"
            echo "$origin_servers" >> "origin_servers_$domain.txt"
          fi
          
          # Add a blank line for readability
          echo "" >> "shodan_ip_details_$domain.txt"
        fi
        # Brief pause to respect Shodan API rate limits
        sleep 1
      done <<< "$ip_addresses"
    fi
    
    # Extract origin IPs from Shodan domain search
    echo -e "\n\033[1;32m[+] Origin IPs discovered from Shodan for: $domain\033[0m"
    if [[ $(echo "$shodan_domain_info" | jq -r '.error? // empty') || $(echo "$shodan_domain_info" | jq -r '.total') -eq 0 ]]; then
      echo -e "\033[1;33mNo direct Shodan data found for domain: $domain\033[0m"
    else
      origin_ips=$(echo "$shodan_domain_info" | jq -r '.matches[]? | .ip_str' | sort -u)
      if [[ ! -z "$origin_ips" ]]; then
        echo "$origin_ips"
        
        # Save origin IPs to file
        echo "$origin_ips" >> "shodan_origin_ips_$domain.txt"
        echo -e "\033[1;36mShodan origin IPs saved to: shodan_origin_ips_$domain.txt\033[0m"
        
        # Also add to the combined IPs file
        echo "$origin_ips" >> "ips_$domain.txt"
      else
        echo -e "\033[1;33mNo origin IPs found in Shodan data for domain: $domain\033[0m"
      fi
    fi
  else
    echo -e "\n\033[1;33mShodan API key not provided. Skipping Shodan queries.\033[0m"
  fi
}

# Function to display a countdown
countdown() {
  local seconds=$1
  while [ $seconds -gt 0 ]; do
    echo -ne "\033[1;36mWaiting for $seconds seconds...\033[0m\r"
    sleep 1
    : $((seconds--))
  done
  echo -ne "\033[0K"  # Clear the countdown line
}

# Function to check prerequisites
check_prerequisites() {
  # Check if jq is installed
  if ! command -v jq &> /dev/null; then
    echo -e "\033[1;31mError: jq is not installed. Please install it first (e.g., 'sudo apt install jq' or 'brew install jq').\033[0m"
    exit 1
  fi
  
  # Check if curl is installed
  if ! command -v curl &> /dev/null; then
    echo -e "\033[1;31mError: curl is not installed. Please install it first.\033[0m"
    exit 1
  fi
}

# Function to prompt for API keys if not set
prompt_for_api_keys() {
  if [[ -z "$SHODAN_API_KEY" ]]; then
    read -p "Enter your Shodan API key (or press Enter to skip Shodan queries): " SHODAN_API_KEY
    echo ""
  fi
}

# Check prerequisites
check_prerequisites

# Check if an argument is provided
if [ -z "$1" ]; then
  echo -e "\033[1;31mUsage: $0 <domain or file_with_domains> [shodan_api_key]\033[0m"
  echo -e "\033[1;33mYou can also set the SHODAN_API_KEY environment variable before running the script.\033[0m"
  exit 1
fi

# Set Shodan API key if provided as second argument
if [ -n "$2" ]; then
  SHODAN_API_KEY="$2"
fi

# Prompt for API keys if not set
prompt_for_api_keys

# Create output directory for results
output_dir="recon_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$output_dir"
cd "$output_dir" || exit 1
echo -e "\033[1;32mCreated output directory: $output_dir\033[0m"

# Initialize variables for API key rotation
vt_api_key_index=1
request_count=0

# Check if the argument is a file
if [ -f "../$1" ]; then
  echo -e "\033[1;32mProcessing domains from file: $1\033[0m"
  while IFS= read -r domain; do
    # Skip empty lines or comments
    [[ -z "$domain" || "$domain" =~ ^#.*$ ]] && continue
    
    # Remove the scheme (http:// or https://) if present
    domain=$(echo "$domain" | sed 's|https\?://||' | sed 's|/.*||')
    
    fetch_domain_data "$domain" $vt_api_key_index
    countdown 20
    
    # Increment the request count and switch API key if needed
    request_count=$((request_count + 1))
    if [ $request_count -ge 5 ]; then
      request_count=0
      if [ $vt_api_key_index -eq 1 ]; then
        vt_api_key_index=2
      elif [ $vt_api_key_index -eq 2 ]; then
        vt_api_key_index=3
      else
        vt_api_key_index=1
      fi
    fi
  done < "../$1"
else
  # Argument is not a file, treat it as a single domain
  domain=$(echo "$1" | sed 's|https\?://||' | sed 's|/.*||')
  fetch_domain_data "$domain" $vt_api_key_index
fi

# Create a combined unique IP list
echo -e "\n\033[1;32mGenerating combined unique IP list...\033[0m"
cat ips_*.txt 2>/dev/null | sort -u > all_unique_ips.txt
echo -e "\033[1;36mAll unique IPs saved to: all_unique_ips.txt\033[0m"

# Create a combined unique origin servers list
echo -e "\033[1;32mGenerating combined unique origin servers list...\033[0m"
cat origin_servers_*.txt 2>/dev/null | sort -u > all_origin_servers.txt
echo -e "\033[1;36mAll unique origin servers saved to: all_origin_servers.txt\033[0m"

echo -e "\n\033[1;32mAll done! Results saved in directory: $output_dir\033[0m"

# Generate a summary file
echo "Reconnaissance Data Extraction Summary" > summary.txt
echo "Date: $(date)" >> summary.txt
echo "Domains processed:" >> summary.txt
if [ -f "../$1" ]; then
  grep -v "^#" "../$1" | grep -v "^$" >> summary.txt
else
  echo "$1" >> summary.txt
fi

# Add statistics to summary
echo -e "\nStatistics:" >> summary.txt
echo "Total unique IPs discovered: $(wc -l < all_unique_ips.txt 2>/dev/null || echo 0)" >> summary.txt
echo "Total origin servers discovered: $(wc -l < all_origin_servers.txt 2>/dev/null || echo 0)" >> summary.txt

echo -e "\n\033[1;32mSummary created in: $output_dir/summary.txt\033[0m"

cd ..
