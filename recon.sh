#!/bin/bash

# Function to fetch data and extract IPs and endpoints for a domain
fetch_domain_data() {
  local domain=$1
  local api_key_index=$2
  local api_key
  
  if [ $api_key_index -eq 1 ]; then
    api_key="key-1"
  elif [ $api_key_index -eq 2 ]; then
    api_key="key-2"
  else
    api_key="key-3"
  fi
  
  local URL="https://www.virustotal.com/vtapi/v2/domain/report?apikey=$api_key&domain=$domain"
  
  echo -e "\n==============================================="
  echo -e "Fetching data for domain: \033[1;34m$domain\033[0m (using API key $api_key_index)"
  echo -e "==============================================="
  
  response=$(curl -s "$URL")
  if [[ $? -ne 0 ]]; then
    echo -e "\033[1;31mError fetching data for domain: $domain\033[0m"
    return
  fi

  # Extract IP addresses
  echo -e "\n\033[1;32m[+] IP addresses associated with domain: $domain\033[0m"
  ip_addresses=$(echo "$response" | jq -r '.resolutions[].ip_address // empty')
  if [[ -z "$ip_addresses" ]]; then
    echo -e "\033[1;33mNo IP addresses found for domain: $domain\033[0m"
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

# Check if an argument is provided
if [ -z "$1" ]; then
  echo -e "\033[1;31mUsage: $0 <domain or file_with_domains>\033[0m"
  exit 1
fi

# Create output directory for results
output_dir="virustotal_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$output_dir"
cd "$output_dir" || exit 1
echo -e "\033[1;32mCreated output directory: $output_dir\033[0m"

# Initialize variables for API key rotation
api_key_index=1
request_count=0

# Check if the argument is a file
if [ -f "../$1" ]; then
  while IFS= read -r domain; do
    # Skip empty lines or comments
    [[ -z "$domain" || "$domain" =~ ^#.*$ ]] && continue
    
    # Remove the scheme (http:// or https://) if present
    domain=$(echo "$domain" | sed 's|https\?://||' | sed 's|/.*||')
    
    fetch_domain_data "$domain" $api_key_index
    countdown 20
    
    # Increment the request count and switch API key if needed
    request_count=$((request_count + 1))
    if [ $request_count -ge 5 ]; then
      request_count=0
      if [ $api_key_index -eq 1 ]; then
        api_key_index=2
      elif [ $api_key_index -eq 2 ]; then
        api_key_index=3
      else
        api_key_index=1
      fi
    fi
  done < "../$1"
else
  # Argument is not a file, treat it as a single domain
  domain=$(echo "$1" | sed 's|https\?://||' | sed 's|/.*||')
  fetch_domain_data "$domain" $api_key_index
fi

echo -e "\n\033[1;32mAll done! Results saved in directory: $output_dir\033[0m"

# Generate a summary file
echo "VirusTotal Data Extraction Summary" > summary.txt
echo "Date: $(date)" >> summary.txt
echo "Domains processed:" >> summary.txt
if [ -f "../$1" ]; then
  grep -v "^#" "../$1" | grep -v "^$" >> summary.txt
else
  echo "$1" >> summary.txt
fi
echo -e "\n\033[1;32mSummary created in: $output_dir/summary.txt\033[0m"

cd ..
