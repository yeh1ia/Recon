#!/bin/bash

# Colors for output
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
PURPLE="\033[0;35m"
CYAN="\033[0;36m"
RESET="\033[0m"

# Clear screen
clear

echo -e "${GREEN}"
echo "  ______                  ____        _           _   _             "
echo " |  ____|                |  _ \\      | |         | | (_)            "
echo " | |__ _ __ ___  ___     | |_) | __ _| | ___  ___| |_ _ _ __   ___  "
echo " |  __| '__/ _ \\/ _ \\    |  _ < / _\` | |/ _ \\/ __| __| | '_ \\ / _ \\ "
echo " | |  | | |  __/  __/    | |_) | (_| | |  __/\\__ \\ |_| | | | |  __/ "
echo " |_|  |_|  \\___|\\___|    |____/ \\__,_|_|\\___||___/\\__|_|_| |_|\\___| "
echo -e "${NC}"
                                                                 
echo -e "                              ${WHITE}by 9x_7ydra${NC}"
echo ""


# Function to fetch data for a subdomain using VirusTotal
fetch_vt_data() {
  local subdomain=$1
  local api_key=$2

  echo -e "\n${PURPLE}============================================================${RESET}"
  echo -e "${BLUE}[+] Processing subdomain: ${GREEN}$subdomain${RESET} (VirusTotal)"
  echo -e "${PURPLE}============================================================${RESET}"

  # Check if API key is available
  if [[ -z "$api_key" ]]; then
    echo -e "${RED}[!] Error: No VirusTotal API key available. Skipping VirusTotal check.${RESET}"
    return 1
  fi

  local URL="https://www.virustotal.com/vtapi/v2/domain/report?apikey=$api_key&domain=$subdomain"

  response=$(curl -s --max-time 30 "$URL")

  # Check for API errors or rate limits
  if [[ "$response" == *"\"response_code\": 0"* ]]; then
    echo -e "${YELLOW}[!] No data found on VirusTotal for: $subdomain${RESET}"
    return 0
  elif [[ "$response" == *"\"error\""* ]]; then
    error_msg=$(echo "$response" | jq -r '.error // "Unknown error"' 2>/dev/null)
    echo -e "${RED}[!] VirusTotal API error: $error_msg${RESET}"
    return 1
  elif [[ -z "$response" ]]; then
    echo -e "${RED}[!] Empty response from VirusTotal API${RESET}"
    return 1
  fi

  # Debug the response if needed
  # echo "$response" > "$OUTPUT_DIR/vt_debug_$subdomain.json"

  # Extract IP addresses
  ip_addresses=$(echo "$response" | jq -r '.resolutions[]?.ip_address' 2>/dev/null)
  if [[ -z "$ip_addresses" ]]; then
    echo -e "${YELLOW}[!] No IP addresses found for: $subdomain${RESET}"
  else
    ip_count=$(echo "$ip_addresses" | grep -v "^$" | wc -l | tr -d ' ')
    echo -e "${GREEN}[+] Found $ip_count IP(s) for: $subdomain${RESET}"

    # Save IP addresses with subdomain mapping
    while IFS= read -r ip; do
      [[ -z "$ip" ]] && continue
      echo -e "${GREEN}    - $ip${RESET}"
      echo "$subdomain,$ip" >> "$OUTPUT_DIR/subdomain_to_ip.csv"
      echo "$ip" >> "$OUTPUT_DIR/all_ips.txt"
    done <<< "$ip_addresses"
  fi

  # Extract detected and undetected URLs
  detected_urls=$(echo "$response" | jq -r '.detected_urls[]?.url // empty' 2>/dev/null)
  undetected_urls=$(echo "$response" | jq -r '.undetected_urls[]?[0] // empty' 2>/dev/null)

  # Combine all URLs
  all_urls=""
  if [[ ! -z "$detected_urls" ]]; then
    all_urls="$detected_urls"
  fi

  if [[ ! -z "$undetected_urls" ]]; then
    if [[ ! -z "$all_urls" ]]; then
      all_urls="$all_urls
$undetected_urls"
    else
      all_urls="$undetected_urls"
    fi
  fi

  if [[ ! -z "$all_urls" ]]; then
    url_count=$(echo "$all_urls" | grep -v "^$" | wc -l | tr -d ' ')
    echo -e "${GREEN}[+] Found $url_count URL(s)${RESET}"
    
    # Display ALL URLs with no limit
    echo -e "${GREEN}[+] URLs found:${RESET}"
    while IFS= read -r url; do
      [[ -z "$url" ]] && continue
      echo -e "${GREEN}    - $url${RESET}"
    done <<< "$all_urls"

    # Save URLs to VirusTotal specific file
    echo "$all_urls" >> "$OUTPUT_DIR/virustotal_urls.txt"

    # Also save to the original all_urls.txt for compatibility
    echo "$all_urls" >> "$OUTPUT_DIR/all_urls.txt"

    # Extract endpoints from URLs
    endpoints=$(echo "$all_urls" | grep -v "^$" | awk -F/ '{if (NF > 3) {path=""; for(i=4;i<=NF;i++){path=path"/"$i} print path}}' | sort -u)

    if [[ ! -z "$endpoints" ]]; then
      endpoint_count=$(echo "$endpoints" | grep -v "^$" | wc -l | tr -d ' ')
      echo -e "${GREEN}[+] Extracted $endpoint_count unique endpoint(s)${RESET}"

      # Save endpoints with subdomain mapping
      while IFS= read -r endpoint; do
        [[ -z "$endpoint" ]] && continue
        echo "$subdomain,$endpoint" >> "$OUTPUT_DIR/subdomain_to_endpoint.csv"
        echo "$endpoint" >> "$OUTPUT_DIR/all_endpoints.txt"
      done <<< "$endpoints"
    fi
  else
    echo -e "${YELLOW}[!] No URLs found for: $subdomain${RESET}"
  fi

  # Extract subdomains if available
  subdomains=$(echo "$response" | jq -r '.subdomains[]? // empty' 2>/dev/null)
  if [[ ! -z "$subdomains" ]]; then
    subdomain_count=$(echo "$subdomains" | grep -v "^$" | wc -l | tr -d ' ')
    echo -e "${GREEN}[+] Found $subdomain_count subdomain(s)${RESET}"

    # Create a new file for discovered subdomains if it doesn't exist
    if [[ ! -f "$OUTPUT_DIR/discovered_subdomains.txt" ]]; then
      touch "$OUTPUT_DIR/discovered_subdomains.txt"
    fi

    # Save discovered subdomains
    while IFS= read -r discovered_subdomain; do
      [[ -z "$discovered_subdomain" ]] && continue
      echo -e "${GREEN}    - $discovered_subdomain${RESET}"
      echo "$discovered_subdomain" >> "$OUTPUT_DIR/discovered_subdomains.txt"
    done <<< "$subdomains"
  fi

  return 0
}

# Function to fetch data from URLscan.io
fetch_urlscan_data() {
  local subdomain=$1
  local api_key=$2

  echo -e "\n${PURPLE}============================================================${RESET}"
  echo -e "${BLUE}[+] Processing subdomain: ${GREEN}$subdomain${RESET} (URLscan.io)"
  echo -e "${PURPLE}============================================================${RESET}"

  # First, search for the domain in URLscan
  local SEARCH_URL="https://urlscan.io/api/v1/search/?q=domain:$subdomain"

  search_response=$(curl -s -H "API-Key: $api_key" --max-time 30 "$SEARCH_URL")
  if [[ $? -ne 0 || -z "$search_response" || "$search_response" == *"error"* ]]; then
    echo -e "${RED}[!] Error searching URLscan.io for: $subdomain${RESET}"
    return 1
  fi

  # Check if results were found
  result_count=$(echo "$search_response" | jq -r '.results | length' 2>/dev/null)
  if [[ "$result_count" -eq 0 ]]; then
    echo -e "${YELLOW}[!] No URLscan.io results found for: $subdomain${RESET}"
    return 0
  fi

  echo -e "${GREEN}[+] Found $result_count URLscan.io result(s) for: $subdomain${RESET}"

  # Get the most recent scan UUID
  latest_uuid=$(echo "$search_response" | jq -r '.results[0]._id' 2>/dev/null)

  # Fetch detailed results for the latest scan
  detail_url="https://urlscan.io/api/v1/result/$latest_uuid/"
  detail_response=$(curl -s -H "API-Key: $api_key" --max-time 30 "$detail_url")

  if [[ $? -ne 0 || -z "$detail_response" || "$detail_response" == *"error"* ]]; then
    echo -e "${RED}[!] Error fetching URLscan.io details for scan ID: $latest_uuid${RESET}"
    return 1
  fi

  # Extract IP addresses
  ip_addresses=$(echo "$detail_response" | jq -r '.data.requests[].response.remote.ip // empty' 2>/dev/null | sort -u)
  if [[ ! -z "$ip_addresses" ]]; then
    echo -e "${GREEN}[+] Found $(echo "$ip_addresses" | wc -l | tr -d ' ') IP(s) from URLscan${RESET}"

    # Save IP addresses with subdomain mapping
    while IFS= read -r ip; do
      [[ -z "$ip" ]] && continue
      echo -e "${GREEN}    - $ip${RESET}"
      echo "$subdomain,$ip" >> "$OUTPUT_DIR/subdomain_to_ip.csv"
      echo "$ip" >> "$OUTPUT_DIR/all_ips.txt"
    done <<< "$ip_addresses"
  fi

  # Extract URLs from the page
  page_urls=$(echo "$detail_response" | jq -r '.data.requests[].request.url // empty' 2>/dev/null | sort -u)
  if [[ ! -z "$page_urls" ]]; then
    echo -e "${GREEN}[+] Found $(echo "$page_urls" | wc -l | tr -d ' ') URL(s) from URLscan${RESET}"

    # Save URLs
    echo "$page_urls" >> "$OUTPUT_DIR/all_urls.txt"

    # Extract endpoints from URLs
    endpoints=$(echo "$page_urls" | awk -F/ '{if (NF > 3) {path=""; for(i=4;i<=NF;i++){path=path"/"$i} print path}}' | sort -u)

    if [[ ! -z "$endpoints" ]]; then
      echo -e "${GREEN}[+] Extracted $(echo "$endpoints" | wc -l | tr -d ' ') unique endpoint(s) from URLscan${RESET}"

      # Save endpoints with subdomain mapping
      while IFS= read -r endpoint; do
        [[ -z "$endpoint" ]] && continue
        echo "$subdomain,$endpoint" >> "$OUTPUT_DIR/subdomain_to_endpoint.csv"
        echo "$endpoint" >> "$OUTPUT_DIR/all_endpoints.txt"
      done <<< "$endpoints"
    fi
  fi

  # Extract technologies used
  tech_used=$(echo "$detail_response" | jq -r '.data.requests[].page.technologies[]?.name // empty' 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')
  if [[ ! -z "$tech_used" ]]; then
    echo -e "${CYAN}[+] Technologies detected: $tech_used${RESET}"
    echo "$subdomain,$tech_used" >> "$OUTPUT_DIR/subdomain_to_tech.csv"
  fi

  return 0
}




# Function to fetch data from Web Archive and check live endpoints
fetch_webarchive_data() {
  local subdomain=$1

  echo -e "\n${PURPLE}============================================================${RESET}"
  echo -e "${BLUE}[+] Processing subdomain: ${GREEN}$subdomain${RESET} (Web Archive)"
  echo -e "${PURPLE}============================================================${RESET}"

  # Web Archive CDX API URL
  local URL="https://web.archive.org/cdx/search/cdx?url=*.$subdomain/*&collapse=urlkey&output=text&fl=original"

  response=$(curl -s --max-time 60 "$URL")
  if [[ $? -ne 0 || -z "$response" ]]; then
    echo -e "${YELLOW}[!] No Web Archive data found for: $subdomain${RESET}"
    return 0
  fi

  # Count URLs found
  url_count=$(echo "$response" | wc -l)
  echo -e "${GREEN}[+] Found $url_count URL(s) in Web Archive for: $subdomain${RESET}"

  # Extract unique endpoints from Web Archive URLs
  endpoints=$(echo "$response" | awk -F/ '{if (NF > 3) {path=""; for(i=4;i<=NF;i++){path=path"/"$i} print path}}' | sort -u)

  if [[ ! -z "$endpoints" ]]; then
    echo -e "${GREEN}[+] Extracted $(echo "$endpoints" | wc -l | tr -d ' ') unique endpoint(s) from Web Archive${RESET}"
    echo -e "${CYAN}[+] Checking which endpoints are still live...${RESET}"

    # Save all endpoints from Web Archive
    while IFS= read -r endpoint; do
      [[ -z "$endpoint" ]] && continue
      echo "$subdomain,$endpoint" >> "$OUTPUT_DIR/webarchive_endpoints.csv"
    done <<< "$endpoints"

    # Check which endpoints are still live
    live_count=0
    while IFS= read -r endpoint; do
      [[ -z "$endpoint" ]] && continue

      # Construct URL to check
      check_url="https://$subdomain$endpoint"

      # Check if the endpoint is live (allow redirects, timeout after 5 seconds)
      status_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -L "$check_url")

      # If status code is 200-399, consider it live
      if [[ $status_code -ge 200 && $status_code -lt 400 ]]; then
        echo -e "${GREEN}    - [LIVE] $endpoint ($status_code)${RESET}"
        echo "$subdomain,$endpoint,$status_code" >> "$OUTPUT_DIR/live_endpoints.csv"
        echo "$endpoint" >> "$OUTPUT_DIR/all_endpoints.txt"
        live_count=$((live_count + 1))
      else
        echo -e "${YELLOW}    - [DEAD] $endpoint ($status_code)${RESET}"
      fi

      # Add URL to the list
      echo "$check_url" >> "$OUTPUT_DIR/all_urls.txt"

    done <<< "$endpoints"

    echo -e "${GREEN}[+] Found $live_count live endpoint(s) out of $(echo "$endpoints" | wc -l | tr -d ' ')${RESET}"
  fi

  return 0
}

# Function to fetch data for an IP using Shodan
fetch_shodan_data() {
  local ip=$1
  local api_key=$2

  echo -e "${BLUE}[+] Querying Shodan for IP: ${GREEN}$ip${RESET}"

  local URL="https://api.shodan.io/shodan/host/$ip?key=$api_key"

  response=$(curl -s --max-time 30 "$URL")
  if [[ $? -ne 0 || -z "$response" || "$response" == *"error"* ]]; then
    echo -e "${YELLOW}    - No Shodan data found for IP: $ip${RESET}"
    return 1
  fi

  # Extract basic host information
  ip_ports=$(echo "$response" | jq -r '.ports[]? // empty' 2>/dev/null | sort -n | tr '\n' ',' | sed 's/,$//')
  ip_org=$(echo "$response" | jq -r '.org? // "Unknown"' 2>/dev/null)
  ip_isp=$(echo "$response" | jq -r '.isp? // "Unknown"' 2>/dev/null)
  ip_country=$(echo "$response" | jq -r '.country_name? // "Unknown"' 2>/dev/null)
  ip_asn=$(echo "$response" | jq -r '.asn? // "Unknown"' 2>/dev/null)
  ip_hostnames=$(echo "$response" | jq -r '.hostnames[]? // empty' 2>/dev/null | tr '\n' ',' | sed 's/,$//')

  echo -e "${GREEN}    - Organization: $ip_org${RESET}"
  echo -e "${GREEN}    - Country: $ip_country${RESET}"
  if [[ ! -z "$ip_ports" ]]; then
    echo -e "${GREEN}    - Open Ports: $ip_ports${RESET}"
  fi

  # Save the Shodan data
  {
    echo "IP: $ip"
    echo "Organization: $ip_org"
    echo "ISP: $ip_isp"
    echo "Country: $ip_country"
    echo "ASN: $ip_asn"
    echo "Open Ports: $ip_ports"
    echo "Hostnames: $ip_hostnames"
  } >> "$OUTPUT_DIR/shodan_details.txt"

  # Extract origin servers from HTTP headers
  origin_servers=$(echo "$response" | jq -r '.data[]? | select(.http?) | .http.headers? | (.["X-Served-By"]? // .["X-Origin"]? // .["Origin"]? // .["Server"]? // empty)' 2>/dev/null)
  if [[ ! -z "$origin_servers" ]]; then
    echo -e "${YELLOW}    - Origin servers: $origin_servers${RESET}"
    echo "Origin Servers: $origin_servers" >> "$OUTPUT_DIR/shodan_details.txt"
    echo "$origin_servers" >> "$OUTPUT_DIR/origin_servers.txt"
    echo "$ip,$origin_servers" >> "$OUTPUT_DIR/ip_to_origin.csv"
  fi

  # Extract web technologies if available
  web_tech=$(echo "$response" | jq -r '.data[]? | select(.http?) | .http.components? | keys[]? // empty' 2>/dev/null)
  if [[ ! -z "$web_tech" ]]; then
    echo -e "${CYAN}    - Technologies: $(echo "$web_tech" | tr '\n' ',' | sed 's/,$//')${RESET}"
    echo "Technologies: $web_tech" >> "$OUTPUT_DIR/shodan_details.txt"
    echo "$ip,$web_tech" >> "$OUTPUT_DIR/ip_to_tech.csv"
  fi

  # Extract SSL certificate information if available
  ssl_info=$(echo "$response" | jq -r '.data[]? | select(.ssl?) | .ssl.cert.subject?' 2>/dev/null)
  if [[ ! -z "$ssl_info" ]]; then
    ssl_common_name=$(echo "$ssl_info" | jq -r '.CN // "Unknown"' 2>/dev/null)
    ssl_org=$(echo "$ssl_info" | jq -r '.O // "Unknown"' 2>/dev/null)
    ssl_issuer=$(echo "$response" | jq -r '.data[]? | select(.ssl?) | .ssl.cert.issuer.CN // "Unknown"' 2>/dev/null)
    ssl_expires=$(echo "$response" | jq -r '.data[]? | select(.ssl?) | .ssl.cert.expires // "Unknown"' 2>/dev/null)

    echo -e "${PURPLE}    - SSL Certificate: $ssl_common_name (Issuer: $ssl_issuer)${RESET}"
    echo -e "${PURPLE}    - SSL Expires: $ssl_expires${RESET}"

    {
      echo "SSL Common Name: $ssl_common_name"
      echo "SSL Organization: $ssl_org"
      echo "SSL Issuer: $ssl_issuer"
      echo "SSL Expires: $ssl_expires"
    } >> "$OUTPUT_DIR/shodan_details.txt"

    echo "$ip,$ssl_common_name,$ssl_issuer,$ssl_expires" >> "$OUTPUT_DIR/ip_to_ssl.csv"
  fi

  # Extract vulnerabilities if available
  vulns=$(echo "$response" | jq -r '.vulns[]? // empty' 2>/dev/null)
  if [[ ! -z "$vulns" ]]; then
    echo -e "${RED}    - Vulnerabilities found!${RESET}"
    echo "Vulnerabilities:" >> "$OUTPUT_DIR/shodan_details.txt"

    while IFS= read -r vuln; do
      [[ -z "$vuln" ]] && continue
      echo -e "${RED}      - $vuln${RESET}"
      echo "  - $vuln" >> "$OUTPUT_DIR/shodan_details.txt"
      echo "$ip,$vuln" >> "$OUTPUT_DIR/ip_to_vulns.csv"
    done <<< "$vulns"
  fi

  # Add a blank line for readability
  echo "" >> "$OUTPUT_DIR/shodan_details.txt"

  return 0
}

# Initialize additional Shodan-related files
touch "$OUTPUT_DIR/ip_to_ssl.csv"
touch "$OUTPUT_DIR/ip_to_vulns.csv"

# Add headers to Shodan CSV files
echo "IP,CommonName,Issuer,Expires" > "$OUTPUT_DIR/ip_to_ssl.csv"
echo "IP,Vulnerability" > "$OUTPUT_DIR/ip_to_vulns.csv"

# Function to display a countdown
countdown() {
  local seconds=$1
  while [ $seconds -gt 0 ]; do
    echo -ne "${CYAN}Waiting for $seconds seconds...${RESET}\r"
    sleep 1
    : $((seconds--))
  done
  echo -ne "\033[0K"  # Clear the countdown line
}

# Function to rotate VirusTotal API key
get_vt_api_key() {
  local index=$1

  if [ $index -eq 1 ] && [ -n "$VT_API_KEY_1" ]; then
    echo "$VT_API_KEY_1"
  elif [ $index -eq 2 ] && [ -n "$VT_API_KEY_2" ]; then
    echo "$VT_API_KEY_2"
  elif [ $index -eq 3 ] && [ -n "$VT_API_KEY_3" ]; then
    echo "$VT_API_KEY_3"
  else
    # Fallback to the first key if available
    if [ -n "$VT_API_KEY_1" ]; then
      echo "$VT_API_KEY_1"
    else
      echo ""
    fi
  fi
}

  if [[ "$SKIP_ALIENVAULT" != "true" && (-n "$ALIENVAULT_API_KEY_1" || -n "$ALIENVAULT_API_KEY_2" || -n "$ALIENVAULT_API_KEY_3") ]]; then
  echo -e "\n${PURPLE}============================================================${RESET}"
  echo -e "${BLUE}[+] Processing unique IPs with AlienVault OTX${RESET}"
  echo -e "${PURPLE}============================================================${RESET}"

  # Get unique IPs
  UNIQUE_IPS=$(sort -u "$OUTPUT_DIR/all_ips.txt")
  IP_COUNT=$(echo "$UNIQUE_IPS" | wc -l | tr -d ' ')

  if [[ $IP_COUNT -eq 0 ]]; then
    echo -e "${YELLOW}[!] No IPs found to process with AlienVault OTX${RESET}"
  else
    echo -e "${GREEN}[+] Found $IP_COUNT unique IPs to process with AlienVault OTX${RESET}"

    # Reset counter for IP processing
    ALIENVAULT_API_KEY_INDEX=1
    ALIENVAULT_REQUEST_COUNT=0

    # Process each IP
    IP_PROCESSED=0
    while IFS= read -r ip; do
      [[ -z "$ip" ]] && continue

      IP_PROCESSED=$((IP_PROCESSED + 1))
      echo -e "${PURPLE}[+] Processing IP ${IP_PROCESSED}/${IP_COUNT}: $ip${RESET}"

      ALIENVAULT_API_KEY=$(get_alienvault_api_key $ALIENVAULT_API_KEY_INDEX)
      fetch_alienvault_data "$ip" "ip" "$ALIENVAULT_API_KEY"
      ALIENVAULT_REQUEST_COUNT=$((ALIENVAULT_REQUEST_COUNT + 1))

      # Rotate AlienVault API keys after every 3 requests to avoid rate limiting
      if [[ $ALIENVAULT_REQUEST_COUNT -ge 3 ]]; then
        ALIENVAULT_API_KEY_INDEX=$(( (ALIENVAULT_API_KEY_INDEX % 3) + 1 ))
        ALIENVAULT_REQUEST_COUNT=0
        echo -e "${YELLOW}[!] Rotated to AlienVault API key $ALIENVAULT_API_KEY_INDEX${RESET}"
      fi

      # Add delay between AlienVault requests if not the last one
      if [[ $IP_PROCESSED -lt $IP_COUNT ]]; then
        countdown 5  # Shorter delay for AlienVault
      fi

    done <<< "$UNIQUE_IPS"
  fi
else
  echo -e "${YELLOW}[!] AlienVault OTX API disabled${RESET}"
fi

# Add to your summary report:
echo "- AlienVault OTX API: $([[ "$SKIP_ALIENVAULT" != "true" ]] && echo "Enabled" || echo "Disabled")"

# Function to fetch data from AlienVault OTX
fetch_alienvault_data() {
  local target=$1
  local type=$2  # "domain" or "ip"
  local api_key=$3

  echo -e "\n${PURPLE}============================================================${RESET}"
  echo -e "${BLUE}[+] Processing $type: ${GREEN}$target${RESET} (AlienVault OTX)"
  echo -e "${PURPLE}============================================================${RESET}"

  # Check if API key is available
  if [[ -z "$api_key" ]]; then
    echo -e "${RED}[!] Error: No AlienVault API key available. Skipping AlienVault check.${RESET}"
    return 1
  fi

  local URL="https://otx.alienvault.com/api/v1/indicators/$type/$target/general"
  local PULSE_URL="https://otx.alienvault.com/api/v1/indicators/$type/$target/pulse_info"
  local MALWARE_URL="https://otx.alienvault.com/api/v1/indicators/$type/$target/malware"
  local URL_LIST_URL="https://otx.alienvault.com/api/v1/indicators/$type/$target/url_list"

  # Fetch general information
  response=$(curl -s -H "X-OTX-API-KEY: $api_key" --max-time 30 "$URL")

  # Check for API errors
  if [[ "$response" == *"\"error\""* ]]; then
    error_msg=$(echo "$response" | jq -r '.error_message // "Unknown error"' 2>/dev/null)
    echo -e "${RED}[!] AlienVault API error: $error_msg${RESET}"
    return 1
  elif [[ -z "$response" ]]; then
    echo -e "${RED}[!] Empty response from AlienVault API${RESET}"
    return 1
  fi

  # Extract general information
  reputation=$(echo "$response" | jq -r '.reputation // 0' 2>/dev/null)
  sections=$(echo "$response" | jq -r '.sections[]? // empty' 2>/dev/null)

  # Display reputation if available
  if [[ "$reputation" != "null" && "$reputation" != "0" ]]; then
    echo -e "${YELLOW}[+] Reputation score: $reputation${RESET}"

    # Store reputation data
    if [[ "$type" == "domain" ]]; then
      echo "$target,$reputation" >> "$OUTPUT_DIR/domain_reputation.csv"
    else
      echo "$target,$reputation" >> "$OUTPUT_DIR/ip_reputation.csv"
    fi
  else
    echo -e "${GREEN}[+] No reputation data found${RESET}"
  fi

  # Fetch pulse information (threat intel reports)
  pulse_response=$(curl -s -H "X-OTX-API-KEY: $api_key" --max-time 30 "$PULSE_URL")

  # Extract pulse information
  if [[ "$pulse_response" != *"\"error\""* && ! -z "$pulse_response" ]]; then
    pulse_count=$(echo "$pulse_response" | jq -r '.count // 0' 2>/dev/null)

    if [[ "$pulse_count" -gt 0 ]]; then
      echo -e "${RED}[+] Found in $pulse_count threat intelligence reports${RESET}"

      # Extract and save the most recent pulses
      pulses=$(echo "$pulse_response" | jq -r '.pulses[] | "\(.name) (\(.created))"' 2>/dev/null | head -5)

      {
        echo "Target: $target ($type)"
        echo "Total pulses: $pulse_count"
        echo "Recent reports:"
        echo "$pulses"
        echo "----------------------------------------"
      } >> "$OUTPUT_DIR/threat_intel_reports.txt"

      # Store threat intel counts
      if [[ "$type" == "domain" ]]; then
        echo "$target,$pulse_count" >> "$OUTPUT_DIR/domain_threat_intel.csv"
      else
        echo "$target,$pulse_count" >> "$OUTPUT_DIR/ip_threat_intel.csv"
      fi

      # Extract tags from pulses
      tags=$(echo "$pulse_response" | jq -r '.pulses[].tags[]? // empty' 2>/dev/null | sort | uniq)
      if [[ ! -z "$tags" ]]; then
        tag_list=$(echo "$tags" | tr '\n' ',' | sed 's/,$//')
        echo -e "${RED}[+] Associated tags: $tag_list${RESET}"

        # Store tags
        if [[ "$type" == "domain" ]]; then
          echo "$target,$tag_list" >> "$OUTPUT_DIR/domain_tags.csv"
        else
          echo "$target,$tag_list" >> "$OUTPUT_DIR/ip_tags.csv"
        fi
      fi
    else
      echo -e "${GREEN}[+] Not found in any threat intelligence reports${RESET}"
    fi
  fi

  # Fetch malware information
  malware_response=$(curl -s -H "X-OTX-API-KEY: $api_key" --max-time 30 "$MALWARE_URL")

  # Extract malware information
  if [[ "$malware_response" != *"\"error\""* && ! -z "$malware_response" ]]; then
    malware_count=$(echo "$malware_response" | jq -r '.count // 0' 2>/dev/null)

    if [[ "$malware_count" -gt 0 ]]; then
      echo -e "${RED}[+] Associated with $malware_count malware samples${RESET}"

      # Save detailed malware information
      {
        echo "Target: $target ($type)"
        echo "Total malware samples: $malware_count"
        echo "----------------------------------------"
      } >> "$OUTPUT_DIR/malware_associations.txt"

      # Store malware counts
      if [[ "$type" == "domain" ]]; then
        echo "$target,$malware_count" >> "$OUTPUT_DIR/domain_malware.csv"
      else
        echo "$target,$malware_count" >> "$OUTPUT_DIR/ip_malware.csv"
      fi
    else
      echo -e "${GREEN}[+] No malware associations found${RESET}"
    fi
  fi

  # Fetch URL list if target is a domain
  if [[ "$type" == "domain" ]]; then
    url_response=$(curl -s -H "X-OTX-API-KEY: $api_key" --max-time 30 "$URL_LIST_URL")

    # Extract URL information
    if [[ "$url_response" != *"\"error\""* && ! -z "$url_response" ]]; then
      url_count=$(echo "$url_response" | jq -r '.url_list | length // 0' 2>/dev/null)

      if [[ "$url_count" -gt 0 ]]; then
        echo -e "${GREEN}[+] Found $url_count related URLs${RESET}"

        # Extract and save URLs
        urls=$(echo "$url_response" | jq -r '.url_list[].url' 2>/dev/null)
        echo "$urls" >> "$OUTPUT_DIR/all_urls.txt"

        # Extract endpoints from URLs
        endpoints=$(echo "$urls" | awk -F/ '{if (NF > 3) {path=""; for(i=4;i<=NF;i++){path=path"/"$i} print path}}' | sort -u)

        if [[ ! -z "$endpoints" ]]; then
          endpoint_count=$(echo "$endpoints" | grep -v "^$" | wc -l | tr -d ' ')
          echo -e "${GREEN}[+] Extracted $endpoint_count unique endpoint(s) from AlienVault${RESET}"

          # Save endpoints with domain mapping
          while IFS= read -r endpoint; do
            [[ -z "$endpoint" ]] && continue
            echo "$target,$endpoint" >> "$OUTPUT_DIR/subdomain_to_endpoint.csv"
            echo "$endpoint" >> "$OUTPUT_DIR/all_endpoints.txt"
          done <<< "$endpoints"
        fi
      else
        echo -e "${YELLOW}[+] No related URLs found${RESET}"
      fi
    fi
  fi

  return 0
}

# Function to rotate AlienVault API key
get_alienvault_api_key() {
  local index=$1

  if [ $index -eq 1 ] && [ -n "$ALIENVAULT_API_KEY_1" ]; then
    echo "$ALIENVAULT_API_KEY_1"
  elif [ $index -eq 2 ] && [ -n "$ALIENVAULT_API_KEY_2" ]; then
    echo "$ALIENVAULT_API_KEY_2"
  elif [ $index -eq 3 ] && [ -n "$ALIENVAULT_API_KEY_3" ]; then
    echo "$ALIENVAULT_API_KEY_3"
  else
    # Fallback to the first key if available
    if [ -n "$ALIENVAULT_API_KEY_1" ]; then
      echo "$ALIENVAULT_API_KEY_1"
    else
      echo ""
    fi
  fi
}

# Function to check prerequisites
check_prerequisites() {
  local missing_tools=0

  # Check if jq is installed
  if ! command -v jq &> /dev/null; then
    echo -e "${RED}[!] Error: jq is not installed. Please install it first (e.g., 'sudo apt install jq' or 'brew install jq').${RESET}"
    missing_tools=1
  fi

  # Check if curl is installed
  if ! command -v curl &> /dev/null; then
    echo -e "${RED}[!] Error: curl is not installed. Please install it first.${RESET}"
    missing_tools=1
  fi

  # Check if base64 is installed
  if ! command -v base64 &> /dev/null; then
    echo -e "${RED}[!] Error: base64 is not installed. Please install it first.${RESET}"
    missing_tools=1
  fi

  if [ $missing_tools -eq 1 ]; then
    exit 1
  fi
}

# Function to check if a string is a valid domain/subdomain
is_valid_domain() {
  local domain=$1
  if [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
    return 0
  else
    return 1
  fi
}

# Function to print usage instructions
print_usage() {
  echo -e "${YELLOW}Usage:${RESET}"
  echo -e "${GREEN}$0 <file_with_subdomains> [options]${RESET}"
  echo -e ""
  echo -e "${YELLOW}Options:${RESET}"
  echo -e "  ${GREEN}--delay <seconds>${RESET}         Delay between requests (default: 15)"
  echo -e "  ${GREEN}--shodan-key <key>${RESET}        Shodan API key"
  echo -e "  ${GREEN}--alienvault-key1 <key>${RESET}    AlienVault OTX API key 1"
  echo -e "  ${GREEN}--alienvault-key2 <key>${RESET}    AlienVault OTX API key 2"
  echo -e "  ${GREEN}--alienvault-key3 <key>${RESET}    AlienVault OTX API key 3"
  echo -e "  ${GREEN}--skip-alienvault${RESET}          Skip AlienVault OTX queries"
  echo -e "  ${GREEN}--vt-key1 <key>${RESET}           VirusTotal API key 1"
  echo -e "  ${GREEN}--vt-key2 <key>${RESET}           VirusTotal API key 2"
  echo -e "  ${GREEN}--vt-key3 <key>${RESET}           VirusTotal API key 3"
  echo -e "  ${GREEN}--urlscan-key <key>${RESET}       URLScan.io API key"
  echo -e "  ${GREEN}--skip-vt${RESET}                 Skip VirusTotal queries"
  echo -e "  ${GREEN}--skip-shodan${RESET}             Skip Shodan queries"
  echo -e "  ${GREEN}--skip-urlscan${RESET}            Skip URLScan.io queries"
  echo -e "  ${GREEN}--skip-webarchive${RESET}         Skip Web Archive queries"
  echo -e "  ${GREEN}--help${RESET}                    Show this help message"
  echo -e ""
  echo -e "${YELLOW}Environment Variables:${RESET}"
  echo -e "  You can also set API keys using environment variables:"
  echo -e "  ${GREEN}SHODAN_API_KEY${RESET}            Shodan API key"
  echo -e "  ${GREEN}ALIENVAULT_API_KEY_1${RESET}       AlienVault OTX API key 1"
  echo -e "  ${GREEN}ALIENVAULT_API_KEY_2${RESET}       AlienVault OTX API key 2"
  echo -e "  ${GREEN}ALIENVAULT_API_KEY_3${RESET}       AlienVault OTX API key 3"
  echo -e "  ${GREEN}VT_API_KEY_1${RESET}              VirusTotal API key 1"
  echo -e "  ${GREEN}VT_API_KEY_2${RESET}              VirusTotal API key 2"
  echo -e "  ${GREEN}VT_API_KEY_3${RESET}              VirusTotal API key 3"
  echo -e "  ${GREEN}URLSCAN_API_KEY${RESET}           URLScan.io API key"
  echo -e ""
  echo -e "${YELLOW}Example:${RESET}"
  echo -e "  ${GREEN}$0 subdomains.txt --shodan-key ABC123 --vt-key1 DEF456 --delay 10${RESET}"
  echo -e ""
}

# Main script starts here
check_prerequisites

# Parse command line arguments
if [ $# -eq 0 ]; then
  print_usage
  exit 1
fi

INPUT_FILE=""
REQUEST_DELAY=15
SKIP_VT=false
SKIP_ALIENVAULT=false
SKIP_SHODAN=false
SKIP_URLSCAN=false
SKIP_WEBARCHIVE=false

# Parse command line options
while [[ $# -gt 0 ]]; do
  case $1 in
    --help)
      print_usage
      exit 0
      ;;
    --delay)
      REQUEST_DELAY="$2"
      shift 2
      ;;
    --shodan-key)
      SHODAN_API_KEY="$2"
      shift 2
      ;;
    # Add to your command line options parsing (inside the while loop):
    --alienvault-key1)
      ALIENVAULT_API_KEY_1="$2"
      shift 2
      ;;
    --alienvault-key2)
      ALIENVAULT_API_KEY_2="$2"
      shift 2
      ;;
    --alienvault-key3)
      ALIENVAULT_API_KEY_3="$2"
      shift 2
      ;;
    --skip-alienvault)
      SKIP_ALIENVAULT=true
      shift
      ;;
    --vt-key1)
      VT_API_KEY_1="$2"
      shift 2
      ;;
    --vt-key2)
      VT_API_KEY_2="$2"
      shift 2
      ;;
    --vt-key3)
      VT_API_KEY_3="$2"
      shift 2
      ;;
    --urlscan-key)
      URLSCAN_API_KEY="$2"
      shift 2
      ;;
    --skip-vt)
      SKIP_VT=true
      shift
      ;;
    --skip-shodan)
      SKIP_SHODAN=true
      shift
      ;;
    --skip-urlscan)
      SKIP_URLSCAN=true
      shift
      ;;
    --skip-webarchive)
      SKIP_WEBARCHIVE=true
      shift
      ;;
    *)
      if [ -z "$INPUT_FILE" ]; then
        INPUT_FILE="$1"
      else
        echo -e "${RED}[!] Error: Unexpected argument: $1${RESET}"
        print_usage
        exit 1
      fi
      shift
      ;;
  esac
done

# Check if input file exists
if [ ! -f "$INPUT_FILE" ]; then
  echo -e "${RED}[!] Error: Input file '$INPUT_FILE' not found!${RESET}"
  exit 1
fi

# Create output directory
OUTPUT_DIR="recon_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"
echo -e "${GREEN}[+] Created output directory: $OUTPUT_DIR${RESET}"

# Initialize output files
touch "$OUTPUT_DIR/domain_reputation.csv"
touch "$OUTPUT_DIR/ip_reputation.csv"
touch "$OUTPUT_DIR/domain_threat_intel.csv"
touch "$OUTPUT_DIR/ip_threat_intel.csv"
touch "$OUTPUT_DIR/domain_tags.csv"
touch "$OUTPUT_DIR/ip_tags.csv"
touch "$OUTPUT_DIR/domain_malware.csv"
touch "$OUTPUT_DIR/ip_malware.csv"
touch "$OUTPUT_DIR/threat_intel_reports.txt"
touch "$OUTPUT_DIR/malware_associations.txt"
touch "$OUTPUT_DIR/subdomain_to_ip.csv"
touch "$OUTPUT_DIR/all_ips.txt"
touch "$OUTPUT_DIR/all_urls.txt"
touch "$OUTPUT_DIR/all_endpoints.txt"
touch "$OUTPUT_DIR/subdomain_to_endpoint.csv"
touch "$OUTPUT_DIR/shodan_details.txt"
touch "$OUTPUT_DIR/origin_servers.txt"
touch "$OUTPUT_DIR/ip_to_origin.csv"
touch "$OUTPUT_DIR/ip_to_tech.csv"
touch "$OUTPUT_DIR/ip_to_port.csv"
touch "$OUTPUT_DIR/ip_to_server.csv"
touch "$OUTPUT_DIR/subdomain_to_tech.csv"
touch "$OUTPUT_DIR/webarchive_endpoints.csv"
touch "$OUTPUT_DIR/live_endpoints.csv"
touch "$OUTPUT_DIR/errors.log"

# Add headers to CSV files
echo "Domain,Reputation" > "$OUTPUT_DIR/domain_reputation.csv"
echo "IP,Reputation" > "$OUTPUT_DIR/ip_reputation.csv"
echo "Domain,ThreatCount" > "$OUTPUT_DIR/domain_threat_intel.csv"
echo "IP,ThreatCount" > "$OUTPUT_DIR/ip_threat_intel.csv"
echo "Domain,Tags" > "$OUTPUT_DIR/domain_tags.csv"
echo "IP,Tags" > "$OUTPUT_DIR/ip_tags.csv"
echo "Domain,MalwareCount" > "$OUTPUT_DIR/domain_malware.csv"
echo "IP,MalwareCount" > "$OUTPUT_DIR/ip_malware.csv"
echo "Subdomain,IP" > "$OUTPUT_DIR/subdomain_to_ip.csv"
echo "Subdomain,Endpoint" > "$OUTPUT_DIR/subdomain_to_endpoint.csv"
echo "IP,Origin" > "$OUTPUT_DIR/ip_to_origin.csv"
echo "IP,Technology" > "$OUTPUT_DIR/ip_to_tech.csv"
echo "IP,Port,Protocol" > "$OUTPUT_DIR/ip_to_port.csv"
echo "IP,Server" > "$OUTPUT_DIR/ip_to_server.csv"
echo "Subdomain,Technology" > "$OUTPUT_DIR/subdomain_to_tech.csv"
echo "Subdomain,Endpoint,StatusCode" > "$OUTPUT_DIR/live_endpoints.csv"

# Count total number of subdomains
TOTAL_SUBDOMAINS=$(grep -v "^#" "$INPUT_FILE" | grep -v "^$" | wc -l | tr -d ' ')
echo -e "${GREEN}[+] Processing $TOTAL_SUBDOMAINS subdomains from file: $INPUT_FILE${RESET}"

# Initialize variables for tracking
VT_API_KEY_INDEX=1
VT_REQUEST_COUNT=0
PROCESSED_COUNT=0
SUCCESSFUL_COUNT=0
ERROR_COUNT=0
ALIENVAULT_API_KEY_INDEX=1
ALIENVAULT_REQUEST_COUNT=0



# Check if we have services to use
SERVICE_COUNT=0
if [[ "$SKIP_VT" != "true" && (-n "$VT_API_KEY_1" || -n "$VT_API_KEY_2" || -n "$VT_API_KEY_3") ]]; then
  SERVICE_COUNT=$((SERVICE_COUNT + 1))
  echo -e "${GREEN}[+] VirusTotal API enabled${RESET}"
else
  echo -e "${YELLOW}[!] VirusTotal API disabled${RESET}"
  SKIP_VT=true
fi

if [[ "$SKIP_URLSCAN" != "true" && -n "$URLSCAN_API_KEY" ]]; then
  SERVICE_COUNT=$((SERVICE_COUNT + 1))
  echo -e "${GREEN}[+] URLScan.io API enabled${RESET}"
else
  echo -e "${YELLOW}[!] URLScan.io API disabled${RESET}"
  SKIP_URLSCAN=true
fi

if [[ "$SKIP_ALIENVAULT" != "true" && (-n "$ALIENVAULT_API_KEY_1" || -n "$ALIENVAULT_API_KEY_2" || -n "$ALIENVAULT_API_KEY_3") ]]; then
  SERVICE_COUNT=$((SERVICE_COUNT + 1))
  echo -e "${GREEN}[+] AlienVault OTX API enabled${RESET}"
else
  echo -e "${YELLOW}[!] AlienVault OTX API disabled${RESET}"
  SKIP_ALIENVAULT=true
fi

if [[ "$SKIP_WEBARCHIVE" != "true" ]]; then
  SERVICE_COUNT=$((SERVICE_COUNT + 1))
  echo -e "${GREEN}[+] Web Archive lookup enabled${RESET}"
else
  echo -e "${YELLOW}[!] Web Archive lookup disabled${RESET}"
fi

# Process each subdomain
while IFS= read -r subdomain || [[ -n "$subdomain" ]]; do
  # Skip comments and empty lines
  [[ "$subdomain" =~ ^#.*$ || -z "$subdomain" ]] && continue

  # Validate subdomain format
  if ! is_valid_domain "$subdomain"; then
    echo -e "${RED}[!] Invalid subdomain format: $subdomain. Skipping.${RESET}"
    echo "Invalid subdomain format: $subdomain" >> "$OUTPUT_DIR/errors.log"
    ERROR_COUNT=$((ERROR_COUNT + 1))
    continue
  fi

  PROCESSED_COUNT=$((PROCESSED_COUNT + 1))
  echo -e "\n${PURPLE}============================================================${RESET}"
  echo -e "${BLUE}[+] Processing subdomain ${PROCESSED_COUNT}/${TOTAL_SUBDOMAINS}: ${GREEN}$subdomain${RESET}"
  echo -e "${PURPLE}============================================================${RESET}"

  # Process with VirusTotal
  if [[ "$SKIP_VT" != "true" ]]; then
    VT_API_KEY=$(get_vt_api_key $VT_API_KEY_INDEX)
    fetch_vt_data "$subdomain" "$VT_API_KEY"
    VT_REQUEST_COUNT=$((VT_REQUEST_COUNT + 1))

    # Rotate VirusTotal API keys after every 4 requests to avoid rate limiting
    if [[ $VT_REQUEST_COUNT -ge 4 ]]; then
      VT_API_KEY_INDEX=$(( (VT_API_KEY_INDEX % 3) + 1 ))
      VT_REQUEST_COUNT=0
      echo -e "${YELLOW}[!] Rotated to VirusTotal API key $VT_API_KEY_INDEX${RESET}"
    fi
  fi

  # Process with URLScan
  if [[ "$SKIP_URLSCAN" != "true" ]]; then
    fetch_urlscan_data "$subdomain" "$URLSCAN_API_KEY"
  fi

  # Process with AlienVault OTX
  if [[ "$SKIP_ALIENVAULT" != "true" ]]; then
    ALIENVAULT_API_KEY=$(get_alienvault_api_key $ALIENVAULT_API_KEY_INDEX)
    fetch_alienvault_data "$subdomain" "domain" "$ALIENVAULT_API_KEY"
    ALIENVAULT_REQUEST_COUNT=$((ALIENVAULT_REQUEST_COUNT + 1))

    # Rotate AlienVault API keys after every 3 requests to avoid rate limiting
    if [[ $ALIENVAULT_REQUEST_COUNT -ge 3 ]]; then
      ALIENVAULT_API_KEY_INDEX=$(( (ALIENVAULT_API_KEY_INDEX % 3) + 1 ))
      ALIENVAULT_REQUEST_COUNT=0
      echo -e "${YELLOW}[!] Rotated to AlienVault API key $ALIENVAULT_API_KEY_INDEX${RESET}"
    fi
  fi

  # Process with Web Archive
  if [[ "$SKIP_WEBARCHIVE" != "true" ]]; then
    fetch_webarchive_data "$subdomain"
  fi

  SUCCESSFUL_COUNT=$((SUCCESSFUL_COUNT + 1))

  # Add delay between processing subdomains if not the last one
  if [[ $PROCESSED_COUNT -lt $TOTAL_SUBDOMAINS ]]; then
    echo -e "${CYAN}[+] Completed processing subdomain: $subdomain${RESET}"
    echo -e "${CYAN}[+] Progress: ${PROCESSED_COUNT}/${TOTAL_SUBDOMAINS} (${ERROR_COUNT} errors)${RESET}"
    countdown $REQUEST_DELAY
  fi

done < "$INPUT_FILE"

# Process unique IPs with Shodan if not skipped
if [[ "$SKIP_SHODAN" != "true" && -n "$SHODAN_API_KEY" ]]; then
  echo -e "\n${PURPLE}============================================================${RESET}"
  echo -e "${BLUE}[+] Processing unique IPs with Shodan${RESET}"
  echo -e "${PURPLE}============================================================${RESET}"

  # Get unique IPs
  UNIQUE_IPS=$(sort -u "$OUTPUT_DIR/all_ips.txt")
  IP_COUNT=$(echo "$UNIQUE_IPS" | wc -l | tr -d ' ')

  if [[ $IP_COUNT -eq 0 ]]; then
    echo -e "${YELLOW}[!] No IPs found to process with Shodan${RESET}"
  else
    echo -e "${GREEN}[+] Found $IP_COUNT unique IPs to process with Shodan${RESET}"

    # Process each IP
    IP_PROCESSED=0
    while IFS= read -r ip; do
      [[ -z "$ip" ]] && continue

      IP_PROCESSED=$((IP_PROCESSED + 1))
      echo -e "${PURPLE}[+] Processing IP ${IP_PROCESSED}/${IP_COUNT}: $ip${RESET}"

      fetch_shodan_data "$ip" "$SHODAN_API_KEY"

      # Add delay between Shodan requests if not the last one
      if [[ $IP_PROCESSED -lt $IP_COUNT ]]; then
        countdown 5  # Shorter delay for Shodan
      fi

    done <<< "$UNIQUE_IPS"
  fi
else
  echo -e "${YELLOW}[!] Shodan API disabled${RESET}"
fi

# Remove duplicates from output files
echo -e "\n${PURPLE}============================================================${RESET}"
echo -e "${BLUE}[+] Cleaning up output files${RESET}"
echo -e "${PURPLE}============================================================${RESET}"

for file in "$OUTPUT_DIR/all_ips.txt" "$OUTPUT_DIR/all_urls.txt" "$OUTPUT_DIR/all_endpoints.txt" "$OUTPUT_DIR/origin_servers.txt"; do
  if [[ -f "$file" ]]; then
    original_count=$(wc -l < "$file")
    sort -u "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
    new_count=$(wc -l < "$file")
    echo -e "${GREEN}[+] Cleaned $(basename "$file"): ${original_count} -> ${new_count} entries${RESET}"
  fi
done

# Generate summary report
echo -e "\n${PURPLE}============================================================${RESET}"
echo -e "${BLUE}[+] Generating summary report${RESET}"
echo -e "${PURPLE}============================================================${RESET}"

{
  echo "# Subdomain Reconnaissance Summary"
  echo ""
  echo "Date: $(date)"
  echo "Input File: $INPUT_FILE"
  echo ""
  echo "## Statistics"
  echo "- Total Subdomains Processed: $PROCESSED_COUNT"
  echo "- Successful: $SUCCESSFUL_COUNT"
  echo "- Errors: $ERROR_COUNT"
  echo ""
  echo "## Data Collection"
  echo "- Domains with Threat Intelligence: $(wc -l < "$OUTPUT_DIR/domain_threat_intel.csv" | awk '{print $1-1}')"  # Subtract 1 for header
  echo "- IPs with Threat Intelligence: $(wc -l < "$OUTPUT_DIR/ip_threat_intel.csv" | awk '{print $1-1}')"  # Subtract 1 for header
  echo "- Unique URLs: $(wc -l < "$OUTPUT_DIR/all_urls.txt")"
  echo "- Unique Endpoints: $(wc -l < "$OUTPUT_DIR/all_endpoints.txt")"
  echo "- Live Endpoints: $(wc -l < "$OUTPUT_DIR/live_endpoints.csv" | awk '{print $1-1}')"  # Subtract 1 for header
  echo ""
  echo "## Service Usage"
  echo "- AlienVault OTX API: $([[ "$SKIP_ALIENVAULT" != "true" ]] && echo "Enabled" || echo "Disabled")"
  echo "- VirusTotal API: $([[ "$SKIP_VT" != "true" ]] && echo "Enabled" || echo "Disabled")"
  echo "- URLScan.io API: $([[ "$SKIP_URLSCAN" != "true" ]] && echo "Enabled" || echo "Disabled")"
  echo "- Web Archive: $([[ "$SKIP_WEBARCHIVE" != "true" ]] && echo "Enabled" || echo "Disabled")"
  echo "- Shodan API: $([[ "$SKIP_SHODAN" != "true" ]] && echo "Enabled" || echo "Disabled")"
} > "$OUTPUT_DIR/summary.md"

# Final output
echo -e "\n${PURPLE}============================================================${RESET}"
echo -e "${GREEN}[+] Reconnaissance complete!${RESET}"
echo -e "${GREEN}[+] Results saved in: $OUTPUT_DIR${RESET}"
echo -e "${GREEN}[+] Summary report: $OUTPUT_DIR/summary.md${RESET}"
echo -e "${PURPLE}============================================================${RESET}"

exit 0
