#!/bin/bash

# ========================================================
# Enhanced URL Crawling & Parameter Discovery Engine
# v1.9 - FFUF Parameter Fuzzing Fix
# Multi-input support with advanced endpoint analysis
# ========================================================

# --- Colors and formatting ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# --- Global variables ---
TEMP_DIR=$(mktemp -d)
THREADS=30
DEPTH=4
OUTPUT_DIR=""
WORDLIST=""
SILENT=false
AGGRESSIVE=false
JS_ANALYSIS=true
PARAM_BRUTEFORCE=true
EXTRACT_SECRETS=true
RATE_LIMIT=100
TIMEOUT=10
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
CUSTOM_HEADERS=""
FILTER_EXTENSIONS=true
VALIDATE_URLS=true
FUZZ_PARAMS=false
EXTRACT_COMMENTS=true
ANALYZE_RESPONSES=true
DEBUG=false
URL=""
FILE=""

# --- !!! IMPORTANT: EDIT THIS LINE if using SecretFinder !!! ---
SECRETFINDER_PY_PATH="/home/yehia/Bug_Hunting/Tools/SecretFinder/SecretFinder.py" # <--- EDIT THIS! e.g., "/path/to/SecretFinder/SecretFinder.py"
# --- !!! IMPORTANT: EDIT THIS LINE !!! ---

# --- Enhanced logging with levels ---
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%H:%M:%S')
    local log_file="$OUTPUT_DIR/crawl.log"

    case $level in
        "DEBUG")
            [ "$DEBUG" = true ] && echo -e "${DIM}[${timestamp}] [DBG] ${message}${NC}" >&2
            ;;
        "INFO")
            [ "$SILENT" = false ] && echo -e "${BLUE}[${timestamp}] [INF] ${message}${NC}" >&2
            ;;
        "SUCCESS")
            [ "$SILENT" = false ] && echo -e "${GREEN}[${timestamp}] [OK ] ${message}${NC}" >&2
            ;;
        "WARNING")
            [ "$SILENT" = false ] && echo -e "${YELLOW}[${timestamp}] [WRN] ${message}${NC}" >&2
            ;;
        "ERROR")
            echo -e "${RED}[${timestamp}] [ERR] ${message}${NC}" >&2
            ;;
        "FINDING")
            [ "$SILENT" = false ] && echo -e "${CYAN}[${timestamp}] [🔍 ] ${message}${NC}" >&2
            ;;
    esac

    [ -n "$OUTPUT_DIR" ] && echo "[${timestamp}] [${level}] ${message}" >> "$log_file" 2>/dev/null
}

# --- Cleanup function ---
cleanup() {
    log "INFO" "Cleaning up temporary files..."
    rm -rf "$TEMP_DIR"
    log "INFO" "Cleanup complete."
}

# --- Trap for cleanup on exit ---
trap cleanup EXIT INT TERM

# --- Enhanced banner ---
print_banner() {
    echo -e "${PURPLE}${BOLD}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║  FFFFFFF RRRRRRR EEEEEEE EEEEEEE DDDDDDD   OOOOOOO  MMMMMMM           ║
║  F       R     R E       E       D     D  O       O M M M M M         ║
║  FFFFF   RRRRRRR EEEEE   EEEEE   D     D O         O M  M M  M         ║
║  F       R   R   E       E       D     D  O       O M   M   M         ║
║  F       R    RR EEEEEEE EEEEEEE DDDDDDD   OOOOOOO  M       M         ║
║                                                                      ║
║                          F R E E D O M                               ║
║                                                                      ║
║           Enhanced URL Crawling & Parameter Discovery Engine         ║
║                      Advanced Reconnaissance Tool                    ║
╚══════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# --- Enhanced usage ---
usage() {
    echo -e "${YELLOW}${BOLD}USAGE:${NC}"
    echo -e "  ${GREEN}# From stdin:${NC}"
    echo -e "  cat urls.txt | $0 [OPTIONS]"
    echo -e "  echo 'https://example.com' | $0 [OPTIONS]"
    echo -e "  subfinder -d example.com | $0 [OPTIONS]"
    echo -e ""
    echo -e "  ${GREEN}# Direct input:${NC}"
    echo -e "  $0 -u https://example.com [OPTIONS]"
    echo -e "  $0 -f urls.txt [OPTIONS]"
    echo -e ""
    echo -e "${YELLOW}${BOLD}OPTIONS:${NC}"
    echo -e "  ${CYAN}-u, --url${NC}           Single URL target"
    echo -e "  ${CYAN}-f, --file${NC}          File containing URLs (one per line)"
    echo -e "  ${CYAN}-o, --output${NC}        Output directory (default: crawl_TIMESTAMP)"
    echo -e "  ${CYAN}-t, --threads${NC}       Number of threads (default: 30) - NOTE: JS analysis is now sequential."
    echo -e "  ${CYAN}-d, --depth${NC}         Crawling depth (default: 4)"
    echo -e "  ${CYAN}-r, --rate${NC}          Rate limit per second (default: 100)"
    echo -e "  ${CYAN}-T, --timeout${NC}       Request timeout (default: 10)"
    echo -e "  ${CYAN}-w, --wordlist${NC}      Custom parameter wordlist (used by Arjun/ParamSpider if they support it)"
    echo -e "  ${CYAN}-H, --header${NC}        Custom headers (e.g., 'Auth: Bearer token')"
    echo -e "  ${CYAN}-A, --user-agent${NC}    Custom User-Agent string"
    echo -e ""
    echo -e "  ${CYAN}--aggressive${NC}        Maximum crawling intensity"
    echo -e "  ${CYAN}--js-deep${NC}           Deep JavaScript analysis (default: $JS_ANALYSIS)"
    echo -e "  ${CYAN}--param-fuzz${NC}        Fuzz discovered parameters with payloads"
    echo -e "  ${CYAN}--extract-secrets${NC}   Extract API keys, tokens, credentials (default: $EXTRACT_SECRETS)"
    echo -e "  ${CYAN}--no-validate${NC}       Skip URL validation (faster)"
    echo -e "  ${CYAN}--include-static${NC}    Include static files (css,js,images)"
    echo -e "  ${CYAN}--silent${NC}            Minimal output mode"
    echo -e "  ${CYAN}--debug${NC}             Debug mode with verbose logging"
    echo -e ""
    echo -e "${YELLOW}${BOLD}EXAMPLES:${NC}"
    echo -e "  ${DIM}# Pipe from subdomain enumeration${NC}"
    echo -e "  subfinder -d example.com | $0 --aggressive --js-deep"
    echo -e ""
    echo -e "  ${DIM}# Comprehensive scan with parameter fuzzing${NC}"
    echo -e "  echo 'https://example.com' | $0 -d 5 --param-fuzz --extract-secrets"
    echo -e ""
    echo -e "  ${DIM}# Fast scan from URL list${NC}"
    echo -e "  cat targets.txt | $0 --no-validate --silent -o quick_scan"
    exit 1
}

# --- Argument Parsing ---
parse_args() {
    while [[ $# -gt 0 ]]; do
        key="$1"
        case $key in
            -u|--url) URL="$2"; shift; shift ;;
            -f|--file) FILE="$2"; shift; shift ;;
            -o|--output) OUTPUT_DIR="$2"; shift; shift ;;
            -t|--threads) THREADS="$2"; shift; shift ;;
            -d|--depth) DEPTH="$2"; shift; shift ;;
            -r|--rate) RATE_LIMIT="$2"; shift; shift ;;
            -T|--timeout) TIMEOUT="$2"; shift; shift ;;
            -w|--wordlist) WORDLIST="$2"; shift; shift ;; # Note: WORDLIST global var is for Arjun/ParamSpider, FFUF uses its own derived list
            -H|--header) CUSTOM_HEADERS="$2"; shift; shift ;;
            -A|--user-agent) USER_AGENT="$2"; shift; shift ;;
            --aggressive) AGGRESSIVE=true; shift ;;
            --js-deep) JS_ANALYSIS=true; shift ;;
            --param-fuzz) FUZZ_PARAMS=true; shift ;;
            --extract-secrets) EXTRACT_SECRETS=true; shift ;;
            --no-validate) VALIDATE_URLS=false; shift ;;
            --include-static) FILTER_EXTENSIONS=false; shift ;;
            --silent) SILENT=true; shift ;;
            --debug) DEBUG=true; shift ;;
            -h|--help) usage ;;
            *) log "ERROR" "Unknown option: $1"; usage ;;
        esac
    done
}

# --- Advanced tool checking with version validation ---
check_tools() {
    local required_tools=("curl" "grep" "sort" "mktemp" "unfurl" "gau" "waybackurls" "katana" "httpx" "anew" "awk" "basename" "tr" "date" "wc" "head" "sed" "python3")
    local optional_tools=("paramspider" "arjun" "nuclei" "ffuf" "hakrawler" "getJS" "secretfinder" "jq" "npm" "js-beautify")
    local missing_required=()
    local missing_optional=()

    log "INFO" "Checking required and optional tools..."

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_required+=("$tool")
        fi
    done

    for tool in "${optional_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_optional+=("$tool")
        fi
    done

    if [ ${#missing_required[@]} -ne 0 ]; then
        log "ERROR" "Missing required tools: ${missing_required[*]}"
        echo -e "${YELLOW}Please install them.${NC}"
        exit 1
    fi

    if [ ${#missing_optional[@]} -ne 0 ]; then
        log "WARNING" "Optional tools not found: ${missing_optional[*]}"
        log "INFO" "Some features will be limited."
    fi

    if command -v npm &> /dev/null && ! command -v js-beautify &> /dev/null; then
        log "WARNING" "'js-beautify' not found. Install with: npm install -g js-beautify"
    fi

    if ( [ "$FUZZ_PARAMS" = true ] || [ "$PARAM_BRUTEFORCE" = true ] ) && ! command -v jq &> /dev/null; then
         log "WARNING" "'jq' is not found, needed for parsing JSON."
    fi
    
    if ! grep -P 'a' <<< 'a' &> /dev/null; then
        log "WARNING" "Your grep version might not support -P (Perl Regex). Some JS analysis might be less effective."
    fi

    if [ -n "$SECRETFINDER_PY_PATH" ]; then
        if [ -f "$SECRETFINDER_PY_PATH" ] && [ -x "$SECRETFINDER_PY_PATH" ]; then
            log "SUCCESS" "SecretFinder.py found and executable at: $SECRETFINDER_PY_PATH"
        elif [ -f "$SECRETFINDER_PY_PATH" ]; then
            log "WARNING" "SecretFinder.py found, but NOT executable: $SECRETFINDER_PY_PATH"
            log "WARNING" "Please run: chmod +x $SECRETFINDER_PY_PATH"
            SECRETFINDER_PY_PATH="" 
        else
            log "WARNING" "SecretFinder.py path set, but NOT found: $SECRETFINDER_PY_PATH"
            log "WARNING" "Please check the SECRETFINDER_PY_PATH variable in the script."
            SECRETFINDER_PY_PATH="" 
        fi
    else
        log "INFO" "SECRETFINDER_PY_PATH not set. Skipping SecretFinder integration."
    fi

    log "SUCCESS" "Tool validation completed."
}

# --- Input processing - handles stdin, file, or single URL ---
process_input() {
    local input_urls="$TEMP_DIR/input_urls.txt"

    if [ -n "$URL" ]; then
        echo "$URL" > "$input_urls"
        log "INFO" "Processing single URL: $URL"
    elif [ -n "$FILE" ]; then
        if [ -f "$FILE" ]; then
            cat "$FILE" > "$input_urls"
            log "INFO" "Processing URLs from file: $FILE"
        else
            log "ERROR" "File not found: $FILE"
            exit 1
        fi
    else
        if [ -t 0 ]; then
            log "ERROR" "No input provided. Use -u URL, -f FILE, or pipe URLs to stdin."
            usage
        else
            cat > "$input_urls"
            log "INFO" "Processing URLs from stdin."
        fi
    fi

    local valid_urls="$TEMP_DIR/valid_urls.txt"
    while read -r url; do
        url=$(echo "$url" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        if [[ -n "$url" && "$url" =~ ^https?:// ]]; then
            echo "$url"
        elif [[ -n "$url" && ! "$url" =~ ^# ]]; then
            if [[ "$url" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,} ]]; then
                log "DEBUG" "Adding 'https://' to: $url"
                echo "https://$url"
            else
                log "WARNING" "Skipping potentially invalid URL: $url"
            fi
        fi
    done < "$input_urls" | sort -u > "$valid_urls"

    local url_count=$(wc -l < "$valid_urls" 2>/dev/null || echo 0)
    if [ "$url_count" -eq 0 ]; then
        log "ERROR" "No valid URLs found in input."
        exit 1
    fi

    log "SUCCESS" "Processed $url_count valid URLs."
    echo "$valid_urls"
}

# --- Setup enhanced directory structure ---
setup_directories() {
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    [ -z "$OUTPUT_DIR" ] && OUTPUT_DIR="crawl_$timestamp"

    mkdir -p "$OUTPUT_DIR"/{raw,processed,parameters,javascript,secrets,reports,wordlists,fuzzing}
    mkdir -p "$OUTPUT_DIR/raw"/{gau,wayback,katana,hakrawler}
    mkdir -p "$OUTPUT_DIR/processed"/{alive,filtered,categorized,responses}
    mkdir -p "$OUTPUT_DIR/javascript"/{files,endpoints,secrets,comments,beautified}
    mkdir -p "$OUTPUT_DIR/parameters"/{discovered,bruteforced,fuzzed}

    log "SUCCESS" "Output directory created: $OUTPUT_DIR"
    log "INFO" "Logs will be stored in: $OUTPUT_DIR/crawl.log"
}

# --- Enhanced passive URL collection with multiple sources ---
enhanced_passive_collection() {
    local input_file=$1
    log "INFO" "Starting enhanced passive URL collection..."
    local passive_combined="$OUTPUT_DIR/raw/passive_combined.txt"

    log "INFO" "Collecting from GAU..."
    cat "$input_file" | unfurl domains | sort -u | gau -providers wayback,commoncrawl,otx,urlscan,alienvault -t $THREADS 2>/dev/null | anew "$passive_combined" > /dev/null &

    log "INFO" "Collecting from Wayback Machine..."
    cat "$input_file" | unfurl domains | sort -u | waybackurls 2>/dev/null | anew "$passive_combined" > /dev/null &

    if command -v hakrawler &> /dev/null; then
        log "INFO" "Collecting with hakrawler..."
        cat "$input_file" | hakrawler -depth 2 -plain -t $THREADS 2>/dev/null | anew "$passive_combined" > /dev/null &
    fi

    wait
    local passive_count=$(wc -l < "$passive_combined" 2>/dev/null || echo "0")
    log "SUCCESS" "Passive collection found $passive_count URLs."
    if [ "$SILENT" = false ] && [ "$passive_count" -gt 0 ]; then
        log "INFO" "Passive Sample (first 10):"
        head -10 "$passive_combined" | sed 's/^/    /'
    fi
}

# --- Advanced active crawling with multiple engines ---
enhanced_active_crawling() {
    local input_file=$1
    log "INFO" "Starting enhanced active crawling with Katana..."
    local katana_output="$OUTPUT_DIR/raw/katana/all.txt"

    if [ ! -f "$input_file" ]; then
        log "ERROR" "Input file $input_file not found for Katana. Likely interrupted. Skipping active crawl."
        return
    fi

    local katana_opts="-d $DEPTH -c $THREADS -rl $RATE_LIMIT -timeout $TIMEOUT"
    katana_opts="$katana_opts -H 'User-Agent: $USER_AGENT'"
    katana_opts="$katana_opts -silent"

    if [ "$AGGRESSIVE" = true ]; then
        log "INFO" "Using aggressive Katana options."
        katana_opts="$katana_opts -jc -aff -kf all -fx"
    else
        katana_opts="$katana_opts -jc"
    fi

    if [ "$FILTER_EXTENSIONS" = true ] && [ "$AGGRESSIVE" = false ]; then
        katana_opts="$katana_opts -ef css,png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico,mp4,mp3,avi,pdf,doc,zip"
    else
        log "INFO" "Including static files in crawl."
    fi

    if [ -n "$CUSTOM_HEADERS" ]; then
        katana_opts="$katana_opts -H '$CUSTOM_HEADERS'"
    fi

    log "DEBUG" "Katana options: $katana_opts"
    cat "$input_file" | katana $katana_opts 2>/dev/null | anew "$katana_output" > /dev/null

    local katana_count=$(wc -l < "$katana_output" 2>/dev/null || echo "0")
    log "SUCCESS" "Active crawling found $katana_count URLs."
    if [ "$SILENT" = false ] && [ "$katana_count" -gt 0 ]; then
        log "INFO" "Active Sample (first 10):"
        head -10 "$katana_output" | sed 's/^/    /'
    elif [ "$SILENT" = false ] && [ "$katana_count" -eq 0 ]; then
        log "WARNING" "Katana found 0 URLs. Check input or target."
    fi
}

# --- Helper function to check for obfuscation ---
check_obfuscation() {
    local js_file=$1
    local is_obfuscated=false
    local long_line_threshold=2000
    local func_count_threshold=5

    local func_count=$(grep -cE '(eval\(|atob\(|String\.fromCharCode|document\.write\(|unescape\()' "$js_file" 2>/dev/null || echo 0)
    local long_lines=$(awk -v t="$long_line_threshold" 'length > t {c++} END {print c+0}' "$js_file" 2>/dev/null || echo 0)
    local escape_count=$(grep -oE '(\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})' "$js_file" | wc -l 2>/dev/null || echo 0)

    if [ "$long_lines" -gt 0 ] || [ "$func_count" -gt "$func_count_threshold" ] || [ "$escape_count" -gt 100 ]; then
        is_obfuscated=true
        log "DEBUG" "Obfuscation check ($js_file): Funcs: $func_count, LongLines: $long_lines, Escapes: $escape_count"
    fi

    echo "$is_obfuscated"
}

# --- Deep JavaScript analysis (SEQUENTIAL VERSION) ---
deep_javascript_analysis() {
    if [ "$JS_ANALYSIS" = false ]; then
        log "INFO" "Skipping JavaScript analysis."
        return
    fi
    log "INFO" "Starting deep JavaScript analysis..."

    local all_js_files="$OUTPUT_DIR/javascript/files/all_js.txt"
    cat "$OUTPUT_DIR/raw"/*.txt "$OUTPUT_DIR/raw"/*/*.txt "$OUTPUT_DIR/javascript/endpoints/full_urls.txt" 2>/dev/null | \
        grep -iE '\.js(\?|$|#)' | sort -u > "$all_js_files"

    local js_count=$(wc -l < "$all_js_files" 2>/dev/null || echo "0")
    if [ "$js_count" -eq 0 ]; then
        log "WARNING" "No JavaScript files found to analyze."
        return
    fi

    log "WARNING" "Analyzing $js_count JavaScript files (SEQUENTIALLY - this may be slow)..."

    local extracted_endpoints="$OUTPUT_DIR/javascript/endpoints/extracted.txt"
    local extracted_secrets_grep="$OUTPUT_DIR/javascript/secrets/extracted_grep.txt"
    local extracted_comments="$OUTPUT_DIR/javascript/comments/all.txt"
    local obfuscated_js_list="$OUTPUT_DIR/javascript/obfuscated_js.txt"
    local secretfinder_output="$OUTPUT_DIR/secrets/secretfinder_all.txt"
    touch "$secretfinder_output" 
    touch "$extracted_secrets_grep"

    local count=0
    while read -r js_url; do
        [ -z "$js_url" ] && continue
        
        count=$((count+1))
        log "DEBUG" "Processing JS ($count/$js_count): $js_url"
        
        local js_basename=$(echo "$js_url" | tr "/:?&=" "_")
        local js_file="$TEMP_DIR/${js_basename}.js"

        curl -s -L -A "$USER_AGENT" --max-time $TIMEOUT "$js_url" -o "$js_file" 2>/dev/null

        if [ -s "$js_file" ]; then
            local is_obf=$(check_obfuscation "$js_file")
            if [ "$is_obf" = true ]; then
                log "WARNING" "Potential obfuscation detected: $js_url"
                echo "$js_url" >> "$obfuscated_js_list"
                if command -v js-beautify &> /dev/null; then
                    log "INFO" "Attempting to beautify: $js_url"
                    js-beautify -r "$js_file" -o "$OUTPUT_DIR/javascript/beautified/${js_basename}_beautified.js" 2>/dev/null
                fi
            fi

            grep -oP "['\"](/?[a-zA-Z0-9_./-]+)['\"]" "$js_file" | sed -e 's/^["'\'']//' -e 's/["'\'']$//' | grep -E "^/" >> "$extracted_endpoints"
            grep -oP "https?://[a-zA-Z0-9\.\-]+[a-zA-Z0-9\.\-\/\?\&\=]*" "$js_file" >> "$extracted_endpoints"

            if [ "$EXTRACT_COMMENTS" = true ]; then
                grep -oP "(//.*|/\*.*?\*/)" "$js_file" >> "$extracted_comments"
            fi

            if [ "$EXTRACT_SECRETS" = true ]; then
                grep -Eio "(api_key|apikey|secret|token|password|auth|aws_access_key_id|aws_secret_access_key|AKIA[0-9A-Z]{16}|AIza[0-Za-z\-_]{35}|eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)" "$js_file" >> "$extracted_secrets_grep"
                
                if [ -n "$SECRETFINDER_PY_PATH" ] && [ -f "$SECRETFINDER_PY_PATH" ] && [ -x "$SECRETFINDER_PY_PATH" ]; then
                     log "DEBUG" "Running SecretFinder on: $js_url"
                     python3 "$SECRETFINDER_PY_PATH" -i "$js_url" -o cli 2>/dev/null | grep -vE "^\[!\]|^\[INFO\]|^\[DEBU\]|Processing URL|Found [0-9]+ Javascript files|Checking:|Found results in" | sed '/^\s*$/d' >> "$secretfinder_output"
                fi
            fi
        else
            log "WARNING" "Failed to download or empty file: $js_url"
        fi
        
        rm -f "$js_file"

    done < "$all_js_files"

    if [ -s "$extracted_endpoints" ]; then
        local first_url=$(head -1 "$TEMP_DIR/valid_urls.txt" 2>/dev/null || echo "https://example.com")
        local domain=$(echo "$first_url" | unfurl domains)
        local scheme=$(echo "$first_url" | unfurl scheme)
        local base_url="${scheme}://${domain}"

        cat "$extracted_endpoints" | sort -u | while read -r endpoint; do
             if [[ "$endpoint" =~ ^/ ]]; then
                echo "${base_url}${endpoint}"
            elif [[ "$endpoint" =~ ^\./ ]]; then
                echo "${base_url}/${endpoint#./}"
            elif [[ "$endpoint" =~ ^https?:// ]]; then
                echo "$endpoint"
            fi
        done | sort -u > "$OUTPUT_DIR/javascript/endpoints/full_urls.txt"
    fi

    local endpoints_count=$(wc -l < "$OUTPUT_DIR/javascript/endpoints/full_urls.txt" 2>/dev/null || echo "0")
    local secrets_grep_count=$(wc -l < "$extracted_secrets_grep" 2>/dev/null || echo "0")
    local obfuscated_count=$(wc -l < "$obfuscated_js_list" 2>/dev/null || echo "0")
    log "SUCCESS" "JS Analysis: $endpoints_count endpoints, $secrets_grep_count secrets (grep), $obfuscated_count potentially obfuscated JS."
    if [ "$SILENT" = false ] && [ "$endpoints_count" -gt 0 ]; then
        log "INFO" "JS Endpoints Sample (first 10):"
        head -10 "$OUTPUT_DIR/javascript/endpoints/full_urls.txt" | sed 's/^/    /'
    fi
}

# --- Enhanced parameter discovery with multiple techniques ---
enhanced_parameter_discovery() {
    log "INFO" "Starting enhanced parameter discovery..."
    local all_urls="$OUTPUT_DIR/processed/all_urls.txt"
    local all_params="$OUTPUT_DIR/parameters/all_parameters.txt"

    cat "$OUTPUT_DIR/raw"/*.txt "$OUTPUT_DIR/raw"/*/*.txt "$OUTPUT_DIR/javascript/endpoints/full_urls.txt" 2>/dev/null | \
        sort -u > "$all_urls"

    cat "$all_urls" | grep "?" | unfurl keys | sort -u > "$OUTPUT_DIR/parameters/discovered/unique_params.txt"

    if command -v paramspider &> /dev/null; then
        log "INFO" "Running ParamSpider..."
        cat "$all_urls" | unfurl domains | sort -u | while read -r domain; do
             paramspider -d "$domain" --exclude png,jpg,css,js -l high -o "$OUTPUT_DIR/parameters/discovered/paramspider_$domain.txt" 2>/dev/null &
        done
        wait
        cat "$OUTPUT_DIR/parameters/discovered"/paramspider_*.txt 2>/dev/null | grep "?" | unfurl keys | sort -u >> "$OUTPUT_DIR/parameters/discovered/unique_params.txt"
    fi

    if [ "$PARAM_BRUTEFORCE" = true ] && command -v arjun &> /dev/null; then
        log "INFO" "Running Arjun parameter bruteforcing..."
        local arjun_input="$TEMP_DIR/arjun_input.txt"
        cat "$all_urls" | unfurl format %s://%d%p | sort -u | head -50 > "$arjun_input" # Use fewer URLs for Arjun if it's too slow
        arjun -i "$arjun_input" -t $THREADS --quiet -oJ "$OUTPUT_DIR/parameters/bruteforced/arjun_results.json" 2>/dev/null
        if [ -f "$OUTPUT_DIR/parameters/bruteforced/arjun_results.json" ] && command -v jq &> /dev/null; then
            jq -r '.[].params | keys[]?' "$OUTPUT_DIR/parameters/bruteforced/arjun_results.json" 2>/dev/null | sort -u >> "$OUTPUT_DIR/parameters/discovered/unique_params.txt"
        fi
    fi

    # Parameter fuzzing if enabled and ffuf is available
    if [ "$FUZZ_PARAMS" = true ] && command -v ffuf &> /dev/null; then
        log "INFO" "Starting parameter fuzzing..."
        local fuzz_param_names_wordlist="$OUTPUT_DIR/wordlists/fuzz_param_names.txt" 
        local fuzz_target_urls_file="$TEMP_DIR/ffuf_target_urls.txt" 

        {
            cat "$OUTPUT_DIR/parameters/discovered/unique_params.txt" 2>/dev/null
            echo -e "id\nuser\nfile\npath\ndata\ncmd\naction\npage\nview\ncat\ndir\nshow\nedit\ndel\ndelete\nurl\nredirect\nnext\nparam\ninput\nquery\nname\nsearch\nkeyword\ntest"
        } | sort -u > "$fuzz_param_names_wordlist"

        cat "$all_urls" | unfurl format %s://%d%p | sort -u | head -20 > "$fuzz_target_urls_file"

        local num_base_urls=$(wc -l < "$fuzz_target_urls_file" | awk '{print $1}')
        local num_param_names=$(wc -l < "$fuzz_param_names_wordlist" | awk '{print $1}')

        if [ "$num_base_urls" -gt 0 ] && [ "$num_param_names" -gt 0 ]; then
            log "INFO" "Fuzzing $num_base_urls base URLs with $num_param_names parameter names (using 'test' as value)..."
            
            ffuf -u "TARGET_URL?PARAM_NAME=test" \
                 -w "$fuzz_target_urls_file:TARGET_URL" \
                 -w "$fuzz_param_names_wordlist:PARAM_NAME" \
                 -mc 200,301,302,403,401,500 -ac -t $THREADS -timeout $TIMEOUT \
                 -o "$OUTPUT_DIR/parameters/fuzzed/ffuf_results.json" \
                 -of json -s 2>/dev/null 

            if [ -f "$OUTPUT_DIR/parameters/fuzzed/ffuf_results.json" ] && command -v jq &> /dev/null; then
                 jq -r '.results[] | .input.PARAM_NAME' "$OUTPUT_DIR/parameters/fuzzed/ffuf_results.json" 2>/dev/null | sort -u >> "$OUTPUT_DIR/parameters/discovered/unique_params.txt"
            fi
        else
            log "WARNING" "Not enough base URLs or parameter names to fuzz. Skipping ffuf."
        fi
    fi

    sort -u "$OUTPUT_DIR/parameters/discovered/unique_params.txt" > "$all_params"
    local param_count=$(wc -l < "$all_params" 2>/dev/null || echo "0")
    log "SUCCESS" "Parameter discovery: Found $param_count unique parameters."
    if [ "$SILENT" = false ] && [ "$param_count" -gt 0 ]; then
        log "INFO" "Parameters Sample (first 10):"
        head -10 "$all_params" | sed 's/^/    /'
    fi
}

# --- URL validation and categorization ---
validate_and_categorize() {
    log "INFO" "Validating and categorizing URLs..."
    local all_urls="$OUTPUT_DIR/processed/all_urls.txt"
    local validated_urls="$OUTPUT_DIR/processed/alive/validated.txt"

    if [ ! -s "$all_urls" ]; then
        log "WARNING" "No URLs found to validate/categorize."
        return
    fi

    if [ "$VALIDATE_URLS" = true ]; then
        log "INFO" "Running httpx for validation..."
        cat "$all_urls" | httpx_live -silent -mc 200,301,302,401,403,500 -t $THREADS -timeout $TIMEOUT \
            -o "$validated_urls" 2>/dev/null

        local alive_count=$(wc -l < "$validated_urls" 2>/dev/null || echo "0")
        log "SUCCESS" "URL validation: $alive_count alive URLs."
    else
        log "INFO" "Skipping URL validation, using all found URLs."
        cp "$all_urls" "$validated_urls"
    fi

    if [ ! -s "$validated_urls" ]; then
        log "WARNING" "No alive URLs found after validation."
        return
    fi

    log "INFO" "Categorizing alive URLs..."
    local categorized_dir="$OUTPUT_DIR/processed/categorized"
    grep -iE "(api|rest|graphql|soap|json|token|xml)" "$validated_urls" 2>/dev/null > "$categorized_dir/api_endpoints.txt"
    grep -iE "(admin|panel|dashboard|login|auth|config|setup|install|signin|signup)" "$validated_urls" 2>/dev/null > "$categorized_dir/admin_areas.txt"
    grep -iE "(upload|file|attach|document|import|export)" "$validated_urls" 2>/dev/null > "$categorized_dir/upload_endpoints.txt"
    grep -E "\.(php|asp|aspx|jsp|cgi|py|rb|pl|cfm)" "$validated_urls" 2>/dev/null > "$categorized_dir/dynamic_pages.txt"
    grep -E "\?" "$validated_urls" 2>/dev/null > "$categorized_dir/with_params.txt"
    grep -iE "(\.txt|\.log|\.conf|\.cfg|\.ini|\.env|\.bak|\.old|\.zip|\.7z|\.db|\.cache|\.secret|\.config|\.tar|\.gz|\.exe|\.rar|\.xml|\.xhtml|\.code|\.iso|\.dll|@)" "$validated_urls" 2>/dev/null > "$categorized_dir/sensitive_files.txt"

    log "SUCCESS" "URL categorization complete."
}

# --- Response Analysis ---
analyze_http_responses() {
    if [ "$ANALYZE_RESPONSES" = false ]; then
        log "INFO" "Skipping response analysis."
        return
    fi
    log "INFO" "Analyzing HTTP responses..."
    local validated_urls="$OUTPUT_DIR/processed/alive/validated.txt"

    if [ ! -s "$validated_urls" ]; then
        log "WARNING" "No alive URLs to analyze responses from."
        return
    fi

    log "INFO" "Running httpx for response details (status, title, tech)..."
    cat "$validated_urls" | httpx -silent -t $THREADS -timeout $TIMEOUT \
        -sc -title -tech-detect -cl -ct -location -server -cdn \
        -o "$OUTPUT_DIR/processed/responses/httpx_details.txt" 2>/dev/null

    log "SUCCESS" "Response analysis complete. See $OUTPUT_DIR/processed/responses/httpx_details.txt"
}

# --- Generate Summary Report ---
generate_report() {
    log "INFO" "Generating summary report..."
    local report_file="$OUTPUT_DIR/reports/summary.txt"

    echo "==================================================" > "$report_file"
    echo "       Enhanced Crawl & Discovery Report" >> "$report_file"
    echo "                 by 9x-7ydra" >> "$report_file" 
    echo "==================================================" >> "$report_file"
    echo "Date: $(date)" >> "$report_file"
    echo "Output Directory: $OUTPUT_DIR" >> "$report_file"
    echo "--------------------------------------------------" >> "$report_file"
    echo "Settings:" >> "$report_file"
    echo "  Threads: $THREADS (Note: JS Analysis Sequential)" >> "$report_file"
    echo "  Depth: $DEPTH" >> "$report_file"
    echo "  Rate Limit: $RATE_LIMIT" >> "$report_file"
    echo "  Aggressive: $AGGRESSIVE" >> "$report_file"
    echo "  JS Analysis: $JS_ANALYSIS" >> "$report_file"
    echo "  Param Fuzzing: $FUZZ_PARAMS" >> "$report_file"
    echo "--------------------------------------------------" >> "$report_file"
    echo "Counts:" >> "$report_file"
    echo "  Initial Valid URLs: $(wc -l < "$TEMP_DIR/valid_urls.txt" 2>/dev/null || echo 0)" >> "$report_file"
    echo "  Passive URLs: $(wc -l < "$OUTPUT_DIR/raw/passive_combined.txt" 2>/dev/null || echo 0)" >> "$report_file"
    echo "  Active (Katana) URLs: $(wc -l < "$OUTPUT_DIR/raw/katana/all.txt" 2>/dev/null || echo 0)" >> "$report_file"
    echo "  Total URLs (Pre-Validation): $(wc -l < "$OUTPUT_DIR/processed/all_urls.txt" 2>/dev/null || echo 0)" >> "$report_file"
    echo "  Alive URLs: $(wc -l < "$OUTPUT_DIR/processed/alive/validated.txt" 2>/dev/null || echo 0)" >> "$report_file"
    echo "  JS Files Found: $(wc -l < "$OUTPUT_DIR/javascript/files/all_js.txt" 2>/dev/null || echo 0)" >> "$report_file"
    echo "  Potentially Obfuscated JS: $(wc -l < "$OUTPUT_DIR/javascript/obfuscated_js.txt" 2>/dev/null || echo 0)" >> "$report_file"
    echo "  JS Endpoints: $(wc -l < "$OUTPUT_DIR/javascript/endpoints/full_urls.txt" 2>/dev/null || echo 0)" >> "$report_file"
    echo "  Potential Secrets (Grep): $(wc -l < "$OUTPUT_DIR/javascript/secrets/extracted_grep.txt" 2>/dev/null || echo 0)" >> "$report_file"
    echo "  Potential Secrets (SecretFinder): $(grep -c . "$OUTPUT_DIR/secrets/secretfinder_all.txt" 2>/dev/null || echo 0)" >> "$report_file"
    echo "  Unique Parameters: $(wc -l < "$OUTPUT_DIR/parameters/all_parameters.txt" 2>/dev/null || echo 0)" >> "$report_file"
    echo "  API Endpoints: $(wc -l < "$OUTPUT_DIR/processed/categorized/api_endpoints.txt" 2>/dev/null || echo 0)" >> "$report_file"
    echo "  Admin Areas: $(wc -l < "$OUTPUT_DIR/processed/categorized/admin_areas.txt" 2>/dev/null || echo 0)" >> "$report_file"
    echo "--------------------------------------------------" >> "$report_file"
    echo "Key Output Files:" >> "$report_file"
    echo "  - $OUTPUT_DIR/processed/alive/validated.txt (Alive URLs)" >> "$report_file"
    echo "  - $OUTPUT_DIR/parameters/all_parameters.txt (All Parameters)" >> "$report_file"
    echo "  - $OUTPUT_DIR/javascript/endpoints/full_urls.txt (JS Endpoints)" >> "$report_file"
    echo "  - $OUTPUT_DIR/javascript/secrets/extracted_grep.txt (Potential Secrets - Grep)" >> "$report_file"
    echo "  - $OUTPUT_DIR/secrets/secretfinder_all.txt (Potential Secrets - SecretFinder)" >> "$report_file"
    echo "  - $OUTPUT_DIR/javascript/obfuscated_js.txt (Potentially Obfuscated JS URLs)" >> "$report_file"
    echo "  - $OUTPUT_DIR/javascript/beautified/ (Beautified JS Files - if available)" >> "$report_file"
    echo "  - $OUTPUT_DIR/processed/responses/httpx_details.txt (Response Details)" >> "$report_file"
    echo "  - $OUTPUT_DIR/crawl.log (Full Log)" >> "$report_file"
    echo "==================================================" >> "$report_file"

    log "SUCCESS" "Summary report generated: $report_file"
    [ "$SILENT" = false ] && cat "$report_file"
}


# --- Main execution block ---
main() {
    print_banner
    parse_args "$@"

    setup_directories
    check_tools

    local valid_urls_file=$(process_input)
    if [ ! -s "$valid_urls_file" ]; then
        log "ERROR" "No valid URLs to process. Exiting."
        exit 1
    fi

    enhanced_passive_collection "$valid_urls_file"
    enhanced_active_crawling "$valid_urls_file"
    [ "$JS_ANALYSIS" = true ] && deep_javascript_analysis
    enhanced_parameter_discovery
    validate_and_categorize
    [ "$ANALYZE_RESPONSES" = true ] && analyze_http_responses
    generate_report

    log "SUCCESS" "Enhanced URL Crawling & Parameter Discovery finished!"
}

# --- Run main function with all provided arguments ---
main "$@"
