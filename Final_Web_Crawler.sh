#!/bin/bash
# ----------------------------------------------------------------------------------------------------
# Section 1: Configuration and Global Variables
# Defines colors, formatting, and all script-wide variables.
# ----------------------------------------------------------------------------------------------------

# --- Terminal Colors and Text Formatting ---
# These variables hold ANSI escape codes for colored and formatted terminal output.
# They enhance readability and highlight important messages (e.g., errors, successes).
RED='\033[0;31m'    # Red color for errors and critical warnings
GREEN='\033[0;32m'  # Green color for success messages
YELLOW='\033[1;33m' # Yellow color for warnings and important notices
BLUE='\033[0;34m'   # Blue color for informational messages
PURPLE='\033[0;35m' # Purple color for banners and major sections
CYAN='\033[0;36m'   # Cyan color for findings and discovery alerts
BOLD='\033[1m'      # Bold text formatting
DIM='\033[2m'       # Dim (faint) text formatting
NC='\033[0m'        # No Color - Resets text formatting to default

# --- Global Script Variables ---
# These variables control the script's behavior, operational parameters, and file paths.
# They can often be overridden by command-line arguments.

# Temporary directory for intermediate files. Created using `mktemp -d` for uniqueness.
TEMP_DIR="" # Initialized later in setup_directories

# Concurrency settings
THREADS=30          # Default number of parallel threads for tools like httpx, gau, katana.
DEPTH=4             # Default crawling depth for active crawlers (e.g., katana).

# Output management
OUTPUT_DIR=""       # Base output directory. If not specified, a timestamped directory is created.
WORDLIST=""         # Path to a custom wordlist for parameter bruteforcing (Arjun/ParamSpider).

# Toggleable features (true/false flags)
SILENT=false        # If true, minimizes console output, only showing errors and major findings.
AGGRESSIVE=false    # If true, enables more intense crawling/scanning options for tools.
JS_ANALYSIS=true    # If true, performs deep JavaScript analysis.
PARAM_BRUTEFORCE=true # If true, attempts to bruteforce common parameters using Arjun.
EXTRACT_SECRETS=true # If true, tries to extract sensitive information (API keys, tokens).
FILTER_EXTENSIONS=true # If true, static file extensions (css, js, images, etc.) are filtered out during crawling.
VALIDATE_URLS=true  # If true, performs HTTPX validation to check URL liveness.
FUZZ_PARAMS=false   # If true, fuzzes discovered parameters with a basic payload using FFUF.
EXTRACT_COMMENTS=true # If true, extracts comments from JavaScript files.
ANALYZE_RESPONSES=true # If true, performs detailed HTTP response analysis (status, title, tech).
DEBUG=false         # If true, enables verbose debug logging for troubleshooting.

# Request specific settings
RATE_LIMIT=100      # Maximum requests per second for tools supporting it.
TIMEOUT=10          # Request timeout in seconds for HTTP requests.
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36" # Default User-Agent string.
CUSTOM_HEADERS=""   # String to hold custom HTTP headers (e.g., "Authorization: Bearer <token>").

# Input sources
URL=""              # Stores a single URL provided via -u.
FILE=""             # Stores the path to a file containing URLs provided via -f.

# --- IMPORTANT: USER CONFIGURATION REQUIRED ---
# Edit this line to point to your SecretFinder.py script.
# Example: SECRETFINDER_PY_PATH="/opt/tools/SecretFinder/SecretFinder.py"
SECRETFINDER_PY_PATH="/home/yehia/Bug_Hunting/Tools/SecretFinder/SecretFinder.py"
# ----------------------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------------------
# Section 2: Logging and Utility Functions
# Defines the core logging mechanism and cleanup procedures.
# ----------------------------------------------------------------------------------------------------

# Function: log()
# Description: Enhanced logging function with support for different log levels, timestamps,
#              and optional writing to a log file within the output directory.
# Arguments:
#   $1: Log level (e.g., "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "FINDING")
#   $2: Message to log
log() {
    # Validate input parameters for robustness
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo -e "${RED}[ERROR] log(): Both level and message arguments are required.${NC}" >&2
        return 1 # Indicate failure
    fi

    local level="$1"
    local message="$2"
    local timestamp=$(date '+%H:%M:%S') # Current time for the log entry
    local log_file="$OUTPUT_DIR/crawl.log" # Path to the main log file

    # Use a case statement to apply specific colors and prefixes based on the log level.
    # Also, controls whether the message is printed to stderr based on SILENT and DEBUG flags.
    case "$level" in
        "DEBUG")
            # Debug messages are only printed if the DEBUG flag is set to true.
            [ "$DEBUG" = true ] && echo -e "${DIM}[${timestamp}] [DBG] ${message}${NC}" >&2
            ;;
        "INFO")
            # Info messages are printed unless the SILENT flag is true.
            [ "$SILENT" = false ] && echo -e "${BLUE}[${timestamp}] [INF] ${message}${NC}" >&2
            ;;
        "SUCCESS")
            # Success messages are printed unless the SILENT flag is true.
            [ "$SILENT" = false ] && echo -e "${GREEN}[${timestamp}] [OK ] ${message}${NC}" >&2
            ;;
        "WARNING")
            # Warning messages are printed unless the SILENT flag is true.
            [ "$SILENT" = false ] && echo -e "${YELLOW}[${timestamp}] [WRN] ${message}${NC}" >&2
            ;;
        "ERROR")
            # Error messages are always printed to ensure critical issues are not missed.
            echo -e "${RED}[${timestamp}] [ERR] ${message}${NC}" >&2
            ;;
        "FINDING")
            # "Finding" messages are for significant discoveries, printed unless silent.
            [ "$SILENT" = false ] && echo -e "${CYAN}[${timestamp}] [🔍 ] ${message}${NC}" >&2
            ;;
        *)
            # Fallback for unrecognized log levels, defaults to a basic INFO style.
            log "WARNING" "log(): Unrecognized log level '$level'. Defaulting to INFO."
            [ "$SILENT" = false ] && echo -e "${BLUE}[${timestamp}] [???] ${message}${NC}" >&2
            ;;
    esac

    # Attempt to append the log message to the log file.
    # Redirects stderr to /dev/null to suppress "No such file or directory" errors
    # if OUTPUT_DIR is not yet set or created.
    if [ -n "$OUTPUT_DIR" ]; then
        echo "[${timestamp}] [${level}] ${message}" >> "$log_file" 2>/dev/null
        # Check if the write operation failed and log a warning if debug is on
        if [ $? -ne 0 ] && [ "$DEBUG" = true ]; then
            echo -e "${DIM}DEBUG: Failed to write to log file: $log_file${NC}" >&2
        fi
    else
        [ "$DEBUG" = true ] && echo -e "${DIM}DEBUG: OUTPUT_DIR not set, skipping log file write.${NC}" >&2
    fi

    return 0 # Indicate success
}

# Function: cleanup()
# Description: Removes the temporary directory and its contents upon script exit or interruption.
#              This ensures no residual files are left on the system.
cleanup() {
    log "INFO" "Initiating cleanup sequence..."

    # Check if TEMP_DIR is set and actually exists to prevent errors.
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        log "DEBUG" "Attempting to remove temporary directory: $TEMP_DIR"
        rm -rf "$TEMP_DIR"
        local rm_status=$?
        if [ $rm_status -eq 0 ]; then
            log "SUCCESS" "Temporary files cleaned up successfully from $TEMP_DIR."
        else
            log "ERROR" "Failed to remove temporary directory: $TEMP_DIR (Exit Code: $rm_status)."
            log "ERROR" "You might need to manually remove: $TEMP_DIR"
        fi
    else
        log "INFO" "No temporary directory to clean up or TEMP_DIR not found/set."
    fi

    log "INFO" "Cleanup sequence completed."
}

# Trap for cleanup on exit, interruption (Ctrl+C), or termination signals.
# This ensures cleanup is always attempted, even if the script crashes or is stopped.
trap cleanup EXIT INT TERM

# ----------------------------------------------------------------------------------------------------
# Section 3: User Interface and Help
# Functions for displaying banners and usage instructions.
# ----------------------------------------------------------------------------------------------------

# Function: print_banner()
# Description: Displays an ASCII art banner for the tool.
print_banner() {
    log "DEBUG" "Displaying script banner."
    # Use PURPLE and BOLD for the banner text for visual emphasis.
    echo -e "${PURPLE}${BOLD}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════╗
║                                                                        ║
║  FFFFFFF RRRRRRR EEEEEEE EEEEEEE DDDDDDD  OOOOOOO  MMMMMMM             ║
║  F       R     R E       E       D     D O       O M M M M M         ║
║  FFFFF   RRRRRRR EEEEE   EEEEE   D     D O         O M  M M  M         ║
║  F       R   R   E       E       D     D  O       O M   M   M         ║
║  F       R    RR EEEEEEE EEEEEEE DDDDDDD   OOOOOOO  M       M         ║
║                                                                        ║
║                      F R E E D O M                                     ║
║                                                                        ║
║            Enhanced URL Crawling & Parameter Discovery Engine          ║
║                    Advanced Reconnaissance Tool                        ║
╚══════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}" # Reset color and formatting after the banner.
    log "DEBUG" "Banner display complete."
}

# Function: usage()
# Description: Prints detailed usage instructions and examples for the script.
#              Exits the script after displaying.
usage() {
    log "INFO" "Displaying usage information."
    echo -e "${YELLOW}${BOLD}USAGE:${NC}"
    echo -e "  This tool supports multiple input methods:"
    echo -e "  ${GREEN}# 1. From stdin (pipe):${NC}"
    echo -e "  cat urls.txt | $0 [OPTIONS]"
    echo -e "  echo 'https://example.com' | $0 [OPTIONS]"
    echo -e "  subfinder -d example.com | $0 [OPTIONS]"
    echo -e "  ${DIM}  (This is ideal for integrating with other CLI tools.)${NC}"
    echo -e ""
    echo -e "  ${GREEN}# 2. Direct input (file or single URL):${NC}"
    echo -e "  $0 -u https://example.com [OPTIONS]"
    echo -e "  $0 -f urls.txt [OPTIONS]"
    echo -e "  ${DIM}  (Useful for standalone operations.)${NC}"
    echo -e ""
    echo -e "${YELLOW}${BOLD}OPTIONS:${NC}"
    echo -e "  ${CYAN}-u, --url${NC}          Specifies a single target URL for analysis."
    echo -e "  ${CYAN}-f, --file${NC}         Provides a path to a file containing a list of URLs, one per line."
    echo -e "  ${CYAN}-o, --output${NC}       Sets the base output directory for all generated files."
    echo -e "                        (Default: 'crawl_TIMESTAMP' e.g., 'crawl_20231027_143000')"
    echo -e "  ${CYAN}-t, --threads${NC}      Determines the number of concurrent threads/workers for supported tools."
    echo -e "                        (Default: $THREADS) - ${YELLOW}NOTE: JS analysis is now sequential for stability.${NC}"
    echo -e "  ${CYAN}-d, --depth${NC}        Defines the maximum crawling depth for active crawlers (e.g., Katana)."
    echo -e "                        (Default: $DEPTH)"
    echo -e "  ${CYAN}-r, --rate${NC}         Sets a rate limit (requests per second) for HTTP-based tools."
    echo -e "                        (Default: $RATE_LIMIT)"
    echo -e "  ${CYAN}-T, --timeout${NC}      Configures the maximum wait time (in seconds) for HTTP requests to complete."
    echo -e "                        (Default: $TIMEOUT)"
    echo -e "  ${CYAN}-w, --wordlist${NC}     Provides a custom wordlist file primarily for parameter bruteforcing."
    echo -e "                        (Used by Arjun/ParamSpider if they support external lists. FFUF uses its own derived list.)"
    echo -e "  ${CYAN}-H, --header${NC}       Allows adding custom HTTP headers to outgoing requests."
    echo -e "                        (Format: 'Header-Name: Value'. Use single quotes to encapsulate.)"
    echo -e "                        (Example: '-H \"Authorization: Bearer mytoken123\"')"
    echo -e "  ${CYAN}-A, --user-agent${NC}   Sets a custom User-Agent string for all HTTP requests."
    echo -e "                        (Default: '${USER_AGENT}')"
    echo -e ""
    echo -e "  ${YELLOW}${BOLD}BEHAVIOR MODIFIERS:${NC}"
    echo -e "  ${CYAN}--aggressive${NC}      Activates a more intense and comprehensive crawling/scanning approach."
    echo -e "                        This may increase scan time and resource usage."
    echo -e "  ${CYAN}--js-deep${NC}         Enables deep analysis of discovered JavaScript files for endpoints, comments, and secrets."
    echo -e "                        (Default: $JS_ANALYSIS - enabled)"
    echo -e "  ${CYAN}--param-fuzz${NC}      Initiates fuzzing of discovered URL parameters with common payloads to test for vulnerabilities."
    echo -e "                        (Requires 'ffuf' to be installed.)"
    echo -e "  ${CYAN}--extract-secrets${NC} Performs active extraction of potential API keys, tokens, and other sensitive credentials."
    echo -e "                        (Default: $EXTRACT_SECRETS - enabled. Requires 'SecretFinder.py' path to be configured.)"
    echo -e "  ${CYAN}--no-validate${NC}     Skips the initial URL validation step using 'httpx'."
    echo -e "                        This can speed up execution but may lead to analysis of dead/unresponsive URLs."
    echo -e "  ${CYAN}--include-static${NC}  Modifies crawling behavior to include static file extensions (e.g., .css, .js, .png)."
    echo -e "                        By default, these are filtered out to focus on dynamic content."
    echo -e "  ${CYAN}--silent${NC}          Reduces console output to a minimum, primarily showing errors and significant findings."
    echo -e "  ${CYAN}--debug${NC}           Enables verbose debug logging, displaying detailed internal process information."
    echo -e ""
    echo -e "${YELLOW}${BOLD}EXAMPLES:${NC}"
    echo -e "  ${DIM}# Example 1: Pipe output from a subdomain enumeration tool for a comprehensive scan${NC}"
    echo -e "  subfinder -d example.com | $0 --aggressive --js-deep --extract-secrets -o my_example_recon"
    echo -e "  ${DIM}  This command will find subdomains of example.com, then feed them into Freedom for an aggressive crawl,"
    echo -e "  ${DIM}  deep JS analysis, secret extraction, and save all results in 'my_example_recon' directory.${NC}"
    echo -e ""
    echo -e "  ${DIM}# Example 2: Perform a focused scan on a single URL with parameter fuzzing and custom headers${NC}"
    echo -e "  $0 -u https://web.example.com/app --param-fuzz -d 5 -t 40 -H 'X-API-Key: secret123' -o app_fuzz_scan"
    echo -e "  ${DIM}  This will crawl the specific app URL, fuzz parameters, go up to 5 levels deep, use 40 threads,"
    echo -e "  ${DIM}  add an API key header, and store results in 'app_fuzz_scan'.${NC}"
    echo -e ""
    echo -e "  ${DIM}# Example 3: Quick validation and categorization from a pre-compiled URL list (silent mode)${NC}"
    echo -e "  cat my_urls_list.txt | $0 --no-validate --silent -o quick_scan_output"
    echo -e "  ${DIM}  This command processes URLs from 'my_urls_list.txt' quickly by skipping validation"
    echo -e "  ${DIM}  and minimizing terminal output, storing results in 'quick_scan_output'.${NC}"
    echo -e ""
    echo -e "${RED}${BOLD}IMPORTANT:${NC} Ensure all required external tools are installed and their paths are correct, especially 'SecretFinder.py'."
    log "INFO" "Usage information displayed. Exiting script."
    exit 1 # Exit with a non-zero status to indicate abnormal termination (help display).
}

# ----------------------------------------------------------------------------------------------------
# Section 4: Argument Parsing
# Handles command-line options and sets global variables accordingly.
# ----------------------------------------------------------------------------------------------------

# Function: parse_args()
# Description: Parses command-line arguments provided to the script.
#              Updates global configuration variables based on user input.
# Arguments:
#   $@: All command-line arguments passed to the script.
parse_args() {
    log "INFO" "Starting argument parsing process."
    # Loop through all arguments until none are left.
    while [[ $# -gt 0 ]]; do
        local key="$1" # Current argument being processed

        log "DEBUG" "Processing argument: $key"
        case "$key" in
            -u|--url)
                # Ensure a value is provided for -u/--url
                if [[ -z "$2" || "$2" =~ ^- ]]; then
                    log "ERROR" "Missing value for $key option."
                    usage
                fi
                URL="$2"
                shift # Consume key
                shift # Consume value
                log "DEBUG" "URL set to: $URL"
                ;;
            -f|--file)
                # Ensure a value is provided for -f/--file
                if [[ -z "$2" || "$2" =~ ^- ]]; then
                    log "ERROR" "Missing value for $key option."
                    usage
                fi
                FILE="$2"
                shift # Consume key
                shift # Consume value
                log "DEBUG" "File path set to: $FILE"
                ;;
            -o|--output)
                # Ensure a value is provided for -o/--output
                if [[ -z "$2" || "$2" =~ ^- ]]; then
                    log "ERROR" "Missing value for $key option."
                    usage
                fi
                OUTPUT_DIR="$2"
                shift # Consume key
                shift # Consume value
                log "DEBUG" "Output directory set to: $OUTPUT_DIR"
                ;;
            -t|--threads)
                # Ensure a numeric value is provided for -t/--threads
                if ! [[ "$2" =~ ^[0-9]+$ ]]; then
                    log "ERROR" "Invalid numeric value for $key: '$2'. Threads must be an integer."
                    usage
                fi
                THREADS="$2"
                shift # Consume key
                shift # Consume value
                log "DEBUG" "Threads set to: $THREADS"
                ;;
            -d|--depth)
                # Ensure a numeric value is provided for -d/--depth
                if ! [[ "$2" =~ ^[0-9]+$ ]]; then
                    log "ERROR" "Invalid numeric value for $key: '$2'. Depth must be an integer."
                    usage
                fi
                DEPTH="$2"
                shift # Consume key
                shift # Consume value
                log "DEBUG" "Depth set to: $DEPTH"
                ;;
            -r|--rate)
                # Ensure a numeric value is provided for -r/--rate
                if ! [[ "$2" =~ ^[0-9]+$ ]]; then
                    log "ERROR" "Invalid numeric value for $key: '$2'. Rate limit must be an integer."
                    usage
                fi
                RATE_LIMIT="$2"
                shift # Consume key
                shift # Consume value
                log "DEBUG" "Rate limit set to: $RATE_LIMIT"
                ;;
            -T|--timeout)
                # Ensure a numeric value is provided for -T/--timeout
                if ! [[ "$2" =~ ^[0-9]+$ ]]; then
                    log "ERROR" "Invalid numeric value for $key: '$2'. Timeout must be an integer."
                    usage
                fi
                TIMEOUT="$2"
                shift # Consume key
                shift # Consume value
                log "DEBUG" "Timeout set to: $TIMEOUT"
                ;;
            -w|--wordlist)
                # Ensure a value is provided for -w/--wordlist
                if [[ -z "$2" || "$2" =~ ^- ]]; then
                    log "ERROR" "Missing value for $key option."
                    usage
                fi
                WORDLIST="$2"
                shift # Consume key
                shift # Consume value
                log "DEBUG" "Wordlist path set to: $WORDLIST"
                ;;
            -H|--header)
                # Ensure a value is provided for -H/--header
                if [[ -z "$2" || "$2" =~ ^- ]]; then
                    log "ERROR" "Missing value for $key option."
                    usage
                fi
                CUSTOM_HEADERS="$2"
                shift # Consume key
                shift # Consume value
                log "DEBUG" "Custom headers set to: '$CUSTOM_HEADERS'"
                ;;
            -A|--user-agent)
                # Ensure a value is provided for -A/--user-agent
                if [[ -z "$2" || "$2" =~ ^- ]]; then
                    log "ERROR" "Missing value for $key option."
                    usage
                fi
                USER_AGENT="$2"
                shift # Consume key
                shift # Consume value
                log "DEBUG" "User-Agent set to: '$USER_AGENT'"
                ;;
            --aggressive)
                AGGRESSIVE=true
                shift # Consume key
                log "DEBUG" "Aggressive mode enabled."
                ;;
            --js-deep)
                JS_ANALYSIS=true
                shift # Consume key
                log "DEBUG" "Deep JavaScript analysis enabled."
                ;;
            --param-fuzz)
                FUZZ_PARAMS=true
                shift # Consume key
                log "DEBUG" "Parameter fuzzing enabled."
                ;;
            --extract-secrets)
                EXTRACT_SECRETS=true
                shift # Consume key
                log "DEBUG" "Secret extraction enabled."
                ;;
            --no-validate)
                VALIDATE_URLS=false
                shift # Consume key
                log "DEBUG" "URL validation disabled."
                ;;
            --include-static)
                FILTER_EXTENSIONS=false
                shift # Consume key
                log "DEBUG" "Inclusion of static files enabled."
                ;;
            --silent)
                SILENT=true
                shift # Consume key
                log "DEBUG" "Silent mode enabled."
                ;;
            --debug)
                DEBUG=true
                shift # Consume key
                log "DEBUG" "Debug mode enabled."
                # If debug is enabled, ensure silent is disabled for full output
                SILENT=false
                ;;
            -h|--help)
                usage
                ;;
            *)
                log "ERROR" "Unrecognized option: $key"
                usage
                ;;
        esac
    done

    # Post-parsing validation: Ensure at least one input method is provided.
    if [[ -z "$URL" && -z "$FILE" && -t 0 ]]; then
        log "ERROR" "No input provided. Please use -u, -f, or pipe URLs via stdin."
        usage
    fi

    log "INFO" "Argument parsing completed successfully."
}

# ----------------------------------------------------------------------------------------------------
# Section 5: Tool Dependency Checking
# Verifies that all necessary external tools are installed and available in PATH.
# ----------------------------------------------------------------------------------------------------

# Function: check_tool_existence()
# Description: Helper function to check if a single command-line tool exists.
# Arguments:
#   $1: The name of the tool to check.
# Returns: 0 if tool exists, 1 otherwise.
check_tool_existence() {
    local tool_name="$1"
    log "DEBUG" "Checking for tool: $tool_name"
    if command -v "$tool_name" &> /dev/null; then
        log "DEBUG" "'$tool_name' found."
        return 0 # Tool found
    else
        log "DEBUG" "'$tool_name' NOT found."
        return 1 # Tool not found
    fi
}

# Function: check_tools()
# Description: Checks for the presence of all required and optional external tools.
#              Logs warnings for missing optional tools and errors for missing required ones.
check_tools() {
    log "INFO" "Initiating external tool dependency check."

    # Define arrays for required and optional tools.
    # Required tools are essential for core script functionality.
    local required_tools=(
        "curl"          # For downloading content (e.g., JS files)
        "grep"          # For pattern matching and extraction
        "sort"          # For sorting unique entries
        "mktemp"        # For creating temporary directories/files
        "unfurl"        # For URL parsing (domains, paths, params)
        "gau"           # Get All URLs (passive collection)
        "waybackurls"   # Wayback Machine URLs (passive collection)
        "katana"        # Active web crawler
        "httpx"         # HTTP client for validation and response analysis
        "anew"          # Appends new lines to a file, preventing duplicates
        "awk"           # Text processing (e.g., for line length checks)
        "basename"      # Extracts base name from path
        "tr"            # Translate or delete characters
        "date"          # For timestamps
        "wc"            # Word Count (for line counts)
        "head"          # Get first N lines of a file
        "sed"           # Stream editor for text transformations
        "python3"       # Python interpreter for tools like SecretFinder.py, ParamSpider, Arjun
    )

    # Optional tools enhance functionality but are not strictly necessary for the script to run.
    local optional_tools=(
        "paramspider"   # Python tool for parameter discovery
        "arjun"         # Python tool for HTTP parameter discovery/bruteforce
        "nuclei"        # Fast and customizable vulnerability scanner (not used in current logic, but often useful)
        "ffuf"          # Fast web fuzzer (used for parameter fuzzing)
        "hakrawler"     # Go-based web crawler (additional passive source)
        "getJS"         # Another JS endpoint extractor (not used in current logic, but good to know)
        "secretfinder"  # Python tool for finding secrets in JS/HTML (used via direct path to .py)
        "jq"            # JSON processor (needed for parsing Arjun/FFUF JSON output)
        "npm"           # Node Package Manager (for js-beautify)
        "js-beautify"   # JavaScript code formatter (for obfuscated JS)
    )

    local missing_required=() # Array to store missing required tools
    local missing_optional=() # Array to store missing optional tools

    log "INFO" "Verifying presence of core required tools..."
    # Iterate through required tools and check for their existence.
    for tool in "${required_tools[@]}"; do
        if ! check_tool_existence "$tool"; then
            missing_required+=("$tool")
        fi
    done

    # Report on missing required tools. If any are missing, the script cannot proceed.
    if [ ${#missing_required[@]} -ne 0 ]; then
        log "ERROR" "Critical tools are missing. Please install the following: ${missing_required[*]}"
        echo -e "${YELLOW}Refer to the 'Installation & Prerequisites' section in the documentation for guidance.${NC}"
        exit 1 # Exit due to unfulfilled critical dependencies.
    else
        log "SUCCESS" "All required tools ($${#required_tools[@]}) found and validated."
    fi

    log "INFO" "Verifying presence of optional tools (features might be limited if missing)..."
    # Iterate through optional tools and check for their existence.
    for tool in "${optional_tools[@]}"; do
        if ! check_tool_existence "$tool"; then
            missing_optional+=("$tool")
        fi
    done

    # Report on missing optional tools.
    if [ ${#missing_optional[@]} -ne 0 ]; then
        log "WARNING" "Some optional tools are not found: ${missing_optional[*]}"
        log "INFO" "Certain advanced features (e.g., parameter fuzzing, enhanced JS beautification) will be unavailable or limited."
        echo -e "${YELLOW}Consider installing these for full functionality.${NC}"
    else
        log "SUCCESS" "All optional tools ($${#optional_tools[@]}) found and validated."
    fi

    # Specific checks for tools with dependencies or specific versions/paths.

    # Check for js-beautify if npm is present but js-beautify itself isn't.
    if check_tool_existence "npm" && ! check_tool_existence "js-beautify"; then
        log "WARNING" "npm is installed, but 'js-beautify' command not found."
        log "WARNING" "To enable JS beautification, install it via npm: 'npm install -g js-beautify'"
    fi

    # Check for 'jq' which is crucial for parsing JSON output from Arjun/FFUF.
    if ( [ "$FUZZ_PARAMS" = true ] || [ "$PARAM_BRUTEFORCE" = true ] ) && ! check_tool_existence "jq"; then
        log "WARNING" "'jq' is not found. JSON output from Arjun/FFUF will not be processed for parameter extraction."
        log "WARNING" "Install 'jq' for full parameter discovery capabilities."
    fi

    # Check grep's Perl-compatible Regular Expression support (-P).
    # This is important for some advanced regex patterns used in JS analysis.
    if ! grep -P 'a' <<< 'a' &> /dev/null; then
        log "WARNING" "Your grep version might not support -P (Perl Regex)."
        log "WARNING" "Some JavaScript analysis and secret extraction might be less effective or fail."
        log "WARNING" "Consider installing a grep version that supports -P (e.g., GNU grep)."
    fi

    # Validate the SecretFinder.py path.
    log "INFO" "Validating SecretFinder.py path: $SECRETFINDER_PY_PATH"
    if [ -n "$SECRETFINDER_PY_PATH" ]; then
        if [ -f "$SECRETFINDER_PY_PATH" ]; then # Check if the file exists
            if [ -x "$SECRETFINDER_PY_PATH" ]; then # Check if the file is executable
                log "SUCCESS" "SecretFinder.py found and executable at: $SECRETFINDER_PY_PATH"
            else
                log "WARNING" "SecretFinder.py found, but NOT executable: $SECRETFINDER_PY_PATH"
                log "WARNING" "Please run: 'chmod +x $SECRETFINDER_PY_PATH' to make it executable."
                SECRETFINDER_PY_PATH="" # Disable SecretFinder integration if not executable
            fi
        else
            log "WARNING" "SecretFinder.py path set, but file NOT found: $SECRETFINDER_PY_PATH"
            log "WARNING" "Please check the SECRETFINDER_PY_PATH variable in the script and update it."
            SECRETFINDER_PY_PATH="" # Disable SecretFinder integration if file not found
        fi
    else
        log "INFO" "SECRETFINDER_PY_PATH variable is not set. SecretFinder integration will be skipped."
    fi

    log "SUCCESS" "Overall tool validation completed."
}


# ----------------------------------------------------------------------------------------------------
# Section 6: Setup and Initialization
# Functions to prepare the environment, create directories, and process initial inputs.
# ----------------------------------------------------------------------------------------------------

# Function: setup_directories()
# Description: Creates the main output directory and its hierarchical subdirectories.
#              If OUTPUT_DIR is not specified via arguments, it generates a unique, timestamped name.
setup_directories() {
    log "INFO" "Initiating directory setup."

    # Generate a timestamp for default output directory naming.
    local timestamp=$(date +"%Y%m%d_%H%M%S")

    # If OUTPUT_DIR is not provided via command-line, use the timestamped default.
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="crawl_$timestamp"
        log "INFO" "Output directory not specified. Using default: $OUTPUT_DIR"
    else
        log "INFO" "Using specified output directory: $OUTPUT_DIR"
    fi

    # Create the main output directory. -p ensures parent directories are created if they don't exist.
    mkdir -p "$OUTPUT_DIR"
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to create main output directory: $OUTPUT_DIR. Check permissions or path."
        exit 1
    fi
    log "DEBUG" "Main output directory '$OUTPUT_DIR' created or already exists."

    # Create subdirectories for organized output.
    # Raw data storage
    mkdir -p "$OUTPUT_DIR/raw" || { log "ERROR" "Failed to create raw directory."; exit 1; }
    mkdir -p "$OUTPUT_DIR/raw/gau" || { log "ERROR" "Failed to create raw/gau directory."; exit 1; }
    mkdir -p "$OUTPUT_DIR/raw/wayback" || { log "ERROR" "Failed to create raw/wayback directory."; exit 1; }
    mkdir -p "$OUTPUT_DIR/raw/katana" || { log "ERROR" "Failed to create raw/katana directory."; exit 1; }
    mkdir -p "$OUTPUT_DIR/raw/hakrawler" || { log "ERROR" "Failed to create raw/hakrawler directory."; exit 1; }
    log "DEBUG" "Raw data directories created."

    # Processed data storage
    mkdir -p "$OUTPUT_DIR/processed" || { log "ERROR" "Failed to create processed directory."; exit 1; }
    mkdir -p "$OUTPUT_DIR/processed/alive" || { log "ERROR" "Failed to create processed/alive directory."; exit 1; }
    mkdir -p "$OUTPUT_DIR/processed/filtered" || { log "ERROR" "Failed to create processed/filtered directory."; exit 1; }
    mkdir -p "$OUTPUT_DIR/processed/categorized" || { log "ERROR" "Failed to create processed/categorized directory."; exit 1; }
    mkdir -p "$OUTPUT_DIR/processed/responses" || { log "ERROR" "Failed to create processed/responses directory."; exit 1; }
    log "DEBUG" "Processed data directories created."

    # JavaScript analysis output storage
    mkdir -p "$OUTPUT_DIR/javascript" || { log "ERROR" "Failed to create javascript directory."; exit 1; }
    mkdir -p "$OUTPUT_DIR/javascript/files" || { log "ERROR" "Failed to create javascript/files directory."; exit 1; }
    mkdir -p "$OUTPUT_DIR/javascript/endpoints" || { log "ERROR" "Failed to create javascript/endpoints directory."; exit 1; }
    mkdir -p "$OUTPUT_DIR/javascript/secrets" || { log "ERROR" "Failed to create javascript/secrets directory."; exit 1; }
    mkdir -p "$OUTPUT_DIR/javascript/comments" || { log "ERROR" "Failed to create javascript/comments directory."; exit 1; }
    mkdir -p "$OUTPUT_DIR/javascript/beautified" || { log "ERROR" "Failed to create javascript/beautified directory."; exit 1; }
    log "DEBUG" "JavaScript analysis directories created."

    # Parameter discovery output storage
    mkdir -p "$OUTPUT_DIR/parameters" || { log "ERROR" "Failed to create parameters directory."; exit 1; }
    mkdir -p "$OUTPUT_DIR/parameters/discovered" || { log "ERROR" "Failed to create parameters/discovered directory."; exit 1; }
    mkdir -p "$OUTPUT_DIR/parameters/bruteforced" || { log "ERROR" "Failed to create parameters/bruteforced directory."; exit 1; }
    mkdir -p "$OUTPUT_DIR/parameters/fuzzed" || { log "ERROR" "Failed to create parameters/fuzzed directory."; exit 1; }
    log "DEBUG" "Parameter directories created."

    # General findings and reports
    mkdir -p "$OUTPUT_DIR/secrets" || { log "ERROR" "Failed to create secrets directory."; exit 1; }
    mkdir -p "$OUTPUT_DIR/reports" || { log "ERROR" "Failed to create reports directory."; exit 1; }
    mkdir -p "$OUTPUT_DIR/wordlists" || { log "ERROR" "Failed to create wordlists directory."; exit 1; }
    mkdir -p "$OUTPUT_DIR/fuzzing" || { log "ERROR" "Failed to create fuzzing directory."; exit 1; }
    log "DEBUG" "Other utility directories created."

    # Initialize TEMP_DIR after checking permissions and creating output dir.
    # This ensures TEMP_DIR is unique and safely created.
    TEMP_DIR=$(mktemp -d 2>/dev/null)
    if [ $? -ne 0 ] || [ -z "$TEMP_DIR" ] || [ ! -d "$TEMP_DIR" ]; then
        log "ERROR" "Failed to create temporary directory. Check system permissions or disk space."
        exit 1
    fi
    log "INFO" "Temporary directory created: $TEMP_DIR"

    log "SUCCESS" "Output directory structure initialized at: $OUTPUT_DIR"
    log "INFO" "All log messages will be written to: $OUTPUT_DIR/crawl.log"
}

# Function: process_input()
# Description: Handles different input methods (single URL, file, or stdin) and
#              standardizes the input URLs into a single, validated list.
# Returns: The path to the file containing valid URLs.
process_input() {
    log "INFO" "Starting input processing."
    local raw_input_urls="$TEMP_DIR/raw_input_urls.txt" # Temporary file for raw input
    local validated_urls_temp="$TEMP_DIR/valid_urls.txt" # Temporary file for validated URLs

    # Determine input source based on command-line arguments or stdin.
    if [ -n "$URL" ]; then
        # If a single URL is provided, write it to the raw input file.
        log "INFO" "Input source: Single URL ('$URL')."
        echo "$URL" > "$raw_input_urls"
    elif [ -n "$FILE" ]; then
        # If a file is provided, check its existence and copy its content.
        log "INFO" "Input source: File ('$FILE')."
        if [ -f "$FILE" ]; then
            cat "$FILE" > "$raw_input_urls"
        else
            log "ERROR" "Input file not found: '$FILE'. Please verify the path."
            exit 1
        fi
    else
        # If neither -u nor -f is used, assume input is piped via stdin.
        log "INFO" "Input source: Stdin (pipeline)."
        # Check if stdin is a terminal. If it is, no input is provided.
        if [ -t 0 ]; then
            log "ERROR" "No input detected via stdin. Please provide input using -u, -f, or pipe data."
            usage # Display usage and exit if no input source is found.
        fi
        # Read from stdin until EOF.
        cat > "$raw_input_urls"
        if [ $? -ne 0 ]; then
            log "ERROR" "Failed to read input from stdin."
            exit 1
        fi
    fi

    # Pre-validation check: Ensure the raw input file is not empty.
    if [ ! -s "$raw_input_urls" ]; then
        log "ERROR" "No URLs found in the provided input source. The input file/stream was empty."
        exit 1
    fi
    log "DEBUG" "Raw input URLs written to: $raw_input_urls"

    log "INFO" "Normalizing and validating input URLs..."
    local initial_count=$(wc -l < "$raw_input_urls" 2>/dev/null || echo 0)
    log "DEBUG" "Initial raw URL count: $initial_count"

    # Process each URL from the raw input file:
    # 1. Trim leading/trailing whitespace.
    # 2. Add 'https://' prefix if only a domain is provided.
    # 3. Filter out comments (lines starting with #).
    # 4. Filter out potentially invalid URLs.
    # 5. Sort and get unique URLs.
    while read -r url; do
        # Trim whitespace from the URL string.
        local trimmed_url=$(echo "$url" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        # Skip empty lines or lines that are comments.
        if [[ -z "$trimmed_url" || "$trimmed_url" =~ ^# ]]; then
            log "DEBUG" "Skipping empty or commented line: '$url'"
            continue
        fi

        # Basic validation for URL format.
        if [[ "$trimmed_url" =~ ^https?:// ]]; then
            # URL already has http(s) scheme, use as is.
            echo "$trimmed_url"
            log "DEBUG" "Valid URL (scheme present): $trimmed_url"
        elif [[ "$trimmed_url" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,} ]]; then
            # Appears to be a domain, prepend https://
            log "WARNING" "Prepending 'https://' to domain: $trimmed_url"
            echo "https://$trimmed_url"
        else
            # Unrecognized format, log a warning and skip.
            log "WARNING" "Skipping potentially invalid URL format: $trimmed_url"
        fi
    done < "$raw_input_urls" | sort -u > "$validated_urls_temp" # Pipe cleaned URLs to sort and then to the validated file.

    # Check if any valid URLs were found after processing.
    local final_valid_count=$(wc -l < "$validated_urls_temp" 2>/dev/null || echo 0)
    if [ "$final_valid_count" -eq 0 ]; then
        log "ERROR" "No valid URLs were found after filtering and normalization. Exiting."
        exit 1
    fi

    log "SUCCESS" "Processed $final_valid_count valid and unique URLs."
    log "INFO" "Valid URLs saved to: $validated_urls_temp"

    # Return the path to the file containing validated URLs.
    echo "$validated_urls_temp"
}


# ----------------------------------------------------------------------------------------------------
# Section 7: Reconnaissance Phases - URL Collection
# Functions for passive and active URL gathering.
# ----------------------------------------------------------------------------------------------------

# Function: enhanced_passive_collection()
# Description: Gathers URLs from various passive sources (Wayback Machine, Common Crawl, OTX, etc.).
#              Utilizes 'gau', 'waybackurls', and 'hakrawler' for broad coverage.
# Arguments:
#   $1: Path to the input file containing base URLs/domains for passive collection.
enhanced_passive_collection() {
    local input_file="$1"
    if [ -z "$input_file" ] || [ ! -f "$input_file" ]; then
        log "ERROR" "enhanced_passive_collection: Input file '$input_file' not found or empty."
        return 1
    fi
    log "INFO" "Starting enhanced passive URL collection from file: $input_file"

    local passive_combined_output="$OUTPUT_DIR/raw/passive_combined.txt"
    touch "$passive_combined_output" # Ensure the output file exists

    local domains_for_passive="$TEMP_DIR/domains_for_passive.txt"
    # Extract unique domains from input URLs using unfurl.
    cat "$input_file" | unfurl domains | sort -u > "$domains_for_passive"
    local domain_count=$(wc -l < "$domains_for_passive" 2>/dev/null || echo 0)
    if [ "$domain_count" -eq 0 ]; then
        log "WARNING" "No unique domains extracted for passive collection. Skipping this phase."
        return 0
    fi
    log "INFO" "Extracted $domain_count unique domains for passive collection."

    # --- Step 1: Collect URLs using GAU (Get All URLs) ---
    log "INFO" "Initiating URL collection via GAU (providers: wayback,commoncrawl,otx,urlscan,alienvault)..."
    log "DEBUG" "GAU command: cat $domains_for_passive | gau -providers wayback,commoncrawl,otx,urlscan,alienvault -t $THREADS | anew $passive_combined_output"
    # Execute GAU in the background. Use 'anew' to append only new unique URLs.
    cat "$domains_for_passive" | gau -providers wayback,commoncrawl,otx,urlscan,alienvault -t "$THREADS" 2>/dev/null | anew "$passive_combined_output" > /dev/null &
    local gau_pid=$! # Store PID of the background process
    log "DEBUG" "GAU process started with PID: $gau_pid"

    # --- Step 2: Collect URLs using Waybackurls ---
    log "INFO" "Initiating URL collection via Wayback Machine (waybackurls)..."
    log "DEBUG" "Waybackurls command: cat $domains_for_passive | waybackurls | anew $passive_combined_output"
    # Execute Waybackurls in the background.
    cat "$domains_for_passive" | waybackurls 2>/dev/null | anew "$passive_combined_output" > /dev/null &
    local wayback_pid=$!
    log "DEBUG" "Waybackurls process started with PID: $wayback_pid"

    # --- Step 3: Collect URLs using Hakrawler (Optional) ---
    if check_tool_existence "hakrawler"; then
        log "INFO" "Initiating URL collection via Hakrawler (depth 2)..."
        log "DEBUG" "Hakrawler command: cat $domains_for_passive | hakrawler -depth 2 -plain -t $THREADS | anew $passive_combined_output"
        # Execute Hakrawler in the background.
        cat "$domains_for_passive" | hakrawler -depth 2 -plain -t "$THREADS" 2>/dev/null | anew "$passive_combined_output" > /dev/null &
        local hakrawler_pid=$!
        log "DEBUG" "Hakrawler process started with PID: $hakrawler_pid"
    else
        log "WARNING" "Hakrawler not found. Skipping hakrawler-based passive collection."
    fi

    # Wait for all background passive collection processes to complete.
    log "INFO" "Waiting for all passive collection processes to finish..."
    wait
    local wait_status=$?
    if [ $wait_status -eq 0 ]; then
        log "DEBUG" "All passive collection background jobs completed successfully."
    else
        log "WARNING" "Some passive collection background jobs finished with non-zero status ($wait_status)."
    fi

    # Final count and reporting for passive collection.
    local passive_count=$(wc -l < "$passive_combined_output" 2>/dev/null || echo 0)
    if [ "$passive_count" -gt 0 ]; then
        log "SUCCESS" "Passive collection found $passive_count unique URLs."
        if [ "$SILENT" = false ]; then
            log "INFO" "Passive Sample (first 10 unique URLs):"
            head -n 10 "$passive_combined_output" | sed 's/^/    /' # Indent for readability
        fi
    else
        log "WARNING" "Passive collection found 0 URLs. This might indicate a very new target or limited public data."
    fi

    log "INFO" "Passive URL collection phase completed."
    return 0
}

# Function: enhanced_active_crawling()
# Description: Performs active web crawling using Katana.
#              Configures Katana options based on script settings (depth, threads, headers, filters).
# Arguments:
#   $1: Path to the input file containing base URLs for active crawling.
enhanced_active_crawling() {
    local input_file="$1"
    if [ -z "$input_file" ] || [ ! -f "$input_file" ]; then
        log "ERROR" "enhanced_active_crawling: Input file '$input_file' not found or empty."
        return 1
    fi
    log "INFO" "Starting enhanced active crawling with Katana from file: $input_file"

    # Define the output file for Katana's results.
    local katana_output="$OUTPUT_DIR/raw/katana/all.txt"
    touch "$katana_output" # Ensure the output file exists

    # Check if Katana is available before attempting to run it.
    if ! check_tool_existence "katana"; then
        log "WARNING" "Katana not found. Skipping active crawling phase."
        return 0
    fi

    # Construct Katana command-line options dynamically.
    local katana_opts=""

    # Basic crawling options.
    katana_opts+=" -d $DEPTH" # Crawling depth
    katana_opts+=" -c $THREADS" # Concurrency
    katana_opts+=" -rl $RATE_LIMIT" # Rate limit
    katana_opts+=" -timeout $TIMEOUT" # Request timeout
    katana_opts+=" -silent" # Suppress verbose Katana output to stderr

    # User-Agent header.
    katana_opts+=" -H 'User-Agent: $USER_AGENT'"
    log "DEBUG" "Katana User-Agent set to: '$USER_AGENT'"

    # Aggressive mode options.
    if [ "$AGGRESSIVE" = true ]; then
        log "INFO" "Aggressive mode enabled for Katana: enabling JS, form, link, and file discovery."
        katana_opts+=" -jc" # JavaScript file discovery
        katana_opts+=" -aff" # All forms discovery
        katana_opts+=" -kf all" # Include all known file types (e.g., PDFs, documents)
        katana_opts+=" -fx" # Find new URLs from external links (beware, can go out of scope if not careful)
    else
        log "INFO" "Aggressive mode not enabled for Katana. Using standard options."
        katana_opts+=" -jc" # Still enable JS discovery by default, as it's crucial
    fi

    # Extension filtering.
    if [ "$FILTER_EXTENSIONS" = true ] && [ "$AGGRESSIVE" = false ]; then
        log "INFO" "Filtering static file extensions (css, png, jpg, etc.) from Katana output."
        katana_opts+=" -ef css,png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico,mp4,mp3,avi,pdf,doc,zip,xml,json,gz,tar" # Exclude common static/archive files
    else
        log "INFO" "Including static files in Katana crawl (due to --include-static or --aggressive)."
    fi

    # Custom headers.
    if [ -n "$CUSTOM_HEADERS" ]; then
        log "INFO" "Adding custom headers to Katana requests: '$CUSTOM_HEADERS'"
        katana_opts+=" -H '$CUSTOM_HEADERS'"
    fi

    log "DEBUG" "Final Katana options string: katana $katana_opts"

    # Execute Katana. Pipe input URLs to Katana. Output to specified file.
    log "INFO" "Executing Katana. This may take some time depending on depth and target complexity."
    cat "$input_file" | katana $katana_opts 2>/dev/null | anew "$katana_output" > /dev/null
    local katana_status=${PIPESTATUS[1]} # Get exit status of katana

    if [ $katana_status -eq 0 ]; then
        log "DEBUG" "Katana execution completed with status 0."
    else
        log "WARNING" "Katana returned a non-zero exit status ($katana_status). Check Katana logs for details if debugging."
    fi

    # Count and report the number of URLs found by Katana.
    local katana_count=$(wc -l < "$katana_output" 2>/dev/null || echo 0)
    if [ "$katana_count" -gt 0 ]; then
        log "SUCCESS" "Active crawling with Katana found $katana_count unique URLs."
        if [ "$SILENT" = false ]; then
            log "INFO" "Active Crawl Sample (first 10 unique URLs from Katana):"
            head -n 10 "$katana_output" | sed 's/^/    /'
        fi
    else
        log "WARNING" "Katana found 0 URLs. This could mean the target is very small, heavily restricted, or the input URLs were invalid for active crawling."
    fi

    log "INFO" "Active crawling phase completed."
    return 0
}

# ----------------------------------------------------------------------------------------------------
# Section 8: Reconnaissance Phases - JavaScript Analysis
# Functions for deep inspection of JavaScript files.
# ----------------------------------------------------------------------------------------------------

# Function: check_obfuscation()
# Description: Analyzes a given JavaScript file for common indicators of obfuscation.
#              Looks for long lines, frequent use of `eval`, `atob`, `fromCharCode`, and escaped characters.
# Arguments:
#   $1: Path to the JavaScript file to analyze.
# Returns: "true" if obfuscation is suspected, "false" otherwise.
check_obfuscation() {
    local js_file="$1"
    if [ -z "$js_file" ] || [ ! -f "$js_file" ]; then
        log "ERROR" "check_obfuscation: JavaScript file '$js_file' not found for analysis."
        echo "false" # Return false as it can't be analyzed
        return 1
    fi
    log "DEBUG" "Checking for obfuscation in: $js_file"

    local is_obfuscated=false
    local long_line_threshold=2000 # Lines longer than this often indicate concatenated/minified/obfuscated code.
    local func_count_threshold=5   # Number of suspicious functions (eval, atob, etc.) to trigger obfuscation alert.
    local escape_seq_threshold=100 # Number of escaped character sequences to trigger obfuscation alert.

    # Count suspicious function calls that are often used in obfuscated JS.
    local func_count=$(grep -cE '(eval\(|atob\(|String\.fromCharCode|document\.write\(|unescape\()' "$js_file" 2>/dev/null || echo 0)
    log "DEBUG" "Obfuscation check ($js_file): Suspicious function calls count: $func_count"

    # Count lines exceeding a certain length, which can indicate minification or obfuscation.
    local long_lines=$(awk -v t="$long_line_threshold" 'length > t {c++} END {print c+0}' "$js_file" 2>/dev/null || echo 0)
    log "DEBUG" "Obfuscation check ($js_file): Long lines (>${long_line_threshold} chars) count: $long_lines"

    # Count escaped character sequences (e.g., \xHH, \uHHHH), common in obfuscation.
    local escape_count=$(grep -oE '(\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})' "$js_file" | wc -l 2>/dev/null || echo 0)
    log "DEBUG" "Obfuscation check ($js_file): Escape sequences count: $escape_count"

    # Determine if obfuscation is likely based on the thresholds.
    if [ "$long_lines" -gt 0 ] || [ "$func_count" -gt "$func_count_threshold" ] || [ "$escape_count" -gt "$escape_seq_threshold" ]; then
        is_obfuscated=true
        log "WARNING" "Potential obfuscation indicators found in '$js_file': Functions: $func_count, Long Lines: $long_lines, Escapes: $escape_count"
    else
        log "DEBUG" "No significant obfuscation indicators found in: $js_file"
    fi

    echo "$is_obfuscated" # Return "true" or "false"
    return 0
}

# Function: deep_javascript_analysis()
# Description: Performs a comprehensive analysis of JavaScript files found during crawling.
#              This includes downloading JS, extracting endpoints, secrets, comments,
#              and attempting to beautify obfuscated code.
#              NOTE: This function processes files sequentially for stability due to external tools.
deep_javascript_analysis() {
    if [ "$JS_ANALYSIS" = false ]; then
        log "INFO" "JavaScript analysis is disabled. Skipping this phase."
        return 0
    fi
    log "INFO" "Starting deep JavaScript analysis phase."

    # Define output file paths for JS analysis results.
    local all_js_files_list="$OUTPUT_DIR/javascript/files/all_js.txt"
    local extracted_endpoints_raw="$OUTPUT_DIR/javascript/endpoints/extracted.txt"
    local extracted_endpoints_full_urls="$OUTPUT_DIR/javascript/endpoints/full_urls.txt"
    local extracted_secrets_grep="$OUTPUT_DIR/javascript/secrets/extracted_grep.txt"
    local extracted_comments="$OUTPUT_DIR/javascript/comments/all.txt"
    local obfuscated_js_list="$OUTPUT_DIR/javascript/obfuscated_js.txt"
    local secretfinder_output="$OUTPUT_DIR/secrets/secretfinder_all.txt"

    # Ensure output files are empty or created before starting.
    > "$all_js_files_list"
    > "$extracted_endpoints_raw"
    > "$extracted_endpoints_full_urls"
    > "$extracted_secrets_grep"
    > "$extracted_comments"
    > "$obfuscated_js_list"
    > "$secretfinder_output"

    log "INFO" "Collecting all potential JavaScript file URLs from raw crawl data."
    # Combine URLs from all raw sources and filter for .js extensions.
    # The '2>/dev/null' suppresses errors if some raw files don't exist yet.
    cat "$OUTPUT_DIR/raw"/*.txt "$OUTPUT_DIR/raw"/*/*.txt "$OUTPUT_DIR/processed/all_urls.txt" 2>/dev/null | \
        grep -iE '\.js(\?|$|#)' | sort -u | anew "$all_js_files_list" > /dev/null

    local js_count=$(wc -l < "$all_js_files_list" 2>/dev/null || echo 0)
    if [ "$js_count" -eq 0 ]; then
        log "WARNING" "No JavaScript files found to analyze. Skipping deep JS analysis."
        return 0
    fi
    log "INFO" "Identified $js_count unique JavaScript files for analysis."
    log "WARNING" "Analyzing JavaScript files sequentially. This may take a significant amount of time for many files."

    local current_file_num=0
    # Loop through each unique JavaScript URL.
    while read -r js_url; do
        current_file_num=$((current_file_num + 1))
        [ -z "$js_url" ] && continue # Skip empty lines

        log "INFO" "(${current_file_num}/${js_count}) Processing JS file: $js_url"
        log "DEBUG" "sanitizing js url for filename use"
        # Sanitize URL for use as a filename by replacing problematic characters with underscores.
        # This helps in saving downloaded JS files with a unique, valid filename.
        local js_basename=$(echo "$js_url" | tr -c '[:alnum:]_.' '_') # Keep alphanumeric, underscore, dot
        js_basename=$(echo "$js_basename" | head -c 200) # Truncate to avoid extremely long filenames
        local js_download_path="$TEMP_DIR/${js_basename}.js"

        log "DEBUG" "Attempting to download JS file to: $js_download_path"
        # Download the JavaScript file using curl.
        # -s: Silent mode, -L: Follow redirects, -A: Set User-Agent, --max-time: Set timeout.
        curl -s -L -A "$USER_AGENT" --max-time "$TIMEOUT" "$js_url" -o "$js_download_path" 2>/dev/null
        local curl_status=$?

        if [ $curl_status -ne 0 ]; then
            log "WARNING" "Failed to download '$js_url' (curl exit: $curl_status) or request timed out. Skipping analysis for this file."
            rm -f "$js_download_path" # Clean up partially downloaded file if any
            continue # Move to the next JS URL
        fi

        # Check if the downloaded file is empty.
        if [ ! -s "$js_download_path" ]; then
            log "WARNING" "Downloaded JavaScript file '$js_url' is empty or invalid. Skipping analysis."
            rm -f "$js_download_path"
            continue
        fi
        log "DEBUG" "Successfully downloaded JS file from '$js_url' to '$js_download_path'."

        # --- Sub-step 1: Obfuscation Detection and Beautification ---
        local is_obf=$(check_obfuscation "$js_download_path")
        if [ "$is_obf" = "true" ]; then
            log "WARNING" "Potential obfuscation detected for '$js_url'."
            echo "$js_url" >> "$obfuscated_js_list" # Record obfuscated URL

            if check_tool_existence "js-beautify"; then
                log "INFO" "Attempting to beautify '$js_url'..."
                local beautified_output_path="$OUTPUT_DIR/javascript/beautified/${js_basename}_beautified.js"
                # Use `js-beautify -r` for in-place beautification on a copy, then copy to output.
                # Or, if we want to keep original, pipe. Here, copy is safer.
                cp "$js_download_path" "$beautified_output_path" # Make a copy to beautify
                js-beautify -r "$beautified_output_path" 2>/dev/null
                local beautify_status=$?
                if [ $beautify_status -eq 0 ]; then
                    log "SUCCESS" "Beautified version saved to: $beautified_output_path"
                else
                    log "WARNING" "js-beautify failed for '$js_url' (exit: $beautify_status). Check file content."
                    rm -f "$beautified_output_path" # Remove failed beautification attempt
                fi
            else
                log "INFO" "js-beautify not found. Skipping beautification for '$js_url'."
            fi
        fi

        # --- Sub-step 2: Endpoint and URL Extraction ---
        log "DEBUG" "Extracting endpoints and URLs from downloaded JS file."
        # Extract relative paths (starting with /) and absolute URLs (http/https).
        grep -oP "['\"](/?[a-zA-Z0-9_./-]+)['\"]" "$js_download_path" | \
            sed -e 's/^["'"'"']//' -e 's/["'"'"']$//' | \
            grep -E "^/" >> "$extracted_endpoints_raw" # Relative paths
        grep -oP "https?://[a-zA-Z0-9\.\-]+[a-zA-Z0-9\.\-\/\?\&\=]*" "$js_download_path" >> "$extracted_endpoints_raw" # Absolute URLs
        log "DEBUG" "Raw endpoints extracted to: $extracted_endpoints_raw"

        # --- Sub-step 3: Comment Extraction ---
        if [ "$EXTRACT_COMMENTS" = true ]; then
            log "DEBUG" "Extracting comments from downloaded JS file."
            grep -oP "(//.*|/\*.*?\*/)" "$js_download_path" >> "$extracted_comments"
            log "DEBUG" "Comments extracted to: $extracted_comments"
        fi

        # --- Sub-step 4: Secret Extraction (Grep and SecretFinder) ---
        if [ "$EXTRACT_SECRETS" = true ]; then
            log "DEBUG" "Attempting to extract secrets using grep patterns."
            # Grep for common keywords indicating secrets.
            grep -Eio "(api_key|apikey|secret|token|password|auth|aws_access_key_id|aws_secret_access_key|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)" "$js_download_path" >> "$extracted_secrets_grep"
            log "DEBUG" "Grep-based secret extraction complete."

            # Run SecretFinder.py if path is configured and tool is executable.
            if [ -n "$SECRETFINDER_PY_PATH" ] && [ -f "$SECRETFINDER_PY_PATH" ] && [ -x "$SECRETFINDER_PY_PATH" ]; then
                log "INFO" "Running SecretFinder.py on '$js_url'..."
                # SecretFinder output can be noisy; filter out INFO/DEBUG/progress lines.
                python3 /home/yehia/Bug_Hunting/Tools/SecretFinder/SecretFinder.py -i "$js_url" -o cli 2>/dev/null | \
                    grep -vE "^\[!\]|^\[INFO\]|^\[DEBU\]|Processing URL|Found [0-9]+ Javascript files|Checking:|Found results in" | \
                    sed '/^\s*$/d' >> "$secretfinder_output" # Remove empty lines
                local sf_status=${PIPESTATUS[0]} # Status of python3 command
                if [ $sf_status -eq 0 ]; then
                    log "DEBUG" "SecretFinder.py executed successfully for '$js_url'."
                else
                    log "WARNING" "SecretFinder.py failed or returned non-zero status ($sf_status) for '$js_url'."
                fi
            else
                log "DEBUG" "SecretFinder.py not available or configured. Skipping SecretFinder scan."
            fi
        fi

        # Clean up the downloaded JavaScript file from temp directory.
        rm -f "$js_download_path"
        log "DEBUG" "Cleaned up temporary JS file: $js_download_path"

    done < "$all_js_files_list"

    # --- Post-processing extracted endpoints to convert relative paths to full URLs ---
    if [ -s "$extracted_endpoints_raw" ]; then
        log "INFO" "Converting relative JS endpoints to full URLs."
        # Get the first valid URL to derive the base domain/scheme.
        local first_valid_url=$(head -n 1 "$TEMP_DIR/valid_urls.txt" 2>/dev/null)
        if [ -z "$first_valid_url" ]; then
            log "WARNING" "Could not determine a base URL for converting relative JS endpoints. Skipping."
        else
            local base_domain=$(echo "$first_valid_url" | unfurl domains)
            local base_scheme=$(echo "$first_valid_url" | unfurl scheme)
            local base_url="${base_scheme}://${base_domain}"
            log "DEBUG" "Derived base URL for endpoint conversion: $base_url"

            # Read raw extracted endpoints, prepend base URL for relative paths.
            while read -r endpoint; do
                if [[ "$endpoint" =~ ^/ ]]; then
                    # Relative path starting with /
                    echo "${base_url}${endpoint}"
                elif [[ "$endpoint" =~ ^\./ ]]; then
                    # Relative path starting with ./ (handle carefully, might need more context)
                    echo "${base_url}/${endpoint#./}"
                elif [[ "$endpoint" =~ ^https?:// ]]; then
                    # Already a full URL
                    echo "$endpoint"
                else
                    log "DEBUG" "Skipping unhandled endpoint format: $endpoint"
                fi
            done < "$extracted_endpoints_raw" | sort -u > "$extracted_endpoints_full_urls"
        fi
    fi

    # Final summary of JS analysis findings.
    local final_endpoints_count=$(wc -l < "$extracted_endpoints_full_urls" 2>/dev/null || echo 0)
    local final_secrets_grep_count=$(wc -l < "$extracted_secrets_grep" 2>/dev/null || echo 0)
    local final_secretfinder_count=$(grep -c . "$secretfinder_output" 2>/dev/null || echo 0)
    local final_obfuscated_count=$(wc -l < "$obfuscated_js_list" 2>/dev/null || echo 0)
    local final_comments_count=$(wc -l < "$extracted_comments" 2>/dev/null || echo 0)

    log "SUCCESS" "JavaScript Analysis Summary:"
    log "FINDING" "  Total JS Endpoints (Full URLs): $final_endpoints_count"
    log "FINDING" "  Potential Secrets (Grep-based): $final_secrets_grep_count"
    log "FINDING" "  Potential Secrets (SecretFinder.py): $final_secretfinder_count"
    log "FINDING" "  Potentially Obfuscated JS Files: $final_obfuscated_count"
    log "INFO" "  Comments Extracted: $final_comments_count"

    if [ "$SILENT" = false ] && [ "$final_endpoints_count" -gt 0 ]; then
        log "INFO" "JS Endpoints Sample (first 10 unique full URLs):"
        head -n 10 "$extracted_endpoints_full_urls" | sed 's/^/    /'
    fi

    log "INFO" "Deep JavaScript analysis phase completed."
    return 0
}

# ----------------------------------------------------------------------------------------------------
# Section 9: Reconnaissance Phases - Parameter Discovery
# Functions for identifying and fuzing URL parameters.
# ----------------------------------------------------------------------------------------------------

# Function: enhanced_parameter_discovery()
# Description: Discovers URL parameters using multiple techniques:
#              1. Direct extraction from crawled URLs.
#              2. ParamSpider for additional passive parameter discovery.
#              3. Arjun for active parameter bruteforcing.
#              4. FFUF for parameter fuzzing (if enabled).
enhanced_parameter_discovery() {
    log "INFO" "Starting enhanced parameter discovery phase."

    local all_urls_for_params="$OUTPUT_DIR/processed/all_urls.txt"
    local unique_discovered_params="$OUTPUT_DIR/parameters/discovered/unique_params.txt"
    local arjun_results_json="$OUTPUT_DIR/parameters/bruteforced/arjun_results.json"
    local ffuf_results_json="$OUTPUT_DIR/parameters/fuzzed/ffuf_results.json"
    local final_all_params_list="$OUTPUT_DIR/parameters/all_parameters.txt"

    # Ensure output files are clean at the start of this phase.
    > "$unique_discovered_params"
    > "$arjun_results_json"
    > "$ffuf_results_json"
    > "$final_all_params_list"

    log "INFO" "Consolidating all crawled and JS-extracted URLs for parameter analysis."
    # Combine all URLs from raw and JS analysis for a comprehensive parameter source.
    # Uses `anew` to ensure uniqueness.
    cat "$OUTPUT_DIR/raw/passive_combined.txt" "$OUTPUT_DIR/raw/katana/all.txt" "$OUTPUT_DIR/javascript/endpoints/full_urls.txt" 2>/dev/null | \
        sort -u | anew "$all_urls_for_params" > /dev/null
    local total_urls_for_params=$(wc -l < "$all_urls_for_params" 2>/dev/null || echo 0)
    log "INFO" "Total $total_urls_for_params URLs consolidated for parameter discovery."

    # --- Step 1: Direct Parameter Extraction from URLs ---
    log "INFO" "Extracting parameters directly from all consolidated URLs."
    # Filter URLs containing '?', then use `unfurl keys` to get parameter names.
    cat "$all_urls_for_params" | grep "?" | unfurl keys | sort -u >> "$unique_discovered_params"
    log "DEBUG" "Initial direct parameter extraction complete."

    # --- Step 2: ParamSpider Integration (Optional) ---
    if check_tool_existence "paramspider"; then
        log "INFO" "Running ParamSpider for additional parameter discovery."
        local domains_for_paramspider="$TEMP_DIR/paramspider_domains.txt"
        cat "$all_urls_for_params" | unfurl domains | sort -u | head -n 500 > "$domains_for_paramspider" # Limit domains for large inputs

        local ps_domain_count=$(wc -l < "$domains_for_paramspider" 2>/dev/null || echo 0)
        if [ "$ps_domain_count" -gt 0 ]; then
            log "INFO" "ParamSpider will run on $ps_domain_count domains (limited to 500 for performance)."
            local paramspider_log="$OUTPUT_DIR/parameters/discovered/paramspider.log"
            touch "$paramspider_log"

            # Iterate through domains and run ParamSpider in background for each.
            # This can be very resource-intensive if many domains are present.
            local current_ps_domain=0
            while read -r domain; do
                current_ps_domain=$((current_ps_domain + 1))
                log "DEBUG" "Running ParamSpider for domain $current_ps_domain/$ps_domain_count: $domain"
                # Exclude common static files to focus on dynamic pages.
                paramspider -d "$domain" --exclude png,jpg,css,js,svg,ico,gif -l high -o "$OUTPUT_DIR/parameters/discovered/paramspider_${domain//[^a-zA-Z0-9]/_}.txt" 2>/dev/null &
            done < "$domains_for_paramspider"
            wait # Wait for all ParamSpider background jobs to complete.

            # Collect parameters from all ParamSpider output files.
            log "INFO" "Consolidating results from ParamSpider."
            cat "$OUTPUT_DIR/parameters/discovered"/paramspider_*.txt 2>/dev/null | \
                grep "?" | unfurl keys | sort -u >> "$unique_discovered_params"
            log "SUCCESS" "ParamSpider execution completed. Discovered parameters merged."
        else
            log "WARNING" "No domains found for ParamSpider. Skipping ParamSpider run."
        fi
    else
        log "INFO" "ParamSpider not found. Skipping ParamSpider integration."
    fi

    # --- Step 3: Arjun Parameter Bruteforcing (Optional) ---
    if [ "$PARAM_BRUTEFORCE" = true ] && check_tool_existence "arjun"; then
        log "INFO" "Running Arjun for active parameter bruteforcing."
        local arjun_input_urls="$TEMP_DIR/arjun_input_urls.txt"
        # Select a subset of unique base URLs (without parameters) for Arjun to target.
        # This prevents Arjun from bruteforcing parameters on every single URL, which would be too slow.
        cat "$all_urls_for_params" | unfurl format %s://%d%p | sort -u | head -n 50 > "$arjun_input_urls" # Limit to 50 URLs for Arjun
        local arjun_target_count=$(wc -l < "$arjun_input_urls" 2>/dev/null || echo 0)

        if [ "$arjun_target_count" -gt 0 ]; then
            log "INFO" "Arjun will bruteforce parameters on $arjun_target_count unique base URLs."
            log "DEBUG" "Arjun command: arjun -i '$arjun_input_urls' -t $THREADS --quiet -oJ '$arjun_results_json'"

            # Execute Arjun. --quiet minimizes Arjun's console output.
            arjun -i "$arjun_input_urls" -t "$THREADS" --quiet -oJ "$arjun_results_json" 2>/dev/null
            local arjun_status=$?

            if [ $arjun_status -eq 0 ]; then
                log "SUCCESS" "Arjun parameter bruteforcing completed."
                # Extract parameters from Arjun's JSON output using jq.
                if [ -f "$arjun_results_json" ] && check_tool_existence "jq"; then
                    log "DEBUG" "Extracting parameters from Arjun JSON output using jq."
                    jq -r '.[].params | keys[]?' "$arjun_results_json" 2>/dev/null | sort -u >> "$unique_discovered_params"
                    log "DEBUG" "Arjun parameters merged into main list."
                else
                    log "WARNING" "jq not found or Arjun JSON output empty. Skipping parameter extraction from Arjun results."
                fi
            else
                log "WARNING" "Arjun failed or returned non-zero status ($arjun_status). Check Arjun logs if debugging."
            fi
        else
            log "INFO" "No suitable base URLs found for Arjun bruteforcing. Skipping Arjun."
        fi
    else
        log "INFO" "Arjun not found or parameter bruteforcing disabled. Skipping Arjun integration."
    fi

    # --- Step 4: FFUF Parameter Fuzzing (Optional) ---
    if [ "$FUZZ_PARAMS" = true ] && check_tool_existence "ffuf"; then
        log "INFO" "Starting FFUF-based parameter fuzzing."
        local fuzz_param_names_wordlist="$OUTPUT_DIR/wordlists/fuzz_param_names.txt"
        local fuzz_target_urls_file="$TEMP_DIR/ffuf_target_urls.txt"

        log "INFO" "Generating parameter name wordlist for fuzzing."
        # Combine already discovered parameters with a common list of names.
        {
            cat "$unique_discovered_params" 2>/dev/null
            echo -e "id\nuser\nfile\npath\ndata\ncmd\naction\npage\nview\ncat\ndir\nshow\nedit\ndel\ndelete\nurl\nredirect\nnext\nparam\ninput\nquery\nname\nsearch\nkeyword\ntest\nvalue\nitem\nlang\ncallback\n_method\n__proto__"
        } | sort -u > "$fuzz_param_names_wordlist"
        local num_param_names=$(wc -l < "$fuzz_param_names_wordlist" 2>/dev/null || echo 0)
        log "DEBUG" "Fuzzing wordlist contains $num_param_names parameter names."

        log "INFO" "Selecting target URLs for FFUF parameter fuzzing."
        # Select a limited number of unique base URLs (no existing params) for fuzzing.
        # Fuzzing every URL with every parameter name can be extremely slow.
        cat "$all_urls_for_params" | unfurl format %s://%d%p | sort -u | head -n 50 > "$fuzz_target_urls_file" # Limit to 50 URLs
        local num_base_urls_for_fuzz=$(wc -l < "$fuzz_target_urls_file" 2>/dev/null || echo 0)

        if [ "$num_base_urls_for_fuzz" -gt 0 ] && [ "$num_param_names" -gt 0 ]; then
            log "INFO" "FFUF will fuzz $num_base_urls_for_fuzz base URLs with $num_param_names parameter names (using 'test' as value)."
            log "DEBUG" "FFUF command: ffuf -u 'TARGET_URL?PARAM_NAME=test' -w '$fuzz_target_urls_file:TARGET_URL' -w '$fuzz_param_names_wordlist:PARAM_NAME' -mc 200,301,302,403,401,500 -ac -t $THREADS -timeout $TIMEOUT -o '$ffuf_results_json' -of json -s"

            # Execute FFUF with multiple wordlists.
            # TARGET_URL and PARAM_NAME are placeholders for FFUF's multi-wordlist mode.
            # -mc: Match status codes (200 OK, redirects, auth, forbidden, internal server errors - looking for any response changes)
            # -ac: Automatically calibrate fuzzing
            # -s: Silent mode for FFUF's console output
            ffuf -u "TARGET_URL?PARAM_NAME=test" \
                 -w "$fuzz_target_urls_file:TARGET_URL" \
                 -w "$fuzz_param_names_wordlist:PARAM_NAME" \
                 -mc 200,301,302,403,401,500 -ac -t "$THREADS" -timeout "$TIMEOUT" \
                 -o "$ffuf_results_json" \
                 -of json -s 2>/dev/null

            local ffuf_status=$?
            if [ $ffuf_status -eq 0 ]; then
                log "SUCCESS" "FFUF parameter fuzzing completed."
                # Extract newly discovered parameters from FFUF's JSON output.
                if [ -f "$ffuf_results_json" ] && check_tool_existence "jq"; then
                    log "DEBUG" "Extracting parameters from FFUF JSON output using jq."
                    jq -r '.results[] | .input.PARAM_NAME' "$ffuf_results_json" 2>/dev/null | sort -u >> "$unique_discovered_params"
                    log "DEBUG" "FFUF parameters merged into main list."
                else
                    log "WARNING" "jq not found or FFUF JSON output empty. Skipping parameter extraction from FFUF results."
                fi
            else
                log "WARNING" "FFUF failed or returned non-zero status ($ffuf_status). Check FFUF logs if debugging."
            fi
        else
            log "INFO" "Not enough base URLs ($num_base_urls_for_fuzz) or parameter names ($num_param_names) to perform FFUF fuzzing. Skipping."
        fi
    else
        log "INFO" "FFUF not found or parameter fuzzing disabled. Skipping FFUF integration."
    fi

    # Final consolidation and uniqueness for all parameters.
    log "INFO" "Consolidating all discovered parameters into a final unique list."
    sort -u "$unique_discovered_params" > "$final_all_params_list"
    local final_param_count=$(wc -l < "$final_all_params_list" 2>/dev/null || echo 0)

    if [ "$final_param_count" -gt 0 ]; then
        log "SUCCESS" "Parameter discovery phase completed. Found $final_param_count unique parameters in total."
        if [ "$SILENT" = false ]; then
            log "FINDING" "Parameters Sample (first 10 unique):"
            head -n 10 "$final_all_params_list" | sed 's/^/    /'
        fi
    else
        log "WARNING" "No unique parameters were discovered across all techniques. This may be normal for simple targets."
    fi

    log "INFO" "Parameter discovery phase completed."
    return 0
}

# ----------------------------------------------------------------------------------------------------
# Section 10: Post-Reconnaissance Analysis
# Functions for URL validation, categorization, and response analysis.
# ----------------------------------------------------------------------------------------------------

# Function: validate_and_categorize()
# Description: Validates the liveness of collected URLs using httpx and then categorizes them
#              based on common patterns (API, admin, upload, etc.).
validate_and_categorize() {
    log "INFO" "Starting URL validation and categorization phase."

    local all_collected_urls="$OUTPUT_DIR/processed/all_urls.txt"
    local validated_alive_urls="$OUTPUT_DIR/processed/alive/validated.txt"
    local categorized_dir="$OUTPUT_DIR/processed/categorized"

    # Ensure output files/directories are clean or exist.
    > "$validated_alive_urls" # Clear previous runs
    mkdir -p "$categorized_dir" # Ensure categorization directory exists

    # Check if there are any URLs to process.
    if [ ! -s "$all_collected_urls" ]; then
        log "WARNING" "No URLs found in '$all_collected_urls' for validation/categorization. Skipping this phase."
        return 0
    fi

    # --- Step 1: URL Validation with HTTPX ---
    if [ "$VALIDATE_URLS" = true ]; then
        log "INFO" "Running httpx for URL liveness validation. This may take some time."
        log "DEBUG" "httpx command: cat '$all_collected_urls' | httpx_live -silent -mc 200,301,302,401,403,500 -t $THREADS -timeout $TIMEOUT -o '$validated_alive_urls'"

        # Execute httpx to check for various success/redirect/error codes, indicating liveness.
        cat "$all_collected_urls" | httpx_live -silent -mc 200,301,302,401,403,500 -t "$THREADS" -timeout "$TIMEOUT" \
            -o "$validated_alive_urls" 2>/dev/null
        local httpx_status=${PIPESTATUS[1]} # Get exit status of httpx

        if [ $httpx_status -eq 0 ]; then
            log "DEBUG" "httpx validation completed successfully."
        else
            log "WARNING" "httpx validation returned a non-zero exit status ($httpx_status). Some URLs might not have been checked."
        fi

        local alive_count=$(wc -l < "$validated_alive_urls" 2>/dev/null || echo 0)
        if [ "$alive_count" -gt 0 ]; then
            log "SUCCESS" "URL validation: $alive_count unique alive URLs found."
            if [ "$SILENT" = false ]; then
                log "INFO" "Alive URLs Sample (first 10):"
                head -n 10 "$validated_alive_urls" | sed 's/^/    /'
            fi
        else
            log "WARNING" "No alive URLs found after validation. This could indicate a down target or strict WAF/firewall."
            return 0 # Exit if no alive URLs to categorize.
        fi
    else
        log "INFO" "URL validation is disabled (--no-validate). All collected URLs will be considered for categorization."
        # If validation is skipped, copy all collected URLs to the 'validated' file for subsequent steps.
        cp "$all_collected_urls" "$validated_alive_urls"
        log "DEBUG" "All URLs copied to '$validated_alive_urls' as validation was skipped."
    fi

    # Check again if there are URLs to categorize, as validation might have yielded none.
    if [ ! -s "$validated_alive_urls" ]; then
        log "WARNING" "No URLs available in '$validated_alive_urls' for categorization. Skipping."
        return 0
    fi

    # --- Step 2: URL Categorization ---
    log "INFO" "Categorizing alive URLs based on common patterns."

    # Clear previous categorization files to ensure fresh results.
    > "$categorized_dir/api_endpoints.txt"
    > "$categorized_dir/admin_areas.txt"
    > "$categorized_dir/upload_endpoints.txt"
    > "$categorized_dir/dynamic_pages.txt"
    > "$categorized_dir/with_params.txt"
    > "$categorized_dir/sensitive_files.txt"

    # API Endpoints: URLs containing keywords related to APIs (e.g., /api/, /rest/, /graphql).
    log "DEBUG" "Categorizing API endpoints..."
    grep -iE "(api|rest|graphql|soap|json|token|xml|v[0-9]+/)" "$validated_alive_urls" 2>/dev/null | sort -u >> "$categorized_dir/api_endpoints.txt"
    local api_count=$(wc -l < "$categorized_dir/api_endpoints.txt" 2>/dev/null || echo 0)
    log "DEBUG" "Found $api_count API endpoints."

    # Admin Areas: URLs pointing to administrative or login interfaces.
    log "DEBUG" "Categorizing admin areas..."
    grep -iE "(admin|panel|dashboard|login|auth|config|setup|install|signin|signup|portal|manage|control|cpanel|wp-admin|phpmyadmin)" "$validated_alive_urls" 2>/dev/null | sort -u >> "$categorized_dir/admin_areas.txt"
    local admin_count=$(wc -l < "$categorized_dir/admin_areas.txt" 2>/dev/null || echo 0)
    log "DEBUG" "Found $admin_count admin areas."

    # Upload Endpoints: URLs related to file upload functionalities.
    log "DEBUG" "Categorizing upload endpoints..."
    grep -iE "(upload|file|attach|document|import|export|image|media|assets)" "$validated_alive_urls" 2>/dev/null | sort -u >> "$categorized_dir/upload_endpoints.txt"
    local upload_count=$(wc -l < "$categorized_dir/upload_endpoints.txt" 2>/dev/null || echo 0)
    log "DEBUG" "Found $upload_count upload endpoints."

    # Dynamic Pages: URLs typically handled by server-side scripts (e.g., PHP, ASP).
    log "DEBUG" "Categorizing dynamic pages..."
    grep -E "\.(php|asp|aspx|jsp|cgi|py|rb|pl|cfm|do|action|serv|shtm|shtml)" "$validated_alive_urls" 2>/dev/null | sort -u >> "$categorized_dir/dynamic_pages.txt"
    local dynamic_count=$(wc -l < "$categorized_dir/dynamic_pages.txt" 2>/dev/null || echo 0)
    log "DEBUG" "Found $dynamic_count dynamic pages."

    # URLs with Parameters: Any URL containing a query string (?).
    log "DEBUG" "Categorizing URLs with parameters..."
    grep -E "\?" "$validated_alive_urls" 2>/dev/null | sort -u >> "$categorized_dir/with_params.txt"
    local params_url_count=$(wc -l < "$categorized_dir/with_params.txt" 2>/dev/null || echo 0)
    log "DEBUG" "Found $params_url_count URLs with parameters."

    # Sensitive Files: URLs pointing to potentially sensitive file types or common backup/config files.
    log "DEBUG" "Categorizing sensitive files..."
    grep -iE "(\.txt|\.log|\.conf|\.cfg|\.ini|\.env|\.bak|\.old|\.zip|\.7z|\.db|\.sqlite|\.cache|\.secret|\.config|\.tar|\.gz|\.exe|\.rar|\.xml|\.xhtml|\.code|\.iso|\.dll|\.sh|\.bashrc|\.git|\.svn|id_rsa|passwd|shadow|token|key|private|confidential|backup|dump|creds|credential|password|account|admin_area|development|dev|test)" "$validated_alive_urls" 2>/dev/null | sort -u >> "$categorized_dir/sensitive_files.txt"
    local sensitive_count=$(wc -l < "$categorized_dir/sensitive_files.txt" 2>/dev/null || echo 0)
    log "DEBUG" "Found $sensitive_count sensitive files."

    log "SUCCESS" "URL categorization complete. Results saved in: $categorized_dir"
    return 0
}

# Function: analyze_http_responses()
# Description: Performs detailed analysis of HTTP responses for alive URLs using httpx.
#              Collects status codes, titles, content length, technologies, server headers, etc.
analyze_http_responses() {
    if [ "$ANALYZE_RESPONSES" = false ]; then
        log "INFO" "HTTP response analysis is disabled. Skipping this phase."
        return 0
    fi
    log "INFO" "Starting detailed HTTP response analysis."

    local validated_urls="$OUTPUT_DIR/processed/alive/validated.txt"
    local httpx_details_output="$OUTPUT_DIR/processed/responses/httpx_details.txt"

    # Ensure output file is clean at the start.
    > "$httpx_details_output"

    if [ ! -s "$validated_urls" ]; then
        log "WARNING" "No alive URLs found in '$validated_urls' for response analysis. Skipping."
        return 0
    fi
    local num_urls_to_analyze=$(wc -l < "$validated_urls" 2>/dev/null || echo 0)
    log "INFO" "HTTPX will analyze responses for $num_urls_to_analyze URLs."

    log "DEBUG" "HTTPX command: cat '$validated_urls' | httpx_live -silent -t $THREADS -timeout $TIMEOUT -sc -title -tech-detect -cl -ct -location -server -cdn -probe -websocket -json -o '$httpx_details_output'"
    # Run httpx again, but this time with more verbose output options.
    # -sc: Status Code, -title: Page Title, -tech-detect: Technology Detection,
    # -cl: Content Length, -ct: Content Type, -location: Redirect Location,
    # -server: Server header, -cdn: CDN detection, -probe: For additional HTTP methods.
    # -json: Output in JSON format for easier parsing (though this script just saves it as text).
    cat "$validated_urls" | httpx_live -silent -t "$THREADS" -timeout "$TIMEOUT" \
        -sc -title -tech-detect -cl -ct -location -server -cdn -probe -websocket -json \
        -o "$httpx_details_output" 2>/dev/null
    local httpx_details_status=${PIPESTATUS[1]}

    if [ $httpx_details_status -eq 0 ]; then
        log "SUCCESS" "HTTP response analysis completed."
        log "INFO" "Detailed response information saved to: $httpx_details_output"
        local analyzed_count=$(wc -l < "$httpx_details_output" 2>/dev/null || echo 0)
        log "DEBUG" "$analyzed_count lines of response details recorded."
        if [ "$SILENT" = false ] && [ "$analyzed_count" -gt 0 ]; then
            log "INFO" "Response Details Sample (first 5 lines):"
            head -n 5 "$httpx_details_output" | sed 's/^/    /'
        fi
    else
        log "WARNING" "HTTPX response analysis failed or returned non-zero status ($httpx_details_status)."
        log "WARNING" "Output file '$httpx_details_output' might be incomplete or empty."
    fi

    log "INFO" "HTTP response analysis phase completed."
    return 0
}

# ----------------------------------------------------------------------------------------------------
# Section 11: Reporting
# Functions for generating the final summary report.
# ----------------------------------------------------------------------------------------------------

# Function: generate_report_header()
# Description: Writes the standard header for the summary report.
# Arguments:
#   $1: The report file path.
generate_report_header() {
    local report_file="$1"
    log "DEBUG" "Generating report header for: $report_file"
    echo "==================================================" >> "$report_file"
    echo "       Enhanced Crawl & Discovery Report" >> "$report_file"
    echo "                 by 9x-7ydra" >> "$report_file"
    echo "==================================================" >> "$report_file"
    echo "Date of Report: $(date)" >> "$report_file"
    echo "Output Directory: $OUTPUT_DIR" >> "$report_file"
    echo "--------------------------------------------------" >> "$report_file"
    echo "Tool Settings & Configuration:" >> "$report_file"
    echo "  Threads Configured: $THREADS (Note: JS Analysis runs sequentially)" >> "$report_file"
    echo "  Crawling Depth: $DEPTH" >> "$report_file"
    echo "  Rate Limit (RPS): $RATE_LIMIT" >> "$report_file"
    echo "  Request Timeout (s): $TIMEOUT" >> "$report_file"
    echo "  User-Agent: '$USER_AGENT'" >> "$report_file"
    if [ -n "$CUSTOM_HEADERS" ]; then
        echo "  Custom Headers: '$CUSTOM_HEADERS'" >> "$report_file"
    else
        echo "  Custom Headers: None" >> "$report_file"
    fi
    echo "  Aggressive Mode: $( [ "$AGGRESSIVE" = true ] && echo "Enabled" || echo "Disabled" )" >> "$report_file"
    echo "  Deep JS Analysis: $( [ "$JS_ANALYSIS" = true ] && echo "Enabled" || echo "Disabled" )" >> "$report_file"
    echo "  Parameter Fuzzing: $( [ "$FUZZ_PARAMS" = true ] && echo "Enabled" || echo "Disabled" )" >> "$report_file"
    echo "  Extract Secrets: $( [ "$EXTRACT_SECRETS" = true ] && echo "Enabled" || echo "Disabled" )" >> "$report_file"
    echo "  URL Validation: $( [ "$VALIDATE_URLS" = true ] && echo "Enabled" || echo "Disabled" )" >> "$report_file"
    echo "  Include Static Files: $( [ "$FILTER_EXTENSIONS" = false ] && echo "Enabled" || echo "Disabled" )" >> "$report_file"
    echo "  Response Analysis: $( [ "$ANALYZE_RESPONSES" = true ] && echo "Enabled" || echo "Disabled" )" >> "$report_file"
    echo "  Debug Mode: $( [ "$DEBUG" = true ] && echo "Enabled" || echo "Disabled" )" >> "$report_file"
    echo "  Silent Mode: $( [ "$SILENT" = true ] && echo "Enabled" || echo "Disabled" )" >> "$report_file"
    echo "--------------------------------------------------" >> "$report_file"
    log "DEBUG" "Report header generation complete."
}

# Function: get_file_line_count()
# Description: Helper to safely get the line count of a file, returning 0 if file is empty or not found.
# Arguments:
#   $1: File path.
# Returns: Line count (integer).
get_file_line_count() {
    local file_path="$1"
    if [ -f "$file_path" ]; then
        wc -l < "$file_path" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

# Function: generate_report_counts()
# Description: Compiles and writes various counts of discovered artifacts to the report.
# Arguments:
#   $1: The report file path.
generate_report_counts() {
    local report_file="$1"
    log "DEBUG" "Compiling and writing discovery counts to report."

    echo "Discovery Statistics:" >> "$report_file"

    local initial_valid_urls_count=$(get_file_line_count "$TEMP_DIR/valid_urls.txt")
    echo "  Initial Valid Input URLs: $initial_valid_urls_count" >> "$report_file"

    local passive_urls_count=$(get_file_line_count "$OUTPUT_DIR/raw/passive_combined.txt")
    echo "  Passive Collected URLs (GAU, Wayback, Hakrawler): $passive_urls_count" >> "$report_file"

    local active_katana_urls_count=$(get_file_line_count "$OUTPUT_DIR/raw/katana/all.txt")
    echo "  Active Crawled URLs (Katana): $active_katana_urls_count" >> "$report_file"

    local total_urls_pre_validation=$(get_file_line_count "$OUTPUT_DIR/processed/all_urls.txt")
    echo "  Total Unique URLs (Pre-Validation): $total_urls_pre_validation" >> "$report_file"

    local alive_urls_count=$(get_file_line_count "$OUTPUT_DIR/processed/alive/validated.txt")
    echo "  Confirmed Alive URLs: $alive_urls_count" >> "$report_file"

    local js_files_found_count=$(get_file_line_count "$OUTPUT_DIR/javascript/files/all_js.txt")
    echo "  Total JavaScript Files Identified: $js_files_found_count" >> "$report_file"

    local obfuscated_js_count=$(get_file_line_count "$OUTPUT_DIR/javascript/obfuscated_js.txt")
    echo "  Potentially Obfuscated JS Files: $obfuscated_js_count" >> "$report_file"

    local js_endpoints_count=$(get_file_line_count "$OUTPUT_DIR/javascript/endpoints/full_urls.txt")
    echo "  Endpoints/URLs Found in JS: $js_endpoints_count" >> "$report_file"

    local js_comments_count=$(get_file_line_count "$OUTPUT_DIR/javascript/comments/all.txt")
    echo "  Comments Extracted from JS: $js_comments_count" >> "$report_file"

    local secrets_grep_count=$(get_file_line_count "$OUTPUT_DIR/javascript/secrets/extracted_grep.txt")
    echo "  Potential Secrets (Grep): $secrets_grep_count" >> "$report_file"

    local secrets_secretfinder_count=$(get_file_line_count "$OUTPUT_DIR/secrets/secretfinder_all.txt")
    echo "  Potential Secrets (SecretFinder.py): $secrets_secretfinder_count" >> "$report_file"

    local unique_params_count=$(get_file_line_count "$OUTPUT_DIR/parameters/all_parameters.txt")
    echo "  Total Unique Parameters Discovered: $unique_params_count" >> "$report_file"

    local api_endpoints_count=$(get_file_line_count "$OUTPUT_DIR/processed/categorized/api_endpoints.txt")
    echo "  Categorized: API Endpoints: $api_endpoints_count" >> "$report_file"

    local admin_areas_count=$(get_file_line_count "$OUTPUT_DIR/processed/categorized/admin_areas.txt")
    echo "  Categorized: Admin/Login Areas: $admin_areas_count" >> "$report_file"

    local upload_endpoints_count=$(get_file_line_count "$OUTPUT_DIR/processed/categorized/upload_endpoints.txt")
    echo "  Categorized: Upload Endpoints: $upload_endpoints_count" >> "$report_file"

    local dynamic_pages_count=$(get_file_line_count "$OUTPUT_DIR/processed/categorized/dynamic_pages.txt")
    echo "  Categorized: Dynamic Pages: $dynamic_pages_count" >> "$report_file"

    local urls_with_params_count=$(get_file_line_count "$OUTPUT_DIR/processed/categorized/with_params.txt")
    echo "  Categorized: URLs With Parameters: $urls_with_params_count" >> "$report_file"

    local sensitive_files_count=$(get_file_line_count "$OUTPUT_DIR/processed/categorized/sensitive_files.txt")
    echo "  Categorized: Potentially Sensitive Files: $sensitive_files_count" >> "$report_file"

    echo "--------------------------------------------------" >> "$report_file"
    log "DEBUG" "Discovery counts written to report."
}

# Function: generate_report_key_files()
# Description: Lists the paths to the most important output files for quick reference.
# Arguments:
#   $1: The report file path.
generate_report_key_files() {
    local report_file="$1"
    log "DEBUG" "Listing key output file paths in report."

    echo "Key Output Files for Further Analysis:" >> "$report_file"
    echo "  - Core Logs: $(basename "$OUTPUT_DIR")/crawl.log" >> "$report_file"
    echo "  - All Discovered URLs (Pre-Validation): $(basename "$OUTPUT_DIR")/processed/all_urls.txt" >> "$report_file"
    echo "  - Confirmed Alive URLs: $(basename "$OUTPUT_DIR")/processed/alive/validated.txt" >> "$report_file"
    echo "  - Detailed HTTP Response Info: $(basename "$OUTPUT_DIR")/processed/responses/httpx_details.txt" >> "$report_file"
    echo "  - All Unique Parameters: $(basename "$OUTPUT_DIR")/parameters/all_parameters.txt" >> "$report_file"
    echo "  - JS Extracted Endpoints (Full URLs): $(basename "$OUTPUT_DIR")/javascript/endpoints/full_urls.txt" >> "$report_file"
    echo "  - JS Extracted Secrets (Grep-based): $(basename "$OUTPUT_DIR")/javascript/secrets/extracted_grep.txt" >> "$report_file"
    echo "  - JS Extracted Secrets (SecretFinder.py): $(basename "$OUTPUT_DIR")/secrets/secretfinder_all.txt" >> "$report_file"
    echo "  - Potentially Obfuscated JS URLs: $(basename "$OUTPUT_DIR")/javascript/obfuscated_js.txt" >> "$report_file"
    echo "  - Beautified JS Files: $(basename "$OUTPUT_DIR")/javascript/beautified/" >> "$report_file"
    echo "  - Extracted JS Comments: $(basename "$OUTPUT_DIR")/javascript/comments/all.txt" >> "$report_file"
    echo "  - Categorized URLs Directory: $(basename "$OUTPUT_DIR")/processed/categorized/" >> "$report_file"
    echo "    - API Endpoints: .../categorized/api_endpoints.txt" >> "$report_file"
    echo "    - Admin Areas: .../categorized/admin_areas.txt" >> "$report_file"
    echo "    - Upload Endpoints: .../categorized/upload_endpoints.txt" >> "$report_file"
    echo "    - Sensitive Files: .../categorized/sensitive_files.txt" >> "$report_file"
    echo "--------------------------------------------------" >> "$report_file"
    log "DEBUG" "Key output files listed in report."
}

# Function: generate_report_conclusion()
# Description: Adds a concluding message and final separator to the report.
# Arguments:
#   $1: The report file path.
generate_report_conclusion() {
    local report_file="$1"
    log "DEBUG" "Adding report conclusion."
    echo "End of Report." >> "$report_file"
    echo "==================================================" >> "$report_file"
    echo "" >> "$report_file" # Add a newline for better readability
    log "DEBUG" "Report conclusion added."
}

# Function: generate_report()
# Description: Main function to orchestrate the generation of the full summary report.
generate_report() {
    log "INFO" "Initiating summary report generation."
    local report_file="$OUTPUT_DIR/reports/summary.txt"

    # Ensure the report file is cleared before writing new content.
    > "$report_file"
    log "DEBUG" "Report file '$report_file' cleared for new content."

    generate_report_header "$report_file"
    generate_report_counts "$report_file"
    generate_report_key_files "$report_file"
    generate_report_conclusion "$report_file"

    log "SUCCESS" "Comprehensive summary report generated: $report_file"

    # If not in silent mode, display the generated report content to the console.
    if [ "$SILENT" = false ]; then
        log "INFO" "Displaying summary report content to console:"
        cat "$report_file"
    fi
    return 0
}

# ----------------------------------------------------------------------------------------------------
# Section 12: Main Execution Flow
# The primary function that orchestrates all phases of the reconnaissance.
# ----------------------------------------------------------------------------------------------------

# Function: main()
# Description: The entry point of the script.
#              Orchestrates the entire reconnaissance workflow from setup to reporting.
# Arguments:
#   $@: All command-line arguments passed to the script.
main() {
    log "INFO" "Freedom: Enhanced URL Crawling & Parameter Discovery Engine - Script Start"

    # --- Phase 1: Initialization and Setup ---
    print_banner                        # Display the welcome banner.
    parse_args "$@"                     # Parse all command-line arguments and set globals.
    setup_directories                   # Create the necessary output directory structure.
    check_tools                         # Verify all external tool dependencies.

    # Process initial input URLs (from -u, -f, or stdin).
    # This function returns the path to a temporary file containing validated input URLs.
    local initial_valid_urls_file=$(process_input)
    if [ -z "$initial_valid_urls_file" ] || [ ! -s "$initial_valid_urls_file" ]; then
        log "ERROR" "Failed to acquire valid input URLs. Exiting reconnaissance process."
        exit 1
    fi
    log "INFO" "Input URLs successfully prepared: $initial_valid_urls_file"

    # --- Phase 2: URL Collection and Discovery ---
    log "INFO" "Beginning URL collection phase."
    # Passive collection using public archives.
    enhanced_passive_collection "$initial_valid_urls_file"
    # Active crawling on the target.
    enhanced_active_crawling "$initial_valid_urls_file"
    log "INFO" "URL collection phase completed."

    # --- Phase 3: Deep JavaScript Analysis ---
    if [ "$JS_ANALYSIS" = true ]; then
        log "INFO" "Beginning deep JavaScript analysis phase."
        deep_javascript_analysis
        log "INFO" "Deep JavaScript analysis phase completed."
    else
        log "INFO" "Deep JavaScript analysis is disabled by configuration."
    fi

    # --- Phase 4: Parameter Discovery and Fuzzing ---
    log "INFO" "Beginning parameter discovery phase."
    enhanced_parameter_discovery
    log "INFO" "Parameter discovery phase completed."

    # --- Phase 5: Post-Reconnaissance Analysis ---
    log "INFO" "Beginning post-reconnaissance analysis phase (validation, categorization, response analysis)."
    validate_and_categorize
    if [ "$ANALYZE_RESPONSES" = true ]; then
        analyze_http_responses
    else
        log "INFO" "HTTP response analysis is disabled by configuration."
    fi
    log "INFO" "Post-reconnaissance analysis phase completed."

    # --- Phase 6: Reporting ---
    log "INFO" "Generating final reconnaissance report."
    generate_report
    log "INFO" "Final report generation completed."

    log "SUCCESS" "Freedom: Enhanced URL Crawling & Parameter Discovery - All phases completed successfully!"
    log "INFO" "Please review the '$OUTPUT_DIR' directory for all generated findings and reports."
}

# --- Execute the main function with all command-line arguments ---
main "$@"
