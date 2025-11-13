#!/bin/bash

# Colors
REDCOLOR='\e[31m'
GREENCOLOR='\e[32m'
YELLOWCOLOR='\e[33m'
BLUECOLOR='\e[34m'
CYANCOLOR='\e[36m'
MAGENTACOLOR='\e[35m'
WHITECOLOR='\e[37m'
RESETCOLOR='\e[0m'

# ============= GLOBAL VARIABLES (Set after validation) =============
DOMAIN=""
OUTPUT_DIR=""

# ============= LOAD CONFIG AND INITIALIZE =============

# Source config.env file
source config.env

# Initialize Shodan API
shodan init "$SHODAN_API_KEY" >/dev/null 2>&1

display_banner() {
    clear
    echo -e "${CYANCOLOR}   _____       _     _    _             _           ${REDCOLOR}__   __"
    echo -e "${CYANCOLOR}  / ____|     | |   | |  | |           | |          ${REDCOLOR}\\ \\ / /"
    echo -e "${CYANCOLOR} | (___  _   _| |__ | |__| |_   _ _ __ | |_ ___ _ __${REDCOLOR} \\ V / "
    echo -e "${CYANCOLOR}  \\___ \\| | | | '_ \\|  __  | | | | '_ \\| __/ _ \\ '__|${REDCOLOR} > <  "
    echo -e "${CYANCOLOR}  ____) | |_| | |_) | |  | | |_| | | | | ||  __/ |  ${REDCOLOR} / . \\ "
    echo -e "${CYANCOLOR} |_____/ \\__,_|_.__/|_|  |_|\\__,_|_| |_|\\__\\___|_| ${REDCOLOR} /_/ \\_\\"
    echo -e "${RESETCOLOR}"
    echo -e "${YELLOWCOLOR}         ═══════════════════════════════════════════${RESETCOLOR}"
    echo -e "${GREENCOLOR}                    v2 ~  with <3 by @who0xac             ${RESETCOLOR}"
    echo -e "${YELLOWCOLOR}         ═══════════════════════════════════════════${RESETCOLOR}"
    echo -e ""
}

show_help() {
    display_banner
    echo -e "${YELLOWCOLOR}Usage:${RESETCOLOR}"
    echo -e "  $0 <domain>"
    echo -e ""
    echo -e "${YELLOWCOLOR}Options:${RESETCOLOR}"
    echo -e "  -h, --help     Show this help message"
    echo -e "  -c, --check    Check if all required tools are installed"
    echo -e ""
    echo -e "${YELLOWCOLOR}Example:${RESETCOLOR}"
    echo -e "  $0 example.com"
    echo -e ""
}

check_tools() {
    # Check if required tools are installed
    echo -e "${YELLOWCOLOR}[${RESETCOLOR} ${WHITECOLOR}Checking Required Tools Installation${RESETCOLOR} ${YELLOWCOLOR}]${RESETCOLOR}"
    echo -e ""

    tools=(amass subfinder findomain assetfinder sublist3r httpx ffuf  dirsearch shodan crtsh puredns gau gowitness massdns katana chaos dnsx gf jq subzy secretfinder nmap nuclei)
    missing_tools=()
    total=${#tools[@]}
    count=0

    echo -e "${BLUECOLOR}Checking $total tools...${RESETCOLOR}"
    echo -e ""

    for tool in "${tools[@]}"; do
      ((count++))

      if command -v "$tool" >/dev/null 2>&1; then
        # installed -> print in green
        echo -e "${BLUECOLOR}▶${RESETCOLOR} $tool : ${GREENCOLOR}[✓]${RESETCOLOR}"
      else
        # not installed -> print in red and add to missing list
        echo -e "${BLUECOLOR}▶${RESETCOLOR} $tool : ${REDCOLOR}[✗]${RESETCOLOR}"
        missing_tools+=("$tool")
      fi
    done

    echo -e ""
    echo -e "${YELLOWCOLOR}════════════════════════════════════════════════════════════${RESETCOLOR}"
    echo -e ""

    if (( ${#missing_tools[@]} == 0 )); then
      echo -e "${GREENCOLOR}[✓] All tools are installed successfully!${RESETCOLOR}"
      echo -e ""
      return 0
    else
      echo -e "${REDCOLOR}[✗] Missing (${#missing_tools[@]}): ${missing_tools[*]}${RESETCOLOR}"
      echo -e "${REDCOLOR}[✗] Please install the missing tools and re-run the script.${RESETCOLOR}"
      echo -e ""
      return 1
    fi
}

validate_domain() {
    # Input and directories
    local domain="$1"
    local output_dir="/root/Desktop/${domain}"

    mkdir -p "$output_dir" || {
        echo -e "${REDCOLOR}[✗] Failed to create output directory${RESETCOLOR}"
        return 1
    }

    echo -e "${BLUECOLOR}[+] Target domain: ${domain}${RESETCOLOR}"
    echo -e "${BLUECOLOR}[+] Output directory: ${output_dir}${RESETCOLOR}"
    echo -e ""

    # Extract TLD
    tld=$(echo "$domain" | sed -E 's/.*\.([a-zA-Z]{2,3}(\.[a-zA-Z]{2,3})?)$/\1/')
    echo -e "${YELLOWCOLOR}[+] Detected TLD: ${tld}${RESETCOLOR}"
    echo -e ""

    return 0
}

start_enumeration() {
    # Start time
    start_time=$(date)
    echo -e "${YELLOWCOLOR}[+] Recon started at: ${start_time}${RESETCOLOR}"
    echo -e ""

    ### Subdomain Enumeration ###
    echo -e "${YELLOWCOLOR}[${RESETCOLOR} ${WHITECOLOR}Starting Subdomain Enumeration${RESETCOLOR} ${YELLOWCOLOR}]${RESETCOLOR}"
    echo -e ""

    echo -e "${REDCOLOR}[+] Enumerating Subdomains...${RESETCOLOR}"
    echo -e ""

    echo -e "${BLUECOLOR}[+] Running Amass...${RESETCOLOR}"
    NO_COLOR=1 amass enum -active -d "$DOMAIN" -config "$AMASS_CONFIG" -rf "$RESOLVERS" -o "$OUTPUT_DIR/amass.txt" || true
    echo -e ""

    echo -e "${BLUECOLOR}[+] Running Subfinder...${RESETCOLOR}"
    # Rate limit: 30 req/s
    subfinder -d "$DOMAIN" -o "$OUTPUT_DIR/subfinder.txt" -rate-limit 30 || true
    echo -e ""

    echo -e "${BLUECOLOR}[+] Running Findomain...${RESETCOLOR}"
    findomain -t "$DOMAIN" --quiet | tee "$OUTPUT_DIR/findomain.txt" || true
    echo -e ""

    echo -e "${BLUECOLOR}[+] Running Assetfinder...${RESETCOLOR}"
    assetfinder -subs-only "$DOMAIN" | tee "$OUTPUT_DIR/assetfinder.txt" || true
    echo -e ""

    echo -e "${BLUECOLOR}[+] Running Sublist3r...${RESETCOLOR}"
    sublist3r -d "$DOMAIN" -e baidu,yahoo,google,bing,ask,netcraft,threatcrowd,ssl,passivedns -o "$OUTPUT_DIR/sublist3r.txt" 2>/dev/null || true
    echo -e ""

    echo -e "${BLUECOLOR}[+] Running Chaos...${RESETCOLOR}"
    chaos -key "$CHAOS_API_KEY" -d "$DOMAIN" -o "$OUTPUT_DIR/chaos.txt" || true
    echo -e ""

    echo -e "${BLUECOLOR}[+] Running Crtsh...${RESETCOLOR}"
    crtsh -d "$DOMAIN" -r > "$OUTPUT_DIR/crtsh.txt" 2>&1 || true
    cat "$OUTPUT_DIR/crtsh.txt" || true
    echo -e ""

    echo -e "${BLUECOLOR}[+] Running Shodan...${RESETCOLOR}"
    shodan search --fields hostnames ssl:"$DOMAIN" --limit 0 | tr ';' '\n' | tee "$OUTPUT_DIR/shodan.txt" || true
    echo -e ""

    echo -e "${BLUECOLOR}[+] Running Puredns Bruteforce...${RESETCOLOR}"
    puredns bruteforce "$WORDLISTS" "$DOMAIN" -r "$RESOLVERS" -t 500 -w "$OUTPUT_DIR/puredns.txt" || true
    echo -e ""
}

merge_and_clean_subdomains() {
    ### Merging and Cleaning Subdomains ###
    echo -e "${YELLOWCOLOR}[${RESETCOLOR} ${WHITECOLOR}Merging and Cleaning Subdomains${RESETCOLOR} ${YELLOWCOLOR}]${RESETCOLOR}"
    echo -e ""

    echo -e "${REDCOLOR}[+] Merging and cleaning subdomains...${RESETCOLOR}"

    # Clean amass output (remove ANSI codes, convert to lowercase, remove trailing dots)
    if [ -f "$OUTPUT_DIR/amass.txt" ]; then
        grep -Eo "([a-zA-Z0-9_-]+\.)+${DOMAIN//./\\.}" "$OUTPUT_DIR/amass.txt" \
            | sed -E "s/\x1B\[[0-9;]*[mK]//g" | tr '[:upper:]' '[:lower:]' | sed 's/\.$//' > "$OUTPUT_DIR/amass_cleaned.txt" || true
    else
        touch "$OUTPUT_DIR/amass_cleaned.txt"
    fi

    # Merge all subdomain files
    sort -u "$OUTPUT_DIR/amass_cleaned.txt" \
            "$OUTPUT_DIR/assetfinder.txt" \
            "$OUTPUT_DIR/chaos.txt" \
            "$OUTPUT_DIR/findomain.txt" \
            "$OUTPUT_DIR/subfinder.txt" \
            "$OUTPUT_DIR/sublist3r.txt" \
            "$OUTPUT_DIR/crtsh.txt" \
            "$OUTPUT_DIR/shodan.txt" \
            "$OUTPUT_DIR/puredns.txt" 2>/dev/null \
        | tr '[:upper:]' '[:lower:]' \
        | sed 's/\.$//' \
        | grep -E "^([a-zA-Z0-9_-]+\.)+${DOMAIN//./\\.}$" \
        > "$OUTPUT_DIR/all_subdomains.txt" || true

    total_subdomains=$(wc -l < "$OUTPUT_DIR/all_subdomains.txt" 2>/dev/null || echo "0")
    echo -e "${GREENCOLOR}[✓] Total unique subdomains found: ${total_subdomains}${RESETCOLOR}"
    echo -e ""
}

probe_live_hosts() {
    ### Probing Live Hosts ###
    echo -e "${YELLOWCOLOR}[${RESETCOLOR} ${WHITECOLOR}Probing Live Hosts with HTTPX${RESETCOLOR} ${YELLOWCOLOR}]${RESETCOLOR}"
    echo -e ""

    echo -e "${REDCOLOR}[+] Probing subdomains for live hosts...${RESETCOLOR}"
    echo -e ""

    if [ ! -f "$OUTPUT_DIR/all_subdomains.txt" ]; then
        echo -e "${REDCOLOR}[✗] all_subdomains.txt not found!${RESETCOLOR}"
        return 1
    fi

    # Rate limit: 150 threads, 50 req/s
    httpx -l "$OUTPUT_DIR/all_subdomains.txt" -sc -mc 200,301,302,403,500 -fr -td -location -o "$OUTPUT_DIR/httpx_results.txt" -threads 150 -rate-limit 50 -http-proxy socks5://127.0.0.1:9050 | tee >(awk '{print $1}' > "$OUTPUT_DIR/live_urls.txt") || true

    echo -e ""

    live_count=$(wc -l < "$OUTPUT_DIR/live_urls.txt" 2>/dev/null || echo "0")
    echo -e "${GREENCOLOR}[✓] Live hosts found: ${live_count}${RESETCOLOR}"
    echo -e "${BLUECOLOR}[+] Full results saved to: httpx_results.txt${RESETCOLOR}"
    echo -e "${BLUECOLOR}[+] Live URLs saved to: live_urls.txt${RESETCOLOR}"
    echo -e ""
}

resolve_ips() {
    ### Resolving IPs ###
    echo -e "${YELLOWCOLOR}[${RESETCOLOR} ${WHITECOLOR}Resolving IP Addresses${RESETCOLOR} ${YELLOWCOLOR}]${RESETCOLOR}"
    echo -e ""

    if [ ! -f "$OUTPUT_DIR/live_urls.txt" ]; then
        echo -e "${REDCOLOR}[✗] live_urls.txt not found!${RESETCOLOR}"
        return 1
    fi

    echo -e "${REDCOLOR}[+] Resolving IP addresses for live hosts...${RESETCOLOR}"
    echo -e ""

    # Extract hostnames from URLs (remove http/https and path)
    sed -E 's|^https?://||; s|/.*$||' "$OUTPUT_DIR/live_urls.txt" > "$OUTPUT_DIR/live_hostnames.txt" || true

    # Use dnsx to resolve IPs
    # Rate limit: 100 threads
    echo -e "${BLUECOLOR}[+] Running dnsx for IP resolution...${RESETCOLOR}"
    dnsx -l "$OUTPUT_DIR/live_hostnames.txt" -a -resp -o "$OUTPUT_DIR/resolved_ips.txt" -t 100 || true

    echo -e ""

    resolved_count=$(wc -l < "$OUTPUT_DIR/resolved_ips.txt" 2>/dev/null || echo "0")
    echo -e "${GREENCOLOR}[✓] IPs resolved: ${resolved_count}${RESETCOLOR}"
    echo -e "${BLUECOLOR}[+] Results saved to: resolved_ips.txt${RESETCOLOR}"
    echo -e ""
}

check_subdomain_takeover() {
    ### Subdomain Takeover Check ###
    echo -e "${YELLOWCOLOR}[${RESETCOLOR} ${WHITECOLOR}Checking for Subdomain Takeover${RESETCOLOR} ${YELLOWCOLOR}]${RESETCOLOR}"
    echo -e ""

    if [ ! -f "$OUTPUT_DIR/all_subdomains.txt" ]; then
        echo -e "${REDCOLOR}[✗] all_subdomains.txt not found!${RESETCOLOR}"
        return 1
    fi

    echo -e "${REDCOLOR}[+] Running Subzy for subdomain takeover detection...${RESETCOLOR}"
    echo -e ""

    # Rate limit: 100 concurrent (already set in original)
    subzy run --targets "$OUTPUT_DIR/all_subdomains.txt" --concurrency 100 --hide_fails --verify_ssl > "$OUTPUT_DIR/subdomain_takeover.txt" || true

    echo -e ""
    echo -e "${GREENCOLOR}[✓] Subdomain takeover check completed!${RESETCOLOR}"
    echo -e "${BLUECOLOR}[+] Results saved to: subdomain_takeover.txt${RESETCOLOR}"
    echo -e ""
}

find_api_endpoints() {
    local api_dir="$OUTPUT_DIR/api"

    ### Finding API Endpoints ###
    echo -e "${YELLOWCOLOR}[${RESETCOLOR} ${WHITECOLOR}Finding API Endpoints${RESETCOLOR} ${YELLOWCOLOR}]${RESETCOLOR}"
    echo -e ""

    if [ ! -f "$OUTPUT_DIR/live_urls.txt" ]; then
        echo -e "${REDCOLOR}[✗] live_urls.txt not found!${RESETCOLOR}"
        return 1
    fi

    # Create API directory
    mkdir -p "$api_dir"
    echo -e "${BLUECOLOR}[+] Created API directory: ${api_dir}${RESETCOLOR}"
    echo -e ""

    echo -e "${REDCOLOR}[+] Searching for API endpoints in live URLs...${RESETCOLOR}"

    # Search for API patterns in URLs
    grep -iE "(api|v[0-9]+|graphql|rest|swagger|openapi)" "$OUTPUT_DIR/live_urls.txt" > "$api_dir/api_urls.txt" 2>/dev/null || touch "$api_dir/api_urls.txt"

    api_count=$(wc -l < "$api_dir/api_urls.txt" 2>/dev/null || echo "0")
    echo -e "${GREENCOLOR}[✓] API endpoints found: ${api_count}${RESETCOLOR}"
    echo -e "${BLUECOLOR}[+] API URLs saved to: api/api_urls.txt${RESETCOLOR}"
    echo -e ""
}

directory_bruteforce() {
    local dirsearch_dir="$OUTPUT_DIR/dirsearch"
    
    ### Directory Bruteforce ###
    echo -e "${YELLOWCOLOR}[${RESETCOLOR} ${WHITECOLOR}Running Directory Bruteforce${RESETCOLOR} ${YELLOWCOLOR}]${RESETCOLOR}"
    echo -e ""
    
    if [ ! -f "$OUTPUT_DIR/live_urls.txt" ]; then
        echo -e "${REDCOLOR}[✗] live_urls.txt not found!${RESETCOLOR}"
        return 1
    fi
    
    # Create dirsearch directory
    mkdir -p "$dirsearch_dir"
    echo -e "${BLUECOLOR}[+] Created directory: ${dirsearch_dir}${RESETCOLOR}"
    echo -e ""
    
    live_count=$(wc -l < "$OUTPUT_DIR/live_urls.txt")
    echo -e "${BLUECOLOR}[+] Running dirsearch on ${live_count} live URLs...${RESETCOLOR}"
    echo -e ""
    
    counter=0
    
    while IFS= read -r url; do
        ((counter++))
        safe_url=$(echo "$url" | tr '/:' '_')
        output_file="$dirsearch_dir/${safe_url}.txt"
        
        echo -e "${CYANCOLOR}[$counter/$live_count]${RESETCOLOR} ${BLUECOLOR}Scanning: ${url}${RESETCOLOR}"
        echo -e ""
        
        # Run dirsearch with live output AND save to file
        dirsearch -u "$url" -x 500,502,429,404,400 -R 5 --random-agent -t 100 -F -o "$output_file" --delay 0 2>&1 | tee -a "$output_file"
        
        echo -e ""
        echo -e "${GREENCOLOR}[✓] Scan completed for ${url}${RESETCOLOR}"
        echo -e "${BLUECOLOR}[+] Results saved to: ${output_file}${RESETCOLOR}"
        echo -e ""
        echo -e "${YELLOWCOLOR}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESETCOLOR}"
        echo -e ""
        
    done < "$OUTPUT_DIR/live_urls.txt"
    
    echo -e "${GREENCOLOR}[✓] All directory bruteforce scans completed!${RESETCOLOR}"
    echo -e "${BLUECOLOR}[+] All results saved in: ${dirsearch_dir}/${RESETCOLOR}"
    echo -e ""
}

ffuf_bruteforce() {
    local ffuf_output="$OUTPUT_DIR/ffuf_results.txt"
    
    ### FFUF Bruteforce ###
    echo -e "${YELLOWCOLOR}[${RESETCOLOR} ${WHITECOLOR}Running FFUF Bruteforce${RESETCOLOR} ${YELLOWCOLOR}]${RESETCOLOR}"
    echo -e ""
    
    if [ ! -f "$OUTPUT_DIR/live_urls.txt" ]; then
        echo -e "${REDCOLOR}[✗] live_urls.txt not found!${RESETCOLOR}"
        return 1
    fi
    
    # Clear/create the output file
    > "$ffuf_output"
    echo -e "${BLUECOLOR}[+] Output file: ${ffuf_output}${RESETCOLOR}"
    echo -e ""
    
    live_count=$(wc -l < "$OUTPUT_DIR/live_urls.txt")
    echo -e "${BLUECOLOR}[+] Running FFUF on ${live_count} live URLs...${RESETCOLOR}"
    echo -e ""
    
    counter=0
    
    while IFS= read -r url; do
        ((counter++))
        
        echo -e "${CYANCOLOR}[$counter/$live_count]${RESETCOLOR} ${BLUECOLOR}Fuzzing: ${url}${RESETCOLOR}"
        echo -e ""
        
        # Run ffuf with live output AND save to file
        ffuf -u "${url}/FUZZ" -w "$FUZZ" -mc 200,301,302,403 -fc 404 -rate 100 2>&1 | tee -a "$ffuf_output"
        
        echo -e ""
        echo -e "${GREENCOLOR}[✓] Fuzzing completed for ${url}${RESETCOLOR}"
        echo -e ""
        echo -e "${YELLOWCOLOR}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESETCOLOR}"
        echo -e ""
        
    done < "$OUTPUT_DIR/live_urls.txt"
    
    echo -e "${GREENCOLOR}[✓] All FFUF scans completed!${RESETCOLOR}"
    echo -e "${BLUECOLOR}[+] All results saved in: ${ffuf_output}${RESETCOLOR}"
    echo -e ""
}

merge_all_urls() {
    sort -u "$OUTPUT_DIR/live_urls.txt" "$OUTPUT_DIR/ffuf_results.txt" 2>/dev/null > "$OUTPUT_DIR/all_discovered_urls.txt" || true
}

url_gathering() {
    ### URL Gathering ###
    echo -e "${YELLOWCOLOR}[${RESETCOLOR} ${WHITECOLOR}URL Gathering (Active & Passive)${RESETCOLOR} ${YELLOWCOLOR}]${RESETCOLOR}"
    echo -e ""

    if [ ! -f "$OUTPUT_DIR/live_urls.txt" ]; then
        echo -e "${REDCOLOR}[✗] live_urls.txt not found!${RESETCOLOR}"
        return 1
    fi

    # Active crawling with Katana
    # Rate limit: 150 req/s, 10 concurrent
    echo -e "${BLUECOLOR}[+] Running Katana (Active Crawling)...${RESETCOLOR}"
    katana -u "$OUTPUT_DIR/live_urls.txt" -d 5 -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o "$OUTPUT_DIR/katana_urls.txt" -rl 150 -c 10 || true
    echo -e ""

    # Rate limit: 10 threads (already set in original)
    echo -e "${BLUECOLOR}[+] Running GAU (Passive URL Gathering)...${RESETCOLOR}"
    cat "$OUTPUT_DIR/all_subdomains.txt" | gau > "$OUTPUT_DIR/gau_urls.txt" || true
    echo -e ""

    # Merge Katana and GAU results
    echo -e "${BLUECOLOR}[+] Merging URLs from Katana and GAU...${RESETCOLOR}"
    sort -u "$OUTPUT_DIR/katana_urls.txt" "$OUTPUT_DIR/gau_urls.txt" 2>/dev/null > "$OUTPUT_DIR/all_gathered_urls.txt" || true

    total_gathered=$(wc -l < "$OUTPUT_DIR/all_gathered_urls.txt" 2>/dev/null || echo "0")
    echo -e "${GREENCOLOR}[✓] Total URLs gathered: ${total_gathered}${RESETCOLOR}"
    echo -e ""

    # Extract JS files
    echo -e "${BLUECOLOR}[+] Extracting JavaScript files...${RESETCOLOR}"
    grep -iE "\.js(\?|$)" "$OUTPUT_DIR/all_gathered_urls.txt" | sort -u > "$OUTPUT_DIR/js_files.txt" 2>/dev/null || touch "$OUTPUT_DIR/js_files.txt"

    js_count=$(wc -l < "$OUTPUT_DIR/js_files.txt" 2>/dev/null || echo "0")
    echo -e "${GREENCOLOR}[✓] JavaScript files found: ${js_count}${RESETCOLOR}"
    echo -e "${BLUECOLOR}[+] JS files saved to: js_files.txt${RESETCOLOR}"
    echo -e ""

    # Find sensitive files and parameters
    echo -e "${BLUECOLOR}[+] Hunting for sensitive files and parameters...${RESETCOLOR}"
    grep -Ei "\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|\.config|\.env|\.crt|\.ini|\.pem|\.bak|\.swp|\.key|\.p12|\.pfx|\.ps1|\.xml|\.csv|\.dat|\.old|\.tar|\.tgz|\.7z|\.asc|\.passwd|\.htpasswd|\.pgp|\.ovpn|\.rc|\.conf|\.cert|\.p7b|\.bash_history|\.zsh_history|\.mysql_history|\.psql_history|\.sqlite3|\.dmp|\.rdp|\.sftp|\.sql|\.plist|\.dockerfile|\.sh|\.bashrc|\.zshrc|\.profile|\.npmrc|\.gitconfig|\.gitignore|\.aws|\.pgpass|\.id_rsa|\.ppk|\.openvpn|\.gpg|\.csr|\.cer|\.apk|\.mobileprovision|\.keystore|\.token|\.cloud|\.envrc|\.bash_aliases|\.my\.cnf|\.netrc|\.enc|\.pem|\.crt|\.ssl|\.cert|api_key|secret|token|auth|password|private|credentials|session|sensitive|access_key|auth_token|client_secret|client_id|admin|user|key_id|account|config|authorization|jwt|bearer|oauth|ssh|ftp|aws|gcp|azure|database|db_pass|db_user|encrypt|decode|hash|salt|signature|cipher|encryption|login|signin|signup|csrf|x_csrf|access_token|refresh_token|master_key|security|backup|recovery|keystore|sid|appid|app_id|consumer_key|consumer_secret|smtp|imap|mail|email|apikey|id_token|auth_key|service_account|firestore|bigquery|storage|cloudfront|billing|payment|stripe|paypal|username|hostname|proxy|proxy_pass|bucket|s3|role_arn|session_token|azure_key|azure_secret|firebase|mongodb|mongo_pass|cloudflare|twilio|plaid|github_token|slack_token|webhook|hook_url|razorpay|linkedin_secret|twitter_secret|facebook_secret|instagram_secret|twilio_sid|twilio_token|twilio_auth" "$OUTPUT_DIR/all_gathered_urls.txt" | sort -u > "$OUTPUT_DIR/sensitive_findings.txt" 2>/dev/null || touch "$OUTPUT_DIR/sensitive_findings.txt"

    sensitive_count=$(wc -l < "$OUTPUT_DIR/sensitive_findings.txt" 2>/dev/null || echo "0")

    if [ "$sensitive_count" -gt 0 ]; then
        echo -e "${GREENCOLOR}[✓] Sensitive findings detected: ${sensitive_count}${RESETCOLOR}"
        echo -e "${REDCOLOR}[!] CRITICAL: Check sensitive_findings.txt for potential security issues!${RESETCOLOR}"
    else
        echo -e "${YELLOWCOLOR}[!] No sensitive findings detected${RESETCOLOR}"
    fi
    echo -e "${BLUECOLOR}[+] Results saved to: sensitive_findings.txt${RESETCOLOR}"
    echo -e ""

    # Probe all gathered URLs with HTTPX
    # Rate limit: 150 threads, 50 req/s
    echo -e "${BLUECOLOR}[+] Probing all gathered URLs with HTTPX...${RESETCOLOR}"
    httpx -l "$OUTPUT_DIR/all_gathered_urls.txt" -mc 200,301,302,403,500 -o "$OUTPUT_DIR/alive_gathered_urls.txt" -threads 150 -rate-limit 50 -http-proxy socks5://127.0.0.1:9050 || true

    alive_count=$(wc -l < "$OUTPUT_DIR/alive_gathered_urls.txt" 2>/dev/null || echo "0")
    echo -e "${GREENCOLOR}[✓] Alive URLs from gathering: ${alive_count}${RESETCOLOR}"
    echo -e "${BLUECOLOR}[+] Results saved to: alive_gathered_urls.txt${RESETCOLOR}"
    echo -e ""

    # Run SecretFinder on JS files
    if [ "$js_count" -gt 0 ]; then
        echo -e "${BLUECOLOR}[+] Running SecretFinder on JavaScript files...${RESETCOLOR}"
        mkdir -p "$OUTPUT_DIR/secretfinder_results"

        counter=0
        while IFS= read -r js_url; do
            ((counter++))
            safe_filename=$(echo "$js_url" | sed 's|https\?://||g' | tr '/:?' '_')

            echo -e "${CYANCOLOR}[$counter/$js_count]${RESETCOLOR} ${BLUECOLOR}Analyzing: ${js_url}${RESETCOLOR}"

            # Small delay between requests (0.5 seconds)
            secretfinder -i "$js_url" -o cli >> "$OUTPUT_DIR/secretfinder_results/${safe_filename}.txt" 2>/dev/null || true
            sleep 0.5

        done < "$OUTPUT_DIR/js_files.txt"

        echo -e ""
        echo -e "${GREENCOLOR}[✓] SecretFinder analysis completed!${RESETCOLOR}"
        echo -e "${BLUECOLOR}[+] Results saved to: secretfinder_results/${RESETCOLOR}"
        echo -e ""
    else
        echo -e "${YELLOWCOLOR}[!] No JS files found, skipping SecretFinder${RESETCOLOR}"
        echo -e ""
    fi
}

gf_pattern_analysis() {
    local gf_dir="$OUTPUT_DIR/gf_patterns"

    ### GF Pattern Analysis ###
    echo -e "${YELLOWCOLOR}[${RESETCOLOR} ${WHITECOLOR}GF Pattern Analysis for Vulnerabilities${RESETCOLOR} ${YELLOWCOLOR}]${RESETCOLOR}"
    echo -e ""

    if [ ! -f "$OUTPUT_DIR/alive_gathered_urls.txt" ]; then
        echo -e "${REDCOLOR}[✗] alive_gathered_urls.txt not found!${RESETCOLOR}"
        return 1
    fi

    local input_file="$OUTPUT_DIR/alive_gathered_urls.txt"

    # Create GF patterns directory
    mkdir -p "$gf_dir"
    echo -e "${BLUECOLOR}[+] Created GF patterns directory: ${gf_dir}${RESETCOLOR}"
    echo -e ""

    echo -e "${REDCOLOR}[+] Running GF patterns for vulnerability detection...${RESETCOLOR}"
    echo -e ""

    # Define patterns array
    patterns=(
        "debug_logic"
        "idor"
        "img-traversal"
        "interestingEXT"
        "interestingparams"
        "interestingsubs"
        "jsvar"
        "lfi"
        "rce"
        "redirect"
        "sqli"
        "ssrf"
        "ssti"
        "xss"
    )

    total_patterns=${#patterns[@]}
    counter=0
    total_findings=0

    # Run each GF pattern
    for pattern in "${patterns[@]}"; do
        ((counter++))

        echo -e "${CYANCOLOR}[$counter/$total_patterns]${RESETCOLOR} ${BLUECOLOR}Running pattern: ${pattern}${RESETCOLOR}"

        # Run gf pattern and save to file
        cat "$input_file" | gf "$pattern" > "$gf_dir/${pattern}.txt" 2>/dev/null || touch "$gf_dir/${pattern}.txt"

        # Count findings
        finding_count=$(wc -l < "$gf_dir/${pattern}.txt" 2>/dev/null || echo "0")

        if [ "$finding_count" -gt 0 ]; then
            echo -e "  ${GREENCOLOR}✓ Found: ${finding_count} potential vulnerabilities${RESETCOLOR}"
            ((total_findings += finding_count))
        else
            echo -e "  ${YELLOWCOLOR}✗ No findings${RESETCOLOR}"
        fi
    done

    echo -e ""
    echo -e "${YELLOWCOLOR}════════════════════════════════════════════════════════════${RESETCOLOR}"
    echo -e ""

    # Summary
    echo -e "${MAGENTACOLOR}[+] GF Pattern Analysis Summary:${RESETCOLOR}"
    echo -e ""

    for pattern in "${patterns[@]}"; do
        count=$(wc -l < "$gf_dir/${pattern}.txt" 2>/dev/null || echo "0")

        if [ "$count" -gt 0 ]; then
            # Highlight critical patterns in red
            if [[ "$pattern" =~ ^(sqli|xss|rce|lfi|ssrf|ssti)$ ]]; then
                echo -e "  ${REDCOLOR}[!] ${pattern}: ${count} findings${RESETCOLOR}"
            else
                echo -e "  ${GREENCOLOR}[+] ${pattern}: ${count} findings${RESETCOLOR}"
            fi
        fi
    done

    echo -e ""
    echo -e "${GREENCOLOR}[✓] Total findings across all patterns: ${total_findings}${RESETCOLOR}"
    echo -e "${BLUECOLOR}[+] Results saved to: gf_patterns/${RESETCOLOR}"
    echo -e ""

    # Create a combined high-priority findings file
    echo -e "${BLUECOLOR}[+] Creating combined critical findings file...${RESETCOLOR}"
    cat "$gf_dir/sqli.txt" \
        "$gf_dir/xss.txt" \
        "$gf_dir/rce.txt" \
        "$gf_dir/lfi.txt" \
        "$gf_dir/ssrf.txt" \
        "$gf_dir/ssti.txt" \
        2>/dev/null | sort -u > "$gf_dir/critical_findings.txt" || true

    critical_count=$(wc -l < "$gf_dir/critical_findings.txt" 2>/dev/null || echo "0")

    if [ "$critical_count" -gt 0 ]; then
        echo -e "${REDCOLOR}[!] CRITICAL: ${critical_count} high-priority vulnerabilities detected!${RESETCOLOR}"
        echo -e "${REDCOLOR}[!] Review critical_findings.txt immediately!${RESETCOLOR}"
    else
        echo -e "${GREENCOLOR}[✓] No critical vulnerabilities detected${RESETCOLOR}"
    fi

    echo -e "${BLUECOLOR}[+] Critical findings saved to: gf_patterns/critical_findings.txt${RESETCOLOR}"
    echo -e ""
}

port_scanning() {
    local portscan_dir="$OUTPUT_DIR/port_scanning"

    ### Port Scanning with Nmap ###
    echo -e "${YELLOWCOLOR}[${RESETCOLOR} ${WHITECOLOR}Port Scanning with Nmap${RESETCOLOR} ${YELLOWCOLOR}]${RESETCOLOR}"
    echo -e ""

    if [ ! -f "$OUTPUT_DIR/resolved_ips.txt" ]; then
        echo -e "${REDCOLOR}[✗] resolved_ips.txt not found!${RESETCOLOR}"
        return 1
    fi

    # Create port scanning directory
    mkdir -p "$portscan_dir"
    echo -e "${BLUECOLOR}[+] Created port scanning directory: ${portscan_dir}${RESETCOLOR}"
    echo -e ""

    # Extract unique IPs from resolved_ips.txt
    echo -e "${BLUECOLOR}[+] Extracting unique IP addresses...${RESETCOLOR}"
    grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$OUTPUT_DIR/resolved_ips.txt" | sort -u > "$portscan_dir/unique_ips.txt" || true

    ip_count=$(wc -l < "$portscan_dir/unique_ips.txt" 2>/dev/null || echo "0")
    echo -e "${GREENCOLOR}[✓] Unique IPs to scan: ${ip_count}${RESETCOLOR}"
    echo -e ""

    if [ "$ip_count" -eq 0 ]; then
        echo -e "${REDCOLOR}[✗] No IPs found to scan!${RESETCOLOR}"
        return 1
    fi

    echo -e "${REDCOLOR}[+] Running Nmap on all ports with technology detection...${RESETCOLOR}"
    echo -e "${YELLOWCOLOR}[!] This may take a while depending on the number of IPs...${RESETCOLOR}"
    echo -e ""

    # Run Nmap: Rate limit with min-rate 1000 (medium speed, already set in original)
    nmap -p- -sV -sC -T4 --open -iL "$portscan_dir/unique_ips.txt" -oA "$portscan_dir/nmap_scan" --min-rate 1000 || true

    echo -e ""
    echo -e "${GREENCOLOR}[✓] Port scanning completed!${RESETCOLOR}"
    echo -e "${BLUECOLOR}[+] Results saved to:${RESETCOLOR}"
    echo -e "  - ${BLUECOLOR}port_scanning/nmap_scan.nmap${RESETCOLOR} (Normal output)"
    echo -e "  - ${BLUECOLOR}port_scanning/nmap_scan.xml${RESETCOLOR} (XML output)"
    echo -e "  - ${BLUECOLOR}port_scanning/nmap_scan.gnmap${RESETCOLOR} (Grepable output)"
    echo -e ""

    # Parse and summarize open ports
    echo -e "${BLUECOLOR}[+] Parsing open ports...${RESETCOLOR}"
    grep -E "^[0-9]+/(tcp|udp).*open" "$portscan_dir/nmap_scan.nmap" | sort -u > "$portscan_dir/open_ports_summary.txt" 2>/dev/null || touch "$portscan_dir/open_ports_summary.txt"

    open_ports_count=$(wc -l < "$portscan_dir/open_ports_summary.txt" 2>/dev/null || echo "0")
    echo -e "${GREENCOLOR}[✓] Open ports found: ${open_ports_count}${RESETCOLOR}"
    echo -e "${BLUECOLOR}[+] Summary saved to: port_scanning/open_ports_summary.txt${RESETCOLOR}"
    echo -e ""
}

screenshot_capture() {
    local screenshots_dir="$OUTPUT_DIR/screenshots"

    ### Screenshot Capture with Gowitness ###
    echo -e "${YELLOWCOLOR}[${RESETCOLOR} ${WHITECOLOR}Capturing Screenshots with Gowitness${RESETCOLOR} ${YELLOWCOLOR}]${RESETCOLOR}"
    echo -e ""

    if [ ! -f "$OUTPUT_DIR/live_urls.txt" ]; then
        echo -e "${REDCOLOR}[✗] live_urls.txt not found!${RESETCOLOR}"
        return 1
    fi

    # Create screenshots directory
    mkdir -p "$screenshots_dir"
    echo -e "${BLUECOLOR}[+] Created screenshots directory: ${screenshots_dir}${RESETCOLOR}"
    echo -e ""

    live_count=$(wc -l < "$OUTPUT_DIR/live_urls.txt")
    echo -e "${BLUECOLOR}[+] Capturing screenshots for ${live_count} live URLs...${RESETCOLOR}"
    echo -e "${YELLOWCOLOR}[!] This may take a while...${RESETCOLOR}"
    echo -e ""

    # Rate limit: 10 threads (already optimal, reduced from unlimited)
    gowitness file -f "$OUTPUT_DIR/live_urls.txt" -P "$screenshots_dir" --disable-logging --timeout 10 --threads 10 || true

    echo -e ""
    echo -e "${GREENCOLOR}[✓] Screenshot capture completed!${RESETCOLOR}"
    echo -e "${BLUECOLOR}[+] Screenshots saved to: screenshots/${RESETCOLOR}"

    # Count captured screenshots
    screenshot_count=$(find "$screenshots_dir" -type f \( -name "*.png" -o -name "*.jpg" \) 2>/dev/null | wc -l)
    echo -e "${GREENCOLOR}[✓] Total screenshots captured: ${screenshot_count}${RESETCOLOR}"
    echo -e ""

    # Generate report if available
    if command -v gowitness >/dev/null 2>&1; then
        echo -e "${BLUECOLOR}[+] Generating Gowitness report...${RESETCOLOR}"
        cd "$screenshots_dir" && gowitness report generate 2>/dev/null || true
        cd - >/dev/null
        echo -e "${GREENCOLOR}[✓] Report available at: screenshots/report.html${RESETCOLOR}"
        echo -e ""
    fi
}

nuclei_vulnerability_scan() {
    local nuclei_dir="$OUTPUT_DIR/nuclei_results"

    ### Nuclei Vulnerability Scanning ###
    echo -e "${YELLOWCOLOR}[${RESETCOLOR} ${WHITECOLOR}Nuclei Vulnerability Scanning${RESETCOLOR} ${YELLOWCOLOR}]${RESETCOLOR}"
    echo -e ""

    if [ ! -f "$OUTPUT_DIR/all_discovered_urls.txt" ]; then
        echo -e "${REDCOLOR}[✗] all_discovered_urls.txt not found!${RESETCOLOR}"
        return 1
    fi

    # Create nuclei directory
    mkdir -p "$nuclei_dir"
    echo -e "${BLUECOLOR}[+] Created Nuclei directory: ${nuclei_dir}${RESETCOLOR}"
    echo -e ""

    # Update Nuclei templates
    echo -e "${BLUECOLOR}[+] Updating Nuclei templates...${RESETCOLOR}"
    nuclei -update-templates >/dev/null 2>&1 || true
    echo -e "${GREENCOLOR}[✓] Templates updated!${RESETCOLOR}"
    echo -e ""

    url_count=$(wc -l < "$OUTPUT_DIR/all_discovered_urls.txt")
    echo -e "${BLUECOLOR}[+] Running Nuclei on ${url_count} URLs...${RESETCOLOR}"
    echo -e "${YELLOWCOLOR}[!] This may take significant time depending on URLs...${RESETCOLOR}"
    echo -e ""

    # Run Nuclei with all severity levels
    # Rate limit: 150 req/s, 50 concurrent (already set in original)
    echo -e "${REDCOLOR}[+] Scanning for vulnerabilities (all severities)...${RESETCOLOR}"

    nuclei -l "$OUTPUT_DIR/all_discovered_urls.txt" -severity critical,high,medium,low,info -o "$nuclei_dir/all_findings.txt" -j -o "$nuclei_dir/all_findings.json"  -rate-limit 250 -c 150 || true

    echo -e ""
    echo -e "${GREENCOLOR}[✓] Nuclei scanning completed!${RESETCOLOR}"
    echo -e ""

    # Separate findings by severity
    echo -e "${BLUECOLOR}[+] Separating findings by severity...${RESETCOLOR}"

    severities=("critical" "high" "medium" "low" "info")

    for severity in "${severities[@]}"; do
        echo -e "${CYANCOLOR}[+] Extracting ${severity} severity findings...${RESETCOLOR}"

        nuclei -l "$OUTPUT_DIR/all_discovered_urls.txt" \
               -severity "$severity" \
               -o "$nuclei_dir/${severity}_findings.txt" \
               -silent \
               -rate-limit 150 \
               -c 50 \
               2>/dev/null || touch "$nuclei_dir/${severity}_findings.txt"

        count=$(wc -l < "$nuclei_dir/${severity}_findings.txt" 2>/dev/null || echo "0")

        if [ "$count" -gt 0 ]; then
            if [[ "$severity" == "critical" || "$severity" == "high" ]]; then
                echo -e "  ${REDCOLOR}[!] ${severity}: ${count} vulnerabilities found${RESETCOLOR}"
            elif [[ "$severity" == "medium" ]]; then
                echo -e "  ${YELLOWCOLOR}[+] ${severity}: ${count} vulnerabilities found${RESETCOLOR}"
            else
                echo -e "  ${GREENCOLOR}[+] ${severity}: ${count} findings${RESETCOLOR}"
            fi
        else
            echo -e "  ${CYANCOLOR}[✓] ${severity}: No findings${RESETCOLOR}"
        fi
    done

    echo -e ""
    echo -e "${YELLOWCOLOR}════════════════════════════════════════════════════════════${RESETCOLOR}"
    echo -e ""

    # Summary
    echo -e "${MAGENTACOLOR}[+] Nuclei Scan Summary:${RESETCOLOR}"
    echo -e ""

    critical_count=$(wc -l < "$nuclei_dir/critical_findings.txt" 2>/dev/null || echo "0")
    high_count=$(wc -l < "$nuclei_dir/high_findings.txt" 2>/dev/null || echo "0")
    medium_count=$(wc -l < "$nuclei_dir/medium_findings.txt" 2>/dev/null || echo "0")
    low_count=$(wc -l < "$nuclei_dir/low_findings.txt" 2>/dev/null || echo "0")
    info_count=$(wc -l < "$nuclei_dir/info_findings.txt" 2>/dev/null || echo "0")

    total_vulns=$((critical_count + high_count + medium_count + low_count + info_count))

    echo -e "  ${REDCOLOR}[!] Critical: ${critical_count}${RESETCOLOR}"
    echo -e "  ${REDCOLOR}[!] High: ${high_count}${RESETCOLOR}"
    echo -e "  ${YELLOWCOLOR}[+] Medium: ${medium_count}${RESETCOLOR}"
    echo -e "  ${GREENCOLOR}[+] Low: ${low_count}${RESETCOLOR}"
    echo -e "  ${CYANCOLOR}[+] Info: ${info_count}${RESETCOLOR}"
    echo -e ""
    echo -e "${GREENCOLOR}[✓] Total findings: ${total_vulns}${RESETCOLOR}"
    echo -e ""

    if [ "$critical_count" -gt 0 ] || [ "$high_count" -gt 0 ]; then
        echo -e "${REDCOLOR}[!] CRITICAL: High-priority vulnerabilities detected!${RESETCOLOR}"
        echo -e "${REDCOLOR}[!] Review critical_findings.txt and high_findings.txt immediately!${RESETCOLOR}"
        echo -e ""
    fi

    echo -e "${BLUECOLOR}[+] Results saved to:${RESETCOLOR}"
    echo -e "  - ${BLUECOLOR}nuclei_results/all_findings.txt${RESETCOLOR} (Text output)"
    echo -e "  - ${BLUECOLOR}nuclei_results/all_findings.json${RESETCOLOR} (JSON output)"
    echo -e "  - ${BLUECOLOR}nuclei_results/<severity>_findings.txt${RESETCOLOR} (By severity)"
    echo -e ""
}

# ============= MAIN EXECUTION =============

# Check command line arguments
if [ $# -lt 1 ]; then
    display_banner
    echo -e "${REDCOLOR}[✗] No arguments provided${RESETCOLOR}"
    echo -e "${REDCOLOR}Usage: $0 <domain> or $0 -h or $0 -c${RESETCOLOR}"
    echo -e ""
    exit 1
fi

# Handle -h or --help flag
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
fi

# Display banner first
display_banner

# Handle -c or --check flag (only show logo and tool check)
if [[ "$1" == "-c" || "$1" == "--check" ]]; then
    if ! check_tools; then
        exit 1
    fi
    exit 0
fi

# Normal execution with domain name
domain="$1"

# Step 1: Check Tools
if ! check_tools; then
    exit 1
fi

# Step 2: Validate domain
if ! validate_domain "$domain"; then
    exit 1
fi

#  SET GLOBAL VARIABLES (after successful validation)
DOMAIN="$domain"
OUTPUT_DIR="/root/Desktop/${DOMAIN}"

# Step 3: Start subdomain enumeration
start_enumeration

# Step 4: Merge and clean subdomains
merge_and_clean_subdomains

# Step 5: Probe live hosts
probe_live_hosts

# Step 6: Resolve IPs
resolve_ips

# Step 7: Check subdomain takeover
check_subdomain_takeover

# Step 8: Find API endpoints
find_api_endpoints

directory_bruteforce

# Step 10: FFUF bruteforce
ffuf_bruteforce

# Step 10: Merge all discovered URLs
merge_all_urls

# Step 11: URL Gathering (Katana + GAU)
url_gathering

# Step 13: GF Pattern Analysis
gf_pattern_analysis

# Step 14: Port Scanning
port_scanning

# Step 15: Screenshot Capture
screenshot_capture

# Step 16: Nuclei Vulnerability Scan
nuclei_vulnerability_scan

# End time
end_time=$(date)
echo -e "${YELLOWCOLOR}[+] Recon completed at: ${end_time}${RESETCOLOR}"
echo -e "${GREENCOLOR}[✓] All results saved to: ${OUTPUT_DIR}${RESETCOLOR}"
echo -e ""
