#!/bin/bash
# DDoS Check Script - Optimized Single-Pass Analysis
# Version: 2.2 - Automatic 403 Exclusion + Fixed Loops

set -euo pipefail

# ============================================
# CONFIGURATION
# ============================================
SCRIPT_NAME=$(basename "$0")
VERSION="2.2"
TMP_DIR=""
LOG_FILE=""
LOG_FORMAT=""
LOG_TZ="UTC"
USER_TZ="IST"
TOP_COUNT=20
EXCLUDE_403=true  # ALWAYS exclude 403 by default

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# ============================================
# SETUP & CLEANUP
# ============================================
setup_temp() {
    TMP_DIR=$(mktemp -d /tmp/ddos.XXXXXX 2>/dev/null || mktemp -d /var/tmp/ddos.XXXXXX)
    trap 'cleanup' EXIT INT TERM
}

cleanup() {
    [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]] && rm -rf "$TMP_DIR"
}

die() { echo -e "${RED}ERROR: $*${NC}" >&2; exit 1; }

prompt() {
    echo -e "${CYAN}▶${NC} $*"
}

# ============================================
# DETECTION FUNCTIONS
# ============================================
detect_log_format() {
    local first_line=$(head -1 "$LOG_FILE" 2>/dev/null)
    
    if [[ "$first_line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*\[.*\].*\"[A-Z]+\ .+\ HTTP/[0-9]+\".* ]]; then
        echo "apache"
        return
    fi
    
    if [[ "$first_line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*\[.*\].*\"[A-Z]+\ .+\ HTTP/[0-9]+\".*\"-\"\ *\" ]]; then
        echo "nginx"
        return
    fi
    
    if [[ "$first_line" =~ .*\"-\"\ *\".* ]]; then
        echo "combined"
        return
    fi
    
    echo "unknown"
}

detect_log_timezone() {
    local first_ts=$(head -1 "$LOG_FILE" | awk -F'[][]' '{print $2}' 2>/dev/null)
    [[ -z "$first_ts" ]] && echo "UTC" && return
    
    if [[ "$first_ts" =~ .*[+-][0-9]{4}$ ]]; then
        echo "UTC"
    elif [[ "$first_ts" =~ .*IST$ ]]; then
        echo "IST"
    else
        echo "UTC"
    fi
}

# ============================================
# TIME HANDLING
# ============================================
convert_log_to_ist() {
    local log_time="$1"
    local formatted=$(echo "$log_time" | sed 's|/| |g' | sed 's|:| |' | awk '{print $3"-"$2"-"$1" "$4}')
    local month_map='Jan=01 Feb=02 Mar=03 Apr=04 May=05 Jun=06 Jul=07 Aug=08 Sep=09 Oct=10 Nov=11 Dec=12'
    for m in $month_map; do
        local mon=${m%=*}
        local num=${m#*=}
        formatted=$(echo "$formatted" | sed "s/$mon/$num/")
    done
    local tz_offset=$(echo "$log_time" | grep -o '[+-][0-9]\{4\}' || echo "+0000")
    TZ=Asia/Kolkata date -d "$formatted $tz_offset" "+%Y-%m-%d %H:%M:%S %Z" 2>/dev/null || echo "N/A"
}

get_time_range() {
    local choice="$1"
    local start_time=""
    local end_time=""
    
    case "$choice" in
        1)
            start_time=$(date -d '60 minutes ago' +"[%d/%b/%Y:%H:%M:%S")
            end_time=$(date +"[%d/%b/%Y:%H:%M:%S")
            ;;
        2)
            start_time=$(date -d '30 minutes ago' +"[%d/%b/%Y:%H:%M:%S")
            end_time=$(date +"[%d/%b/%Y:%H:%M:%S")
            ;;
        3)
            start_time=$(date +"[%d/%b/%Y:00:00:00")
            end_time=$(date +"[%d/%b/%Y:23:59:59")
            ;;
        4)
            prompt "Enter start time (format: YYYY-MM-DD HH:MM:SS)"
            echo -e "${YELLOW}Example: 2026-06-28 10:30:00${NC}"
            read -p "➜ Start: " custom_start
            prompt "Enter end time (format: YYYY-MM-DD HH:MM:SS)"
            read -p "➜ End: " custom_end
            start_time=$(date -d "$custom_start" +"[%d/%b/%Y:%H:%M:%S" 2>/dev/null)
            end_time=$(date -d "$custom_end" +"[%d/%b/%Y:%H:%M:%S" 2>/dev/null)
            [[ -z "$start_time" || -z "$end_time" ]] && die "Invalid time format"
            ;;
        *) die "Invalid choice" ;;
    esac
    
    echo "$start_time|$end_time"
}

# ============================================
# SINGLE-PASS PARSING - ALWAYS EXCLUDE 403
# ============================================
parse_logs() {
    local start_time="$1"
    local end_time="$2"
    local parse_file="$3"
    
    awk -v start="$start_time" -v end="$end_time" '
    BEGIN {
        split("", ip_count)
        split("", ua_count)
        split("", url_count)
        split("", query_count)
        split("", status_count)
        split("", hourly_ok)
        split("", hourly_range)
        
        total_requests = 0
        total_ok = 0
        total_errors = 0
        total_403 = 0
    }
    
    {
        ts = ""
        if (match($0, /\[[^]]+\]/)) {
            ts = substr($0, RSTART, RLENGTH)
        }
        
        if (ts >= start && ts <= end) {
            status = $9
            
            # Count 403 but skip them
            if (status == 403) {
                total_403++
                status_count[status]++
                next  # Skip 403 entirely
            }
            
            total_requests++
            status_count[status]++
            
            if (status == 200 || status == 304) {
                total_ok++
                
                ip = $1
                ip_count[ip]++
                
                url = $7
                url_count[url]++
                
                query = url
                if (match(url, /\?/)) {
                    query = substr(url, RSTART + 1)
                    query_count[query]++
                } else {
                    query = "(no query)"
                }
                
                hour = ""
                if (match(ts, /[0-9]{2}:[0-9]{2}/)) {
                    hour = substr(ts, RSTART, 5)
                    if (!(hour in hourly_ok)) {
                        hourly_ok[hour] = 0
                        hourly_range[hour "_start"] = ts
                    }
                    hourly_ok[hour]++
                    hourly_range[hour "_end"] = ts
                }
            } else {
                ip_status[ip] = ip_status[ip] ? ip_status[ip]","status : status
            }
            
            if (match($0, /"[^"]*"$/)) {
                ua = substr($0, RSTART + 1, RLENGTH - 2)
                if (ua != "-" && length(ua) > 0) {
                    ua_count[ua]++
                }
            }
        }
    }
    
    END {
        for (i in ip_count) {
            print ip_count[i], i > "'$TMP_DIR'/ips.txt"
        }
        
        for (u in ua_count) {
            print ua_count[u], u > "'$TMP_DIR'/ua.txt"
        }
        
        for (u in url_count) {
            print url_count[u], u > "'$TMP_DIR'/urls.txt"
        }
        
        for (q in query_count) {
            print query_count[q], q > "'$TMP_DIR'/queries.txt"
        }
        
        for (h in hourly_ok) {
            start_ts = hourly_range[h "_start"]
            end_ts = hourly_range[h "_end"]
            # Clean up timestamps - remove brackets
            gsub(/\[/, "", start_ts)
            gsub(/\]/, "", start_ts)
            gsub(/\[/, "", end_ts)
            gsub(/\]/, "", end_ts)
            print h, hourly_ok[h], start_ts, end_ts > "'$TMP_DIR'/hourly.txt"
        }
        
        for (s in status_count) {
            print s, status_count[s] > "'$TMP_DIR'/status.txt"
        }
        
        print total_requests > "'$TMP_DIR'/total_requests.txt"
        print total_ok > "'$TMP_DIR'/total_ok.txt"
        print total_403 > "'$TMP_DIR'/total_403.txt"
    }
    ' "$parse_file"
}

# ============================================
# GEOIP FUNCTIONS
# ============================================
get_country_asn() {
    local ip="$1"
    local country="Unknown"
    local asn="Unknown"
    
    if command -v geoiplookup >/dev/null 2>&1; then
        country=$(geoiplookup "$ip" 2>/dev/null | head -1 | awk -F': ' '{print $2}' | cut -d',' -f1)
        asn=$(geoiplookup -f /usr/share/GeoIP/GeoIPASNum.dat "$ip" 2>/dev/null | awk -F': ' '{print $2}' | cut -d' ' -f1)
    fi
    
    if [[ "$country" == "Unknown" || -z "$country" ]]; then
        local api_data=$(curl -s -m 2 "http://ip-api.com/csv/$ip?fields=countryCode,as" 2>/dev/null)
        country=$(echo "$api_data" | cut -d',' -f1)
        asn=$(echo "$api_data" | cut -d',' -f2 | cut -d' ' -f1)
    fi
    
    echo "$country|$asn"
}

# ============================================
# ANALYSIS FUNCTIONS
# ============================================
show_top_ips() {
    local count="${1:-$TOP_COUNT}"
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}TOP $count IP ADDRESSES${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}#  HITS  IP ADDRESS         COUNTRY          ASN${NC}"
    echo -e "${BLUE}───────────────────────────────────────────────────────────────${NC}"
    
    sort -rn "$TMP_DIR/ips.txt" | head -"$count" | while read -r hits ip; do
        local geo=$(get_country_asn "$ip")
        local country=$(echo "$geo" | cut -d'|' -f1)
        local asn=$(echo "$geo" | cut -d'|' -f2)
        printf "%-3s %-6s %-18s %-15s %s\n" "" "$hits" "$ip" "$country" "$asn"
    done
}

show_top_ua() {
    local count="${1:-$TOP_COUNT}"
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}TOP $count USER AGENTS${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}#  HITS  USER AGENT${NC}"
    echo -e "${BLUE}───────────────────────────────────────────────────────────────${NC}"
    
    sort -rn "$TMP_DIR/ua.txt" | head -"$count" | while read -r hits ua; do
        printf "%-3s %-6s %s\n" "" "$hits" "$ua"
    done
}

show_top_urls() {
    local count="${1:-$TOP_COUNT}"
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}TOP $count REQUESTED URLS${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}#  HITS  URL${NC}"
    echo -e "${BLUE}───────────────────────────────────────────────────────────────${NC}"
    
    sort -rn "$TMP_DIR/urls.txt" | head -"$count" | while read -r hits url; do
        printf "%-3s %-6s %s\n" "" "$hits" "$url"
    done
}

show_top_queries() {
    local count="${1:-$TOP_COUNT}"
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}TOP $count QUERY STRINGS${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}#  HITS  QUERY STRING${NC}"
    echo -e "${BLUE}───────────────────────────────────────────────────────────────${NC}"
    
    sort -rn "$TMP_DIR/queries.txt" | head -"$count" | while read -r hits query; do
        printf "%-3s %-6s %s\n" "" "$hits" "$query"
    done
}

show_status_breakdown() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}HTTP STATUS CODE BREAKDOWN${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}STATUS  COUNT${NC}"
    echo -e "${BLUE}───────────────────────────────────────────────────────────────${NC}"
    
    sort -rn "$TMP_DIR/status.txt" | while read -r status count; do
        local color="$NC"
        [[ "$status" -ge 200 && "$status" -lt 300 ]] && color="$GREEN"
        [[ "$status" -ge 300 && "$status" -lt 400 ]] && color="$YELLOW"
        [[ "$status" -ge 400 && "$status" -lt 500 ]] && color="$PURPLE"
        [[ "$status" -ge 500 ]] && color="$RED"
        if [[ "$status" == "403" ]]; then
            echo -e "${RED}$status${NC}  $count (Excluded from analysis)"
        else
            echo -e "${color}$status${NC}  $count"
        fi
    done
}

show_hourly_stats() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}HOURLY 200 OK REQUESTS${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}TIME RANGE                              HITS${NC}"
    echo -e "${BLUE}───────────────────────────────────────────────────────────────${NC}"
    
    sort "$TMP_DIR/hourly.txt" | while read -r hour count start_ts end_ts; do
        # Clean display format
        printf "%-35s %s\n" "$start_ts → $end_ts" "$count"
    done
}

show_summary() {
    local total_req=$(cat "$TMP_DIR/total_requests.txt" 2>/dev/null || echo "0")
    local total_ok=$(cat "$TMP_DIR/total_ok.txt" 2>/dev/null || echo "0")
    local total_403=$(cat "$TMP_DIR/total_403.txt" 2>/dev/null || echo "0")
    local total_err=$((total_req - total_ok))
    local err_pct=0
    [[ "$total_req" -gt 0 ]] && err_pct=$((total_err * 100 / total_req))
    
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}SUMMARY${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "Total Requests:  ${YELLOW}$total_req${NC} (excluding 403)"
    echo -e "Total 403 Hits:  ${PURPLE}$total_403${NC} (excluded from analysis)"
    echo -e "Total 200 OK:    ${GREEN}$total_ok${NC}"
    echo -e "Total Errors:    ${RED}$total_err${NC} (${err_pct}%)"
    echo -e "Log Timezone:    ${CYAN}$LOG_TZ${NC}"
    echo -e "User Timezone:   ${CYAN}IST${NC}"
    echo -e "${YELLOW}📌 403 status codes are automatically excluded${NC}"
}

# ============================================
# MENU SYSTEM
# ============================================
show_analysis_menu() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}ANALYSIS OPTIONS${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "1. Top $TOP_COUNT IP Addresses"
    echo -e "2. Top $TOP_COUNT User Agents"
    echo -e "3. Top $TOP_COUNT Requested URLs"
    echo -e "4. Top $TOP_COUNT Query Strings"
    echo -e "5. HTTP Status Breakdown (403 excluded)"
    echo -e "6. Hourly 200 OK Stats (with time range)"
    echo -e "7. Complete Analysis (All of above)"
    echo -e "8. Summary Only"
    echo -e "9. Exit to Time Menu"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

run_analysis() {
    local choice="$1"
    
    case "$choice" in
        1) show_top_ips $TOP_COUNT ;;
        2) show_top_ua $TOP_COUNT ;;
        3) show_top_urls $TOP_COUNT ;;
        4) show_top_queries $TOP_COUNT ;;
        5) show_status_breakdown ;;
        6) show_hourly_stats ;;
        7)
            show_summary
            show_top_ips $TOP_COUNT
            show_top_ua $TOP_COUNT
            show_top_urls $TOP_COUNT
            show_top_queries $TOP_COUNT
            show_status_breakdown
            show_hourly_stats
            ;;
        8) show_summary ;;
        9) return 1 ;;
        *) echo -e "${RED}Invalid choice${NC}" ;;
    esac
    return 0
}

# ============================================
# TIME MENU
# ============================================
show_time_menu() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}SELECT TIME FRAME${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "1. Last 60 minutes (default)"
    echo -e "2. Last 30 minutes"
    echo -e "3. Whole day"
    echo -e "4. Custom time range"
    echo -e "5. Exit script"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

# ============================================
# MAIN EXECUTION
# ============================================
main() {
    setup_temp
    
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}DDOS Check Script v$VERSION${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}ℹ️  403 status codes will be automatically excluded${NC}"
    
    prompt "Enter access log file path"
    echo -e "${YELLOW}Examples: /var/log/nginx/access.log or /var/log/apache2/*_access_log${NC}"
    read -p "➜ Log File: " LOG_FILE
    
    LOG_FILE=$(eval echo "$LOG_FILE" 2>/dev/null)
    [[ ! -f "$LOG_FILE" ]] && die "Log file not found: $LOG_FILE"
    
    LOG_FORMAT=$(detect_log_format)
    LOG_TZ=$(detect_log_timezone)
    
    echo -e "\n${GREEN}✓ Log file: $LOG_FILE${NC}"
    echo -e "${GREEN}✓ Format: $LOG_FORMAT${NC}"
    echo -e "${GREEN}✓ Timezone: $LOG_TZ${NC}"
    
    local first_entry=$(head -1 "$LOG_FILE" | awk -F'[][]' '{print $2}')
    local last_entry=$(tail -1 "$LOG_FILE" | awk -F'[][]' '{print $2}')
    local first_ist=$(convert_log_to_ist "$first_entry")
    local last_ist=$(convert_log_to_ist "$last_entry")
    
    echo -e "\n${GREEN}📅 Log Time Range:${NC}"
    echo -e "  ${CYAN}First Entry:${NC} $first_entry ($LOG_TZ) → $first_ist"
    echo -e "  ${CYAN}Last Entry:${NC}  $last_entry ($LOG_TZ) → $last_ist"
    
    while true; do
        show_time_menu
        read -p "➜ Choose time frame [1-5]: " time_choice
        [[ -z "$time_choice" ]] && time_choice=1
        
        if [[ "$time_choice" == "5" ]]; then
            echo -e "${GREEN}Goodbye!${NC}"
            break
        fi
        
        local range=$(get_time_range "$time_choice")
        local start_time=$(echo "$range" | cut -d'|' -f1)
        local end_time=$(echo "$range" | cut -d'|' -f2)
        
        echo -e "\n${CYAN}⏳ Processing logs from $start_time to $end_time...${NC}"
        echo -e "${YELLOW}📌 403 status codes are being excluded automatically${NC}"
        
        parse_logs "$start_time" "$end_time" "$LOG_FILE"
        
        show_summary
        
        while true; do
            show_analysis_menu
            read -p "➜ Choose analysis [1-9]: " analysis_choice
            [[ -z "$analysis_choice" ]] && analysis_choice=7
            
            if ! run_analysis "$analysis_choice"; then
                break
            fi
            
            echo -e "\n${YELLOW}💾 Save results to file? (y/n)${NC}"
            read -p "➜ " save_choice
            if [[ "$save_choice" =~ ^[Yy]$ ]]; then
                local output_file="$HOME/ddos_results_$(date +%Y%m%d_%H%M%S).txt"
                {
                    echo "DDOS Check Results - $(date)"
                    echo "Log File: $LOG_FILE"
                    echo "Time Range: $start_time to $end_time"
                    echo "403 Status: Excluded from analysis"
                    echo "========================================="
                } > "$output_file"
                echo -e "${GREEN}✅ Results saved to: $output_file${NC}"
            fi
            
            echo -e "\n${YELLOW}🔄 Run another analysis on same time range? (y/n)${NC}"
            read -p "➜ " repeat_analysis
            if [[ ! "$repeat_analysis" =~ ^[Yy]$ ]]; then
                break
            fi
        done
    done
    
    echo -e "${GREEN}✅ Done!${NC}"
    cleanup
}

# ============================================
# START
# ============================================
[[ "${BASH_SOURCE[0]}" == "$0" ]] && main "$@"
