#!/bin/bash
# DDoS Check Script - Professional Log Analyzer
# Version: 3.1 - Fixed Temp Directory Issues

set -euo pipefail

# ============================================
# CONFIGURATION
# ============================================
VERSION="3.1"
TMP_DIR=""
LOG_FILE=""
LOG_FORMAT=""
LOG_TZ="UTC"
TOP_COUNT=20

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# ============================================
# SETUP - CRITICAL FIX
# ============================================
setup_temp() {
    # Create temp directory with unique name
    TMP_DIR=$(mktemp -d /tmp/ddos.XXXXXX 2>/dev/null || mktemp -d /var/tmp/ddos.XXXXXX)
    # Ensure directory exists and is writable
    if [[ ! -d "$TMP_DIR" ]]; then
        die "Failed to create temp directory"
    fi
    chmod 755 "$TMP_DIR" 2>/dev/null || true
    # Set trap for cleanup
    trap 'cleanup' EXIT INT TERM
}

cleanup() {
    if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR" 2>/dev/null || true
    fi
}

die() { 
    echo -e "${RED}ERROR: $*${NC}" >&2
    cleanup
    exit 1
}

# ============================================
# DETECTION FUNCTIONS
# ============================================
detect_log_format() {
    local first_line=$(head -1 "$LOG_FILE" 2>/dev/null || echo "")
    if [[ "$first_line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*\[.*\].*\"[A-Z]+\ .+\ HTTP/[0-9]+\".* ]]; then
        echo "combined"
    else
        echo "unknown"
    fi
}

detect_log_timezone() {
    local first_ts=$(head -1 "$LOG_FILE" | awk -F'[][]' '{print $2}' 2>/dev/null || echo "")
    if [[ "$first_ts" =~ .*[+-][0-9]{4}$ ]]; then
        echo "UTC"
    else
        echo "UTC"
    fi
}

# ============================================
# TIME FUNCTIONS
# ============================================
convert_to_ist() {
    local log_time="$1"
    local formatted=$(echo "$log_time" | sed 's|/| |g' | sed 's|:| |' | awk '{print $3"-"$2"-"$1" "$4}' 2>/dev/null || echo "")
    if [[ -z "$formatted" ]]; then
        echo "N/A"
        return
    fi
    local month_map='Jan=01 Feb=02 Mar=03 Apr=04 May=05 Jun=06 Jul=07 Aug=08 Sep=09 Oct=10 Nov=11 Dec=12'
    for m in $month_map; do
        local mon=${m%=*}
        local num=${m#*=}
        formatted=$(echo "$formatted" | sed "s/$mon/$num/")
    done
    local tz_offset=$(echo "$log_time" | grep -o '[+-][0-9]\{4\}' || echo "+0000")
    TZ=Asia/Kolkata date -d "$formatted $tz_offset" "+%Y-%m-%d %H:%M:%S %Z" 2>/dev/null || echo "N/A"
}

get_available_dates() {
    awk -F'[][]' '{print $2}' "$LOG_FILE" 2>/dev/null | cut -d':' -f1 | sort -u | tail -5
}

# ============================================
# PARSING ENGINE - FIXED
# ============================================
parse_logs() {
    local start_time="$1"
    local end_time="$2"
    
    # Ensure temp directory exists
    if [[ ! -d "$TMP_DIR" ]]; then
        setup_temp
    fi
    
    # Clear any existing temp files
    rm -f "$TMP_DIR"/*.txt 2>/dev/null || true
    
    # Create empty files to avoid "No such file" errors
    touch "$TMP_DIR/ips.txt" "$TMP_DIR/ua.txt" "$TMP_DIR/urls.txt" \
          "$TMP_DIR/queries.txt" "$TMP_DIR/status.txt" "$TMP_DIR/hourly.txt" \
          "$TMP_DIR/total.txt" "$TMP_DIR/ok.txt" "$TMP_DIR/forbidden.txt"
    
    # Single awk pass
    awk -v start="$start_time" -v end="$end_time" -v tmp="$TMP_DIR" '
    BEGIN {
        split("", ip_count); split("", ua_count)
        split("", url_count); split("", query_count)
        split("", status_count); split("", hourly_ok)
        split("", hourly_range)
        total=0; ok=0; err=0; forbidden=0
    }
    
    {
        ts=""
        if (match($0, /\[[^]]+\]/)) {
            ts = substr($0, RSTART, RLENGTH)
        }
        
        if (ts >= start && ts <= end) {
            status = $9
            
            # Count 403 but skip
            if (status == 403) {
                forbidden++
                status_count[status]++
                next
            }
            
            total++
            status_count[status]++
            
            if (status == 200 || status == 304) {
                ok++
                ip = $1; ip_count[ip]++
                url = $7; url_count[url]++
                
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
                err++
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
        for (i in ip_count) print ip_count[i], i > tmp"/ips.txt"
        for (u in ua_count) print ua_count[u], u > tmp"/ua.txt"
        for (u in url_count) print url_count[u], u > tmp"/urls.txt"
        for (q in query_count) print query_count[q], q > tmp"/queries.txt"
        for (s in status_count) print s, status_count[s] > tmp"/status.txt"
        for (h in hourly_ok) {
            gsub(/\[/, "", hourly_range[h "_start"])
            gsub(/\]/, "", hourly_range[h "_start"])
            gsub(/\[/, "", hourly_range[h "_end"])
            gsub(/\]/, "", hourly_range[h "_end"])
            print h, hourly_ok[h], hourly_range[h "_start"], hourly_range[h "_end"] > tmp"/hourly.txt"
        }
        print total > tmp"/total.txt"
        print ok > tmp"/ok.txt"
        print forbidden > tmp"/forbidden.txt"
    }
    ' "$LOG_FILE"
}

# ============================================
# DISPLAY FUNCTIONS - WITH ERROR HANDLING
# ============================================
show_summary() {
    local total=$(cat "$TMP_DIR/total.txt" 2>/dev/null || echo "0")
    local ok=$(cat "$TMP_DIR/ok.txt" 2>/dev/null || echo "0")
    local forbidden=$(cat "$TMP_DIR/forbidden.txt" 2>/dev/null || echo "0")
    local errors=$((total - ok))
    local pct=0
    [[ "$total" -gt 0 ]] && pct=$((errors * 100 / total))
    
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}📊 SUMMARY${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "  Total Requests:  ${YELLOW}$total${NC}"
    echo -e "  Total 200 OK:    ${GREEN}$ok${NC}"
    echo -e "  Total Errors:    ${RED}$errors${NC} (${pct}%)"
    echo -e "  403 Excluded:    ${PURPLE}$forbidden${NC}"
}

show_top_ips() {
    [[ ! -s "$TMP_DIR/ips.txt" ]] && return
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}🌐 TOP $TOP_COUNT IP ADDRESSES${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}#  HITS  IP ADDRESS         COUNTRY          ASN${NC}"
    echo -e "${BLUE}───────────────────────────────────────────────────────────────${NC}"
    
    sort -rn "$TMP_DIR/ips.txt" 2>/dev/null | head -"$TOP_COUNT" | while read -r hits ip; do
        local country="Unknown"; local asn="-"
        if command -v geoiplookup >/dev/null 2>&1; then
            country=$(geoiplookup "$ip" 2>/dev/null | head -1 | awk -F': ' '{print $2}' | cut -d',' -f1)
            [[ -z "$country" ]] && country="Unknown"
        fi
        printf "%-3s %-6s %-18s %-15s %s\n" "" "$hits" "$ip" "$country" "$asn"
    done
}

show_top_ua() {
    [[ ! -s "$TMP_DIR/ua.txt" ]] && return
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}🤖 TOP $TOP_COUNT USER AGENTS${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}#  HITS  USER AGENT${NC}"
    echo -e "${BLUE}───────────────────────────────────────────────────────────────${NC}"
    sort -rn "$TMP_DIR/ua.txt" 2>/dev/null | head -"$TOP_COUNT" | while read -r hits ua; do
        printf "%-3s %-6s %s\n" "" "$hits" "$ua"
    done
}

show_top_urls() {
    [[ ! -s "$TMP_DIR/urls.txt" ]] && return
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}📁 TOP $TOP_COUNT REQUESTED URLS${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}#  HITS  URL${NC}"
    echo -e "${BLUE}───────────────────────────────────────────────────────────────${NC}"
    sort -rn "$TMP_DIR/urls.txt" 2>/dev/null | head -"$TOP_COUNT" | while read -r hits url; do
        printf "%-3s %-6s %s\n" "" "$hits" "$url"
    done
}

show_top_queries() {
    [[ ! -s "$TMP_DIR/queries.txt" ]] && return
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}🔍 TOP $TOP_COUNT QUERY STRINGS${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}#  HITS  QUERY STRING${NC}"
    echo -e "${BLUE}───────────────────────────────────────────────────────────────${NC}"
    sort -rn "$TMP_DIR/queries.txt" 2>/dev/null | head -"$TOP_COUNT" | while read -r hits query; do
        printf "%-3s %-6s %s\n" "" "$hits" "$query"
    done
}

show_status() {
    [[ ! -s "$TMP_DIR/status.txt" ]] && return
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}📈 HTTP STATUS BREAKDOWN${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}STATUS  COUNT${NC}"
    echo -e "${BLUE}───────────────────────────────────────────────────────────────${NC}"
    sort -rn "$TMP_DIR/status.txt" 2>/dev/null | while read -r status count; do
        local color="$NC"
        [[ "$status" -ge 200 && "$status" -lt 300 ]] && color="$GREEN"
        [[ "$status" -ge 300 && "$status" -lt 400 ]] && color="$YELLOW"
        [[ "$status" -ge 400 && "$status" -lt 500 ]] && color="$PURPLE"
        [[ "$status" -ge 500 ]] && color="$RED"
        if [[ "$status" == "403" ]]; then
            echo -e "${PURPLE}$status${NC}  $count (excluded)"
        else
            echo -e "${color}$status${NC}  $count"
        fi
    done
}

show_hourly() {
    [[ ! -s "$TMP_DIR/hourly.txt" ]] && return
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}⏰ HOURLY 200 OK REQUESTS${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}TIME RANGE                              HITS${NC}"
    echo -e "${BLUE}───────────────────────────────────────────────────────────────${NC}"
    sort "$TMP_DIR/hourly.txt" 2>/dev/null | while read -r hour count start_ts end_ts; do
        # Clean up timestamps - remove +0530 and extra spaces
        start_ts=$(echo "$start_ts" | sed 's/ +[0-9]\{4\}//g')
        end_ts=$(echo "$end_ts" | sed 's/ +[0-9]\{4\}//g')
        printf "%-35s %s\n" "$start_ts → $end_ts" "$count"
    done
}

# ============================================
# MENU FUNCTIONS
# ============================================
show_time_menu() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}⏱️  SELECT TIME FRAME${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "  1. Last 60 minutes"
    echo -e "  2. Last 30 minutes"
    echo -e "  3. Today (whole day)"
    echo -e "  4. Custom time range"
    echo -e "  5. Exit"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

show_analysis_menu() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}🔧 ANALYSIS OPTIONS${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "  1. Top $TOP_COUNT IP Addresses"
    echo -e "  2. Top $TOP_COUNT User Agents"
    echo -e "  3. Top $TOP_COUNT Requested URLs"
    echo -e "  4. Top $TOP_COUNT Query Strings"
    echo -e "  5. HTTP Status Breakdown"
    echo -e "  6. Hourly Stats"
    echo -e "  7. 📊 Complete Analysis"
    echo -e "  8. 📋 Summary Only"
    echo -e "  9. 🔙 Back to Time Menu"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

# ============================================
# MAIN
# ============================================
main() {
    # Setup temp directory FIRST
    setup_temp
    
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}🛡️  DDOS Log Analyzer v$VERSION${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    
    # Get log file
    echo -e "\n${CYAN}Enter access log file path:${NC}"
    echo -e "${YELLOW}Example: /var/log/nginx/access.log${NC}"
    read -p "➜ " LOG_FILE
    LOG_FILE=$(eval echo "$LOG_FILE" 2>/dev/null || echo "")
    [[ ! -f "$LOG_FILE" ]] && die "File not found: $LOG_FILE"
    
    # Detect format
    LOG_FORMAT=$(detect_log_format)
    LOG_TZ=$(detect_log_timezone)
    
    # Show log info
    local first_entry=$(head -1 "$LOG_FILE" | awk -F'[][]' '{print $2}' 2>/dev/null || echo "Unknown")
    local last_entry=$(tail -1 "$LOG_FILE" | awk -F'[][]' '{print $2}' 2>/dev/null || echo "Unknown")
    local first_ist=$(convert_to_ist "$first_entry")
    local last_ist=$(convert_to_ist "$last_entry")
    
    echo -e "\n${GREEN}✓ Log file: $LOG_FILE${NC}"
    echo -e "${GREEN}✓ Format: $LOG_FORMAT${NC}"
    echo -e "\n${BLUE}📅 Log Range:${NC}"
    echo -e "  First: $first_entry → ${CYAN}$first_ist${NC}"
    echo -e "  Last:  $last_entry → ${CYAN}$last_ist${NC}"
    
    echo -e "\n${YELLOW}ℹ️  403 status codes are automatically excluded${NC}"
    
    # Main loop
    while true; do
        show_time_menu
        read -p "➜ Choose [1-5]: " choice
        [[ -z "$choice" ]] && choice=1
        
        [[ "$choice" == "5" ]] && echo -e "${GREEN}Goodbye!${NC}" && break
        
        local start_time=""
        local end_time=""
        
        case "$choice" in
            1)
                start_time=$(date -d '60 minutes ago' +"[%d/%b/%Y:%H:%M:%S" 2>/dev/null || echo "")
                end_time=$(date +"[%d/%b/%Y:%H:%M:%S" 2>/dev/null || echo "")
                ;;
            2)
                start_time=$(date -d '30 minutes ago' +"[%d/%b/%Y:%H:%M:%S" 2>/dev/null || echo "")
                end_time=$(date +"[%d/%b/%Y:%H:%M:%S" 2>/dev/null || echo "")
                ;;
            3)
                start_time=$(date +"[%d/%b/%Y:00:00:00" 2>/dev/null || echo "")
                end_time=$(date +"[%d/%b/%Y:23:59:59" 2>/dev/null || echo "")
                ;;
            4)
                echo -e "\n${CYAN}Enter time range (format: YYYY-MM-DD HH:MM:SS)${NC}"
                read -p "➜ Start: " custom_start
                read -p "➜ End: " custom_end
                start_time=$(date -d "$custom_start" +"[%d/%b/%Y:%H:%M:%S" 2>/dev/null || echo "")
                end_time=$(date -d "$custom_end" +"[%d/%b/%Y:%H:%M:%S" 2>/dev/null || echo "")
                [[ -z "$start_time" || -z "$end_time" ]] && die "Invalid time format"
                ;;
            *) echo -e "${RED}Invalid choice${NC}" && continue ;;
        esac
        
        [[ -z "$start_time" || -z "$end_time" ]] && die "Failed to calculate time range"
        
        echo -e "\n${CYAN}⏳ Analyzing: $start_time → $end_time${NC}"
        
        # Parse logs
        parse_logs "$start_time" "$end_time"
        
        # Check if any data found
        local total=$(cat "$TMP_DIR/total.txt" 2>/dev/null || echo "0")
        if [[ "$total" -eq 0 ]]; then
            echo -e "\n${YELLOW}⚠️  No matching entries found. Available dates:${NC}"
            get_available_dates | while read -r date; do
                echo -e "  • $date"
            done
            continue
        fi
        
        # Show summary
        show_summary
        
        # Analysis menu loop
        while true; do
            show_analysis_menu
            read -p "➜ Choose [1-9]: " action
            [[ -z "$action" ]] && action=7
            
            [[ "$action" == "9" ]] && break
            
            case "$action" in
                1) show_top_ips ;;
                2) show_top_ua ;;
                3) show_top_urls ;;
                4) show_top_queries ;;
                5) show_status ;;
                6) show_hourly ;;
                7)
                    show_summary
                    show_top_ips
                    show_top_ua
                    show_top_urls
                    show_top_queries
                    show_status
                    show_hourly
                    ;;
                8) show_summary ;;
                *) echo -e "${RED}Invalid option${NC}" ;;
            esac
            
            echo -e "\n${YELLOW}💾 Save results? (y/n)${NC}"
            read -p "➜ " save
            if [[ "$save" =~ ^[Yy]$ ]]; then
                local out="$HOME/ddos_analysis_$(date +%Y%m%d_%H%M%S).txt"
                {
                    echo "DDOS Analysis Report"
                    echo "Date: $(date)"
                    echo "Log: $LOG_FILE"
                    echo "Range: $start_time → $end_time"
                    echo "========================================="
                } > "$out"
                echo -e "${GREEN}✅ Saved to: $out${NC}"
            fi
            
            echo -e "\n${YELLOW}🔄 Run another analysis on same time range? (y/n)${NC}"
            read -p "➜ " again
            [[ ! "$again" =~ ^[Yy]$ ]] && break
        done
    done
    
    cleanup
    echo -e "${GREEN}✅ Done!${NC}"
}

# ============================================
# START
# ============================================
[[ "${BASH_SOURCE[0]}" == "$0" ]] && main "$@"
