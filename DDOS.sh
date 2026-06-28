#!/bin/bash
# DDoS Check Script - Professional Log Analyzer
# Version: 3.0

set -euo pipefail

# ============================================
# CONFIGURATION
# ============================================
VERSION="3.0"
TMP_DIR=""
LOG_FILE=""
LOG_FORMAT=""
LOG_TZ="UTC"
TOP_COUNT=20
EXCLUDE_403=true

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# ============================================
# SETUP
# ============================================
setup_temp() {
    TMP_DIR=$(mktemp -d /tmp/ddos.XXXXXX 2>/dev/null || mktemp -d /var/tmp/ddos.XXXXXX)
    trap 'cleanup' EXIT INT TERM
}

cleanup() {
    [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]] && rm -rf "$TMP_DIR"
}

die() { echo -e "${RED}ERROR: $*${NC}" >&2; exit 1; }

# ============================================
# LOG DETECTION
# ============================================
detect_log_format() {
    local first_line=$(head -1 "$LOG_FILE" 2>/dev/null)
    if [[ "$first_line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*\[.*\].*\"[A-Z]+\ .+\ HTTP/[0-9]+\".* ]]; then
        echo "combined"
    else
        echo "unknown"
    fi
}

detect_log_timezone() {
    local first_ts=$(head -1 "$LOG_FILE" | awk -F'[][]' '{print $2}' 2>/dev/null)
    if [[ "$first_ts" =~ .*[+-][0-9]{4}$ ]]; then
        echo "UTC"
    else
        echo "UTC"
    fi
}

# ============================================
# SMART TIME DETECTION
# ============================================
get_log_date_range() {
    local first=$(head -1 "$LOG_FILE" | awk -F'[][]' '{print $2}' | cut -d':' -f1 | cut -d'/' -f1-3)
    local last=$(tail -1 "$LOG_FILE" | awk -F'[][]' '{print $2}' | cut -d':' -f1 | cut -d'/' -f1-3)
    echo "$first|$last"
}

has_data_for_date() {
    local date_pattern="$1"
    grep -q "$date_pattern" "$LOG_FILE" 2>/dev/null
}

get_available_dates() {
    awk -F'[][]' '{print $2}' "$LOG_FILE" | cut -d':' -f1 | sort -u | tail -5
}

convert_to_ist() {
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

# ============================================
# SMART TIME RANGE
# ============================================
get_smart_time_range() {
    local choice="$1"
    local start_time=""
    local end_time=""
    local today=$(date +%d/%b/%Y)
    
    case "$choice" in
        1)  # Last 60 min - check if data exists
            start_time=$(date -d '60 minutes ago' +"[%d/%b/%Y:%H:%M:%S")
            end_time=$(date +"[%d/%b/%Y:%H:%M:%S")
            # Check if any data exists in this range
            if ! grep -q "$(date +%d/%b/%Y)" "$LOG_FILE" 2>/dev/null; then
                echo "NO_DATA|$start_time|$end_time"
                return
            fi
            ;;
        2)  # Last 30 min
            start_time=$(date -d '30 minutes ago' +"[%d/%b/%Y:%H:%M:%S")
            end_time=$(date +"[%d/%b/%Y:%H:%M:%S")
            if ! grep -q "$(date +%d/%b/%Y)" "$LOG_FILE" 2>/dev/null; then
                echo "NO_DATA|$start_time|$end_time"
                return
            fi
            ;;
        3)  # Whole day - check if today has data
            start_time=$(date +"[%d/%b/%Y:00:00:00")
            end_time=$(date +"[%d/%b/%Y:23:59:59")
            if ! grep -q "$today" "$LOG_FILE" 2>/dev/null; then
                echo "NO_DATA|$start_time|$end_time"
                return
            fi
            ;;
        4)  # Custom
            echo -e "\n${CYAN}Enter time range (format: YYYY-MM-DD HH:MM:SS)${NC}"
            read -p "➜ Start: " custom_start
            read -p "➜ End: " custom_end
            start_time=$(date -d "$custom_start" +"[%d/%b/%Y:%H:%M:%S" 2>/dev/null)
            end_time=$(date -d "$custom_end" +"[%d/%b/%Y:%H:%M:%S" 2>/dev/null)
            [[ -z "$start_time" || -z "$end_time" ]] && die "Invalid time format"
            ;;
        5) exit 0 ;;
        *) die "Invalid choice" ;;
    esac
    
    echo "OK|$start_time|$end_time"
}

# ============================================
# PARSING ENGINE
# ============================================
parse_logs() {
    local start_time="$1"
    local end_time="$2"
    
    # Clear temp files
    rm -f "$TMP_DIR"/*.txt 2>/dev/null
    
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
# DISPLAY FUNCTIONS
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
    echo -e "  403 Excluded:    ${PURPLE}$forbidden${NC} (skipped from analysis)"
    echo -e "  Log Timezone:    ${CYAN}$LOG_TZ${NC}"
    echo -e "  Your Timezone:   ${CYAN}IST${NC}"
}

show_top_ips() {
    [[ ! -f "$TMP_DIR/ips.txt" ]] && return
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}🌐 TOP $TOP_COUNT IP ADDRESSES${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}#  HITS  IP ADDRESS         COUNTRY          ASN${NC}"
    echo -e "${BLUE}───────────────────────────────────────────────────────────────${NC}"
    
    sort -rn "$TMP_DIR/ips.txt" 2>/dev/null | head -"$TOP_COUNT" | while read -r hits ip; do
        local country="Unknown"; local asn="Unknown"
        if command -v geoiplookup >/dev/null 2>&1; then
            country=$(geoiplookup "$ip" 2>/dev/null | head -1 | awk -F': ' '{print $2}' | cut -d',' -f1)
            asn=$(geoiplookup -f /usr/share/GeoIP/GeoIPASNum.dat "$ip" 2>/dev/null | awk -F': ' '{print $2}' | cut -d' ' -f1)
        fi
        [[ -z "$country" ]] && country="Unknown"
        [[ -z "$asn" ]] && asn="-"
        printf "%-3s %-6s %-18s %-15s %s\n" "" "$hits" "$ip" "$country" "$asn"
    done
}

show_top_ua() {
    [[ ! -f "$TMP_DIR/ua.txt" ]] && return
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
    [[ ! -f "$TMP_DIR/urls.txt" ]] && return
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
    [[ ! -f "$TMP_DIR/queries.txt" ]] && return
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
    [[ ! -f "$TMP_DIR/status.txt" ]] && return
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
        [[ "$status" == "403" ]] && echo -e "${PURPLE}$status${NC}  $count (excluded)"
        echo -e "${color}$status${NC}  $count"
    done
}

show_hourly() {
    [[ ! -f "$TMP_DIR/hourly.txt" ]] && return
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}⏰ HOURLY 200 OK REQUESTS${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}TIME RANGE                              HITS${NC}"
    echo -e "${BLUE}───────────────────────────────────────────────────────────────${NC}"
    sort "$TMP_DIR/hourly.txt" 2>/dev/null | while read -r hour count start_ts end_ts; do
        printf "%-35s %s\n" "$start_ts → $end_ts" "$count"
    done
}

# ============================================
# MENU
# ============================================
show_menu() {
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
    setup_temp
    
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}🛡️  DDOS Log Analyzer v$VERSION${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    
    # Get log file
    echo -e "\n${CYAN}Enter access log file path:${NC}"
    echo -e "${YELLOW}Example: /var/log/nginx/access.log${NC}"
    read -p "➜ " LOG_FILE
    LOG_FILE=$(eval echo "$LOG_FILE" 2>/dev/null)
    [[ ! -f "$LOG_FILE" ]] && die "File not found: $LOG_FILE"
    
    # Detect format
    LOG_FORMAT=$(detect_log_format)
    LOG_TZ=$(detect_log_timezone)
    
    # Show log info
    local first_entry=$(head -1 "$LOG_FILE" | awk -F'[][]' '{print $2}')
    local last_entry=$(tail -1 "$LOG_FILE" | awk -F'[][]' '{print $2}')
    local first_ist=$(convert_to_ist "$first_entry")
    local last_ist=$(convert_to_ist "$last_entry")
    
    echo -e "\n${GREEN}✓ Log file: $LOG_FILE${NC}"
    echo -e "${GREEN}✓ Format: $LOG_FORMAT${NC}"
    echo -e "\n${BLUE}📅 Log Range:${NC}"
    echo -e "  First: $first_entry → ${CYAN}$first_ist${NC}"
    echo -e "  Last:  $last_entry → ${CYAN}$last_ist${NC}"
    
    # Show 403 exclusion ONCE
    echo -e "\n${YELLOW}ℹ️  403 status codes are automatically excluded from analysis${NC}"
    
    # Main loop
    while true; do
        echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}⏱️  SELECT TIME FRAME${NC}"
        echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "  1. Last 60 minutes"
        echo -e "  2. Last 30 minutes"
        echo -e "  3. Today (whole day)"
        echo -e "  4. Custom time range"
        echo -e "  5. Exit"
        echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
        read -p "➜ Choose [1-5]: " choice
        [[ -z "$choice" ]] && choice=1
        
        [[ "$choice" == "5" ]] && echo -e "${GREEN}Goodbye!${NC}" && break
        
        # Get smart time range
        local result=$(get_smart_time_range "$choice")
        local status=$(echo "$result" | cut -d'|' -f1)
        local start_time=$(echo "$result" | cut -d'|' -f2)
        local end_time=$(echo "$result" | cut -d'|' -f3)
        
        # Handle no data
        if [[ "$status" == "NO_DATA" ]]; then
            echo -e "\n${YELLOW}⚠️  No data found for this time range.${NC}"
            echo -e "${CYAN}Available dates in this log:${NC}"
            get_available_dates | while read -r date; do
                echo -e "  • $date"
            done
            echo -e "\n${YELLOW}Please use Custom time range (option 4) with dates from above.${NC}"
            continue
        fi
        
        echo -e "\n${CYAN}⏳ Analyzing: $start_time → $end_time${NC}"
        
        # Parse
        parse_logs "$start_time" "$end_time"
        
        # Check if any data found
        local total=$(cat "$TMP_DIR/total.txt" 2>/dev/null || echo "0")
        if [[ "$total" -eq 0 ]]; then
            echo -e "\n${YELLOW}⚠️  No matching entries found in this time range.${NC}"
            continue
        fi
        
        # Show summary
        show_summary
        
        # Analysis menu loop
        while true; do
            show_menu
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
            
            # Save option
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
            
            echo -e "\n${YELLOW}🔄 Run another analysis? (y/n)${NC}"
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
