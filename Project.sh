#!/bin/bash

# ============================================================================
# ENHANCED AUTOMATIC IP & WEBSITE SECURITY SCANNER v1.0 (FIXED)
# Original file (uploaded): sandbox:/mnt/data/0303f292-a8a1-4dc2-b3e6-e9c6a3a9a905.png
# Fixes applied:
#  - Closed an unterminated single-quoted regex used with grep/dig resolution
#  - Removed duplicated/garbled block that repeated the main program twice
#  - Ensured here-doc delimiters and sed substitutions are safe
#  - Minor formatting cleanups
# ============================================================================

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# Directories
REPORTS_DIR="scan_reports"
HISTORY_DIR="scan_history"
FIXES_DIR="security_fixes"

# Files
CURRENT_REPORT="$REPORTS_DIR/latest_scan.txt"
HTML_REPORT="$REPORTS_DIR/latest_scan.html"
TEMP_SCAN="temp_scan.txt"

# Variables
TARGET_IP=""
TARGET_DOMAIN=""
THREAT_SCORE=0
IP_COUNTRY=""
IP_ISP=""

# Create directories
mkdir -p "$REPORTS_DIR" "$HISTORY_DIR" "$FIXES_DIR"

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                       ║"
    echo "║    🛡  ENHANCED SECURITY SCANNER v1.0 🚀                              ║"
    echo "║                                                                       ║"
    echo "║    🌐 Threat Intel | 📜 History | 🔧 Auto-Fix | 🔔 Alerts             ║"
    echo "║                                                                       ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}ℹ  Date: ${WHITE}$(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo ""
}

print_section_header() {
    local title=$1
    local icon=$2
    echo ""
    echo -e "${MAGENTA}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║  ${icon}  ${title}"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

draw_box() {
    local text=$1
    local color=$2
    local icon=$3
    echo -e "${color}┌─────────────────────────────────────────────┐${NC}"
    echo -e "${color}│  ${icon}  ${text}${NC}"
    echo -e "${color}└─────────────────────────────────────────────┘${NC}"
}

print_success() { echo -e "${GREEN}✅  $1${NC}"; }
print_error() { echo -e "${RED}✗  $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠  $1${NC}"; }
print_info() { echo -e "${BLUE}ℹ  $1${NC}"; }

check_dependencies() {
    print_section_header "CHECKING DEPENDENCIES" "🔍"
    local missing_deps=()
    
    command -v nmap >/dev/null 2>&1 || missing_deps+=("nmap")
    command -v dialog >/dev/null 2>&1 || missing_deps+=("dialog")
    command -v dig >/dev/null 2>&1 || missing_deps+=("dnsutils")
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing: ${missing_deps[*]}"
        echo -e "\n${WHITE}Install with: sudo apt-get install ${missing_deps[*]} -y${NC}\n"
        exit 1
    fi
    
    print_success "All dependencies satisfied"
}

# ============================================================================
# THREAT INTELLIGENCE
# ============================================================================

check_threat_intelligence() {
    local ip=$1
    
    print_section_header "THREAT INTELLIGENCE LOOKUP" "🗺"
    print_info "Querying threat databases for: ${WHITE}$ip${NC}"
    echo ""
    
    print_info "Checking IP geolocation..."
    local geo_data=$(curl -s --connect-timeout 5 "http://ip-api.com/json/$ip?fields=status,country,regionName,city,isp" 2>/dev/null)
    
    if echo "$geo_data" | grep -q '"status":"success"'; then
        IP_COUNTRY=$(echo "$geo_data" | grep -o '"country":"[^"]*"' | cut -d'"' -f4)
        IP_ISP=$(echo "$geo_data" | grep -o '"isp":"[^"]*"' | cut -d'"' -f4)
        local city=$(echo "$geo_data" | grep -o '"city":"[^"]*"' | cut -d'"' -f4)
        local region=$(echo "$geo_data" | grep -o '"regionName":"[^"]*"' | cut -d'"' -f4)
        
        print_success "Location identified"
        echo -e "  ${CYAN}├─${NC} Country: ${WHITE}$IP_COUNTRY${NC}"
        echo -e "  ${CYAN}├─${NC} Region: ${WHITE}$region, $city${NC}"
        echo -e "  ${CYAN}└─${NC} ISP: ${WHITE}$IP_ISP${NC}"
    else
        print_warning "Geolocation unavailable"
    fi
    
    echo ""
    
    if [[ "$IP_ISP" =~ (Amazon|Google|Microsoft|DigitalOcean|Vultr|Linode) ]]; then
        print_warning "Cloud provider IP detected: ${IP_ISP}"
        echo -e "  ${DIM}Could be legitimate service or scanning host${NC}"
        THREAT_SCORE=$((THREAT_SCORE + 10))
    fi
    
    if [[ "$ip" =~ ^(185\.220\.|185\.100\.|103\.253\.) ]]; then
        print_warning "IP matches known suspicious range"
        THREAT_SCORE=$((THREAT_SCORE + 25))
    fi
    
    echo ""
    
    local threat_level="LOW"
    local threat_color="${GREEN}"
    local threat_icon="✅"
    
    if [ "$THREAT_SCORE" -ge 40 ]; then
        threat_level="HIGH"
        threat_color="${RED}"
        threat_icon="🔴"
    elif [ "$THREAT_SCORE" -ge 20 ]; then
        threat_level="MEDIUM"
        threat_color="${YELLOW}"
        threat_icon="⚠"
    fi
    
    draw_box "IP Reputation: $threat_level (Score: $THREAT_SCORE/100)" "$threat_color" "$threat_icon"
    echo ""
}

# ============================================================================
# HISTORICAL TRACKING
# ============================================================================

save_scan_history() {
    local target=$1
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local history_file="$HISTORY_DIR/${target//[:.\/]/}$timestamp.txt"
    
    if [ -f "$TEMP_SCAN" ]; then
        cp "$TEMP_SCAN" "$history_file"
        print_success "Scan saved to history"
    fi
}

compare_with_history() {
    local target=$1
    local sanitized=${target//[:.\/]/_}
    
    print_section_header "HISTORICAL COMPARISON" "📜"
    
    local prev_scan=$(ls -t "$HISTORY_DIR/${sanitized}"_*.txt 2>/dev/null | sed -n '2p')
    
    if [ -z "$prev_scan" ]; then
        print_info "First scan for this target"
        print_info "Future scans will show changes"
        return 0
    fi
    
    local prev_date=$(basename "$prev_scan" | grep -o '[0-9]\{8\}_[0-9]\{6\}')
    print_info "Comparing with scan from: ${WHITE}${prev_date:0:8} ${prev_date:9:2}:${prev_date:11:2}${NC}"
    echo ""
    
    local curr_ports=$(grep "^[0-9]*/tcp.*open" "$TEMP_SCAN" 2>/dev/null | awk '{print $1}' | cut -d/ -f1 | sort -n)
    local prev_ports=$(grep "^[0-9]*/tcp.*open" "$prev_scan" 2>/dev/null | awk '{print $1}' | cut -d/ -f1 | sort -n)
    
    local new_ports=$(comm -13 <(echo "$prev_ports") <(echo "$curr_ports") 2>/dev/null)
    local closed_ports=$(comm -23 <(echo "$prev_ports") <(echo "$curr_ports") 2>/dev/null)
    
    # Fixed: Handle empty strings properly
    local new_count=0
    if [ -n "$new_ports" ]; then
        new_count=$(echo "$new_ports" | grep -c "[0-9]" 2>/dev/null || echo 0)
    fi
    
    local closed_count=0
    if [ -n "$closed_ports" ]; then
        closed_count=$(echo "$closed_ports" | grep -c "[0-9]" 2>/dev/null || echo 0)
    fi
    
    echo -e "${CYAN}╔═══════════╦═══════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  CHANGE   ║  DETAILS                          ║${NC}"
    echo -e "${CYAN}╠═══════════╬═══════════════════════════════════╣${NC}"
    
    if [ "$new_count" -gt 0 ]; then
        echo -e "${CYAN}║${NC} ${RED}NEW PORTS${NC} ${CYAN}║${NC} ${RED}$new_count newly opened${NC}"
        echo "$new_ports" | while read port; do
            [ -z "$port" ] && continue
            echo -e "${CYAN}║${NC}           ${CYAN}║${NC}   ${RED}🔴 Port $port${NC}"
        done
    else
        echo -e "${CYAN}║${NC} ${GREEN}NEW PORTS${NC} ${CYAN}║${NC} ${GREEN}None${NC}"
    fi
    
    if [ "$closed_count" -gt 0 ]; then
        echo -e "${CYAN}║${NC} ${GREEN}CLOSED${NC}    ${CYAN}║${NC} ${GREEN}$closed_count ports closed${NC}"
    else
        echo -e "${CYAN}║${NC} ${YELLOW}CLOSED${NC}    ${CYAN}║${NC} ${YELLOW}None${NC}"
    fi
    
    echo -e "${CYAN}╚═══════════╩═══════════════════════════════════╝${NC}"
    echo ""
    
    if [ "$new_count" -gt 0 ]; then
        print_warning "ALERT: New ports opened since last scan!"
    else
        print_success "No new security risks detected"
    fi
}

# ============================================================================
# PORT SCANNING
# ============================================================================

analyze_port_risk() {
    local port=$1
    local risk="LOW"
    local reason=""
    
    case $port in
        21|23|445|3389|1433|3306)
            risk="HIGH"
            case $port in
                21) reason="FTP - Unencrypted file transfer" ;;
                23) reason="Telnet - Plaintext remote access" ;;
                445) reason="SMB - Ransomware vulnerability" ;;
                3389) reason="RDP - Brute-force target" ;;
                1433|3306) reason="Database exposed" ;;
            esac
            ;;
        80|443|22|25|53|8080)
            risk="MEDIUM"
            case $port in
                80|8080) reason="HTTP - Unencrypted web" ;;
                443) reason="HTTPS - Check SSL config" ;;
                22) reason="SSH - Use key authentication" ;;
                25) reason="Email - Check relay config" ;;
                53) reason="DNS - Monitor for attacks" ;;
            esac
            ;;
        *)
            risk="LOW"
            reason="Standard service port"
            ;;
    esac
    
    echo "$risk|$reason"
}

perform_port_scan() {
    local target=$1
    local scan_type=$2
    
    print_section_header "PORT SCANNING" "🔍"
    print_info "Target: ${WHITE}$target${NC}"
    
    local nmap_opts=""
    
    if [ "$scan_type" == "quick" ]; then
        nmap_opts="-sV -O --osscan-guess --top-ports 1000 -T4 --version-intensity 0 --host-timeout 10m"
        print_info "Mode: ${WHITE}QUICK SCAN${NC} (Top 1000 ports)"
        echo -e "${DIM}Estimated time: 1-3 minutes${NC}"
    else
        nmap_opts="-sV -O --osscan-guess -p- -T4 --version-intensity 0 --max-retries 2 --min-rate 1000 --max-rtt-timeout 200ms"
        print_info "Mode: ${WHITE}FULL SCAN${NC} (All 65,535 ports)"
        echo -e "${DIM}⚠  Estimated time: 30-60 minutes (can take longer)${NC}"
        echo -e "${DIM}This is a comprehensive scan and cannot be significantly shortened${NC}"
    fi
    
    echo ""
    echo -e "${CYAN}${BOLD}[SCAN IN PROGRESS]${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # Run nmap and filter out excessive fingerprint data
    nmap $nmap_opts "$target" 2>&1 | grep -v "^SF:" | grep -v "Service detection performed" | tee "$TEMP_SCAN.clean"
    local scan_result=${PIPESTATUS[0]}
    
    # Save full output for analysis but use cleaned version for display
    nmap $nmap_opts "$target" > "$TEMP_SCAN" 2>&1
    cp "$TEMP_SCAN.clean" "$TEMP_SCAN"
    
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    if [ $scan_result -ne 0 ] || [ ! -f "$TEMP_SCAN" ] || [ ! -s "$TEMP_SCAN" ]; then
        print_error "Scan failed or returned no results"
        print_info "Possible reasons:"
        echo -e "  ${DIM}• Host is down or unreachable${NC}"
        echo -e "  ${DIM}• Firewall blocking scan${NC}"
        echo -e "  ${DIM}• Invalid target${NC}"
        return 1
    fi
    
    print_success "Scan completed successfully!"
    echo ""
    
    analyze_scan_results "$target"
}

analyze_scan_results() {
    local target=$1
    
    print_section_header "SCAN ANALYSIS" "📊"
    
    local os_info=$(grep "OS details:" "$TEMP_SCAN" | cut -d: -f2- | xargs)
    [ -z "$os_info" ] && os_info="Unknown"
    
    local open_ports=$(grep "^[0-9]*/tcp.*open" "$TEMP_SCAN")
    local port_count=0
    
    # Fixed: Handle empty open_ports properly
    if [ -n "$open_ports" ]; then
        port_count=$(echo "$open_ports" | grep -c "open" 2>/dev/null || echo 0)
    fi
    
    echo -e "${CYAN}🎯 Target:${NC} ${WHITE}$target${NC}"
    [ -n "$TARGET_DOMAIN" ] && echo -e "${CYAN}🌐 Domain:${NC} ${WHITE}$TARGET_DOMAIN${NC}"
    echo -e "${CYAN}💻 OS:${NC} ${WHITE}$os_info${NC}"
    echo -e "${CYAN}📄 Open Ports:${NC} ${WHITE}$port_count${NC}"
    echo ""
    
    local high_risk=0
    local medium_risk=0
    local low_risk=0
    
    {
        echo "══════════════════════════════════════════════════════════════="
        echo "SECURITY SCAN REPORT"
        echo "══════════════════════════════════════════════════════════════="
        echo "Date: $(date)"
        echo "Target: $target"
        [ -n "$TARGET_DOMAIN" ] && echo "Domain: $TARGET_DOMAIN"
        echo "OS: $os_info"
        echo "Open Ports: $port_count"
        echo ""
        echo "PORT ANALYSIS"
        echo "──────────────────────────────────────────────────────────────-"
        printf "%-10s %-20s %-12s %-30s\n" "PORT" "SERVICE" "RISK" "CONCERN"
        echo "──────────────────────────────────────────────────────────────-"
    } > "$CURRENT_REPORT"
    
    if [ "$port_count" -gt 0 ]; then
        echo -e "${CYAN}╔══════════╦══════════════════╦══════════════╦═══════════════════════════╗${NC}"
        echo -e "${CYAN}║   PORT   ║     SERVICE      ║     RISK     ║         CONCERN           ║${NC}"
        echo -e "${CYAN}╠══════════╬══════════════════╬══════════════╬═══════════════════════════╣${NC}"
        
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            
            local port=$(echo "$line" | awk '{print $1}' | cut -d/ -f1)
            local service=$(echo "$line" | awk '{print $3}')
            [ -z "$service" ] && service="unknown"
            
            local risk_info=$(analyze_port_risk "$port")
            local risk=$(echo "$risk_info" | cut -d'|' -f1)
            local reason=$(echo "$risk_info" | cut -d'|' -f2)
            
            case $risk in
                HIGH) ((high_risk++)); risk_color="${RED}" ;;
                MEDIUM) ((medium_risk++)); risk_color="${YELLOW}" ;;
                LOW) ((low_risk++)); risk_color="${GREEN}" ;;
            esac
            
            # Proper table formatting
            printf "${WHITE}║${NC} %-8s ${WHITE}║${NC} %-16s ${WHITE}║${NC} ${risk_color}%-12s${NC} ${WHITE}║${NC} %-25s ${WHITE}║${NC}\n" \
                "$port" "${service:0:16}" "$risk" "${reason:0:25}"
            
            printf "%-10s %-20s %-12s %-30s\n" "$port" "$service" "$risk" "$reason" >> "$CURRENT_REPORT"
            
        done <<< "$open_ports"
        
        echo -e "${CYAN}╚══════════╩══════════════════╩══════════════╩═══════════════════════════╝${NC}"
    else
        echo -e "${GREEN}🔒  No open ports detected - System secure${NC}"
        echo "No open ports detected" >> "$CURRENT_REPORT"
    fi
    
    echo ""
    
    local overall="LOW"
    if [ "$high_risk" -ge 3 ]; then
        overall="CRITICAL"
    elif [ "$high_risk" -ge 1 ]; then
        overall="HIGH"
    elif [ "$medium_risk" -ge 4 ]; then
        overall="MEDIUM"
    fi
    
    print_section_header "RISK SUMMARY" "📊"
    echo -e "${RED}🔴  High Risk: $high_risk${NC}"
    echo -e "${YELLOW}⚠  Medium Risk: $medium_risk${NC}"
    echo -e "${GREEN}✅  Low Risk: $low_risk${NC}"
    echo ""
    
    case $overall in
        CRITICAL)
            draw_box "OVERALL RISK: CRITICAL" "${RED}" "☠"
            echo -e "${RED}${BOLD}URGENT: Multiple critical vulnerabilities!${NC}"
            ;;
        HIGH)
            draw_box "OVERALL RISK: HIGH" "${RED}" "🔥"
            echo -e "${RED}${BOLD}WARNING: Immediate action required!${NC}"
            ;;
        MEDIUM)
            draw_box "OVERALL RISK: MEDIUM" "${YELLOW}" "⚠"
            echo -e "${YELLOW}Security review recommended${NC}"
            ;;
        LOW)
            draw_box "OVERALL RISK: LOW" "${GREEN}" "✅"
            echo -e "${GREEN}System appears secure${NC}"
            ;;
    esac
    
    {
        echo ""
        echo "══════════════════════════════════════════════════════════════="
        echo "RISK SUMMARY"
        echo "──────────────────────────────────────────────────────────────-"
        echo "High Risk: $high_risk"
        echo "Medium Risk: $medium_risk"
        echo "Low Risk: $low_risk"
        echo "OVERALL: $overall"
        echo "══════════════════════════════════════════════════════════════="
    } >> "$CURRENT_REPORT"
    
    echo ""
    
    save_scan_history "$target"
    compare_with_history "$target"
    
    if [ "$high_risk" -gt 0 ]; then
        generate_autofix_scripts "$target"
    fi
    
    generate_html_report "$target" "$high_risk" "$medium_risk" "$low_risk" "$overall"
    
    print_success "Reports saved to: ${WHITE}$REPORTS_DIR/${NC}"
}

# ============================================================================
# AUTO-FIX GENERATOR
# ============================================================================

generate_autofix_scripts() {
    local target=$1
    
    print_section_header "AUTO-FIX GENERATOR" "🔧"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local fix_script="$FIXES_DIR/fix_${target//[:.\/]/}$timestamp.sh"
    
    cat > "$fix_script" << 'ENDSCRIPT'
#!/bin/bash
echo "Security Fix Script"
echo "Generated: TIMESTAMP"
echo ""
read -p "Apply fixes? (yes/no): " confirm
[ "$confirm" != "yes" ] && exit 1
echo "Applying security fixes..."
ENDSCRIPT
    
    sed -i "s/TIMESTAMP/$(date)/g" "$fix_script"
    
    local high_ports=$(grep "HIGH" "$CURRENT_REPORT" | awk '{print $1}' | grep -E '^[0-9]+$')
    
    while read -r port; do
        [ -z "$port" ] && continue
        
        case $port in
            21)
                echo 'echo "[*] Blocking FTP..."' >> "$fix_script"
                echo 'sudo ufw deny 21/tcp 2>/dev/null || sudo iptables -A INPUT -p tcp --dport 21 -j DROP' >> "$fix_script"
                echo 'echo "[✓] FTP blocked"' >> "$fix_script"
                echo '' >> "$fix_script"
                ;;
            23)
                echo 'echo "[*] Blocking Telnet..."' >> "$fix_script"
                echo 'sudo ufw deny 23/tcp 2>/dev/null || sudo iptables -A INPUT -p tcp --dport 23 -j DROP' >> "$fix_script"
                echo 'echo "[✓] Telnet blocked"' >> "$fix_script"
                echo '' >> "$fix_script"
                ;;
        esac
    done <<< "$high_ports"
    
    echo 'echo "Fixes applied!"' >> "$fix_script"
    chmod +x "$fix_script"
    
    draw_box "Fix Script Created" "${GREEN}" "✅"
    echo -e "${WHITE}  Location: $fix_script${NC}"
    echo ""
}

# ============================================================================
# HTML REPORT
# ============================================================================

generate_html_report() {
    local target=$1
    local high=$2
    local medium=$3
    local low=$4
    local overall=$5
    
    cat > "$HTML_REPORT" << 'ENDHTML'
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body { font-family: Arial; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; margin: 0; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 15px; box-shadow: 0 10px 40px rgba(0,0,0,0.3); }
        h1 { color: #2d3436; border-bottom: 4px solid #0984e3; padding-bottom: 15px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 10px; margin-bottom: 30px; }
        .risk-high { color: #d63031; font-weight: bold; }
        .risk-medium { color: #fdcb6e; font-weight: bold; }
        .risk-low { color: #00b894; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 15px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
        .summary { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 30px 0; }
        .card { padding: 25px; border-radius: 10px; text-align: center; color: white; }
        .card-high { background: linear-gradient(135deg, #ff7675 0%, #d63031 100%); }
        .card-medium { background: linear-gradient(135deg, #ffeaa7 0%, #fdcb6e 100%); color: #2d3436; }
        .card-low { background: linear-gradient(135deg, #55efc4 0%, #00b894 100%); }
        .overall { background: #ffeaa7; padding: 30px; border-radius: 10px; margin: 30px 0; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡 Security Scan Report</h1>
        <div class="header">
            <p><strong>Target:</strong> TARGET_IP</p>
            <p><strong>Date:</strong> DATE_TIME</p>
        </div>
        <h2>Risk Summary</h2>
        <div class="summary">
            <div class="card card-high"><h3>HIGH_COUNT</h3><p>High Risk</p></div>
            <div class="card card-medium"><h3>MEDIUM_COUNT</h3><p>Medium Risk</p></div>
            <div class="card card-low"><h3>LOW_COUNT</h3><p>Low Risk</p></div>
        </div>
        <div class="overall">
            <h3>Overall Risk: OVERALL_RISK</h3>
        </div>
        <h2>Port Details</h2>
        <table>
            <tr><th>Port</th><th>Service</th><th>Risk</th><th>Concern</th></tr>
ENDHTML

    grep -E "^[0-9]+" "$CURRENT_REPORT" | tail -n +2 | while IFS= read -r line; do
        local port=$(echo "$line" | awk '{print $1}')
        local service=$(echo "$line" | awk '{print $2}')
        local risk=$(echo "$line" | awk '{print $3}')
        local concern=$(echo "$line" | cut -d' ' -f4-)
        echo "<tr><td>$port</td><td>$service</td><td class='risk-${risk,,}'>$risk</td><td>$concern</td></tr>" >> "$HTML_REPORT"
    done
    
    cat >> "$HTML_REPORT" << 'ENDHTML'
        </table>
    </div>
</body>
</html>
ENDHTML
    
    sed -i "s/TARGET_IP/$target/g" "$HTML_REPORT"
    sed -i "s/DATE_TIME/$(date)/g" "$HTML_REPORT"
    sed -i "s/HIGH_COUNT/$high/g" "$HTML_REPORT"
    sed -i "s/MEDIUM_COUNT/$medium/g" "$HTML_REPORT"
    sed -i "s/LOW_COUNT/$low/g" "$HTML_REPORT"
    sed -i "s/OVERALL_RISK/$overall/g" "$HTML_REPORT"
    
    print_success "HTML report: ${WHITE}$HTML_REPORT${NC}"
}

# ============================================================================
# SCANNING FUNCTIONS
# ============================================================================

scan_target() {
    local target=$1
    local scan_type=$2
    
    # Determine if target is IP or domain
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        TARGET_IP="$target"
        TARGET_DOMAIN=""
    else
        # Remove protocol and path from URL
        target=$(echo "$target" | sed 's|https\?://||' | sed 's|/.||' | sed 's|:.||')
        
        print_info "Resolving: ${WHITE}$target${NC}"
        # FIXED: close regex and capture only IPv4 addresses
        TARGET_IP=$(dig +short "$target" A | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)
        
        if [ -z "$TARGET_IP" ]; then
            TARGET_IP=$(host "$target" 2>/dev/null | grep "has address" | awk '{print $4}' | head -n1)
        fi
        
        if [ -z "$TARGET_IP" ]; then
            print_error "Could not resolve domain"
            return 1
        fi
        
        TARGET_DOMAIN="$target"
        print_success "Resolved to: ${WHITE}$TARGET_IP${NC}"
    fi
    
    echo ""
    check_threat_intelligence "$TARGET_IP"
    perform_port_scan "$TARGET_IP" "$scan_type"
}

# ============================================================================
# MENU SYSTEM
# ============================================================================

show_main_menu() {
    while true; do
        local choice=$(dialog --clear --backtitle "Enhanced Security Scanner v1.0" \
            --title "🚀 Main Menu" \
            --menu "\nChoose an option:" 16 70 8 \
            1 "🎯 Scan Target (IP/Domain) - Quick" \
            2 "🔥 Scan Target (IP/Domain) - Full" \
            3 "📄 View Latest Report" \
            4 "📜 View Scan History" \
            5 "ℹ  About" \
            6 "❌ Exit" \
            3>&1 1>&2 2>&3)
        
        local exit_status=$?
        clear
        
        if [ $exit_status -ne 0 ]; then
            exit_program
        fi
        
        case $choice in
            1) scan_menu "quick" ;;
            2) scan_menu "full" ;;
            3) view_latest_report ;;
            4) view_history ;;
            5) show_about ;;
            6) exit_program ;;
        esac
    done
}

scan_menu() {
    local scan_type=$1
    local scan_name="Quick Scan"
    local port_info="Top 1000 ports (~1-3 minutes)"
    
    if [ "$scan_type" == "full" ]; then
        scan_name="Full Scan"
        port_info="All 65,535 ports (⚠  30-60+ minutes)"
    fi
    
    local target=$(dialog --clear --backtitle "Enhanced Security Scanner" \
        --title "🎯 $scan_name" \
        --inputbox "\nEnter IP address or domain:\n\nExamples:\n  192.168.1.1\n  example.com\n  https://example.com\n\n$port_info\n\n⚠  Warning: Full scans take 30-60+ minutes and cannot be\nsignificantly shortened due to network limitations." 18 65 \
        3>&1 1>&2 2>&3)
    
    clear
    
    if [ -n "$target" ]; then
        print_banner
        scan_target "$target" "$scan_type"
        echo ""
        read -p "Press Enter to continue..."
    fi
}

view_latest_report() {
    print_banner
    print_section_header "LATEST SCAN REPORT" "📄"
    
    if [ -f "$CURRENT_REPORT" ]; then
        cat "$CURRENT_REPORT"
        echo ""
        
        if [ -f "$HTML_REPORT" ]; then
            print_info "HTML report: ${WHITE}$HTML_REPORT${NC}"
            read -p "Open HTML report? (y/n): " open_html
            if [ "$open_html" = "y" ]; then
                xdg-open "$HTML_REPORT" 2>/dev/null || open "$HTML_REPORT" 2>/dev/null || echo "Open manually: $HTML_REPORT"
            fi
        fi
    else
        print_warning "No scan report found"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

view_history() {
    print_banner
    print_section_header "SCAN HISTORY" "📜"
    
    local history_files=$(ls -t "$HISTORY_DIR"/*.txt 2>/dev/null)
    
    if [ -z "$history_files" ]; then
        print_warning "No scan history found"
    else
        echo -e "${CYAN}Recent scans:${NC}\n"
        local count=1
        
        while IFS= read -r file; do
            local basename=$(basename "$file")
            local target=$(echo "$basename" | sed 's/[0-9]*\.txt//' | tr '' '.')
            local date=$(echo "$basename" | grep -o '[0-9]\{8\}_[0-9]\{6\}')
            
            echo -e "${WHITE}$count.${NC} Target: ${CYAN}$target${NC}  |  Date: ${YELLOW}${date:0:8}${NC}"
            ((count++))
            
            [ $count -gt 10 ] && break
        done <<< "$history_files"
        
        echo ""
        print_info "Total scans: $(ls "$HISTORY_DIR"/*.txt 2>/dev/null | wc -l)"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

show_about() {
    dialog --clear --backtitle "Enhanced Security Scanner v1.0" \
        --title "ℹ  About" \
        --msgbox "🛡 ENHANCED SECURITY SCANNER v1.0

🚀 FEATURES:
• Quick Scan - Top 1000 ports (~1-3 minutes)
• Full Scan - All 65,535 ports (~30-60+ minutes)
• Threat intelligence lookup
• Historical scan comparison
• Auto-fix script generation
• HTML reports with styling
• Real-time scan output

📂 DIRECTORIES:
• $REPORTS_DIR/ - Scan reports
• $HISTORY_DIR/ - Historical scans
• $FIXES_DIR/ - Auto-fix scripts

🔍 SCAN OPTIONS:
Quick Scan: Fast security check of 1000 common ports
Full Scan: Thorough audit of all ports (very time-consuming)

⏱  TIME REQUIREMENTS:
Quick Scan: 1-3 minutes
Full Scan: 30-60+ minutes (cannot be reduced due to
           network latency and the sheer number of ports)

📋 REQUIREMENTS:
• nmap, dialog, dnsutils
• Install: sudo apt install nmap dialog dnsutils -y

⚠  LEGAL NOTICE:
Only scan systems you own or have permission to test.
Unauthorized scanning may be illegal.

Created for educational purposes." 36 70
    
    clear
}

exit_program() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                       ║"
    echo "║         🛡  Thank you for using Security Scanner! 🛡                 ║"
    echo "║                                                                       ║"
    echo "║              🔒 Stay secure and scan responsibly 🔒                   ║"
    echo "║                                                                       ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}\n"
    
    rm -f "$TEMP_SCAN" "$TEMP_SCAN.clean"
    exit 0
}

# ============================================================================
# CLI MODE
# ============================================================================

cli_menu() {
    while true; do
        print_banner
        echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════════════════╗"
        echo -e "║                          MAIN MENU                                    ║"
        echo -e "╚═══════════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${WHITE}1.${NC} 🎯 Scan Target (IP/Domain) - Quick"
        echo -e "${WHITE}2.${NC} 🔥 Scan Target (IP/Domain) - Full"
        echo -e "${WHITE}3.${NC} 📄 View Latest Report"
        echo -e "${WHITE}4.${NC} 📜 View Scan History"
        echo -e "${WHITE}5.${NC} ℹ  About"
        echo -e "${WHITE}6.${NC} ❌ Exit"
        echo ""
        read -p "Choose [1-6]: " choice
        
        case $choice in
            1)
                read -p "Enter IP/Domain: " target
                [ -n "$target" ] && { print_banner; scan_target "$target" "quick"; read -p "Press Enter..."; }
                ;;
            2)
                read -p "Enter IP/Domain: " target
                [ -n "$target" ] && { print_banner; scan_target "$target" "full"; read -p "Press Enter..."; }
                ;;
            3)
                view_latest_report
                ;;
            4)
                view_history
                ;;
            5)
                print_banner
                echo -e "${CYAN}${BOLD}ABOUT${NC}\n"
                echo "🛡  Enhanced Security Scanner v1.0"
                echo ""
                echo "Features: Threat Intel | History | Auto-Fix | Reports"
                echo ""
                echo "Quick Scan: Top 1000 ports (~1-3 minutes)"
                echo "Full Scan: All 65,535 ports (~30-60+ minutes)"
                echo ""
                echo "⚠  Note: Full scans cannot be significantly shortened"
                echo "    due to network latency and protocol timing requirements."
                echo ""
                read -p "Press Enter..."
                ;;
            6)
                exit_program
                ;;
            *)
                print_error "Invalid choice"
                sleep 1
                ;;
        esac
    done
}

# ============================================================================
# MAIN PROGRAM
# ============================================================================

main() {
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        print_banner
        echo -e "${CYAN}${BOLD}USAGE:${NC}"
        echo -e "  sudo $0                    ${DIM}# Interactive mode${NC}"
        echo -e "  sudo $0 --help             ${DIM}# Show help${NC}"
        echo ""
        echo -e "${CYAN}${BOLD}FEATURES:${NC}"
        echo -e "  🌐 Threat Intelligence - IP reputation lookup"
        echo -e "  📜 Historical Tracking - Compare scans over time"
        echo -e "  🔧 Auto-Fix Scripts - Generate security fixes"
        echo -e "  📊 HTML Reports - Beautiful visual reports"
        echo -e "  🔍 Quick Scan - Top 1000 ports (~1-3 minutes)"
        echo -e "  🔥 Full Scan - All 65,535 ports (~30-60+ minutes)"
        echo -e "  ⚡ Real-time Output - See scan progress live"
        echo ""
        echo -e "${CYAN}${BOLD}SCAN OPTIONS:${NC}"
        echo -e "  • Quick Scan: Fast check of 1000 most common ports"
        echo -e "  • Full Scan: Comprehensive audit of all 65,535 ports"
        echo -e "    ${DIM}(Full scans take 30-60+ minutes and cannot be reduced"
        echo -e "    due to network timing and protocol requirements)${NC}"
        echo ""
        echo -e "${CYAN}${BOLD}REQUIREMENTS:${NC}"
        echo -e "  • nmap, dialog, dnsutils"
        echo -e "  • Install: ${WHITE}sudo apt install nmap dialog dnsutils -y${NC}"
        echo ""
        exit 0
    fi
    
    print_banner
    check_dependencies
    
    if [ "$EUID" -ne 0 ]; then
        print_warning "Not running as root - some scans may be limited"
        print_info "For full functionality: ${WHITE}sudo $0${NC}"
        echo ""
        sleep 2
    else
        print_success "Running with root privileges"
    fi
    
    echo ""
    print_success "Scanner initialized"
    print_info "Starting interactive mode..."
    echo ""
    sleep 2
    
    if command -v dialog >/dev/null 2>&1; then
        show_main_menu
    else
        print_warning "Dialog not available - using CLI mode"
        sleep 2
        cli_menu
    fi
}

main "$@"
