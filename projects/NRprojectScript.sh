#!/bin/bash
#=================================
#set -euo pipefail
#stops on errors
#detect failure inside pipelines
#reject use of undefined variables
#=================================
set -euo pipefail

AuditLog="$HOME/Desktop/audit.log"
 touch "$AuditLog"
# ================================
# ANSI COLORS
# ================================
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
CYAN='\e[36m'
MAGENTA='\e[35m'
RESET='\e[0m'
BOLD='\e[1m'

LINE="${MAGENTA}=========================================${RESET}"
# ================================
# AUDIT LOGGING FUNCTION
# ================================
log_action() {
    local action="$1"
    local comment="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: $action - $comment" >> "$AuditLog"
}

# ================================
# INSTALL REQUIRED APPS
# ================================
function APP_INSTALL() 
{
    echo -e "${CYAN}🔍 Checking and installing required applications...${RESET}"
    echo -e "$LINE"

    APPS=( "sshpass" "tor" "nmap" "whois" )
    for A in "${APPS[@]}" ; do
        if ! command -v "$A" >/dev/null 2>&1 ; then 
            echo -e "${YELLOW}Installing $A...${RESET}"
            sudo apt-get install -y "$A" >/dev/null 2>&1
            log_action "install $A" "$A installed"

        else
            echo -e "${GREEN}✅ $A is already installed.${RESET}"
            log_action "Check $A" "$A is already installed"

        fi
    done

    if ! command -v geoiplookup >/dev/null 2>&1; then
        echo -e "${YELLOW}Installing Geoiplookup...${RESET}"
        sudo apt-get install geoip-bin -y >/dev/null 2>&1 
    else 
        echo -e "${GREEN}✅ Geoiplookup is already installed.${RESET}"
    fi
}
APP_INSTALL
echo -e "$LINE"

# ================================
# VERIFY INSTALLATIONS
# ================================
function IF_INSTALLED() {
    echo -e "${CYAN}🔍 Verifying installed tools...${RESET}"
    echo -e "$LINE"

    TOOLS=( "sshpass" "tor" "nmap" "whois" "geoiplookup" )
    for T in "${TOOLS[@]}"; do 
        if ! command -v "$T" >/dev/null 2>&1; then 
            echo -e "${RED}❌ $T is NOT installed! Install manually.${RESET}"
        else
            echo -e "${GREEN}✔️  $T is installed successfully.${RESET}"
        fi
    done
}
IF_INSTALLED
echo -e "$LINE"

# ================================
# INSTALL NIPE
# ================================
function NIPE_INSTALL() {
    echo -e "${CYAN}📥 Installing and setting up Nipe...${RESET}"

    git clone https://github.com/htrgouvea/nipe >/dev/null 2>&1 && cd nipe 
    sudo apt install cpanminus -y >/dev/null 2>&1
    sudo cpanm --notest --quiet --sudo --installdeps . >/dev/null 2>&1
    sudo perl nipe.pl install >/dev/null 2>&1
    sudo systemctl start tor
    sudo systemctl start ssh
    echo -e "${YELLOW}Starting nipe service...${RESET}"
    sudo perl nipe.pl start 
}
NIPE_INSTALL
echo -e "$LINE"

# ================================
# CHECK ANONYMITY
# ================================
function CHECK_ANONYMITY() {
    echo -e "$LINE"
    echo -e "${CYAN}🔎 Checking network anonymity...${RESET}"

    IP=$(curl -s ifconfig.co)
    COUNTRY=$(geoiplookup "$IP" | awk -F ': ' '{print $2}')

    if echo "$COUNTRY" | grep -iqE "Israel|IL"; then
        echo -e "${RED}❌ You're NOT anonymous. Exiting now.${RESET}"
log_action "Check Anonymity" "Real IP detected: $IP"
        
        exit 1
    else 
        echo -e "$LINE"
        echo -e "${GREEN}✅ You're anonymous!${RESET}"
        echo -e "${YELLOW}🌍 IP: $IP${RESET}"
        echo -e "${YELLOW}📌 Spoofed Country: $COUNTRY${RESET}"
log_action "Check Anonymity" "Spoofed country: $COUNTRY (IP: $IP)"

    fi
    
    
}
CHECK_ANONYMITY
echo -e "$LINE"

# ================================
# REMOTE VPS EXECUTION
# ================================ 
function RMT_VPS () 
{
    RemoteScanResults="$HOME/Desktop/RemoteScanReport"
    mkdir -p "$RemoteScanResults"

    echo -e "$LINE"
    read -p "PW of the Remote Server: " RMSPW
    read -p "USER of the Remote Server: " RMSUS
    read -p "IP of the Remote Server: " RMSIP
    read -p "Enter target domain/IP for scanning: " TARGET

    echo -e "${CYAN}[+] Running scan on remote VPS...${RESET}"
log_action "Retrieve Remote Details" "Server IP: $RMSIP"
log_action "Set Scan Target" "Target: $TARGET"
   sshpass -p "$RMSPW" ssh -o StrictHostKeyChecking=no "$RMSUS@$RMSIP" "
        mkdir -p ~/scan_reports
        REPORT=~/scan_reports/${TARGET}_report_$(date +%F_%H-%M).txt

        echo '========== SYSTEM INFO ==========' >> \"\$REPORT\"
        echo 'Hostname:' \$(hostname) >> \"\$REPORT\"
        echo 'Uptime:' >> \"\$REPORT\"
        uptime >> \"\$REPORT\"

        echo '========== PUBLIC IP ==========' >> \"\$REPORT\"
        IP=\$(curl -s ifconfig.co)
        echo \"IP: \$IP\" >> \"\$REPORT\"
        geoiplookup \"\$IP\" >> \"\$REPORT\"

        echo '========== WHOIS ($TARGET) ==========' >> \"\$REPORT\"
        whois \"$TARGET\" >> \"\$REPORT\"

        echo '========== NMAP ($TARGET) ==========' >> \"\$REPORT\"
        nmap -sV -T4 --top-ports 200 \"$TARGET\" >> \"\$REPORT\"

        echo \"===== REPORT SAVED ON VPS: \$REPORT =====\"
    "
     sshpass -p "$RMSPW" scp -o StrictHostKeyChecking=no \
    "$RMSUS@$RMSIP:~/scan_reports/${TARGET}_report_*" \
    "$RemoteScanResults/"
log_action "Save Scan Report" "Saved results for $TARGET"
log_action "WHOIS Lookup" "Completed WHOIS for $TARGET"
log_action "Nmap Scan" "Completed Nmap scan for $TARGET"
    echo -e "${YELLOW}============= Saving results =============${RESET}"
    {
        echo "=============================================="
        echo " Scan Audit Record"
        echo " Timestamp        : $(date)"
        echo " Remote Server IP : $RMSIP"
        echo " Remote Username  : $RMSUS"
        echo " Target Scanned   : $TARGET"
        echo " Report Saved To  : $RemoteScanResults/${TARGET}_report_$(date +%F_%H-%M).txt"
    } >> "$AuditLog"

    echo -e "${GREEN}================== Done ==================${RESET}"
}
RMT_VPS
