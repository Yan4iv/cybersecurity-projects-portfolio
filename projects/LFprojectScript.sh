#!/bin/bash

# ================================
# ANSI color codes for readability
# ================================
YELLOW='\e[33m'
RED='\e[31m'
CYAN='\e[36m'
RESET='\e[0m'

# ==========================================================
# Function: mynet_info
# Purpose: Display key network information of the machine:
#          - Public IP address
#          - Private/host IP address
#          - MAC address of the network interface
# Notes:
#   • curl ifconfig.me queries an external service to identify public IP.
#   • hostname -I prints all assigned internal IP addresses.
#   • ifconfig | grep "ether" extracts MAC address lines.
# ==========================================================
mynet_info() {
    echo -e "${RED}My public IP address is:${RESET}"
    curl ifconfig.me   # Retrieves public IP from external service
    echo " "
    echo  "----------------------------------"

    echo -e "${RED}My host(private) IP address is:${RESET}"
    hostname -I        # Prints internal/private IP address
    echo  "----------------------------------"

    echo -e "${RED}My Device's MAC address:${RESET}"
    ifconfig | grep "ether" | awk '{print $2}'   # Extracts MAC address field
    echo  "----------------------------------"
}
mynet_info

# ==========================================================
# Function: syshardware_info
# Purpose: Display system hardware + performance information:
#          - Top 5 running processes by CPU usage
#          - RAM usage summary
#          - Currently active services
# Notes:
#   • ps -eo ... lists all processes with chosen columns.
#   • top -b -n 1 prints non-interactive system stats (memory usage).
#   • service --status-all shows all services (+ = running).
# ==========================================================
syshardware_info() {
    echo -e "${CYAN} **Top 5 Running processes** ${RESET}"
    echo  "----------------------------------"
    ps -eo pid,comm,%cpu,%mem --sort=-%cpu | head -n 6   # Sorted by highest CPU usage
    echo  "----------------------------------"

    echo -e "${CYAN} RAM memory Usage statistics ${RESET}"
    echo  "----------------------------------"
    top -b -n 1 | grep "MiB Mem" | awk '{print $2,$3,$4,$5,$6,$7}'   # Extract memory fields
    echo  "----------------------------------"

    echo -e "${CYAN} list of active services  ${RESET}"
    echo  "----------------------------------"
    service --status-all | grep '+'   # Filters only running services
    echo  "----------------------------------"
}
syshardware_info

# ==========================================================
# Prompt: Ask user if they want to display 10 largest files
# Notes:
#   • find /home -type f searches for all files inside /home.
#   • du -h {} prints size of each file in human-readable format.
#   • sort -rh sorts by size (largest first).
#   • head -n 10 limits to top 10 entries.
# ==========================================================
echo -e " ${YELLOW} Would you also like to display Top 10 Largest files in home? ${RESET} [Yes\\No] "
read -r answer

if [[ "$answer" =~ ^[Yy][Ee]?[Ss]?$ ]]; then
    echo -e "$(YELLOW)Loading... This might take a minute${RESET}"
    echo -e "${CYAN}Top 10 Largest Files in /home:${RESET}"
    echo "----------------------------------"
    find /home -type f -exec du -h {} \; 2>/dev/null | sort -rh | head -n 10
    echo "----------------------------------"
else
    echo -e "${RED} skipping file size check ${RESET}"
fi
