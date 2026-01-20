#!/bin/bash


START_TIME=$(date +"%Y-%m-%d %H:%M:%S")
START_EPOCH=$(date +%s)
#===========================================================================
# Ansi color variables because we love them for our eyes
#===========================================================================
GREEN='\e[0;32m'
RED='\e[0;31m'
BLUE='\e[0;34m'
DARKGREY='\e[1;30m'
RESET='\e[0m'
LINE="============================================="

echo -e "${BLUE}${LINE}${RESET}"
#===========================================================================
# A fast check to see if user is root , if not it will exit
#===========================================================================
REAL_USER="${SUDO_USER:-$USER}"
if [ $(whoami) != "root" ] ;
then 
echo -e "${RED}Exiting ... run as root${RESET}" 
	exit 1
	else 
	echo -e "${GREEN}You're Root , Continuing...${RESET}"
fi
echo -e "${BLUE}${LINE}${RESET}"

#===========================================================================
# User input for a file name that is going to be investigated
#===========================================================================

read -p "Enter your file name to analyze:" FILENM
filepath=$(find /home/$REAL_USER/Desktop -type f -name "$FILENM" 2>/dev/null )
if [ -z "$filepath" ]; then
    echo -e "${RED}Your file doesn't exist,Please enter a valid file${RESET}"
    exit 1
else
    echo -e "${GREEN}Found required file at${RESET} ${RED}: "$filepath" ${RESET}"
    echo -e "${GREEN}Initiating analysis...${RESET}"
fi
echo -e "${BLUE}${LINE}${RESET}"

#===========================================================================
# Declaring an array of tools to install 
# To loop them in a for loop installing them 1 by 1 if not installed already
#===========================================================================
declare -A Packages=(
    [foremost]="foremost"
    [scalpel]="scalpel"
    [bulk_extractor]="bulk-extractor"
    [binwalk]="binwalk"
    [strings]="binutils"
    [file]="file"
    [exiftool]="libimage-exiftool-perl"
)
for tool in "${!Packages[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo -e "${RED}Installing missing tool: $tool ${RESET}"
        apt install -y "${Packages[$tool]}" >/dev/null 2>&1
    else
        echo -e "${GREEN}$tool already installed ${RESET}"
    fi
done
echo -e "${BLUE}${LINE}${RESET}"

#===========================================================================
#Extracting the file using various tools and save into a directory
#===========================================================================

echo -e "${GREEN}Extracting Data using carvers, it will take a while... ${RESET}"
OUTDIR="/home/$REAL_USER/Desktop/Extracted_Data"
mkdir -p "$OUTDIR"
REPORT="$OUTDIR/REPORT.txt"
VOL_LOG="$OUTDIR/volatility_plugins.log"
: > "$VOL_LOG"
mkdir -p "$OUTDIR/bulk"
mkdir -p "$OUTDIR/binwalk"
mkdir -p "$OUTDIR/foremost" 
echo -e "${GREEN}Running Bulk Extractor on the file [+]${RESET}"
bulk_extractor "$filepath" -o "$OUTDIR/bulk" >/dev/null 2>&1
echo -e "${GREEN}Running Binwalk on the file [+]${RESET}"
binwalk -e "$filepath" -C "$OUTDIR/binwalk" >/dev/null 2>&1
echo -e "${GREEN}Running foremost on the file [+]${RESET}" 
foremost -i "$filepath" -o "$OUTDIR/foremost" >/dev/null 2>&1
echo -e "${GREEN}Running strings on the file [+}${RESET}"
strings "$filepath" > "$OUTDIR/strings.txt" 2>/dev/null
echo -e "${GREEN}[+] Extraction completed.${RESET}"
echo -e "${BLUE}${LINE}${RESET}"

#===========================================================================
#Checking if network traffic file was extracted by one of the tools
#===========================================================================
echo -e "${GREEN}Checking for network traffic file...${RESET}"
PCAP=$(find "$OUTDIR" -type f -name "*.pcap" 2>/dev/null | head -n 1 )
if [ -z "$PCAP" ] ; then 
echo -e "${RED}Network traffic file is not found [-]${RESET}"
else
echo -e "${GREEN}Found Network Traffic File at:${RESET}" "$PCAP"
fi
echo -e "${BLUE}${LINE}${RESET}"
#===========================================================================
#Checks for human readable using strings and grep & saves into a text file 
#===========================================================================
echo -e "${GREEN}Extracting useful artifacts using strings...${RESET}"
echo -e "${BLUE}${LINE}${RESET}"
grep -iE "pass|user|key|token" "$OUTDIR/strings.txt" > "$OUTDIR/creds.txt"  
grep -iE "http[s]?://" "$OUTDIR/strings.txt" > "$OUTDIR/url.txt"S
grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" "$OUTDIR/strings.txt" > "$OUTDIR/ips.txt"
echo -e "${GREEN}Finished Extraction, using strings!${RESET}"
echo -e "${BLUE}${LINE}${RESET}"
#===========================================================================
#Installing volatility
#===========================================================================
echo -e "${GREEN}Installing dependencies and volatility to perform extraction...${RESET}"
VOL_DIR="/home/$REAL_USER/Desktop/volatility3"
VOL_PATH="$VOL_DIR/vol.py"
pip3 install capstone simplejson pycryptodome pillow openpyxl ujson yara-python --break-system-packages > /dev/null 2>&1
apt install python3 python3-pip -y   > /dev/null 2>&1
if [ ! -d "$VOL_DIR" ]; then
    git clone https://github.com/volatilityfoundation/volatility3.git >/dev/null 2>&1 "$VOL_DIR"
fi
chown -R "$REAL_USER:$REAL_USER" "$OUTDIR" "$VOL_DIR"


#===========================================================================
# Detect memory dump by EXTENSION or FILE SIGNATURE
#===========================================================================
echo -e "${GREEN}Checking if file is memory-dump compatible...${RESET}"
FILE_TYPE=$(file -b "$filepath")
echo -e "${BLUE}Detected file type:${RESET} $FILE_TYPE"
IS_MEMORY=false
FILE_EXT="${filepath##*.}"

if echo "$FILE_EXT" | grep -qiE 'mem|raw|dmp|vmem|lime'; then
    IS_MEMORY=true
elif echo "$FILE_TYPE" | grep -qiE 'memory|crash dump|vmcore|event trace'; then
    IS_MEMORY=true
fi

#===========================================================================
#Detect Operating System using Volatility banners
#Validate memory dump compatibility with Volatility
#===========================================================================
CAN_ANALYZE=false

if [ "$IS_MEMORY" = true ]; then
    echo -e "${GREEN}Testing Volatility compatibility...${RESET}"

    if python3 "$VOL_PATH" -f "$filepath" windows.info > "$OUTDIR/vol_probe.txt" 2>&1; then
        CAN_ANALYZE=true
        OS_TYPE="windows"
    elif python3 "$VOL_PATH" -f "$filepath" linux.info > "$OUTDIR/vol_probe.txt" 2>&1; then
        CAN_ANALYZE=true
        OS_TYPE="linux"
    elif python3 "$VOL_PATH" -f "$filepath" mac.info > "$OUTDIR/vol_probe.txt" 2>&1; then
        CAN_ANALYZE=true
        OS_TYPE="mac"
    fi
fi
if [ "$CAN_ANALYZE" = true ]; then
    echo -e "${GREEN}Volatility confirmed this memory dump is analyzable.${RESET}"
else
    echo -e "${RED}Volatility could NOT analyze this memory dump.${RESET}"
fi
#===========================================================================
#   Safe Volatility plugin runner
#===========================================================================
run_vol_plugin() {
    local plugin="$1"
    local outfile="$2"

    if python3 "$VOL_PATH" -f "$filepath" "$plugin" > "$outfile" 2>&1; then
        echo -e "${GREEN}[+] $plugin completed${RESET}"
        echo "OK,$plugin,$outfile" >> "$VOL_LOG"
        return 0
    else
        echo -e "${DARKGREY}[-] $plugin not supported or failed${RESET}"
        echo "FAIL,$plugin,$outfile" >> "$VOL_LOG"
        return 1
    fi
}
#===========================================================================
#  Windows memory artifact extraction
#===========================================================================

if [ "$CAN_ANALYZE" = true ] && [ "$OS_TYPE" = "windows" ]; then
    echo -e "${GREEN}Extracting Windows memory artifacts...${RESET}"

    run_vol_plugin windows.pslist "$OUTDIR/vol_windows_pslist.txt"
    run_vol_plugin windows.netstat "$OUTDIR/vol_windows_netstat.txt"
    run_vol_plugin windows.cmdline "$OUTDIR/vol_windows_cmdline.txt"
    run_vol_plugin windows.registry.hivelist "$OUTDIR/vol_windows_hivelist.txt"
    run_vol_plugin windows.registry.userassist "$OUTDIR/vol_windows_userassist.txt"
    run_vol_plugin windows.registry.sam "$OUTDIR/vol_windows_sam.txt"
    run_vol_plugin windows.registry.system "$OUTDIR/vol_windows_system.txt"
fi
#===========================================================================
#  Linux memory artifact extraction
#===========================================================================

if [ "$CAN_ANALYZE" = true ] && [ "$OS_TYPE" = "linux" ]; then
    echo -e "${GREEN}Extracting Linux memory artifacts...${RESET}"

    run_vol_plugin linux.pslist "$OUTDIR/vol_linux_pslist.txt"
    run_vol_plugin linux.netstat "$OUTDIR/vol_linux_netstat.txt"
    run_vol_plugin linux.lsmod "$OUTDIR/vol_linux_modules.txt"
    run_vol_plugin linux.bash "$OUTDIR/vol_linux_bash.txt"
fi
#===========================================================================
#  macOS memory artifact extraction
#===========================================================================

if [ "$CAN_ANALYZE" = true ] && [ "$OS_TYPE" = "mac" ]; then
    echo -e "${GREEN}Extracting macOS memory artifacts...${RESET}"

    run_vol_plugin mac.pslist "$OUTDIR/vol_mac_pslist.txt"
    run_vol_plugin mac.netstat "$OUTDIR/vol_mac_netstat.txt"
fi
#===========================================================================
#  Build report + statistics
#===========================================================================
END_TIME=$(date +"%Y-%m-%d %H:%M:%S")
END_EPOCH=$(date +%s)
DURATION_SEC=$((END_EPOCH - START_EPOCH))

FILE_SIZE_BYTES=$(stat -c%s "$filepath" 2>/dev/null)
FILE_SHA256=$(sha256sum "$filepath" 2>/dev/null | awk '{print $1}')

TOTAL_EXTRACTED_FILES=$(find "$OUTDIR" -type f 2>/dev/null | wc -l)
CARVED_FILES_FOREMOST=$(find "$OUTDIR/foremost" -type f 2>/dev/null | wc -l)
CARVED_FILES_BINWALK=$(find "$OUTDIR/binwalk" -type f 2>/dev/null | wc -l)
BULK_FILES=$(find "$OUTDIR/bulk" -type f 2>/dev/null | wc -l)

PCAP_FOUND="no"
if [ -n "$PCAP" ]; then PCAP_FOUND="yes"; fi

CREDS_HITS=$(wc -l < "$OUTDIR/creds.txt" 2>/dev/null || echo 0)
URL_HITS=$(wc -l < "$OUTDIR/url.txt" 2>/dev/null || echo 0)
IP_HITS=$(wc -l < "$OUTDIR/ips.txt" 2>/dev/null || echo 0)

VOL_OK_COUNT=$(grep -c '^OK,' "$VOL_LOG" 2>/dev/null || echo 0)
VOL_FAIL_COUNT=$(grep -c '^FAIL,' "$VOL_LOG" 2>/dev/null || echo 0)

{
echo "================ FORENSICS REPORT ================"
echo "Start Time:   $START_TIME"
echo "End Time:     $END_TIME"
echo "Duration:     ${DURATION_SEC}s"
echo ""
echo "---------------- TARGET FILE ----------------"
echo "Path:         $filepath"
echo "Size (bytes): ${FILE_SIZE_BYTES:-unknown}"
echo "SHA256:       ${FILE_SHA256:-unknown}"
echo "file(1):      $FILE_TYPE"
echo ""
echo "---------------- DETECTION ------------------"
echo "Is memory-like:   $IS_MEMORY"
echo "Detected OS:      $OS_TYPE"
echo "Volatility OK:    $CAN_ANALYZE"
echo ""
echo "---------------- CARVING OUTPUT --------------"
echo "Total files under OUTDIR:     $TOTAL_EXTRACTED_FILES"
echo "Foremost files:               $CARVED_FILES_FOREMOST"
echo "Binwalk extracted files:      $CARVED_FILES_BINWALK"
echo "Bulk Extractor files:         $BULK_FILES"
echo "PCAP found:                   $PCAP_FOUND"
if [ -n "$PCAP" ]; then echo "PCAP path:                    $PCAP"; fi
echo ""
echo "---------------- STRINGS HITS ----------------"
echo "Cred keywords lines:          $CREDS_HITS"
echo "URL lines:                    $URL_HITS"
echo "IP lines:                     $IP_HITS"
echo ""
echo "---------------- VOLATILITY PLUGINS ----------"
echo "Succeeded: $VOL_OK_COUNT"
echo "Failed:    $VOL_FAIL_COUNT"
echo ""
if [ -s "$VOL_LOG" ]; then
    echo "Details (status,plugin,output_file):"
    cat "$VOL_LOG"
else
    echo "No volatility plugins were attempted."
fi
echo "=================================================="
} > "$REPORT"

echo -e "${GREEN}Report saved to:${RESET} $REPORT"
#===========================================================================
# packaging (zip + hash + full date )
#===========================================================================
TimeStamps=$(date +"%Y-%m-%d_%H-%M-%S")
ZipPath="/home/$REAL_USER/Desktop/forensics_results_${TimeStamps}.zip"
Hash="${ZipPath}.sha256"

echo -e "${GREEN}Creating ZIP archive...${RESET}"
zip -r "$ZipPath" "$OUTDIR" >/dev/null

echo -e "${GREEN}Calculating SHA256 hash...${RESET}"
sha256sum "$ZipPath" > "$Hash"

echo -e "${GREEN}Results packaged successfully:${RESET}"
echo " ZIP : $ZipPath"
echo " HASH: $Hash"




