#!/bin/bash

# Log_övervakning.sh - 

# Skapat av: Jarryd Martino, April 2025

# Syfte: Bash-skript som övervakar och analyserar säkerhetsloggar på en Ubuntu Server (/var/log/auth.log och /var/log/syslog) för att identifiera, 
# rapportera och reagera på misstänkt aktivitet.

# Krav: 

# Sök efter mönster som "Failed password", "Invalid user", "Accepted password" och "session opened" över de senaste 24 timmarna.

# Räkna förekomster per IP och användarnamn; flagga IP:n med över 20 misslyckade försök eller icke-existerande användare som "hög risk".

# Generera en rapport (security_report_$(date +%Y%m%d).txt) med tidpunkter, IP-adresser, användarnamn, händelsetyper och risknivåer.

# Skicka rapporten via e-post till en administratör med mail-kommandot (förutsätter att mailutils är installerat på Ubuntu).

# Blockera "hög risk"-IP:n med ufw (Ubuntu Firewall) och logga åtgärden i /var/log/security_actions.log.

# Komprimera och arkivera analyserade loggar till /backup/logs/ med tar, radera original efter arkivering om äldre än 7 dagar.

# Förväntat resultat: En daglig rapport genereras, misstänkta IP:n blockeras automatiskt via ufw, administratören notifieras, och loggar arkiveras effektivt.

# Säkerhetsroll-exempel: Simulerar proaktiv loggövervakning och respons på Ubuntu-servrar för att stoppa brute-force-attacker, en kärnuppgift för IT-säkerhetsutvecklare.

#---------------------------------------------------------------------------------------------------------------------------------------------------------------------------



# Error handling that exits on error 
set -euo pipefail

# Trap to clean up on interruption
trap 'echo "Script interrupted! Cleaning up..."; rm -f "$HIGH_RISK_IPS" "$TEMP_LOG"; exit 1' INT TERM EXIT


# ------------------------Varriabler-----------------------------------
LOG_FILES=(/var/log/auth.log /var/log/syslog)       # Sökväg till loggfilen som ska analyseras
BACKUP_DIR="/backup/logs"                           # Backup directory for archived logs
HIGH_RISK_IPS="/tmp/high_risk_ips_$$.txt"           # Temporär fil för att lagra hög risk IP-adresser
TEMP_LOG="/tmp/log_analysis_$$.tmp"                 # Temporär fil för att lagra analysresultat
REPORT_FILE="security_report_$(date +%Y%m%d).txt"   # Fil där analysreporten sparas och namnges med datum
SECURITY_ACTION_LOG="/var/log/security_actions.log" # Fil där blockering av IP:er loggas

ADMIN_EMAIL="test123@gmail.com"                     # E-postadress för administratör att få säkerhetsrapporter
MAIL_SUBJECT="Säkerhetsrapport $(date +%Y-%m-%d)"   # Ämnet för e-postmeddelandet

# Nyckelord att söka efter i loggarna
KEYWORDS='Failed password|Invalid user|Accepted password|session opened' 

TODAY=$(date '+%Y-%m-%d')                           # Dagens datum för loggning av sista 24 timmar
YDAY=$(date -d 'yesterday' '+%Y-%m-%d')             # Gårdagens datum för loggning av sista 24 timmar

MAX_ATTEMPTS=20                                     # Max antal misslyckade inloggningsförsök för att flagga en IP som "hög risk"
MAX_DAYS=7                                          # Max antal dagar för att arkivera loggar



# -----------------------Funktioner--------------------------

log_message() {                  # Function to log messages
    local level="$1"             # Log level (INFO, WARNING, ERROR)
    local message="$2"           # Message to log to the security action log
    printf "%s [%s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$message" >> "$SECURITY_ACTION_LOG" # Log message format for security action log and write to file
}

#----------------Function to analyze logs---------------------
analyze_logs() {
    log_message "INFO" "Starting log analysis..."

    
    for LOG_FILE in "${LOG_FILES[@]}"; do                         # Validate log file existence if not found exit script
        if [[ ! -f "$LOG_FILE" ]]; then                           # This is to check if the log file exists if it is not found exit the script and print error message
            log_message "ERROR" "Log file $LOG_FILE not found."   # -f checks if the file exists in the array that was vreated for the log files
            echo "Error: Log file $LOG_FILE not found!" >&2       # >&2 redirects the error message to stderr. stderr is a standard error stream that is used to output error messages
            exit 1
        fi
    done

  
# The code below is a grep command that searches for specific keywords in the log files from the array created above
    # 1) Collect logs from the last 24 hours
    # 2) Filter logs for relevant keywords
    # 3) Count fails per IP; flag > MAX_ATTEMPTS as HIGH-risk
    # templog is a temporary file to store the filtered logs
 grep -hE "^($TODAY|$YDAY)T" "${LOG_FILES[@]}" \
      | grep -Ei "$KEYWORDS" \
      > "$TEMP_LOG"

    local total_lines
    total_lines=$(wc -l < "$TEMP_LOG")
    log_message "INFO" "Collected $total_lines relevant log lines → $TEMP_LOG"

    : > "$HIGH_RISK_IPS"                     

    awk '{ print $(NF-3) }' "$TEMP_LOG" \
      | sort | uniq -c | sort -nr \
      | while read -r count ip; do
          if (( count > MAX_ATTEMPTS )); then
              echo "$ip" >> "$HIGH_RISK_IPS"
              log_message "WARNING" "Flagged HIGH‑risk $ip ($count failures)"
          fi

         done
}

#----------------------Function to generate report--------------------
generate_report() {
   log_message "INFO" "Generating report $REPORT_FILE"               # Log message for report generation

    {
        echo "Daily Security Report – $(date '+%Y-%m-%d %H:%M:%S')"  # Header for the report with date and time
        echo "-----------------------------------------------------" # Separator line for clarity
        printf "%-18s %7s   %s\n" "IP Address" "Fails" "Risk"        # Column headers created for clear visibility
        printf "%-18s %7s   %s\n" "----------" "-----" "----"        # corresponding column headersshowing expected output

        
        awk '{ print $(NF-3) }' "$TEMP_LOG"\
          | sort | uniq -c | sort -nr \
          | while read -r count ip; do                               # Loop through each IP and its count determine risk level based on the number of failures
                risk="OK"
                if grep -qx "$ip" "$HIGH_RISK_IPS"; then
                    risk="HIGH"
                fi
                printf "%-18s %7d   %s\n" "$ip" "$count" "$risk"     # print the IP address, count, and risk level to the report
            done
    } > "$REPORT_FILE"

    log_message "INFO" "Report written to $REPORT_FILE"
}

#--------------------Function to send email--------------------
# This is just fortest purposes and will not be used in the final script
send_email() {
    log_message "INFO" "Sending report to $ADMIN_EMAIL"                # Log message for email sending

    # Check if mailutils is installed if not found continue without sending email
    
    if ! command -v mail &> /dev/null; then
        log_message "ERROR" "mailutils is not installed. Cannot send email."
        echo "Error: mailutils is not installed. Cannot send email!" >&2
        return
    fi
    
    log_message "INFO" "Sending email to $ADMIN_EMAIL"                  # Log message for email sending
    
    if mail -s "$MAIL_SUBJECT" "$ADMIN_EMAIL" < "$REPORT_FILE"; then    # Send email with the report using variables created above piping the report file to the email body
        log_message "INFO" "Email sent successfully to $ADMIN_EMAIL"    # Log message for successful email sending
        echo "Email sent successfully to $ADMIN_EMAIL"                  # Print message to stdout
    else
        log_message "ERROR" "Failed to send email to $ADMIN_EMAIL"      # Log message for failed email sending
        echo "Error: Failed to send email to $ADMIN_EMAIL!" >&2         # Print error message to stderr
    fi
}

#-------------------Function to block IPs---------------------
block_ips() {

    log_message "INFO" "Blocking high-risk IPs..."                     # Log message for blocking IPs

    if ! ufw status | grep -q "Status: active"; then                    # grep and pipe is used to check if ufw is active
        log_message "ERROR" "UFW is not active. Cannot block IPs."      # Log message for UFW not active 
        echo "Error: UFW is not active. Cannot block IPs!" >&2          # Print error message to stderr
        return
    fi

    if [[ ! -s "$HIGH_RISK_IPS" ]]; then                                # Check if the high-risk IPs file is empty if it isthe log message is printed
        log_message "INFO" "No high-risk IPs to block."                 # Log message for no high-risk IPs
        echo "No high-risk IPs to block."                               # Print message to stderr
        return
    fi

    log_message "INFO" "Blocking IPs via UFW"                           # Log message for blocking IPs via UFW        
    
    local valid_ip_found=false                                          # Flag to check if valid IPs are found
                
    grep -v '^\s*$' "$HIGH_RISK_IPS" | while read -r ip; do             # Loop through each IP in the high-risk IPs file and check if it is valid

        if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then         # Validate IP address format by meaning it should be in the format of 0-255.0-255.0-255.0-255 with out any other characters
            log_message "WARNING" "Invalid IP address format: $ip. Skipping."  # Log message for invalid IP address format
            echo "Invalid IP address format: $ip. Skipping."           
            continue
        fi

        local valid_ip_found=true

       if ! ufw status | grep -qE "DENY.*\\b$ip\\b"; then                        # here we are checiking the ufw status to see if the IP is already blocked or not 
            ufw insert 1 deny from "$ip" comment " blocked do to high risk"     # Block the IP using UFW 
            log_message "WARNING" "Blocked IP $ip with UFW"
            echo " Blocked IP $ip with UFW"  
        else
            log_message "INFO" "IP $ip already blocked."                       # Log message for already blocked IP
            echo "IP $ip already blocked."
        fi
    done

    if [[ "$valid_ip_found" == false ]]; then                                  #if no valid ip is found the log message is printed
        log_message "WARNING" "No valid IP addresses found to block."
        echo "No valid IP addresses found to block."
    fi

}
#-------------------Function to archive logs-------------------
archive_logs() {

    log_message "INFO" "Archiving logs older than $MAX_DAYS days..."   # Log message for archiving logs
    if [[ ! -d "$BACKUP_DIR" ]]; then                                  # check if the backup directory exsists if not create it
        mkdir -p "$BACKUP_DIR"                                         # Create backup directory if it doesn't exist
        log_message "INFO" "Created backup directory $BACKUP_DIR" 
    fi

    local archive_name
    archive_name="$BACKUP_DIR/logs_$(date +%Y%m%d).tar.gz"             # Archive name with date
    log_message "INFO" "Archiving logs to $archive_name"               # Log message for archiving logs

    tar -czf "$archive_name" "${LOG_FILES[@]}"                         # tar command to create a compressed archive of the log files
    log_message "INFO" "Logs archived to $archive_name"                # Log message for successful archiving
    echo "Logs archived to $archive_name"                              # Print message to stdout

    
    find /var/log -maxdepth 1 \                                         # Find and delete old logs older than MAX_DAYS
     \( -name 'auth.log*' -o -name 'syslog*' \) \
     -type f -mtime +"$MAX_DAYS" -print -delete |
  while read -r oldfile; do
      log_message "INFO" "Removed old original $oldfile"
  done

    log_message "INFO" "Removed old original logs older than $MAX_DAYS days" # Log message for removing old logs
    echo "Removed old original logs older than $MAX_DAYS days"          # Print message to stdout


}


#-------------------Main script execution----------------------
analyze_logs
generate_report
send_email
block_ips
archive_logs

# Cleanup temporary files 
rm -f "$HIGH_RISK_IPS" "$TEMP_LOG"
log_message "INFO" "Temporary files cleaned up."