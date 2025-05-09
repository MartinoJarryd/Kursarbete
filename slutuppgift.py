# Syfte: Skapa ett omfattande Python-program som övervakar nätverkstrafik i realtid (via en simulerad loggfil eller scapy) och vidtar åtgärder vid misstänkta attacker.

# Krav --------------------------------
# Läs en dynamisk loggfil (network_traffic.log) med formatet: tidpunkt, källa-IP, destination-IP, port, protokoll.
# Analysera trafiken i 5-minutersintervall; flagga IP:n med över 100 anslutningar, ovanliga portar (< 1024 utanför 22, 80, 443) 
# eller hög volym till enstaka destinationer.
# Skicka e-postvarningar med smtplib till en administratör vid misstänkt aktivitet.
# Generera en CSV-rapport (attack_report.csv) med detaljer om flaggade händelser, inklusive statistik (t.ex. genomsnittlig anslutningsfrekvens).
# Skapa och kör ett ufw-kommando via subprocess för att blockera misstänkta IP:n på Ubuntu-servern.

# Förväntat resultat: -----------------------
# Programmet körs kontinuerligt, genererar rapporter, skickar varningar och blockerar hot i realtid.

# Säkerhetsroll-exempel: --------------------
# Simulerar en IT-säkerhetsutvecklare som bygger ett intrångsdetekteringssystem (IDS) för att skydda mot nätverksattacker.

# ------------------------Import Libraries------------------------
import os                                # for file and directory operations
import logging                           # for logging events and errors
import time                              # for time-related functions
import csv                               # for CSV file operations     
import smtplib                           # for sending emails
import subprocess                        # for running shell commands, this script will run on Ubuntu
import shutil                            # for file operations
from datetime import datetime, timezone  # for handling timestamps and timezones
from typing import List, Dict            # for type hinting

#------------------------Variabels------------------------
LOG_PATH  = "/var/log/network_traffic.log"          # the directory where the log file is located
LOG_DIR   = os.path.expanduser("~/IDS_logs")        # This is the directory where the logs will be saved. stored in the home directory of the user running the script
CSV_PATH  = os.path.join(LOG_DIR, "attack_report.csv") # the path to the CSV file where the report will be saved
IDS_LOG   = os.path.join(LOG_DIR, "ids_actions.log") # the path to the log file where the IDS actions will be logged
# The log file is located in the home directory of the user running the script so as to avoid sudo permissions issues

WINDOW = 300                                        #  5 minutes in seconds
MAX_CONNECTIONS = 100                          # maximum number of connections allowed from a single IP in the time window
SAFE_PORTS = {22, 80, 443}                     # safe ports that are allowed even if they are below 1024

EMAIL_FROM = "Test@gmail.com"      
EMAIL_TO   = "admin@gmail.com"
EMAIL_PASSWORD = "password" 
SMTP_HOST  = "smtp.gmail.com"                   # SMTP server for Gmail so an email can be sent to the admin
SMTP_PORT  = 587

#------------------------Logging------------------------
def setup_logging() -> None:                                # Set up logging configuration 
     os.makedirs(LOG_DIR, exist_ok=True)                    # Create the log directory if it doesn't exist
     logging.basicConfig(                                   
        level=logging.INFO,                                    # Here we set the logging level to INFO, which means that all messages at this level and above will be logged.
        format="%(asctime)s [%(levelname)s] %(message)s",      # Format of the log messages ie. timestamp, log level, and message
        handlers=[logging.FileHandler(IDS_LOG), logging.StreamHandler()] # Log to both file and console
    )
#----------------------Help functions------------------------
def tail_f(path:str):                                         # Generator function to read a file line by line, simulating tail -f
    try:                                                       #try to open the file if it exists, if not it will raise an error
        f = open(path, "r")
    except FileNotFoundError:
        logging.error("Traffic log file not found: %s", path)
        raise

    f.seek(0, os.SEEK_END)                             # Move the file pointer to the end of the file
    while True:                                        # Read the next line from the file if it exists, if not wait for 0.5 seconds and try again
        line = f.readline()
        if line:
            yield line.rstrip("\n")
        else:
            time.sleep(0.5)

#------------------------------------------------------------------------
def parse_line(raw: str) -> dict:                         # Parse a line from the log file and return a dictionary with the parsed values
    try:
        ts_s, src, dst, port_s, proto = [x.strip() for x in raw.split(",")] # Split the line by comma and strip whitespace as a formof validation
        ts = datetime.fromisoformat(ts_s)                                   # Convert the timestamp string to a datetime object
        return {                                                            # return a dictionary with souurce IP, destination IP, port, and protocol
            "ts": ts,
            "src": src,
            "dst": dst,
            "port": int(port_s),
            "proto": proto.upper(),
        }
    except ValueError:                                              # If the line is malformed, log a warning and return None                                               
        logging.warning("Malformed line skipped: %s", raw.strip())
        return None

# ------------------ helper: write one CSV row ----------------------

def write_report_row(ip: str, count: int, reason: str) -> None:
    os.makedirs(LOG_DIR, exist_ok=True)
    new_file = not os.path.exists(CSV_PATH)
    with open(CSV_PATH, "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        if new_file:
            writer.writerow(["timestamp", "ip", "connections", "reason"])
        writer.writerow([datetime.now(timezone.utc).isoformat(), ip, count, reason])
#------------------------------------------------------------------------
def analyse_window(events: List[Dict]) -> None:
    logging.info("Analysing %d events in last %d‑second window",
                 len(events), WINDOW)
    if not events:                       # nothing to do 
        return

    # --- build per‑IP statistics ----------------------------------
    stats: Dict[str, Dict] = {}
    for e in events:
        ip = e["src"]
        s  = stats.setdefault(ip, {"count": 0, "ports": set(), "dests": set()})
        s["count"] += 1
        s["ports"].add(e["port"])
        s["dests"].add(e["dst"])
    
    evaluate_rules_and_react(stats)
#---------------------------------------------------------------------

def block_ip(ip: str) -> None:
    if shutil.which("ufw") is None:
        logging.warning("UFW not installed; cannot block %s", ip)
        return
    cmd = ["sudo", "ufw", "insert", "1", "deny", "from", ip, "comment", "IDS"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        logging.info("Blocked IP %s with UFW", ip)
    else:
        logging.error("UFW failed (%s): %s", ip, result.stderr.strip())

# --- evaluate rules & react -----------------------------------
def evaluate_rules_and_react(stats: Dict[str, Dict]) -> None:
    for ip, s in stats.items():
        reasons: List[str] = []

        # Rule A – too many connections
        if s["count"] > MAX_CONNECTIONS:
            reasons.append(f">{MAX_CONNECTIONS} connections ({s['count']})")

        # Rule B – unusual low port
        bad_ports = [p for p in s["ports"] if p < 1024 and p not in SAFE_PORTS]
        if bad_ports:
            reasons.append(f"unusual port(s) {', '.join(map(str, bad_ports))}")

        # Rule C – single‑destination flood
        if len(s["dests"]) == 1 and s["count"] > 50:
            reasons.append(f"single‑dest flood ({s['count']})")

        if reasons:                       
            reason_txt = "; ".join(reasons)
            logging.warning("ALERT %s – %s", ip, reason_txt)
            write_report_row(ip, s["count"], reason_txt)
            block_ip(ip)

#---------------------------send_email------------------------
def send_email(subject: str, body: str) -> None:

    try:
       with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
         server.starttls()
         server.login(EMAIL_FROM, EMAIL_PASSWORD)
         message = f"Subject: {subject}\n\n{body}"
         server.sendmail(EMAIL_FROM, EMAIL_TO, message)
         logging.info("Email sent to %s", EMAIL_TO)
    except smtplib.SMTPException as e:  
        logging.error("Failed to send email: %s", e)
        print("Kunbde inte skicka epost!")  


#--------------------------------------------------------------

# ----------------------Main functions------------------------
def main() -> None:                                    ## Main function to run the IDS 
    setup_logging()                                    
    logging.info("Starting IDS (window %d s)…", WINDOW)

    buffer: List[Dict] = []                            # buffer to hold events for the current time window
    win_start = time.time()                            # start time of the current window
    tail = tail_f(LOG_PATH)                            # open the log file and start reading it

    while True:
        
        try:
            raw = next(tail)      
            evt = parse_line(raw)
            if evt:
                buffer.append(evt)
        except StopIteration:
            pass                  
        except Exception as e:
            logging.error("Unexpected error reading log: %s", e)

        
        if time.time() - win_start >= WINDOW:
            analyse_window(buffer)
            buffer.clear()
            win_start = time.time()

        time.sleep(0.5)           

#------------------------Main------------------------
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Monitoring stopped by user.")
        