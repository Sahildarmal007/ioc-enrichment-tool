# IOC check tool
# Takes IPs from ips.txt, checks them on AbuseIPDB and VirusTotal,
# and saves the result in results.csv

# How to run:
# 1. pip install requests
# 2. make free accounts on AbuseIPDB and VirusTotal and get your api keys
# 3. set the keys in terminal (powershell), don't write them in the code:
#       $env:ABUSEIPDB_KEY="your key"
#       $env:VT_KEY="your key"
# 4. make a file ips.txt in the same folder, one IP in each line
# 5. run: python ioc_check.py
# (keys work only in the same terminal window where you set them)

import os
import sys
import requests
import ipaddress
import time
import csv

# AbuseIPDB
API_KEY = os.getenv("ABUSEIPDB_KEY")   # key is taken from terminal, not from code
URL = "https://api.abuseipdb.com/api/v2/check"

def check_ip(ip):
    # asks AbuseIPDB about one IP
    headers = {"Key" : API_KEY, "Accept" : "application/json"}
    params = {"ipAddress" : ip, "maxAgeInDays" : 90}   # only last 90 days reports
    r = requests.get(URL, headers=headers, params=params, timeout=10)
    r.raise_for_status()   # gives error if key is wrong or limit is over
    return r.json()["data"]

# VirusTotal
VT_KEY = os.getenv("VT_KEY")
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

def check_vt(ip):
    # asks VirusTotal, returns how many vendors said malicious/suspicious etc
    headers = {"x-apikey" : VT_KEY}
    r = requests.get(VT_URL + ip, headers=headers, timeout=10)
    r.raise_for_status()
    return r.json()["data"]["attributes"]["last_analysis_stats"]

def enrich(ip):
    # this also checks if the IP is valid (wrong IP gives ValueError)
    ip_obj = ipaddress.ip_address(ip)

    # private IPs (10.x, 192.168.x) are not on internet, so no point checking
    if ip_obj.is_private:
        return None

    d = check_ip(ip)
    vt = check_vt(ip)
    score = d["abuseConfidenceScore"]

    # verdict is made only from AbuseIPDB score
    if score >= 75:
        verdict = "Malicious"
    elif score >= 25:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    # order should be same as the header in the csv below
    return [d["ipAddress"], score, verdict, d["countryCode"],
            d["totalReports"], vt["malicious"], vt["suspicious"]]

if __name__ == "__main__":

    # stop if keys are not set
    if not API_KEY or not VT_KEY:
        print("Set ABUSEIPDB_KEY and VT_KEY first")
        sys.exit(1)

    # read IPs from the file, skip empty lines
    with open("ips.txt") as f:
        ips = [line.strip() for line in f if line.strip()]

    # results.csv gets overwritten every time you run
    with open("results.csv", "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["ip", "abuse_score", "verdict", "country", "reports", "vt_malicious", "vt_suspicious"])
        for ip in ips:
            try:
                row = enrich(ip)
            except (ValueError, requests.RequestException) as e:
                # wrong IP or api problem, just print and move to next IP
                print(f"{ip} : error {e}")
                continue
            if row:
                writer.writerow(row)
                print(f"{ip} : done")
                time.sleep(15)   # VirusTotal free allows only 4 requests per minute
            else:
                print(f"{ip} : Private IP, Skipped")