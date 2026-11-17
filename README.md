# IOC Enrichment Tool

A small python tool that checks IP addresses on AbuseIPDB and VirusTotal and saves the result in a CSV file.

## Why I made this

While learning SOC analyst work on TryHackMe, Hack The Box, and CyberDefenders, I used to check suspicious IPs one by one by pasting them into VirusTotal. This took a lot of time when there were many IPs. So, I made this tool to check them on AbuseIPDB and VirusTotal and save everything in a single CSV file.

Adding extra information to an IOC (Indicator of Compromise) like this is called IOC enrichment.

ye kaise ha ??

## What it does

1. Reads IPs from `ips.txt` (one IP in each line)
2. Skips private IPs like 10.x.x.x or 192.168.x.x because they are not on the internet
3. If the IP is wrong, it prints an error and goes to the next one
4. Checks the IP on AbuseIPDB and VirusTotal
5. Gives a verdict (Clean, Suspicious or Malicious)
6. Saves everything in `results.csv`

## What you need

- Python 3
- requests library
- Free API key from AbuseIPDB
- Free API key from VirusTotal

## Setup

1. Install requests
   ```
   pip install requests
   ```
2. Set your API keys in the terminal (PowerShell). Don't write the keys inside the code.
   ```
   $env:ABUSEIPDB_KEY="your_abuseipdb_key"
   $env:VT_KEY="your_virustotal_key"
   ```
   The keys work only in the same terminal window. If you open a new terminal, set them again.
3. Make a file `ips.txt` in the same folder and write one IP in each line
   ```
   8.8.8.8
   64.89.160.247
   10.1.1.1
   ```

## How to run

```
python ioc_check.py
```

Then open `results.csv`.

## Sample output

Terminal:

```
8.8.8.8 : done
64.89.160.247 : done
10.1.1.1 : Private IP, Skipped
abc.def.ghi.jkl : error 'abc.def.ghi.jkl' does not appear to be an IPv4 or IPv6 address
```

results.csv:

| ip | abuse_score | verdict | country | reports | vt_malicious | vt_suspicious |
|---|---|---|---|---|---|---|
| 8.8.8.8 | 0 | Clean | US | 192 | 1 | 0 |
| 64.89.160.247 | 100 | Malicious | DE | 92 | 3 | 4 |

## How the verdict is made

Verdict is made only from the AbuseIPDB abuse score.

- 75 and above = Malicious
- 25 to 74 = Suspicious
- below 25 = Clean

VirusTotal numbers are saved in the CSV separately. 8.8.8.8 (Google DNS) has 1 flag on VirusTotal but its abuse score is 0, so it is Clean. So one flag alone does not mean the IP is bad, check both.

## Limits

- VirusTotal free plan allows only 4 requests per minute, so the tool waits 15 seconds after each IP. 10 IPs will take around 2 to 3 minutes.
- Works only for IPs right now, not for domains or file hashes
- `results.csv` is overwritten every time you run it

## What I want to add next

- Use VirusTotal result in the verdict also
- Take IPs directly from my Windows log analyzer project
- Single IP mode (python ioc_check.py 8.8.8.8)

## Note

I made this for learning. Always check the result yourself before blocking any IP.
