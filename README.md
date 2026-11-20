# IOC Enrichment Tool

A small python tool that checks IP addresses and file hashes on AbuseIPDB and VirusTotal and saves the result in CSV files.

## Why I made this

When there are many suspicious IPs, we have to paste them one by one in VirusTotal or AbuseIPDB and note the result by hand. This is slow and boring, and I think many people who are learning SOC work have faced this. So, I made this tool to check all of them together and save everything in a single CSV file.

Adding extra information to an IOC (Indicator of Compromise) like this is called IOC enrichment.

Later I also added a file hash check. The hashes come from my File Integrity Monitor (`fim.py`), which saves the hashes of my files in `fim_iocs.txt`.

## What it does

**IP check**

1. Asks for one IP. If you type one, it checks it and shows the result in the terminal only
2. If you press Enter, it reads many IPs from `ips.txt` (one IP in each line)
3. Skips private IPs like 10.x.x.x or 192.168.x.x because they are not on the internet
4. If the IP is wrong, it prints an error and goes to the next one
5. Checks the IP on AbuseIPDB and VirusTotal
6. Gives a verdict (Clean, Suspicious or Malicious)
7. Saves everything in `results.csv` (file mode only)

**Hash check**

1. Reads the SHA-256 hashes from `fim_iocs.txt` (made by `fim.py`)
2. Skips repeated hashes
3. Checks each hash on VirusTotal
4. Gives a verdict (Clean, Suspicious, Malicious or Not found)
5. Saves everything in `hash_results.csv`

## What you need

- Python 3
- requests library
- Free API key from AbuseIPDB
- Free API key from VirusTotal
- (Optional) `fim.py`, to make `fim_iocs.txt` for the hash check

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
3. For many IPs, make a file `ips.txt` in the same folder and write one IP in each line (not needed for single IP mode)
   ```
   8.8.8.8
   64.89.160.247
   10.1.1.1
   ```
4. For the hash check, run `fim.py` first. It makes `fim_iocs.txt` in the same folder.

`ips.txt` and `fim_iocs.txt` are both optional. In file mode, the part whose file is missing is skipped.

## How to run

```
python ioc_check.py
```

It will ask: `Enter one IP (or press Enter to use ips.txt and fim_iocs.txt)`

- Type one IP for a quick check. The result is shown in the terminal and no file is made.
- Press Enter to check all IPs in `ips.txt` and all hashes in `fim_iocs.txt`. Then open `results.csv` and `hash_results.csv`.

## Sample output

Single IP mode (terminal):

```
IP            : 8.8.8.8
Verdict       : Clean
Abuse score   : 0
Country       : US
Reports       : 192
VT malicious  : 1
VT suspicious : 0
```

File mode (terminal):

```
8.8.8.8 : done
64.89.160.247 : done
10.1.1.1 : Private IP, Skipped
abc.def.ghi.jkl : error 'abc.def.ghi.jkl' does not appear to be an IPv4 or IPv6 address
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 : Clean
df60d76cb0da7452a009c7cf3063b1b1dd80983dd8788f89a27f595db6cbffac : Not found
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f : Malicious
```

results.csv:

| ip | abuse_score | verdict | country | reports | vt_malicious | vt_suspicious |
|---|---|---|---|---|---|---|
| 8.8.8.8 | 0 | Clean | US | 192 | 1 | 0 |
| 64.89.160.247 | 100 | Malicious | DE | 92 | 3 | 4 |

hash_results.csv has these columns: `sha256`, `verdict`, `vt_malicious`, `vt_suspicious`

## How the IP verdict is made

Verdict is made only from the AbuseIPDB abuse score.

- 75 and above = Malicious
- 25 to 74 = Suspicious
- below 25 = Clean

VirusTotal numbers are saved in the CSV separately. 8.8.8.8 (Google DNS) has 1 flag on VirusTotal but its abuse score is 0, so it is Clean. So one flag alone does not mean the IP is bad, check both.

## How the hash verdict is made

Verdict is made from how many VirusTotal vendors said the file is malicious.

- 5 or more = Malicious
- 1 to 4 = Suspicious
- 0 = Clean
- Not found = VirusTotal has never seen this file

"Not found" does not mean the file is safe. It only means VirusTotal does not know it. For example, a file I just made myself will show "Not found".

I tested the hash check with the EICAR test file hash (a harmless file made for antivirus testing). It came as Malicious.

## Limits

- VirusTotal free plan allows only 4 requests per minute, so in file mode the tool waits 15 seconds after each IP and each hash. 10 IPs will take around 2 to 3 minutes.
- Works only for IPs and file hashes right now, not for domains
- Only SHA-256 hashes are checked. MD5 and SHA-1 are skipped because they are of the same file and would waste VirusTotal requests.
- `results.csv` and `hash_results.csv` are overwritten every time you run it

## What I want to add next

- Use VirusTotal result in the verdict also
- Take IPs directly from my Windows log analyzer project

## Note

I made this for learning. Always check the result yourself before blocking any IP or deleting any file.
