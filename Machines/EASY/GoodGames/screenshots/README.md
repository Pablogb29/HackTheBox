# GoodGames screenshots index

Order matches appearance in `cases/HackTheBox/EASY/GoodGames/README.md`.

| # | Filename | Captured command / action | README section |
|---|----------|---------------------------|----------------|
| 1 | `goodgames_01_ping.png` | ICMP: `ping` to target | `## 1. Initial Enumeration` → `### 1.1 Connectivity Test` |
| 2 | `goodgames_02_nmap_allports.png` | Full TCP: `nmap -p-` | `### 1.2 Port Scanning` |
| 3 | `goodgames_03_extractports.png` | `extractPorts`/open port list helpers | `### 1.2 Port Scanning` |
| 4 | `goodgames_04_nmap_targeted.png` | `nmap -sCV` on discovered ports | `### 1.3 Targeted Scan` |
| 5 | `goodgames_05_whatweb.png` | `whatweb` against primary URL | `### 1.3 Targeted Scan` |
| 6 | `goodgames_06_ffuf_routes.png` | `ffuf` (routes like `/login`, `/profile`) | `## 2. Service Enumeration` → `### 2.1 Primary web surface enumeration` |
| 7 | `goodgames_07_burp_sqli_bypass.png` | Burp: SQLi on `POST /login` | `### 2.2 Authentication surface review` |
| 8 | `goodgames_08_burp_setcookie_session.png` | Burp response: session after bypass | `### 2.2 Authentication surface review` |
| 9 | `goodgames_08_sqli_login_success.png` | Browser: post-bypass “Login Successful” | `## 3. Foothold` → `### 3.1 SQL injection foothold …` |
| 10 | `goodgames_09_admin_profile.png` | Browser: `/profile` admin context | `### 3.2 Portal pivot …` |
| 11 | `goodgames_10_sqlmap_dbs.png` | `sqlmap` database enumeration | `### 3.3 Automated extraction with sqlmap` |
| 12 | `goodgames_11_sqlmap_tables_main.png` | `sqlmap` tables in `main` | `### 3.3 Automated extraction with sqlmap` |
| 13 | `goodgames_12_sqlmap_dump_main_user.png` | `sqlmap` dump of `main.user` | `### 3.3 Automated extraction with sqlmap` |
| 14 | `goodgames_13_crackstation_md5_crack.png` | MD5 cracking (CrackStation) | `### 3.4 Password cracking …` |
| 15 | `goodgames_14_internal_dashboard.png` | Browser: internal subdomain dashboard | `### 3.4 Password cracking …` |
| 16 | `goodgames_15_internal_settings_form.png` | Browser: `/settings` form | `### 3.4 Password cracking …` |
| 17 | `goodgames_16_ssti_reverse_shell.png` | SSTI payload + callback (`nc`) | `### 3.4 Password cracking …` |
| 18 | `goodgames_13_container_mount_portscan.png` | Container: mount / `172.19.0.1` port loop | `## 4. Privilege Escalation` → `### 4.1 Container context …` |
| 19 | `goodgames_17_container_user_flag.png` | Container: `user.txt` | `### 4.1 Container context …` |
| 20 | `goodgames_14_ssh_host_enum.png` | Host SSH: `whoami` / network context | `### 4.1 Container context …` |
| 21 | `goodgames_18_host_copy_bash.png` | Host: copy `bash` into writable area | `### 4.2 Writable host home …` |
| 22 | `goodgames_15_privesc_suid_bash_root.png` | Host: SUID `bash -p` / root proof | `### 4.2 Writable host home …` |

## Extra PNGs in this folder (not referenced in README)

Useful for notes or a longer edition; safe to delete or fold into the writeup later:

- `goodgames_04_nmap_targeted_1.png`, `goodgames_05_nmap_targeted_2.png` — alternate nmap capture passes
- `goodgames_06_web_home.png`, `goodgames_07_web_signin_modal.png` — landing / sign-in UI
- `goodgames_09_sqli_orderby_columns.png` — `ORDER BY` column discovery
- `goodgames_10_sqlmap_raw_request.png` — raw request file used with `sqlmap`
- `goodgames_11_sqlmap_detect_mysql.png` — DBMS detection output
- `goodgames_12_sqlmap_user_columns.png` — column enumeration for `user`

## Source mapping (`Pasted image 20260505*.png`)

During packaging, root-level `Pasted image 20260505*.png` files were copied/renamed into `goodgames_*.png` per `notes/ctf/htb-goodgames.md` chronology. Exact 1:1 filename mapping is recorded in that note if you need to re-trace an image.
