# Screenshots index — Devvortex (`devvortex`)

| # | Filename | Command / action captured | README section |
|---|----------|----------------------------|----------------|
| 01 | `devvortex_01_ping.png` | `ping -c 1 10.129.28.37` | §1.1 Connectivity Test |
| 02 | `devvortex_02_nmap_allports.png` | `nmap -p- --open ... 10.129.28.37 -oG allPorts` | §1.2 Port Scanning |
| 03 | `devvortex_03_extractports.png` | `extractPorts allPorts` | §1.2 Port Scanning |
| 04 | `devvortex_04_nmap_targeted_1.png` | `nmap -sCV -p22,80 ...` (live/output portion) | §1.3 Targeted Scan |
| 05 | `devvortex_05_nmap_targeted_2.png` | `cat targeted` (same scan transcript; duplicate crop alternate) | §1.3 Targeted Scan |
| 06 | `devvortex_06_hosts_whatweb_apex.png` | `/etc/hosts` mapping + `whatweb http://devvortex.htb/` | §2.1 Host mapping and apex fingerprint |
| 07 | `devvortex_07_robots_txt_dev_subdomain.png` | Browser/`curl`: `http://dev.devvortex.htb/robots.txt` | §2.2 Joomla discovery |
| 08 | `devvortex_08_joomla_administrator_login.png` | Browser: Joomla admin login (`/administrator/`) | §2.2 Joomla discovery |
| 09 | `devvortex_09_joomscan_clone_run.png` | `git clone joomscan` + `./joomscan.pl -u ...` start | §2.3 JoomScan |
| 10 | `devvortex_10_joomscan_results.png` | JoomScan results (**Joomla 4.2.6**) | §2.3 JoomScan |
| 11 | `devvortex_11_cve_2023_23752_exploit.png` | `CVE-2023-23752.py -u http://dev.devvortex.htb` | §3.1 CVE-2023-23752 |
| 12 | `devvortex_12_joomla_admin_dashboard.png` | Authenticated Joomla **4.2.6** dashboard | §3.2 Administrator access |
| 13 | `devvortex_13_cassiopeia_error_php_editor.png` | Template editor: `error.php` malicious PHP | §3.3 Template / PHP execution |
| 14 | `devvortex_14_reverse_shell_nc_www_data.png` | `nc -lvnp 443` catch + `whoami` (`www-data`) | §3.3 Reverse shell proof |
| 15 | `devvortex_15_www_data_home_enum.png` | `www-data` enumerates `/home/logan`, `user.txt` denied | §3.4 Execution context |
| 16 | `devvortex_16_mysql_joomla_tables.png` | `mysql -u lewis -p` → `SHOW DATABASES` / `SHOW TABLES` | §4.1 MySQL enumeration |
| 17 | `devvortex_17_mysql_sd4fg_users_hashes.png` | `SELECT username,email,password FROM sd4fg_users` | §4.1 Hash harvesting |
| 18 | `devvortex_18_hashcat_bcrypt_logan.png` | `hashcat -m 3200 --user hashes rockyou.txt` | §4.2 hashcat |
| 19 | `devvortex_19_user_flag_logan.png` | `su logan` → `cat /home/logan/user.txt` | §4.3 User flag |
| 20 | `devvortex_20_sudo_l_apport_cli.png` | `sudo -l` (`apport-cli` rule) | §4.4 sudo enumeration |
| 21 | `devvortex_21_apport_less_bang_bash.png` | `less` prompt with `!/bin/bash` during **`sudo apport-cli`** flow | §4.5 Root privesc |
| 22 | `devvortex_22_apport_cli_menu_view_report.png` | Interactive **`sudo apport-cli -f`** menus ending at **`v`** | §4.5 Root privesc |
| 23 | `devvortex_23_root_shell_root_txt.png` | `root` shell → `cat /root/root.txt` | §4.5 Root privesc |

## Source rename map (workspace paste → canonical)

| Canonical filename | Original workspace file |
|-------------------|-------------------------|
| `devvortex_01_ping.png` | `Pasted image 20260503120008.png` |
| `devvortex_02_nmap_allports.png` | `Pasted image 20260503120027.png` |
| `devvortex_03_extractports.png` | `Pasted image 20260503120036.png` |
| `devvortex_04_nmap_targeted_1.png` | `Pasted image 20260503120048.png` |
| `devvortex_05_nmap_targeted_2.png` | `Pasted image 20260503120048.png` *(duplicate copy)* |
| `devvortex_06_hosts_whatweb_apex.png` | `Pasted image 20260503120102.png` |
| `devvortex_07_robots_txt_dev_subdomain.png` | `Pasted image 20260503121114.png` |
| `devvortex_08_joomla_administrator_login.png` | `Pasted image 20260503121103.png` |
| `devvortex_09_joomscan_clone_run.png` | `Pasted image 20260503121534.png` |
| `devvortex_10_joomscan_results.png` | `Pasted image 20260503122252.png` |
| `devvortex_11_cve_2023_23752_exploit.png` | `Pasted image 20260503122408.png` |
| `devvortex_12_joomla_admin_dashboard.png` | `Pasted image 20260503122426.png` |
| `devvortex_13_cassiopeia_error_php_editor.png` | `Pasted image 20260503125742.png` |
| `devvortex_14_reverse_shell_nc_www_data.png` | `Pasted image 20260503130011.png` |
| `devvortex_15_www_data_home_enum.png` | `Pasted image 20260503130252.png` |
| `devvortex_16_mysql_joomla_tables.png` | `Pasted image 20260503131407.png` |
| `devvortex_17_mysql_sd4fg_users_hashes.png` | `Pasted image 20260503131430.png` |
| `devvortex_18_hashcat_bcrypt_logan.png` | `Pasted image 20260503131442.png` |
| `devvortex_19_user_flag_logan.png` | `Pasted image 20260503131454.png` |
| `devvortex_20_sudo_l_apport_cli.png` | `Pasted image 20260503131508.png` |
| `devvortex_21_apport_less_bang_bash.png` | `Pasted image 20260503133639.png` |
| `devvortex_22_apport_cli_menu_view_report.png` | `Pasted image 20260503133843.png` |
| `devvortex_23_root_shell_root_txt.png` | `Pasted image 20260503133820.png` |

**Unused duplicate (not copied):** `Pasted image 20260503133824.png` — near-duplicate of `devvortex_23_*`; keep as spare if you want an alternate crop.
