# BoardLight screenshots index

| # | Filename | Captures | Used in |
|---:|---|---|---|
| 01 | `boardlight_01_ping.png` | `ping -c 1 10.129.231.37` | `1.1 Connectivity Test` |
| 02 | `boardlight_02_nmap_allports.png` | `nmap -p- --open ... -oG allPorts` | `1.2 Port Scanning` |
| 03 | `boardlight_03_extractports.png` | `extractPorts allPorts` | `1.2 Port Scanning` |
| 04 | `boardlight_04_nmap_targeted.png` | `nmap -sCV -p22,80 ...` + `cat targeted` | `1.3 Targeted Scan` |
| 05 | `boardlight_05_whatweb.png` | `whatweb http://10.129.231.37` | `2.1 HTTP Enumeration` |
| 06 | `boardlight_06_hosts_board_htb.png` | Add `board.htb` to `/etc/hosts` | `2.1 HTTP Enumeration` |
| 07 | `boardlight_07_ffuf_content.png` | `ffuf` content discovery on `/FUZZ` | `2.2 Content/VHost Discovery` |
| 08 | `boardlight_08_dolibarr_login.png` | Dolibarr `17.0.0` login at `crm.board.htb` | `2.2 Content/VHost Discovery` |
| 09 | `boardlight_09_dolibarr_admin_access_denied.png` | Authenticated Dolibarr UI (admin session) | `3.1 Dolibarr admin access` |
| 10 | `boardlight_10_cve_2023_30253_shell.png` | Exploit run + `nc` reverse shell as `www-data` | `3.2 Authenticated RCE` |
| 11 | `boardlight_11_wwwdata_enum_paths.png` | `www-data` enumeration in Dolibarr directories | `3.2 Authenticated RCE` |
| 12 | `boardlight_12_conf_php_db_creds.png` | `cat conf.php` showing DB creds | `3.3 Credential discovery` |
| 13 | `boardlight_13_ssh_larissa_user_flag.png` | SSH as `larissa` + `cat user.txt` | `3.4 SSH pivot` |
| 14 | `boardlight_14_sudo_l.png` | `sudo -l` (no sudo rights) | `4.1 Baseline checks` |
| 15 | `boardlight_15_suid_getcap.png` | `find / -perm -4000 ...` and `getcap -r /` | `4.1 Baseline checks` |
| 16 | `boardlight_16_enlightenment_version_suid.png` | `enlightenment --version` + SUID `enlightenment_sys` | `4.1 Baseline checks` |
| 17 | `boardlight_17_transfer_exploit.png` | `curl` + `scp` exploit transfer to target | `4.2 Root via CVE-2022-37706` |
| 18 | `boardlight_18_root_shell_root_flag.png` | Run exploit → root shell + `cat /root/root.txt` | `4.2 Root via CVE-2022-37706` |

