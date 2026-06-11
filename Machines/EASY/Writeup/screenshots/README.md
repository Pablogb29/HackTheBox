# Screenshots index — HTB Writeup

This folder contains the screenshots referenced by `../README.md`.

| # | Filename | Capture | Used in README |
|---:|---|---|---|
| 01 | `writeup_01_ping.png` | `ping -c 1 10.129.30.59` output | 1.1 Connectivity Test |
| 02 | `writeup_02_nmap_allports.png` | Full TCP scan (`nmap -p- ... -oG allPorts`) summary showing 22/80 | 1.2 Port Scanning |
| 03 | `writeup_03_extractports.png` | `extractPorts allPorts` output showing open ports | 1.2 Port Scanning |
| 04 | `writeup_04_nmap_targeted.png` | Targeted scan output (`nmap -sCV -p22,80 ...`) | 1.3 Targeted Scan |
| 05 | `writeup_05_http_landing_dos_warning.png` | Browser view of `/` showing DoS/40x ban warning | 2.1 HTTP Enumeration |
| 06 | `writeup_06_robots.png` | Browser/terminal view of `robots.txt` showing `/writeup/` | 2.1 HTTP Enumeration |
| 07 | `writeup_07_cmsms_home.png` | Browser view of `/writeup/` home (CMSMS content/menu) | 2.1 HTTP Enumeration |
| 08 | `writeup_08_cmsms_generator_meta.png` | `curl ...page=writeup` showing `Generator: CMS Made Simple` | 2.2 CMS Identification |
| 09 | `writeup_09_searchsploit_2019.png` | `searchsploit "CMS Made Simple" 2019` results | 3.1 SQLi candidate selection |
| 10 | `writeup_10_cve_2019_9053_output.png` | CVE-2019-9053 PoC output (salt/user/hash) | 3.1 SQLi |
| 11 | `writeup_11_hash_formatting_attempt1.png` | First (invalid) hash formatting attempt | 3.2 Offline cracking (notes) |
| 12 | `writeup_12_hash_formatting_attempt2.png` | Second (invalid) hash formatting attempt | 3.2 Offline cracking (notes) |
| 13 | `writeup_13_hash_formatting_attempt3.png` | Third (invalid) hash formatting attempt | 3.2 Offline cracking (notes) |
| 14 | `writeup_14_hashcat_cracked.png` | Hashcat cracked password line | 3.2 Offline cracking |
| 15 | `writeup_15_ssh_user_flag.png` | SSH as `jkr` + `cat user.txt` | 3.2 Offline cracking → SSH |
| 16 | `writeup_16_pspy_download_scp.png` | Download + `scp` `pspy32` to target | 4.2 pspy |
| 17 | `writeup_17_id_no_sudo_hostname.png` | `id`, `sudo -l` missing, `hostname` | 4.1 staff/PATH (context) |
| 18 | `writeup_18_staff_writable_localbin_path.png` | `/usr/local/*` perms + `echo $PATH` | 4.1 staff/PATH |
| 19 | `writeup_19_pspy_root_runparts.png` | `pspy` shows root `env -i ... PATH=... run-parts ...` | 4.2 pspy |
| 20 | `writeup_20_drop_runparts_wrapper.png` | Dropping `/usr/local/bin/run-parts` wrapper | 4.3 PATH hijack |
| 21 | `writeup_21_root_proof.png` | SUID bash + root shell + `root.txt` | 4.3 Root |

