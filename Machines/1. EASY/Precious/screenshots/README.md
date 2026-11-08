# Precious — Screenshot Index

| # | Filename | Command / action captured | Used in `README.md` section |
|---:|---|---|---|
| 01 | `htb-precious_01_ping.png` | `ping -c 1 10.129.228.98` | 1.1 Connectivity Test |
| 02 | `htb-precious_02_nmap_allports.png` | `nmap -p- ... -oG allPorts` | 1.2 Port Scanning |
| 03 | `htb-precious_03_extractports.png` | `extractPorts allPorts` | 1.2 Port Scanning |
| 04 | `htb-precious_04_nmap_targeted.png` | `nmap -sCV -p22,80 ...` + `cat targeted` | 1.3 Targeted Scan |
| 05 | `htb-precious_05_hosts_whatweb_curl.png` | `/etc/hosts` mapping + `whatweb` + `curl` | 2.1 HTTP Enumeration |
| 06 | `htb-precious_06_web_landing.png` | Browser view of “Convert Web Page to PDF” | 2.1 HTTP Enumeration |
| 07 | `htb-precious_07_curl_cannot_load.png` | POSTing URL returns “Cannot load remote URL!” | 2.1 HTTP Enumeration |
| 08 | `htb-precious_08_pdf_from_attacker_url.png` | POSTing attacker URL returns PDF + HTTP server GET | 2.1 HTTP Enumeration |
| 09 | `htb-precious_09_pdfkit_exiftool_pdftotext.png` | `exiftool` shows `pdfkit v0.8.6` + `pdftotext` | 2.1 HTTP Enumeration |
| 10 | `htb-precious_10_searchsploit_pdfkit_poc.png` | `searchsploit pdfkit` + PoC usage | 3.1 Foothold (PoC setup) |
| 11 | `htb-precious_11_poc_revshell_and_nc.png` | PoC run + `nc -lvnp 4444` + `whoami` | 3.1 Foothold (shell) |
| 12 | `htb-precious_12_ruby_enum_users_denied_userflag.png` | `ruby` enumeration + permission denied on `user.txt` | 4.1 Lateral movement |
| 13 | `htb-precious_13_bundle_config_creds.png` | `/home/ruby/.bundle/config` credentials | 4.1 Lateral movement |
| 14 | `htb-precious_14_ssh_henry_userflag.png` | SSH as `henry` + `cat user.txt` | 4.1 Lateral movement |
| 15 | `htb-precious_15_sudo_l_update_dependencies.png` | `sudo -l` + `/opt/update_dependencies.rb` | 4.2 Root via YAML.load |
| 16 | `htb-precious_16_yaml_id_root.png` | `dependencies.yml` gadget with `git_set: id` -> `uid=0(root)` | 4.2 Root via YAML.load |
| 17 | `htb-precious_17_root_flag.png` | `git_set: cat /root/root.txt` output | 4.2 Root via YAML.load |

