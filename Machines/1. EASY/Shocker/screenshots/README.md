# Shocker Screenshot Index

| sequence | filename | command/action captured | README section where embedded |
|---|---|---|---|
| 01 | `shocker_01_ping.png` | `ping -c 1 10.129.10.164` | `1.1 Connectivity Test` |
| 02 | `shocker_02_nmap_allports.png` | `nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn ...` | `1.2 Port Scanning` |
| 03 | `shocker_03_extractports.png` | `extractPorts allPorts` output | `1.2 Port Scanning` |
| 04 | `shocker_04_nmap_targeted.png` | `nmap -sCV -p80,2222 ...` and `cat targeted` | `1.3 Targeted Scan` |
| 05 | `shocker_05_whatweb.png` | `whatweb http://10.129.10.164` | `2.1 HTTP Surface Enumeration` |
| 06 | `shocker_06_curl_index.png` | `curl -i http://10.129.10.164` | `2.1 HTTP Surface Enumeration` |
| 07 | `shocker_07_ffuf_root.png` | root path fuzzing (`ffuf .../FUZZ ... common.txt`) | `2.1 HTTP Surface Enumeration` |
| 08 | `shocker_08_browser_homepage.png` | browser view of landing page (“Don’t Bug Me!”) | `2.1 HTTP Surface Enumeration` |
| 09 | `shocker_09_cgi_bin_403.png` | browser `403` on `/cgi-bin/` | `2.2 CGI Enumeration` |
| 10 | `shocker_10_ffuf_cgibin_user_sh.png` | CGI fuzzing discovering `user.sh` | `2.2 CGI Enumeration` |
| 11 | `shocker_11_nmap_shellshock_vuln.png` | `nmap --script http-shellshock ...` vuln confirmation | `3.1 Shellshock Validation and RCE` |
| 12 | `shocker_12_tshark_capture_setup.png` | `nmap` Shellshock check + `tshark -w Capture.cap -i tun0` | `3.1 Shellshock Validation and RCE` |
| 13 | `shocker_13_tshark_http_summary.png` | `tshark -r Capture.cap -Y "http"` summary | `3.1 Shellshock Validation and RCE` |
| 14 | `shocker_14_tshark_payload_hex.png` | HTTP payload extraction (hex) with tshark | `3.1 Shellshock Validation and RCE` |
| 15 | `shocker_15_tshark_payload_decoded.png` | decoded payload (`... \| xxd -ps -r`) | `3.1 Shellshock Validation and RCE` |
| 16 | `shocker_16_rce_id_whoami.png` | `curl` Shellshock probes (`whoami`, `id`) | `3.1 Shellshock Validation and RCE` |
| 17 | `shocker_17_reverse_shell_user_flag.png` | reverse shell callback + `cat /home/shelly/user.txt` | `3.2 Reverse Shell and User Proof` |
| 18 | `shocker_18_sudo_l.png` | `sudo -l` (NOPASSWD `perl`) | `4.1 Sudo Misconfiguration Discovery` |
| 19 | `shocker_19_sudo_perl_root_flag.png` | `sudo perl ...`, `whoami`, `cat /root/root.txt` | `4.2 Root Access and Proof` |
