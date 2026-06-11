# Screenshots — HTB Sau

Evidence images for `../README.md`. Filenames use slug **`sau`**.

| # | Filename | Command / action captured | README section |
|---|----------|---------------------------|----------------|
| 01 | `sau_01_ping.png` | `ping -c 1 10.129.229.26` | §1.1 Connectivity Test |
| 02 | `sau_02_nmap_allports.png` | `nmap -p- --open -sS --min-rate 5000 …` | §1.2 Port Scanning |
| 03 | `sau_03_extractports.png` | `extractPorts allPorts` | §1.2 Port Scanning |
| 04 | `sau_04_nmap_targeted_1.png` | `nmap -sCV -p22,55555 …` (scan output) | §1.3 Targeted Scan |
| 05 | `sau_05_nmap_targeted_2.png` | `cat targeted` (full nmap log) | §1.3 Targeted Scan |
| 06 | `sau_06_whatweb.png` | `whatweb http://10.129.229.26:55555/` | §2.1 HTTP fingerprint |
| 07 | `sau_07_request_baskets_web_ui.png` | Browser: Request Baskets “Created” modal / UI | §2.1 HTTP fingerprint |
| 08 | `sau_08_ssrf_attacker_nc.png` | `CVE-2023-27163.sh` → tun0 + `nc -lvnp 8000` + `curl` basket | §2.2 SSRF proof |
| 09 | `sau_09_ssrf_localhost_basket_create.png` | `./CVE-2023-27163.sh '…55555/' 'http://127.0.0.1/'` | §2.3 Localhost pivot |
| 10 | `sau_10_maltrail_via_basket_curl.png` | `curl -i 'http://…:55555/sevwog'` (Maltrail headers) | §2.3 Localhost pivot |
| 11 | `sau_11_maltrail_browser_dashboard.png` | Browser: basket URL rendering Maltrail UI | §2.3 Localhost pivot |
| 12 | `sau_12_maltrail_exploit_shell_user_flag.png` | `python3 exploit.py …` + `nc` shell + `user.txt` | §3.1 Foothold |
| 13 | `sau_13_sudo_systemctl_root_flag.png` | `sudo -l`, `systemctl --version`, pager escape, `root.txt` | §4.1 Privilege escalation |

## Source mapping (Obsidian paste filenames)

Renamed from repo-root **`Pasted image …`** captures:

| Renamed file | Original paste filename |
|--------------|-------------------------|
| `sau_01_ping.png` | `Pasted image 20260503103005.png` |
| `sau_02_nmap_allports.png` | `Pasted image 20260503103021.png` |
| `sau_03_extractports.png` | `Pasted image 20260503103030.png` |
| `sau_04_nmap_targeted_1.png` | `Pasted image 20260503103242.png` |
| `sau_05_nmap_targeted_2.png` | `Pasted image 20260503103549.png` |
| `sau_06_whatweb.png` | `Pasted image 20260503103619.png` |
| `sau_07_request_baskets_web_ui.png` | `Pasted image 20260503102942.png` |
| `sau_08_ssrf_attacker_nc.png` | `Pasted image 20260503105639.png` |
| `sau_09_ssrf_localhost_basket_create.png` | `Pasted image 20260503110825.png` |
| `sau_10_maltrail_via_basket_curl.png` | `Pasted image 20260503110845.png` |
| `sau_11_maltrail_browser_dashboard.png` | `Pasted image 20260503110911.png` |
| `sau_12_maltrail_exploit_shell_user_flag.png` | `Pasted image 20260503111402.png` |
| `sau_13_sudo_systemctl_root_flag.png` | `Pasted image 20260503112341.png` |
