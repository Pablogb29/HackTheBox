# Sense — screenshot index

Screenshots are embedded from this folder using paths like `screenshots/Sense_01_ping.png` in `../README.md`.

**Status:** **16** canonical files (`Sense_01` … `Sense_16`); numbering follows solve chronology.

| Seq | Filename | Command / action captured | README section |
|-----|----------|---------------------------|----------------|
| 01 | `Sense_01_ping.png` | `ping -c 1 10.129.10.174` | § 1.1 Connectivity Test |
| 02 | `Sense_02_nmap_allports.png` | `nmap -p- --open ... -oG allPorts` | § 1.2 Port Scanning |
| 03 | `Sense_03_extractports.png` | `extractPorts allPorts` | § 1.2 Port Scanning |
| 04 | `Sense_04_nmap_targeted_1.png` | `nmap -sCV -p80,443 ...` + `cat targeted` | § 1.3 Targeted Scan |
| 05 | `Sense_05_whatweb.png` | `whatweb http://10.129.10.174` | § 1.3 Targeted Scan |
| 06 | `Sense_06_pfsense_login.png` | Browser: pfSense login UI (`index.php`) | § 1.3 Targeted Scan |
| 07 | `Sense_07_openssl_tls.png` | `openssl s_client -connect 10.129.10.174:443` | § 2.1 HTTPS and TLS |
| 08 | `Sense_08_wfuzz_directory.png` | `wfuzz ... /FUZZ` (`tree` hit) | § 2.2 Web content discovery |
| 09 | `Sense_09_tree_interface.png` | `/tree` UI / navigation | § 2.2 Web content discovery |
| 10 | `Sense_10_grep_wordlist.png` | `grep ... > files` (keyword wordlist) | § 2.3 Keyword-filtered `.txt` |
| 11 | `Sense_11_wfuzz_fuzz_txt.png` | `wfuzz ... /FUZZ.txt` (changelog + system-users hits) | § 2.3 Keyword-filtered `.txt` |
| 12 | `Sense_12_changelog_txt.png` | Browser: `/changelog.txt` | § 2.3 Keyword-filtered `.txt` |
| 13 | `Sense_13_system_users_txt.png` | Browser: `/system-users.txt` | § 2.3 Keyword-filtered `.txt` |
| 14 | `Sense_14_searchsploit_edb43560.png` | `searchsploit` + `searchsploit -m` + `mv` exploit | § 3.1 Exploit selection |
| 15 | `Sense_15_exploit_python_output.png` | `python3 pfsense_exploit.py ...` | § 3.2 Authenticated exploit |
| 16 | `Sense_16_proof_shell_flags.png` | `nc` listener, `whoami`, `cat` user + root flags | § 4.2 Proof |

## Maintenance notes

- **`Pasted image 20260327204519.png`** was added as the primary **full TCP** scan capture → **`Sense_02_nmap_allports.png`**.
- A duplicate **`Sense_16_proof_shell.png`** (same content as searchsploit) was **deleted**.
- **`Sense_13_pfsense_dashboard.png`** was mislabeled: it showed **exploit output + `nc` + flags**, not only the dashboard → renamed **`Sense_16_proof_shell_flags.png`**.
