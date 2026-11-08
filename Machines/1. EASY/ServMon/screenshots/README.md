# ServMon — Screenshot index

Canonical assets live next to this file. The main writeup references them as `screenshots/<filename>.png`.

## Rename mapping (import name → final filename)

| Old name (Pasted image …) | New filename |
| --- | --- |
| `Pasted image 20251208134128.png` | `ServMon_01_ping.png` |
| `Pasted image 20251208134203.png` | `ServMon_02_nmap_allports.png` |
| `Pasted image 20251208134255.png` | `ServMon_03_extractports.png` |
| `Pasted image 20251208134736.png` | `ServMon_04_nmap_targeted_services.png` |
| `Pasted image 20251208134813.png` | `ServMon_05_nmap_targeted_rpc_fingerprints_smb.png` |
| `Pasted image 20251208135120.png` | `ServMon_06_ftp_anonymous_listing.png` |
| `Pasted image 20251208135213.png` | `ServMon_07_cat_confidential_txt.png` |
| `Pasted image 20251208135304.png` | `ServMon_08_cat_notes_to_do_txt.png` |
| `Pasted image 20251208135437.png` | `ServMon_09_searchsploit_nvms_traversal.png` |
| `Pasted image 20251208135827.png` | `ServMon_10_nvms1000_web_login.png` |
| `Pasted image 20251208140038.png` | `ServMon_11_exploitdb_47774_directory_traversal_poc.png` |
| `Pasted image 20251208140707.png` | `ServMon_12_burp_repeater_login_htm.png` |
| `Pasted image 20251208140751.png` | `ServMon_13_burp_repeater_traversal_win_ini.png` |
| `Pasted image 20251208140910.png` | `ServMon_14_burp_repeater_traversal_hosts.png` |
| `Pasted image 20251208141102.png` | `ServMon_15_burp_repeater_traversal_passwords_txt.png` |
| `Pasted image 20251208141339.png` | `ServMon_16_cat_users_passwords_files.png` |
| `Pasted image 20251208142005.png` | `ServMon_17_crackmapexec_smb_spray.png` |
| `Pasted image 20251208142051.png` | `ServMon_18_cat_credentials_nadine.png` |
| `Pasted image 20251208142147.png` | `ServMon_19_crackmapexec_smb_verify.png` |
| `Pasted image 20251208142600.png` | `ServMon_20_cmd_user_txt.png` |
| `Pasted image 20251208143135.png` | `ServMon_21_nadine_enum_net_user.png` |
| `Pasted image 20251208144737.png` | `ServMon_22_nsclient_web_login_8443.png` |
| `Pasted image 20251208144817.png` | `ServMon_23_searchsploit_nsclient.png` |
| `Pasted image 20251208144913.png` | `ServMon_24_exploitdb_46802_nsclient_privesc_txt.png` |
| `Pasted image 20251208145056.png` | `ServMon_25_nscp_web_password_display.png` |
| `Pasted image 20251208145230.png` | `ServMon_26_nsclient_login_403_forbidden.png` |
| `Pasted image 20251208145736.png` | `ServMon_27_nsclient_localhost_home_metrics.png` |
| `Pasted image 20251208150003.png` | `ServMon_28_nsclient_modules_enabled.png` |
| `Pasted image 20251208150437.png` | `ServMon_29_netcat_evil_bat_staging.png` |
| `Pasted image 20251208151238.png` | `ServMon_30_smb_guest_blocked_impacket_smbserver.png` |
| `Pasted image 20251208151451.png` | `ServMon_31_smb_authenticated_mount_impacket.png` |
| `Pasted image 20251208151604.png` | `ServMon_32_copy_payloads_c_temp.png` |
| `Pasted image 20251208151757.png` | `ServMon_33_nsclient_external_script_reverse.png` |
| `Pasted image 20251208152947.png` | `ServMon_34_nc_listener_system_shell_root_txt.png` |

**Removed as exact duplicates (same pixels / redundant capture):**

- `Pasted image 20251208134438.png`, `Pasted image 20251208134501.png` — duplicate `extractPorts` output vs `…34255.png`
- `Pasted image 20251208134847.png` — duplicate tail of targeted `nmap` vs `…34813.png`
- `Pasted image 20251208145350.png` — duplicate NSClient **403** login vs `…45230.png`

## Table (sequence → content → README section)

| Seq | Filename | What it shows | README section |
| --- | --- | --- | --- |
| 01 | `ServMon_01_ping.png` | `ping -c 1` reply, TTL 127 | §1.1 Connectivity |
| 02 | `ServMon_02_nmap_allports.png` | Full TCP SYN scan, open ports | §1.2 Port scan |
| 03 | `ServMon_03_extractports.png` | `extractPorts allPorts` comma list | §1.2 Port scan |
| 04 | `ServMon_04_nmap_targeted_services.png` | `nmap -sC -sV` services (FTP anon, SSH, HTTP, SMB, 8443 NSClient++) | §1.3 Targeted scan |
| 05 | `ServMon_05_nmap_targeted_rpc_fingerprints_smb.png` | High RPC ports, HTTP/8443 fingerprints, SMB scripts, OS Windows | §1.3 Targeted scan |
| 06 | `ServMon_06_ftp_anonymous_listing.png` | Anonymous FTP, `Users/Nadine/Nathan`, `get` files | §2.1 FTP |
| 07 | `ServMon_07_cat_confidential_txt.png` | `Confidential.txt` (Passwords.txt on Desktop) | §2.1 FTP |
| 08 | `ServMon_08_cat_notes_to_do_txt.png` | `Notes to do.txt` (NVMS / NSClient tasks) | §2.1 FTP |
| 09 | `ServMon_09_searchsploit_nvms_traversal.png` | `searchsploit NVMS` — EDB **47774** | §3.1 SearchSploit |
| 10 | `ServMon_10_nvms1000_web_login.png` | Browser NVMS-1000 login page | §2.2 Web |
| 11 | `ServMon_11_exploitdb_47774_directory_traversal_poc.png` | `searchsploit -x` **47774** PoC (`win.ini` path) | §3.1 SearchSploit |
| 12 | `ServMon_12_burp_repeater_login_htm.png` | Burp **Repeater** `GET /Pages/login.htm` | §3.2 Burp |
| 13 | `ServMon_13_burp_repeater_traversal_win_ini.png` | Traversal to `win.ini` body | §3.2 Burp |
| 14 | `ServMon_14_burp_repeater_traversal_hosts.png` | Traversal to `…\Drivers\etc\hosts` | §3.2 Burp |
| 15 | `ServMon_15_burp_repeater_traversal_passwords_txt.png` | Traversal to `Passwords.txt` | §3.2 Burp |
| 16 | `ServMon_16_cat_users_passwords_files.png` | `cat users` / `cat passwords` | §3.3 SMB / SSH |
| 17 | `ServMon_17_crackmapexec_smb_spray.png` | `crackmapexec smb … --continue-on-success` | §3.3 SMB / SSH |
| 18 | `ServMon_18_cat_credentials_nadine.png` | `credentials` file `Nadine:…` | §3.3 SMB / SSH |
| 19 | `ServMon_19_crackmapexec_smb_verify.png` | Single-user `crackmapexec` verify | §3.3 SMB / SSH |
| 20 | `ServMon_20_cmd_user_txt.png` | `whoami`, `type user.txt` | §3.3 SMB / SSH |
| 21 | `ServMon_21_nadine_enum_net_user.png` | `whoami /priv`, `net user nadine` | §4.1 Privesc |
| 22 | `ServMon_22_nsclient_web_login_8443.png` | NSClient++ `:8443` password-only login | §4.1 Privesc |
| 23 | `ServMon_23_searchsploit_nsclient.png` | `searchsploit NSClient++` | §4.1 Privesc |
| 24 | `ServMon_24_exploitdb_46802_nsclient_privesc_txt.png` | **46802** privesc text (`nscp`, modules, `nc`) | §4.1 Privesc |
| 25 | `ServMon_25_nscp_web_password_display.png` | `nscp web --password --display` output | §4.2 NSClient password |
| 26 | `ServMon_26_nsclient_login_403_forbidden.png` | Direct **403** on `:8443` | §4.2 NSClient password |
| 27 | `ServMon_27_nsclient_localhost_home_metrics.png` | `https://localhost:8443` Home after forward | §4.3 Port forward |
| 28 | `ServMon_28_nsclient_modules_enabled.png` | Modules — **CheckExternalScripts**, **Scheduler** | §4.3 Port forward |
| 29 | `ServMon_29_netcat_evil_bat_staging.png` | Unzip netcat, `evil.bat` contents | §4.4 Transfer |
| 30 | `ServMon_30_smb_guest_blocked_impacket_smbserver.png` | Guest SMB blocked + `impacket-smbserver` | §4.4 Transfer |
| 31 | `ServMon_31_smb_authenticated_mount_impacket.png` | `net use` + credentialed `impacket-smbserver` | §4.4 Transfer |
| 32 | `ServMon_32_copy_payloads_c_temp.png` | `copy` from `X:` to `C:\Temp` | §4.4 Transfer |
| 33 | `ServMon_33_nsclient_external_script_reverse.png` | Settings → external script **`reverse`** → `evil.bat` | §4.5 Execute |
| 34 | `ServMon_34_nc_listener_system_shell_root_txt.png` | `nc -nlvp 443`, `whoami` SYSTEM, `root.txt` | §4.5 Execute |
