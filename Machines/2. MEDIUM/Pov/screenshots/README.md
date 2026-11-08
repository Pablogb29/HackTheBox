# POV screenshots index

| # | Filename | Captures | Used in |
|---:|---|---|---|
| 01 | `pov_01_ping.png` | `ping -c 1 10.129.61.84` | `1.1 Connectivity Test` |
| 02 | `pov_02_nmap_allports.png` | `nmap -p- ... -oG allPorts` | `1.2 Port Scanning` |
| 03 | `pov_03_extractports.png` | `extractPorts` → port `80` | `1.2 Port Scanning` |
| 04 | `pov_04_nmap_targeted.png` | `nmap -sCV -p80` + `cat targeted` | `1.3 Targeted Scan` |
| 05 | `pov_05_whatweb.png` | `whatweb http://10.129.61.84/` | `2.1 HTTP fingerprint` |
| 06 | `pov_06_website_pov_htb.png` | Browser `http://pov.htb` | `2.1 HTTP fingerprint` |
| 07 | `pov_07_contact_dev_hint.png` | Contact page → `dev.pov.htb` / `sfitz@pov.htb` | `2.2 Contact page` |
| 08 | `pov_08_dev_portfolio.png` | `http://dev.pov.htb/portfolio/` | `2.3 Developer portfolio` |
| 09 | `pov_09_cv_pdf.png` | Downloaded `cv.pdf` (Stephen Fitz) | `2.3 Developer portfolio` |
| 10 | `pov_10_dev_contact.png` | Portfolio contact section | `2.3 Developer portfolio` |
| 11 | `pov_11_burp_download_cv.png` | Burp POST `file=cv.pdf` | `3.1 Path traversal` |
| 12 | `pov_12_lfi_web_config.png` | `file=....//web.config` + machineKey | `3.1 Path traversal` |
| 13 | `pov_13_ysoserial_viewstate.png` | ysoserial ViewState payload generation | `3.2 ViewState RCE` |
| 14 | `pov_14_revshells_powershell.png` | revshells.com PowerShell Base64 | `3.2 ViewState RCE` |
| 15 | `pov_15_viewstate_shell_sfitz.png` | Burp ViewState + shell as `sfitz` | `3.2 ViewState RCE` |
| 16 | `pov_16_connection_xml.png` | `connection.xml` for `alaading` | `3.3 Credential reuse` |
| 17 | `pov_17_decrypt_alaading_password.png` | `Import-Clixml` → plaintext password | `3.3 Credential reuse` |
| 18 | `pov_18_user_flag_invoke_command.png` | `Invoke-Command` → `user.txt` | `3.3 Credential reuse` |
| 19 | `pov_19_upload_runascs.png` | `certutil` download of RunasCs | `3.4 RunasCs shell` |
| 20 | `pov_20_runascs_alaading_shell.png` | RunasCs reverse shell as `alaading` | `3.4 RunasCs shell` |
| 21 | `pov_21_sedebugprivilege.png` | `whoami /priv` SeDebugPrivilege | `4.1 SeDebugPrivilege` |
| 22 | `pov_22_upload_psgetsys.png` | Upload `psgetsys.ps1` | `4.1 SeDebugPrivilege` |
| 23 | `pov_23_tasklist_winlogon.png` | `tasklist` → `winlogon.exe` PID 556 | `4.1 SeDebugPrivilege` |
| 24 | `pov_24_upload_nc.png` | Upload `nc.exe` | `4.1 SeDebugPrivilege` |
| 25 | `pov_25_chisel_evil_winrm.png` | Chisel local port + Evil-WinRM | `4.2 Chisel + Evil-WinRM` |
| 26 | `pov_26_system_shell.png` | ImpersonateFromParentPid → SYSTEM | `4.3 SYSTEM + root flag` |
| 27 | `pov_27_root_flag.png` | `type root.txt` | `4.3 SYSTEM + root flag` |
