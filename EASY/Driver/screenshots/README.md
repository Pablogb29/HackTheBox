# Screenshots index — Driver (HTB)

| # | Filename | Command / action captured | README section |
|---|----------|----------------------------|----------------|
| 01 | `driver_01_ping.png` | `ping -c 1 10.129.29.215` | §1.1 Connectivity Test |
| 02 | `driver_02_nmap_allports.png` | Full TCP SYN scan (`nmap -p- ...`) | §1.2 Port Scanning |
| 03 | `driver_03_extractports.png` | `extractPorts allPorts` | §1.2 Port Scanning |
| 04 | `driver_04_nmap_targeted_1.png` | `nmap -sCV -p80,135,445,5985 ...` | §1.3 Targeted Scan |
| 05 | `driver_05_nmap_targeted_2.png` | `cat targeted -l java` | §1.3 Targeted Scan |
| 06 | `driver_06_whatweb_curl.png` | `whatweb`, `curl`, `curl -I` | §2.1 HTTP / IIS enumeration |
| 07 | `driver_07_smbclient_failures.png` | `smbclient -N -L`, `smbclient -L ... admin%admin` | §2.3 SMB share listing attempts |
| 08 | `driver_08_web_home.png` | Browser — authenticated MFP portal home | §2.2 Authenticated web surface |
| 09 | `driver_09_probe_scf.png` | `nano` / `cat probe.scf` | §3.1 Coerced NetNTLMv2 capture |
| 10 | `driver_10_fw_up_responder.png` | Browser upload + Responder startup | §3.1 Coerced NetNTLMv2 capture |
| 11 | `driver_11_responder_hash.png` | Responder SMB hash capture (`DRIVER\\tony`) | §3.1 Coerced NetNTLMv2 capture |
| 12 | `driver_12_john_crack.png` | `john --wordlist=... tony.ntlmv2` | §3.2 Offline cracking |
| 13 | `driver_13_evil_winrm_user_flag.png` | `evil-winrm`, `whoami`, `user.txt` | §3.2 WinRM foothold |
| 14 | `driver_14_privesc_enum_history.png` | `whoami /priv`, PSReadLine history (Ricoh) | §4.1 Local enumeration |
| 15 | `driver_15_msfvenom.png` | `msfvenom ... shell.exe` | §4.3 Meterpreter + Ricoh exploit |
| 16 | `driver_16_upload_shell.png` | Evil-WinRM `upload shell.exe`, `.\shell.exe` | §4.3 Meterpreter + Ricoh exploit |
| 17 | `driver_17_meterpreter_handler.png` | Handler `run -j`, `sessions -i 1`, `getuid` | §4.3 Meterpreter + Ricoh exploit |
| 18 | `driver_18_ricoh_privesc.png` | `ricoh_driver_privesc`, session 2 / `whoami` SYSTEM | §4.3 Meterpreter + Ricoh exploit |
| 19 | `driver_19_root_flag.png` | `type root.txt` | §4.4 SYSTEM proof |
