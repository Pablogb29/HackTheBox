# Jeeves screenshots index

| # | Filename | Captures | Used in |
|---:|---|---|---|
| 01 | `jeeves_01_ping.png` | `ping -c 1 10.129.228.112` | `1.1 Connectivity Test` |
| 02 | `jeeves_02_nmap_allports.png` | `nmap -p- --open ... -oG allPorts` | `1.2 Port Scanning` |
| 03 | `jeeves_03_extractports.png` | `extractPorts allPorts` → `80,135,445,50000` | `1.2 Port Scanning` |
| 04 | `jeeves_04_nmap_targeted_1.png` | `nmap -sCV -p80,135,445,50000 ... -oN targeted` | `1.3 Targeted Scan` |
| 05 | `jeeves_05_nmap_targeted_2.png` | `cat targeted` (IIS / Jetty / SMB details) | `1.3 Targeted Scan` |
| 06 | `jeeves_06_ffuf_askjeeves.png` | `ffuf` on `:50000` finds `/askjeeves` | `2.1 Jetty / Jenkins path discovery` |
| 07 | `jeeves_07_jenkins_script_whoami.png` | Script Console `whoami` → `jeeves\kohsuke` | `3.1 Jenkins Script Console RCE` |
| 08 | `jeeves_08_jenkins_script_ipconfig.png` | Script Console `ipconfig` (Windows confirmed) | `3.1 Jenkins Script Console RCE` |
| 09 | `jeeves_09_nishang_invoke_powershelltcp.png` | Nishang callback line `10.10.15.14:8001` | `3.2 Nishang reverse shell` |
| 10 | `jeeves_10_reverse_shell_kohsuke.png` | HTTP serve + `nc` + Groovy cradle → shell | `3.2 Nishang reverse shell` |
| 11 | `jeeves_11_user_flag.png` | `user.txt` on `kohsuke` desktop | `3.3 User flag` |
| 12 | `jeeves_12_smb_exfil_ceh_kdbx.png` | Impacket SMB + copy `CEH.kdbx` | `4.1 KeePass exfiltration` |
| 13 | `jeeves_13_john_keepass.png` | `keepass2john` + `john` → `moonshine1` | `4.2 Crack KeePass` |
| 14 | `jeeves_14_keepass_backup_hash.png` | KeePassXC “Backup stuff” NTLM hash | `4.2 Crack KeePass` |
| 15 | `jeeves_15_pth_winexe_administrator.png` | `pth-winexe` as Administrator + `hm.txt` hint | `4.3 Pass-the-Hash` |
| 16 | `jeeves_16_ads_root_flag.png` | `dir /R` + ADS `hm.txt:root.txt` | `4.4 Root flag via ADS` |
