# VulnCicada screenshots index

| # | Filename | Captures | Used in |
|---:|---|---|---|
| 01 | `vulncicada_01_ping.png` | `ping -c 1 10.129.234.48` (ttl 127) | `1.1 Connectivity Test` |
| 02 | `vulncicada_02_nmap_allports.png` | `nmap -p- --open ... -oG allPorts` | `1.2 Port Scanning` |
| 03 | `vulncicada_03_extractports.png` | `extractPorts allPorts` | `1.2 Port Scanning` |
| 04 | `vulncicada_04_nmap_targeted.png` | `nmap -sCV` / `targeted` (DC + NFS + IIS) | `1.3 Targeted Scan` |
| 05 | `vulncicada_05_iis_default.png` | Browser default IIS welcome page | `2.1 IIS Default Site` |
| 06 | `vulncicada_06_whatweb.png` | `whatweb` → Microsoft-IIS/10.0 | `2.1 IIS Default Site` |
| 07 | `vulncicada_07_null_smb_nfs_showmount.png` | Null SMB/RPC fail + `showmount -e` `/profiles` | `2.2` / NFS hint |
| 08 | `vulncicada_08_nfs_mount_profiles.png` | Mount NFS + `ls` profile dirs | `2.3 NFS /profiles` |
| 09 | `vulncicada_09_users_txt.png` | `users.txt` from profile folder names | `2.3 NFS /profiles` |
| 10 | `vulncicada_10_marketing_sticky.png` | `marketing.png` sticky note `Cicada123` | `3.1 Credential from marketing.png` |
| 11 | `vulncicada_11_nxc_kerberos_shares.png` | NTLM fail vs Kerberos `-k --shares` | `3.2 Kerberos Authentication` |
| 11b | `vulncicada_11b_certipy_esc8.png` | Certipy find → ESC8 HTTP web enrollment | `4.1 AD CS Enumeration` |
| 11c | `vulncicada_11c_certsrv_401.png` | `curl` `/certsrv/` → HTTP 401 | `4.1 AD CS Enumeration` |
| 12a | `vulncicada_12a_marshaled_dns_dig.png` | `dig` marshaled name → attacker IP | `4.2 Kerberos ESC8` |
| 12 | `vulncicada_12_krbrelayx_got_certificate.png` | `krbrelayx` GOT CERTIFICATE + PetitPotam coerce | `4.2 Kerberos ESC8` |
| 12b | `vulncicada_12b_certipy_auth.png` | `certipy-ad auth` → TGT + `dc-jpq225$` NT hash | `4.3 PKINIT / DCSync` |
| 13 | `vulncicada_13_secretsdump_administrator.png` | DCSync Administrator NT hash | `4.3 PKINIT / DCSync` |
| 14 | `vulncicada_14_flags.png` | `wmiexec` + `user.txt` / `root.txt` | `4.3 Administrator Shell` |
