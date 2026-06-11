# Screenshots — HTB Certified

| # | Filename | Command / Action | README Section |
|---|----------|-----------------|----------------|
| 01 | `certified_01_ping.png` | `ping -c 1 10.129.231.186` | 1.1 Connectivity Test |
| 02 | `certified_02_nmap_allports.png` | `nmap -p- --open -sS ...` | 1.2 Port Scanning |
| 03 | `certified_03_extractports.png` | `extractPorts allPorts` | 1.2 Port Scanning |
| 04 | `certified_04_nmap_targeted_1.png` | `nmap -sCV ...` (raw output) | 1.3 Targeted Scan |
| 05 | `certified_05_nmap_targeted_2.png` | `cat targeted` (formatted) | 1.3 Targeted Scan |
| 06 | `certified_06_nxc_smb_winrm.png` | `nxc smb` + `nxc winrm` judith.mader | 2.1 SMB and WinRM Authentication |
| 07 | `certified_07_rpcclient_users.png` | `rpcclient enumdomusers` | 2.2 Domain User Enumeration |
| 08 | `certified_08_bloodhound_collection.png` | `bloodhound-python -c all` | 2.3 BloodHound AD Enumeration |
| 09 | `certified_09_bh_writeowner.png` | BH CE: judith.mader WriteOwner → MANAGEMENT | 2.3 BloodHound AD Enumeration |
| 10 | `certified_10_acl_ownership.png` | impacket-owneredit + dacledit + net rpc group addmem | 3.1 ACL Chain Abuse |
| 11 | `certified_11_pywhisker_mgmtsvc.png` | pywhisker shadow creds on management_svc | 3.2 Shadow Credentials |
| 12 | `certified_12_pkinit_mgmtsvc_hash.png` | PKINITtools TGT + getnthash management_svc | 3.3 PKINIT Authentication |
| 13 | `certified_13_nxc_mgmtsvc_pwned.png` | `nxc smb/winrm` management_svc (Pwn3d!) | 3.4 WinRM Access |
| 14 | `certified_14_user_flag.png` | `evil-winrm` + `type user.txt` | 3.4 WinRM Access |
| 15 | `certified_15_lateral_ca_operator.png` | pywhisker + PKINITtools + nxc for ca_operator | 4.1 Lateral Movement |
| 16 | `certified_16_certipy_adcs_enum.png` | `certipy-ad find -vulnerable` | 4.2 AD CS Enumeration |
| 17 | `certified_17_esc9_exploit.png` | ESC9: UPN change + cert request + auth | 4.3 ESC9 Exploitation |
| 18 | `certified_18_nxc_admin_pwned.png` | `nxc smb/winrm` administrator (Pwn3d!) | 4.4 Administrator Access |
| 19 | `certified_19_root_flag.png` | `evil-winrm` + `type root.txt` | 4.4 Administrator Access |
