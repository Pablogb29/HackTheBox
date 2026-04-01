# Screenshots index — Support (`support`)

| # | Filename | Command / action captured | README section |
|---|----------|---------------------------|----------------|
| 01 | `support_01_ping.png` | `ping -c 1` target | §1.1 Connectivity Test |
| 02 | `support_02_nmap_allports.png` | `nmap -p- --open -sS …` | §1.2 Port Scanning |
| 03 | `support_03_extractports.png` | `extractPorts allPorts` | §1.2 Port Scanning |
| 04 | `support_04_nmap_targeted.png` | `nmap -sC -sV` (`targeted`) | §1.3 Targeted Scan |
| 05 | `support_05_smbclient_list.png` | `smbclient -L … -N` | §2.1 SMB share enumeration |
| 06 | `support_06_smbmap.png` | `smbmap -H … -u none` | §2.1 SMB share enumeration |
| 07 | `support_07_smb_support_tools.png` | `smbclient //…/support-tools` + `get` | §2.2 support-tools share |
| 08 | `support_08_unzip_userinfo.png` | `unzip UserInfo.exe.zip` | §2.2 support-tools share |
| 09 | `support_09_userinfo_config.png` | `UserInfo.exe.config` | §2.3 UserInfo configuration |
| 10 | `support_10_strings_userinfo.png` | `strings -e l UserInfo.exe` | §2.3 UserInfo configuration |
| 11 | `support_11_kerbrute_ldap.png` | `kerbrute userenum` (short user list) | §2.4 Kerberos user validation |
| 12 | `support_12_kerbrute_xato.png` | `kerbrute userenum` (large wordlist) | §2.4 Kerberos user validation |
| 13 | `support_13_ilspy_overview.png` | ILSpy / decompiler overview | §3.1 Recovering ldap credentials |
| 14 | `support_14_ilspy_search.png` | ILSpy search / types | §3.1 Recovering ldap credentials |
| 15 | `support_15_ilspy_decoder.png` | ILSpy decoder logic | §3.1 Recovering ldap credentials |
| 16 | `support_16_decoder_output.png` | `decoder.py` output | §3.1 Recovering ldap credentials |
| 17 | `support_17_cme_smb_ldap.png` | `crackmapexec smb` + `ldap` | §3.1 Recovering ldap credentials |
| 18 | `support_18_cme_winrm_ldap.png` | `crackmapexec winrm` + `ldap` | §3.1 Recovering ldap credentials |
| 19 | `support_19_rpcclient_enumerate.png` | `rpcclient` session | §3.2 Validating ldap and hunting support |
| 20 | `support_20_enumdomusers.png` | `enumdomusers` + pipeline → `users` | §3.2 Validating ldap and hunting support |
| 21 | `support_21_cme_spray.png` | `crackmapexec smb` spray | §3.2 Validating ldap and hunting support |
| 22 | `support_23_ldapsearch_support.png` | `ldapsearch` + `grep` for `support` | §3.2 Validating ldap and hunting support |
| 23 | `support_23_cme_support_winrm.png` | `crackmapexec winrm` for `support` | §3.2 Validating ldap and hunting support |
| 24 | `support_24_evil_winrm_user.png` | `evil-winrm` + `user.txt` | §3.3 Initial shell as support |
| 25 | `support_25_groups.png` | `whoami /groups` — **Shared Support Accounts** | §4.1 Orientation as support |
| 26 | `support_29_bloodhound_files.png` | `bloodhound-python` → **JSON** output | §4.2 Domain Enumeration with BloodHound |
| 27 | `support_30_bloodhound_password.png` | Docker logs — **BloodHound CE** initial admin password | §4.2 Domain Enumeration with BloodHound |
| 28 | `support_31_bloodhound_pathfinding.png` | Pathfinding **SUPPORT** → **ADMINISTRATOR** | §4.2 Domain Enumeration with BloodHound |
| 29 | `support_32_powermad_machineaccount.png` | `New-MachineAccount` (SERVICEA) | §4.3 RBCD setup |
| 30 | `support_33_get_domain_computer_servicea.png` | `Get-DomainComputer SERVICEA` | §4.3 RBCD setup |
| 31 | `support_34_rbcd_msds_allowedtoact.png` | `impacket-rbcd` **write** then **read** (verify **SERVICEA$**) | §4.3 RBCD setup |
| 32 | `support_36_clock_sync_getst.png` | `sudo timedatectl set-ntp off` / `sudo rdate -n` (time sync) | §4.4 Delegation abuse to Administrator |
| 33 | `support_35_getst.png` | `impacket-getST` → `Administrator@…ccache` | §4.4 Delegation abuse to Administrator |
| 34 | `support_37_psexec_shell.png` | `impacket-psexec -k` | §4.4 Delegation abuse to Administrator |
| 35 | `support_38_root_flag.png` | `root.txt` | §4.4 Delegation abuse to Administrator |

**Total:** 35 unique image filenames referenced in `README.md` (two files share the `support_23_` prefix; numbering gaps **22** and **26–28** are unused in the current README).
