# TombWatcher — screenshots index

| # | Filename | Captures | Used in |
|---:|---|---|---|
| 01 | `tombwatcher_01_ping.png` | ICMP reachability (TTL 127) | 1.1 Connectivity Test |
| 02 | `tombwatcher_02_nmap_allports.png` | Full TCP port discovery | 1.2 Port Scanning |
| 03 | `tombwatcher_03_extractports.png` | `extractPorts` open-port list | 1.2 Port Scanning |
| 04 | `tombwatcher_04_nmap_targeted_1.png` | Targeted `-sCV` scan (start) | 1.3 Targeted Scan |
| 05 | `tombwatcher_05_nmap_targeted_2.png` | Targeted scan output (`cat targeted`) | 1.3 Targeted Scan |
| 06 | `tombwatcher_06_iis_default.png` | Default IIS page on port 80 | 2.1 HTTP (IIS) |
| 07 | `tombwatcher_07_nxc_henry_ldap.png` | SMB fail / LDAP OK / WinRM fail for `henry` | 2.2 Credential check |
| 08 | `tombwatcher_08_ldap_users.png` | LDAP user export | 2.2 Credential check |
| 09 | `tombwatcher_09_ldap_groups.png` | LDAP groups | 2.2 Credential check |
| 10 | `tombwatcher_10_asreproast_fail.png` | AS-REP roast with no hits | 2.2 Credential check |
| 11 | `tombwatcher_11_rusthound.png` | RustHound-CE collection | 2.3 RustHound / BloodHound |
| 12 | `tombwatcher_12_bloodhound_path.png` | Henry → ADCS attack path | 2.3 RustHound / BloodHound |
| 13 | `tombwatcher_13_ntpdate.png` | Clock sync to DC | 3.1 Clock sync / Kerberoast |
| 14 | `tombwatcher_14_kerberoast_empty.png` | Default Kerberoast empty | 3.1 Clock sync / Kerberoast |
| 15 | `tombwatcher_15_targeted_kerberoast_alfred.png` | WriteSPN + targeted roast of Alfred | 3.1 Clock sync / Kerberoast |
| 16 | `tombwatcher_16_hashcat_alfred.png` | Hashcat crack → `basketball` | 3.1 Clock sync / Kerberoast |
| 17 | `tombwatcher_17_alfred_winrm_fail.png` | Alfred WinRM denied | 3.1 Clock sync / Kerberoast |
| 18 | `tombwatcher_18_gmsa_ansible_dev.png` | Add to Infrastructure + gMSA hash | 3.2 gMSA → sam → john |
| 19 | `tombwatcher_19_set_password_sam.png` | Reset `sam` via `ansible_dev$` | 3.2 gMSA → sam → john |
| 20 | `tombwatcher_20_genericall_john.png` | Owner + GenericAll on `john` | 3.2 gMSA → sam → john |
| 21 | `tombwatcher_21_shadow_john.png` | Shadow Credentials → john NT hash | 3.2 gMSA → sam → john |
| 22 | `tombwatcher_22_john_remote_mgmt.png` | John in Remote Management Users | 3.2 gMSA → sam → john |
| 23 | `tombwatcher_23_user_flag.png` | Evil-WinRM as john + user.txt | 3.3 WinRM as john |
| 24 | `tombwatcher_24_whoami_all.png` | `whoami /all` as john | 3.3 WinRM as john |
| 25 | `tombwatcher_25_certipy_find_john.png` | Certipy find as john | 4.1 Certipy / cert_admin |
| 26 | `tombwatcher_26_webserver_template.png` | WebServer template details | 4.1 Certipy / cert_admin |
| 27 | `tombwatcher_27_deleted_cert_admin.png` | Deleted object SID …-1111 | 4.1 Certipy / cert_admin |
| 28 | `tombwatcher_28_restore_cert_admin.png` | Restore-ADObject → cert_admin | 4.1 Certipy / cert_admin |
| 29 | `tombwatcher_29_shadow_cert_admin.png` | Shadow Credentials on cert_admin | 4.1 Certipy / cert_admin |
| 30 | `tombwatcher_30_certipy_vulnerable.png` | Certipy find `-vulnerable` | 4.2 ESC15 |
| 31 | `tombwatcher_31_esc15_webserver.png` | ESC15 / CVE-2024-49019 on WebServer | 4.2 ESC15 |
| 32 | `tombwatcher_32_administrator_sid.png` | Administrator SID …-500 in BloodHound | 4.2 ESC15 |
| 33 | `tombwatcher_33_esc15_req.png` | ESC15 cert request (Client Auth policy) | 4.2 ESC15 |
| 34 | `tombwatcher_34_auth_eku_fail.png` | Auth fails (Server Auth EKU) | 4.2 ESC15 |
| 35 | `tombwatcher_35_cert_request_agent.png` | Certificate Request Agent PFX | 4.3 ESC3 |
| 36 | `tombwatcher_36_machine_esc3.png` | Machine template / ESC3 note | 4.3 ESC3 |
| 37 | `tombwatcher_37_esc3_on_behalf.png` | Restore + User on-behalf-of admin | 4.3 ESC3 |
| 38 | `tombwatcher_38_admin_root_flag.png` | Certipy auth + admin WinRM + root.txt | 4.3 ESC3 |
