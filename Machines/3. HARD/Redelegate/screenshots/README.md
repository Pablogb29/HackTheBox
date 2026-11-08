# Redelegate — Screenshots Index

| # | Filename | Captures | Used in |
|---:|---|---|---|
| 01 | `redelegate_01_ping.png` | ICMP connectivity to `10.129.234.50` (TTL 127) | 1.1 Connectivity Test |
| 02 | `redelegate_02_nmap_allports.png` | Full TCP SYN scan — DC/AD port set + FTP/HTTP | 1.2 Port Scanning |
| 03 | `redelegate_03_extractports.png` | `extractPorts` clipboard list | 1.2 Port Scanning |
| 04 | `redelegate_04_nmap_targeted_1.png` | Targeted `-sCV` (FTP anon + AD services, part 1) | 1.3 Targeted Scan |
| 05 | `redelegate_05_nmap_targeted_2.png` | Targeted `-sCV` (RDP/WinRM/SMB scripts, part 2) | 1.3 Targeted Scan |
| 06 | `redelegate_06_ftp_anonymous.png` | Anonymous FTP listing + ASCII downloads | 2.1 Anonymous FTP Enumeration |
| 07 | `redelegate_07_ftp_binary_kdbx.png` | Binary-mode download of `Shared.kdbx` | 2.1 Anonymous FTP Enumeration |
| 08 | `redelegate_08_ftp_txt_files.png` | `CyberAudit.txt` + `TrainingAgenda.txt` (`SeasonYear!`) | 2.1 Anonymous FTP Enumeration |
| 09 | `redelegate_09_season_passwords.png` | Seasonal wordlist `passwords.txt` | 2.2 KeePass Credential Recovery |
| 10 | `redelegate_10_keepass_unlocked.png` | KeePassXC vault structure (IT/HelpDesk/Finance) | 2.2 KeePass Credential Recovery |
| 11 | `redelegate_11_keepass_creds.png` | Extracted credentials in `creds.txt` | 2.2 KeePass Credential Recovery |
| 12 | `redelegate_12_ftpuser_fail.png` | `FTPUser` login rejected | 2.3 Credential Validation |
| 13 | `redelegate_13_admin_auth_fail.png` | Administrator WinRM/SMB `STATUS_LOGON_FAILURE` | 2.3 Credential Validation |
| 14 | `redelegate_14_mssql_sqlguest.png` | `SQLGuest` local MSSQL auth + guest context | 2.4 MSSQL Local Login |
| 15 | `redelegate_15_msf_enum_domain.png` | Metasploit RID domain account enumeration | 2.4 MSSQL Local Login |
| 16 | `redelegate_16_users_extract.png` | Grep → `users.txt` spray list | 2.4 MSSQL Local Login |
| 17 | `redelegate_17_password_spray.png` | Spray hit `Marie.Curie:Fall2024!` | 3.1 Password Spray |
| 18 | `redelegate_18_ldap_marie.png` | LDAP auth as `marie.curie` | 3.1 Password Spray |
| 19 | `redelegate_19_rusthound.png` | RustHound-CE BloodHound collection | 3.2 BloodHound Collection |
| 20 | `redelegate_20_bh_forcechangepassword.png` | Helpdesk `ForceChangePassword` graph | 3.2 BloodHound Collection |
| 21 | `redelegate_21_bh_helen_fs01.png` | Helen → IT → `GenericAll` on FS01 | 3.2 BloodHound Collection |
| 22 | `redelegate_22_reset_helen.png` | `bloodyAD` password reset for Helen.Frost | 3.3 ForceChangePassword |
| 23 | `redelegate_23_helen_auth.png` | Helen LDAP/SMB/WinRM (`Pwn3d!`) | 3.3 ForceChangePassword |
| 24 | `redelegate_24_user_flag.png` | Evil-WinRM as Helen + `user.txt` | 3.3 ForceChangePassword |
| 25 | `redelegate_25_whoami_priv.png` | `whoami /all` — `SeEnableDelegationPrivilege` | 4.1 Privilege Discovery |
| 26 | `redelegate_26_fs01_takeover_delegation.png` | Reset `FS01$`, SMB verify, UAC `TRUSTED_TO_AUTH_FOR_DELEGATION`, `msDS-AllowedToDelegateTo` | 4.2 Takeover + Delegation Setup |
| 27 | `redelegate_27_getst_secretsdump.png` | S4U `getST` + Administrator secretsdump | 4.3 Constrained Delegation |
| 28 | `redelegate_28_root_flag.png` | Evil-WinRM PtH Administrator + `root.txt` | 4.3 Constrained Delegation |
