# Screenshots index — Scrambled

Paths are relative to `cases/HackTheBox/MEDIUM/Scrambled/README.md`.

| # | Filename | Captured from `notes/ctf/htb-scrambled.md` |
|---:|---|---|
| 01 | `scrambled_01_ping.png` | `PING` |
| 02 | `scrambled_02_nmap_targeted.png` | `cat targeted` |
| 03 | `scrambled_03_smb_rpc_no_useful_results.png` | SMB/RPC enum yielded nothing |
| 04 | `scrambled_04_ldap_namingcontexts.png` | `ldapsearch ... -s base namingcontexts` |
| 05 | `scrambled_05_ldap_exhaustive_search.png` | `ldapsearch ... -b 'DC=scrm,DC=local'` |
| 06 | `scrambled_06_web_ntlm_disabled.png` | Web note: NTLM disabled |
| 07 | `scrambled_07_contact_it_user.png` | Web “Contact IT” shows `ksimpson` |
| 08 | `scrambled_08_kerbrute_userenum.png` | `kerbrute userenum --dc ... users` |
| 09 | `scrambled_09_kerbrute_wordlist_enum.png` | `kerbrute` (wordlist) attempt |
| 10 | `scrambled_10_getuserspns_initial_try.png` | `GetUserSPNs.py ... -k -dc-ip ...` (initial try) |
| 11 | `scrambled_11_smbclient_public_share_access.png` | `impacket-smbclient ...` |
| 12 | `scrambled_12_public_share_listing.png` | Browse `Public` share |
| 13 | `scrambled_13_pdf_sql_credentials_hint.png` | Read downloaded PDF |
| 14 | `scrambled_14_kerberos_request_ticket_setup.png` | Kerberos ticket flow / request setup |
| 15 | `scrambled_15_john_crack_result.png` | John cracked the SQL service password |
| 16 | `scrambled_16_record_sqlsvc_password_spn.png` | Saved SQL password + SPN |
| 17 | `scrambled_17_mssqlclient_ntlm_login_failure.png` | MSSQL login failed (NTLM/attempt) |
| 18 | `scrambled_18_gettgt_and_mssqlclient_kerberos_attempt.png` | `getTGT.py` + Kerberos MSSQL attempt |
| 19 | `scrambled_19_ntlm_hash_conversion_web.png` | Password -> NTLM hash conversion |
| 20 | `scrambled_20_getpac_domain_sid.png` | `getPac.py ... -targetUser Administrator` |
| 21 | `scrambled_21_ticketer_silver_ticket.png` | `ticketer.py` generates `Administrator.ccache` |
| 22 | `scrambled_22_mssql_silver_ticket_success.png` | MSSQL access via Silver Ticket |
| 23 | `scrambled_23_enable_xp_cmdshell.png` | `sp_configure 'xp_cmdshell', 1` |
| 24 | `scrambled_24_upload_nc_via_xp_cmdshell.png` | `xp_cmdshell` staging `nc.exe` |
| 25 | `scrambled_25_reverse_shell_trigger.png` | `xp_cmdshell` triggers reverse shell |
| 26 | `scrambled_26_recursive_user_txt_search.png` | SQL `dir /r /s user.txt` |
| 27 | `scrambled_27_recursive_other_flags_search.png` | Continued file hunting |
| 28 | `scrambled_28_juicypotato_failed.png` | JuicyPotato attempt failed |
| 29 | `scrambled_29_sql_openrowset_user_flag.png` | SQL `OPENROWSET` user flag |
| 30 | `scrambled_30_sql_openrowset_root_flag.png` | SQL `OPENROWSET` root flag |

