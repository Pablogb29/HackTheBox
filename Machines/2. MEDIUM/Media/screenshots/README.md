# Media — screenshots index

| # | Filename | Captures | Used in |
|---:|---|---|---|
| 01 | `media_01_ping.png` | ICMP reachability (TTL 127) | 1.1 Connectivity Test |
| 02 | `media_02_nmap_allports.png` | Full TCP discovery → 22,80,3389 | 1.2 Port Scanning |
| 03 | `media_03_extractports.png` | `extractPorts` open-port list | 1.2 Port Scanning |
| 04 | `media_04_nmap_targeted.png` | Targeted `-sCV` on 22,80,3389 | 1.3 Targeted Scan |
| 05 | `media_05_whatweb.png` | `whatweb` Apache/PHP fingerprint | 2.1 HTTP fingerprint |
| 06 | `media_06_website.png` | ProMotion Studio home | 2.1 HTTP fingerprint |
| 07 | `media_07_team_workers.png` | Team / workers page | 2.1 HTTP fingerprint |
| 08 | `media_08_upload_form.png` | Hiring upload (WMP-compatible) | 2.1 HTTP fingerprint |
| 09 | `media_09_wmp_exploits_search.png` | Search for WMP / NTLM techniques | 2.2 NTLM theft research |
| 10 | `media_10_ntlm_theft.png` | `ntlm_theft.py` payload generation | 2.2 NTLM theft research |
| 11 | `media_11_upload_asx_ready.png` | Hiring form with `media.asx` selected | 3.1 Responder + ASX |
| 12 | `media_12_upload_asx_ok.png` | Successful `.asx` submission | 3.1 Responder + ASX |
| 13 | `media_13_ntlm_hash_captured.png` | Responder NetNTLMv2 for `MEDIA\enox` | 3.1 Responder + ASX |
| 14 | `media_14_hashcat_enox.png` | Hashcat → `1234virus@` | 3.2 Crack + SSH |
| 15 | `media_15_user_flag.png` | SSH as enox + `user.txt` | 3.2 Crack + SSH |
| 16 | `media_16_enox_whoami_all.png` | `whoami /all` as enox | 3.2 Crack + SSH |
| 17 | `media_17_users_ip.png` | `C:\Users` + `ipconfig` | 3.2 Crack + SSH |
| 18 | `media_18_review_ps1.png` | `review.ps1` WMP worker | 3.3 review.ps1 |
| 19 | `media_19_xampp.png` | `C:\xampp` listing | 4.1 XAMPP / MD5 |
| 20 | `media_20_passwords_txt.png` | XAMPP `passwords.txt` | 4.1 XAMPP / MD5 |
| 21 | `media_21_index_php.png` | Upload / MD5 path logic in source | 4.1 XAMPP / MD5 |
| 22 | `media_22_uploads_dir.png` | Uploads dir + `44b85c98…` folder | 4.1 XAMPP / MD5 |
| 23 | `media_23_md5sum_test.png` | MD5 of `testtesttest@test.com` | 4.1 XAMPP / MD5 |
| 24 | `media_24_mklink_fail.png` | Junction fail (path exists) | 4.2 Junction + webshell |
| 25 | `media_25_mklink_success.png` | Junction `6331bca0…` → htdocs | 4.2 Junction + webshell |
| 26 | `media_26_webshell_php.png` | `webshell.php` one-liner | 4.2 Junction + webshell |
| 27 | `media_27_upload_webshell.png` | Upload webshell as test1/test1 | 4.2 Junction + webshell |
| 28 | `media_28_htdocs_webshell.png` | `webshell.php` in htdocs | 4.2 Junction + webshell |
| 29 | `media_29_webshell_whoami.png` | Browser RCE as LOCAL SERVICE | 4.2 Junction + webshell |
| 30 | `media_30_revshells.png` | revshells.com PowerShell payload | 4.3 SeTcbPrivilege |
| 31 | `media_31_reverse_shell.png` | `nc -lvnp 443` reverse shell | 4.3 SeTcbPrivilege |
| 32 | `media_32_local_service_whoami.png` | `SeTcbPrivilege` on LOCAL SERVICE | 4.3 SeTcbPrivilege |
| 33 | `media_33_download_tcb_tools.png` | Download nc + TcbElevation | 4.3 SeTcbPrivilege |
| 34 | `media_34_tcb_add_admin.png` | Add enox to Administrators | 4.3 SeTcbPrivilege |
| 35 | `media_35_root_flag.png` | Admin groups + `root.txt` | 4.3 SeTcbPrivilege |
