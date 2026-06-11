# Nibbles Screenshot Index

| # | Filename | Command / Action Captured | README Section |
|---|---|---|---|
| 01 | `nibbles_01_ping.png` | `ping -c 1 10.129.96.84` result | `1.1 Connectivity Test` |
| 02 | `nibbles_02_nmap_allports.png` | `nmap -p- --open ... -oG allPorts` output | `1.2 Full Port Scan` |
| 03 | `nibbles_03_extractports.png` | `extractPorts allPorts` output (`22,80`) | `1.2 Full Port Scan` |
| 04 | `nibbles_04_nmap_targeted.png` | `nmap -sCV -p22,80 ...` output | `1.3 Targeted Scan` |
| 05 | `nibbles_05_root_hidden_comment.png` | Root page/source showing `/nibbleblog/` HTML comment | `2.1 Root Page and Hidden Path` |
| 06 | `nibbles_06_nibbleblog_curl_1.png` | `curl -i /nibbleblog/` response (part 1) | `2.2 Nibbleblog Discovery and Version` |
| 07 | `nibbles_07_nibbleblog_curl_2.png` | `curl -i /nibbleblog/` response (part 2) | `2.2 Nibbleblog Discovery and Version` |
| 08 | `nibbles_08_nibbleblog_readme_version_1.png` | `curl -i /nibbleblog/README` version output (part 1) | `2.2 Nibbleblog Discovery and Version` |
| 09 | `nibbles_09_nibbleblog_readme_version_2.png` | `curl -i /nibbleblog/README` version output (part 2) | `2.2 Nibbleblog Discovery and Version` |
| 10 | `nibbles_10_ffuf_nibbleblog.png` | `ffuf` results under `/nibbleblog/` | `2.3 Directory and Sensitive File Exposure` |
| 11 | `nibbles_11_private_directory_listing_1.png` | `/nibbleblog/content/private/` listing (terminal) | `2.3 Directory and Sensitive File Exposure` |
| 12 | `nibbles_12_private_directory_listing_2.png` | `/nibbleblog/content/private/` listing (browser) | `2.3 Directory and Sensitive File Exposure` |
| 13 | `nibbles_13_users_xml_admin_1.png` | `users.xml` showing username `admin` (terminal) | `2.3 Directory and Sensitive File Exposure` |
| 14 | `nibbles_14_users_xml_admin_2.png` | `users.xml` showing username `admin` (browser) | `2.3 Directory and Sensitive File Exposure` |
| 15 | `nibbles_15_admin_login.png` | Authenticated admin panel view (first capture) | `3.1 Admin Access to Nibbleblog` |
| 16 | `nibbles_16_admin_login_success.png` | Authenticated admin panel view (second capture) | `3.1 Admin Access to Nibbleblog` |
| 17 | `nibbles_17_my_image.png` | `Plugins -> My image` upload interface | `3.2 RCE via My Image Plugin Upload` |
| 18 | `nibbles_18_php_rce_file.png` | PHP file execution/validation output | `3.2 RCE via My Image Plugin Upload` |
| 19 | `nibbles_19_my_image_file_uploaded.png` | Uploaded file visible in plugin directory listing | `3.2 RCE via My Image Plugin Upload` |
| 20 | `nibbles_20_user_flag.png` | `cat /home/nibbler/user.txt` output | `3.3 Reverse Shell and User Flag` |
| 21 | `nibbles_21_monitor_sh.png` | `sudo -l` and monitor script path context | `4.1 Sudo Rule Discovery` |
| 22 | `nibbles_22_monitor_edited.png` | Edited `monitor.sh` payload before sudo execution | `4.2 Root via Writable NOPASSWD Script` |
| 23 | `nibbles_23_root_flag.png` | `cat /root/root.txt` output | `4.2 Root via Writable NOPASSWD Script` |

