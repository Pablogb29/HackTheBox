# Snoopy — Screenshots Index

| # | Filename | Captures | Used in |
|---:|---|---|---|
| 01 | `snoopy_01_ping.png` | ICMP connectivity to `10.129.229.5` | 1.1 Connectivity Test |
| 02 | `snoopy_02_nmap_allports.png` | Full TCP SYN scan — ports 22, 53, 80 | 1.2 Port Scanning |
| 03 | `snoopy_03_extractports.png` | `extractPorts` output | 1.2 Port Scanning |
| 04 | `snoopy_04_nmap_targeted.png` | Targeted `-sCV` scan (OpenSSH, BIND, nginx) | 1.3 Targeted Scan |
| 05 | `snoopy_05_whatweb.png` | `whatweb` fingerprint + `info@snoopy.htb` | 2.1 Web Application Enumeration |
| 06 | `snoopy_06_website_home.png` | SnoopySec homepage with download links | 2.1 Web Application Enumeration |
| 07 | `snoopy_07_announcement_pdf_p1.png` | Announcement PDF page 1 (Charles Schultz) | 2.1 Web Application Enumeration |
| 08 | `snoopy_08_announcement_pdf_p2.png` | Announcement PDF page 2 (`pr@snoopy.htb`) | 2.1 Web Application Enumeration |
| 09 | `snoopy_09_team_page.png` | Team page emails | 2.1 Web Application Enumeration |
| 10 | `snoopy_10_contact_mail_banner.png` | Contact form PHP error + mail.snoopy.htb banner | 2.1 Web Application Enumeration |
| 11 | `snoopy_11_mail_vhost.png` | `mail.snoopy.htb` same site | 2.1 Web Application Enumeration |
| 12 | `snoopy_12_dig_axfr.png` | Successful AXFR for `snoopy.htb` | 2.2 DNS Zone Transfer |
| 13 | `snoopy_13_hosts_file.png` | `/etc/hosts` mappings | 2.2 DNS Zone Transfer |
| 14 | `snoopy_14_mm_landing.png` | Mattermost landing at `mm.snoopy.htb` | 2.2 DNS Zone Transfer |
| 15 | `snoopy_15_mm_login.png` | Mattermost login | 2.2 DNS Zone Transfer |
| 16 | `snoopy_16_mm_access_problem.png` | Workspace access restriction | 2.2 DNS Zone Transfer |
| 17 | `snoopy_17_mm_reset_password.png` | Password reset form | 2.2 DNS Zone Transfer |
| 18 | `snoopy_18_mm_reset_failed.png` | Reset fails while mail offline | 2.2 DNS Zone Transfer |
| 19 | `snoopy_19_burp_download.png` | `/download?file=announcement.pdf` → ZIP | 2.3 Path Traversal |
| 20 | `snoopy_20_burp_index.png` | Burp request to `/index.html` | 2.3 Path Traversal |
| 21 | `snoopy_21_burp_test_404.png` | `/test` nginx 404 | 2.3 Path Traversal |
| 22 | `snoopy_22_burp_test_php.png` | `/test.php` File not found | 2.3 Path Traversal |
| 23 | `snoopy_23_lfi_abs_fail.png` | Absolute `/etc/passwd` → empty ZIP | 2.3 Path Traversal |
| 24 | `snoopy_24_lfi_dotdot_fail.png` | Standard `../` → empty ZIP | 2.3 Path Traversal |
| 25 | `snoopy_25_lfi_bypass_passwd.png` | `....//` bypass succeeds | 2.3 Path Traversal |
| 26 | `snoopy_26_passwd_users.png` | Unzipped `/etc/passwd` bash users | 2.3 Path Traversal |
| 27 | `snoopy_27_lfi_named_conf_local.png` | Download `named.conf.local` | 2.4 BIND Config |
| 28 | `snoopy_28_named_conf_local.png` | Zone allows update with `rndc-key` | 2.4 BIND Config |
| 29 | `snoopy_29_lfi_named_conf.png` | Download `named.conf` | 2.4 BIND Config |
| 30 | `snoopy_30_rndc_key.png` | Extracted `rndc-key` secret | 2.4 BIND Config |
| 31 | `snoopy_31_nsupdate_mail.png` | `nsupdate` + AXFR with attacker A record | 3.1 Dynamic DNS Update |
| 32 | `snoopy_32_smtp_intercept.png` | aiosmtpd catches Mattermost reset mail | 3.1 Dynamic DNS Update |
| 33 | `snoopy_33_reset_token_page.png` | Reset-complete page with token | 3.1 Dynamic DNS Update |
| 34 | `snoopy_34_invalid_token.png` | Invalid token when `3D` left in URL | 3.1 Dynamic DNS Update |
| 35 | `snoopy_35_password_updated.png` | Password updated successfully | 3.1 Dynamic DNS Update |
| 36 | `snoopy_36_mattermost_town_square.png` | Town Square chat (ClamAV / IPA hints) | 3.2 Mattermost |
| 37 | `snoopy_37_mattermost_about.png` | Mattermost 7.9.0 about dialog | 3.2 Mattermost |
| 38 | `snoopy_38_find_channels.png` | Find Channels → Server Provisioning | 3.2 Mattermost |
| 39 | `snoopy_39_server_provisioning.png` | `/server_provision` welcome | 3.2 Mattermost |
| 40 | `snoopy_40_provision_form.png` | Server provisioning request form | 3.2 Mattermost |
| 41 | `snoopy_41_nc_paramiko_callback.png` | Outbound Paramiko SSH to port 2222 | 3.2 Mattermost |
| 42 | `snoopy_42_cbrown_dm.png` | DM from `cbrown` | 3.2 Mattermost |
| 43 | `snoopy_43_ssh_mitm_creds.png` | `ssh-mitm` captures `cbrown` password | 3.3 Credential Capture |
| 44 | `snoopy_44_ssh_cbrown.png` | SSH session as `cbrown` | 3.3 Credential Capture |
| 45 | `snoopy_45_cbrown_enum.png` | Home dirs, groups, Docker interfaces | 4.1 Lateral Movement |
| 46 | `snoopy_46_sudo_git_apply.png` | `sudo -l` git apply rule | 4.1 Lateral Movement |
| 47 | `snoopy_47_ssh_keygen_sbrown.png` | Generate ed25519 key for `sbrown` | 4.1 Lateral Movement |
| 48 | `snoopy_48_git_symlink_repo.png` | Repo with symlink to `/home/sbrown/.ssh` | 4.1 Lateral Movement |
| 49 | `snoopy_49_git_patch.png` | Patch renaming symlink + authorized_keys | 4.1 Lateral Movement |
| 50 | `snoopy_50_git_apply_success.png` | `sudo -u sbrown git apply -v patch` | 4.1 Lateral Movement |
| 51 | `snoopy_51_user_flag.png` | SSH as `sbrown` + `user.txt` | 4.1 Lateral Movement |
| 52 | `snoopy_52_sudo_clamscan.png` | `sudo -l` clamscan rule | 4.2 Root |
| 53 | `snoopy_53_clamscan_version.png` | ClamAV 1.0.0 | 4.2 Root |
| 54 | `snoopy_54_cve_2023_20052_build.png` | Build malicious DMG for XXE | 4.2 Root |
| 55 | `snoopy_55_scp_exploit_dmg.png` | Upload `exploit.dmg` to `scanfiles` | 4.2 Root |
| 56 | `snoopy_56_clamscan_debug.png` | `sudo clamscan --debug` start | 4.2 Root |
| 57 | `snoopy_57_root_key_leak.png` | Root SSH key leaked in debug output | 4.2 Root |
| 58 | `snoopy_58_root_flag.png` | SSH as root + `root.txt` | 4.2 Root |
