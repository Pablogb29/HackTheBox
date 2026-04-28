# Screenshots — Trick (`trick`)

All images referenced from `../README.md` use `screenshots/trick_NN_<topic>.png` (01–28). Optional extras keep the `trick_extra_*` prefix.

## Main sequence (28)

| # | Filename | Description | README section |
|---|----------|-------------|------------------|
| 01 | `trick_01_ping.png` | `ping -c 1` to target | §1.1 |
| 02 | `trick_02_nmap_allports.png` | Full TCP SYN scan | §1.2 |
| 03 | `trick_03_extractports.png` | `extractPorts` output | §1.2 |
| 04 | `trick_04_nmap_targeted_1.png` | `nmap -sCV` (part 1) | §1.3 |
| 05 | `trick_05_nmap_targeted_2.png` | `nmap -sCV` (part 2) | §1.3 |
| 06 | `trick_06_whatweb.png` | `whatweb` on IP | §2.1 |
| 07 | `trick_07_http_coming_soon.png` | Default “Coming Soon” page | §2.1 |
| 08 | `trick_08_dig_reverse.png` | `dig -x` PTR | §2.2 |
| 09 | `trick_09_dig_axfr.png` | `dig axfr trick.htb` | §2.2 |
| 10 | `trick_10_dig_version_bind.png` | `version.bind` CHAOS TXT | §2.2 |
| 11 | `trick_11_payroll_login.png` | Payroll login page | §2.3 |
| 12 | `trick_12_payroll_admin_home.png` | Post–SQLi admin UI | §2.4 |
| 13 | `trick_13_php_filter_home_browser.png` | Browser: Base64 from `php://filter` (`home`) | §2.5 |
| 14 | `trick_14_php_filter_home_decoded.png` | Terminal: decoded `home` PHP | §2.5 |
| 15 | `trick_15_php_filter_db_connect_browser.png` | Browser: Base64 from `php://filter` (`db_connect`) | §2.5 |
| 16 | `trick_16_php_filter_db_connect_decoded.png` | Terminal: decoded `db_connect` / creds | §2.5 |
| 17 | `trick_17_wfuzz_marketing.png` | `wfuzz` vhost discovery | §2.6 |
| 18 | `trick_18_marketing_site_home.png` | Marketing template, `?page=…` | §2.6 |
| 19 | `trick_19_lfi_etc_passwd.png` | LFI → `/etc/passwd` | §2.7 |
| 20 | `trick_20_lfi_id_rsa.png` | Local `cat id_rsa` after LFI | §2.8 |
| 21 | `trick_21_ssh_michael.png` | SSH as `michael` | §2.8 |
| 22 | `trick_22_user_flag.png` | `user.txt` | §3.1 |
| 23 | `trick_23_fail2ban_nano_iptables.png` | `nano` / `sudo -l` context for action file | §4.1 |
| 24 | `trick_24_fail2ban_actionban_config.png` | `actionban` / `actionunban` lines | §4.1 |
| 25 | `trick_25_fail2ban_restart_bash_ls.png` | After restart: `ls -la /bin/bash` | §4.1 |
| 26 | `trick_26_failed_ssh_ban_trigger.png` | Failed SSH / ban trigger | §4.1 |
| 27 | `trick_27_suid_bash.png` | SUID bit on `/bin/bash` | §4.1 |
| 28 | `trick_28_root_proof.png` | `bash -p` / root flag | §4.2 |

## Optional extras (not in main README)

| Filename | Note |
|----------|------|
| `trick_extra_wfuzz_ip_directory.png` | Directory fuzz on raw IP |
| `trick_extra_lfi_passwd_curl.png` | `curl` LFI to `/etc/passwd` |
| `trick_extra_lfi_ssh_host_rsa_key.png` | LFI to host SSH key (not user `id_rsa`) |

**Total primary screenshots:** 28
