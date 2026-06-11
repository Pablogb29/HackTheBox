# Screenshots — HTB Paper (`paper`)

Index of images referenced from `../README.md`. Files were copied from repo-root `Pasted image 20260503*.png` captures and renamed to `paper_NN_<desc>.png` after **content-based** review (filenames describe what each image shows, not paste timestamp order). One duplicate `list sales` capture was dropped; assets are numbered **`paper_01` … `paper_26`** consecutively.

| # | Filename | Command / action captured | README section |
|---|----------|---------------------------|----------------|
| 01 | `paper_01_ping.png` | `ping -c 1 10.129.28.97` | §1.1 Connectivity Test |
| 02 | `paper_02_nmap_allports.png` | Full TCP `nmap -p- ...` | §1.2 Port Scanning |
| 03 | `paper_03_extractports.png` | `extractPorts allPorts` | §1.2 Port Scanning |
| 04 | `paper_04_nmap_sCV.png` | `nmap -sCV -p22,80,443 ...` | §1.3 Targeted Scan |
| 05 | `paper_05_cat_targeted.png` | `cat targeted` / scan output | §1.3 Targeted Scan |
| 06 | `paper_06_whatweb.png` | `whatweb http://10.129.28.97/` | §2.1 Web fingerprinting |
| 07 | `paper_07_ffuf.png` | `ffuf` against bare IP | §2.1 Web fingerprinting |
| 08 | `paper_08_browser_default_ip.png` | Browser: default page on IP | §2.1 Web fingerprinting |
| 09 | `paper_09_curl_headers.png` | `curl -sI` against bare IP (`X-Backend-Server`) | §2.1 Web fingerprinting |
| 10 | `paper_10_hosts_office_paper.png` | Append `office.paper` to `/etc/hosts` | §2.2 Mapping office.paper |
| 11 | `paper_11_wp_home_office_paper.png` | Browser: WordPress home on `office.paper` | §2.2 WordPress surface |
| 12 | `paper_12_wp_nick_draft_hint.png` | WP post + Nick comment (draft hint) | §2.2 WordPress surface |
| 13 | `paper_13_searchsploit_47690.png` | `searchsploit wordpress 5.2.3` / PoC mirror | §2.3 CVE + draft leak |
| 14 | `paper_14_wp_author_static_leak.png` | Author archive `?static=1` draft leak | §2.3 CVE + draft leak |
| 15 | `paper_15_rocketchat_register.png` | Rocket.Chat registration UI | §2.4 Rocket.Chat |
| 16 | `paper_16_rocketchat_home_post_register.png` | Rocket.Chat home after register | §2.4 Rocket.Chat |
| 17 | `paper_17_rocketchat_home_users.png` | Rocket.Chat home / users sidebar | §2.4 Rocket.Chat |
| 18 | `paper_18_recyclops_help.png` | `recyclops` help / intro | §2.4 Rocket.Chat |
| 19 | `paper_19_recyclops_list_sales.png` | `recyclops list` (sales) | §3.1 Foothold |
| 20 | `paper_20_recyclops_path_traversal_home.png` | `recyclops list` path outside sales | §3.1 Foothold |
| 21 | `paper_21_recyclops_file_passwd.png` | `recyclops file` + `/etc/passwd` | §3.1 Foothold |
| 22 | `paper_22_recyclops_hubot_env.png` | `recyclops file` Hubot `.env` | §3.1 Foothold |
| 23 | `paper_23_ssh_user_flag.png` | `ssh dwight@...` + `user.txt` | §3.1–3.2 Foothold / User flag |
| 24 | `paper_24_sudo_not_allowed_version.png` | `sudo -l` denied + `sudo --version` | §4.1 Privilege escalation |
| 25 | `paper_25_polkit_CVE_2021_3560_exploit.png` | `privesc.sh` Polkit CVE-2021-3560 run | §4.1 Privilege escalation |
| 26 | `paper_26_root_flag.png` | `sudo su` + `cat /root/root.txt` | §4.2 Root access |

**Source:** repo root `Pasted image 20260503*.png` → packaged under this folder; semantic rename applied on packaging / review pass.
