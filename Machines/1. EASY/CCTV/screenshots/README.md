# CCTV — Screenshot index

All images are referenced from `../README.md` as `screenshots/<filename>.png`.

| # | Filename | Capture (command / UI / result) | README section |
|---:|---|---|---|
| 1 | `cctv_01_ping.png` | `ping -c 1 10.129.20.51` output | §1.1 Connectivity Test |
| 2 | `cctv_02_nmap_allports.png` | Full TCP `nmap -p- ...` showing **22** and **80** open | §1.2 Port Scanning |
| 3 | `cctv_03_extractports.png` | `extractPorts allPorts` output (ports **22,80**) | §1.2 Port Scanning |
| 4 | `cctv_04_nmap_targeted_1.png` | `nmap -sCV -p22,80` (SSH + HTTP headers/scripts, first screenful) | §1.3 Targeted Scan |
| 5 | `cctv_05_nmap_targeted_2.png` | `cat targeted` continuation if split across terminals | §1.3 Targeted Scan |
| 6 | `cctv_06_hosts_cctv.png` | `/etc/hosts` line or `tee` showing `cctv.htb` mapping | §1.3 Targeted Scan |
| 7 | `cctv_07_whatweb_cctv.png` | `whatweb http://cctv.htb/` output | §2.1 `cctv.htb` Enumeration |
| 8 | `cctv_08_securevision_landing.png` | Browser: SecureVision homepage + **Staff Login** | §2.1 `cctv.htb` Enumeration |
| 9 | `cctv_09_zoneminder_console.png` | Browser: ZoneMinder console showing **v1.37.63** + logged-in context | §2.2 ZoneMinder discovery |
| 10 | `cctv_10_sqlmap_zm_users.png` | `sqlmap` showing **`tid`** injectable + `zm.Users` dump / key rows | §3.1 SQLi → `zm.Users` |
| 11 | `cctv_11_hashcat_mark.png` | `hashcat` **Cracked** line for `mark` bcrypt | §3.2 Hash cracking + SSH |
| 12 | `cctv_12_ssh_mark.png` | SSH session: `whoami` → `mark`, host `cctv` | §3.2 Hash cracking + SSH |
| 13 | `cctv_13_mark_id_sudo.png` | `sudo -l`, `id`, `groups` (no sudo) | §4.1 Localhost stack enum |
| 14 | `cctv_14_ip_a_bridges.png` | `ip a` showing **docker bridges / veth** | §4.1 Localhost stack enum |
| 15 | `cctv_15_ss_lntp.png` | `ss -lntp` listener table (localhost ports) | §4.1 Localhost stack enum |
| 16 | `cctv_16_curl_localhost_services.png` | `curl` loop headers for **8765/8888/9081/7999** | §4.1 Localhost stack enum |
| 17 | `cctv_17_motion_webcontrol_status.png` | `curl` body: **Motion 4.7.1** status on **7999** | §4.1 Localhost stack enum |
| 18 | `cctv_18_motioneye_conf_listen.png` | `motioneye.conf`: **`listen 127.0.0.1`**, **`port 8765`**, **`http_basic_auth false`** | §4.1 Localhost stack enum |
| 19 | `cctv_19_motioneye_motion_conf.png` | `motion.conf`: **`@admin_username`** / **`@admin_password`** lines | §4.1 Localhost stack enum |
| 20 | `cctv_20_ssh_tunnel_motioneye.png` | Attacker terminal: **`ssh -N -L 8766:127.0.0.1:8765 mark@10.129.20.51`** (verbose ok) | §4.2 Port-forward + RCE |
| 21 | `cctv_21_msf_motioneye_check.png` | Metasploit: **`check`** vulnerable + **0.43.1b4** | §4.2 Port-forward + RCE |
| 22 | `cctv_22_msf_meterpreter_root.png` | Metasploit: session opened + `whoami` → **root** | §4.2 Port-forward + RCE |
| 23 | `cctv_23_user_flag.png` | `cat /home/sa_mark/user.txt` | §4.2 Port-forward + RCE |
| 24 | `cctv_24_root_flag.png` | `cat /root/root.txt` | §4.2 Port-forward + RCE |

## Optional evidence (notes mention; not required for template validation)

| Filename (suggested) | Capture | Notes |
|---|---|---|
| `cctv_optional_zm_login_page.png` | Browser: ZoneMinder login (`ZM - Login`) | Supports the **`ZMSESSID` pre-login vs browser session** lesson |
| `cctv_optional_sqlmap_401.png` | `sqlmap` **401 Unauthorized** with wrong cookie | Contrasts failed vs successful authenticated run |
