# Screenshots index — Squashed

Paths are relative to `cases/HackTheBox/EASY/Squashed/README.md`.

| Order | Filename | Command / action captured | README section |
|-------|----------|----------------------------|----------------|
| 1 | `squashed_01_ping.png` | `ping -c 1 10.129.11.87` | §1.1 Connectivity Test |
| 2 | `squashed_02_nmap_allports.png` | `nmap -p- --open ...` | §1.2 Port Scanning |
| 3 | `squashed_03_extractports.png` | `extractPorts allPorts` | §1.2 Port Scanning |
| 4 | `squashed_04_nmap_targeted.png` | `nmap -sCV ...` + `cat targeted` | §1.3 Targeted Scan |
| 5 | `squashed_05_whatweb.png` | `whatweb http://10.129.11.87` | §2.1 HTTP fingerprint |
| 6 | `squashed_06_showmount_exports.png` | `showmount -e 10.129.11.87` | §2.2 NFS export listing |
| 7 | `squashed_07_local_mount.png` | `cd /mnt && ls -l` after mounts | §2.3 Mounting exports |
| 8 | `squashed_08_nfs_mount_tree.png` | `tree -fas /mnt/squashed_ross` | §2.3 Mounting exports |
| 9a | `squashed_09_keepassxc.png` | KeePass / `Passwords.kdbx` context on share | §2.3 Mounting exports |
| 9b | `squashed_09_squashed_www_id.png` | Permission denied / UID 2017 on `squashed_www` | §2.3 Mounting exports |
| 10 | `squashed_10_uid2017_docroot_tree.png` | UID 2017 user, `tree` in docroot | §3.1 Impersonating UID 2017 |
| 11 | `squashed_11_test_txt.png` | Browser or proof of `test.txt` | §3.1 Write proof |
| 12 | `squashed_12_cmdphp_whoami.png` | `cmd.php?cmd=whoami` → `alex` | §3.1 PHP webshell |
| 13 | `squashed_13_reverse_shell_netcat.png` | `nc` listener + reverse shell | §3.2 Reverse shell |
| 14a | `squashed_14_user_flag.png` | `cat /home/alex/user.txt` | §3.2 User flag |
| 14b | `squashed_14_w_ross_tty7.png` | `w` — `ross` on `tty7` `:0` | §4.1 Active session |
| 14c | `squashed_14_newuser_xauth.png` | UID 1001 user, `.Xauthority` / `xxd` | §4.1 Cookie prep |
| 16 | `squashed_16_xdpyinfo_success.png` | `xdpyinfo` after env fix | §4.1 X11 verify |
| 17 | `squashed_17_xwininfo_keepassxc.png` | `xwininfo -root -tree` | §4.1 Window tree |
| 18 | `squashed_18_xwd_exfil_convert.png` | `xwd` / `nc` exfil pipeline | §4.2 Screenshot exfil |
| 19 | `squashed_19_keepassxc_root_entry.png` | Converted PNG — KeePassXC entry | §4.2 KeePassXC |
| 20 | `squashed_20_keepassxc_try_password.png` | Optional unlock / UI context | §4.2 KeePassXC |
| 21 | `squashed_21_su_root_root_txt.png` | `su root`, `cat /root/root.txt` | §4.3 Root flag |

**Total:** 21 image references in `README.md` (some share the `14` prefix in filenames by design).
