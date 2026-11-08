# Screenshots index — Teacher

Paths are relative to `cases/HackTheBox/EASY/Teacher/README.md` (difficulty is **Medium**; case folder follows repo layout under `EASY/`).

**Populated:** `Pasted image …png` files from the Ohara vault root were moved here as `teacher_XX_*.png` (see `move-teacher-screenshots.ps1`). To import from another folder, use `copy-screenshots.ps1 -SourceFolder …`.

| # | Filename | Captured from `notes/ctf/htb-teacher.md` (order of appearance) |
|---:|---|---|
| 01 | `teacher_01_ping.png` | `ping` |
| 02 | `teacher_02_nmap_allports_01.png` | Full TCP `nmap` (part 1) |
| 03 | `teacher_03_nmap_allports_02.png` | Full TCP `nmap` (part 2) |
| 04 | `teacher_04_nmap_targeted.png` | `nmap -sCV -p80` + `cat targeted` |
| 05 | `teacher_05_whatweb.png` | `whatweb` |
| 06 | `teacher_06_http_enum.png` | `nmap --script http-enum` |
| 07 | `teacher_07_web_directory_listing_01.png` | Web / directory listing context |
| 08 | `teacher_08_web_directory_listing_02.png` | Web / directory listing context |
| 09 | `teacher_09_images_5png_plaintext.png` | `wget` / `file` / `cat` `5.png` |
| 10 | `teacher_10_wfuzz_content_discovery.png` | `wfuzz` directories |
| 11 | `teacher_11_wfuzz_moodle_login_01.png` | `crunch` + `wfuzz` Moodle login |
| 12 | `teacher_12_wfuzz_moodle_login_02.png` | `wfuzz` hit `Th4C00lTheacha#` |
| 13 | `teacher_13_moodle_authenticated.png` | Moodle session / course view |
| 14 | `teacher_14_moodle_quiz_add_activity.png` | Add Quiz activity |
| 15 | `teacher_15_moodle_calculated_question_payload.png` | Calculated question formula |
| 16 | `teacher_16_moodle_rce_ping_tcpdump_01.png` | RCE ping + `tcpdump` (setup) |
| 17 | `teacher_17_moodle_rce_ping_tcpdump_02.png` | RCE ping + `tcpdump` (ICMP seen) |
| 18 | `teacher_18_reverse_shell_url.png` | Reverse shell in URL `&0=bash...` |
| 19 | `teacher_19_reverse_shell_netcat.png` | `nc` catch + `www-data` |
| 20 | `teacher_20_config_php.png` | `cat config.php` |
| 21 | `teacher_21_mysql_login.png` | `mysql -uroot -p` |
| 22 | `teacher_22_mysql_show_databases.png` | `show databases;` |
| 23 | `teacher_23_mysql_use_moodle.png` | `use moodle` / context |
| 24 | `teacher_24_mdl_user_hashes.png` | `select username,password from mdl_user` |
| 25 | `teacher_25_crackstation_giovannibak.png` | CrackStation MD5 → `expelled` |
| 26 | `teacher_26_user_flag_su_giovanni.png` | `su giovanni` + `user.txt` |
| 27 | `teacher_27_pspy_wget.png` | Host `pspy64` + target `wget` |
| 28 | `teacher_28_pspy_backup_sh_cron.png` | `pspy` shows `backup.sh` / `tar` / `chmod` |
| 29 | `teacher_29_backup_sh_symlink.png` | Symlink + world-writable `backup.sh` |
| 30 | `teacher_30_suid_bash_root.png` | SUID `/bin/bash`, `bash -p`, `root` |
| 31 | `teacher_31_root_flag.png` | `root.txt` |

### Source filename mapping (Obsidian)

| Pasted image (source) | Renamed to |
|---|---|
| `Pasted image 20260408170328.png` | `teacher_01_ping.png` |
| `Pasted image 20260408170337.png` | `teacher_02_nmap_allports_01.png` |
| `Pasted image 20260408170349.png` | `teacher_03_nmap_allports_02.png` |
| `Pasted image 20260408170402.png` | `teacher_04_nmap_targeted.png` |
| `Pasted image 20260408170422.png` | `teacher_05_whatweb.png` |
| `Pasted image 20260408190505.png` | `teacher_06_http_enum.png` |
| `Pasted image 20260408190553.png` | `teacher_07_web_directory_listing_01.png` |
| `Pasted image 20260408190537.png` | `teacher_08_web_directory_listing_02.png` |
| `Pasted image 20260408190443.png` | `teacher_09_images_5png_plaintext.png` |
| `Pasted image 20260408190618.png` | `teacher_10_wfuzz_content_discovery.png` |
| `Pasted image 20260408174823.png` | `teacher_11_wfuzz_moodle_login_01.png` |
| `Pasted image 20260408174805.png` | `teacher_12_wfuzz_moodle_login_02.png` |
| `Pasted image 20260408190644.png` | `teacher_13_moodle_authenticated.png` |
| `Pasted image 20260408204611.png` | `teacher_14_moodle_quiz_add_activity.png` |
| `Pasted image 20260408204620.png` | `teacher_15_moodle_calculated_question_payload.png` |
| `Pasted image 20260408204627.png` | `teacher_16_moodle_rce_ping_tcpdump_01.png` |
| `Pasted image 20260408204633.png` | `teacher_17_moodle_rce_ping_tcpdump_02.png` |
| `Pasted image 20260408204648.png` | `teacher_18_reverse_shell_url.png` |
| `Pasted image 20260408204655.png` | `teacher_19_reverse_shell_netcat.png` |
| `Pasted image 20260408204828.png` | `teacher_20_config_php.png` |
| `Pasted image 20260408204856.png` | `teacher_21_mysql_login.png` |
| `Pasted image 20260408204927.png` | `teacher_22_mysql_show_databases.png` |
| `Pasted image 20260408204942.png` | `teacher_23_mysql_use_moodle.png` |
| `Pasted image 20260408205004.png` | `teacher_24_mdl_user_hashes.png` |
| `Pasted image 20260408205017.png` | `teacher_25_crackstation_giovannibak.png` |
| `Pasted image 20260408205024.png` | `teacher_26_user_flag_su_giovanni.png` |
| `Pasted image 20260408205038.png` | `teacher_27_pspy_wget.png` |
| `Pasted image 20260408205111.png` | `teacher_28_pspy_backup_sh_cron.png` |
| `Pasted image 20260408205203.png` | `teacher_29_backup_sh_symlink.png` |
| `Pasted image 20260408205238.png` | `teacher_30_suid_bash_root.png` |
| `Pasted image 20260408205351.png` | `teacher_31_root_flag.png` |
