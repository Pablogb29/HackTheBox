# DevHub — Screenshot index

Evidence for [`../README.md`](../README.md). Filenames follow `devhub_NN_<desc>.png`.

| # | Filename | Captures | README section |
|---|----------|----------|----------------|
| 01 | `devhub_01_ping.png` | `ping -c 1 10.129.8.143` | §1.1 Connectivity Test |
| 02 | `devhub_02_nmap_allports.png` | Full TCP SYN scan (`-p-`), ports 22/80/6274 | §1.2 Port Scanning |
| 03 | `devhub_03_extractports.png` | `extractPorts allPorts` → 22, 80, 6274 | §1.2 Port Scanning |
| 04 | `devhub_04_nmap_targeted_1.png` | `nmap -sCV -p22,80,6274` (scan output) | §1.3 Targeted Scan |
| 05 | `devhub_05_nmap_targeted_2.png` | `bat targeted` (MCPJam fingerprint, vhost redirect) | §1.3 Targeted Scan |
| 06 | `devhub_06_hosts_whatweb.png` | `/etc/hosts` + `whatweb http://devhub.htb` | §2.1 DevHub web |
| 07 | `devhub_07_devhub_landing.png` | DevHub portal (MCP 6274, Jupyter 8888 hints) | §2.1 DevHub web |
| 08 | `devhub_08_mcpjam_inspector.png` | MCPJam Inspector v1.4.2 settings UI | §2.2 MCPJam |
| 09 | `devhub_09_mcpjam_rce_shell.png` | `python3 exploit.py` + `nc` → `mcp-dev` | §3.1 Foothold |
| 10 | `devhub_10_mcpdev_local_services.png` | `ss -tlnp` + `ps aux` (8888, 5000, Jupyter token) | §4.1 Lateral |
| 11 | `devhub_11_jupyter_login.png` | Jupyter login at `127.0.0.1:8888` (via tunnel) | §4.1 Lateral |
| 12 | `devhub_12_jupyter_lab.png` | JupyterLab launcher | §4.1 Lateral |
| 13 | `devhub_13_user_flag.png` | `cat /home/analyst/user.txt` in Jupyter terminal | §4.1 Lateral |
| 14 | `devhub_14_analyst_shell_enum.png` | `analyst` revshell: `whoami`, `user.txt`, `id`, `ip a` | §4.2 OPSMCP (initial enum) |
| 15 | `devhub_15_analyst_revshell.png` | User flag + bash revshell to Kali `nc` | §4.1 Lateral |
| 16 | `devhub_16_opsmcp_server_py.png` | `tail` of `/opt/opsmcp/server.py` (hidden tools) | §4.2 OPSMCP |
| 17 | `devhub_17_opsmcp_ssh_key_dump.png` | `ops._admin_dump` → `/tmp/root_id_rsa` | §4.3 Root |
| 18 | `devhub_18_root_flag.png` | `ssh -i root_id_rsa root@...` + `cat root.txt` | §4.3 Root |

## Source mapping

| Original file | Renamed to |
|---------------|------------|
| Pasted image 20260602181940.png | 01 |
| Pasted image 20260602181958.png | 02 |
| Pasted image 20260602182008.png | 03 |
| Pasted image 20260602182352.png | 04 |
| Pasted image 20260602182540.png | 05 |
| Pasted image 20260602182554.png | 06 |
| Pasted image 20260602182636.png | 07 |
| Pasted image 20260602182620.png | 08 |
| Pasted image 20260602181927.png | 09 |
| Screenshot 2026-06-02 203046.png | 10 |
| Pasted image 20260602185628.png | 11 |
| Pasted image 20260602185943.png | 12 |
| Pasted image 20260602190033.png | 13 |
| Pasted image 20260602195712.png | 14 |
| Pasted image 20260602190349.png | 15 |
| Pasted image 20260602195543.png | 16 |
| Pasted image 20260602195357.png | 17 |
| Pasted image 20260602195346.png | 18 |
