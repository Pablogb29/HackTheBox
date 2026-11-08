# Craft screenshots index

| # | Filename | Captures | Used in |
|---:|---|---|---|
| 01 | `craft_01_ping.png` | `ping -c 1` (previous IP `10.129.65.222`) | `1.1 Connectivity Test` |
| 02 | `craft_02_nmap_allports.png` | Full TCP nmap → `22,443,6022` | `1.2 Port Scanning` |
| 03 | `craft_03_extractports.png` | `extractPorts allPorts` | `1.2 Port Scanning` |
| 04 | `craft_04_nmap_targeted.png` | `nmap -sCV -p22,443,6022` + `craft.htb` cert | `1.3 Targeted Scan` |
| 05 | `craft_05_craft_about.png` | HTTPS About page + API/Git links | `2.1 HTTPS / Craft landing page` |
| 06 | `craft_06_gogs_about.png` | Gogs version (`0.11.86.0130`) | `2.2 Gogs enumeration` |
| 07 | `craft_07_gogs_explore_repo.png` | Explore → `Craft/craft-api` | `2.2 Gogs enumeration` |
| 08 | `craft_08_gogs_users.png` | Gogs users list | `2.2 Gogs enumeration` |
| 09 | `craft_09_craft_api_files.png` | Repo file tree | `2.2 Gogs enumeration` |
| 10 | `craft_10_gogs_issue_token.png` | Issue with expired API JWT + brew curl | `2.2 Gogs enumeration` |
| 11 | `craft_11_api_swagger.png` | Swagger UI at `api.craft.htb/api/` | `2.3 API Swagger surface` |
| 12 | `craft_12_download_craft_api.png` | Unzip `craft-api-master.zip` | `2.4 Source download and commit history` |
| 13 | `craft_13_commits_history.png` | Commit history (ABV fix / test script) | `2.4 Source download and commit history` |
| 14 | `craft_14_commit_test_creds.png` | `tests/test.py` commit with `dinesh` creds | `2.4 Source download and commit history` |
| 15 | `craft_15_gogs_dinesh_login.png` | Gogs profile logged in as `dinesh` | `2.4 Source download and commit history` |
| 16 | `craft_16_jwt_decode.png` | Base64 decode of issue JWT header/payload | `2.2 Gogs enumeration` |
| 17 | `craft_17_jwt_expired.png` | Epoch `1549385242` → 2019-02-05 | `2.2 Gogs enumeration` |
| 18 | `craft_18_test_py.png` | Local `cat tests/test.py` | `2.4 Source download and commit history` |
| 19 | `craft_19_api_login_check.png` | `/api/auth/login` + `/api/auth/check` | `3.1 Fresh API token` |
| 20 | `craft_20_grep_eval_abv.png` | `grep` finds `eval('%s > 1' % …)` | `3.2 ABV eval injection` |
| 21 | `craft_21_brew_baseline.png` | `abv=0.15` OK / `abv=15.0` rejected | `3.2 ABV eval injection` |
| 22 | `craft_22_abv_rce_shell.png` | Reverse shell via `abv` payload (container) | `3.2 ABV eval injection` |
| 23 | `craft_23_dbtest_dockerenv.png` | `/.dockerenv` + `dbtest.py` | `3.3 Container → MySQL user dump` |
| 24 | `craft_24_settings_mysql.png` | `craft_api/settings.py` MySQL creds | `3.3 Container → MySQL user dump` |
| 25 | `craft_25_mysql_dump_users.png` | `SELECT * FROM user` dump | `3.3 Container → MySQL user dump` |
| 26 | `craft_26_gogs_gilfoyle.png` | Gogs as `gilfoyle` + private `craft-infra` | `4.1 Gogs as Gilfoyle` |
| 27 | `craft_27_craft_infra_repo.png` | `craft-infra` tree (`.ssh`, vault, …) | `4.1 Gogs as Gilfoyle` |
| 28 | `craft_28_infra_ssh_keys.png` | Unzip + `.ssh/id_rsa` | `4.1 Gogs as Gilfoyle` |
| 29 | `craft_29_ssh_gilfoyle_userflag.png` | SSH as `gilfoyle` + `user.txt` | `4.2 SSH as gilfoyle` |
| 30 | `craft_30_vault_token.png` | `cat .vault-token` | `4.3 Vault root token` |
| 31 | `craft_31_vault_token_lookup.png` | `vault token lookup` → root policy | `4.3 Vault root token` |
| 32 | `craft_32_vault_ssh_role.png` | `ssh/roles/root_otp` | `4.3 Vault root token` |
| 33 | `craft_33_root_otp_flag.png` | `vault ssh` OTP → `root` + `root.txt` | `4.3 Vault root token` |
