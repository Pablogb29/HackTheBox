# Screenshots — HTB Authority

| # | Filename | Command / Action Captured | README Section |
|---|----------|--------------------------|----------------|
| 01 | authority_01_ping.png | `ping -c 1 10.129.229.56` | 1.1 Connectivity Test |
| 02 | authority_02_nmap_allports.png | `nmap -p- --open -sS ...` | 1.2 Port Scanning |
| 03 | authority_03_extractports.png | `extractPorts allPorts` | 1.2 Port Scanning |
| 04 | authority_04_nmap_targeted_1.png | `nmap -sCV -p<ports> ...` (raw output) | 1.3 Targeted Scan |
| 05 | authority_05_nmap_targeted_2.png | `cat targeted` (colored output) | 1.3 Targeted Scan |
| 06 | authority_06_smb_shares.png | `smbclient -L //10.129.229.56 -N` | 2.1 SMB Enumeration |
| 07 | authority_07_smb_development.png | `smbclient ... -c 'recurse ON; ls'` | 2.1 SMB Enumeration |
| 08 | authority_08_ansible_tree.png | `tree` (Ansible roles structure) | 2.2 Ansible Playbook Analysis |
| 09 | authority_09_vault_secrets.png | `cat PWM/defaults/main.yml` + `tomcat-users.xml.j2` | 2.2 Ansible Playbook Analysis |
| 10 | authority_10_hashcat.png | `hashcat -m 16900 vault_hashes ...` | 2.3 Cracking Ansible Vault Secrets |
| 11 | authority_11_vault_decrypt.png | `ansible-vault decrypt` (all 3 vaults) | 2.3 Cracking Ansible Vault Secrets |
| 12 | authority_12_pwm_login.png | PWM login page (`/pwm/private/login`) | 2.4 PWM Web Application |
| 13 | authority_13_pwm_error.png | PWM Error 5017 (LDAP bind DN leaked) | 2.4 PWM Web Application |
| 14 | authority_14_pwm_config_manager.png | PWM Configuration Manager page | 2.4 PWM Web Application |
| 15 | authority_15_pwm_config_editor.png | PWM Configuration Editor page | 2.4 PWM Web Application |
| 16 | authority_16_ldap_connection.png | LDAP connection settings + attacker URL added | 3.1 LDAP Credential Capture |
| 17 | authority_17_ldap_capture.png | `nc -lvnp 389` + LDAP test = cleartext creds | 3.1 LDAP Credential Capture |
| 18 | authority_18_user_flag.png | `evil-winrm` + `type user.txt` | 3.2 WinRM Access |
| 19 | authority_19_root_flag.png | `impacket-psexec` + `type root.txt` | 4.2 Certificate Abuse and Domain Takeover |
| 20 | authority_20_certipy_enum.png | `certipy-ad find ... -vulnerable` | 4.1 AD CS Enumeration (ESC1) |
| 21 | authority_21_addcomputer_certreq.png | `impacket-addcomputer` + `certipy-ad req` | 4.2 Certificate Abuse and Domain Takeover |
| 22 | authority_22_openssl_extract.png | `openssl pkcs12` key/cert extraction | 4.2 Certificate Abuse and Domain Takeover |
| 23 | authority_23_getst_impersonate.png | `ntpdate` + `impacket-getST` S4U2Proxy | 4.2 Certificate Abuse and Domain Takeover |
