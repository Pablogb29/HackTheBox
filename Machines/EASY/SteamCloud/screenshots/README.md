## SteamCloud screenshots index

> This folder contains evidence screenshots referenced by `../README.md`.
>
> **Note:** You currently have screenshots named like `Pasted image 20260511....png` in the repo root. I have **not** renamed or moved them. See the checklist at the end of the chat for the exact rename/move mapping to this folder.

| # | Filename (expected) | Captures | Used in README section |
|---:|---|---|---|
| 01 | `steamcloud_01_ping.png` | `ping -c 1 10.129.96.167` output | 1.1 Connectivity Test |
| 02 | `steamcloud_02_nmap_allports.png` | `nmap -p- … -oG allPorts` open ports | 1.2 Port Scanning |
| 03 | `steamcloud_03_extractports.png` | `extractPorts allPorts` output | 1.2 Port Scanning |
| 04 | `steamcloud_04_nmap_targeted.png` | `nmap -sCV … -oN targeted` summary | 1.3 Targeted Scan |
| 05 | `steamcloud_05_targeted_full_output.png` | `cat targeted` (full-ish) output | 1.3 Targeted Scan |
| 06 | `steamcloud_06_k8s_api_forbidden_and_version.png` | `curl` API forbidden + `/version` JSON | 2.1 Kubernetes API |
| 07 | `steamcloud_07_kubeletctl_pods.png` | `kubeletctl … pods` list | 2.2 Kubelet Enumeration |
| 08 | `steamcloud_08_kubeletctl_scan_rce.png` | `kubeletctl … scan rce` table | 2.2 Kubelet Enumeration |
| 09 | `steamcloud_09_kubeletctl_exec_nginx.png` | `kubeletctl exec …` into `nginx` | 3.1 Exec into `nginx` |
| 10 | `steamcloud_10_user_flag.png` | `cat user.txt` output | 3.1 Exec into `nginx` |
| 11 | `steamcloud_11_serviceaccount_dump.png` | Listing serviceaccount secrets dir | 3.2 Extract token + CA |
| 12 | `steamcloud_12_token_and_ca_files.png` | `cat ca.crt` and `cat token` | 3.2 Extract token + CA |
| 13 | `steamcloud_13_kubectl_get_pods.png` | `kubectl … get pods` works | 3.2 Extract token + CA |
| 14 | `steamcloud_14_kubectl_auth_can_i_list.png` | `kubectl auth can-i --list` perms | 3.2 Extract token + CA |
| 15 | `steamcloud_15_kubectl_get_pod_nginx_yaml.png` | `kubectl get pod nginx -o yaml` | 3.2 Extract token + CA |
| 16 | `steamcloud_16_evil_yaml.png` | `evil.yaml` content shown | 4.1 Create hostPath pod |
| 17 | `steamcloud_17_kubectl_apply_evil_pod.png` | `kubectl apply -f evil.yaml` created | 4.1 Create hostPath pod |
| 18 | `steamcloud_18_evil_pod_visible_and_rce.png` | `kubeletctl pods` + `scan rce` includes `evil-pod` | 4.1 Create hostPath pod |
| 19 | `steamcloud_19_root_flag.png` | `cat root.txt` output | 4.2 Root access |

