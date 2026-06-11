---
title: "HTB - Paper"
author: "M0k4"
date: "2026-05-03"
tags: ["htb", "writeup", "linux", "easy", "wordpress", "rocketchat", "polkit", "cve-2019-17671", "cve-2021-3560"]
---

# HTB - Paper

**IP Address:** `10.129.28.97`  
**OS:** Linux (CentOS-flavored Apache stack; OpenSSH 8.0)  
**Difficulty:** Easy  
**Tags:** #htb #linux #wordpress #rocketchat #hubot #polkit #privilege-escalation

---
## Synopsis

Starting from a sparse external footprint (SSH, HTTP, HTTPS), enumeration surfaced a real hostname via HTTP headers (`office.paper`). The WordPress blog at that vhost led to a known Core issue affecting draft/private content visibility, which exposed an internal Rocket.Chat registration URL on `chat.office.paper`. Inside Rocket.Chat, a Hubot-derived bot exposed filesystem operations that escaped their intended directory scope, leaking Hubot configuration including credentials reused for SSH access as `dwight`. With a shell as `dwight`, the host showed no usable `sudo` entries for that user, but shipped a vulnerable Polkit-related desktop stack; a timing-based local exploit created a wheel user with full `sudo` rights, enabling a transition to `root` and retrieval of the root flag.

---
## Skills Required

- Basic TCP reconnaissance and `nmap` interpretation
- HTTP virtual host reasoning and local `hosts` mapping
- WordPress surface analysis (public vs non-public content)
- Reading and adapting public exploit notes / PoCs responsibly

## Skills Learned

- WordPress Core information disclosure affecting non-public posts (CVE-2019-17671) in a real deployment context
- Rocket.Chat + Hubot bot command abuse and path traversal patterns
- Polkit-related local privilege escalation on CentOS-class targets (CVE-2021-3560) and exploit reliability considerations

---
## 1. Initial Enumeration

### 1.1 Connectivity Test

Check if the host is alive using ICMP:

```bash
ping -c 1 10.129.28.97
```

![ping](paper_01_ping.png)

The reply confirms the target is reachable on the VPN path with a TTL consistent with a nearby Linux hop, which is enough signal to move on to a full TCP sweep instead of guessing why later scans might look “empty.”

---
### 1.2 Port Scanning

Scan all TCP ports to identify open services:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.28.97 -oG allPorts
```

- `-p-` : Scan all 65,535 ports  
- `--open` : Show only open ports  
- `-sS` : SYN scan (stealthy and fast)  
- `--min-rate 5000` : Increase scan speed  
- `-Pn` : Skip host discovery  
- `-oG` : Output in grepable format  

![allports](paper_02_nmap_allports.png)

The sweep is intentionally boring here in a good way: only three TCP ports surface, so the rest of the box is unlikely to be “hidden” behind obscure services and the focus can stay on **SSH plus the web stack**.

Extract the open ports:

```bash
extractPorts allPorts
```

![extractports](paper_03_extractports.png)

`extractPorts` (or any equivalent parser) turns the greppable output into a clean comma list you can paste straight into the next `nmap -p` invocation, which avoids transcription mistakes when the scan output is long.

---
### 1.3 Targeted Scan

Run a deeper scan on the identified ports with version detection and default scripts:

```bash
nmap -sCV -p22,80,443 10.129.28.97 -oN targeted
cat targeted
```

- `-sC` : Run default NSE scripts  
- `-sV` : Detect service versions  
- `-oN` : Output in human-readable format  

![nmap sCV](paper_04_nmap_sCV.png)

The scripted scan pass is where versions and banners start to matter: you want **Apache build strings**, **TLS certificate fields**, and any default-page titles that hint whether you are looking at a real application or a placeholder vhost.

![cat targeted](paper_05_cat_targeted.png)

Reading the saved `targeted` file end-to-end is often faster than scrolling a live terminal buffer, and it makes it easier to spot small clues (like generic cert subjects) that do not jump out during the scan itself.

**Findings:**

| Port(s) | Service | Notes |
|---|---|---|
| 22/tcp | ssh | OpenSSH 8.0 |
| 80/tcp | http | Apache httpd 2.4.37 (CentOS) with `mod_fcgid`; default landing page on raw IP |
| 443/tcp | ssl/http | Same Apache stack; generic TLS cert (`localhost.localdomain`) |

---
## 2. Service Enumeration

### 2.1 Web fingerprinting, default vhost behavior, and backend hostname

The versioned scan showed a default CentOS test page on the bare IP, which usually means the “real” site is elsewhere. Fingerprinting the IP over HTTP, fuzzing for obvious paths, confirming the default page in a browser, and finally reading response headers helped identify the backend hostname used for routing.

```bash
whatweb http://10.129.28.97/
ffuf -u http://10.129.28.97/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -ac -fc 404 -t 40
```

![whatweb](paper_06_whatweb.png)

`whatweb` against the bare IP is useful even when the status code is non-200: the interesting part is often **uncommon response headers** that leak how traffic is routed internally.

![ffuf](paper_07_ffuf.png)

Directory brute forcing on the default vhost is mostly a sanity check. You are not trying to “solve the box with a wordlist” here; you are confirming whether anything obvious exists on the placeholder surface and calibrating expectations before shifting requests to the correct hostname.

![browser default page on IP](paper_08_browser_default_ip.png)

A browser view of the same IP helps separate “scanner noise” from what a normal client actually renders: a stock CentOS test page is a strong hint that the meaningful content is **name-based virtual hosting**, not a missing directory.

``` bash
curl -s -X GET "http://10.129.28.97" -I
```

![curl headers](paper_09_curl_headers.png)

A header-only `curl` pass is the cleanest way to capture backend routing clues without dumping a huge HTML body. In this case, the response includes a backend identifier pointing at **`office.paper`**, which is the hostname you want mapped locally next.

---
### 2.2 Mapping `office.paper` and reviewing the WordPress surface

Once `office.paper` is mapped locally, the blog content and comments provide the next pivot: a hint about sensitive draft material, plus corroboration that expected usernames exist.

```bash
echo "10.129.28.97 office.paper" | sudo tee -a /etc/hosts
```

![hosts office.paper](paper_10_hosts_office_paper.png)

Until DNS (or your local `hosts` file) maps `office.paper` to the machine IP, your browser and many CLI tools will keep talking to the wrong logical site even though the TCP connection is correct.

![wordpress home](paper_11_wp_home_office_paper.png)

Once the vhost resolves, the surface changes completely: you are now looking at a real WordPress install with identifiable themes/plugins and human-written content, which is where username hints and “internal process” storytelling usually start to appear.

![nick comment draft hint](paper_12_wp_nick_draft_hint.png)

Comments are not just flavor text on WordPress boxes. A remark about drafts or unpublished material is a direct nudge to think about **post visibility states** (public vs private vs draft) rather than only chasing plugin CVEs.

---
### 2.3 CVE-2019-17671 notes and draft leak

Fingerprinting and exploit-db correlation for the confirmed WordPress version pointed at a Core issue involving unauthenticated visibility of non-public posts (CVE-2019-17671), documented in Exploit-DB material. Applying the documented query-string behavior against the author archive leaked draft content, including a secret employee chat registration URL on `chat.office.paper`.

```bash
searchsploit wordpress 5.2.3
searchsploit -m multiple/webapps/47690.md
```

![searchsploit 47690](paper_13_searchsploit_47690.png)

The exploit-db entry is not “the whole attack” by itself; it is a **behavior description** tied to a specific WordPress version range. The practical question becomes: can you trigger that rendering path without authentication, and does it expose content that was never meant to be public?

```bash
# Browser / HTTP GET (example)
# http://office.paper/index.php/author/prisonmike/?static=1
```

![author static draft leak](paper_14_wp_author_static_leak.png)

The author archive is a natural place to test static rendering quirks. When it works, the impact is immediate operational intelligence: here, draft text references an internal chat host (`chat.office.paper`) and a registration URL that is not linked from the public blog UI.

---
### 2.4 Rocket.Chat onboarding and bot capabilities

After adding `chat.office.paper` to `hosts`, the leaked registration path allowed creating a local chat account. The workspace then exposes channels, users, and the `recyclops` bot introduction that describes filesystem-adjacent features.

```bash
# Add to /etc/hosts (example)
# 10.129.28.97 chat.office.paper
```

![rocketchat register](paper_15_rocketchat_register.png)

Employee chat platforms often allow **open registration** on internal hostnames because the assumption is “nobody can resolve this unless they are already on-network.” On a lab machine, that assumption is exactly what turns a leaked URL into access.

![rocketchat home after register](paper_16_rocketchat_home_post_register.png)

After onboarding, treat the UI like a small internal portal: note default channels, pinned messages, and integrations. Those elements frequently hide the shortest path to privileged automation.

![rocketchat home users](paper_17_rocketchat_home_users.png)

The users sidebar is useful context even before you DM anyone: you are confirming which accounts look like humans versus bots, and which bot accounts are likely wired to scripts running on the server side.

![recyclops help](paper_18_recyclops_help.png)

Bot help output is the contract you are about to test. If the bot claims directory restrictions, assume the implementation might be wrong until you prove otherwise with **edge cases** (`..`, absolute paths, alternate spellings, and “list vs read” behaviors).

---
## 3. Foothold

### 3.1 From `recyclops` to SSH as `dwight`

**Objective:** treat Rocket.Chat’s `recyclops` bot as a constrained file interface, prove where that constraint breaks, harvest credentials from bot integration files, and finish on a normal **SSH** session as a UNIX user.

`recyclops` is marketed around a **sales** directory: typical verbs are `list` and `file`, with an implied promise that paths stay “under sales.” Treat that promise as an untrusted claim. If the backend builds filesystem paths by string concatenation without a strict jail, then `../` segments and carefully chosen relative paths become a directory walk and, with `file`, a selective file reader—still not a shell, but close enough to steal secrets the bot’s OS user can read.

A sensible progression is: **baseline → boundary tests → high-signal targets**. The screenshots below follow that order so each image answers a distinct question (“does it work normally?”, “does traversal work?”, “does file read work?”, “where is the secret?”, “does SSH accept it?”). Two separate captures of `list sales` (channel vs DM) turned out to be **identical** in content, so only one baseline image is kept here; if you reproduce this locally, prefer a **DM** with `recyclops` so the full traversal thread stays on one clean timeline.

![recyclops list sales](paper_19_recyclops_list_sales.png)

First, exercise the documented path: list the sales folder the bot is supposed to expose. This step is not about finding a vulnerability yet; it is about locking in **expected output shape** so later screenshots are easy to explain (“same bot, same command family, different path—yet it still responded”). Run the same check from a DM if you want a quieter transcript—the visual evidence is the same capture family as a public channel `list sales`.

![recyclops list parent directory](paper_20_recyclops_path_traversal_home.png)

Now pressure the boundary: ask `list` to climb out of the sales tree (`..` chains, parent directories, then home-like locations). If the bot prints contents outside sales, you have confirmed a **path traversal in a listing primitive**. The next question is no longer “is there a bug?” but “which directories does this OS user see, and which filenames look like automation?”

![recyclops read etc passwd](paper_21_recyclops_file_passwd.png)

Switch from `list` to `file` once traversal is credible. `/etc/passwd` is a good next step because it is usually world-readable, short, and it grounds the story in real usernames (`dwight`, service users). You are proving **arbitrary readable file retrieval**, not exfiltrating the flag through chat.

![recyclops hubot env leak](paper_22_recyclops_hubot_env.png)

Operational secrets rarely live in `/etc/passwd`; they live next to **integrations**. Hubot-style setups commonly store Rocket.Chat credentials in a `.env` beside the bot. If you can pull that file through `file`, you often get a password string that doubles as a UNIX login for whoever owns the workstation narrative on the box.

**Recovered (lab notes):** Hubot `.env` contained `ROCKETCHAT_USER=recyclops` and `ROCKETCHAT_PASSWORD=Queenofblad3s!23` (redact before publishing).

At this point the chain is intentionally boring on purpose: map `dwight` from `/etc/passwd` and blog context, then test **password reuse** against SSH before chasing secondary web bugs.

```bash
ssh dwight@10.129.28.97
whoami
```

![ssh dwight and user flag](paper_23_ssh_user_flag.png)

SSH is the foothold milestone. Chat access was only the delivery mechanism; an interactive `dwight` session (and the ability to read `user.txt` in the same capture) is what upgrades the finding from “information disclosure via bot” to **authenticated remote access** you can build privesc from.

---
### 3.2 User flag

The same session capture above already shows `dwight` reading `user.txt`, but the milestone is worth calling out explicitly: with SSH access, the user flag is usually just a matter of **home-directory hygiene** and basic path knowledge (`/home/<user>/user.txt` on HTB Linux).

With an interactive shell as `dwight`, the user flag could be read from the home directory.

```bash
cat /home/dwight/user.txt
```

![user flag](paper_23_ssh_user_flag.png)

🏁 **User flag obtained**

---
## 4. Privilege Escalation

### 4.1 Polkit-related local privilege escalation (CVE-2021-3560)

`dwight` had no usable sudo configuration, but the installed `sudo` version and the presence of a vulnerable polkit-related desktop stack made a known timing-based local exploit plausible. A public PoC was executed from `/tmp` and required more than one attempt before the race succeeded.

```bash
sudo -l
/usr/bin/sudo --version
```

![sudo denied and sudo version](paper_24_sudo_not_allowed_version.png)

`sudo -l` failing for `dwight` is not the end of the privesc story on older enterprise Linux images. The next question is whether the box still ships **desktop-era components** (polkit/accountsservice stacks) that historically had local auth bypass issues, which is why collecting `sudo --version` and broader package context still matters even when sudo rules are empty.

``` bash
cd /tmp
chmod +x privesc.sh
./privesc.sh
su secnigma
id
sudo -l
```

![polkit CVE-2021-3560 exploit output](paper_25_polkit_CVE_2021_3560_exploit.png)

The polkit-style exploit path is intentionally noisy: it is race-based, so expect multiple attempts and messy output. The screenshot is documenting **that the primitive fired on this target**, not that it always works on the first run.

**Recovered (lab notes):** the PoC created a local user `secnigma` in `wheel` with `sudo (ALL) ALL` after a successful run (redact operational details before publishing).

---
### 4.2 Root access and proof

After switching to the injected account, `sudo` allowed elevating to `root`, which unlocked the root flag.

The final proof is intentionally boring: once you have a reliable local elevation primitive that yields a sudo-capable user, the remainder is standard account hopping (`su` / `sudo`) and reading the root-owned proof file.

```bash
sudo su
whoami
cat /root/root.txt
```

![root flag](paper_26_root_flag.png)

At this point you are mostly verifying containment: confirm identity with `whoami`, capture the flag artifact, and stop before doing unnecessary post-exploitation on a lab system.

🏁 **Root flag obtained**

---
# ✅ MACHINE COMPLETE

---
## Summary of Exploitation Path

1. TCP recon identified SSH and a CentOS Apache stack on HTTP/HTTPS.
2. HTTP headers exposed `office.paper`, leading to a WordPress blog with a draft-related hint.
3. CVE-2019-17671-style static rendering leaked a secret `chat.office.paper` registration URL.
4. Rocket.Chat access led to `recyclops` path traversal and Hubot `.env` credential disclosure.
5. Credential reuse granted SSH access as `dwight` and the user flag.
6. CVE-2021-3560-style polkit exploitation created a sudo-capable user, enabling `root` and the root flag.

---
## Defensive Recommendations

- Patch WordPress Core and validate that unauthenticated rendering paths cannot expose non-public content.
- Treat chat bots as privileged automation: strict path allowlists, separate service accounts, and no filesystem “convenience” features without authorization checks.
- Keep polkit/accountsservice/gnome-control-center stacks patched; monitor for local exploit primitives tied to dbus polkit interactions.
- Avoid password reuse between chat integrations and interactive UNIX accounts; prefer scoped secrets and rotation.
