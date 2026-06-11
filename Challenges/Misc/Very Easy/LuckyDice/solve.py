#!/usr/bin/env python3
"""solve.py — LuckyDice auto-solver

HTB Challenge: LuckyDice (Misc, Very Easy)

WHY THIS SCRIPT EXISTS:
-----------------------
The challenge presents a dice game with 100 rounds. Each round, 8-13 players
roll dice (increasing each round: 4 dice in round 1, up to 202 in round 100).
You must identify the winning player (highest sum) within 0.3 seconds.

This is impossible to do manually because:
  1. Rounds have up to 13 players × 202 dice = 2,626 values to sum.
  2. The 0.3s timeout starts the instant the server prints the prompt.
  3. 100 consecutive correct answers are required — one mistake ends the game.

HOW IT WORKS:
-------------
1. Connects to the remote TCP instance.
2. Answers "1" to the initial "Are you ready?" prompt.
3. For each of 100 rounds:
   a. Receives all output up to the "> " input prompt.
   b. Parses lines matching "Player X: d1 d2 d3 ..." to extract dice values.
   c. Sums each player's dice values.
   d. Determines the winner: player with the highest sum.
      Tie-break: highest player number wins (matches server's sorted() behavior).
   e. Sends the winner's number back immediately.
4. After 100 correct rounds, the server reveals flag.txt contents.

KEY IMPLEMENTATION DETAIL — Buffered I/O:
The server uses Python's input() which flushes all pending stdout at once.
This means the dice rolls, "Who wins?" text, player options, and "> " prompt
all arrive in a single burst. A naive approach of doing recvuntil("Who wins?")
then recvuntil("> ") will fail because the first call consumes the "> " bytes.
The Conn class maintains an internal buffer that properly splits at markers.
"""
import socket
import sys


HOST = "154.57.164.83"
PORT = 31992


class Conn:
    """Buffered socket wrapper. Splits received data at markers and preserves
    leftover bytes in an internal buffer for subsequent reads."""

    def __init__(self, host, port, timeout=30):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect((host, port))
        self.buf = b""

    def recvuntil(self, marker):
        """Read from socket until marker is found. Returns data up to and
        including the marker. Leftover bytes stay in self.buf."""
        while marker not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError(
                    f"Connection closed. Buffer:\n{self.buf.decode(errors='replace')}"
                )
            self.buf += chunk
        idx = self.buf.index(marker) + len(marker)
        result = self.buf[:idx]
        self.buf = self.buf[idx:]
        return result

    def sendline(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data + b"\n")

    def recv_remaining(self, timeout=5):
        """Drain remaining data (for flag output after game ends)."""
        self.sock.settimeout(timeout)
        out = self.buf
        while True:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                out += chunk
            except socket.timeout:
                break
        return out.decode(errors='replace')

    def close(self):
        self.sock.close()


def solve():
    r = Conn(HOST, PORT)
    print(f"[*] Connected to {HOST}:{PORT}")

    # Server shows game banner and rules, then asks "Are you ready? 1. Yes 2. No"
    r.recvuntil(b"> ")
    r.sendline("1")
    print("[*] Sent '1' (ready)")

    for rnd in range(100):
        # Receive everything up to the answer prompt "> "
        # Contains: round header, player dice lines, "Who wins?", numbered options
        data = r.recvuntil(b"> ").decode()

        # Parse "Player X: d1 d2 d3 ..." lines
        players = {}
        for line in data.split("\n"):
            line = line.strip()
            if line.startswith("Player ") and ":" in line:
                parts = line.split(":")
                player_num = int(parts[0].replace("Player ", "").strip())
                dice_vals = list(map(int, parts[1].strip().split()))
                players[player_num] = sum(dice_vals)

        if not players:
            print(f"[!] No players parsed in round {rnd+1}!\n{data}")
            r.close()
            sys.exit(1)

        # Winner = highest sum. Tie-break: highest player number.
        max_sum = max(players.values())
        winner = max(p for p, sv in players.items() if sv == max_sum)

        r.sendline(str(winner))

        resp = r.recvuntil(b"\n").decode()
        if "Correct" in resp:
            print(f"[+] Round {rnd+1}/100: Player {winner} (sum={max_sum})")
        else:
            print(f"[-] Round {rnd+1} FAILED: {resp.strip()}")
            r.close()
            sys.exit(1)

    print("[*] All 100 rounds complete! Reading flag...")
    flag = r.recv_remaining()
    print(flag)
    r.close()


if __name__ == "__main__":
    solve()
