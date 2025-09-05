from pwn import *
from pwnlib.elf.elf import Function

context.log_level = "debug"


def solveQuestion():
    q1 = io.recvuntil(b"?")
    return safeeval.expr(q1[:-3])


io = remote("inf226.puffling.no", 6001)
print(io.recvline())
io.sendline(b"infA")
io.recvline()

for i in range(1024):
    a = solveQuestion()
    io.sendline(f"{a}".encode("utf-8"))


io.interactive()
