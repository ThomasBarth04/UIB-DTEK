from pwn import *

# Load your local ELF
e = ELF("../../../Downloads/pwnexercise")

print("Symbols in ELF:")
for k, v in e.symbols.items():
    print(f"{hex(v)}  {k}")

# Dump out all printable strings in .rodata
rodata = e.get_section_by_name(".rodata").data()


def printable_runs(bs, minlen=4):
    run, out = bytearray(), []
    for b in bs:
        if 32 <= b <= 126:  # ASCII range
            run.append(b)
        else:
            if len(run) >= minlen:
                out.append(bytes(run).decode("ascii", errors="ignore"))
            run.clear()
    if len(run) >= minlen:
        out.append(bytes(run).decode("ascii", errors="ignore"))
    return out


print("\nStrings in .rodata:")
for s in printable_runs(rodata):
    print(s)
