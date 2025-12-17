from pwn import *  # type: ignore
import sys

id_token = ""  # insert your token here

# Set to 'info' if you don't want a trace of data sent and received
context.log_level = "debug"

io: tube = None  # type: ignore


def pretty(b: bytes) -> str:
    out = []
    for c in b:
        if 32 <= c <= 126:   # printable ASCII range
            out.append(chr(c))
        else:
            out.append(f"\\x{c:02x}")
    return ''.join(out)


def start(port: int):
    """
    Connect to INF226 server. Port number should be 7000-7004.

    With command line arguments (in sys.argv):
        - `FILE`              -- load ELF file (probably requires Posix system)
        - `--process FILE`    -- start local process instead (requires Linux)
        - `--gdb FILE CMDS`   -- start local debugger process instead (requires Linux)
        - `--remote`          -- connect to server (default)

    *(Call this first, then proceed with `read_welcome`)*
    """
    global io, _elf_file
    action = "--remote"
    file = None
    # very crude commandline option parser
    if len(sys.argv) < 2:
        pass
    elif sys.argv[1].startswith("--"):
        action = sys.argv[1]
        file = sys.argv[2] if len(sys.argv) > 2 else None
    else:
        file = sys.argv[1]

    if file:
        try:
            _elf_file = ELF(file)
        except Exception as e:
            error("Failed to load ELF file %s", file)

        if action == "--gdb":
            gdb_script = "".join([f"{a}\n" for a in sys.argv[3:]])
            io = gdb.debug(file, gdb_script or "break main\n")
        elif action == "--process":
            io = process(file)
    # By default, we connect to the official assignment servers
    if not io:
        io = remote("inf226.puffling.no", port)
    io.timeout = 2  # wait max 5 seconds when reading data
    return io


_elf_file = None


def elf_file():
    """Return the ELF executable for the current task, if available."""
    return _elf_file


question_delims = [b": ", b"? ", b":", b"?"]


def read_welcome(tok: str | None = None):
    """
    Send token and read the welcome/first question. Questions end with '?' or ':'.

    *(It's a good idea to call this first for all the tasks!)*
    """

    tok = tok or id_token
    # type: ignore # read welcome or token request
    question = io.recvuntil(question_delims, timeout=1024).decode()

    if "Please enter your token:" in question:
        if not tok:
            io.warning_once("WARNING: No token specified!")
        io.sendline(b"" + tok.encode())  # send token
        question = io.recvuntil(question_delims).decode()  # read welcome

    return question


def next_qa() -> str:
    """
    Read a question/answer from the tube. (In practice, reads until the next `?` or `:`.

    *(Might be useful for any task)*
    """

    return io.recvuntil(question_delims).decode().strip()


def read_answer() -> tuple[str, str | None]:
    """
    Read and decode answer once you've completed the challenge.

    Call this after you've sent your exploit. Print the result with `log_answer`.

    *(Might be useful for any task)*
    """
    a = io.recvuntil(question_delims).decode()

    if "signed success token" in a:
        new_tok = io.recvline().decode()
        return a, new_tok
    else:
        rest = io.recvall().decode()
        return a + rest, None


def log_answer(answer_and_token: tuple[str, str | None]) -> None:
    """
    Combine with read_answer() to get pretty output.

    *(Might be useful for any task)*
    """
    answer, token = answer_and_token
    if token:
        info("Success!!")
        info("")
        info(
            "*** Please submit the new token to https://inf226.puffling.no/oblig1/ as proof you have completed the task:"
        )
        info("")
        info("        " + token)
        info("")
    else:
        for line in answer.splitlines():
            warning(line)


def chars(n: int):
    """
    Reinterpret a 64-bit integer as a string. Non-ASCII characters are displayed as `.`

    *(Might be useful for task-4)*
    """

    def convert_char(c):
        return chr(c) if 32 <= c < 127 else "."

    return "".join([convert_char(c) for c in unpack_many(p64(n), word_size=8)])


def print_mem_entry(addr: int | str, data: int | str | bytes):
    """
    Helper for printing a memory location.

    Arguments:
        addr (int): the memory address the word was found at
        word (int|str|bytes): contents of memory location, as an integer (possibly encoded as str or bytes)

    *(Useful for task-4)*
    """
    if addr == 0:
        info(f"        {'Address':12s}   {'Word':16s}  {
             'Chars':8s}  {'Original':24s}")
        info(f"        {'-' * 12}   {'-' * 16}  {'-' * 8}  {'-' * 24}")
    else:
        if isinstance(data, bytes):
            text = repr(data)
            word = int(data, 10)
        if isinstance(data, str):
            text = repr(data)
            word = int(data, 10)
        elif isinstance(data, int):
            text = ""
            word = data
        if isinstance(addr, int):
            info(
                f"------  {addr:12x}:  {word:016x}  {chars(word):8s}  {text:24s}")
        else:
            info(f"{addr:20s}:  {word:016x}  {chars(word):8s}  {text:24s}")
