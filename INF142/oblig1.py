from pwn import *
import re
import base64
import math

# Server connection details
SERVER_IP = "158.39.74.18"
SERVER_PORT = 50001

# Student ID used for authentication (must match server regex)
STUDENT_ID = "thbar6999"


def solve_polynomial(expr: str) -> str:
    """
    Solves a quadratic polynomial of the form:
        ax^2 + bx + c = 0

    The server guarantees that an integer root exists.
    The function returns one valid integer root as a string.
    """
    # Extract coefficients a, b, and c using a regular expression
    m = re.match(r"(-?\d+)x\^2 \+ (-?\d+)x \+ (-?\d+)", expr)
    a, b, c = map(int, m.groups())

    # Compute the discriminant
    disc = b * b - 4 * a * c

    # Compute integer square root of the discriminant
    sqrt_d = int(math.isqrt(disc))

    # Test both possible roots of the quadratic equation
    for r in ((-b + sqrt_d) // (2 * a), (-b - sqrt_d) // (2 * a)):
        if a * r * r + b * r + c == 0:
            return str(r)


def solve_encoding(line: str) -> str:
    """
    Decodes a string sent by the server.
    The server specifies the encoding type followed by the encoded payload.
    """
    encoding, payload = line.split(": ", 1)

    if encoding == "hex":
        # Decode hexadecimal representation
        return bytes.fromhex(payload).decode()

    elif encoding == "base64":
        # Decode base64 representation
        return base64.b64decode(payload).decode()

    elif encoding == "utf-8":
        # Payload is a list of integer character codes
        values = eval(payload)
        return "".join(chr(v) for v in values)


def main():
    """
    Main loop.
    Establishes a TCP connection, authenticates, and
    solves challenges until the flag is received.
    """
    # Connect to the remote TCP server
    io_tcpsvr = remote(SERVER_IP, SERVER_PORT)

    # Wait for authentication prompt and send student ID
    io_tcpsvr.recvuntil(b"student id")
    io_tcpsvr.sendline(STUDENT_ID)

    # Main interaction loop
    while True:
        # Receive a line from the server with a short timeout
        line = io_tcpsvr.recvline(timeout=1)
        if not line:
            break

        msg = line.decode().strip()

        # Polynomial challenge
        if "x^2" in msg:
            answer = solve_polynomial(msg)
            io_tcpsvr.sendline(answer)

        # Encoding challenge
        elif msg.startswith(("hex:", "base64:", "utf-8:")):
            answer = solve_encoding(msg)
            io_tcpsvr.sendline(answer)

        # Favourite colour challenge
        # The server accepts the first answer and expects the same later
        elif "favourite color" in msg:
            io_tcpsvr.sendline("blue")

        # Flag received: proof of success
        elif msg.startswith("INF142{"):
            print("FLAG:", msg)
            break

    # Close the TCP connection
    io_tcpsvr.close()


if __name__ == "__main__":
    main()
