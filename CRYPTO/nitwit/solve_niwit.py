#!/usr/bin/env python3
# Full, verbose solver for nitwit WOTS (Winternitz, base=16)
# Exploit: checksum length bug -> build m2 with 'admin' and s2 >= s1, push chains forward.

import socket, ssl, sys, ast, hashlib
from math import log

HOST = "nitwit.challs.pwnoh.io"
PORT = 1337

# ---- challenge params ----
d  = 15                  # base-1 -> base=16
n0 = 64                  # 256 bits -> 64 nibbles
n1 = int(log(n0, d+1)) + 1   # = 2 (buggy)
n  = n0 + n1             # 66 chains
HS = 32                  # sha256 bytes

def H(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()

def hash_chain(x: bytes, steps: int) -> bytes:
    for _ in range(steps):
        x = H(x)
    return x

def int_to_vec(m: int, L: int, base: int) -> list[int]:
    # exact same (buggy) semantics as service
    digits = [0]*L
    i = L-1
    while m > 0:
        digits[i] = m % base
        m //= base
        i -= 1
    return digits

def domfree(m_int: int) -> list[int]:
    m_vec = int_to_vec(m_int, n0, d+1)
    c     = (d*n0) - sum(m_vec)
    c_vec = int_to_vec(c, n1, d+1)   # buggy: only 2 digits
    return m_vec + c_vec

def hex_digit_sum(b: bytes) -> int:
    return sum(((x>>4) + (x & 0xF)) for x in b)

def construct_msg_with_sum(target_sum: int, prefix=b"admin", total_len=32) -> bytes:
    # Build 32-byte message starting with 'admin' whose nibble-sum == target_sum
    m = bytearray(prefix + b"\x00"*(total_len-len(prefix)))
    need = target_sum - hex_digit_sum(m)
    for i in range(len(prefix), total_len):
        if need <= 0: break
        add = min(need, 30)          # ≤ 15+15 per byte
        hi  = min(15, add//2)
        lo  = add - hi
        if lo > 15:
            lo = 15
            hi = min(15, add - lo)
        m[i] = (hi<<4) | lo
        need -= (hi + lo)
    if need != 0:
        raise RuntimeError("cannot hit target nibble-sum")
    return bytes(m)

# ---- Verbose I/O helpers ----
def info(msg: str):
    print(msg, flush=True)

def recv_until(sock, marker: bytes, timeout=180) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        sys.stdout.write(chunk.decode("utf-8", errors="ignore"))
        sys.stdout.flush()
    return buf

def drain(sock, timeout=3) -> bytes:
    sock.settimeout(timeout)
    out = b""
    try:
        while True:
            ch = sock.recv(4096)
            if not ch: break
            out += ch
            sys.stdout.write(ch.decode("utf-8", errors="ignore"))
            sys.stdout.flush()
    except Exception:
        pass
    return out

def read_list_literal_stream(sock, start_after: bytes) -> str:
    # Wait until marker text is seen (and echo as we go)
    recv_until(sock, start_after, timeout=300)

    # Now consume from the first '['; use quote/escape-aware bracket counting
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before '['")
        buf += chunk
        sys.stdout.write(chunk.decode("utf-8", errors="ignore")); sys.stdout.flush()
        i = buf.find(b"[")
        if i != -1:
            j = i
            break

    depth = 0
    out = bytearray()
    in_str = False
    quote = 0
    escape = False
    while True:
        if j >= len(buf):
            more = sock.recv(4096)
            if not more:
                raise RuntimeError("closed while reading list")
            buf += more
            sys.stdout.write(more.decode("utf-8", errors="ignore")); sys.stdout.flush()
            continue
        ch = buf[j]
        out.append(ch)
        if in_str:
            if escape:
                escape = False
            elif ch == 92:      # '\'
                escape = True
            elif ch == quote:
                in_str = False
        else:
            if ch in (39, 34):  # ' or "
                in_str = True
                quote = ch
            elif ch == 91:      # '['
                depth += 1
            elif ch == 93:      # ']'
                depth -= 1
                if depth == 0:
                    break
        j += 1

    return out.decode("utf-8", errors="ignore")

def parse_sig_text(text: str) -> list[bytes]:
    obj = ast.literal_eval(text)
    if not isinstance(obj, list):
        raise ValueError("signature is not a list")
    sig = []
    for item in obj:
        if isinstance(item, (bytes, bytearray)):
            bts = bytes(item)
        elif isinstance(item, list):
            bts = bytes(item)  # in case printed as list of ints
        elif isinstance(item, str):
            try:
                bts = bytes.fromhex(item)
            except ValueError:
                inner = ast.literal_eval(item)
                if not isinstance(inner, (bytes, bytearray)):
                    raise
                bts = bytes(inner)
        else:
            raise ValueError("unexpected element in signature list")
        if len(bts) != HS:
            raise ValueError("bad element length in signature list")
        sig.append(bts)
    if len(sig) != n:
        raise ValueError(f"bad signature length {len(sig)} != {n}")
    return sig

def main():
    info("[*] connecting …")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((HOST, PORT), timeout=60) as raw:
        with ctx.wrap_socket(raw, server_hostname=HOST) as s:
            info("[*] connected. waiting for first prompt …")
            recv_until(s, b">>> ")

            # 1) get signature on zero message (safe)
            m1 = b"\x00"*32
            info(f"[client] send m1 = {m1.hex()}")
            s.sendall(m1.hex().encode() + b"\n")

            info("[*] reading signature list …")
            sig_text = read_list_literal_stream(s, b"Your signature is:")
            info(f"[*] signature list length (chars): {len(sig_text)}")

            sig1 = parse_sig_text(sig_text)
            info(f"[*] parsed elements: {len(sig1)} (expected {n})")

            # 2) prompt for forged message
            info("[*] syncing to next prompt …")
            recv_until(s, b">>> ")

            # 3) craft admin message with dominating step vector
            s1 = domfree(int.from_bytes(m1, "big"))
            chosen = None
            for target_c in (205, 206, 207, 211, 212, 213, 214, 215, 216, 217):
                target_sum = (d * n0) - target_c    # 960 - c
                try:
                    m2 = construct_msg_with_sum(target_sum, prefix=b"admin", total_len=32)
                except RuntimeError:
                    continue
                s2 = domfree(int.from_bytes(m2, "big"))
                if all(a <= b for a, b in zip(s1, s2)):
                    chosen = (m2, s2, target_c)
                    break
            if not chosen:
                raise RuntimeError("failed to find dominating step-vector")
            m2, s2, tc = chosen
            info(f"[*] chosen target_c={tc}, m2.hex={m2.hex()}")

            # 4) forge by pushing forward
            forged = [hash_chain(sig1[i], s2[i]-s1[i]) for i in range(n)]
            info("[*] forged signature ready")

            # 5) submit forged message and signature
            s.sendall(m2.hex().encode() + b"\n")
            info("[client] sent m2")

            recv_until(s, b">>> ")
            s.sendall((repr(forged) + "\n").encode())
            info("[client] sent forged signature (list of bytes)")

            # 6) print server’s final response (flag expected)
            info("[*] server response:")
            drain(s, timeout=5)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # make sure any error shows up on screen
        print(f"[!] ERROR: {e}", file=sys.stderr, flush=True)
        raise
