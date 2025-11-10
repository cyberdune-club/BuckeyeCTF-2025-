import socket, ssl, re, sys
from binascii import unhexlify

HOST = "cube-cipher.challs.pwnoh.io"
PORT = 1337

PROMPT = b"Option: "

def recv_until(sock, token=PROMPT, max_bytes=1_000_000):
    buf = b""
    while token not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > max_bytes:
            break
    return buf

def open_conn():
    s = socket.create_connection((HOST, PORT))
    ctx = ssl.create_default_context()
    ss = ctx.wrap_socket(s, server_hostname=HOST)
    banner = recv_until(ss)  # menu
    return ss

HEX_RE = re.compile(rb"\b[0-9a-f]{2}\b", re.I)

def get_bytes(ss):
    ss.sendall(b"3\n")
    data = recv_until(ss)  # until next "Option: "
    # grab the last line of hex pairs
    hexes = HEX_RE.findall(data)
    if len(hexes) < 27:
        # sometimes all 27 bytes come contiguous w/o spaces
        m = re.search(rb"([0-9a-fA-F]{54})\s*\r?\n", data)
        if not m:
            raise RuntimeError("failed to parse bytes")
        hx = m.group(1).decode()
    else:
        hx = b"".join(hexes[-27:]).decode()
    return hx.lower()

def reapply(ss):
    ss.sendall(b"4\n")
    recv_until(ss)

def try_candidates(b):
    """Return first plausible flag-like string if found, else None."""
    # raw
    try:
        s = b.decode("latin1", "ignore")
        m = re.search(r"[A-Za-z0-9_]{3,20}\{[^}]{5,200}\}", s)
        if m:
            return m.group(0)
    except:
        pass
    # nibble swap inside each byte
    b_sw = bytes(((x & 0x0F) << 4) | ((x & 0xF0) >> 4) for x in b)
    s2 = b_sw.decode("latin1", "ignore")
    m = re.search(r"[A-Za-z0-9_]{3,20}\{[^}]{5,200}\}", s2)
    if m:
        return m.group(0)
    # rotate bytes and check both raw and swapped
    for r in range(1, len(b)):
        br = b[r:]+b[:r]
        for candidate in (br, bytes(((x & 0x0F) << 4) | ((x & 0xF0) >> 4) for x in br)):
            s3 = candidate.decode("latin1", "ignore")
            m = re.search(r"[A-Za-z0-9_]{3,20}\{[^}]{5,200}\}", s3)
            if m:
                return m.group(0)
    return None

def main():
    ss = open_conn()
    seen = {}
    seq = []
    # take the starting ciphertext as state 0
    hx = get_bytes(ss)
    seen[hx] = 0
    seq.append(hx)

    # keep re-applying the hidden algorithm until we loop
    for i in range(1, 10000):
        reapply(ss)
        hx = get_bytes(ss)
        if hx in seen:
            loop_start = seen[hx]
            # plaintext should be the state just before the loop repeated
            # i.e., the element preceding the earliest duplicate:
            if loop_start == 0:
                # unscrambled is the one right before current (i-1)
                cand_hex = seq[i-1]
            else:
                cand_hex = seq[loop_start-1]
            pt = unhexlify(cand_hex)
            flag = try_candidates(pt)
            if flag:
                print(flag)
                return
            # try also the very first state (sometimes already plaintext)
            pt0 = unhexlify(seq[0])
            flag0 = try_candidates(pt0)
            if flag0:
                print(flag0)
                return
            # last resort: print best guess
            print(pt.decode("latin1", "ignore"))
            return
        else:
            seen[hx] = i
            seq.append(hx)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
