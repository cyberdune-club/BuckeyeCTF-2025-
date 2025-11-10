#!/usr/bin/env python3
import sys, math, requests

BASE = "https://clandescriptorius.challs.pwnoh.io"

def chunks(bs, n): 
    return [bs[i:i+n] for i in range(0, len(bs), n)]

def pkcs7_unpad(b):
    if not b: 
        return b
    k = b[-1]
    if k < 1 or k > 16 or b[-k:] != bytes([k])*k:
        return b  # just in case
    return b[:-k]

def start_session():
    # choose T0 = -123 so we can use the split trick
    T0 = -123
    r = requests.post(f"{BASE}/startsession", json={"timestamp": T0}, timeout=15)
    r.raise_for_status()
    j = r.json()
    sess = j["session_id"]
    cflag = bytes.fromhex(j["encrypted_flag"])
    return sess, T0, cflag

def get_keystream_blocks(sess, T1, max_block_needed):
    # encrypt zeros up to (max_block_needed+1) blocks at timestamp T1
    zeros = bytes([0])*16*(max_block_needed+1)
    r = requests.post(f"{BASE}/encrypt", json={
        "session_id": sess,
        "timestamp": T1,
        "data": zeros.hex()
    }, timeout=30)
    r.raise_for_status()
    enc = bytes.fromhex(r.json()["encrypted"])
    return chunks(enc, 16)

def solve():
    sess, T0, cflag = start_session()
    nb = math.ceil(len(cflag)/16)
    # we'll use T1 = -12 and j(i) = int("3"+str(i)) so that:
    # str(-12) + str(j) == str(-123) + str(i)
    T1 = -12
    j_for = [int("3"+str(i)) for i in range(nb)]
    maxj = max(j_for)
    blocks_at_T1 = get_keystream_blocks(sess, T1, maxj)

    # recover flag by XORing cflag_block with keystream block at j(i)
    cblocks = chunks(cflag, 16)
    pblocks = []
    for i, cb in enumerate(cblocks):
        ks = blocks_at_T1[j_for[i]]
        pblocks.append(bytes(a ^ b for a, b in zip(cb, ks)))

    flag = pkcs7_unpad(b"".join(pblocks)).decode("utf-8", "replace")
    print(flag)

if __name__ == "__main__":
    # optional: custom base url as argv
    if len(sys.argv) == 2:
        BASE = sys.argv[1].rstrip("/")
    solve()
