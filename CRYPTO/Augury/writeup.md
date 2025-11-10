# Augury — Crypto Challenge Write‑up

**Category:** Cryptography (Beginner)  
**Solver:** valague  
**Service:** `augury.challs.pwnoh.io:1337` (SSL)  
**Files:** `main.py`

---

## TL;DR
The service “encrypts” files by XORing them with a keystream seeded from only 4 bytes of `SHAKE-128`, then advances that state using a linear congruential generator (LCG). With a known file type (e.g., PNG header) you recover the first keystream words and, because the LCG is predictable, you derive the rest and decrypt the file. The decrypted image contains the flag: **`bctf{pr3d1c7_7h47_k3y57r34m}`**.

---

## Challenge summary
You can upload/view files. Uploading asks for a password; the program derives a 32‑bit value from `SHAKE-128(password)` and uses it as the initial keystream word. For each 4‑byte block of the file, it XORs with the current 32‑bit word and updates the word via an LCG. Viewing a file prints the stored hex.

Key observations:
- **Key truncation:** Only 4 bytes from `SHAKE-128` are used → tiny keyspace.
- **Predictable PRNG:** Keystream evolves with a fixed LCG → fully deterministic.
- **Known‑plaintext:** The target file is `secret_pic.png`, and PNG headers are standard, so we can deduce the first keystream bytes by XORing ciphertext with the PNG magic bytes.

---

## Relevant code fragments (from `main.py`)
- **LCG:** `next = (cur * 3404970675 + 3553295105) mod 2^32`
- **Key derivation:** `cur = SHAKE128(password).digest(4)` (32‑bit state)
- **XOR stream:** For each 4‑byte chunk: `chunk ^= cur; cur = LCG(cur)`

This design is a textbook example of why LCGs must **not** be used for stream ciphers and why truncating cryptographic outputs is dangerous.

---

## Attack plan

1. **Connect & fetch ciphertext**  
   Use `ncat --ssl augury.challs.pwnoh.io 1337` or `pwntools` to select *View Files* and read the hex of `secret_pic.png`.

2. **Recover initial keystream word (known‑plaintext)**  
   PNG starts with 8 known bytes: `89 50 4E 47 0D 0A 1A 0A`.  
   XOR the first 8 ciphertext bytes with those 8 header bytes to obtain the first 8 keystream bytes. The first 4 bytes form the initial 32‑bit state `k0` (big‑endian).

3. **Predict all subsequent keystream words**  
   Iterate `k_{i+1} = (k_i * 3404970675 + 3553295105) mod 2^32`, and for each 4‑byte block of ciphertext XOR with the big‑endian bytes of `k_i`.

4. **Decrypt**  
   Process the whole hex stream block‑by‑block to recover the original PNG. Saving the result yields a valid image with the embedded flag.

---

## Reproduction sketch (language‑agnostic)

1. Read the hex string `C`.  
2. Compute `H = 89504E470D0A1A0A`.  
3. `K0_bytes = C[0:8] XOR H` → `k0 = BE32(K0_bytes[0:4])`.  
4. For `i = 0..` over 4‑byte blocks:
   - `key_i = BE32_BYTES(k_i)`  
   - `P[i] = C[i] XOR key_i`  
   - `k_{i+1} = (k_i * 3404970675 + 3553295105) mod 2^32`
5. Write `P` to `flag.png` and open it.

---

## Flag
```
bctf{pr3d1c7_7h47_k3y57r34m}
```

---

## Why it works (and how to fix it)
- **Predictability kills stream ciphers.** Once a single keystream word leaks, an LCG gives you the rest.  
- **Do not truncate strong primitives** to short keys/states unless you’ve proven security for that size.  
- **Use standard, vetted constructions** such as AES‑CTR/ChaCha20 with full‑length keys and CSPRNGs (`secrets`, `/dev/urandom`) for key/nonce generation.

