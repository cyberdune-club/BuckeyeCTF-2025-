# Clandescriptorius — Writeup

**Category:** Crypto  
**Service:** https://clandescriptorius.challs.pwnoh.io  
**Author:** jm8  
**Write‑up by:** marlithor_cyber  
**Points / Solves:** 176 pts / 90 solves

---

## TL;DR
The challenge’s stream construction derives the per‑block keystream from **`timestamp || block_index` as decimal strings without a delimiter**. By starting a session with **T₀ = −123** (getting the encrypted flag) and later encrypting all‑zero bytes at **T₁ = −12** while asking for block indices **j(i) = “3” ∥ i**, you satisfy

```
str(T₁) + str(j(i)) == str(T₀) + str(i)
```

so the service emits **the very same keystream blocks** used for the flag. XOR those keystream blocks with the flag ciphertext blocks, then **PKCS#7‑unpad** to read the plaintext. The recovered flag is:

```
bctf{the_future_is_now_e3faa77c672e6d62}
```

---

## Black‑box interface
- **/startsession** — accepts a `timestamp`, returns a `session_id` and an `encrypted_flag` (hex).  
- **/encrypt** — accepts `session_id`, `timestamp`, and user `data` (hex), returns `encrypted` (hex).  
Empirically, the service behaves like a **block cipher in CTR‑style mode** where each keystream block depends on the *decimal string* of the timestamp concatenated with the *decimal string* of the block index (no separator). fileciteturn2file0

---

## Vulnerability
The per‑block nonce/counter is formed by **string concatenation** of `timestamp` and `block_index` in base‑10, e.g.,

```
counter_label = str(timestamp) + str(block_index)
```

Because there is **no delimiter and no fixed‑width encoding**, different `(timestamp, block_index)` pairs can collide after concatenation. For example:

- With **T₀ = −123** and index **i**, the label is `"-123" + str(i)`.
- With **T₁ = −12** and index **j = int("3" + str(i))**, the label is `"-12" + "3" + str(i)` = `"-123" + str(i)`.

Thus the same label drives the same keystream block, i.e., **keystream reuse** across API calls.

---

## Attack plan (no scripts required)
1. **Start a session** with `timestamp = −123` and save the returned `encrypted_flag` (hex).  
2. **Count blocks:** let `nb = ceil(len(encrypted_flag)/16)` (the service uses 16‑byte blocks).  
3. **Request keystream blocks:** call `/encrypt` at `timestamp = −12` with a payload of **all zeros** long enough to cover at least `nb` blocks. This yields a contiguous run of keystream‑XOR‑zeros = **keystream**.  
4. **Select matching blocks:** for each flag block `i` (0‑based), take block **j(i) = int("3" + str(i))** from the zero‑encryption output; that block equals the keystream used for flag block `i`.  
5. **Recover plaintext:** XOR each flag block with its matching keystream block; then **PKCS#7 unpad** the result to ASCII.  
6. **Read the flag:**

```
bctf{the_future_is_now_e3faa77c672e6d62}
```

---

## Why it works
Any stream/CTR construction is secure only if **each keystream block is unique per (key, nonce, counter)**. Here, building the per‑block selector as `str(timestamp) + str(index)` without separators introduces **ambiguous encodings** (e.g., `(-123, i)` collides with `(-12, 3i)`), enabling a **chosen‑timestamp keystream‑reuse** attack and straightforward decryption by XOR.

---

## Notes, checks, and pitfalls
- Make sure to request **enough zero blocks** to cover the highest `j(i)` you need (i.e., the largest `int("3"+str(i))`).  
- If the service hex output includes whitespace, strip it before chunking into 16‑byte blocks.  
- If the recovered plaintext looks padded, **PKCS#7** unpadding is expected. fileciteturn2file0

---

## Remediation
- Encode counters using **fixed‑width binary** (e.g., 64‑bit BE) and concatenate with the nonce using **structured binary fields**—not decimal strings.  
- Alternatively, adopt a standard AEAD (e.g., AES‑GCM) with **random per‑message nonces** and validated parameter handling.  
- Validate and bound user‑supplied timestamps, or decouple keystream derivation from attacker‑controlled inputs.

---

## Credits
- **Challenge author:** jm8  
- **Write‑up:** marlithor_cyber

**Flag:** `bctf{the_future_is_now_e3faa77c672e6d62}`
