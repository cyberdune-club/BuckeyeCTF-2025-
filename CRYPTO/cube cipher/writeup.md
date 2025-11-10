# Cube Cipher — Writeup

**Category:** Crypto  
**Service:** `ncat --ssl cube-cipher.challs.pwnoh.io 1337`  
**Author:** fisher792  
**Write‑up by:** marlithor_cyber  
**Points / Solves:** 100 pts / 178 solves

---

## TL;DR
The challenge is a **keyless permutation cipher** over a single **27‑byte block** (split into **54 nibbles** laid out on a Rubik’s Cube net). Each press of “reapply” applies the **same fixed permutation**. Record the printed 27‑byte state after each reapply until a state **repeats**; the plaintext is the state **immediately before** that first repeat. Because of how nibbles/bytes are packed and how the cube is “unfolded,” you may need to apply a **per‑byte nibble swap** and/or a **circular rotation** by 0..26 bytes to make the text readable. Doing so reveals the flag:

```
bctf{the_cUb3_pl4yS_Y0U}
```

---

## Challenge Overview
- The service exposes a menu with, among others:
  - **Print current state**: dumps **27 bytes** as hex.
  - **Reapply**: applies the same hidden “cube shuffle” once more.
- Internally, the 27 bytes are treated as **54 nibbles**, placed onto a cube net. The “shuffle” is just a **permutation of sticker positions**; there’s no key schedule or nonlinear mixing.
- After shuffling, the nibbles are repacked into 27 bytes and printed.

**Key takeaway:** This is pure permutation. Applying a **fixed permutation** repeatedly inevitably produces a **cycle**: some state reappears.

---

## Cryptanalysis (Why this works)
Let the printed states be:
\[ x_0, x_1, x_2, \dots \quad \text{with} \quad x_{i+1} = \pi(x_i) \]
for a fixed permutation \(\pi\) on 27‑byte strings.

Because the state space is finite, there exist indices \(0 \le j < i\) such that **\(x_i = x_j\)** and this is the **first** time any duplicate appears. Once you encounter this first duplicate:

- The unshuffled arrangement is effectively **\(\pi^{-1}(x_j)\)**, which is exactly the state **before** \(x_j\) in your transcript.
- In other words, the **candidate plaintext** is the entry **just before the repeated state**.

Two presentational quirks may obscure readability:
1. **Nibble packing:** Each byte was formed from two nibbles; sometimes the **high/low nibbles are swapped**. Fix by mapping each byte \(b\) to \(((b \ll 4) \mid (b \gg 4)) \& 0\xFF\).
2. **Cube net offset:** The “unfolding” can be offset; treat this as a **circular rotation** of the 27‑byte string by an unknown shift **0..26**.

Trying the candidate plaintext **as‑is**, then **nibble‑swapped**, and for both trying **all 27 rotations**, will expose a readable ASCII string (or a standard flag pattern).

---

## Reproduction (No script needed)
1. **Connect**  
   ```
   ncat --ssl cube-cipher.challs.pwnoh.io 1337
   ```

2. **Collect states**  
   - From the menu, choose **Print current state**. Copy the **27‑byte hex** (call this `x0`).  
   - Choose **Reapply**, then **Print** again (now `x1`).  
   - Repeat: Reapply → Print → copy `x2`, `x3`, …  
   - Keep a list of these hex dumps in order.

3. **Find the first repeat**  
   - In your list, search for the **first time** any 27‑byte string reappears. Suppose `xj` equals a previous `xi` (with `i < j`), and this is the first duplicate overall.  
   - The **candidate plaintext** is the state **right before** that repeated one: i.e., the element preceding `xj` in your list.

4. **Make it read**  
   For the candidate plaintext:
   - Try **as‑is** (decode hex → ASCII).  
   - If unreadable, try a **per‑byte nibble swap**.  
   - For each of the above, try **all 27 circular rotations** (shift by 0..26 bytes).  
   - Look for a flag pattern like `xxxx{...}` (ASCII letters/digits/underscores, braces).

5. **Result**  
   Following the process above reveals the flag:
   ```
   bctf{the_cUb3_pl4yS_Y0U}
   ```

---

## Why it’s secure‑looking but weak
- A single, fixed sticker permutation **without diffusion or key material** is not cryptographically secure.  
- Observing iterates leaks the **cycle structure** (the orbit under \(\pi\)), which lets you infer a preimage (effectively applying \(\pi^{-1}\) once) without knowing \(\pi\).  
- The nibble/rotation quirks are **presentation‑level** and can be brute‑normalized cheaply (27 rotations × 2 nibble states).

---

## Notes & Pitfalls
- Sometimes the **very first** state is already close to plaintext; don’t forget to try it.  
- If the dump format varies (spaces vs. compact hex), normalize it before comparing.  
- If the flag alphabet differs, widen your “is this readable?” heuristic (e.g., allow mixed case, digits, underscores, punctuation).

---

## Credits
- **Challenge author:** fisher792  
- **Write‑up:** marlithor_cyber

**Flag:** `bctf{the_cUb3_pl4yS_Y0U}`
