# nitwit — Writeup

**Category:** Crypto  
**Service:** `ncat --ssl nitwit.challs.pwnoh.io 1337`  
**Author:** can.of.porridge  
**Write-up by:** marlithor_cyber  
**Points / Solves:** 100 pts / 122 solves

---

## TL;DR
The challenge implements **Winternitz one‑time signatures (WOTS)** with base **\(d+1 = 16\)** over a 256‑bit message (64 nibbles). The **checksum is truncated to only 2 hex digits**, although its range requires **3 digits**. This breaks the required **domination‑free** mapping. You obtain a signature on a harmless message (e.g., 32 zero bytes), then craft a 32‑byte message beginning with **`admin`** whose step vector **component‑wise dominates** the first. Advancing each signature element by the difference in steps yields a valid forged signature, which the service accepts and returns the admin flag.

---

## What the service does
- Implements WOTS chains with parameters:  
  - \(v = 256\) bits (message bound), \(d = 15\) so base \(b = d+1 = 16\).  
  - \(n_0 = 64\) message digits (256 bits = 64 nibbles).  
  - **Checksum** \(c = d \cdot n_0 - \sum m_i \in [0, 960]\).  
  - **Bug:** checksum vector length is **\(n_1 = 2\)** hex digits instead of 3.  
- Key generation picks random chain seeds \(x_i\) and publishes \(y_i = H^{d}(x_i)\).  
- To **sign** message \(m\), compute the base‑16 digits \(\mathbf{s}(m) = (m\_0,\dots,m\_{63}, c\_0,c\_1)\) and output the list \(\sigma\_i = H^{\,s\_i}(x\_i)\).  
- **Verify** hashes each element forward \(d-s\_i\) and checks it matches the public key aggregate.

---

## Why the checksum length matters
In WOTS, the digit vector must be **domination‑free**: there should not exist two messages \(m, m'\) with digit vectors \(\mathbf{s}(m) = (s\_i)\) and \(\mathbf{s}(m') = (s'_i)\) such that **\(s'_i \ge s_i\)** for **all** indices. The checksum ensures this by “soaking up” how much you can increase message digits.

Here, the checksum \(c\in[0,960]\) needs **3 hex digits** \([0x000..0x3C0]\). Truncating to **2 digits** effectively reduces it **modulo 256**, so increasing message digits by multiples of 256 in total nibble sum **does not increase** the published checksum digits. Consequently you can have \(\mathbf{s}(m') \ge \mathbf{s}(m)\) component‑wise.

---

## Attack outline (no script required)
1. **Connect** to the service and submit a harmless message for signing, e.g. 32 zero bytes. Save the resulting signature list \(\sigma\) and the printed public key.  
2. **Compute the step vector** for your harmless message \(\mathbf{s}(m)\). For 32 zero bytes, the 64 message digits are all 0, and the truncated 2‑digit checksum corresponds to \(c = 960\) with only its **low two hex digits** kept (i.e., **C0**).  
3. **Construct an admin message** \(m'\) (32 bytes beginning with the ASCII `admin`) whose:  
   - 64 base‑16 message digits are all **\(\ge 0\)** (trivial), and  
   - the **two‑digit truncated checksum** \(c'\) has each hex digit \(\ge\) that of **C0**.  
   You can achieve this by **tuning the total nibble sum** of the remaining bytes so that \(c' \equiv c \pmod{256}\) or any value with both digits not smaller than C0. (Each byte contributes between 0 and 30 to the nibble sum, so you can hit the required target.)  
4. With such an \(m'\), you have **\(\mathbf{s}(m') \ge \mathbf{s}(m)\)** element‑wise.  
5. **Forge the signature:** For each index \(i\), compute  
   \[ \sigma'_i \;=\; H^{\,s'(m')\_i - s(m)\_i}(\sigma_i) \]  
   i.e., **hash each element forward** by the difference in steps.  
6. **Submit** \(m'\) (the one that contains `admin`) and the forged signature list. Verification computes \(H^{d - s'(m')\_i}(\sigma'_i) = H^{d - s(m)\_i}(\sigma_i) = y_i\), so it accepts—and the service prints the flag.

---

## Why this is sufficient for a one‑try service
- The signing phase prohibits signing messages containing **`admin`**, but allows other messages.  
- Because the first message is entirely under your control, picking **all‑zeros** makes its step vector minimal, maximizing the chance to dominate it later.  
- The **two‑digit checksum leak** lets you craft the required \(m'\) using only **nibble‑sum arithmetic**, no brute force over the full 256‑bit space.

---

## Remediation
- Use the **correct checksum length**: represent \(c\in[0,960]\) with **3 base‑16 digits**.  
- Or, adopt a standard, audited WOTS parameterization (e.g., from RFCs) where the checksum length is derived with **ceil/bit‑length**, not `int(log(...))+1` on floating logs.  
- Prefer **XMSS/LMS** or an AEAD signature scheme for production; and never reuse a WOTS key beyond its intended one‑time use.

---

## Credits
- **Challenge author:** can.of.porridge  
- **Write‑up:** marlithor_cyber

*(Flag omitted in this writeup; it is returned by the service upon a successful forge as described.)*
