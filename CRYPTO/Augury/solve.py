#!/usr/bin/env python3
"""
Augury CTF Challenge Solver
bctf{pr3d1c7_7h47_k3y57r34m}
"""

from pwn import *
import re

def generate_keystream(i):
    """LCG used by the service - this is the vulnerability!"""
    return (i * 3404970675 + 3553295105) % (2 ** 32)

class AuguryCracker:
    def __init__(self, known_keystream_int):
        self.current_keystream = known_keystream_int
    
    def get_next_key_bytes(self):
        """Get the next 4 bytes of keystream using the predictable LCG"""
        key_bytes = self.current_keystream.to_bytes(4, byteorder='big')
        self.current_keystream = generate_keystream(self.current_keystream)
        return key_bytes
    
    def decrypt(self, encrypted_hex):
        """Decrypt encrypted hex data using the predicted keystream"""
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        decrypted = bytearray()
        
        for i in range(0, len(encrypted_bytes), 4):
            key_bytes = self.get_next_key_bytes()
            chunk = encrypted_bytes[i:i+4]
            
            # XOR decrypt this chunk
            for j in range(len(chunk)):
                decrypted.append(chunk[j] ^ key_bytes[j])
        
        return decrypted

def get_encrypted_data():
    """Connect to service and download the encrypted flag file"""
    print("[+] Connecting to service...")
    r = remote("augury.challs.pwnoh.io", 1337, ssl=True)
    
    # Wait for menu and navigate to file listing
    r.recvuntil(b"Exit")
    r.sendline(b"2")  # Choose "View Files"
    
    # Wait for file list and select the flag file
    r.recvuntil(b"Choose a file to get")
    r.sendline(b"secret_pic.png")
    
    print("[+] Receiving encrypted data...")
    encrypted_data = b""
    
    # Receive all data (it might be sent in multiple chunks)
    while True:
        try:
            chunk = r.recv(4096, timeout=1)
            if not chunk:
                break
            encrypted_data += chunk
            # Stop when we see the menu again
            if b"Please select an option:" in chunk or b"Exit" in chunk:
                break
        except:
            break
    
    r.close()
    
    # Extract just the hex characters
    hex_data = encrypted_data.decode('latin-1')
    hex_clean = re.sub(r'[^0-9a-fA-F]', '', hex_data)
    
    print(f"[+] Received {len(hex_clean)} hex characters")
    return hex_clean.lower()  # Convert to lowercase for consistency

def main():
    # Step 1: Get the encrypted data from the service
    encrypted_hex = get_encrypted_data()
    
    if len(encrypted_hex) == 0:
        print("[-] Failed to get encrypted data")
        return
    
    # Save encrypted data for debugging
    with open('encrypted_flag.hex', 'w') as f:
        f.write(encrypted_hex)
    print("[+] Saved encrypted data to 'encrypted_flag.hex'")
    
    # Step 2: Recover the keystream using known plaintext attack
    # PNG files always start with: 89 50 4E 47 0D 0A 1A 0A
    png_header = bytes.fromhex("89504E470D0A1A0A")
    
    # Get first 8 bytes of encrypted data
    encrypted_start = bytes.fromhex(encrypted_hex[:16])
    
    # XOR with PNG header to recover keystream
    keystream_start = bytearray()
    for i in range(8):
        keystream_start.append(encrypted_start[i] ^ png_header[i])
    
    print(f"[+] Recovered keystream start: {keystream_start.hex()}")
    
    # Convert first 4 bytes to integer for LCG initialization
    first_keystream_int = int.from_bytes(keystream_start[:4], byteorder='big')
    print(f"[+] First keystream value: {first_keystream_int:08x}")
    
    # Step 3: Decrypt the entire file using the predictable LCG
    print("[+] Decrypting file...")
    cracker = AuguryCracker(first_keystream_int)
    decrypted_data = cracker.decrypt(encrypted_hex)
    
    # Step 4: Save the decrypted file
    with open('decrypted_flag.png', 'wb') as f:
        f.write(decrypted_data)
    print("[+] Decrypted file saved as 'decrypted_flag.png'")
    
    # Verify it's a valid PNG
    if decrypted_data[:8] == png_header:
        print("[✓] Success! File is a valid PNG")
    else:
        print("[-] Warning: File doesn't have proper PNG header")
    
    # Try to extract flag from text as well
    try:
        text = decrypted_data.decode('utf-8', errors='ignore')
        if 'bctf' in text.lower():
            print("[+] Flag found in text!")
            flag_match = re.search(r'bctf\{[^}]+\}', text, re.IGNORECASE)
            if flag_match:
                print(f"\n🎉 FLAG: {flag_match.group()}\n")
    except:
        pass
    
    print("\n[+] Open 'decrypted_flag.png' to see the flag!")

if __name__ == "__main__":
    main()