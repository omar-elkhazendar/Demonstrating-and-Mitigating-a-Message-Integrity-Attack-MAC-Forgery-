import sys
import struct
from server import verify
import pymd5

# Intercepted values (from server.py output)
intercepted_message = b"hello_world"
intercepted_mac = "0cd9bd4e4eb587e2481ec840948b252d"  # From server.py output

# Data attacker wants to append
append_data = b"&admin=true"

# Brute-force key length range
MIN_KEY_LEN = 8
MAX_KEY_LEN = 20

def md5_padding(msg_len):
    pad = b"\x80"
    pad += b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
    pad += struct.pack("<Q", msg_len * 8)
    return pad

def parse_md5_hexdigest(h):
    return struct.unpack('<4I', bytes.fromhex(h))

def perform_attack():
    if not intercepted_mac:
        print("[!] Please set intercepted_mac from server.py output.")
        return
    for key_len in range(MIN_KEY_LEN, MAX_KEY_LEN + 1):
        orig_len = key_len + len(intercepted_message)
        padding = md5_padding(orig_len)
        forged_message = intercepted_message + padding + append_data
        state = parse_md5_hexdigest(intercepted_mac)
        total_len = orig_len + len(padding)
        m = pymd5.md5(state=state, count=total_len*8)
        m.update(append_data)
        forged_mac = m.hexdigest()
        print(f"Trying key length: {key_len}")
        print("Forged message (hex):", forged_message.hex())
        print("Forged MAC:", forged_mac)
        if verify(forged_message, forged_mac):
            print(f"[SUCCESS] Forged MAC is valid! Key length: {key_len}")
            print("Forged message:", forged_message)
            return
        else:
            print("[FAIL] Forged MAC is not valid.")
    print("Tried all key lengths, none succeeded.")

if __name__ == "__main__":
    perform_attack() 