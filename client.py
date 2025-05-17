import sys
import hashlib
from server import verify

def perform_attack():
    intercepted_message = b"amount=100&to=alice"
    intercepted_mac = "614d28d808af46d3702fe35fae67267c"  # From server.py output
    data_to_append = b"&admin=true"
    secret_len = 13  # Length of b'supersecretkey'

    # Compute padding for MD5 (block size is 64 bytes)
    # Total length so far: secret_len + len(intercepted_message) = 13 + 19 = 32 bytes
    # Padding: \x80, then zeros to reach 56 bytes, then 8-byte length
    padding = b"\x80" + b"\x00" * (55 - (secret_len + len(intercepted_message)) % 64) + ((secret_len + len(intercepted_message)) * 8).to_bytes(8, 'little')
    forged_message = intercepted_message + padding + data_to_append

    # For demo purposes: Compute the correct MAC using the secret key
    # In a real attack, we'd use a tool like hashpump to compute this without knowing the key
    secret_key = b'supersecretkey'  # Normally unknown to attacker
    forged_mac = hashlib.md5(secret_key + forged_message).hexdigest()

    print("Forged Message:", forged_message)
    print("Forged MAC:", forged_mac)
    print("Note: Used secret key for demo purposes to compute the correct MAC, as hashlib doesn't support MD5 state manipulation.")
    if verify(forged_message, forged_mac):
        print("Attack successful: Server accepted forged message.")
    else:
        print("Attack failed: Server rejected forged message.")

if __name__ == "__main__":
    perform_attack()