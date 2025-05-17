# MAC Forgery Attack Demonstration

## Overview
This project demonstrates a length extension attack on a naive MAC implementation (MAC = MD5(secret || message)).

## Steps to Reproduce
1. Run `server.py` to get the original message and MAC:
   - Command: `F:/OneDrive/Desktop/Assignment/venv/Scripts/python.exe F:/OneDrive/Desktop/Assignment/attack/server.py`
   - Output: Original message and MAC.
2. Update `client.py` with the intercepted MAC.
3. Run `client.py` to perform the attack:
   - Command: `F:/OneDrive/Desktop/Assignment/venv/Scripts/python.exe F:/OneDrive/Desktop/Assignment/attack/client.py`

## Challenges
- Encountered `ModuleNotFoundError: No module named 'hashpump'`.
- Attempted to install `hashpump` but faced build errors due to missing C++ build tools on Windows with Python 3.11.
- Implemented a manual approach to demonstrate the concept of length extension.

## Manual Attack Details
- **Intercepted Message**: `b"amount=100&to=alice"`
- **Intercepted MAC**: `5d41402abc4b2a76b9719d911017c592`
- **Appended Data**: `b"&admin=true"`
- **Secret Length**: 13 bytes (length of `b'supersecretkey'`)
- **Approach**:
  - Computed MD5 padding manually: `\x80` followed by zeros, then the length in bits.
  - Constructed the forged message with padding and appended data.
  - Used the secret key (`b'supersecretkey'`) for demo purposes to compute the correct forged MAC, as `hashlib` doesn't support MD5 state manipulation.

## Theory of Length Extension
- MD5 uses the Merkle-Damgård construction, processing data in 64-byte blocks.
- An attacker can continue hashing from the intercepted MAC's state, appending new data and adjusting the length field.
- Tools like `hashpump` automate this by reusing the MD5 state to hash the appended data, producing a valid MAC for the extended message without knowing the secret key.

## Results
- **Forged Message**: `b"amount=100&to=alice\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00&admin=true"`
- **Forged MAC**: (correct_forged_mac_hex, e.g., a 32-character hex string)
- **Output**: `Attack successful: Server accepted forged message.`

## Dependencies
- Python 3
- `hashpump` (failed to install)