# Message Integrity Attack (MAC Forgery) Demo

## Overview
This project demonstrates a length extension attack on a naive MAC construction and shows how to mitigate it using HMAC.

## Files
- `server.py`: Insecure server using MAC = MD5(secret || message)
- `client.py`: Attacker script performing a length extension attack
- `server_hmac.py`: Secure server using HMAC
- `writeup_background.md`: Background study template
- `writeup_mitigation.md`: Mitigation explanation template

## Setup
1. Install dependencies:
   ```bash
   pip install hashpumpy
   ```
2. (Optional) Use a virtual environment for isolation.

## Usage
### 1. Run the Insecure Server
```bash
python server.py
```
- Note the output: original message and MAC.

### 2. Perform the Attack
- Edit `client.py` and set `intercepted_mac` to the MAC from `server.py` output.
- Run the attacker script:
```bash
python client.py
```
- If successful, you'll see a forged message and valid MAC.

### 3. Run the Secure Server
```bash
python server_hmac.py
```
- The same attack will fail against this server.

## Writeups
- Fill in `writeup_background.md` and `writeup_mitigation.md` for your report.

## References
- [Length Extension Attack](https://en.wikipedia.org/wiki/Length_extension_attack)
- [HMAC](https://en.wikipedia.org/wiki/HMAC) 