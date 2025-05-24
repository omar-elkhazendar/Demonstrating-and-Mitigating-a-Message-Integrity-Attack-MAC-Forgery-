import hashlib

SECRET_KEY = b'YoussefSaeedthabet'  # Unknown to attacker

def generate_mac(message: bytes) -> str:
    # Naive MAC: hash(secret || message)
    return hashlib.md5(SECRET_KEY + message).hexdigest()

def verify(message: bytes, mac: str) -> bool:
    expected_mac = generate_mac(message)
    return mac == expected_mac

def main():
    # Example message
    message = b"hello_world"
    mac = generate_mac(message)

    print("=== Server Simulation ===")
    print(f"Original message: {message.decode()}")
    print(f"MAC: {mac}")
    print("\n--- Verifying legitimate message ---")
    if verify(message, mac):
        print("MAC verified successfully. Message is authentic.\n")

    # Simulated attacker-forged message
    forged_message = b"amount=100&to=alice" + b"&admin=true"
    forged_mac = mac  # Attacker provides same MAC (initially)

    print("--- Verifying forged message ---")
    if verify(forged_message, forged_mac):
        print("MAC verified successfully (unexpected).")
    else:
        print("MAC verification failed (as expected).")

if __name__ == "__main__":
    main()

    # --- Manual test for length extension attack ---
    # Use the exact forged message and MAC from client.py output
    forged_message = bytes.fromhex("616d6f756e743d31303026746f3d616c6963658000000000000000000000000000000000000000000010010000000000002661646d696e3d74727565")
    forged_mac = 'd8284d61d346af085fe32f707c2667ae'
    print("\n--- Manual verification of forged message (with padding) ---")
    print("Forged message (hex):", forged_message.hex())
    print("Forged MAC:", forged_mac)
    if verify(forged_message, forged_mac):
        print("[SUCCESS] Forged MAC is valid! (Manual test)")
    else:
        print("[FAIL] Forged MAC is not valid. (Manual test)") 
        
        
        