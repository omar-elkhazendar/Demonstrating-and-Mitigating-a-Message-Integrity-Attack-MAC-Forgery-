import hashlib
import hmac

SECRET_KEY = b'supersecretkey'

def generate_mac(message: bytes) -> str:
    return hmac.new(SECRET_KEY, message, hashlib.sha256).hexdigest()

def verify(message: bytes, mac: str) -> bool:
    expected_mac = generate_mac(message)
    return hmac.compare_digest(mac, expected_mac)

def main():
    message = b"amount=100&to=alice"
    mac = generate_mac(message)
    print("=== Server Simulation (Secure) ===")
    print(f"Original message: {message.decode()}")
    print(f"MAC: {mac}")
    print("\n--- Verifying legitimate message ---")
    if verify(message, mac):
        print("MAC verified successfully. Message is authentic.\n")
    forged_message = b"amount=100&to=alice&admin=true"
    forged_mac = mac
    print("--- Verifying forged message ---")
    if verify(forged_message, forged_mac):
        print("MAC verified successfully (unexpected).")
    else:
        print("MAC verification failed (as expected).")

if __name__ == "__main__":
    main()