from core.config import SHA_256_HASHES, DIRECTORIES
from install import install  
from main import Vanguard
import hashlib
import os
import hmac

def verify_signature(file_path: str, hash: str) -> bool:
    """Verifies the signature of a file.

    Args:
        file_path (str): The path to the file.
        hash (str): The expected hash value.

    Returns:
        bool: True if the signature is valid
    """
    if not os.path.isfile(file_path):
        return False
    
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    computed_hash = sha256_hash.hexdigest()
    
    if hmac.compare_digest(computed_hash, hash):
        return True
    return False

def main():
    for key, val in DIRECTORIES.items():
        if not verify_signature(val, SHA_256_HASHES[key]):
            print(f"[ERROR] Invalid file signature (in {val}).\nWould you like to redownload files? (y/n/ignore)")
            choice = input("=>").lower()
            if choice == "y":
                install()
            elif choice == "ignore":
                pass
            else:
                exit(1)
    
    app = Vanguard()
    app.run()

if __name__ == "__main__":
    main()
            