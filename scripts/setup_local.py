"""Interactive local bootstrap; no shared passwords or encryption keys in source."""
import base64
import getpass
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.pwa.security import password_hash


def main():
    target = ROOT / ".env"
    if target.exists():
        raise SystemExit(".env already exists; edit it explicitly instead of replacing existing keys.")
    password = getpass.getpass("New local administrator password (minimum 14 characters): ")
    if len(password) < 14 or password != getpass.getpass("Confirm password: "):
        raise SystemExit("Passwords must match and have at least 14 characters.")
    content = f"VAULT_OPERATOR_USERNAME=admin\nVAULT_OPERATOR_PASSWORD_HASH='{password_hash(password)}'\nVAULT_ENCRYPTION_KEY={base64.b64encode(os.urandom(32)).decode()}\nVAULT_KEY_ID=primary-v1\nAPP_ORIGIN=http://localhost:8502\n"
    target.write_text(content, encoding="utf-8")
    print("Local settings saved in ignored .env. Back up the encryption key securely. Start: python -m uvicorn app:app --port 8502")


if __name__ == "__main__":
    main()
