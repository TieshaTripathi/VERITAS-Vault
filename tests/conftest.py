import base64
import os
import pytest

@pytest.fixture(autouse=True)
def default_test_env(monkeypatch):
    # Ensure tests do not accidentally inherit production/external cloud credentials from local .env unless a test explicitly sets them
    for key in ("SUPABASE_URL", "SUPABASE_KEY", "SUPABASE_SERVICE_ROLE_KEY", "CALLMEBOT_API_KEY", "CALLMEBOT_PHONE",
                "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "PUSHOVER_APP_TOKEN", "PUSHOVER_USER_KEY"):
        monkeypatch.delenv(key, raising=False)
    if not os.environ.get("VAULT_ENCRYPTION_KEY"):
        monkeypatch.setenv("VAULT_ENCRYPTION_KEY", base64.b64encode(b"K" * 32).decode())

