import pytest

@pytest.fixture(autouse=True)
def default_test_env(monkeypatch):
    # Ensure tests do not accidentally inherit production/external cloud credentials from local .env unless a test explicitly sets them
    for key in ("SUPABASE_URL", "SUPABASE_KEY", "SUPABASE_SERVICE_ROLE_KEY", "CALLMEBOT_API_KEY", "CALLMEBOT_PHONE"):
        monkeypatch.delenv(key, raising=False)
