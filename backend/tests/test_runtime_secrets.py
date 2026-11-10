import pytest

from app.security import validate_runtime_secrets


@pytest.mark.parametrize("jwt_secret,webhook_secret", [
    ("change-this-before-exposure-1234567890", "long-unique-webhook-secret-1234567890"),
    ("demo-secret-change-before-exposure-1234567890", "long-unique-webhook-secret-1234567890"),
    ("short", "long-unique-webhook-secret-1234567890"),
    ("distinct-long-jwt-secret-1234567890", "change-webhook-secret"),
    ("same-secret-1234567890123456789012345", "same-secret-1234567890123456789012345"),
])
def test_connected_rejects_weak_or_public_secrets(jwt_secret, webhook_secret):
    with pytest.raises(RuntimeError, match="CONNECTED требует"):
        validate_runtime_secrets("CONNECTED", jwt_secret, webhook_secret)


def test_connected_accepts_distinct_secrets_and_demo_keeps_local_defaults():
    validate_runtime_secrets("CONNECTED", "jwt-for-connected-12345678901234567890",
                             "webhook-for-connected-1234567890123456")
    validate_runtime_secrets("DEMO", "demo-secret-change-before-exposure-1234567890",
                             "demo-webhook-change-before-exposure")
