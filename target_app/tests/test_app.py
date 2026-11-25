"""Tests de la cible : les identifiants ci-dessous sont factices (fixtures)."""
TEST_PASSWORD = "test-password-123"


def test_password_constant():
    assert len(TEST_PASSWORD) > 8
