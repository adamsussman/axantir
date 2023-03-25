import pytest


@pytest.fixture(autouse=True)
def clean_audit_log_registry() -> None:
    from axantir.audit.registry import registry

    registry.clear()


@pytest.fixture(autouse=True)
def clean_permissions_registry() -> None:
    from axantir.permissions.registry import registry

    registry.clear()
