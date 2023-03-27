# Usage:
#
# in one of your test files add:
#    from axantir.permissions.testing import *  # noqa: F401,F403
#
# or, if you just need a clean registry fixture:
#    from axantir.permissions.testing import clean_permission_registry

from typing import Generator

import pytest
from pytest_mock import MockerFixture

from .registry import registry


@pytest.fixture()
def clean_permisison_registry(mocker: MockerFixture) -> Generator[None, None, None]:
    from axantir.permissions.registry import Registry

    registry = Registry()

    mocker.patch("axantir.permissions.actions.get_registry", return_value=registry)
    mocker.patch("axantir.permissions.models.get_registry", return_value=registry)
    yield


def test_registry_populated() -> None:
    assert registry.get_all_permissions(), (
        "No permissions defined.  Make sure to import permission definitions before importing "
        "axantir.permissions.testing"
    )

    assert registry.get_all_target_policies(), (
        "No policies defined.  Make sure to import permission definitions before importing "
        "axantir.permissions.testing"
    )


@pytest.mark.parametrize(
    "permission_id", [p.id for p in registry.get_all_permissions()]
)
def test_permissions_all_have_policies(permission_id: str) -> None:
    permission = registry.permissions_by_id.get(permission_id)
    assert permission

    policies = registry.policies_by_permission.get(permission)
    assert (
        policies
    ), f"Could not find any policies implementing permission `{permission_id}`"
