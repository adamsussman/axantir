from typing import Any, List, Optional

import pytest
from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase, mapped_column
from sqlalchemy.sql.elements import ColumnElement

from axantir.context import ContextOriginEnum, SecurityContext
from axantir.exceptions import BadSecurityContextExpectation
from axantir.permissions import (
    Permission,
    TargetPolicy,
    has_permissions,
    sqla_filter_for_permissions,
)
from axantir.permissions.registry import Registry


@pytest.fixture
def registry() -> Registry:
    from axantir.permissions.registry import registry

    return registry


def test_registry_register_permission(registry: Registry) -> None:
    perm = Permission(
        name="testperm",
        target_type="foo",
    )

    assert registry.permissions_by_id.get(perm.id) == perm
    assert registry.permissions_by_target["foo"] == set([perm])
    assert registry.get_all_permissions() == [perm]


def test_registry_double_register_permission() -> None:
    Permission(
        name="testperm",
        target_type="foo",
    )
    with pytest.raises(ValueError) as e:
        Permission(name="testperm", target_type="foo")

    assert str(e.value) == "Duplicate permission `foo:testperm`"


def test_registry_register_non_permission(registry: Registry) -> None:
    with pytest.raises(TypeError):
        registry.register_permission("foo")  # type: ignore


def test_registry_register_policy(registry: Registry) -> None:
    class TestPolicy(TargetPolicy):
        def has_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> bool:
            return False
            ...

        def sqla_filter_for_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> Optional[ColumnElement]:
            return None

    TARGET_TYPE = "test_target"

    PERM = Permission(
        name="testperm",
        target_type=TARGET_TYPE,
    )

    policy = TestPolicy(
        target_type=TARGET_TYPE,
        target_classes=[str, list],
        target_permissions=[PERM],
    )

    assert registry.policies_by_target.get(policy.target_type) == {policy}
    assert registry.get_all_target_policies() == [policy]


def test_registry_double_register_policy() -> None:
    class TestPolicy(TargetPolicy):
        def has_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> bool:
            return False
            ...

        def sqla_filter_for_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> Optional[ColumnElement]:
            return None

    TARGET_TYPE = "test_target"

    PERM = Permission(
        name="testperm",
        target_type=TARGET_TYPE,
    )

    TestPolicy(
        target_type=TARGET_TYPE,
        target_classes=[str, list],
        target_permissions=[PERM],
    )

    with pytest.raises(ValueError) as e:
        TestPolicy(
            target_type=TARGET_TYPE,
            target_classes=[str, list],
            target_permissions=[PERM],
        )

    assert str(e.value) == "Duplicate policy `test_target`"


def test_registry_register_non_policy(registry: Registry) -> None:
    with pytest.raises(TypeError):
        registry.register_target_policy("foo")  # type: ignore


@pytest.mark.parametrize("granted", [False, True])
def test_simple_permission_check(granted: bool) -> None:
    TARGET_TYPE = "thingy"

    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=TARGET_TYPE,
    )

    class TestContext(SecurityContext):
        @property
        def is_admin(self) -> bool:
            return False

        def audit_data(self) -> dict:
            return {}

    class Thingy(object):
        ...

    class AlwaysGrantPolicy(TargetPolicy):
        def has_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> bool:
            return granted

        def sqla_filter_for_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> Optional[ColumnElement]:
            return None

    AlwaysGrantPolicy(
        target_type=TARGET_TYPE,
        target_classes=[Thingy],
        target_permissions=[CAN_MESS_WITH_THINGY],
    )

    assert granted == has_permissions(
        security_context=TestContext(origin=ContextOriginEnum.internal, scopes=["*"]),
        permissions=[CAN_MESS_WITH_THINGY],
        targets=[Thingy()],
    )


@pytest.mark.parametrize("granted", [False, True])
def test_simple_sqla_filter(granted: bool) -> None:
    TARGET_TYPE = "thingy"

    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=TARGET_TYPE,
    )

    class TestContext(SecurityContext):
        @property
        def is_admin(self) -> bool:
            return False

        def audit_data(self) -> dict:
            return {}

    class Thingy(DeclarativeBase):
        thingy_id = mapped_column(String(), primary_key=True)
        field1 = mapped_column(String())

    class AlwaysGrantPolicy(TargetPolicy):
        def has_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> bool:
            return granted

        def sqla_filter_for_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> Optional[ColumnElement]:
            if not granted:
                return None

            return Thingy.field1 == "foo"

    AlwaysGrantPolicy(
        target_type=TARGET_TYPE,
        target_classes=[Thingy],
        target_permissions=[CAN_MESS_WITH_THINGY],
    )

    filt = sqla_filter_for_permissions(
        security_context=TestContext(origin=ContextOriginEnum.internal, scopes=["*"]),
        permissions=[CAN_MESS_WITH_THINGY],
        targets=[Thingy],
    )
    if granted:
        assert isinstance(filt, ColumnElement)
    else:
        assert filt is None


def test_permission_context_failure() -> None:
    TARGET_TYPE = "thingy"

    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=TARGET_TYPE,
    )

    class TestContext(SecurityContext):
        @property
        def is_admin(self) -> bool:
            return False

        def audit_data(self) -> dict:
            return {}

    class Thingy(object):
        ...

    class AlwaysGrantPolicy(TargetPolicy):
        def has_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> bool:
            return security_context.user.is_someone_special

        def sqla_filter_for_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> Optional[ColumnElement]:
            if security_context.user.is_someone_special:
                return None

            return None

    AlwaysGrantPolicy(
        target_type=TARGET_TYPE,
        target_classes=[Thingy],
        target_permissions=[CAN_MESS_WITH_THINGY],
    )

    with pytest.raises(BadSecurityContextExpectation):
        has_permissions(
            security_context=TestContext(
                origin=ContextOriginEnum.internal, scopes=["*"]
            ),
            permissions=[CAN_MESS_WITH_THINGY],
            targets=[Thingy()],
        )

    with pytest.raises(BadSecurityContextExpectation):
        sqla_filter_for_permissions(
            security_context=TestContext(
                origin=ContextOriginEnum.internal, scopes=["*"]
            ),
            permissions=[CAN_MESS_WITH_THINGY],
            targets=[Thingy],
        )


@pytest.mark.filterwarnings("ignore: Permission")
def test_permission_with_no_policy() -> None:
    TARGET_TYPE = "thingy"

    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=TARGET_TYPE,
    )

    class TestContext(SecurityContext):
        @property
        def is_admin(self) -> bool:
            return False

        def audit_data(self) -> dict:
            return {}

    class Thingy(object):
        ...

    with pytest.warns(UserWarning) as w:
        assert not has_permissions(
            security_context=TestContext(
                origin=ContextOriginEnum.internal, scopes=["*"]
            ),
            permissions=[CAN_MESS_WITH_THINGY],
            targets=[Thingy()],
        )

    assert len(w) == 1
    assert (
        str(w[0].message)
        == "Permission `thingy:can_mess_with` has target_type with no policy: `thingy`"
    )

    with pytest.warns(UserWarning) as w:
        assert (
            sqla_filter_for_permissions(
                security_context=TestContext(
                    origin=ContextOriginEnum.internal, scopes=["*"]
                ),
                permissions=[CAN_MESS_WITH_THINGY],
                targets=[Thingy],
            )
            is None
        )

    assert len(w) == 1
    assert (
        str(w[0].message)
        == "Permission `thingy:can_mess_with` has target_type with no policy: `thingy`"
    )


@pytest.mark.filterwarnings("ignore: No permission requested has a policy")
def test_permission_with_unknown_target_classes() -> None:
    TARGET_TYPE = "thingy"

    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=TARGET_TYPE,
    )

    class TestContext(SecurityContext):
        @property
        def is_admin(self) -> bool:
            return False

        def audit_data(self) -> dict:
            return {}

    class Thingy(DeclarativeBase):
        thingy_id = mapped_column(String(), primary_key=True)
        field1 = mapped_column(String())

    class AlwaysGrantPolicy(TargetPolicy):
        def has_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> bool:
            return True

        def sqla_filter_for_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> Optional[ColumnElement]:
            return Thingy.field1 == "foo"

    AlwaysGrantPolicy(
        target_type=TARGET_TYPE,
        target_classes=[Thingy],
        target_permissions=[CAN_MESS_WITH_THINGY],
    )

    with pytest.warns(UserWarning) as w:
        assert not has_permissions(
            security_context=TestContext(
                origin=ContextOriginEnum.internal, scopes=["*"]
            ),
            permissions=[CAN_MESS_WITH_THINGY],
            targets=["foo"],
        )
    assert len(w) == 1
    assert (
        str(w[0].message)
        == "No permission requested has a policy for target class `str`"
    )

    with pytest.warns(UserWarning) as w:
        assert (
            sqla_filter_for_permissions(
                security_context=TestContext(
                    origin=ContextOriginEnum.internal, scopes=["*"]
                ),
                permissions=[CAN_MESS_WITH_THINGY],
                targets=["foo"],
            )
            is None
        )

    assert len(w) == 2
    assert (
        str(w[0].message)
        == "No permission requested has a policy for target class `str`"
    )
    assert (
        str(w[1].message)
        == "Targets to `sqla_filter_for_permissions` should be classes, not instances"
    )


@pytest.mark.filterwarnings("ignore: No permission requested has a policy")
def test_permissions_mismatch_target() -> None:
    TARGET_TYPE = "thingy"

    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=TARGET_TYPE,
    )

    class TestContext(SecurityContext):
        @property
        def is_admin(self) -> bool:
            return False

        def audit_data(self) -> dict:
            return {}

    class Thingy(DeclarativeBase):
        thingy_id = mapped_column(String(), primary_key=True)
        field1 = mapped_column(String())

    class OtherThing(object):
        ...

    class AlwaysGrantPolicy(TargetPolicy):
        def has_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> bool:
            return True

        def sqla_filter_for_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> Optional[ColumnElement]:
            return Thingy.field1 == "foo"

    AlwaysGrantPolicy(
        target_type=TARGET_TYPE,
        target_classes=[Thingy],
        target_permissions=[CAN_MESS_WITH_THINGY],
    )

    assert not has_permissions(
        security_context=TestContext(origin=ContextOriginEnum.internal, scopes=["*"]),
        permissions=[CAN_MESS_WITH_THINGY],
        targets=[OtherThing],
    )

    assert (
        sqla_filter_for_permissions(
            security_context=TestContext(
                origin=ContextOriginEnum.internal, scopes=["*"]
            ),
            permissions=[CAN_MESS_WITH_THINGY],
            targets=[OtherThing],
        )
        is None
    )


def test_permissions_no_targets() -> None:
    TARGET_TYPE = "thingy"

    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=TARGET_TYPE,
    )

    class TestContext(SecurityContext):
        @property
        def is_admin(self) -> bool:
            return False

        def audit_data(self) -> dict:
            return {}

    class Thingy(DeclarativeBase):
        thingy_id = mapped_column(String(), primary_key=True)
        field1 = mapped_column(String())

    class AlwaysGrantPolicy(TargetPolicy):
        def has_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> bool:
            return True

        def sqla_filter_for_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> Optional[ColumnElement]:
            return Thingy.field1 == "foo"

    AlwaysGrantPolicy(
        target_type=TARGET_TYPE,
        target_classes=[Thingy],
        target_permissions=[CAN_MESS_WITH_THINGY],
    )

    assert not has_permissions(
        security_context=TestContext(origin=ContextOriginEnum.internal, scopes=["*"]),
        permissions=[CAN_MESS_WITH_THINGY],
        targets=[],
    )

    assert (
        sqla_filter_for_permissions(
            security_context=TestContext(
                origin=ContextOriginEnum.internal, scopes=["*"]
            ),
            permissions=[CAN_MESS_WITH_THINGY],
            targets=[],
        )
        is None
    )


def test_no_policy_for_permission() -> None:
    TARGET_TYPE = "thingy"

    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=TARGET_TYPE,
    )

    CAN_DO_OTHER_THING = Permission(
        name="do_whatever",
        target_type=TARGET_TYPE,
    )

    class TestContext(SecurityContext):
        @property
        def is_admin(self) -> bool:
            return False

        def audit_data(self) -> dict:
            return {}

    class Thingy(object):
        ...

    class AlwaysGrantPolicy(TargetPolicy):
        def has_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> bool:
            return True

        def sqla_filter_for_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> Optional[ColumnElement]:
            return True  # type: ignore

    AlwaysGrantPolicy(
        target_type=TARGET_TYPE,
        target_classes=[Thingy],
        target_permissions=[CAN_MESS_WITH_THINGY],
    )

    with pytest.warns(UserWarning) as w:
        assert not has_permissions(
            security_context=TestContext(
                origin=ContextOriginEnum.internal, scopes=["*"]
            ),
            permissions=[CAN_DO_OTHER_THING],
            targets=[Thingy()],
        )

    assert len(w) == 1
    assert (
        str(w[0].message)
        == "No permission requested has a policy for target class `Thingy`"
    )

    with pytest.warns(UserWarning) as w:
        assert (
            sqla_filter_for_permissions(
                security_context=TestContext(
                    origin=ContextOriginEnum.internal, scopes=["*"]
                ),
                permissions=[CAN_DO_OTHER_THING],
                targets=[Thingy],
            )
            is None
        )

    assert len(w) == 1
    assert (
        str(w[0].message)
        == "No permission requested has a policy for target class `Thingy`"
    )


def test_multiple_policies_for_target() -> None:
    TARGET_TYPE = "thingy"

    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=TARGET_TYPE,
    )

    CAN_DO_OTHER_THING = Permission(
        name="do_whatever",
        target_type=TARGET_TYPE,
    )

    class TestContext(SecurityContext):
        @property
        def is_admin(self) -> bool:
            return False

        def audit_data(self) -> dict:
            return {}

    class Thingy(object):
        ...

    class AlwaysGrantPolicy(TargetPolicy):
        def has_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> bool:
            return True

        def sqla_filter_for_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> Optional[ColumnElement]:
            return True  # type: ignore

    class AlwaysDenyPolicy(TargetPolicy):
        def has_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> bool:
            return False

        def sqla_filter_for_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> Optional[ColumnElement]:
            return None

    AlwaysGrantPolicy(
        target_type=TARGET_TYPE,
        target_classes=[Thingy],
        target_permissions=[CAN_MESS_WITH_THINGY],
    )

    AlwaysDenyPolicy(
        target_type=TARGET_TYPE,
        target_classes=[Thingy],
        target_permissions=[CAN_DO_OTHER_THING],
    )

    assert has_permissions(
        security_context=TestContext(origin=ContextOriginEnum.internal, scopes=["*"]),
        permissions=[CAN_MESS_WITH_THINGY],
        targets=[Thingy()],
    )

    assert not has_permissions(
        security_context=TestContext(origin=ContextOriginEnum.internal, scopes=["*"]),
        permissions=[CAN_DO_OTHER_THING],
        targets=[Thingy()],
    )

    assert not has_permissions(
        security_context=TestContext(origin=ContextOriginEnum.internal, scopes=["*"]),
        permissions=[CAN_MESS_WITH_THINGY, CAN_DO_OTHER_THING],
        targets=[Thingy()],
    )

    assert (
        sqla_filter_for_permissions(
            security_context=TestContext(
                origin=ContextOriginEnum.internal, scopes=["*"]
            ),
            permissions=[CAN_MESS_WITH_THINGY],
            targets=[Thingy],
        )
        is not None
    )

    assert (
        sqla_filter_for_permissions(
            security_context=TestContext(
                origin=ContextOriginEnum.internal, scopes=["*"]
            ),
            permissions=[CAN_DO_OTHER_THING],
            targets=[Thingy],
        )
        is None
    )

    assert (
        sqla_filter_for_permissions(
            security_context=TestContext(
                origin=ContextOriginEnum.internal, scopes=["*"]
            ),
            permissions=[CAN_MESS_WITH_THINGY, CAN_DO_OTHER_THING],
            targets=[Thingy],
        )
        is None
    )


def test_multiple_policies_for_target_with_overlap() -> None:
    pass


def test_sqla_filter_on_instances() -> None:
    pass


def test_policy_target_mismatch() -> None:
    TARGET_TYPE = "thingy"

    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=TARGET_TYPE,
    )

    class TestContext(SecurityContext):
        @property
        def is_admin(self) -> bool:
            return False

        def audit_data(self) -> dict:
            return {}

    class Thingy(object):
        ...

    class AlwaysGrantPolicy(TargetPolicy):
        def has_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> bool:
            return True

        def sqla_filter_for_permissions(
            self,
            security_context: SecurityContext,
            permissions: List[Permission],
            targets: List[Any],
        ) -> Optional[ColumnElement]:
            return True  # type: ignore

    with pytest.raises(Exception) as e:
        AlwaysGrantPolicy(
            target_type="foo",
            target_classes=[Thingy],
            target_permissions=[CAN_MESS_WITH_THINGY],
        )

    assert "does not match the policy target type" in str(e.value)


# multi-perms
# multi-targets -> make sure unhandled target type is not merged with other successes
# multi-target-types
# scopes
# sqla_filter_for_permissions with target instances
# has_permissions/sqla_filter_for_permissions with a permission for which no policy exists
# multiple policies per target type, overlap and not overlap
