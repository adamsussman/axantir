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


class Thingy(object):
    pass


class ThingyModel(DeclarativeBase):
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
        return True  # type: ignore


class AlwaysGrantPolicyThingyModel(TargetPolicy):
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
        return ThingyModel.field1 == "foo"


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


class Context(SecurityContext):
    def audit_data(self) -> dict:
        return {}


@pytest.fixture
def registry() -> Registry:
    from axantir.permissions.registry import registry

    return registry


def test_registry_register_permission(registry: Registry) -> None:
    perm = Permission(
        name="testperm",
        target_type=Thingy,
    )

    assert registry.permissions_by_id.get(perm.id) == perm
    assert registry.get_all_permissions() == [perm]


def test_register_permission_bad_target() -> None:
    with pytest.raises(ValueError):
        Permission(name="testperm", target_type="foo")


def test_registry_double_register_permission() -> None:
    Permission(
        name="testperm",
        target_type=Thingy,
    )
    with pytest.raises(ValueError) as e:
        Permission(name="testperm", target_type=Thingy)

    assert str(e.value) == "Duplicate permission `thingy:testperm`"


def test_registry_register_non_permission(registry: Registry) -> None:
    with pytest.raises(TypeError):
        registry.register_permission("foo")  # type: ignore


def test_registry_register_policy(registry: Registry) -> None:
    PERM = Permission(
        name="testperm",
        target_type=Thingy,
    )

    policy = AlwaysGrantPolicy(
        name="test_policy",
        target_permissions=[PERM],
    )

    assert registry.policies_by_permission.get(PERM) == {policy}
    assert registry.get_all_target_policies() == [policy]


def test_registry_double_register_policy() -> None:
    PERM = Permission(
        name="testperm",
        target_type=Thingy,
    )

    AlwaysDenyPolicy(
        name="test_policy",
        target_permissions=[PERM],
    )

    with pytest.raises(ValueError) as e:
        AlwaysDenyPolicy(
            name="test_policy",
            target_permissions=[PERM],
        )

    assert str(e.value) == "Duplicate policy `thingy:testperm:test_policy`"


def test_registry_register_non_policy(registry: Registry) -> None:
    with pytest.raises(TypeError):
        registry.register_target_policy("foo")  # type: ignore


@pytest.mark.parametrize("granted", [False, True])
def test_simple_permission_check(granted: bool) -> None:
    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=Thingy,
    )

    policy_class = AlwaysGrantPolicy if granted else AlwaysDenyPolicy
    policy_class(
        name="test_policy",
        target_permissions=[CAN_MESS_WITH_THINGY],
    )

    assert granted == has_permissions(
        security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
        permissions=[CAN_MESS_WITH_THINGY],
        targets=[Thingy()],
    )


@pytest.mark.parametrize("granted", [False, True])
def test_simple_sqla_filter(granted: bool) -> None:
    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=ThingyModel,
    )

    policy_class = AlwaysGrantPolicyThingyModel if granted else AlwaysDenyPolicy
    policy_class(
        name="test_policy",
        target_permissions=[CAN_MESS_WITH_THINGY],
    )

    filt = sqla_filter_for_permissions(
        security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
        permissions=[CAN_MESS_WITH_THINGY],
        targets=[ThingyModel],
    )
    if granted:
        assert isinstance(filt, ColumnElement)
    else:
        assert filt is None


def test_permission_context_failure() -> None:
    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=Thingy,
    )

    class Policy(TargetPolicy):
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

    Policy(
        name="test_policy",
        target_permissions=[CAN_MESS_WITH_THINGY],
    )

    with pytest.raises(BadSecurityContextExpectation):
        has_permissions(
            security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
            permissions=[CAN_MESS_WITH_THINGY],
            targets=[Thingy()],
        )

    with pytest.raises(BadSecurityContextExpectation):
        sqla_filter_for_permissions(
            security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
            permissions=[CAN_MESS_WITH_THINGY],
            targets=[Thingy],
        )


@pytest.mark.filterwarnings("ignore: Permission")
def test_permission_with_no_policy() -> None:
    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=Thingy,
    )

    with pytest.warns(UserWarning) as w:
        assert not has_permissions(
            security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
            permissions=[CAN_MESS_WITH_THINGY],
            targets=[Thingy()],
        )

    assert len(w) == 1
    assert str(w[0].message) == "No policy found for permission: `can_mess_with`"

    with pytest.warns(UserWarning) as w:
        assert (
            sqla_filter_for_permissions(
                security_context=Context(
                    origin=ContextOriginEnum.internal, scopes=["*"]
                ),
                permissions=[CAN_MESS_WITH_THINGY],
                targets=[Thingy],
            )
            is None
        )

    assert len(w) == 1
    assert str(w[0].message) == "No policy found for permission: `can_mess_with`"


@pytest.mark.filterwarnings("ignore: No permission requested has a policy")
def test_permission_with_unknown_target_classes() -> None:
    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=Thingy,
    )

    AlwaysGrantPolicyThingyModel(
        name="test_policy",
        target_permissions=[CAN_MESS_WITH_THINGY],
    )

    with pytest.warns(UserWarning) as w:
        assert not has_permissions(
            security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
            permissions=[CAN_MESS_WITH_THINGY],
            targets=["foo"],
        )
    assert len(w) == 1
    assert (
        str(w[0].message) == "No targets found for permission(s): thingy:can_mess_with"
    )

    with pytest.warns(UserWarning) as w:
        assert (
            sqla_filter_for_permissions(
                security_context=Context(
                    origin=ContextOriginEnum.internal, scopes=["*"]
                ),
                permissions=[CAN_MESS_WITH_THINGY],
                targets=["foo"],
            )
            is None
        )

    assert len(w) == 2
    assert (
        str(w[0].message) == "No targets found for permission(s): thingy:can_mess_with"
    )
    assert (
        str(w[1].message)
        == "Targets to `sqla_filter_for_permissions` should be classes, not instances"
    )


@pytest.mark.filterwarnings("ignore: No targets found for permission")
def test_permissions_mismatch_target() -> None:
    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=Thingy,
    )

    class OtherThing(object):
        ...

    AlwaysGrantPolicyThingyModel(
        name="test_policy",
        target_permissions=[CAN_MESS_WITH_THINGY],
    )

    assert not has_permissions(
        security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
        permissions=[CAN_MESS_WITH_THINGY],
        targets=[OtherThing],
    )

    assert (
        sqla_filter_for_permissions(
            security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
            permissions=[CAN_MESS_WITH_THINGY],
            targets=[OtherThing],
        )
        is None
    )


def test_permissions_no_targets() -> None:
    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=Thingy,
    )

    AlwaysGrantPolicyThingyModel(
        name="test_policy",
        target_permissions=[CAN_MESS_WITH_THINGY],
    )

    with pytest.warns(UserWarning) as w:
        assert not has_permissions(
            security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
            permissions=[CAN_MESS_WITH_THINGY],
            targets=[],
        )

    assert len(w) == 1
    assert (
        str(w[0].message) == "No targets found for permission(s): thingy:can_mess_with"
    )

    with pytest.warns(UserWarning) as w:
        assert (
            sqla_filter_for_permissions(
                security_context=Context(
                    origin=ContextOriginEnum.internal, scopes=["*"]
                ),
                permissions=[CAN_MESS_WITH_THINGY],
                targets=[],
            )
            is None
        )

    assert len(w) == 1
    assert (
        str(w[0].message) == "No targets found for permission(s): thingy:can_mess_with"
    )


def test_no_policy_for_permission() -> None:
    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=Thingy,
    )

    CAN_DO_OTHER_THING = Permission(
        name="do_whatever",
        target_type=Thingy,
    )

    AlwaysGrantPolicy(
        name="test_policy",
        target_permissions=[CAN_MESS_WITH_THINGY],
    )

    with pytest.warns(UserWarning) as w:
        assert not has_permissions(
            security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
            permissions=[CAN_DO_OTHER_THING],
            targets=[Thingy()],
        )

    assert len(w) == 1
    assert str(w[0].message) == "No policy found for permission: `do_whatever`"

    with pytest.warns(UserWarning) as w:
        assert (
            sqla_filter_for_permissions(
                security_context=Context(
                    origin=ContextOriginEnum.internal, scopes=["*"]
                ),
                permissions=[CAN_DO_OTHER_THING],
                targets=[Thingy],
            )
            is None
        )

    assert len(w) == 1
    assert str(w[0].message) == "No policy found for permission: `do_whatever`"


def test_no_policy_for_target() -> None:
    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=Thingy,
    )

    AlwaysGrantPolicy(
        name="test_policy",
        target_permissions=[CAN_MESS_WITH_THINGY],
    )

    class Thingy2(object):
        pass

    with pytest.warns(UserWarning) as w:
        assert not has_permissions(
            security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
            permissions=[CAN_MESS_WITH_THINGY],
            targets=[Thingy(), Thingy2()],
        )

    assert len(w) == 1
    assert str(w[0].message) == "No policies found for target(s): Thingy2"

    with pytest.warns(UserWarning) as w:
        assert (
            sqla_filter_for_permissions(
                security_context=Context(
                    origin=ContextOriginEnum.internal, scopes=["*"]
                ),
                permissions=[CAN_MESS_WITH_THINGY],
                targets=[Thingy, Thingy2],
            )
            is None
        )

    assert len(w) == 1
    assert str(w[0].message) == "No policies found for target(s): Thingy2"


def test_multiple_policies_for_target() -> None:
    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=Thingy,
    )

    CAN_DO_OTHER_THING = Permission(
        name="do_whatever",
        target_type=Thingy,
    )

    AlwaysGrantPolicy(
        name="test_policy1",
        target_permissions=[CAN_MESS_WITH_THINGY],
    )

    AlwaysDenyPolicy(
        name="test_policy2",
        target_permissions=[CAN_DO_OTHER_THING],
    )

    assert has_permissions(
        security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
        permissions=[CAN_MESS_WITH_THINGY],
        targets=[Thingy()],
    )

    assert not has_permissions(
        security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
        permissions=[CAN_DO_OTHER_THING],
        targets=[Thingy()],
    )

    assert not has_permissions(
        security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
        permissions=[CAN_MESS_WITH_THINGY, CAN_DO_OTHER_THING],
        targets=[Thingy()],
    )

    assert (
        sqla_filter_for_permissions(
            security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
            permissions=[CAN_MESS_WITH_THINGY],
            targets=[Thingy],
        )
        is not None
    )

    assert (
        sqla_filter_for_permissions(
            security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
            permissions=[CAN_DO_OTHER_THING],
            targets=[Thingy],
        )
        is None
    )

    assert (
        sqla_filter_for_permissions(
            security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
            permissions=[CAN_MESS_WITH_THINGY, CAN_DO_OTHER_THING],
            targets=[Thingy],
        )
        is None
    )


def test_multiple_policies_for_target_with_overlap() -> None:
    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=Thingy,
    )

    CAN_DO_OTHER_THING = Permission(
        name="do_whatever",
        target_type=Thingy,
    )

    AlwaysGrantPolicy(
        name="test_policy1",
        target_permissions=[CAN_MESS_WITH_THINGY, CAN_DO_OTHER_THING],
    )

    AlwaysDenyPolicy(
        name="test_policy2",
        target_permissions=[CAN_MESS_WITH_THINGY],
    )

    assert not has_permissions(
        security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
        permissions=[CAN_MESS_WITH_THINGY],
        targets=[Thingy()],
    )

    assert has_permissions(
        security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
        permissions=[CAN_DO_OTHER_THING],
        targets=[Thingy()],
    )

    assert not has_permissions(
        security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
        permissions=[CAN_MESS_WITH_THINGY, CAN_DO_OTHER_THING],
        targets=[Thingy()],
    )

    assert (
        sqla_filter_for_permissions(
            security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
            permissions=[CAN_MESS_WITH_THINGY],
            targets=[Thingy],
        )
        is None
    )

    assert (
        sqla_filter_for_permissions(
            security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
            permissions=[CAN_DO_OTHER_THING],
            targets=[Thingy],
        )
        is not None
    )

    assert (
        sqla_filter_for_permissions(
            security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
            permissions=[CAN_MESS_WITH_THINGY, CAN_DO_OTHER_THING],
            targets=[Thingy],
        )
        is None
    )


def test_sqla_filter_on_instances() -> None:
    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=Thingy,
    )

    AlwaysGrantPolicy(
        name="test_policy1",
        target_permissions=[CAN_MESS_WITH_THINGY],
    )

    with pytest.warns(UserWarning) as w:
        sqla_filter_for_permissions(
            security_context=Context(origin=ContextOriginEnum.internal, scopes=["*"]),
            permissions=[CAN_MESS_WITH_THINGY],
            targets=[Thingy()],
        )

    assert len(w) == 1
    assert (
        str(w[0].message)
        == "Targets to `sqla_filter_for_permissions` should be classes, not instances"
    )


def test_scopes_mismatch() -> None:
    CAN_MESS_WITH_THINGY = Permission(
        name="can_mess_with",
        target_type=Thingy,
    )

    CAN_DO_OTHER_THING = Permission(
        name="do_whatever",
        target_type=Thingy,
    )

    AlwaysGrantPolicy(
        name="test_policy",
        target_permissions=[CAN_MESS_WITH_THINGY, CAN_DO_OTHER_THING],
    )

    assert not has_permissions(
        security_context=Context(
            origin=ContextOriginEnum.internal, scopes=[CAN_DO_OTHER_THING.id]
        ),
        permissions=[CAN_MESS_WITH_THINGY],
        targets=[Thingy()],
    )

    assert (
        sqla_filter_for_permissions(
            security_context=Context(
                origin=ContextOriginEnum.internal, scopes=[CAN_DO_OTHER_THING.id]
            ),
            permissions=[CAN_MESS_WITH_THINGY],
            targets=[Thingy()],
        )
        is None
    )


# multi-perms
# multi-targets -> make sure unhandled target type is not merged with other successes
# multi-target-types
