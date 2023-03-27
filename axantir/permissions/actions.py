import inspect
import operator
import warnings
from collections import defaultdict
from functools import reduce
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple, Type

from sqlalchemy.sql.elements import ColumnElement

from ..context import SecurityContext
from .models import Permission, TargetPolicy

if TYPE_CHECKING:  # pragma: no cover
    from .registry import Registry


# For testing, mock here
def get_registry() -> "Registry":  # pragma: no cover
    from .registry import registry

    return registry


def has_permissions(
    security_context: SecurityContext,
    permissions: List[Permission],
    targets: List[Any],
) -> bool:
    permissions = _filter_permissions_by_scopes(
        scopes=security_context.scopes, permissions=permissions
    )
    if not permissions:
        return False

    policy_permissions, policy_targets = _get_policy_groups(permissions, targets)

    if (
        policy_permissions
        and policy_targets
        and _validate_target_classes(
            target_objects=targets,
            target_classes=[
                permission.target_type
                for policy in policy_permissions.keys()
                for permission in policy.target_permissions
            ],
        )
        and all(
            [
                policy.has_permissions(
                    security_context=security_context,
                    permissions=list(policy_permissions[policy]),
                    targets=policy_targets[policy],
                )
                for policy in policy_targets.keys()
            ]
        )
    ):
        return True

    return False


def sqla_filter_for_permissions(
    security_context: SecurityContext,
    permissions: List[Permission],
    targets: List[Any],
) -> Optional[ColumnElement]:
    permissions = _filter_permissions_by_scopes(
        scopes=security_context.scopes, permissions=permissions
    )
    if not permissions:
        return None

    policy_permissions, policy_targets = _get_policy_groups(permissions, targets)

    for target in targets:
        if not inspect.isclass(target):
            warnings.warn(
                "Targets to `sqla_filter_for_permissions` should be classes, not instances",
                stacklevel=3,
            )

    if (
        policy_permissions
        and policy_targets
        and (
            clauses := [
                policy.sqla_filter_for_permissions(
                    security_context=security_context,
                    permissions=list(policy_permissions[policy]),
                    targets=policy_targets[policy],
                )
                for policy in policy_targets.keys()
            ]
        )
        and not any([True for c in clauses if c is None])
    ):
        return reduce(operator.and_, clauses)

    return None


def _get_policy_groups(
    permissions: List[Permission],
    targets: List[Any],
) -> Tuple[Dict[TargetPolicy, Set[Permission]], Dict[TargetPolicy, List[Any]]]:
    policy_permissions: Dict[TargetPolicy, Set[Permission]] = defaultdict(set)
    policy_targets: Dict[TargetPolicy, List[Any]] = defaultdict(list)

    registry = get_registry()
    target_types = set([t if inspect.isclass(t) else t.__class__ for t in targets])

    for permission in permissions:
        policies = registry.policies_by_permission.get(permission) or set()
        if not policies:
            warnings.warn(
                f"No policy found for permission: `{permission.name}`",
                stacklevel=3,
            )
            return {}, {}

        for policy in policies:
            policy_permissions[policy].update(
                [
                    perm
                    for perm in permissions
                    if perm in policy.target_permissions
                    and perm.target_type in target_types
                ]
            )
            for target in targets:
                targets = [perm.target_type for perm in policy.target_permissions]
                target_class = target if inspect.isclass(target) else target.__class__
                if target_class in targets:
                    policy_targets[policy].append(target)

    handled_permissions = set(
        reduce(operator.iconcat, [list(pp) for pp in policy_permissions.values()])
    )
    unhandled_permissions = set(permissions) - handled_permissions
    if unhandled_permissions:
        warnings.warn(
            f"No targets found for permission(s): "
            f"{', '.join([p.id for p in unhandled_permissions])}",
            stacklevel=3,
        )
        return {}, {}

    handled_targets = set(reduce(operator.iconcat, policy_targets.values()))

    unhandled_targets = target_types - set(
        [t if inspect.isclass(t) else t.__class__ for t in handled_targets]
    )
    if unhandled_targets:
        target_names = [
            t.__name__ if inspect.isclass(t) else t.__class__.__name__
            for t in unhandled_targets
        ]
        warnings.warn(
            f"No policies found for target(s): " f"{', '.join(target_names)}",
            stacklevel=3,
        )
        return {}, {}

    return policy_permissions, policy_targets


def _validate_target_classes(
    target_objects: List[Any], target_classes: List[Type]
) -> bool:
    return set([t.__class__ for t in target_objects]) == set(target_classes)


def _filter_permissions_by_scopes(
    scopes: List[str], permissions: List[Permission]
) -> List[Permission]:
    if scopes == ["*"]:
        return permissions

    return [p for p in permissions if p.id in scopes]
