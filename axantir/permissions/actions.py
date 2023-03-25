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
    policy_permissions, policy_targets = _get_policy_groups(permissions, targets)

    if (
        policy_permissions
        and policy_targets
        and _validate_target_classes(
            target_objects=targets,
            target_classes=[
                cls
                for policy in policy_permissions.keys()
                for cls in policy.target_classes
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
    target_class_policies: Dict[Any, Set[TargetPolicy]] = defaultdict(set)

    registry = get_registry()

    for permission in permissions:
        policy = registry.policies_by_target.get(permission.target_type)
        if not policy:
            warnings.warn(
                f"Permission `{permission.id}` has target_type with no policy: "
                f"`{permission.target_type}`",
                stacklevel=3,
            )
            return {}, {}

        policy_permissions[policy].add(permission)
        for target_class in policy.target_classes:
            target_class_policies[target_class].add(policy)

    for target in targets:
        target_class = target if inspect.isclass(target) else target.__class__
        if target_class not in target_class_policies:
            warnings.warn(
                f"No permission requested has a policy for target class "
                f"`{target_class.__name__}`",
                stacklevel=3,
            )
            return {}, {}

        for policy in target_class_policies[target_class]:
            policy_targets[policy].append(target)

    if (
        policy_permissions
        and policy_targets
        and set(policy_permissions.keys()) != set(policy_targets.keys())
    ):
        warnings.warn(
            "Mismatch policy_permissions `{}` vs policy_targets `{}`".format(
                ", ".join(sorted([t.target_type for t in policy_permissions.keys()])),
                ", ".join(sorted([t.target_type for t in policy_targets.keys()])),
            ),
            stacklevel=3,
        )
        return {}, {}

    return policy_permissions, policy_targets


def _validate_target_classes(
    target_objects: List[Any], target_classes: List[Type]
) -> bool:
    return set([t.__class__ for t in target_objects]) == set(target_classes)
