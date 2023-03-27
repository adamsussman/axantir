from collections import defaultdict
from typing import Dict, List, Set

from .models import Permission, TargetPolicy


class Registry(object):
    permissions_by_id: Dict[str, Permission]
    permissions_by_target: Dict[str, Set[Permission]]
    policies_by_id: Dict[str, TargetPolicy]
    policies_by_target: Dict[str, Set[TargetPolicy]]

    def __init__(self) -> None:
        self.clear()

    def clear(self) -> None:
        self.permissions_by_id = {}
        self.permissions_by_target = defaultdict(set)
        self.policies_by_id = {}
        self.policies_by_target = defaultdict(set)

    def register_permission(self, permission: Permission) -> None:
        if not isinstance(permission, Permission):
            raise TypeError()

        if permission.id in self.permissions_by_id:
            raise ValueError(f"Duplicate permission `{permission.id}`")

        self.permissions_by_id[permission.id] = permission
        self.permissions_by_target[permission.target_type].add(permission)

    def register_target_policy(self, policy: TargetPolicy) -> None:
        if not isinstance(policy, TargetPolicy):
            raise TypeError(
                "policy must be a sublcass (not an instance) of TargetPolicy"
            )

        if policy.id in self.policies_by_id:
            raise ValueError(f"Duplicate policy `{policy.target_type}`")

        self.policies_by_id[policy.id] = policy
        self.policies_by_target[policy.target_type].add(policy)

    def get_all_permissions(self) -> List[Permission]:
        return sorted(self.permissions_by_id.values(), key=lambda p: p.id)

    def get_all_target_policies(self) -> List[TargetPolicy]:
        return sorted(self.policies_by_id.values(), key=lambda p: p.id)


registry = Registry()
