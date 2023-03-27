from collections import defaultdict
from typing import Dict, List, Set

from .models import Permission, TargetPolicy


class Registry(object):
    permissions_by_id: Dict[str, Permission]
    policies_by_id: Dict[str, TargetPolicy]
    policies_by_permission: Dict[Permission, Set[TargetPolicy]]

    def __init__(self) -> None:
        self.clear()

    def clear(self) -> None:
        self.permissions_by_id = {}
        self.policies_by_id = {}
        self.policies_by_permission = defaultdict(set)

    def register_permission(self, permission: Permission) -> None:
        if not isinstance(permission, Permission):
            raise TypeError()

        if permission.id in self.permissions_by_id:
            raise ValueError(f"Duplicate permission `{permission.id}`")

        self.permissions_by_id[permission.id] = permission

    def register_target_policy(self, policy: TargetPolicy) -> None:
        if not isinstance(policy, TargetPolicy):
            raise TypeError(
                "policy must be a sublcass (not an instance) of TargetPolicy"
            )

        if policy.id in self.policies_by_id:
            raise ValueError(f"Duplicate policy `{policy.id}`")

        self.policies_by_id[policy.id] = policy
        for permission in policy.target_permissions:
            self.policies_by_permission[permission].add(policy)

    def get_all_permissions(self) -> List[Permission]:
        return sorted(self.permissions_by_id.values(), key=lambda p: p.id)

    def get_all_target_policies(self) -> List[TargetPolicy]:
        return sorted(self.policies_by_id.values(), key=lambda p: p.id)


registry = Registry()
