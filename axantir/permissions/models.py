import abc
from typing import TYPE_CHECKING, Any, List, Optional, Type

from pydantic import BaseModel, Field, root_validator
from sqlalchemy.sql.elements import ColumnElement

from ..context import SecurityContext
from ..fields import IdSlug

if TYPE_CHECKING:  # pragma: no cover
    from .registry import Registry


# For testing, mock here
def get_registry() -> "Registry":  # pragma: no cover
    from .registry import registry

    return registry


class Permission(BaseModel):
    name: IdSlug
    target_type: IdSlug
    description: Optional[str] = None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        get_registry().register_permission(self)

    @property
    def id(self) -> str:
        return ":".join([self.target_type, self.name])

    def __hash__(self) -> int:
        return hash(self.id)


class TargetPolicy(BaseModel, abc.ABC):
    target_type: IdSlug
    target_classes: List[Type] = Field(min_items=1)
    target_permissions: List[Permission] = Field(min_items=1)

    @root_validator
    def validate_targets(cls, values: dict) -> dict:
        for permission in values.get("target_permissions", []):
            if values.get("target_type") != permission.target_type:
                raise ValueError(
                    f"permission `{permission.name}`'s target type does not "
                    "match the policy target type"
                )

        return values

    @abc.abstractmethod
    def has_permissions(
        self,
        security_context: SecurityContext,
        permissions: List[Permission],
        targets: List[Any],
    ) -> bool:
        ...  # pragma: no cover

    @abc.abstractmethod
    def sqla_filter_for_permissions(
        self,
        security_context: SecurityContext,
        permissions: List[Permission],
        targets: List[Any],
    ) -> Optional[ColumnElement]:
        ...  # pragma: no cover

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        get_registry().register_target_policy(self)

    @property
    def id(self) -> str:
        return ":".join(
            [
                self.target_type,
                "/".join(sorted([p.id for p in self.target_permissions])),
            ]
        )

    def __hash__(self) -> int:
        return hash(self.id)
