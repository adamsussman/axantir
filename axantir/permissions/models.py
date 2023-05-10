import abc
import inspect
import re
from typing import TYPE_CHECKING, Any, List, Optional, Type

from pydantic import BaseModel, Field, validator

try:
    from sqlalchemy.sql.elements import ColumnElement
except ImportError:
    ColumnElement = Type[object]  # type: ignore

from ..context import SecurityContext
from ..fields import IdSlug

if TYPE_CHECKING:  # pragma: no cover
    from .registry import Registry


# For testing, mock here
def get_registry() -> "Registry":  # pragma: no cover
    from .registry import registry

    return registry


def slugify(value: str) -> str:
    value = re.sub(r"([a-z])([A-Z])", r"\1_\2", value).lower()
    value = re.sub(r"[^\w\d_]", "", value)
    return value


class Permission(BaseModel):
    name: IdSlug
    target_type: Any
    description: Optional[str] = None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        get_registry().register_permission(self)

    @validator("target_type")
    def validate_target_type(cls, value: Any) -> Any:
        if not inspect.isclass(value):
            raise ValueError("must be a class")

        return value

    @property
    def id(self) -> str:
        return ":".join([self.target_slug, self.name])

    @property
    def target_slug(self) -> str:
        return slugify(self.target_type.__name__)

    def __hash__(self) -> int:
        return hash(self.id)


class TargetPolicy(BaseModel, abc.ABC):
    name: IdSlug
    target_permissions: List[Permission] = Field(min_items=1)
    description: Optional[str] = None

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
    ) -> ColumnElement:
        """
        Return where clause filter.

        For a no-op sql that always succeeds, return sqlalchemy.true()

        For a no-op sql that always fails (yields no rows), return sqlalchemy.false()
        """
        ...  # pragma: no cover

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        get_registry().register_target_policy(self)

    @property
    def id(self) -> str:
        return ":".join(
            ["/".join(sorted([p.id for p in self.target_permissions])), self.name]
        )

    def __hash__(self) -> int:
        return hash(self.id)
