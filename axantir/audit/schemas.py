import datetime
from typing import Any, Dict, List, Optional, Type

from pydantic import BaseModel, ConfigDict, Field

from ..fields import IdSlug, SemVer


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


class AuditHeaderBase(BaseModel):
    timestamp: datetime.datetime = Field(default_factory=utcnow)
    actor: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(frozen=True)


class ContextObjectFieldSpec(BaseModel):
    object_class: Type
    includes: List[str]
    nullable: List[str] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True)


class AuditActionSpec(BaseModel):
    version: SemVer
    name: IdSlug

    context_objects: Optional[List[ContextObjectFieldSpec]] = None

    model_config = ConfigDict(frozen=True, extra="forbid")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        from .registry import registry

        super().__init__(*args, **kwargs)
        registry.register_action(self)


class AuditAction(BaseModel):
    version: SemVer
    name: IdSlug

    model_config = ConfigDict(extra="allow", frozen=True)


class AuditEvent(BaseModel):
    version: SemVer = SemVer("1.0.0")
    header: AuditHeaderBase | Type[AuditHeaderBase] = Field(
        default_factory=lambda: AuditHeaderBase()
    )
    action: AuditAction

    model_config = ConfigDict(frozen=True)
