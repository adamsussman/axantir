import datetime
from typing import Any, Dict, List, Optional, Type

from pydantic import BaseModel, Field

from ..fields import IdSlug, SemVer


def utcnow() -> datetime.datetime:
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)


class AuditHeaderBase(BaseModel):
    timestamp: datetime.datetime = Field(default_factory=utcnow)
    actor: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        allow_mutation = False


class ContextObjectFieldSpec(BaseModel):
    object_class: Type
    includes: List[str]
    nullable: List[str] = Field(default_factory=list)

    class Config:
        allow_mutation = False


class AuditActionSpec(BaseModel):
    version: SemVer
    name: IdSlug

    context_objects: Optional[List[ContextObjectFieldSpec]]

    class Config:
        allow_mutation = False
        extra = "forbid"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        from .registry import registry

        super().__init__(*args, **kwargs)
        registry.register_action(self)


class AuditAction(BaseModel):
    version: SemVer
    name: IdSlug

    class Config:
        extra = "allow"
        allow_mutation = False


class AuditEvent(BaseModel):
    version: SemVer = Field(const=True, default=SemVer("1.0.0"))
    header: AuditHeaderBase = Field(default_factory=lambda: AuditHeaderBase())
    action: AuditAction

    class Config:
        allow_mutation = False
