import abc
import typing
from enum import Enum

from pydantic import BaseModel, Field

from .exceptions import BadSecurityContextExpectation


class ContextOriginEnum(str, Enum):
    session = "session"
    token = "bearer_token"
    internal = "internal"
    api_key = "api_key"


class SecurityContext(BaseModel, abc.ABC):
    origin: ContextOriginEnum
    scopes: typing.List[str] = Field(min_items=1, exclude=True)

    class Config:
        allow_mutation = False

    @abc.abstractmethod
    def audit_data(self) -> dict:  # pragma: nocover
        ...

    def __getattr__(self, field: str) -> typing.Any:
        # If we get here, no subclass defined the attribute
        # which means the code in question cannot use the
        # current context, which needs to be an authorization error.
        # The idea is that not every single line of code has to typecheck
        # the security context.  If what it needs is there, fine, if not
        # there is a graceful failure.  Outer handling code will turn
        # the exception into a proper 401 (etc) response.
        raise BadSecurityContextExpectation(field)


class AdminSecurityContext(SecurityContext):
    user_agent: str
    admin_identity: str

    def audit_data(self) -> dict:
        data = self.dict()
        data["is_admin"] = True
        return data
