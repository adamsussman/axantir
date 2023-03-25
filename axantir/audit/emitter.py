import abc
import datetime
import json
from logging import getLogger
from typing import Any, Optional

from .schemas import AuditEvent


class Emitter(abc.ABC):
    @abc.abstractmethod
    def emit(self, event: AuditEvent) -> None:
        ...


class EmitterLog(Emitter):
    def __init__(self, logger_name: Optional[str] = "audit") -> None:
        self.logger_name = logger_name

    def emit(self, event: AuditEvent) -> None:
        message = json.dumps(event.dict(), cls=SubsecondJSONEncoder, sort_keys=True)
        getLogger(self.logger_name).info(message)


class SubsecondJSONEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, datetime.datetime):
            return o.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        return super().default(o)
