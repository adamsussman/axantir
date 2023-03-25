from typing import Any, Optional, Type

from flask import Flask

from .audit_logger import AuditLogger
from .emitter import EmitterLog
from .schemas import AuditActionSpec, AuditHeaderBase

EXTENSION_KEY = "audit_logger"


def get_audit_logger() -> AuditLogger:
    from flask import current_app

    if current_app and EXTENSION_KEY in current_app.extensions:
        return current_app.extensions[EXTENSION_KEY]

    return AuditLogger(emitters=[EmitterLog()])


class FlaskAuditLogger(object):
    audit_logger: AuditLogger

    def __init__(
        self,
        audit_logger: Optional[AuditLogger] = None,
        audit_header_class: Optional[Type[AuditHeaderBase]] = None,
        app: Optional[Flask] = None,
    ) -> None:
        self.app = app
        self.audit_logger = audit_logger or AuditLogger(
            emitters=[EmitterLog()], header_class=audit_header_class
        )

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        app.extensions[EXTENSION_KEY] = self
        self.app = app

    def emit_action(self, action: AuditActionSpec, *context_objects: Any) -> None:
        self.audit_logger.emit_action(action, *context_objects)
