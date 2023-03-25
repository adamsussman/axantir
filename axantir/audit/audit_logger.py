from logging import getLogger
from typing import Any, List, Optional, Type

from ..context import SecurityContext
from .emitter import Emitter
from .schemas import AuditAction, AuditActionSpec, AuditEvent, AuditHeaderBase
from .utils import action_body_from_context


class AuditLogger(object):
    def __init__(
        self,
        emitters: List[Emitter],
        header_class: Optional[Type[AuditHeaderBase]] = AuditHeaderBase,
        exception_logger_name: Optional[str] = None,
    ) -> None:
        if not emitters or not all([isinstance(e, Emitter) for e in emitters]):
            raise Exception("Emitters required")

        self.header_class = header_class
        self.emitters = emitters
        self.exception_logger_name = exception_logger_name

    def emit_action(self, action: AuditActionSpec, *context_objects: Any) -> None:
        try:
            assert self.header_class

            header_kwargs = {}
            context: Optional[SecurityContext] = next(
                filter(lambda x: isinstance(x, SecurityContext), context_objects), None
            )
            if context:
                header_kwargs["actor"] = context.audit_data()

            header = self.header_class(**header_kwargs)

            event = AuditEvent(
                header=header,
                action=AuditAction(
                    name=action.name,
                    version=action.version,
                    **action_body_from_context(action, *context_objects),
                ),
            )
            for emitter in self.emitters:
                try:
                    emitter.emit(event)
                except Exception:
                    # do not block whatever was calling this, just log the exception and move on
                    getLogger(self.exception_logger_name).exception(
                        f"audit emitter `{emitter.__class__.__name__}` failed for action "
                        f"`{action.name}:{action.version}`"
                    )

        # XXX: log stacktrace
        except Exception:
            # do not block whatever was calling this, just log the exception and move on
            getLogger(self.exception_logger_name).exception(
                f"audit emit failed for action `{action.name}:{action.version}`"
            )
