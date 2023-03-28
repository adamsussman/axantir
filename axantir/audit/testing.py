from typing import Dict, List, Optional

from .audit_logger import AuditLogger, Emitter
from .schemas import AuditEvent

# Usage:
# @pytest.fixture
# def capauditlog(application: Flask) -> AuditLogFixture:
#     return AuditLogFixture()
#
# Usage Flask:
#
# @pytest.fixture
# def capauditlog(application: Flask) -> AuditLogFixture:
#    with application.app_context():
#       return AuditLogFixture()
#
# def test_something(capauditlog: AuditLogFixture) -> None:
#    ... do stuff ...
#    assert len(capaudit.log.records) == 10
#    assert capauditlog.records[0].actor == "something"
#    ...


class FixtureEmitter(Emitter):
    records: List[Dict]

    def __init__(self) -> None:
        self.clear()

    def clear(self) -> None:
        self.records = []

    def emit(self, event: AuditEvent) -> None:
        self.records.append(event.dict())


class AuditLogFixture(object):
    audit_logger: AuditLogger
    emitter: Optional[FixtureEmitter] = None

    def __init__(self) -> None:
        try:
            from flask import current_app

            from .flask import get_audit_logger

            assert current_app
            self.audit_logger = get_audit_logger().audit_logger
        except (ImportError, AssertionError):
            self.audit_logger = AuditLogger(emitters=[FixtureEmitter()])

        self.emitter = None
        for emitter in self.audit_logger.emitters:
            if isinstance(emitter, FixtureEmitter):
                self.emitter = emitter
                self.emitter.clear()
                break

        if not self.emitter:
            self.emitter = FixtureEmitter()
            self.audit_logger.emitters.append(self.emitter)

    def clear(self) -> None:
        if self.emitter:
            self.emitter.clear()

    @property
    def records(self) -> List[Dict]:
        return self.emitter.records if self.emitter else []
