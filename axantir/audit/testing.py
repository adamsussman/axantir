from typing import Dict, List

from .audit_logger import AuditLogger, Emitter
from .schemas import AuditEvent

# Usage:
# @pytest.fixture
# def capauditlog(application: Flask) -> AuditLogFixture
#     return AuditLogFixture()
#
# Usage Flask:
#
# @pytest.fixture
# def capauditlog(application: Flask) -> AuditLogFixture
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

    def __init__(self) -> None:
        self.audit_logger = AuditLogger(emitters=[FixtureEmitter()])

    def clear(self) -> None:
        self.audit_logger.emitters[0].clear()  # type: ignore

    @property
    def records(self) -> List[Dict]:
        return (
            self.audit_logger.emitters[0].records  # type: ignore
            if self.audit_logger.emitters[0]
            else []
        )
