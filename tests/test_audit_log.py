import datetime
import json
import re
from typing import Optional

import pytest
from pydantic import BaseModel

from axantir.audit import AuditActionSpec, AuditLogger, EmitterLog
from axantir.audit.emitter import SubsecondJSONEncoder


def utcnow() -> datetime.datetime:
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)


def datetime_to_iso8601_ms(value: datetime.datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def test_duplicate_actions() -> None:
    AuditActionSpec(
        version="1.0.0",
        name="action1",
    )

    with pytest.raises(Exception) as e:
        AuditActionSpec(
            version="1.0.0",
            name="action1",
        )

    assert "Duplicate action" in str(e)


@pytest.mark.freeze_time
def test_basic_emit(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("INFO")

    action1 = AuditActionSpec(
        version="1.0.0",
        name="action1",
    )

    audit = AuditLogger(emitters=[EmitterLog()])
    audit.emit_action(action1)

    expected_message = {
        "version": "1.0.0",
        "header": {
            "timestamp": datetime_to_iso8601_ms(utcnow()),
            "actor": {},
        },
        "action": {
            "name": "action1",
            "version": "1.0.0",
        },
    }

    assert (
        json.dumps(expected_message, cls=SubsecondJSONEncoder, sort_keys=True)
        in caplog.text
    )


def test_emit_with_dict_context(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("INFO")

    my_action = AuditActionSpec(
        name="my_action",
        version="1.0.0",
        context_objects=[
            {"object_path": "dict", "includes": ["attribute1", "attribute3"]}
        ],
    )

    audit_logger = AuditLogger(emitters=[EmitterLog()])

    audit_logger.emit_action(
        my_action,
        {
            "attribute1": "c1a1",
            "attribute2": "c1a2",
            "attribute3": 3,
        },
    )

    assert len(caplog.records) == 1

    match = re.match(r"(\{[^\n]*)", caplog.records[0].message)
    assert match
    message = json.loads(match.group(0))

    assert message["action"] == {
        "name": "my_action",
        "version": "1.0.0",
        "attribute1": "c1a1",
        "attribute3": 3,
    }


def test_warning_missing_context_objs(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("INFO")

    class MyContextObject(BaseModel):
        attribute1: str

    my_action = AuditActionSpec(
        name="my_action",
        version="1.0.0",
        context_objects=[
            {"object_path": "foo.bar", "includes": ["a", "b", "c"]},
            {"object_path": "dict", "includes": ["a", "b", "c"]},
            {
                "object_path": "test_audit_log.MyContextObject",
                "includes": ["attribute1"],
            },
        ],
    )

    audit_logger = AuditLogger(emitters=[EmitterLog()])
    audit_logger.emit_action(my_action, MyContextObject(attribute1="val1"))

    infos = [r.message for r in caplog.records if r.levelname == "INFO"]
    warns = [r.message for r in caplog.records if r.levelname == "WARNING"]

    assert len(infos) == 1
    match = re.match(r"(\{[^\n]*)", infos[0])
    assert match
    message = json.loads(match.group(0))
    assert message["action"] == {
        "name": "my_action",
        "version": "1.0.0",
        "attribute1": "val1",
    }

    assert len(warns) == 1
    assert (
        "AuditLogger: `my_action:1.0.0` action was missing context items: "
        "expected object(s): dict, foo.bar" in warns[0]
    )


def test_warning_missing_context_obj_keys(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("INFO")

    class MyContextObject(BaseModel):
        attribute1: Optional[str] = None

    my_action = AuditActionSpec(
        name="my_action",
        version="1.0.0",
        context_objects=[
            {"object_path": "dict", "includes": ["a", "b", "c", "d"]},
            {
                "object_path": "test_audit_log.MyContextObject",
                "includes": ["attribute1"],
            },
        ],
    )

    audit_logger = AuditLogger(emitters=[EmitterLog()])
    audit_logger.emit_action(my_action, MyContextObject(), {"a": "aval", "b": "bval"})

    infos = [r.message for r in caplog.records if r.levelname == "INFO"]
    warns = [r.message for r in caplog.records if r.levelname == "WARNING"]

    assert len(infos) == 1
    match = re.match(r"(\{[^\n]*)", infos[0])
    assert match
    message = json.loads(match.group(0))
    assert message["action"] == {
        "name": "my_action",
        "version": "1.0.0",
        "a": "aval",
        "b": "bval",
    }

    assert len(warns) == 1
    assert (
        "expected fields(s): test_audit_log.MyContextObject: attribute1; dict: c, d"
        in warns[0]
    )


def test_warning_missing_context_obj_keys_nullable(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("INFO")

    class MyContextObject(BaseModel):
        attribute1: Optional[str] = None

    my_action = AuditActionSpec(
        name="my_action",
        version="1.0.0",
        context_objects=[
            {
                "object_path": "dict",
                "includes": ["a", "b", "c", "d"],
                "nullable": ["d"],
            },
            {
                "object_path": "test_audit_log.MyContextObject",
                "includes": ["attribute1", "attribute2"],
                "nullable": ["attribute2"],
            },
        ],
    )

    audit_logger = AuditLogger(emitters=[EmitterLog()])
    audit_logger.emit_action(my_action, MyContextObject(), {"a": "aval", "b": "bval"})

    infos = [r.message for r in caplog.records if r.levelname == "INFO"]
    warns = [r.message for r in caplog.records if r.levelname == "WARNING"]

    assert len(infos) == 1
    match = re.match(r"(\{[^\n]*)", infos[0])
    assert match
    message = json.loads(match.group(0))
    assert message["action"] == {
        "name": "my_action",
        "version": "1.0.0",
        "a": "aval",
        "b": "bval",
    }

    assert len(warns) == 1
    assert (
        "expected fields(s): test_audit_log.MyContextObject: attribute1; dict: c"
        in warns[0]
    )
