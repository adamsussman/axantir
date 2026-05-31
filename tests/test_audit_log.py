import datetime
import json
import re
from typing import Optional

import pytest
from pydantic import BaseModel

from axantir.audit import AuditActionSpec, AuditLogger, EmitterLog
from axantir.audit.emitter import SubsecondJSONEncoder
from axantir.audit.schemas import AuditEvent


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
            {"object_class": dict, "includes": ["attribute1", "attribute3"]}
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

    class Bar:
        a: str
        b: str
        c: str

    my_action = AuditActionSpec(
        name="my_action",
        version="1.0.0",
        context_objects=[
            {"object_class": Bar, "includes": ["a", "b", "c"]},
            {"object_class": dict, "includes": ["a", "b", "c"]},
            {
                "object_class": MyContextObject,
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
        "expected object(s): dict, test_audit_log.Bar" in warns[0]
    )


def test_warning_missing_context_obj_keys(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("INFO")

    class MyContextObject(BaseModel):
        attribute1: Optional[str] = None

    my_action = AuditActionSpec(
        name="my_action",
        version="1.0.0",
        context_objects=[
            {"object_class": dict, "includes": ["a", "b", "c", "d"]},
            {
                "object_class": MyContextObject,
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
                "object_class": dict,
                "includes": ["a", "b", "c", "d"],
                "nullable": ["d"],
            },
            {
                "object_class": MyContextObject,
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


def test_conext_object_includes_conflicts_with_spec_keys(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("INFO")

    class MyContextObject(BaseModel):
        name: str

    class MyContextObject2(BaseModel):
        version: str

    class MyContextObject3(BaseModel):
        context_objects: str

    my_action = AuditActionSpec(
        name="my_action",
        version="1.0.0",
        context_objects=[
            {
                "object_class": MyContextObject,
                "includes": ["name"],
            },
            {
                "object_class": MyContextObject2,
                "includes": ["version"],
            },
            {
                "object_class": MyContextObject3,
                "includes": ["context_objects"],
            },
        ],
    )

    audit_logger = AuditLogger(emitters=[EmitterLog()])
    audit_logger.emit_action(
        my_action,
        MyContextObject(name="foo"),
        MyContextObject2(version="1.2.3"),
        MyContextObject3(context_objects="stuff"),
    )

    infos = [r.message for r in caplog.records if r.levelname == "INFO"]

    assert len(infos) == 1
    match = re.match(r"(\{[^\n]*)", infos[0])
    assert match
    message = json.loads(match.group(0))
    assert message["action"] == {
        "name": "my_action",
        "version": "1.0.0",
        "object_name": "foo",
        "object_version": "1.2.3",
        "object_context_objects": "stuff",
    }


def test_emit_with_custom_event_class_and_event_kwargs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("INFO")

    class MyAuditEvent(AuditEvent):
        request_id: str
        tenant: Optional[str] = None

    action1 = AuditActionSpec(
        version="1.0.0",
        name="action1",
    )

    audit = AuditLogger(emitters=[EmitterLog()], event_class=MyAuditEvent)
    audit.emit_action(action1, request_id="req-abc-123", tenant="acme")

    infos = [r.message for r in caplog.records if r.levelname == "INFO"]
    assert len(infos) == 1
    match = re.match(r"(\{[^\n]*)", infos[0])
    assert match
    message = json.loads(match.group(0))

    assert message["request_id"] == "req-abc-123"
    assert message["tenant"] == "acme"
    assert message["action"] == {
        "name": "action1",
        "version": "1.0.0",
    }


def test_emit_with_custom_event_class_uses_defaults(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("INFO")

    class MyAuditEvent(AuditEvent):
        source: str = "default-source"

    action1 = AuditActionSpec(
        version="1.0.0",
        name="action1",
    )

    audit = AuditLogger(emitters=[EmitterLog()], event_class=MyAuditEvent)
    audit.emit_action(action1)

    infos = [r.message for r in caplog.records if r.levelname == "INFO"]
    assert len(infos) == 1
    match = re.match(r"(\{[^\n]*)", infos[0])
    assert match
    message = json.loads(match.group(0))

    assert message["source"] == "default-source"


def test_event_class_defaults_to_audit_event(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("INFO")

    action1 = AuditActionSpec(
        version="1.0.0",
        name="action1",
    )

    audit = AuditLogger(emitters=[EmitterLog()])
    assert audit.event_class is AuditEvent

    audit.emit_action(action1)

    infos = [r.message for r in caplog.records if r.levelname == "INFO"]
    assert len(infos) == 1
    match = re.match(r"(\{[^\n]*)", infos[0])
    assert match
    message = json.loads(match.group(0))
    # base AuditEvent has only version, header, action — no extras
    assert set(message.keys()) == {"version", "header", "action"}


def test_emit_event_kwargs_combined_with_context_objects(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("INFO")

    class MyAuditEvent(AuditEvent):
        correlation_id: str

    my_action = AuditActionSpec(
        name="my_action",
        version="1.0.0",
        context_objects=[{"object_class": dict, "includes": ["attribute1"]}],
    )

    audit = AuditLogger(emitters=[EmitterLog()], event_class=MyAuditEvent)
    audit.emit_action(
        my_action,
        {"attribute1": "val1"},
        correlation_id="corr-xyz",
    )

    infos = [r.message for r in caplog.records if r.levelname == "INFO"]
    assert len(infos) == 1
    match = re.match(r"(\{[^\n]*)", infos[0])
    assert match
    message = json.loads(match.group(0))

    assert message["correlation_id"] == "corr-xyz"
    assert message["action"] == {
        "name": "my_action",
        "version": "1.0.0",
        "attribute1": "val1",
    }


def test_emit_event_kwargs_missing_required_field_is_swallowed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("INFO")

    class MyAuditEvent(AuditEvent):
        request_id: str  # required, no default

    action1 = AuditActionSpec(
        version="1.0.0",
        name="action1",
    )

    audit = AuditLogger(emitters=[EmitterLog()], event_class=MyAuditEvent)
    # Failure to construct the event must not raise — it is logged and swallowed.
    audit.emit_action(action1)

    infos = [r.message for r in caplog.records if r.levelname == "INFO"]
    errors = [r for r in caplog.records if r.levelname == "ERROR"]
    assert infos == []
    assert len(errors) == 1
    assert "audit emit failed for action `action1:1.0.0`" in errors[0].message


def test_emit_event_kwargs_ignored_with_default_event_class(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The default AuditEvent has no `extra='allow'`, so unknown event_kwargs
    are silently ignored by pydantic — emission still succeeds."""
    caplog.set_level("INFO")

    action1 = AuditActionSpec(
        version="1.0.0",
        name="action1",
    )

    audit = AuditLogger(emitters=[EmitterLog()])
    audit.emit_action(action1, unknown_kwarg="should-be-dropped")

    infos = [r.message for r in caplog.records if r.levelname == "INFO"]
    assert len(infos) == 1
    match = re.match(r"(\{[^\n]*)", infos[0])
    assert match
    message = json.loads(match.group(0))
    assert "unknown_kwarg" not in message
