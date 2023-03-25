import json
import re
import uuid
from typing import Any, Dict, Optional

import pytest
from flask import Flask, Response, g, make_response, request
from pydantic import Field

from axantir.audit import AuditActionSpec, AuditHeaderBase
from axantir.audit.flask import FlaskAuditLogger
from axantir.context import SecurityContext


def get_correlation_id() -> Optional[str]:
    return request.environ.get("correlation_id") if request else None


def get_session_id() -> Optional[str]:
    return request.environ.get("session_id") if request else None


def get_security_context() -> Dict[str, Any]:
    return g.security_context.audit_data() if g and g.security_context else {}


class FlaskSecurityContext(SecurityContext):
    user_id: str

    def audit_data(self) -> dict:
        return self.dict()


class FlaskAuditHeader(AuditHeaderBase):
    correlation_id: Optional[str] = Field(default_factory=get_correlation_id)
    session_id: Optional[str] = Field(default_factory=get_session_id)
    actor: Dict[str, Any] = Field(default_factory=get_security_context)

    class Config:
        allow_mutation = False


def test_flask_header_values(
    caplog: pytest.LogCaptureFixture,
) -> None:
    application = Flask("test_app")
    simple_user_id = str(uuid.uuid4())

    caplog.set_level("INFO")

    audit_logger = FlaskAuditLogger(
        app=application, audit_header_class=FlaskAuditHeader
    )

    action1 = AuditActionSpec(
        version="1.0.0",
        name="action1",
    )

    application._got_first_request = (
        False  # disable post-setup fence for adding new routes
    )

    @application.get("/testaudit")
    def test_audit_in_view() -> Response:
        audit_logger.emit_action(action1)
        return make_response({}, 200)

    @application.before_request
    def setup_security_context() -> None:
        g.security_context = FlaskSecurityContext(
            user_id=simple_user_id, origin="session", scopes=["*"]
        )

    client = application.test_client()
    response = client.get("/testaudit", environ_overrides={"correlation_id": "foo"})
    assert response.status_code == 200

    assert len(caplog.records) == 1

    match = re.match(r"(\{[^\n]*)", caplog.records[0].message)
    assert match
    message = json.loads(match.group(0))
    assert "header" in message
    assert message["header"]["correlation_id"] is not None
    assert message["header"]["session_id"] is None
    assert message["header"]["actor"]["user_id"] == simple_user_id
