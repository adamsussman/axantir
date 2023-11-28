import re
from typing import Any

import semver
from pydantic import GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema

SLUG_RE = r"^[a-z0-9_-]{3,}$"


class IdSlug(str):
    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        return core_schema.no_info_plain_validator_function(cls.validate)

    @classmethod
    def validate(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("string required")

        if not value:
            raise ValueError("value must not be None")

        if len(value) < 3:
            raise ValueError("value must be at least 3 characters long")

        if not re.match(SLUG_RE, value):
            raise ValueError(
                "value must be lower case letters, digits, underscores or dashes"
            )

        return value


class SemVer(str):
    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        return core_schema.no_info_plain_validator_function(cls.validate)

    @classmethod
    def validate(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("string required")

        semver.VersionInfo.parse(value)
        return value
