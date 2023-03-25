import re
from typing import Callable, Generator

import semver

SLUG_RE = r"^[a-z0-9_-]{3,}$"


class IdSlug(str):
    @classmethod
    def __get_validators__(cls) -> Generator[Callable, None, None]:
        yield cls.validate

    @classmethod
    def validate(cls, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("string required")

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
    def __get_validators__(cls) -> Generator[Callable, None, None]:
        yield cls.validate

    @classmethod
    def validate(cls, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("string required")

        semver.VersionInfo.parse(value)
        return value
