import datetime
import tempfile
import uuid
from typing import IO, BinaryIO, Optional, Union

from pydantic import BaseModel, Field

BINARY_CONTENT_TYPE = Union[
    IO, BinaryIO, tempfile.SpooledTemporaryFile, bytes, bytearray
]


def utcnow() -> datetime.datetime:
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)


class File(BaseModel):
    file_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    name: str

    # format
    mime_type: Optional[str] = None
    extension: Optional[str] = None

    # storage
    size: Optional[int] = None
    md5: Optional[str] = None

    created: datetime.datetime = Field(default_factory=utcnow)
    updated: datetime.datetime = Field(default_factory=utcnow)

    @property
    def file_name(self) -> str:
        return "".join([self.name or "", self.extension or ""])
