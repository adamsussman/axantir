from typing import Optional

import magic

from .schemas import BINARY_CONTENT_TYPE


def get_file_mime_type(
    content: BINARY_CONTENT_TYPE,
    declared_mime_type: Optional[str] = None,
) -> str:
    if declared_mime_type and declared_mime_type != "application/octet-stream":
        return declared_mime_type

    if hasattr(content, "seek") and hasattr(content, "read"):
        mime_type = (
            magic.from_buffer(content.read(2048), mime=True)
            or "application/octet-stream"
        )
        content.seek(0)

    else:
        mime_type = (
            magic.from_buffer(content[:2048], mime=True) or "application/octet-stream"
        )
    return mime_type
