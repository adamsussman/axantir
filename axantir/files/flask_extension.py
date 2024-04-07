from typing import Optional

import werkzeug.utils
from flask import Flask, current_app
from flask.globals import app_ctx

from .storage import FileStoreBase


class FlaskFileStore(object):
    def __init__(self, app: Optional[Flask] = None) -> None:
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        app.extensions["axantir_filestore"] = self

    def get_filestore(self, name: str = "default") -> FileStoreBase:
        if (
            app_ctx is not None
            and (filestores := getattr(app_ctx, "axantir_file_store", None))
            and (filestore := filestores.get(name))
        ):
            return filestore

        if (
            app_ctx is not None
            and current_app.config.get("FILES_STORE_SETTINGS")
            and (settings := current_app.config["FILES_STORE_SETTINGS"].get(name, None))
        ):
            storage_class = werkzeug.utils.import_string(settings["class"])
            filestore = storage_class(**settings.get("kwargs", {}))
            if not hasattr(app_ctx, "axantir_file_store"):
                app_ctx.axantir_file_store = {}  # type: ignore

            app_ctx.axantir_file_store[name] = filestore  # type: ignore

            return filestore

        raise Exception(
            f"No filestore named `{name}` configured on the current application"
        )
