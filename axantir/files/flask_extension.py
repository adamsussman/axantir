from typing import Dict, Optional

import werkzeug.utils
from flask import Flask

from .storage import FileStoreBase


class FlaskFileStore(object):
    app: Flask
    filestores: Dict[str, FileStoreBase]

    def __init__(self, app: Optional[Flask] = None) -> None:
        self.filestores = {}
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        self.app = app
        app.extensions["axantir_filestore"] = self

        if app.config.get("FILES_STORE_SETTINGS"):
            for name, settings in self.app.config["FILES_STORE_SETTINGS"].items():
                storage_class = werkzeug.utils.import_string(settings["class"])
                self.filestores[name] = storage_class(**settings.get("kwargs", {}))

    def get_filestore(self, name: str = "default") -> FileStoreBase:
        if name in self.filestores:
            return self.filestores[name]

        raise Exception(
            f"No filestore named `{name}` configured on the current application"
        )
