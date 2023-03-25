from typing import Dict

from pydantic import BaseModel, Field

from .schemas import AuditActionSpec


class AuditActionRegistry(BaseModel):
    actions_by_name_ver: Dict[str, AuditActionSpec] = Field(default_factory=dict)

    def clear(self) -> None:
        for field in self.__fields__.values():
            setattr(self, field.name, field.get_default())

    def register_action(self, action: AuditActionSpec) -> None:
        key = ":".join([action.name, action.version])
        if key in self.actions_by_name_ver:
            raise Exception(f"Duplicate action: {key}")

        self.actions_by_name_ver[key] = action


registry = AuditActionRegistry()
