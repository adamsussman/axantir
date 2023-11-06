from typing import Dict

from pydantic import BaseModel, Field

from .schemas import AuditActionSpec


class AuditActionRegistry(BaseModel):
    actions_by_name_ver: Dict[str, AuditActionSpec] = Field(default_factory=dict)

    def clear(self) -> None:
        for field_name, field in self.model_fields.items():
            setattr(self, field_name, field.get_default(call_default_factory=True))

    def register_action(self, action: AuditActionSpec) -> None:
        key = ":".join([action.name, action.version])
        if key in self.actions_by_name_ver:
            raise Exception(f"Duplicate action: {key}")

        self.actions_by_name_ver[key] = action


registry = AuditActionRegistry()
