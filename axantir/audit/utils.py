from collections import defaultdict
from inspect import isclass
from logging import getLogger
from typing import Any, Dict, Set

from .schemas import AuditActionSpec, ContextObjectFieldSpec


def dotted_getattr(obj: Any, key: str) -> Any:
    if "." not in key:
        return getattr(obj, key, None)

    keyparts = key.split(".")
    value = getattr(obj, keyparts[0], None)
    if value is not None:
        return dotted_getattr(value, ".".join(keyparts[1:]))

    return None


def fully_qualified_class_name(obj: Any) -> str:
    if not isclass(obj):
        obj = obj.__class__

    if obj.__module__ == "builtins":
        return obj.__name__

    return ".".join([obj.__module__, obj.__name__])


def action_body_from_context(action: AuditActionSpec, *context_objects: Any) -> Dict:
    body = {}

    context_specs_by_fqcn: Dict[str, ContextObjectFieldSpec] = {
        fully_qualified_class_name(c.object_class): c
        for c in action.context_objects or []
    }

    seen_objects: Set[str] = set()
    missing_object_keys: Dict[str, Set[str]] = defaultdict(set)

    for obj in context_objects or []:
        fqcn = fully_qualified_class_name(obj)
        seen_objects.add(fqcn)

        spec = context_specs_by_fqcn.get(fqcn)
        if not spec:
            continue

        is_dict = isinstance(obj, dict)

        for key in spec.includes:
            value = obj.get(key) if is_dict else dotted_getattr(obj, key)
            if value is not None:
                body[key] = value
            elif key not in spec.nullable:
                missing_object_keys[fqcn].add(key)

    missing_objects = set(context_specs_by_fqcn.keys()) - seen_objects
    if missing_objects or missing_object_keys:
        message = [
            f"AuditLogger: `{action.name}:{action.version}` action was missing context items:"
        ]

        if missing_objects:
            message.append(
                f"expected object(s): {', '.join((sorted(missing_objects)))}"
            )

        if missing_object_keys:
            message.append("expected fields(s):")
            message.append(
                "; ".join(
                    [
                        f"{fqcn}: {', '.join(sorted(missing_object_keys[fqcn]))}"
                        for fqcn in missing_object_keys
                    ]
                )
            )

        getLogger().warning(" ".join(message))

    return body
