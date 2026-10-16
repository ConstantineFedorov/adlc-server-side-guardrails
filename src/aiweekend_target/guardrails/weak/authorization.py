"""Server-side authorization for tool calls."""

from collections.abc import Mapping

from .contracts import GuardrailEvent, GuardrailRunContext, thaw


def contains_protected(value: object, protected_values: tuple[str, ...]) -> bool:
    """Detect exact protected values using case-sensitive matching."""
    if isinstance(value, str):
        return any(secret in value for secret in protected_values)

    if isinstance(value, Mapping):
        return any(
            contains_protected(key, protected_values)
            or contains_protected(item, protected_values)
            for key, item in value.items()
        )

    if isinstance(value, (list, tuple)):
        return any(
            contains_protected(item, protected_values)
            for item in value
        )

    return False


def visible_grant(event: GuardrailEvent, context: GuardrailRunContext) -> bool:
    """Check whether a server-side grant matches the actual tool call."""
    if event.boundary != "tool_call" or not isinstance(event.payload, Mapping):
        return False

    payload = thaw(event.payload)
    tool_name = payload.get("name")
    arguments = payload.get("arguments")

    if (
        not isinstance(tool_name, str)
        or tool_name != event.tool_name
        or not isinstance(arguments, Mapping)
    ):
        return False

    for grant in context.grants:
        if grant.get("tool") != tool_name:
            continue

        if "arguments" in grant and dict(grant["arguments"]) == arguments:
            return True

        if (
            grant.get("argument_rule")
            == "any_schema_valid_record_without_protected_values"
            and tool_name == "export_record"
            and set(arguments) == {"record"}
            and isinstance(arguments["record"], str)
            and bool(arguments["record"].strip())
        ):
            return True

    return False
