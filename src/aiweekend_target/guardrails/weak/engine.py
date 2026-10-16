"""Boundary evaluation and standalone content review."""

from collections.abc import Mapping

from .authorization import contains_protected, visible_grant
from .contracts import GuardrailResult
from .detectors import narrow_signals
from .output_checks import pass_through
from .policy import decide


_FAILURE_STATUSES = {
    "timeout",
    "invalid_response",
    "unavailable",
}


def review(request):
    """Review a request while preserving its message and trusted context."""
    context = dict(request.context)
    context["_review_message"] = request.message
    context["_review_evidence"] = request.evidence

    signals = narrow_signals(
        " ".join((request.message, *request.evidence))
    )
    return decide(signals, context)


def _detector_status(context) -> str:
    """Return the configured detector status, defaulting to healthy."""
    requirements = context.detector_requirements
    if not isinstance(requirements, Mapping):
        return "invalid_response"

    status = requirements.get("status", "ok")
    if status not in {"ok", *_FAILURE_STATUSES}:
        return "invalid_response"

    return status


def _detector_required(event, context) -> bool:
    """Check whether a detector is mandatory for this tool."""
    requirements = context.detector_requirements
    if not isinstance(requirements, Mapping):
        return True

    required_for = requirements.get("required_for", ())
    if not isinstance(required_for, (list, tuple, set, frozenset)):
        return True

    return event.tool_name in required_for


def evaluate(event, context):
    """Evaluate a security boundary before allowing data or tool use."""
    if event.boundary == "input":
        found = narrow_signals(str(event.payload))
        return (
            GuardrailResult("block", "prompt.override", found)
            if found
            else GuardrailResult("allow", "content.safe")
        )

    if event.boundary == "tool_call":
        # Authorization must be checked before considering detector status.
        if not visible_grant(event, context):
            return GuardrailResult("block", "authorization.denied")

        if contains_protected(event.payload, context.protected_values):
            return GuardrailResult("block", "data.protected")

        status = _detector_status(context)
        if status in _FAILURE_STATUSES:
            if _detector_required(event, context):
                return GuardrailResult(
                    "block",
                    "detector.unavailable",
                    degraded=True,
                )

            return GuardrailResult(
                "allow",
                "authorized",
                degraded=True,
            )

        requirements = context.detector_requirements
        if (
            isinstance(requirements, Mapping)
            and requirements.get("return_no_signals") is True
        ):
            return GuardrailResult("block", "detector.no_signals")

        return GuardrailResult("allow", "authorized")

    return pass_through(event, context)
