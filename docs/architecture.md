# Architecture and Trust Boundaries

## Purpose

The guardrail is a server-side decision layer around an LLM agent. Its role is to distinguish active instructions from untrusted data, apply policy decisions, preserve authorization boundaries, and inspect tool results and final output.

## Conceptual flow

```text
User input / quoted content
          |
          v
Content detectors and policy decision
          |
          +----> authorization before sensitive tool call
          |
          v
Tool execution and tool-result checks
          |
          v
Final-output checks
```

## Trust assumptions

- User-provided text may be adversarial.
- Quoted text and educational examples should not automatically be treated as active instructions.
- Retrieved documents and tool results may contain malicious instructions.
- Model-generated intent is not authorization.
- Sensitive actions require validation and permission checks in trusted application code.

## Design review questions

- Are permissions checked before a sensitive tool is executed?
- Are tool names and arguments constrained to the intended operation?
- Is quoted material distinguished from active instructions?
- Are tool results checked before they affect subsequent model behavior?
- Are final responses checked for unsafe content or sensitive data?
- Are degraded/failure modes explicit and covered by tests?

This is a conceptual summary of the educational assessment, not a claim that every item has been independently proven across all runtime paths. Consult the implementation and regression evidence before reusing the controls.
