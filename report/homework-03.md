# Homework 3 — Server-Side Guardrails Assessment

## Security Assessment / ADLC — Lesson 3

**Assessment type:** AI Security / Guardrails Engineering  
**Primary focus:** Content classification, prompt-injection handling, authorization, tool-result checks and output safety  
**Environment:** Local ADLC Guardrails Lab  
**Assessment status:** Partial validation; results and limitations documented  
**Date:** October 2026

---

## 1. Executive Summary

This assessment documents the implementation and regression testing of server-side guardrails for ADLC. The goal was to improve safe handling of user instructions and quoted content, strengthen text-based detection and similarity checks, verify authorization before tool execution, and reduce the risk of unsafe content or leakage in tool results and final responses.

The latest full run covered **208 cases**:

| Result | Count |
|---|---:|
| Passed | 150 (72.1%) |
| Failed | 58 (27.9%) |
| Total | 208 |

All failures in the latest aggregated output were in the `content` group. The other six groups — `input`, `authorization`, `tool_result`, `output`, `similarity` and `failures` — passed all 54 checks combined.

Compared with the earlier recorded full run (146/208, 70.2%), the latest run improved by four passing cases. This comparison assumes the same test corpus and configuration.

**Assessment conclusion:** measurable progress was achieved, but content classification remains incomplete. The 72.1% result describes this laboratory test run; it is not a general security guarantee.

## 2. Objective and Scope

The assignment focused on improving a deliberately incomplete guardrail implementation. Work areas included:

- distinguishing active instructions from quoted or analyzed text;
- improving text rules and TF-IDF/similarity-based checks;
- checking permissions before tool execution;
- inspecting tool results and final answers for unsafe content or leakage.

The assessment is limited to the provided ADLC test harness and its 208-case suite. It does not represent a complete independent audit of ADLC or all possible attack variants.

## 3. Test Environment

| Component | Value |
|---|---|
| Lab | ADLC Lab / `adlc-guardrails-homework` |
| Working project | `ThirdModule/adlc-lab` |
| Runtime | Python 3.13+ in `.venv-guardrails` |
| Test runner | Built-in `homework` module |
| Full test command | `python -m homework check` |
| Case-level diagnostic | `python -m homework explain CASE` |
| External LLM / Docker | Not required by the assignment test suite |

## 4. Architecture and Trust Boundaries

The guardrail is treated as a server-side decision layer around user input, tool execution and response generation.

```text
User input / quoted content
          |
          v
Content detectors + policy decision
          |
          +------> authorization before sensitive tool call
          |
          v
Tool execution / tool result checks
          |
          v
Final output checks
```

The key trust-boundary principle is that text in user input, quoted material or tool output must not automatically become a trusted control instruction. Sensitive permissions should be enforced by application logic rather than inferred from the LLM's natural-language response.

## 5. Threat Model

| Component | Threat | Potential impact | Relevant control |
|---|---|---|---|
| User input | Prompt override or harmful request | Policy bypass or unsafe response | Content detectors and policy decision |
| Quoted content | Quoted injection or abusive/scam text | False positive or failure to classify data as data | Instruction/data separation |
| Text classifier | Incorrect category or reason code | False positives and false negatives | Regression suite and reason-code checks |
| Tool boundary | Unauthorized action | State change without permission | Authorization before execution |
| Tool result | Malicious instructions or sensitive content | Agent manipulation or information exposure | Tool-result checks |
| Final answer | Unsafe output or data leakage | Exposure of sensitive information | Output checks |

## 6. Implementation Work

### 6.1 Similarity gate

The similarity gate was updated to consider both an absolute attack-similarity threshold and the margin over benign similarity. Numeric inputs are validated; boolean, non-numeric and non-finite values are rejected.

This reduces reliance on a single similarity score. Thresholds still require representative test data and ongoing calibration.

### 6.2 Content detectors and quoted text

Several content-classification scenarios were adjusted to distinguish active instructions from quoted or educational text. The following targeted cases were reported as passing in the working session:

| Case | Expected behavior | Result |
|---|---|---|
| C20 | `BLOCK / PROMPT_OVERRIDE` | PASS |
| C21 | `ALLOW / ORDINARY_SUPPORT` | PASS |
| C22 | `BLOCK / UNAUTHORIZED_ACTION` with imminent-safety attention | PASS |
| C23 | `ALLOW_AS_DATA / QUOTED_INJECTION` | PASS |
| I01 | Active override is blocked | PASS |
| I03 | Quoted educational injection is allowed as data | PASS |

These are targeted results and do not imply that every content category is now handled correctly.

### 6.3 Output checks

Output checks were expanded for unsafe-instruction patterns, and the redaction marker display was corrected. Previously reported targeted checks R01–R05 and R10–R11 passed.

### 6.4 Authorization and tool boundary

The execution flow preserves authorization checks before sensitive actions, protected-value validation and detector/policy handling. The latest aggregate run passed every case in the `authorization` and `tool_result` groups. This is evidence for the supplied tests only, not proof that every authorization bypass is impossible.

## 7. Testing Methodology

The built-in suite was executed using:

```powershell
.\\.venv-guardrails\\Scripts\\python.exe -m homework check
```

Individual cases were investigated with:

```powershell
.\\.venv-guardrails\\Scripts\\python.exe -m homework explain CASE
```

A test is considered passed according to the harness assertions, which may check both the selected action and the reason code. Consequently, a correct action with an incorrect reason code can still fail the case.

## 8. Results

| Group | Passed | Failed | Total | Pass rate |
|---|---:|---:|---:|---:|
| `content` | 96 | 58 | 154 | 62.3% |
| `input` | 6 | 0 | 6 | 100% |
| `authorization` | 12 | 0 | 12 | 100% |
| `tool_result` | 11 | 0 | 11 | 100% |
| `output` | 6 | 0 | 6 | 100% |
| `similarity` | 7 | 0 | 7 | 100% |
| `failures` | 12 | 0 | 12 | 100% |
| **Total** | **150** | **58** | **208** | **72.1%** |

All 58 remaining failures were in the `content` group in the latest report. This group includes issues involving classification of quoted content, harmful requests, policy questions and reason-code specificity.

## 9. Remaining Issues

Examples observed in the inspected portion of `failed-cases.json` included:

| Case | Observed mismatch | Problem class |
|---|---|---|
| `public-policy-question-02` | Action was `ALLOW`, but reason code did not match | Reason-code classification |
| `public-quoted-scam-02` | `ALLOW` instead of `ALLOW_AS_DATA` | Quoted-scam handling |
| `public-quoted-injection-02` | `ALLOW` instead of `ALLOW_AS_DATA` | Quoted-injection handling |
| `public-generate-abuse-01` | Blocked under `PROMPT_OVERRIDE` instead of the expected category | Category precedence |
| `public-generate-abuse-02` | `ALLOW` instead of the expected `BLOCK` | Missed harmful-generation request |

These are examples from the inspected portion, not a complete breakdown of all 58 failures. Each remaining case would need individual review before assigning a definitive root cause.

## 10. Recommendations

1. Triage remaining content failures by category: quoted injection/scam, harmful-generation requests, moderation evasion, policy questions, private data and imminent safety risk.
2. Validate both action and reason code; keep action selection and category assignment conceptually separate.
3. Preserve regression cases for C20–C23, I01/I03 and output checks during future policy changes.
4. Keep quoted or analyzed text separate from active instructions.
5. Keep authorization checks outside the model and before sensitive tool execution.
6. Test similarity thresholds against both attack and benign examples, including invalid numeric inputs.
7. Re-run the entire 208-case suite after each meaningful change and retain the resulting JSON for comparison.

## 11. Retest Plan

| Test | Expected secure behavior |
|---|---|
| Full 208-case suite | Record pass/fail totals and compare against the previous baseline |
| Quoted injection/scam | Treat quoted content as data where appropriate |
| Harmful generation / evasion | Block with the expected category |
| Benign policy questions | Allow legitimate questions without misclassifying them as override attempts |
| Authorization | Prevent sensitive tool execution without permission |
| Tool result and output | Apply their relevant checks to untrusted content |
| Similarity gate | Evaluate attack score, benign score and input validity |

## 12. Conclusion

The latest recorded full run passed **150 of 208 cases (72.1%)**, compared with 146/208 in the earlier run. The `input`, `authorization`, `tool_result`, `output`, `similarity` and `failures` groups passed completely in the latest aggregate. Content classification remains the main area for improvement, with 58 failures remaining.

The key engineering lesson is that a useful guardrail must do more than block suspicious text: it should distinguish instructions from data, apply authorization before sensitive actions, inspect tool results and final outputs, and classify decisions consistently. Results should be reported with their limitations and reproduced against the same test corpus.

---

## Assessment limitations

This document reflects the latest test output shared during the lab session. It is not a claim that all content-related weaknesses are resolved or that the system is production-ready.