# ADLC Server-Side Guardrails

> **AI Security · Guardrails Engineering · LLM Agent Security**
>
> A prototype and security assessment of server-side guardrails for classifying content, enforcing policy, validating tool interactions, and checking model output.

![Domain](https://img.shields.io/badge/domain-AI%20Security-17365D)
![Scope](https://img.shields.io/badge/scope-Server--Side%20Guardrails-0F6B78)
![Assessment](https://img.shields.io/badge/type-Security%20Prototype-596579)
![Regression](https://img.shields.io/badge/regression-208%20cases-6B46C1)

## 1. Overview

The central design principle is that **model output, user input, retrieved content, and tool results must not replace trusted application policy or authorization**.

This repository contains modified guardrail modules, supporting security documentation, and the recorded regression assessment. It is an overlay on the separately maintained [ADLC lab](https://github.com/makrushind/adlc-lab), not a self-contained installable package.

## 2. Executive Summary

Latest recorded full regression run:

| Result | Count |
|---|---:|
| Passed | **150 / 208 (72.1%)** |
| Failed | 58 / 208 (27.9%) |
| Content classification | 96 / 154 passed |
| Other groups | 54 / 54 passed |

All 58 recorded failures were in the `content` group. The `input`, `authorization`, `tool_result`, `output`, `similarity`, and `failures` groups passed all supplied assertions in that run.

These figures describe one recorded regression corpus and configuration. They do not establish general attack-detection accuracy or production readiness, and the run has not been independently reproduced from this repository.

## 3. Security Controls in Scope

- **Policy decisions:** classify requests and select actions and reason codes.
- **Instruction versus data:** distinguish active instructions from quoted or analyzed text.
- **Similarity gate:** validate numeric inputs and compare attack similarity with benign similarity.
- **Authorization:** check permissions before sensitive tool execution.
- **Tool-result validation:** treat external tool output as untrusted and inspect it before further use.
- **Output checks:** inspect final responses for unsafe content and sensitive-data leakage.
- **Failure handling:** exercise detector/runtime failure behavior and fail safely when required components are unavailable.

## 4. Conceptual Architecture

```text
User input / quoted content / tool result
                  |
                  v
          Content classification
                  |
                  v
             Policy decision
                  |
           +------+------+
           |             |
        DENY/BLOCK   Authorization
                         |
                         v
                   Tool execution
                         |
                         v
                  Tool-result checks
                         |
                         v
                  Final-output checks
```

This is a conceptual flow. Review the implementation and runtime integration before relying on any specific enforcement path.

## 5. Results and Remaining Work

Content classification remains the primary follow-up area. The recorded failures include cases involving quoted scam/injection content, harmful-generation requests, policy questions, and reason-code specificity.

A passing test group demonstrates compliance with the supplied assertions for that group only. It does not prove resistance to untested payloads, integrations, configurations, or attack techniques.

## 6. Reproduction

The recorded run used the separate upstream lab checkout, Python 3.13+ and its test runner:

```powershell
.\.venv-guardrails\Scripts\python.exe -m homework check
.\.venv-guardrails\Scripts\python.exe -m homework explain CASE
```

Replace `CASE` with a case identifier to inspect an individual test. These commands are not expected to work from this repository alone: the overlay depends on upstream modules, configuration, data, and test assets. The recorded result has not been verified by a fresh run from this repository.

## 7. Repository Structure

| Path | Purpose |
|---|---|
| `src/aiweekend_target/guardrails/weak/` | Modified guardrail modules |
| `report/` | Detailed assessment and recorded results |
| `docs/guardrails-control-matrix.md` | Security objectives mapped to controls and evidence |
| `docs/architecture.md` | Trust boundaries and conceptual control flow |
| `docs/methodology.md` | Methodology and interpretation of regression results |
| `SECURITY.md` | Responsible testing and evidence handling |
| `ATTRIBUTION.md` | Upstream provenance, license, and scope notes |

Implementation files include `authorization.py`, `detectors.py`, `engine.py`, `output_checks.py`, `policy.py`, and `similarity.py`.

## 8. Recommended Next Steps

1. Review content-classification failures by category and preserve each as a regression case.
2. Separate action selection from reason-code classification and test both.
3. Retain passing cases for quoted content, policy questions, and output checks.
4. Keep authorization as an independent check before sensitive tool execution.
5. Test similarity logic with benign pairs, boundary values, invalid types, and non-finite numbers.
6. Repeat the full regression suite after significant changes and retain the exact result artifact.

## 9. Related Work

- [DocsAgent Security Assessment](https://github.com/ConstantineFedorov/docsagent-security-assessment) — RAG, MCP metadata, and privileged side effects.
- [ADLC Agent Security Assessment](https://github.com/ConstantineFedorov/adlc-agent-security-assessment) — poisoned tool-result testing and runtime enforcement.
- [Agent Runtime Security](https://github.com/ConstantineFedorov/agent-runtime-security-lab) — runtime telemetry processing and session reconstruction.

## 10. Limitations and Responsible Use

This repository is a prototype/overlay, not a production-ready guardrail framework or security certification. The upstream author has not endorsed this repository or its modifications. Test only systems you own or are explicitly authorized to assess. Keep credentials, private logs, local model files, and sensitive evidence out of version control.
