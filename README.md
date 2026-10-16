# ADLC Server-Side Guardrails

> **AI Security · Guardrails Engineering · LLM Agent Security**  
> An educational implementation and assessment of server-side guardrails for an LLM-agent lab.

![Focus](https://img.shields.io/badge/focus-AI%20Security-17365D)
![Scope](https://img.shields.io/badge/scope-Server--Side%20Guardrails-0F6B78)
![Status](https://img.shields.io/badge/status-Educational%20Prototype-lightgrey)

## Overview

This repository contains the Homework 3 assessment, supporting security documentation, and six modified Python source files for a server-side guardrail layer. The work focuses on separating trusted application policy from untrusted text and model-generated intent.

The central principle is that **model output, user input, retrieved content, and tool results must not replace trusted application policy or authorization**.

The project is based on the educational lab maintained separately by [makrushind/adlc-lab](https://github.com/makrushind/adlc-lab). This repository is an educational overlay/patch and is not currently a self-contained installable package.

## Assessment status

Latest recorded full regression run:

| Result | Count |
|---|---:|
| Passed | **150 / 208 (72.1%)** |
| Failed | 58 / 208 (27.9%) |
| Content classification | 96 / 154 passed |
| Other groups | 54 / 54 passed |

All 58 recorded failures were in the `content` group. The `input`, `authorization`, `tool_result`, `output`, `similarity` and `failures` groups passed all supplied assertions in that run.

These results describe one educational regression corpus and configuration. They are not a general security guarantee and do **not** indicate production readiness. The results are recorded from a local run and have not been independently reproduced from this repository.

## Security controls in scope

- **Policy decisions:** classify requests and select actions/reason codes.
- **Instruction versus data:** consider quoted or analyzed text without automatically treating it as an active instruction.
- **Similarity gate:** validate numeric inputs and consider attack similarity alongside benign similarity.
- **Authorization:** check permissions before sensitive tool execution.
- **Tool-result validation:** treat external tool output as untrusted and inspect it before further use.
- **Output checks:** inspect final responses for unsafe content and sensitive-data leakage.
- **Failure handling:** exercise expected detector/runtime failure behavior and fail safely when required components are unavailable.

## Conceptual architecture

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

This diagram is conceptual. Review the implementation and its runtime integration before relying on any specific enforcement path.

## Repository layout

| Path | Purpose |
|---|---|
| `src/aiweekend_target/guardrails/weak/` | Six modified guardrail source files |
| `report/homework-03.md` | Assessment summary, findings, recorded results and retest plan |
| `docs/guardrails-control-matrix.md` | Security objectives mapped to controls and evidence |
| `docs/architecture.md` | Trust boundaries and conceptual control flow |
| `docs/methodology.md` | Methodology and interpretation of regression results |
| `SECURITY.md` | Responsible testing and evidence-handling guidance |
| `ATTRIBUTION.md` | Upstream project, license and scope notes |
| `LICENSE` | Upstream MIT license text retained with attribution |

Implementation files included:
`authorization.py`, `detectors.py`, `engine.py`, `output_checks.py`, `policy.py` and `similarity.py`.

## Reproducing the recorded test

The recorded run used the separate upstream lab checkout, Python 3.13+ and its homework runner. From the root of that checkout, the commands were:

```powershell
.\.venv-guardrails\Scripts\python.exe -m homework check
.\.venv-guardrails\Scripts\python.exe -m homework explain CASE
```

Replace `CASE` with a case identifier when inspecting one test. These commands are **not expected to work from this repository alone**: the overlay depends on upstream package modules, configuration, data and test assets. To reproduce or extend the work, first obtain the upstream lab and its dependencies, then apply/review the modified files at the matching package paths. The recorded result has not been verified by a fresh run from this repository.

## Findings and limitations

Content classification is the primary remaining follow-up area. The recorded failures include cases involving quoted scam/injection content, harmful-generation requests, policy questions and reason-code specificity. See [the detailed report](report/homework-03.md) and [control matrix](docs/guardrails-control-matrix.md).

A passing test group demonstrates compliance with that group's supplied assertions only. It does not prove resistance to untested payloads, integrations, configurations or attack techniques. This project is an educational prototype, not a production-ready guardrail framework or security certification.

## Related projects

- [DocsAgent Security Assessment — Homework 1](https://github.com/ConstantineFedorov/docsagent-security-assessment)
- [ADLC Agent Security Assessment — Homework 2](https://github.com/ConstantineFedorov/adlc-agent-security-assessment)
- [Upstream ADLC lab](https://github.com/makrushind/adlc-lab)

## Interview summary

> I assessed and modified an educational server-side guardrail layer for an LLM-agent lab. The work covered policy decisions, instruction-versus-data handling, similarity checks, authorization before sensitive tool calls, tool-result validation and final-output checks. The latest recorded regression run passed 150 of 208 cases, with all 58 remaining failures in content classification. I documented the limitations and follow-up work rather than presenting the prototype as production-ready.

## Responsible use

Test only systems you own or are explicitly authorized to assess. Use isolated environments and harmless test values. Do not publish credentials, private logs, local model files or sensitive evidence. See [ATTRIBUTION.md](ATTRIBUTION.md) and the retained upstream license text for provenance and license information. The upstream author has not endorsed this repository or its modifications.
