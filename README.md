# ADLC Server-Side Guardrails

> **AI Security · Guardrails Engineering · LLM Agent Security**  
> An educational assessment of server-side guardrails for an LLM-agent lab, focusing on instruction/data separation, policy decisions, authorization, tool-result validation and output checks.

![Focus](https://img.shields.io/badge/focus-AI%20Security-17365D)
![Scope](https://img.shields.io/badge/scope-Server--Side%20Guardrails-0F6B78)
![Runtime](https://img.shields.io/badge/runtime-Python%203.13%2B-3776AB)
![Status](https://img.shields.io/badge/status-Educational%20Prototype-lightgrey)

## Overview

This repository presents the third ADLC security assignment as a standalone portfolio project. It documents work on a server-side decision layer around an LLM agent, including content classification, similarity checks, authorization before sensitive tool calls, tool-result checks and final-output validation.

The central design principle is that **untrusted text and model-generated intent must not replace trusted application policy or authorization**.

The work is based on an educational lab maintained separately by its upstream author: [makrushind/adlc-lab](https://github.com/makrushind/adlc-lab). This repository documents the assessment and is not a claim of ownership over the upstream lab or its complete test corpus.

## Assessment status

The latest recorded full regression run covered 208 cases:

| Result | Count |
|---|---:|
| Passed | **150 / 208 (72.1%)** |
| Failed | 58 / 208 (27.9%) |
| Content classification | 96 / 154 passed |
| Other test groups | 54 / 54 passed |

The 58 remaining failures were in the `content` group. The `input`, `authorization`, `tool_result`, `output`, `similarity` and `failures` groups passed all supplied assertions in that run.

These results apply to a specific educational regression corpus and configuration. They are not a general security guarantee and do not indicate production readiness.

## Scope and security controls

- **Instruction versus data:** handle quoted or analyzed text without automatically treating it as an active instruction.
- **Content classification:** classify requests and select an appropriate action and reason code.
- **Similarity gate:** consider attack similarity together with benign similarity and validate numeric inputs.
- **Authorization:** check permissions before sensitive tool execution.
- **Tool-result checks:** treat external tool output as untrusted and inspect it before further use.
- **Output checks:** inspect final responses for unsafe content and sensitive-data leakage.
- **Failure handling:** test expected detector/runtime failure conditions and document degraded behavior.

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

The diagram is conceptual. Exact enforcement paths and policy semantics should be reviewed in the implementation before reuse.

## Repository contents

| Path | Purpose |
|---|---|
| `report/homework-03.md` | Detailed assessment, test results, findings and retest plan |
| `docs/guardrails-control-matrix.md` | Objective-to-control mapping and observed evidence |
| `docs/architecture.md` | Trust boundaries and high-level control flow |
| `docs/methodology.md` | Interpretation of regression results |
| `SECURITY.md` | Responsible testing and evidence-handling guidance |

Implementation files will be added after confirming what can be redistributed from the upstream educational lab. Obtain the upstream checkout and its data from the original source under its applicable terms.

## Reproducing the recorded test

The run was performed in the local ADLC lab with Python 3.13+ and the built-in homework runner. In that checkout, the command was:

```powershell
.\.venv-guardrails\Scripts\python.exe -m homework check
```

To inspect a single case:

```powershell
.\.venv-guardrails\Scripts\python.exe -m homework explain CASE
```

These commands assume the separate upstream lab checkout, its package/dependency setup and relevant test assets are available. They are not guaranteed to work from this documentation-only repository yet.

## Findings and limitations

The latest recorded aggregate passed all supplied assertions for input handling, authorization, tool-result checks, output checks, similarity checks and expected failure handling. The principal remaining weakness is content classification, where quoted scams/injections, harmful-generation requests, policy questions and reason-code specificity need further triage.

A passing group demonstrates compliance with that group's supplied assertions only. It does not prove resistance to untested payloads, configurations or attack techniques. This is an educational assessment, not a production-ready guardrail framework or a security certification.

## Related projects

- [DocsAgent Security Assessment — Homework 1](https://github.com/ConstantineFedorov/docsagent-security-assessment)
- [ADLC Agent Security Assessment — Homework 2](https://github.com/ConstantineFedorov/adlc-agent-security-assessment)
- [Upstream ADLC lab](https://github.com/makrushind/adlc-lab)

## Interview summary

> I worked on an educational server-side guardrail implementation for an LLM-agent lab. The assessment covered instruction-versus-data handling, content classification, similarity gates, authorization before sensitive tool calls, tool-result checks and final-output validation. The latest recorded regression run passed 150 of 208 cases; all 58 remaining failures were in content classification. I documented the result as an intermediate finding and identified content classification as the primary follow-up area, while emphasizing that permissions must be enforced by trusted application code outside the model.

## Responsible use

Test only systems you own or are explicitly authorized to assess. Use isolated environments and harmless test values. Do not publish credentials, private logs, local model files or sensitive evidence. Review the upstream license and corpus terms before redistributing code or test data.
