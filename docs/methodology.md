# Test Methodology and Result Interpretation

## Scope

The recorded suite contains 208 cases for an educational ADLC guardrail lab. Assertions may check both the selected action and reason code, so an action that seems directionally correct can still fail if its classification differs from the expected value.

## Latest recorded result

| Group | Passed | Failed | Total |
|---|---:|---:|---:|
| content | 96 | 58 | 154 |
| input | 6 | 0 | 6 |
| authorization | 12 | 0 | 12 |
| tool_result | 11 | 0 | 11 |
| output | 6 | 0 | 6 |
| similarity | 7 | 0 | 7 |
| failures | 12 | 0 | 12 |
| **Total** | **150** | **58** | **208** |

The pass rate was 72.1%. All 58 failures in this recorded aggregate were in the content group.

## Reproduction in the lab checkout

The command used in the working lab was:

```powershell
.\.venv-guardrails\Scripts\python.exe -m homework check
```

For a specific case:

```powershell
.\.venv-guardrails\Scripts\python.exe -m homework explain CASE
```

These commands assume the original lab checkout, the homework package, its dependencies and test assets are installed. They are not guaranteed to work from this documentation-only repository yet.

## Interpretation rules

1. Report the corpus size and configuration with each result.
2. Distinguish security outcomes from task completion and classification accuracy.
3. Do not infer complete security from a passing test group.
4. Preserve evidence for failed as well as passed cases.
5. Compare runs only when corpus, configuration and assertions are comparable.
6. Treat remaining failures as unresolved until individually reproduced and triaged.

## Limitation

These are educational regression results, not an independent security audit or production-readiness assessment.
