# Guardrails Control Matrix

This matrix maps the educational assignment objectives to the observed control areas and the limits of the available regression evidence.

| Control area | Security objective | Recorded evidence | Limitation |
|---|---|---|---|
| Instruction vs. quoted data | Avoid treating quoted or analyzed text as active instructions by default | Targeted cases C20–C23 and I01/I03 were reported passing | The broader content group still has failures |
| Text rules and similarity | Improve matching while reducing benign collisions | Similarity gate checks an attack threshold and margin over benign similarity; invalid numeric inputs are rejected | Threshold quality depends on corpus coverage and calibration |
| Authorization | Verify permission before a sensitive tool call | 12/12 supplied authorization checks passed | Does not prove all authorization bypasses are impossible |
| Tool-result checks | Treat tool output as untrusted data and inspect it | 11/11 supplied tool-result checks passed | Coverage is limited to tested payloads |
| Output checks | Detect unsafe output and leakage patterns | 6/6 supplied output checks passed; selected targeted checks were reported passing | Coverage depends on rules and assertions |
| Failure handling | Fail safely under expected failure conditions | 12/12 supplied failure checks passed | Must be retested as implementation changes |
| Content classification | Select appropriate actions and reason codes | 96/154 content checks passed | Main remaining issue: 58 failed cases |

## Recorded aggregate

- Total: 208 cases
- Passed: 150 (72.1%)
- Failed: 58 (27.9%)
- Remaining failures: all within the content group in the recorded run

## Review priorities

1. Triage each remaining content failure by category.
2. Separate action selection from reason-code assignment.
3. Keep regression tests for adversarial inputs and benign near-neighbours.
4. Verify that trusted code checks authorization before a sensitive tool call.
5. Re-run the full suite after meaningful implementation changes and compare like-for-like configurations.

## Interpretation

Passing assertions support only the tested behaviors and configuration. The results are not proof that the implementation is secure against all inputs or suitable for production.
