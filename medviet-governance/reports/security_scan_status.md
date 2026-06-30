# Security scan status

All required security tools were exercised on 2026-06-30.

| Control | Result |
|---|---|
| Bandit SAST | PASS — 0 issues |
| OPA policy tests | PASS — 4/4 |
| git-secrets working tree | PASS — no prohibited patterns |
| git-secrets history | PASS — no prohibited patterns after allowlisting documented test fixtures |
| git-secrets hook block test | PASS — fake non-allowlisted AWS key blocked with exit code 1 |
| TruffleHog Git scan | PASS — 31 chunks, 105,201 bytes, 0 verified secrets |
| pip-audit | PASS — no known vulnerabilities |

The credential shown in the original lab (`...EXAMPLEKEY`) is automatically
allowlisted by `git secrets --register-aws`. Therefore, the hook test used a
different fake, structurally valid AWS access key in an isolated temporary Git
repository. The failed commit did not modify the assignment repository history.
