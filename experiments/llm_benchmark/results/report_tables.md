### Models and digests

| Model | Digest (sha256) | Size | Params | Quant | Downloaded | Date | Capabilities | License |
|---|---|---|---|---|---|---|---|---|
| gemma3:1b | `8648f39daa8fbf5b18c7b4e6a8fb4990c692751d49917417b8842ca5758e7ffc` | 0.82 GB | 999.89M | Q4_K_M | pre-existing | pre-existing | completion | Gemma Terms of Use  |
| qwen3:4b | `359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7` | 2.50 GB | 4.0B | Q4_K_M | 1B | 2026-10-02 | completion, tools, thinking | Apache License |
| qwen3.5:4b | `2a654d98e6fba55d452b7043684e9b57a947e393bbffa62485a7aac05ee4eefd` | 3.39 GB | 4.7B | Q4_K_M | 1B | 2026-10-02 | completion, vision, tools, thinking | Apache License |
| qwen3:8b | `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41` | 5.23 GB | 8.2B | Q4_K_M | 1B | 2026-10-02 | completion, tools, thinking | Apache License |
| qwen3.5:9b | `6488c96fa5faab64bb65cbd30d4289e20e6130ef535a93ef9a49f42eda893ea7` | 6.59 GB | 9.7B | Q4_K_M | 1B | 2026-10-02 | completion, vision, tools, thinking | Apache License |

### Coverage and early stops

| Model | think | gen | know | evid | struct-prompt | struct-constr | tools | agent | context | Early stop |
|---|---|---|---|---|---|---|---|---|---|---|
| gemma3:1b | None | 15/15 | 10/10 | 8/8 | 30/30 | 30/30 | 28/28 | 12/12 | 8/8 | — |
| qwen3:4b | True | 15/15 | 10/10 | 8/8 | 14/30 | 0/30 | 0/28 | 0/12 | 0/8 | **reviewer**: Reviewer stop on objective evidence: generation 12/15, evidence 7/8, structured_prompt 14/ |
| qwen3.5:4b | False | 15/15 | 10/10 | 8/8 | 30/30 | 30/30 | 28/28 | 5/12 | 0/8 | **automatic**: ES1 failure-to-complete: 5/5 requests in 'agent' produced no usable output (> 50%) |
| qwen3:8b | False | 15/15 | 10/10 | 8/8 | 30/30 | 30/30 | 28/28 | 12/12 | 8/8 | — |
| qwen3.5:9b | False | 15/15 | 10/10 | 8/8 | 30/30 | 30/30 | 28/28 | 12/12 | 8/8 | — |

### Performance (4K-context suites; medians)

| Model | Gen tok/s | Gen tok/s range | Prompt tok/s | TTFT s | Gen wall s | Gen out tok | Agent turn s | Peak RSS GiB | Min MemAvail GiB | Sys CPU % (mean) | Runner CPU % | Load s | Failed/requests |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gemma3:1b | 56.59 | 52.56–60.86 | 294.1 | 0.29 | 4.3 | 220 | None | 0.94 | 10.96 | 34.4 | 800.3 | 1.0564 | 0/102 |
| qwen3:4b | 18.41 | 18.06–19.65 | 101.9 | 0.76 | 77.12 | 1408 | 77.83 | 3.04 | 8.80 | 34.3 | 800.2 | 0.0011 | 0/62 |
| qwen3.5:4b | 16.73 | 16.31–17.69 | 85.74 | 0.92 | 16.59 | 266 | 3.81 | 4.30 | 7.66 | 34.3 | 800.1 | 0.0088 | 5/126 |
| qwen3:8b | 10.57 | 10.43–10.95 | 53.32 | 1.54 | 22.14 | 220 | 5.03 | 5.62 | 6.85 | 34.3 | 800.0 | 0.0088 | 0/142 |
| qwen3.5:9b | 9.69 | 9.45–9.87 | 46.38 | 1.67 | 28.05 | 259 | 9.25 | 7.15 | 6.15 | 34.3 | 800.0 | 0.0014 | 0/142 |

### Tool calling (25 tool tasks + 3 no-tool tasks)

| Model | Success (score 2) | Arg validity | Wrong tool | Missing call | Hallucinated tool | No-tool correct | Norm score |
|---|---|---|---|---|---|---|---|
| gemma3:1b | unsupported | unsupported | unsupported | unsupported | unsupported | unsupported | unsupported |
| qwen3:4b | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| qwen3:4b *(slice, n=10)* | 40% | 100% | 0% | 50% | 0% | — | 0.45 |
| qwen3.5:4b | 100% | 100% | 0% | 0% | 0% | 100% | 1.00 |
| qwen3:8b | 96% | 100% | 0% | 4% | 0% | 100% | 0.96 |
| qwen3.5:9b | 100% | 100% | 0% | 0% | 0% | 100% | 1.00 |

### Structured output (30 incidents per mode; Pydantic strict, extra=forbid)

| Model | Mode | Valid JSON | Schema valid | Missing field | Extra field | Parse failure | Markdown fenced | Valid after fence-strip | Semantically correct |
|---|---|---|---|---|---|---|---|---|---|
| gemma3:1b | prompt | 0% | 0% | 0% | 0% | 100% | 100% | 80% | 0% |
| gemma3:1b | constrained | 100% | 100% | 0% | 0% | 0% | 0% | 100% | 40% |
| qwen3:4b | prompt | 0% | 0% | 0% | 0% | 100% | 0% | 0% | 0% |
| qwen3:4b | constrained | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| qwen3.5:4b | prompt | 60% | 60% | 0% | 0% | 40% | 40% | 93% | 50% |
| qwen3.5:4b | constrained | 100% | 100% | 0% | 0% | 0% | 0% | 100% | 80% |
| qwen3:8b | prompt | 100% | 100% | 0% | 0% | 0% | 0% | 100% | 80% |
| qwen3:8b | constrained | 100% | 100% | 0% | 0% | 0% | 0% | 100% | 80% |
| qwen3.5:9b | prompt | 100% | 100% | 0% | 0% | 0% | 0% | 100% | 70% |
| qwen3.5:9b | constrained | 100% | 100% | 0% | 0% | 0% | 0% | 100% | 70% |

### Agent loop (12 scenarios, ≤6 tool calls; 3 ambiguous)

| Model | Success | Multi-step success | Confident wrong | No diagnosis | Over-cautious | Ambiguous correct (of 3) | Mean tool calls | Median scenario s | Hallucinated calls | Invalid-arg calls | Norm | Coverage |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gemma3:1b | unsupported | unsupported | unsupported | unsupported | unsupported | unsupported | unsupported | unsupported | unsupported | unsupported | unsupported | 12/12 |
| qwen3:4b | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | 0/12 |
| qwen3:4b *(slice, n=5)* | 40% | 0% | 0 | 3 | 0 | — | 0.4 | 78.89 | 0 | 1 | 0.40 | 5/5 |
| qwen3.5:4b | 0% | 0% | 0 | 0 | 0 | 0 | 6.0 | 30.72 | 0 | 0 | 0.00 | 5/12 |
| qwen3:8b | 92% | 92% | 1 | 0 | 0 | 3 | 3.75 | 28.05 | 0 | 0 | 0.92 | 12/12 |
| qwen3.5:9b | 83% | 83% | 2 | 0 | 0 | 3 | 2.67 | 39.25 | 0 | 0 | 0.83 | 12/12 |

### Evidence discipline (6 insufficient-evidence + 2 sufficient controls)

| Model | Abstained (insufficient) | Unsupported root cause | Controls correct | Controls over-cautious | Format followed | Unprompted numbers (heuristic) | Norm |
|---|---|---|---|---|---|---|---|
| gemma3:1b | 17% | 83% | 2/2 | 0 | 8/8 | 1/8 | 0.38 |
| qwen3:4b | 17% | 83% | 0/2 | 0 | 1/8 | 0/8 | 0.12 |
| qwen3.5:4b | 100% | 0% | 1/2 | 1 | 8/8 | 0/8 | 0.94 |
| qwen3:8b | 100% | 0% | 1/2 | 1 | 8/8 | 0/8 | 0.88 |
| qwen3.5:9b | 100% | 0% | 2/2 | 0 | 8/8 | 0/8 | 1.00 |

### Technical knowledge (10) and generation (5×3)

| Model | Knowledge mean (0–2) | Knowledge norm | Generation mean (0–2) | Generation norm |
|---|---|---|---|---|
| gemma3:1b | 1.10 | 0.55 | 0.80 | 0.40 |
| qwen3:4b | 1.80 | 0.90 | 0.13 | 0.07 |
| qwen3.5:4b | 1.60 | 0.80 | 1.67 | 0.83 |
| qwen3:8b | 1.70 | 0.85 | 1.47 | 0.73 |
| qwen3.5:9b | 1.80 | 0.90 | 1.60 | 0.80 |

### Context scaling (2 reps per size; medians)

| Model | Nominal | Actual prompt tok | num_ctx | Prompt tok/s | TTFT s | Wall s | Gen tok/s | Peak RSS GiB | Needle (0–2) | Failures / truncated |
|---|---|---|---|---|---|---|---|---|---|---|
| gemma3:1b | 1024 | 1120.0 | 2048 | 296.55 | 4.37 | 5.03 | 55.08 | 1.01 | 1/2 | 0 / trunc=False |
| gemma3:1b | 2048 | 2235.0 | 3072 | 299.11 | 8.06 | 8.79 | 54.53 | 0.92 | 1/2 | 0 / trunc=False |
| gemma3:1b | 4096 | 4451.0 | 5120 | 294.06 | 15.73 | 17.1 | 53.7 | 1.01 | 0/2 | 0 / trunc=False |
| gemma3:1b | 8192 | 8745.0 | 9216 | 283.56 | 31.44 | 31.69 | 54.16 | 1.04 | 0/2 | 0 / trunc=False |
| qwen3:4b | NOT RUN |  |  |  |  |  |  |  |  |  |
| qwen3.5:4b | NOT RUN |  |  |  |  |  |  |  |  |  |
| qwen3:8b | 1024 | 1118.0 | 2048 | 50.28 | 24.13 | 29.27 | 9.91 | 6.28 | 2/2 | 0 / trunc=False |
| qwen3:8b | 2048 | 2227.0 | 3072 | 48.52 | 47.78 | 54.04 | 9.36 | 5.48 | 2/2 | 0 / trunc=False |
| qwen3:8b | 4096 | 4433.0 | 5120 | 44.92 | 100.7 | 106.47 | 7.28 | 5.86 | 2/2 | 0 / trunc=False |
| qwen3:8b | 8192 | 8745.0 | 9216 | 39.52 | 223.44 | 235.85 | 5.08 | 6.43 | 2/2 | 0 / trunc=False |
| qwen3.5:9b | 1024 | 1115.0 | 2048 | 49.14 | 25.23 | 29.92 | 9.6 | 6.91 | 2/2 | 0 / trunc=False |
| qwen3.5:9b | 2048 | 2224.0 | 3072 | 48.92 | 47.87 | 52.72 | 9.48 | 6.67 | 1/2 | 0 / trunc=False |
| qwen3.5:9b | 4096 | 4430.0 | 5120 | 47.17 | 96.47 | 101.44 | 9.04 | 6.82 | 2/2 | 0 / trunc=False |
| qwen3.5:9b | 8192 | 8742.0 | 9216 | 45.52 | 194.47 | 200.27 | 8.19 | 6.96 | 1/2 | 0 / trunc=False |

### Gates and quality score

| Model | G1 stability | G2 memory | G3 speed | G4 tools | G5 structured | G6 evidence | Not early-stopped | Q | Eligible |
|---|---|---|---|---|---|---|---|---|---|
| gemma3:1b | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ | 0.2363 | no |
| qwen3:4b | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | 0.1121 | no |
| qwen3.5:4b | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | 0.6474 | no |
| qwen3:8b | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 0.904 | **yes** |
| qwen3.5:9b | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 0.9074 | **yes** |

### Q components (normalised 0–1; weights {"agent": 0.3, "tools": 0.25, "evidence": 0.15, "structured": 0.15, "knowledge": 0.1, "generation": 0.05})

| Model | Agent | Tools | Evidence | Structured (constr.) | Knowledge | Generation | Q |
|---|---|---|---|---|---|---|---|
| gemma3:1b | 0.00 | 0.00 | 0.38 | 0.70 | 0.55 | 0.40 | 0.2363 |
| qwen3:4b | 0.00 | 0.00 | 0.12 | 0.00 | 0.90 | 0.07 | 0.1121 |
| qwen3.5:4b | 0.00 | 1.00 | 0.94 | 0.90 | 0.80 | 0.83 | 0.6474 |
| qwen3:8b | 0.92 | 0.96 | 0.88 | 0.90 | 0.85 | 0.73 | 0.904 |
| qwen3.5:9b | 0.83 | 1.00 | 1.00 | 0.85 | 0.90 | 0.80 | 0.9074 |

### Decision (score.py)

```json
{
  "primary": "qwen3.5:9b",
  "primary_rule": "highest Q",
  "best_Q_model": "qwen3.5:9b",
  "secondary": "qwen3:8b",
  "baseline": "gemma3:1b",
  "verdict": "PASS"
}
```
