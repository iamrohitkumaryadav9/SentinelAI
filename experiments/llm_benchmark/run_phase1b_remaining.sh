#!/usr/bin/env bash
# Phase 1B continuation: qwen3:4b validation slice + early-stop record, then remaining candidates.
set -u
cd "$HOME/sentinelai"
PY="env PYTHONNOUSERSITE=1 .venv/bin/python -u experiments/llm_benchmark/benchmark.py"
echo "### qwen3:4b validation slice $(date -Is)"
$PY run --model qwen3:4b --suites slice
$PY early-stop --model qwen3:4b \
  --trigger "Reviewer stop on objective evidence: generation 12/15, evidence 7/8, structured_prompt 14/14 requests hit the token budget (num_predict + 1024 thinking) with no answer; median latency 66-77 s/request" \
  --decided-by "reviewer (user instruction 2026-10-02 ~16:05), before ES rules were pre-registered; validation slice run afterwards"
echo "### remaining candidates $(date -Is)"
$PY campaign --models qwen3.5:4b,qwen3:8b,qwen3.5:9b
echo "### PHASE1B_REMAINING_DONE rc=$? $(date -Is)"
