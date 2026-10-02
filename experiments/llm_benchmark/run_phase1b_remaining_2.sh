#!/usr/bin/env bash
# Phase 1B continuation (2): remaining candidates after qwen3.5:4b early stop. Rules unchanged.
set -u
cd "$HOME/sentinelai"
echo "### remaining candidates (2) $(date -Is)"
env PYTHONNOUSERSITE=1 .venv/bin/python -u experiments/llm_benchmark/benchmark.py campaign --models qwen3:8b,qwen3.5:9b
echo "### PHASE1B_REMAINING_DONE rc=$? $(date -Is)"
