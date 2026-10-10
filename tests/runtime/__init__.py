"""Phase 2A.1 runtime core tests (stdlib unittest; no live /proc or /sys, no eBPF attach, no host change)."""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
for _p in (_ROOT / "src", _ROOT / "tests"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
