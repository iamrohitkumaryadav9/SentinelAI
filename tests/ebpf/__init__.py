"""Phase 1C M3B eBPF tests (stdlib unittest). Build and fixture tests only: nothing is loaded or attached."""
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[2] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
