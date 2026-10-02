"""Phase 1C M3A collector tests (stdlib unittest, fixture-based; one short read-only live test)."""
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[2] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
