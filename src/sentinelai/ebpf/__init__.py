"""Phase 1C M3B: process boundary for the privileged eBPF loader (ebpf/loader).

The collector layer stays pure (sentinelai.collectors.ebpf parses and measures). This package is the
only place that starts the loader process; starting it with privileges is a separate, explicitly
authorised validation step and never happens implicitly.
"""

from .loader import (DEFAULT_LOADER, LoaderRefused, ProcessEbpfSource, loader_argv, replay_argv,
                     resolve_ebpf_target)

__all__ = ["DEFAULT_LOADER", "LoaderRefused", "ProcessEbpfSource", "loader_argv", "replay_argv",
           "resolve_ebpf_target"]
