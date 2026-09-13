"""Importing this package registers every built-in scanner with the default
registry (registration happens as a side effect of importing each scanner
module). The CLI imports this package so a normal run has all scanners available;
tests that need isolation build their own Registry instead.
"""

from scanner.scanners.sca import scanner as _sca  # noqa: F401  (registers "sca")
from scanner.scanners.dast import scanner as _dast  # noqa: F401  (registers "dast")
from scanner.scanners.dast_active import scanner as _dast_active  # noqa: F401  (registers "dast-active")
from scanner.scanners.sast import scanner as _sast  # noqa: F401  (registers "sast")
