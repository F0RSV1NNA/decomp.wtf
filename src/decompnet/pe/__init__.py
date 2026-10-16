"""Windows PE32+ (x64) import.

Read a linked image, recover its functions, and build synthetic target objects that an
objdiff project can be driven from -- so a stripped third-party executable can be worked
on with no original objects and no PDB.

`pe.image` reads the format; `pe.discover` finds functions; `pe.coff` writes the objects.
"""

from .discover import Found, call_targets, discover, unwind_regions
from .image import PEError, PEImage, RuntimeFunction, Section

__all__ = ["PEImage", "PEError", "RuntimeFunction", "Section",
           "Found", "discover", "call_targets", "unwind_regions"]
