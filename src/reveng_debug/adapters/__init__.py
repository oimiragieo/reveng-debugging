from reveng_debug.adapters.electron import inventory_electron
from reveng_debug.adapters.javascript import inventory_javascript, slice_text
from reveng_debug.adapters.pe import inventory_pe
from reveng_debug.adapters.website import clone_website

__all__ = [
    "clone_website",
    "inventory_electron",
    "inventory_javascript",
    "inventory_pe",
    "slice_text",
]
