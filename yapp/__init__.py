"""
yapp/__init__.py
YAPP - Swiss Army Knife for Pentester File Processing
A Python library for parsing and processing various pentesting tool outputs.

Supported formats:
- Nessus .nessus XML files (with consolidation and API formatting)
- Nmap .xml XML files (with flat JSON output option)

Examples:
    Basic parsing (auto-detect):
        >>> from yapp import process_file
        >>> results = process_file('scan.nessus')
        >>> # or
        >>> results = process_file('scan.xml')
    
    Nessus with consolidation and API output:
        >>> from yapp import process_file
        >>> results = process_file('scan.nessus', consolidate=True, api_format=True, entity_limit=10)
    
    Nmap with port filtering:
        >>> from yapp import process_file
        >>> results = process_file('scan.xml', port_status='open')
    
    Nmap with flat JSON output (legacy tool compatibility):
        >>> from yapp import process_file
        >>> results = process_file('scan.xml', flat_json=True)
    
    Using individual components:
        >>> from yapp import NessusParser, NmapParser, VulnerabilityConsolidator, APIFormatter
        >>> nessus_parser = NessusParser('scan.nessus')
        >>> nmap_parser = NmapParser('scan.xml')
        >>> consolidator = VulnerabilityConsolidator()
        >>> formatter = APIFormatter(entity_limit=5)
"""

# Import core classes
from .core import (
    NessusParser,
    NmapParser,
    VulnerabilityConsolidator, 
    APIFormatter,
    ConsolidationError,
    FormatterError
)

# Import main processing function
from .core.processor import process_file

# Import CLI functionality
from .cli import cli_entry_point

# Import utilities
from .utils.file_utils import detect_file_type

# Version info - dynamically read from package metadata
try:
    from importlib.metadata import version, metadata
    __version__ = version("yapp")
    
    # Get other metadata from package info
    _metadata = metadata("yapp")
    __author__ = _metadata.get("Author", "FlyingPhishy")
    __description__ = _metadata.get("Summary", "Swiss Army Knife for Pentester File Processing")
except ImportError:
    # Fallback for development/editable installs where metadata might not be available
    __version__ = "4.0.0-dev"
    __author__ = "FlyingPhishy"
    __description__ = "Swiss Army Knife for Pentester File Processing"
except Exception:
    # Fallback if package not installed properly
    __version__ = "4.0.0-dev"
    __author__ = "FlyingPhishy" 
    __description__ = "Swiss Army Knife for Pentester File Processing"

# Public API
__all__ = [
    # Core parsers
    "NessusParser",
    "NmapParser",
    
    # Processing classes
    "VulnerabilityConsolidator", 
    "APIFormatter",
    
    # Exceptions
    "ConsolidationError",
    "FormatterError",
    
    # Main processing function
    "process_file",
    
    # Utilities
    "detect_file_type",
    
    # CLI entry point
    "cli_entry_point",
    
    # Package info
    "__version__"
]



def get_supported_file_types() -> dict:
    """
    Get information about supported file types and their capabilities.
    
    Returns:
        dict: File type information including supported features
    """
    return {
        "nessus": {
            "description": "Nessus vulnerability scanner XML files",
            "extensions": [".nessus"],
            "features": ["parsing", "consolidation", "api_formatting", "entity_limiting"],
            "parser_class": "NessusParser"
        },
        "nmap": {
            "description": "Nmap network scanner XML files", 
            "extensions": [".xml"],
            "features": ["parsing", "port_filtering", "flat_json_output"],
            "parser_class": "NmapParser"
        }
    }

def get_version_info() -> dict:
    """
    Get detailed version and package information.
    
    Returns:
        dict: Version information including package details
    """
    return {
        "version": __version__,
        "author": __author__, 
        "description": __description__,
        "package": "yapp",
        "supported_formats": list(get_supported_file_types().keys())
    }