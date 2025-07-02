"""
yanp/core/__init__.py
YANP core processing modules.

This package contains the core functionality for parsing, consolidating,
and formatting data from various pentesting tools.

Supported parsers:
- NessusParser: Parse Nessus .nessus XML files
- NmapParser: Parse Nmap .xml XML files

Future parsers can be added following the same interface pattern.
"""

from .nessus_parser import NessusParser
from .nmap_parser import NmapParser
from .consolidator import VulnerabilityConsolidator, ConsolidationError
from .formatter import APIFormatter, FormatterError

__all__ = [
    # Core parsers
    'NessusParser',
    'NmapParser',
    
    # Processing classes
    'VulnerabilityConsolidator', 
    'APIFormatter',
    
    # Exceptions
    'ConsolidationError',
    'FormatterError'
]