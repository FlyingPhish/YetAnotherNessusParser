"""
yapp/core/__init__.py
YAPP core processing modules.

This package contains the core functionality for parsing, consolidating,
and formatting data from various pentesting tools.

Supported parsers:
- NessusParser: Parse Nessus .nessus XML files
- NmapParser: Parse Nmap .xml XML files

Future parsers can be added following the same interface pattern.
"""

from .nessus_parser import NessusParser
from .nmap_parser import NmapParser
from .nmap_comparator import NmapComparator
from .consolidator import VulnerabilityConsolidator, ConsolidationError
from .formatter import APIFormatter, FormatterError
from .excel_formatter import ExcelFormatter
from .processor import process_file, process_nmap_comparison

__all__ = [
    # Core parsers
    'NessusParser',
    'NmapParser',
    'NmapComparator',
    
    # Processing classes
    'VulnerabilityConsolidator', 
    'APIFormatter',
    'ExcelFormatter',
    
    # Main processing functions
    'process_file',
    'process_nmap_comparison',
    
    # Exceptions
    'ConsolidationError',
    'FormatterError'
]