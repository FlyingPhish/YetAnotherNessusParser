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
from .ad_analyzer import ADAnalyzerError, load_bloodhound_zip
from .ad_pipeline import analyze_bloodhound
from .ad_excel import ADExcelFormatter
from .ad_reporting import (
    ADAPIFormatter,
    ADReportingError,
    load_ad_configuration,
    load_ad_rules,
    map_ad_findings,
)

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
    'analyze_bloodhound',
    'load_bloodhound_zip',
    
    # Exceptions
    'ConsolidationError',
    'FormatterError',
    "ADAnalyzerError",
    "ADReportingError",
    "ADAPIFormatter",
    "ADExcelFormatter",
    "load_ad_configuration",
    "load_ad_rules",
    "map_ad_findings",
]
