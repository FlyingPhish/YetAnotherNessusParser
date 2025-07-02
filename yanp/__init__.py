"""
YANP - Yet Another Nessus Parser
A Python library for parsing and processing Nessus XML reports.

Examples:
    Basic parsing:
        >>> from yanp import NessusParser
        >>> parser = NessusParser('scan.nessus')
        >>> data = parser.parse()
    
    Complete processing pipeline:
        >>> from yanp import process_nessus_file
        >>> results = process_nessus_file('scan.nessus', consolidate=True, api_format=True)
    
    Using individual components:
        >>> from yanp import NessusParser, VulnerabilityConsolidator, APIFormatter
        >>> parser = NessusParser('scan.nessus')
        >>> consolidator = VulnerabilityConsolidator()
        >>> formatter = APIFormatter()
"""

# Import core classes
from .core import (
    NessusParser,
    VulnerabilityConsolidator, 
    APIFormatter,
    ConsolidationError,
    FormatterError
)

# Import CLI functionality
from .cli import cli_entry_point

# Version info - dynamically read from package metadata
try:
    from importlib.metadata import version, metadata
    __version__ = version("yanp")
    
    # Get other metadata from package info
    _metadata = metadata("yanp")
    __author__ = _metadata.get("Author", "FlyingPhishy")
    __description__ = _metadata.get("Summary", "Yet Another Nessus Parser - A Python library for parsing and processing Nessus XML reports")
except ImportError:
    # Fallback for development/editable installs where metadata might not be available
    __version__ = "4.0.0-dev"
    __author__ = "FlyingPhishy"
    __description__ = "Yet Another Nessus Parser - A Python library for parsing and processing Nessus XML reports"
except Exception:
    # Fallback if package not installed properly
    __version__ = "4.0.0-dev"
    __author__ = "FlyingPhishy" 
    __description__ = "Yet Another Nessus Parser - A Python library for parsing and processing Nessus XML reports"

# Public API
__all__ = [
    # Core classes
    "NessusParser",
    "VulnerabilityConsolidator", 
    "APIFormatter",
    
    # Exceptions
    "ConsolidationError",
    "FormatterError",
    
    # Convenience functions
    "process_nessus_file",
    
    # CLI entry point
    "cli_entry_point",
    
    # Package info
    "__version__"
]

def process_nessus_file(
    nessus_file: str,
    consolidate: bool = False,
    api_format: bool = False,
    rules_file: str = None,
    output_dir: str = None,
    custom_output_name: str = None
) -> dict:
    """
    Complete processing pipeline for Nessus files.
    
    This is a convenience function that handles the complete workflow:
    parsing, optional consolidation, and optional API formatting.
    
    Args:
        nessus_file: Path to Nessus XML file
        consolidate: Whether to apply consolidation rules (default: False)
        api_format: Whether to format for API consumption (requires consolidate=True)
        rules_file: Path to custom consolidation rules file (optional)
        output_dir: If provided, write JSON files to this directory (optional)
        custom_output_name: Custom name for the main parsed output file (optional)
        
    Returns:
        dict: Contains 'parsed', 'consolidated' (if requested), and 'api_ready' (if requested) keys
        
    Raises:
        FileNotFoundError: If the Nessus file doesn't exist
        ValueError: If the file is not a valid Nessus file
        ConsolidationError: If consolidation fails
        FormatterError: If API formatting fails
        
    Examples:
        Basic parsing:
            >>> results = process_nessus_file('scan.nessus')
            >>> print(f"Found {len(results['parsed']['vulnerabilities'])} vulnerabilities")
        
        With consolidation:
            >>> results = process_nessus_file('scan.nessus', consolidate=True)
            >>> consolidated = results.get('consolidated')
            >>> if consolidated:
            ...     print(f"Consolidated into {len(consolidated['consolidated_vulnerabilities'])} categories")
        
        Full pipeline with file output and custom name:
            >>> results = process_nessus_file(
            ...     'scan.nessus', 
            ...     consolidate=True, 
            ...     api_format=True,
            ...     output_dir='./results',
            ...     custom_output_name='my_scan_results.json'
            ... )
    """
    results = {}
    
    # Parse Nessus file
    parser = NessusParser(nessus_file)
    parsed_data = parser.parse()
    results['parsed'] = parsed_data
    
    # Optional consolidation
    if consolidate:
        consolidator = VulnerabilityConsolidator(rules_file)
        consolidated_data = consolidator.consolidate(parsed_data)
        results['consolidated'] = consolidated_data
        
        # Optional API formatting
        if api_format and consolidated_data:
            formatter = APIFormatter()
            api_data = formatter.format_for_api(consolidated_data)
            results['api_ready'] = api_data
    
    # Optional file output
    if output_dir:
        from .utils import write_results_to_files
        write_results_to_files(results, nessus_file, output_dir, custom_output_name)
    
    return results

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
        "package": "yanp"
    }