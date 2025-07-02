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
    
    # Convenience functions
    "process_file",
    "process_nessus_file",  # Backward compatibility
    
    # Utilities
    "detect_file_type",
    
    # CLI entry point
    "cli_entry_point",
    
    # Package info
    "__version__"
]

def process_file(
    input_file: str,
    file_type: str = "auto",
    port_status: str = "all",
    consolidate: bool = False,
    api_format: bool = False,
    rules_file: str = None,
    entity_limit: int = None,
    output_dir: str = None,
    custom_output_name: str = None,
    flat_json: bool = False
) -> dict:
    """
    Complete processing pipeline for supported file types.
    
    This is the main convenience function that handles the complete workflow:
    parsing, optional consolidation (Nessus only), optional API formatting (Nessus only),
    and optional flat JSON output (Nmap only).
    
    Args:
        input_file: Path to input file
        file_type: File type ('auto', 'nessus', 'nmap')
        port_status: Port status filter for Nmap ('all', 'open', 'closed', 'filtered')
        consolidate: Whether to apply consolidation rules (Nessus only)
        api_format: Whether to format for API consumption (Nessus only, requires consolidate=True)
        rules_file: Path to custom consolidation rules file (Nessus only)
        entity_limit: Maximum number of affected entities per API finding (Nessus only)
        output_dir: If provided, write JSON files to this directory
        custom_output_name: Custom name for the main parsed output file
        flat_json: Whether to generate flat JSON format compatible with legacy tools (Nmap only)
        
    Returns:
        dict: Contains 'parsed', 'file_type', and optional 'consolidated'/'api_ready'/'flat_json' keys
        
    Raises:
        FileNotFoundError: If the input file doesn't exist
        ValueError: If the file type is unsupported or cannot be determined
        ConsolidationError: If consolidation fails (Nessus only)
        FormatterError: If API formatting fails (Nessus only)
        
    Examples:
        Auto-detect and parse any supported file:
            >>> results = process_file('scan.nessus')
            >>> results = process_file('scan.xml')
        
        Nessus with full pipeline:
            >>> results = process_file(
            ...     'scan.nessus',
            ...     consolidate=True,
            ...     api_format=True,
            ...     entity_limit=10,
            ...     output_dir='./results'
            ... )
        
        Nmap with port filtering:
            >>> results = process_file('scan.xml', port_status='open')
            >>> nmap_data = results['parsed']
            >>> print(f"Found {nmap_data['stats']['services']['total']} services")
        
        Nmap with flat JSON output for legacy tools:
            >>> results = process_file('scan.xml', flat_json=True)
            >>> flat_data = results['flat_json']
            >>> print(f"Generated {len(flat_data)} port records")
    """
    results = {}
    
    # Auto-detect file type if needed
    if file_type == "auto":
        file_type = detect_file_type(input_file)
    
    # Parse based on file type
    if file_type == "nessus":
        parser = NessusParser(input_file)
        parsed_data = parser.parse()
        results['parsed'] = parsed_data
        results['file_type'] = 'nessus'
        
        # Optional consolidation (Nessus only)
        if consolidate:
            consolidator = VulnerabilityConsolidator(rules_file)
            consolidated_data = consolidator.consolidate(parsed_data)
            results['consolidated'] = consolidated_data
            
            # Optional API formatting (Nessus only)
            if api_format and consolidated_data:
                formatter = APIFormatter(entity_limit=entity_limit)
                api_data = formatter.format_for_api(consolidated_data)
                results['api_ready'] = api_data
                
    elif file_type == "nmap":
        parser = NmapParser(input_file)
        parsed_data = parser.parse(port_status_filter=port_status)
        results['parsed'] = parsed_data
        results['file_type'] = 'nmap'
        
        # Optional flat JSON output (Nmap only)
        if flat_json:
            flat_data = parser.parse_to_flat_json(port_status_filter=port_status)
            results['flat_json'] = flat_data
        
    else:
        raise ValueError(f"Unsupported file type: {file_type}")
    
    # Optional file output
    if output_dir:
        from .utils import write_results_to_files
        write_results_to_files(results, input_file, output_dir, custom_output_name)
    
    return results

def process_nessus_file(
    nessus_file: str,
    consolidate: bool = False,
    api_format: bool = False,
    rules_file: str = None,
    entity_limit: int = None,
    output_dir: str = None,
    custom_output_name: str = None
) -> dict:
    """
    Legacy convenience function for Nessus file processing.
    
    This function is maintained for backward compatibility.
    New code should use process_file() instead.
    
    Args:
        nessus_file: Path to Nessus XML file
        consolidate: Whether to apply consolidation rules
        api_format: Whether to format for API consumption (requires consolidate=True)
        rules_file: Path to custom consolidation rules file
        entity_limit: Maximum number of affected entities per API finding
        output_dir: If provided, write JSON files to this directory
        custom_output_name: Custom name for the main parsed output file
        
    Returns:
        dict: Contains 'parsed', 'consolidated' (if requested), and 'api_ready' (if requested) keys
    """
    return process_file(
        input_file=nessus_file,
        file_type="nessus",
        consolidate=consolidate,
        api_format=api_format,
        rules_file=rules_file,
        entity_limit=entity_limit,
        output_dir=output_dir,
        custom_output_name=custom_output_name
    )

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