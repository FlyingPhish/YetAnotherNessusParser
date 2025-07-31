import logging
from typing import Dict, Any

from .nessus_parser import NessusParser
from .nmap_parser import NmapParser
from .consolidator import VulnerabilityConsolidator
from .formatter import APIFormatter
from ..utils.file_utils import detect_file_type

logger = logging.getLogger(__name__)

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
    flat_json: bool = False,
    log_exclusions: bool = False
) -> Dict[str, Any]:
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
            consolidator = VulnerabilityConsolidator(
                rules_file=rules_file,
                enable_exclusion_logging=log_exclusions
            )
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
        from ..utils import write_results_to_files
        write_results_to_files(results, input_file, output_dir, custom_output_name)
    
    return results