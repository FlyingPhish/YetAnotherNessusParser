import logging
from typing import Dict, Any

from .nessus_parser import NessusParser
from .nmap_parser import NmapParser
from .consolidator import VulnerabilityConsolidator
from .formatter import APIFormatter
from .excel_formatter import ExcelFormatter
from ..utils.file_utils import detect_file_type

logger = logging.getLogger(__name__)

def process_file(
    input_file: str,
    file_type: str = "auto",
    port_status: str = "all",
    consolidate: bool = False,
    api_format: bool = False,
    excel_format: bool = False,
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
    optional Excel formatting (consolidated JSON only), and optional flat JSON output (Nmap only).
    
    Args:
        input_file: Path to input file
        file_type: File type ('auto', 'nessus', 'nmap', 'consolidated_json')
        port_status: Port status filter for Nmap ('all', 'open', 'closed', 'filtered')
        consolidate: Whether to apply consolidation rules (Nessus only)
        api_format: Whether to format for API consumption (Nessus only, requires consolidate=True)
        excel_format: Whether to generate Excel report (consolidated JSON only)
        rules_file: Path to custom consolidation rules file (Nessus only)
        entity_limit: Maximum number of affected entities per API finding (Nessus only)
        output_dir: If provided, write JSON files to this directory
        custom_output_name: Custom name for the main parsed output file
        flat_json: Whether to generate flat JSON format compatible with legacy tools (Nmap only)
        log_exclusions: Enable detailed exclusion logging during consolidation (Nessus only)
        
    Returns:
        dict: Contains 'parsed', 'file_type', and optional 'consolidated'/'api_ready'/'excel'/'flat_json' keys
        
    Raises:
        FileNotFoundError: If the input file doesn't exist
        ValueError: If the file type is unsupported or cannot be determined
        ConsolidationError: If consolidation fails (Nessus only)
        FormatterError: If API or Excel formatting fails
        
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
        
        Generate Excel from consolidated JSON:
            >>> results = process_file(
            ...     'scan_Consolidated.json',
            ...     file_type='consolidated_json',
            ...     excel_format=True
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
    
    elif file_type == "consolidated_json":
        # Load consolidated JSON and generate Excel
        import json
        from pathlib import Path
        
        input_path = Path(input_file)
        if not input_path.exists():
            raise FileNotFoundError(f"File not found: {input_file}")
        
        with open(input_path, 'r') as f:
            consolidated_data = json.load(f)
        
        results['file_type'] = 'consolidated_json'
        
        # Generate Excel if requested
        if excel_format:
            excel_formatter = ExcelFormatter()
            excel_workbook = excel_formatter.format(consolidated_data)
            results['excel'] = excel_workbook
            # Store consolidated data only for Excel generation (don't write it back out)
            results['consolidated_loaded'] = consolidated_data
    
    else:
        raise ValueError(f"Unsupported file type: {file_type}")
    
    # Optional file output
    if output_dir:
        from ..utils import write_results_to_files
        write_results_to_files(results, input_file, output_dir, custom_output_name)
    
    return results

def process_nmap_comparison(
    first_file: str,
    second_file: str,
    output_dir: str = None,
    custom_output_name: str = None
) -> Dict[str, Any]:
    """
    Process Nmap comparison between two scan files.
    
    This function handles the complete workflow for comparing two Nmap XML scans:
    parsing both files, comparing ports and services, generating statistics,
    and creating an Excel report with comparison data and pie charts.
    
    Args:
        first_file: Path to first Nmap XML file
        second_file: Path to second Nmap XML file
        output_dir: Optional output directory for Excel file
        custom_output_name: Optional custom name for output file
        
    Returns:
        dict: Contains 'comparison', 'excel', and 'file_type' keys
        
    Raises:
        FileNotFoundError: If either input file doesn't exist
        ValueError: If files are not valid Nmap XML files
        FormatterError: If Excel formatting fails
        
    Examples:
        Basic comparison:
            >>> results = process_nmap_comparison('scan1.xml', 'scan2.xml')
            >>> excel_wb = results['excel']
            
        With custom output:
            >>> results = process_nmap_comparison(
            ...     'scan1.xml',
            ...     'scan2.xml',
            ...     output_dir='./comparison_reports',
            ...     custom_output_name='network_comparison'
            ... )
    """
    from pathlib import Path
    from .nmap_parser import NmapParser
    from .nmap_comparator import NmapComparator
    from .excel_formatter import ExcelFormatter
    
    results = {}
    
    # Get filenames for display
    first_filename = Path(first_file).stem
    second_filename = Path(second_file).stem
    
    # Parse both files
    first_parser = NmapParser(first_file)
    first_parsed = first_parser.parse(port_status_filter='open')
    
    second_parser = NmapParser(second_file)
    second_parsed = second_parser.parse(port_status_filter='open')
    
    # Perform comparison
    comparator = NmapComparator()
    comparison_data = comparator.compare(
        first_parsed,
        second_parsed,
        first_filename,
        second_filename
    )
    
    results['comparison'] = comparison_data
    results['file_type'] = 'nmap_comparison'
    
    # Generate Excel report
    logger.info("Generating Excel comparison report")
    formatter = ExcelFormatter()
    excel_workbook = formatter.format_nmap_comparison(
        comparison_data,
        first_filename,
        second_filename
    )
    
    results['excel'] = excel_workbook
    
    # Write Excel file if output directory specified
    if output_dir and excel_workbook:
        from datetime import datetime
        from ..utils.file_utils import ensure_output_directory
        
        output_path = ensure_output_directory(output_dir)
        
        if custom_output_name:
            excel_filename = f"{custom_output_name}.xlsx"
        else:
            timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            excel_filename = f"Nmap_Comparison_{timestamp}.xlsx"
        
        excel_file_path = output_path / excel_filename
        excel_workbook.save(excel_file_path)
        results['excel_file_path'] = str(excel_file_path)
    
    return results