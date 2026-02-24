import argparse
import sys
from pathlib import Path

from .core.consolidator import ConsolidationError
from .core.formatter import FormatterError
from .core.processor import process_file, process_nmap_comparison
from .utils import setup_logging, write_results_to_files
from .utils.file_utils import ensure_output_directory, detect_file_type
from .utils.display import (
    print_banner, 
    display_summary, 
    display_consolidation_summary, 
    display_api_summary,
    display_excel_summary,
    display_nmap_comparison_summary,
    Colors
)

# Get version directly to avoid circular import
try:
    from importlib.metadata import version
    __version__ = version("yapp")
except ImportError:
    __version__ = "ERROR"
except Exception:
    __version__ = "ERROR"

def setup_argparse() -> argparse.ArgumentParser:
    """Setup and return argument parser"""
    parser = argparse.ArgumentParser(
        description='YAPP - Swiss Army Knife for Pentester File Processing',
        prog='yapp'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )
    
    # Create subparsers for commands
    subparsers = parser.add_subparsers(
        dest='command',
        help='Available commands',
        metavar='{parse,excel,compare}'
    )
    
    # ===== PARSE COMMAND (default) =====
    parse_parser = subparsers.add_parser(
        'parse',
        help='Parse and process pentesting files (Nessus/Nmap/JSON)'
    )
    
    parse_parser.add_argument(
        '-i', '--input-file',
        required=True,
        help='Path to input file (Nessus .nessus, Nmap .xml, Consolidated JSON)'
    )
    
    parse_parser.add_argument(
        '-t', '--file-type',
        choices=['auto', 'nessus', 'nmap', 'consolidated_json'],
        default='auto',
        help='Input file type (default: auto-detect)'
    )
    
    parse_parser.add_argument(
        '-of', '--output-folder',
        default='./output',
        help='Output folder path (default: ./output)'
    )
    
    parse_parser.add_argument(
        '-on', '--output-name',
        help='Output file name (default: timestamp_<original-name>_Parsed.json)'
    )
    
    parse_parser.add_argument(
        '--no-output',
        action='store_true',
        help='Skip writing files, only display results'
    )
    
    # Output mode options
    output_group = parse_parser.add_argument_group('Output options')
    output_group.add_argument(
        '-sf', '--single-file',
        action='store_true',
        help='Write all selected outputs into one combined JSON file instead of separate files'
    )
    
    # Nessus-specific options
    nessus_group = parse_parser.add_argument_group('Nessus options')
    nessus_group.add_argument(
        '-c', '--consolidate',
        action='store_true',
        help='Generate consolidated findings file'
    )
    
    nessus_group.add_argument(
        '-a', '--api-output',
        action='store_true',
        help='Generate API-ready JSON (requires --consolidate)'
    )
    
    nessus_group.add_argument(
        '-r', '--rules-file',
        help='Custom consolidation rules file'
    )
    
    nessus_group.add_argument(
        '-el', '--entity-limit',
        type=int,
        help='Max entities per API finding'
    )
    
    nessus_group.add_argument(
        '--log-exclusions',
        action='store_true',
        help='Enable detailed exclusion logging'
    )
    
    # Nmap-specific options
    nmap_group = parse_parser.add_argument_group('Nmap options')
    nmap_group.add_argument(
        '-s', '--port-status',
        choices=['all', 'open', 'closed', 'filtered'],
        default='all',
        help='Filter by port status (default: all)'
    )
    
    nmap_group.add_argument(
        '-fj', '--flat-json',
        action='store_true',
        help='Generate flat JSON format'
    )
    
    # Excel output options
    excel_group = parse_parser.add_argument_group('Excel options')
    excel_group.add_argument(
        '-x', '--excel',
        action='store_true',
        help='Also generate Excel report (Nessus: requires -c; or consolidated JSON input)'
    )
    
    # ===== EXCEL COMMAND =====
    excel_parser = subparsers.add_parser(
        'excel',
        help='Generate Excel report from YAPP JSON output'
    )
    
    excel_parser.add_argument(
        '-i', '--input-file',
        required=True,
        help='Path to YAPP JSON file (consolidated, combined, or parsed)'
    )
    
    excel_parser.add_argument(
        '-of', '--output-folder',
        default='./output',
        help='Output folder path (default: ./output)'
    )
    
    excel_parser.add_argument(
        '-on', '--output-name',
        help='Custom output filename (without extension)'
    )
    
    # ===== COMPARE COMMAND =====
    compare_parser = subparsers.add_parser(
        'compare',
        help='Compare two Nmap XML scans'
    )
    
    compare_parser.add_argument(
        '-ff', '--first-file',
        required=True,
        help='Path to first Nmap XML file'
    )
    
    compare_parser.add_argument(
        '-lf', '--last-file',
        required=True,
        help='Path to second Nmap XML file'
    )
    
    compare_parser.add_argument(
        '-of', '--output-folder',
        default='./output',
        help='Output folder path (default: ./output)'
    )
    
    compare_parser.add_argument(
        '-on', '--output-name',
        help='Custom output filename (without extension)'
    )
    
    return parser

def handle_parse(args, log):
    """Handle parse command"""
    # Validate arguments
    if args.api_output and not args.consolidate:
        log.error("--api-output requires --consolidate flag")
        return 1
    
    if args.entity_limit is not None and args.entity_limit < 1:
        log.error("--entity-limit must be a positive integer")
        return 1
    
    # Validate Excel: for Nessus input, -x requires -c (consolidation)
    if args.excel and args.file_type not in ['consolidated_json']:
        if not args.consolidate:
            # Auto-detect might resolve to consolidated_json, but for nessus/nmap we need -c
            if args.file_type != 'auto' or Path(args.input_file).suffix.lower() != '.json':
                log.error("--excel requires --consolidate (-c) for Nessus files, or use with consolidated JSON input")
                return 1
    
    # Check for Nessus-only options with other file types
    if args.file_type in ['nmap', 'consolidated_json'] or (
        args.file_type == 'auto' and Path(args.input_file).suffix.lower() == '.xml'
    ):
        nessus_only_options = []
        if args.consolidate:
            nessus_only_options.append("--consolidate")
        if args.api_output:
            nessus_only_options.append("--api-output")
        if args.rules_file:
            nessus_only_options.append("--rules-file")
        if args.entity_limit:
            nessus_only_options.append("--entity-limit")
        if args.log_exclusions:
            nessus_only_options.append("--log-exclusions")
        
        if nessus_only_options and args.file_type in ['nmap', 'consolidated_json']:
            log.warning(f"Ignoring Nessus-only options for {args.file_type} file: {', '.join(nessus_only_options)}")
    
    # Check for Nmap-only options with other file types
    if args.file_type in ['nessus', 'consolidated_json'] or (args.file_type == 'auto' and Path(args.input_file).suffix.lower() == '.nessus'):
        nmap_only_options = []
        if args.flat_json:
            nmap_only_options.append("--flat-json")
        
        if nmap_only_options and args.file_type in ['nessus', 'consolidated_json']:
            log.warning(f"Ignoring Nmap-only options for {args.file_type} file: {', '.join(nmap_only_options)}")
    
    try:
        # Auto-detect file type if needed and display
        if args.file_type == "auto":
            detected_type = detect_file_type(args.input_file)
            print(f"{Colors.CYAN}Auto-detected file type: {Colors.GREEN}{detected_type.upper()}{Colors.RESET}")
        
        # Process using the main library function
        results = process_file(
            input_file=args.input_file,
            file_type=args.file_type,
            port_status=args.port_status,
            consolidate=args.consolidate,
            api_format=args.api_output,
            excel_format=args.excel,
            rules_file=args.rules_file,
            entity_limit=args.entity_limit,
            flat_json=args.flat_json,
            log_exclusions=args.log_exclusions
        )
        
        # Display results
        if 'parsed' in results and results['parsed']:
            display_summary(results['parsed'], results['file_type'])
        
        if 'consolidated' in results and results['consolidated']:
            display_consolidation_summary(results['consolidated'])
        
        if 'api_ready' in results and results['api_ready']:
            display_api_summary(results['api_ready'])
        
        if 'excel' in results and results['excel']:
            # Display summary from whichever source has the consolidated data
            consolidated_for_summary = results.get('consolidated_loaded') or results.get('consolidated')
            if consolidated_for_summary:
                display_excel_summary(consolidated_for_summary)
        
        # Write output files unless disabled
        if not args.no_output:
            output_folder = ensure_output_directory(args.output_folder)
            
            write_status = write_results_to_files(
                results, 
                args.input_file, 
                output_folder,
                custom_output_name=args.output_name,
                single_file=args.single_file
            )
            
            # Check if any writes failed
            failed_writes = [file_type for file_type, success in write_status.items() if not success]
            if failed_writes:
                log.warning(f"Failed to write files: {', '.join(failed_writes)}")
                return 1
        
        return 0
        
    except FileNotFoundError as e:
        log.error(f"File not found: {e}")
        return 1
    except ConsolidationError as e:
        log.error(f"Consolidation failed: {e}")
        return 1
    except FormatterError as e:
        log.error(f"API formatting failed: {e}")
        return 1
    except Exception as e:
        log.error(f"Unexpected error: {str(e)}")
        return 1

def handle_compare(args, log):
    """Handle compare command"""
    try:
        # Validate input files
        first_path = Path(args.first_file)
        last_path = Path(args.last_file)
        
        if not first_path.exists():
            log.error(f"First file not found: {args.first_file}")
            return 1
        
        if not last_path.exists():
            log.error(f"Second file not found: {args.last_file}")
            return 1
        
        # Process comparison
        results = process_nmap_comparison(
            first_file=args.first_file,
            second_file=args.last_file,
            output_dir=args.output_folder,
            custom_output_name=args.output_name
        )
        
        # Display comparison summary
        display_nmap_comparison_summary(results['comparison'])
        
        # Display output file info
        if 'excel_file_path' in results:
            print(f"\n{Colors.GREEN}{Colors.BRIGHT}✓ Excel comparison report saved:{Colors.RESET}")
            print(f"  {Colors.CYAN}{results['excel_file_path']}{Colors.RESET}\n")
        
        return 0
        
    except FileNotFoundError as e:
        log.error(f"File not found: {e}")
        return 1
    except Exception as e:
        log.error(f"Comparison failed: {str(e)}")
        return 1

def handle_excel(args, log):
    """Handle excel command — generate Excel from YAPP JSON output"""
    import json
    from .core.excel_formatter import ExcelFormatter
    from .utils.file_utils import _get_base_name, _build_output_name
    
    input_path = Path(args.input_file)
    
    if not input_path.exists():
        log.error(f"File not found: {args.input_file}")
        return 1
    
    try:
        with open(input_path, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        log.error(f"Invalid JSON: {e}")
        return 1
    
    # Extract consolidated data from whichever structure we got
    consolidated_data = None
    
    if isinstance(data, dict):
        if 'consolidated_vulnerabilities' in data:
            # Direct consolidated JSON
            consolidated_data = data
        elif 'consolidated' in data and isinstance(data['consolidated'], dict):
            # Combined file with consolidated key
            consolidated_data = data['consolidated']
    
    if not consolidated_data or not consolidated_data.get('consolidated_vulnerabilities'):
        log.error("Input JSON does not contain consolidated vulnerability data")
        log.error("Excel generation requires consolidated data (from -c flag or consolidated JSON)")
        return 1
    
    try:
        formatter = ExcelFormatter()
        workbook = formatter.format(consolidated_data)
        
        if not workbook:
            log.error("Excel formatting returned no workbook")
            return 1
        
        # Write output
        output_folder = ensure_output_directory(args.output_folder)
        base = _get_base_name(args.input_file, args.output_name)
        excel_filename = _build_output_name(base, "_Report", ".xlsx")
        excel_path = output_folder / excel_filename
        
        workbook.save(excel_path)
        
        display_excel_summary(consolidated_data)
        print(f"\n{Colors.GREEN}{Colors.BRIGHT}✓ Excel report saved:{Colors.RESET}")
        print(f"  {Colors.CYAN}{excel_path}{Colors.RESET}\n")
        
        return 0
        
    except Exception as e:
        log.error(f"Excel generation failed: {str(e)}")
        return 1

def main():
    """Main CLI execution function"""
    print_banner(__version__)
    
    # Setup logging
    log = setup_logging()
    
    # Parse arguments
    parser = setup_argparse()
    args = parser.parse_args()
    
    # Default to parse command if no command specified (backward compatibility)
    if not args.command:
        # Check if user provided -i flag (old style)
        if len(sys.argv) > 1 and ('-i' in sys.argv or '--input-file' in sys.argv):
            # Insert 'parse' command at beginning
            sys.argv.insert(1, 'parse')
            args = parser.parse_args()
        else:
            # No command and no -i flag, show help
            parser.print_help()
            return 1
    
    # Route to appropriate handler
    if args.command == 'parse':
        return handle_parse(args, log)
    elif args.command == 'excel':
        return handle_excel(args, log)
    elif args.command == 'compare':
        return handle_compare(args, log)
    else:
        log.error(f"Unknown command: {args.command}")
        parser.print_help()
        return 1

def cli_entry_point():
    """Entry point for console script."""
    sys.exit(main())

if __name__ == "__main__":
    cli_entry_point()