import argparse
import sys
from pathlib import Path

from .core.consolidator import ConsolidationError
from .core.formatter import FormatterError
from .core.processor import process_file
from .utils import setup_logging, write_results_to_files
from .utils.file_utils import ensure_output_directory, detect_file_type
from .utils.display import (
    print_banner, 
    display_summary, 
    display_consolidation_summary, 
    display_api_summary,
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
        '-i', '--input-file',
        required=True,
        help='Path to input file (Nessus .nessus, Nmap .xml, Burp .xml)'
    )
    
    parser.add_argument(
        '-t', '--file-type',
        choices=['auto', 'nessus', 'nmap', 'burp'],
        default='auto',
        help='Input file type (default: auto-detect)'
    )
    
    parser.add_argument(
        '-of', '--output-folder',
        default='./output',
        help='Output folder path (default: ./output)'
    )
    
    parser.add_argument(
        '-on', '--output-name',
        help='Output file name (default: timestamp_<original-name>_Parsed.json)'
    )
    
    # Nessus-specific options
    nessus_group = parser.add_argument_group('Nessus options')
    nessus_group.add_argument(
        '-c', '--consolidate',
        action='store_true',
        help='Generate consolidated findings file based on rules (Nessus/Burp)'
    )
    
    nessus_group.add_argument(
        '-a', '--api-output',
        action='store_true',
        help='Generate API-ready JSON format (requires --consolidate, Nessus/Burp)'
    )
    
    nessus_group.add_argument(
        '-r', '--rules-file',
        help='Custom consolidation rules file (Nessus only)'
    )
    
    nessus_group.add_argument(
        '-el', '--entity-limit',
        type=int,
        help='Maximum number of affected entities per API finding (Nessus only)'
    )
    
    nessus_group.add_argument(
        '--log-exclusions',
        action='store_true',
        help='Enable detailed exclusion logging to file during consolidation (Nessus only)'
    )
    
    # Nmap-specific options
    nmap_group = parser.add_argument_group('Nmap options')
    nmap_group.add_argument(
        '-s', '--port-status',
        choices=['all', 'open', 'closed', 'filtered'],
        default='all',
        help='Filter by port status (Nmap only, default: all)'
    )
    
    nmap_group.add_argument(
        '-fj', '--flat-json',
        action='store_true',
        help='Generate flat JSON format compatible with legacy tools (Nmap only)'
    )
    
    parser.add_argument(
        '--no-output',
        action='store_true',
        help='Skip writing files, only display results'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )
    
    # Burp-specific options
    burp_group = parser.add_argument_group('Burp options')
    burp_group.add_argument(
        '--burp-consolidate',
        action='store_true',
        help='Generate consolidated findings file based on rules (Burp only, experimental)'
    )

    burp_group.add_argument(
        '--burp-api-output',
        action='store_true',
        help='Generate API-ready JSON format (requires --burp-consolidate, Burp only)'
    )

    return parser

def main():
    """Main CLI execution function"""
    print_banner(__version__)
    
    # Setup logging
    log = setup_logging()
    
    # Parse arguments
    args = setup_argparse().parse_args()
    
    # Validate arguments
    if args.api_output and not args.consolidate:
        log.error("--api-output requires --consolidate flag")
        return 1
    
    if args.entity_limit is not None and args.entity_limit < 1:
        log.error("--entity-limit must be a positive integer")
        return 1
    
    if args.burp_api_output and not args.burp_consolidate:
        log.error("--burp-api-output requires --burp-consolidate flag")
        return 1
    
    # Check for Nessus-only options with other file types
    if args.file_type in ['nmap'] or (args.file_type == 'auto' and Path(args.input_file).suffix.lower() == '.xml'):
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
        
        if nessus_only_options and args.file_type == 'nmap':
            log.warning(f"Ignoring Nessus-only options for Nmap file: {', '.join(nessus_only_options)}")
    
    # Check for Nmap-only options with other file types
    if args.file_type in ['nessus'] or (args.file_type == 'auto' and Path(args.input_file).suffix.lower() == '.nessus'):
        nmap_only_options = []
        if args.flat_json:
            nmap_only_options.append("--flat-json")
        
        if nmap_only_options and args.file_type == 'nessus':
            log.warning(f"Ignoring Nmap-only options for Nessus file: {', '.join(nmap_only_options)}")

    # Check for Nessus/Burp-only options with other file types
    if args.file_type in ['nmap'] or (args.file_type == 'auto' and Path(args.input_file).suffix.lower() == '.xml'):
        nessus_burp_only_options = []
        if args.consolidate:
            nessus_burp_only_options.append("--consolidate")
        if args.api_output:
            nessus_burp_only_options.append("--api-output")
        if args.rules_file:
            nessus_burp_only_options.append("--rules-file")
        if args.entity_limit:
            nessus_burp_only_options.append("--entity-limit")
        if args.log_exclusions:
            nessus_burp_only_options.append("--log-exclusions")
        if args.burp_consolidate:
            nessus_burp_only_options.append("--burp-consolidate")
        if args.burp_api_output:
            nessus_burp_only_options.append("--burp-api-output")
        
        if nessus_burp_only_options and args.file_type == 'nmap':
            log.warning(f"Ignoring Nessus/Burp-only options for Nmap file: {', '.join(nessus_burp_only_options)}")

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
            consolidate=args.consolidate or args.burp_consolidate,
            api_format=args.api_output or args.burp_api_output,
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
        
        # Write output files unless disabled
        if not args.no_output:
            output_folder = ensure_output_directory(args.output_folder)
            
            write_status = write_results_to_files(
                results, 
                args.input_file, 
                output_folder,
                custom_output_name=args.output_name
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

def cli_entry_point():
    """Entry point for console script."""
    sys.exit(main())

if __name__ == "__main__":
    cli_entry_point()