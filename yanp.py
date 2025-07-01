from pathlib import Path
from modules import (
    logger,
    file_utils,
    cli,
    json_utils,
    nessus,
    consolidation,
    api_formatter
)

version = "3.3.0"

def main():
    """Main execution function"""
    cli.print_banner(version)
    # Setup logging
    log = logger.setup_logging()
    
    # Parse arguments
    args = cli.setup_argparse().parse_args()
    
    # Validate API output requirements
    if args.api_output and not args.consolidate:
        log.error("--api-output requires --consolidate flag")
        return 1
    
    # Validate and create output directory
    output_folder = Path(args.output_folder)
    output_folder.mkdir(parents=True, exist_ok=True)
    
    # Validate input file
    if not file_utils.validate_nessus_file(args.nessus_file):
        return 1

    # Initialize parser and parse file
    parser = nessus.NessusParser(args.nessus_file)
    parsed_data = parser.parse()
    
    if not parsed_data:
        log.error("Failed to parse Nessus file")
        return 1
    
    # Display formatted summary
    cli.display_summary(parsed_data)

    # Set output filename and write results
    output_name = args.output_name or file_utils.get_default_output_name(args.nessus_file)
    output_path = output_folder / output_name
    
    # Write to JSON file
    if not json_utils.write_json_output(parsed_data, output_path):
        return 1
    
    # Handle consolidation if requested
    if args.consolidate:
        consolidator = consolidation.VulnerabilityConsolidator()
        consolidated_data = consolidator.consolidate(parsed_data)
        
        if consolidated_data:
            # Display consolidation summary in YANP style
            cli.display_consolidation_summary(consolidated_data)
            
            # Generate consolidated findings filename
            consolidated_name = file_utils.get_consolidated_output_name(args.nessus_file)
            consolidated_path = output_folder / consolidated_name
            
            if not json_utils.write_json_output(consolidated_data, consolidated_path):
                log.warning("Failed to write consolidated findings file")
                return 1
            
            # Handle API output if requested
            if args.api_output:
                formatter = api_formatter.APIFormatter()
                api_data = formatter.format_for_api(consolidated_data)
                
                if api_data:
                    cli.display_api_summary(api_data)
                    # Generate API output filename
                    api_name = file_utils.get_api_output_name(args.nessus_file)
                    api_path = output_folder / api_name
                    
                    if not json_utils.write_json_output(api_data, api_path):
                        log.warning("Failed to write API-ready file")
                        return 1
                    else:
                        pass
                else:
                    log.warning("No API-ready findings generated - no rules with internal_vulnerability_id found")
                
        else:
            log.warning("Consolidation was requested but no consolidated data was generated")
            if args.api_output:
                log.error("API output cannot be generated without successful consolidation")
                return 1
    
    return 0

if __name__ == "__main__":
    exit(main())