from pathlib import Path
from modules import (
    logger,
    file_utils,
    cli,
    json_utils,
    nessus,
    consolidation
)

version = "3.1.0"

def main():
    """Main execution function"""
    cli.print_banner(version)
    # Setup logging
    log = logger.setup_logging()
    
    # Parse arguments
    args = cli.setup_argparse().parse_args()
    
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
                
        else:
            log.warning("Consolidation was requested but no consolidated data was generated")
    
    return 0

if __name__ == "__main__":
    exit(main())