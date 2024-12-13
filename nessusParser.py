from pathlib import Path
from modules import (
    logger,
    file_utils,
    cli,
    nessus,
    json_utils
)
import nessus_file_reader as nfr

def main():
    """Main execution function"""
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
    
    # Parse Nessus file
    try:
        root = nfr.file.nessus_scan_file_root_element(args.nessus_file)
        
        # Get scan data
        scan_summary = nessus.get_scan_summary(root)
        detailed_data = nessus.get_detailed_scan_data(root)
        
        if not scan_summary or not detailed_data:
            return 1
        
        # Prepare output
        output_data = {
            'summary': scan_summary,
            'detailed_data': detailed_data
        }
        
        # Write output
        output_name = args.output_name or file_utils.get_default_output_name(args.nessus_file)
        output_path = output_folder / output_name
        
        if not json_utils.write_json_output(output_data, output_path):
            return 1
            
        return 0
        
    except Exception as e:
        log.error(f"Failed to process Nessus file: {str(e)}")
        return 1

if __name__ == "__main__":
    exit(main())