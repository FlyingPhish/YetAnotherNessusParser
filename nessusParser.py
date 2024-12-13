from pathlib import Path
from modules import (
    logger,
    file_utils,
    cli,
    json_utils,
    nessus
)

def display_summary(parsed_data: dict):
    """Display formatted summary of scan results"""
    host_summary = parsed_data['host_summary']
    
    # Calculate total unique vulnerabilities across all hosts
    total_per_risk = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'None': 0}
    for host_vulns in host_summary['number_of_unique_vulns_per_host_per_severity'].values():
        for risk_factor, count in host_vulns.items():
            total_per_risk[risk_factor] += count

    # Print summary without timestamps
    print("-" * 50)
    print("Scan Summary:")
    print(f"Total Hosts: {host_summary['number_of_hosts']}")
    print(f"Discovered Ports: {len(host_summary['discovered_ports'])}")
    
    print("\nUnique Findings by Risk Factor:")
    risk_order = ['Critical', 'High', 'Medium', 'Low', 'None']
    for risk in risk_order:
        print(f"{risk}: {total_per_risk[risk]}")
    print("-" * 50 + "\n")

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

    # Initialize parser and parse file
    parser = nessus.NessusParser(args.nessus_file)
    parsed_data = parser.parse()
    
    if not parsed_data:
        log.error("Failed to parse Nessus file")
        return 1
    
    # Display formatted summary
    display_summary(parsed_data)

    # Set output filename and write results
    output_name = args.output_name or file_utils.get_default_output_name(args.nessus_file)
    output_path = output_folder / output_name
    
    print(f"Writing results to: {output_path}")
    
    # Write to JSON file
    if not json_utils.write_json_output(parsed_data, output_path):
        return 1

    return 0

if __name__ == "__main__":
    exit(main())