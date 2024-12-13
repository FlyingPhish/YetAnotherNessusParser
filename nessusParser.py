import argparse
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET

def setup_logging():
    """Configure logging format and level for CLI output"""
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=logging.INFO,
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def validate_nessus_file(file_path: str) -> bool:
    """
    Validate if the input file is accessible and has correct format
    Returns: bool indicating if file is valid
    """
    path = Path(file_path)
    if not path.exists():
        logging.error(f"File not found: {file_path}")
        return False
    if path.suffix != '.nessus':
        logging.error(f"Invalid file extension: {path.suffix}")
        return False
    try:
        ET.parse(file_path)
        return True
    except ET.ParseError:
        logging.error(f"Invalid XML format in file: {file_path}")
        return False

def create_backup(nessus_file: str, output_folder: str) -> None:
    """Create backup of original nessus file in output directory"""
    original_name = Path(nessus_file).stem
    backup_name = f"{original_name}_Backup.nessus"
    backup_path = os.path.join(output_folder, backup_name)
    
    try:
        shutil.copy2(nessus_file, backup_path)
        logging.info(f"Backup created: {backup_path}")
    except Exception as e:
        logging.error(f"Failed to create backup: {str(e)}")

def setup_argparse() -> argparse.ArgumentParser:
    """Setup and return argument parser with defined arguments"""
    parser = argparse.ArgumentParser(
        description='Nessus XML Parser - Converts Nessus XML to JSON format'
    )
    
    parser.add_argument(
        '-n', '--nessus-file',
        required=True,
        help='Path to input Nessus XML file'
    )
    
    parser.add_argument(
        '-of', '--output-folder',
        default='./output',
        help='Output folder path (default: ./output)'
    )
    
    parser.add_argument(
        '-on', '--output-name',
        help='Output file name (default: timestamp_<original-name>_Parsed_Nessus.json)'
    )
    
    return parser

def get_default_output_name(nessus_file: str) -> str:
    """Generate default output name using timestamp and original filename"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    original_name = Path(nessus_file).stem
    return f"{timestamp}_{original_name}_Parsed_Nessus.json"

def main():
    """Main execution function"""
    # Setup logging
    setup_logging()
    
    # Parse arguments
    parser = setup_argparse()
    args = parser.parse_args()
    
    # Validate and create output directory
    output_folder = Path(args.output_folder)
    output_folder.mkdir(parents=True, exist_ok=True)
    
    # Validate input file
    if not validate_nessus_file(args.nessus_file):
        return 1
    
    # Create backup
    create_backup(args.nessus_file, str(output_folder))
    
    # Set output filename
    output_name = args.output_name or get_default_output_name(args.nessus_file)
    output_path = output_folder / output_name
    
    logging.info(f"Output will be saved to: {output_path}")
    
    # TODO: Implement XML parsing and JSON creation once we see the file structure
    
    return 0

if __name__ == "__main__":
    exit(main())