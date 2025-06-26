import logging
import shutil
from pathlib import Path
import xml.etree.ElementTree as ET
from datetime import datetime

logger = logging.getLogger(__name__)

def validate_nessus_file(file_path: str) -> bool:
    """Validate if the input file is accessible and has correct format"""
    path = Path(file_path)
    if not path.exists():
        logger.error(f"File not found: {file_path}")
        return False
    if path.suffix != '.nessus':
        logger.error(f"Invalid file extension: {path.suffix}")
        return False
    try:
        ET.parse(file_path)
        return True
    except ET.ParseError:
        logger.error(f"Invalid XML format in file: {file_path}")
        return False

def create_backup(nessus_file: str, output_folder: str) -> None:
    """Create backup of original nessus file"""
    original_name = Path(nessus_file).stem
    backup_name = f"{original_name}_Backup.nessus"
    backup_path = Path(output_folder) / backup_name
    
    try:
        shutil.copy2(nessus_file, backup_path)
        logger.info(f"Backup created: {backup_path}")
    except Exception as e:
        logger.error(f"Failed to create backup: {str(e)}")

def get_default_output_name(nessus_file: str) -> str:
    """Generate default output name"""
    timestamp = datetime.now().strftime('%d-%m-%y_%H-%M-%S')
    original_name = Path(nessus_file).stem
    return f"{timestamp}_{original_name}_Parsed_Nessus.json"

def get_consolidated_output_name(nessus_file: str) -> str:
    """Generate consolidated findings output name"""
    timestamp = datetime.now().strftime('%d-%m-%y_%H-%M-%S')
    original_name = Path(nessus_file).stem
    return f"{timestamp}_{original_name}_Consolidated_Findings.json"