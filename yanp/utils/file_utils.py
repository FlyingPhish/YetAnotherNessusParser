import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Union

logger = logging.getLogger(__name__)

def get_default_output_name(nessus_file: Union[str, Path]) -> str:
    """
    Generate default output filename for parsed Nessus data.
    
    Args:
        nessus_file: Path to the original Nessus file
        
    Returns:
        Generated filename string
    """
    timestamp = datetime.now().strftime('%d-%m-%y_%H-%M-%S')
    original_name = Path(nessus_file).stem
    return f"{timestamp}_{original_name}_Parsed_Nessus.json"

def get_consolidated_output_name(nessus_file: Union[str, Path]) -> str:
    """
    Generate consolidated findings output filename.
    
    Args:
        nessus_file: Path to the original Nessus file
        
    Returns:
        Generated filename string
    """
    timestamp = datetime.now().strftime('%d-%m-%y_%H-%M-%S')
    original_name = Path(nessus_file).stem
    return f"{timestamp}_{original_name}_Consolidated_Findings.json"

def get_api_output_name(nessus_file: Union[str, Path]) -> str:
    """
    Generate API-ready output filename.
    
    Args:
        nessus_file: Path to the original Nessus file
        
    Returns:
        Generated filename string
    """
    timestamp = datetime.now().strftime('%d-%m-%y_%H-%M-%S')
    original_name = Path(nessus_file).stem
    return f"{timestamp}_{original_name}_API_Ready.json"

def ensure_output_directory(output_path: Union[str, Path]) -> Path:
    """
    Ensure output directory exists, creating it if necessary.
    
    Args:
        output_path: Path to output directory or file
        
    Returns:
        Path object for the directory
    """
    output_path = Path(output_path)
    
    # If it's a file path, get the parent directory
    if output_path.suffix:
        directory = output_path.parent
    else:
        directory = output_path
    
    directory.mkdir(parents=True, exist_ok=True)
    logger.debug(f"Ensured directory exists: {directory}")
    
    return directory

def write_results_to_files(results: Dict[str, Any], nessus_file: Union[str, Path], output_dir: Union[str, Path], custom_output_name: str = None) -> Dict[str, bool]:
    """
    Write all processing results to appropriately named files.
    
    Args:
        results: Dictionary containing 'parsed', 'consolidated', and/or 'api_ready' data
        nessus_file: Original Nessus file path (for naming)
        output_dir: Output directory path
        custom_output_name: Custom name for the main parsed file (optional)
        
    Returns:
        Dictionary indicating success/failure for each file type
    """
    from .json_utils import write_json_output
    
    output_dir = ensure_output_directory(output_dir)
    write_status = {}
    
    # Generate base filename (without extension) for custom naming
    if custom_output_name:
        # Remove .json extension if present to get base name
        base_name = Path(custom_output_name).stem
    else:
        base_name = None
    
    # Write main parsed file
    if 'parsed' in results and results['parsed']:
        if custom_output_name:
            parsed_filename = custom_output_name
        else:
            parsed_filename = get_default_output_name(nessus_file)
        parsed_path = output_dir / parsed_filename
        write_status['parsed'] = write_json_output(results['parsed'], parsed_path)
    
    # Write consolidated file
    if 'consolidated' in results and results['consolidated']:
        if base_name:
            consolidated_filename = f"{base_name}_Consolidated_Findings.json"
        else:
            consolidated_filename = get_consolidated_output_name(nessus_file)
        consolidated_path = output_dir / consolidated_filename
        write_status['consolidated'] = write_json_output(results['consolidated'], consolidated_path)
    
    # Write API file
    if 'api_ready' in results and results['api_ready']:
        if base_name:
            api_filename = f"{base_name}_API_Ready.json"
        else:
            api_filename = get_api_output_name(nessus_file)
        api_path = output_dir / api_filename
        write_status['api_ready'] = write_json_output(results['api_ready'], api_path)
    
    return write_status

def get_package_resource_path(resource_path: str) -> Path:
    """
    Get path to a resource within the YANP package.
    
    Args:
        resource_path: Relative path to resource (e.g., 'config/default_rules.json')
        
    Returns:
        Absolute path to the resource
    """
    # Get the package root directory (parent of utils)
    package_root = Path(__file__).parent.parent
    return package_root / resource_path

def find_nessus_files(directory: Union[str, Path], recursive: bool = False) -> list[Path]:
    """
    Find all .nessus files in a directory.
    
    Args:
        directory: Directory to search
        recursive: Whether to search subdirectories
        
    Returns:
        List of Path objects for .nessus files found
    """
    directory = Path(directory)
    
    if not directory.exists():
        logger.warning(f"Directory does not exist: {directory}")
        return []
    
    if not directory.is_dir():
        logger.warning(f"Path is not a directory: {directory}")
        return []
    
    if recursive:
        pattern = "**/*.nessus"
    else:
        pattern = "*.nessus"
    
    nessus_files = list(directory.glob(pattern))
    logger.info(f"Found {len(nessus_files)} .nessus files in {directory}")
    
    return nessus_files

def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by removing/replacing invalid characters.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename safe for filesystem
    """
    import re
    
    # Replace invalid characters with underscores
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove multiple consecutive underscores
    sanitized = re.sub(r'_{2,}', '_', sanitized)
    
    # Remove leading/trailing underscores and whitespace
    sanitized = sanitized.strip('_ ')
    
    # Ensure we don't have an empty filename
    if not sanitized:
        sanitized = "output"
    
    return sanitized