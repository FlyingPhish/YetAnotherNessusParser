import logging
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Union, Optional

logger = logging.getLogger(__name__)

def detect_file_type(file_path: Union[str, Path]) -> str:
    """
    Auto-detect file type based on extension and content analysis.
    
    Args:
        file_path: Path to the file to analyze
        
    Returns:
        Detected file type: 'nessus', 'nmap', 'consolidated_json', or 'unknown'
        
    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file type cannot be determined
    """
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Check file extension first
    extension = file_path.suffix.lower()
    
    if extension == '.nessus':
        # Verify it's actually a Nessus file
        if _verify_nessus_file(file_path):
            return 'nessus'
    elif extension == '.xml':
        # Could be Nmap or other XML - check content
        xml_type = _analyze_xml_content(file_path)
        if xml_type:
            return xml_type
    elif extension == '.json':
        # Check if it's a consolidated JSON file
        json_type = _analyze_json_content(file_path)
        if json_type:
            return json_type
    
    # If extension-based detection failed, try content analysis
    try:
        content_type = _analyze_file_content(file_path)
        if content_type:
            return content_type
    except Exception as e:
        logger.debug(f"Content analysis failed for {file_path}: {e}")
    
    raise ValueError(f"Unable to determine file type for: {file_path}")

def _verify_nessus_file(file_path: Path) -> bool:
    """
    Verify that a .nessus file is actually a valid Nessus XML file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        True if valid Nessus file, False otherwise
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # Check for Nessus-specific root element and structure
        if root.tag == "NessusClientData_v2":
            return True
            
        # Some Nessus files might have different root elements
        if root.find('.//Report') is not None and root.find('.//Policy') is not None:
            return True
            
        return False
    except ET.ParseError:
        return False
    except Exception:
        return False

def _analyze_xml_content(file_path: Path) -> Optional[str]:
    """
    Analyze XML file content to determine the specific type.
    
    Args:
        file_path: Path to the XML file
        
    Returns:
        Detected file type or None if unknown
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # Check for Nmap XML
        if root.tag == "nmaprun":
            return 'nmap'
        
        # Check for Nessus XML (alternative structures)
        if root.tag in ["NessusClientData_v2", "NessusClientData"]:
            return 'nessus'
            
        # Check for other known pentesting tool formats
        # Add more as needed...
        
        return None
    except ET.ParseError:
        return None
    except Exception:
        return None

def _analyze_json_content(file_path: Path) -> Optional[str]:
    """
    Analyze JSON file content to determine if it's a consolidated JSON file.
    
    Args:
        file_path: Path to the JSON file
        
    Returns:
        'consolidated_json' if it's a consolidated vulnerability file, None otherwise
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Check for consolidated vulnerability structure
        if isinstance(data, dict) and 'consolidated_vulnerabilities' in data:
            logger.debug(f"Detected consolidated JSON file: {file_path}")
            return 'consolidated_json'
        
        return None
    except (json.JSONDecodeError, Exception):
        return None

def _analyze_file_content(file_path: Path) -> Optional[str]:
    """
    Analyze file content by reading the beginning of the file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Detected file type or None if unknown
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Read first 1024 characters
            content = f.read(1024).lower()
            
            # Check for XML declaration and specific markers
            if '<?xml' in content:
                if 'nmaprun' in content:
                    return 'nmap'
                elif 'nessusclientdata' in content:
                    return 'nessus'
                elif '<report' in content and '<policy' in content:
                    return 'nessus'
            
            # Check for consolidated JSON structure
            if content.strip().startswith('{') and 'consolidated_vulnerabilities' in content:
                return 'consolidated_json'
            
        return None
    except Exception:
        return None

def get_default_output_name(input_file: Union[str, Path], file_type: str = None) -> str:
    """
    Generate default output filename for parsed data.
    
    Args:
        input_file: Path to the original input file
        file_type: Optional file type to include in name
        
    Returns:
        Generated filename string
    """
    timestamp = datetime.now().strftime('%d-%m-%y_%H-%M-%S')
    original_name = Path(input_file).stem
    
    if file_type:
        return f"{timestamp}_{original_name}_Parsed_{file_type.title()}.json"
    else:
        return f"{timestamp}_{original_name}_Parsed.json"

def get_consolidated_output_name(input_file: Union[str, Path], file_type: str = None) -> str:
    """
    Generate consolidated findings output filename.
    
    Args:
        input_file: Path to the original input file
        file_type: Optional file type to include in name
        
    Returns:
        Generated filename string
    """
    timestamp = datetime.now().strftime('%d-%m-%y_%H-%M-%S')
    original_name = Path(input_file).stem
    
    if file_type:
        return f"{timestamp}_{original_name}_Consolidated_{file_type.title()}.json"
    else:
        return f"{timestamp}_{original_name}_Consolidated_Findings.json"

def get_api_output_name(input_file: Union[str, Path], file_type: str = None) -> str:
    """
    Generate API-ready output filename.
    
    Args:
        input_file: Path to the original input file
        file_type: Optional file type to include in name
        
    Returns:
        Generated filename string
    """
    timestamp = datetime.now().strftime('%d-%m-%y_%H-%M-%S')
    original_name = Path(input_file).stem
    
    if file_type:
        return f"{timestamp}_{original_name}_API_Ready_{file_type.title()}.json"
    else:
        return f"{timestamp}_{original_name}_API_Ready.json"

def get_flat_json_output_name(input_file: Union[str, Path], file_type: str = None) -> str:
    """
    Generate flat JSON output filename.
    
    Args:
        input_file: Path to the original input file
        file_type: Optional file type to include in name
        
    Returns:
        Generated filename string
    """
    timestamp = datetime.now().strftime('%d-%m-%y_%H-%M-%S')
    original_name = Path(input_file).stem
    
    if file_type:
        return f"{timestamp}_{original_name}_Flat_{file_type.title()}.json"
    else:
        return f"{timestamp}_{original_name}_Flat.json"

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

def write_results_to_files(results: Dict[str, Any], input_file: Union[str, Path], output_dir: Union[str, Path], custom_output_name: str = None) -> Dict[str, bool]:
    """
    Write all processing results to appropriately named files.
    
    Args:
        results: Dictionary containing parsed data and optional consolidated/API/flat_json/excel data
        input_file: Original input file path (for naming)
        output_dir: Output directory path
        custom_output_name: Custom name for the main parsed file (optional)
        
    Returns:
        Dictionary indicating success/failure for each file type
    """
    from .json_utils import write_json_output
    
    output_dir = ensure_output_directory(output_dir)
    write_status = {}
    
    # Get file type from results
    file_type = results.get('file_type', None)
    
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
            parsed_filename = get_default_output_name(input_file, file_type)
        parsed_path = output_dir / parsed_filename
        write_status['parsed'] = write_json_output(results['parsed'], parsed_path)
    
    # Write consolidated file (Nessus only)
    if 'consolidated' in results and results['consolidated']:
        if base_name:
            consolidated_filename = f"{base_name}_Consolidated_Findings.json"
        else:
            consolidated_filename = get_consolidated_output_name(input_file, file_type)
        consolidated_path = output_dir / consolidated_filename
        write_status['consolidated'] = write_json_output(results['consolidated'], consolidated_path)
    
    # Write API file (Nessus only)
    if 'api_ready' in results and results['api_ready']:
        if base_name:
            api_filename = f"{base_name}_API_Ready.json"
        else:
            api_filename = get_api_output_name(input_file, file_type)
        api_path = output_dir / api_filename
        write_status['api_ready'] = write_json_output(results['api_ready'], api_path)
    
    # Write flat JSON file (Nmap only)
    if 'flat_json' in results and results['flat_json']:
        if base_name:
            flat_filename = f"{base_name}_Flat.json"
        else:
            flat_filename = get_flat_json_output_name(input_file, file_type)
        flat_path = output_dir / flat_filename
        write_status['flat_json'] = write_json_output(results['flat_json'], flat_path)
    
    # Write Excel file (Consolidated JSON only)
    if 'excel' in results and results['excel']:
        # Simply replace .json extension with .xlsx
        input_path = Path(input_file)
        excel_filename = input_path.stem + '.xlsx'
        excel_path = output_dir / excel_filename
        
        try:
            results['excel'].save(excel_path)
            logger.info(f"Excel report written to: {excel_path}")
            write_status['excel'] = True
        except Exception as e:
            logger.error(f"Failed to write Excel file: {e}")
            write_status['excel'] = False
    
    return write_status

def get_package_resource_path(resource_path: str) -> Path:
    """
    Get path to a resource within the YAPP package.
    
    Args:
        resource_path: Relative path to resource (e.g., 'config/default_rules.json')
        
    Returns:
        Absolute path to the resource
    """
    # Get the package root directory (parent of utils)
    package_root = Path(__file__).parent.parent
    return package_root / resource_path

def find_input_files(directory: Union[str, Path], file_types: list = None, recursive: bool = False) -> Dict[str, list[Path]]:
    """
    Find all supported input files in a directory.
    
    Args:
        directory: Directory to search
        file_types: List of file types to find (['nessus', 'nmap', 'consolidated_json'] or None for all)
        recursive: Whether to search subdirectories
        
    Returns:
        Dictionary mapping file types to lists of Path objects
    """
    directory = Path(directory)
    
    if not directory.exists():
        logger.warning(f"Directory does not exist: {directory}")
        return {}
    
    if not directory.is_dir():
        logger.warning(f"Path is not a directory: {directory}")
        return {}
    
    if file_types is None:
        file_types = ['nessus', 'nmap', 'consolidated_json']
    
    found_files = {ft: [] for ft in file_types}
    
    # Define patterns for each file type
    patterns = {
        'nessus': ['*.nessus'],
        'nmap': ['*.xml'],
        'consolidated_json': ['*_Consolidated*.json']
    }
    
    for file_type in file_types:
        for pattern in patterns.get(file_type, []):
            if recursive:
                search_pattern = f"**/{pattern}"
            else:
                search_pattern = pattern
            
            files = list(directory.glob(search_pattern))
            
            # Verify files using detect_file_type
            verified_files = []
            for file_path in files:
                try:
                    detected = detect_file_type(file_path)
                    if detected == file_type:
                        verified_files.append(file_path)
                except Exception:
                    continue
            
            found_files[file_type].extend(verified_files)
    
    # Log results
    total_files = sum(len(files) for files in found_files.values())
    logger.info(f"Found {total_files} supported files in {directory}")
    for file_type, files in found_files.items():
        if files:
            logger.info(f"  {file_type.upper()}: {len(files)} files")
    
    return found_files

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