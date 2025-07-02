import json
import logging
from pathlib import Path
from typing import Any, Dict, Union

logger = logging.getLogger(__name__)

def write_json_output(data: Dict[str, Any], output_path: Union[str, Path], indent: int = 2) -> bool:
    """
    Write data to JSON file with proper error handling.
    
    Args:
        data: Dictionary data to write
        output_path: Path where to write the JSON file
        indent: JSON indentation level (default: 2)
        
    Returns:
        bool: True if successful, False otherwise
    """
    output_path = Path(output_path)
    
    try:
        # Ensure parent directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
            
        logger.info(f"Successfully wrote data to {output_path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to write output file {output_path}: {str(e)}")
        return False

def read_json_file(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Read and parse a JSON file.
    
    Args:
        file_path: Path to the JSON file
        
    Returns:
        Parsed JSON data as dictionary
        
    Raises:
        FileNotFoundError: If file doesn't exist
        json.JSONDecodeError: If file contains invalid JSON
    """
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"JSON file not found: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Invalid JSON in file {file_path}: {str(e)}")

def validate_json_structure(data: Dict[str, Any], required_keys: list[str]) -> bool:
    """
    Validate that a JSON data structure contains required keys.
    
    Args:
        data: JSON data to validate
        required_keys: List of required top-level keys
        
    Returns:
        bool: True if all required keys are present
    """
    if not isinstance(data, dict):
        logger.error("Data must be a dictionary")
        return False
    
    missing_keys = [key for key in required_keys if key not in data]
    if missing_keys:
        logger.error(f"Missing required keys: {missing_keys}")
        return False
    
    return True

def pretty_print_json(data: Dict[str, Any], indent: int = 2) -> str:
    """
    Convert data to pretty-printed JSON string.
    
    Args:
        data: Data to convert
        indent: Indentation level
        
    Returns:
        Pretty-printed JSON string
    """
    return json.dumps(data, indent=indent, ensure_ascii=False)