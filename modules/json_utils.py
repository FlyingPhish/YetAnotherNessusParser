import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

def write_json_output(data: dict, output_path: Path) -> bool:
    """Write data to JSON file"""
    try:
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Successfully wrote parsed data to {output_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to write output file: {str(e)}")
        return False