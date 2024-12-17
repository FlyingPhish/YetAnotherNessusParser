import json
import logging
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)

def parse_html_encoded_fqdns(fqdns_str: str) -> List[str]:
    """Parse HTML-encoded JSON string containing FQDN data.
    
    Args:
        fqdns_str: HTML-encoded JSON string with FQDN data
        
    Returns:
        List of FQDN strings
    """
    try:
        # Remove HTML encoding and parse JSON
        cleaned_str = fqdns_str.replace('&quot;', '"')
        fqdns_data = json.loads(cleaned_str)
        
        # Extract all unique FQDNs
        return [entry['FQDN'] for entry in fqdns_data if 'FQDN' in entry]
    except (json.JSONDecodeError, TypeError):
        logger.debug(f"Failed to parse FQDN JSON: {fqdns_str}")
        return []
    
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