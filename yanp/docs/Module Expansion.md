# YANP Parser Extension Guide
How to add new file type parsers to the YANP framework

This guide shows how to extend YANP with new parsers while maintaining
the existing clean architecture and following KISS/DRY principles.

## STEP 1: CREATE THE NEW PARSER CLASS
Create a new parser in yanp/core/your_parser.py following this template:

```python
import logging
import xml.etree.ElementTree as ET  # or json, csv, etc.
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class YourToolParser:
    '''Parser for YourTool output files with structured output format.'''
    
    def __init__(self, file_path: str):
        '''Initialize parser with file path.'''
        self.file_path = Path(file_path)
        # Add your initialization here
        
    def parse(self, **kwargs) -> Optional[Dict[str, Any]]:
        '''
        Parse YourTool file and return structured data.
        
        Args:
            **kwargs: Tool-specific parsing options
        
        Returns:
            dict: Parsed data with context, stats, and main data sections
        '''
        # Validate input file
        self._validate_file()
        
        try:
            # Your parsing logic here
            context = self._parse_context()
            main_data = self._parse_main_data(**kwargs)
            stats = self._generate_statistics(main_data)
            
            return {
                "context": context,
                "stats": stats,
                "main_data": main_data  # Use appropriate name
            }
            
        except Exception as e:
            logger.error(f"Unexpected error during parsing: {str(e)}")
            raise
    
    def _validate_file(self) -> None:
        '''Validate if the input file is accessible and has correct format.'''
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")
        
        # Add format-specific validation
        # Check extension, content headers, etc.
        
    def _parse_context(self) -> Dict[str, Any]:
        '''Parse scan/tool context information.'''
        return {
            "tool": "yourtool",
            "tool_version": "",
            "scan_start": "",
            "scan_end": "",
            # Add tool-specific context
        }
    
    def _parse_main_data(self, **kwargs) -> Dict[str, Dict[str, Any]]:
        '''Parse the main data from the file.'''
        # Your main parsing logic here
        return {}
    
    def _generate_statistics(self, main_data: Dict) -> Dict[str, Any]:
        '''Generate comprehensive statistics.'''
        return {
            "total_items": len(main_data),
            # Add relevant statistics
        }
```
---
## STEP 2: UPDATE FILE TYPE DETECTION
Update yanp/utils/file_utils.py to detect your new file type:

Add to detect_file_type():
```python
def detect_file_type(file_path: Union[str, Path]) -> str:
    # ... existing code ...
    
    elif extension == '.yourtool':
        if _verify_yourtool_file(file_path):
            return 'yourtool'
    
    # ... rest of function ...

def _verify_yourtool_file(file_path: Path) -> bool:
    '''Verify that a file is actually a valid YourTool file.'''
    try:
        # Add your validation logic
        # Check file headers, required fields, etc.
        return True
    except Exception:
        return False
```

Add to _analyze_xml_content() if it's XML-based:
```python
def _analyze_xml_content(file_path: Path) -> Optional[str]:
    # ... existing code ...
    
    # Check for YourTool XML
    if root.tag == "yourtoolrun":
        return 'yourtool'
```

Add to _analyze_file_content() for other formats:
```python
def _analyze_file_content(file_path: Path) -> Optional[str]:
    # ... existing code ...
    
    # Check for YourTool JSON format
    if content.strip().startswith('{') and '"yourtool_version"' in content:
        return 'yourtool'
```
---
## STEP 3: UPDATE CORE MODULE
Update yanp/core/__init__.py to include your parser:

```python
from .nessus_parser import NessusParser
from .nmap_parser import NmapParser
from .yourtool_parser import YourToolParser  # Add this
from .consolidator import VulnerabilityConsolidator, ConsolidationError
from .formatter import APIFormatter, FormatterError

__all__ = [
    # Core parsers
    'NessusParser',
    'NmapParser',
    'YourToolParser',  # Add this
    
    # ... rest unchanged
]
```
---
# STEP 4: UPDATE CLI SUPPORT
Update yanp/cli.py to support your new file type:

1. Add to setup_argparse():
```python
parser.add_argument(
    '-t', '--file-type',
    choices=['auto', 'nessus', 'nmap', 'yourtool'],  # Add yourtool
    default='auto',
    help='Input file type (default: auto-detect)'
)

# Add tool-specific argument group
yourtool_group = parser.add_argument_group('YourTool options')
yourtool_group.add_argument(
    '--yourtool-option',
    help='Your tool specific option'
)
```

2. Add to process_file():
```python
def process_file(
    # ... existing args ...
    yourtool_option: str = None,  # Add tool-specific args
) -> Dict[str, Any]:
    
    # ... existing code ...
    
    elif file_type == "yourtool":
        from .core.yourtool_parser import YourToolParser
        parser = YourToolParser(input_file)
        parsed_data = parser.parse(yourtool_option=yourtool_option)
        results['parsed'] = parsed_data
        results['file_type'] = 'yourtool'
        
        # Add tool-specific processing if needed
```

3. Add display function:
```python
def display_yourtool_summary(parsed_data: dict):
    '''Display formatted summary of YourTool results'''
    # Implement tool-specific summary display
```
---
## STEP 5: UPDATE MAIN MODULE
Update yanp/__init__.py to include your parser:

1. Add import:
```python
from .core import (
    NessusParser,
    NmapParser,
    YourToolParser,  # Add this
    # ... rest
)
```

2. Add to __all__:
```python
__all__ = [
    # Core parsers
    "NessusParser",
    "NmapParser", 
    "YourToolParser",  # Add this
    # ... rest
]
```

3. Update process_file():
```python
def process_file(
    # ... existing args ...
    yourtool_option: str = None,  # Add tool-specific args
) -> dict:
    
    # ... existing code ...
    
    elif file_type == "yourtool":
        parser = YourToolParser(input_file)
        parsed_data = parser.parse(yourtool_option=yourtool_option)
        results['parsed'] = parsed_data
        results['file_type'] = 'yourtool'
        
        # Add any tool-specific processing
```

4. Update get_supported_file_types():
```python
def get_supported_file_types() -> dict:
    return {
        # ... existing entries ...
        "yourtool": {
            "description": "YourTool scanner output files",
            "extensions": [".yourtool", ".xml"],
            "features": ["parsing", "your_feature"],
            "parser_class": "YourToolParser"
        }
    }
```
---
## STEP 6: UPDATE UTILITIES (OPTIONAL)
If your tool needs special output handling, update yanp/utils/file_utils.py:

```python
def get_default_output_name(input_file: Union[str, Path], file_type: str = None) -> str:
    # ... existing code handles this automatically with file_type parameter
    # No changes needed unless you need special naming
```

Add find patterns if needed:
```python
def find_input_files(directory: Union[str, Path], file_types: list = None, recursive: bool = False) -> Dict[str, list[Path]]:
    # Add to patterns dict:
    patterns = {
        'nessus': ['*.nessus'],
        'nmap': ['*.xml'],
        'yourtool': ['*.yourtool', '*.yt'],  # Add your patterns
    }
```
---
## STEP 7: USAGE EXAMPLES
After implementing your parser, users can use it like this:

### CLI usage
yanp -i scan.yourtool -t yourtool --yourtool-option value

### Library usage
from yanp import process_file, YourToolParser

### Auto-detect
results = process_file('scan.yourtool')

### Explicit type
results = process_file('scan.yourtool', file_type='yourtool', yourtool_option='value')

### Direct parser usage
parser = YourToolParser('scan.yourtool')
data = parser.parse(yourtool_option='value')

---
## CONSOLIDATION AND API FORMATTING (ADVANCED)
If your tool finds vulnerabilities that could benefit from consolidation:

1. Create tool-specific consolidation rules in yanp/config/
2. Extend VulnerabilityConsolidator to handle your data format
3. Create tool-specific API formatter if needed

This requires more extensive changes but follows the same modular approach.


### EXAMPLE: ADDING MASSCAN SUPPORT
Here's a concrete example of adding Masscan JSON support:

1. Create yanp/core/masscan_parser.py
2. Update file detection for .json with masscan signatures
3. Add CLI support with --rate-limit option
4. Update all imports and __all__ lists
5. Users can then run:
   yanp -i scan.json -t masscan --rate-limit 1000

The framework handles everything else automatically!


if __name__ == "__main__":
    print("This is a guide file - see comments for implementation details")
    print("Follow the steps above to add new parsers to YANP")
    print("Maintain the same interface patterns for consistency")