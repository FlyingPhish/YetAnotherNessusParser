# YAPP Parser Extension Guide

How to add new file type parsers to YAPP while maintaining clean architecture and KISS/DRY principles.

## Current Architecture

```
yapp/
├── __init__.py              # Public API exports
├── cli.py                   # Command-line interface
├── core/
│   ├── processor.py         # Main processing pipeline
│   ├── nessus_parser.py     # Nessus XML parser
│   ├── nmap_parser.py       # Nmap XML parser
│   ├── consolidator.py      # Vulnerability consolidation
│   ├── formatter.py         # API formatting
│   └── __init__.py          # Core exports
└── utils/
    ├── file_utils.py        # File operations & detection
    ├── display.py           # CLI output formatting
    └── ...
```

## Step 1: Create Parser Class

Create `yapp/core/yourtool_parser.py`:

```python
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class YourToolParser:
    """Parser for YourTool output files."""
    
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        
    def parse(self, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Parse YourTool file and return structured data.
        
        Returns:
            dict: Parsed data with context, stats, and main data sections
        """
        self._validate_file()
        
        try:
            context = self._parse_context()
            main_data = self._parse_main_data(**kwargs)
            stats = self._generate_statistics(main_data)
            
            return {
                "context": context,
                "stats": stats,
                "main_data": main_data
            }
        except Exception as e:
            logger.error(f"Parsing failed: {str(e)}")
            raise
    
    def _validate_file(self) -> None:
        """Validate file exists and has correct format."""
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")
        
        # Add format-specific validation
        if self.file_path.suffix.lower() != '.yourtool':
            raise ValueError(f"Invalid file extension")
    
    def _parse_context(self) -> Dict[str, Any]:
        """Parse tool context information."""
        return {
            "tool": "yourtool",
            "tool_version": "",
            "scan_start": "",
            "scan_end": ""
        }
    
    def _parse_main_data(self, **kwargs) -> Dict[str, Any]:
        """Parse main data from file."""
        # Your parsing logic here
        return {}
    
    def _generate_statistics(self, main_data: Dict) -> Dict[str, Any]:
        """Generate statistics from parsed data."""
        return {
            "total_items": len(main_data)
        }
```

## Step 2: Update File Detection

Update `yapp/utils/file_utils.py`:

```python
def detect_file_type(file_path: Union[str, Path]) -> str:
    # Add to extension check
    elif extension == '.yourtool':
        if _verify_yourtool_file(file_path):
            return 'yourtool'
    
    # Add content analysis if needed
    
def _verify_yourtool_file(file_path: Path) -> bool:
    """Verify file is valid YourTool format."""
    try:
        # Add validation logic
        return True
    except Exception:
        return False
```

## Step 3: Update Core Processor

Update `yapp/core/processor.py`:

```python
from .yourtool_parser import YourToolParser

def process_file(
    input_file: str,
    file_type: str = "auto",
    # ... existing params ...
    yourtool_option: str = None,  # Add tool-specific params
    **kwargs
) -> Dict[str, Any]:
    
    # Add to file type handling
    elif file_type == "yourtool":
        parser = YourToolParser(input_file)
        parsed_data = parser.parse(yourtool_option=yourtool_option)
        results['parsed'] = parsed_data
        results['file_type'] = 'yourtool'
        
        # Add tool-specific processing if needed
    
    # ... rest unchanged
```

## Step 4: Update Core Exports

Update `yapp/core/__init__.py`:

```python
from .yourtool_parser import YourToolParser

__all__ = [
    'NessusParser',
    'NmapParser',
    'YourToolParser',  # Add this
    # ... rest unchanged
]
```

## Step 5: Update CLI Support

Update `yapp/cli.py`:

### Add argument parsing:
```python
def setup_argparse() -> argparse.ArgumentParser:
    parser.add_argument(
        '-t', '--file-type',
        choices=['auto', 'nessus', 'nmap', 'yourtool'],  # Add yourtool
        default='auto'
    )
    
    # Add tool-specific options
    yourtool_group = parser.add_argument_group('YourTool options')
    yourtool_group.add_argument(
        '--yourtool-option',
        help='YourTool specific option'
    )
```

### Add display function in `yapp/utils/display.py`:
```python
def display_yourtool_summary(parsed_data: dict):
    """Display YourTool scan results."""
    stats = parsed_data['stats']
    context = parsed_data['context']
    
    print(f"\n{Colors.CYAN}{'=' * 50}{Colors.RESET}")
    print(f"{Colors.WHITE}{Colors.BRIGHT}YOURTOOL SCAN SUMMARY{Colors.RESET}")
    print(f"{Colors.CYAN}{'-' * 50}{Colors.RESET}")
    
    print(f"{Colors.WHITE}{Colors.BRIGHT}Scan Context:{Colors.RESET}")
    print(f"  • Tool: {Colors.GREEN}{context['tool']}{Colors.RESET}")
    # Add more context display
    
    print(f"\n{Colors.WHITE}{Colors.BRIGHT}Statistics:{Colors.RESET}")
    print(f"  • Total Items: {Colors.GREEN}{stats['total_items']}{Colors.RESET}")
    # Add more stats display
```

### Update display dispatcher:
```python
def display_summary(parsed_data: dict, file_type: str):
    if file_type == "nessus":
        display_nessus_summary(parsed_data)
    elif file_type == "nmap":
        display_nmap_summary(parsed_data)
    elif file_type == "yourtool":
        display_yourtool_summary(parsed_data)
```

## Step 6: Update Main Module

Update `yapp/__init__.py`:

```python
from .core import (
    NessusParser,
    NmapParser,
    YourToolParser,  # Add this
    # ... rest
)

__all__ = [
    "NessusParser",
    "NmapParser", 
    "YourToolParser",  # Add this
    # ... rest
]

def get_supported_file_types() -> dict:
    return {
        # ... existing entries ...
        "yourtool": {
            "description": "YourTool scanner output files",
            "extensions": [".yourtool"],
            "features": ["parsing", "your_feature"],
            "parser_class": "YourToolParser"
        }
    }
```

## Step 7: Update File Utils (Optional)

If your tool needs special file handling, update `yapp/utils/file_utils.py`:

```python
def find_input_files(directory, file_types=None, recursive=False):
    patterns = {
        'nessus': ['*.nessus'],
        'nmap': ['*.xml'],
        'yourtool': ['*.yourtool'],  # Add patterns
    }
```

## Usage Examples

After implementation, users can:

### CLI usage:
```bash
yapp -i scan.yourtool -t yourtool --yourtool-option value
```

### Library usage:
```python
from yapp import process_file, YourToolParser

# Auto-detect
results = process_file('scan.yourtool')

# Explicit type with options
results = process_file(
    'scan.yourtool', 
    file_type='yourtool',
    yourtool_option='value'
)

# Direct parser usage
parser = YourToolParser('scan.yourtool')
data = parser.parse(yourtool_option='value')
```

## Key Principles

### Follow Existing Patterns
- Same return structure: `{"context": {}, "stats": {}, "main_data": {}}`
- Same error handling approach
- Same logging patterns

### Maintain Modularity
- Parser class is self-contained
- Processing options passed as parameters
- No dependencies between parsers

### Keep It Simple
- One parser per file type
- Clear, descriptive method names
- Minimal required methods

## Testing Your Parser

```python
# Basic functionality test
from yapp import process_file

try:
    results = process_file('test.yourtool')
    print("✅ Parser working")
    print(f"File type: {results['file_type']}")
    print(f"Items found: {results['parsed']['stats']['total_items']}")
except Exception as e:
    print(f"❌ Parser failed: {e}")
```

## Advanced: Adding Consolidation Support

If your tool finds vulnerabilities that need consolidation:

1. Extend the data structure to match vulnerability format
2. Create tool-specific rules in `yapp/config/`
3. Update consolidator to handle your data format

This requires deeper integration but follows the same modular approach.

## Example: Masscan JSON Support

Complete example for adding Masscan support:

1. **Parser**: `yapp/core/masscan_parser.py` - Parse JSON output
2. **Detection**: Check for JSON with `"masscan"` signature  
3. **CLI**: Add `--rate-limit` option for Masscan-specific filtering
4. **Display**: Show discovered hosts and ports

Users can then run:
```bash
yapp -i scan.json -t masscan --rate-limit 1000
```

The framework handles file I/O, argument parsing, and output formatting automatically.