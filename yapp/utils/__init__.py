"""
yapp/utils/__init__.py
YAPP utilities package.

This package contains utility modules for file operations, JSON handling, and logging.
"""

# Import key functions for easy access
from .logger import setup_logging, get_logger, set_log_level
from .json_utils import write_json_output, read_json_file, validate_json_structure
from .file_utils import (
    detect_file_type,
    get_default_output_name,
    get_consolidated_output_name, 
    get_api_output_name,
    get_flat_json_output_name,
    ensure_output_directory,
    write_results_to_files,
    find_input_files,
    sanitize_filename
)
from .display import (
    print_banner,
    display_summary,
    display_nessus_summary,
    display_nmap_summary,
    display_consolidation_summary,
    display_api_summary,
    Colors
)

__all__ = [
    # Logger functions
    'setup_logging',
    'get_logger', 
    'set_log_level',
    
    # JSON utilities
    'write_json_output',
    'read_json_file',
    'validate_json_structure',
    
    # File utilities
    'detect_file_type',
    'get_default_output_name',
    'get_consolidated_output_name',
    'get_api_output_name', 
    'get_flat_json_output_name',
    'ensure_output_directory',
    'write_results_to_files',
    'find_input_files',
    'sanitize_filename',
    
    # Display utilities
    'print_banner',
    'display_summary',
    'display_nessus_summary',
    'display_nmap_summary',
    'display_consolidation_summary',
    'display_api_summary',
    'Colors'
]