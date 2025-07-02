"""
yapp/config/__init__.py
YAPP configuration package.

This package contains default configuration files and utilities
for managing YAPP settings.
"""

from pathlib import Path

def get_default_rules_path() -> Path:
    """
    Get the path to the default consolidation rules file.
    
    Returns:
        Path: Path to default_rules.json in this package
    """
    return Path(__file__).parent / "default_rules.json"

def get_config_dir() -> Path:
    """
    Get the path to the configuration directory.
    
    Returns:
        Path: Path to the config directory
    """
    return Path(__file__).parent

__all__ = [
    'get_default_rules_path',
    'get_config_dir'
]