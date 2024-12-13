import argparse
from pathlib import Path

def setup_argparse() -> argparse.ArgumentParser:
    """Setup and return argument parser"""
    parser = argparse.ArgumentParser(
        description='Nessus XML Parser - Converts Nessus XML to JSON format'
    )
    
    parser.add_argument(
        '-n', '--nessus-file',
        required=True,
        help='Path to input Nessus XML file'
    )
    
    parser.add_argument(
        '-of', '--output-folder',
        default='./output',
        help='Output folder path (default: ./output)'
    )
    
    parser.add_argument(
        '-on', '--output-name',
        help='Output file name (default: timestamp_<original-name>_Parsed_Nessus.json)'
    )
    
    return parser