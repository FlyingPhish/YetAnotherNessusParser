import logging

def setup_logging(level=logging.DEBUG):
    """Configure and return logger instance"""
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=level,
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger(__name__)