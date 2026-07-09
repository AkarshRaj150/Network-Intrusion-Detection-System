"""
utils/logger.py
----------------
One place that sets up Python's logging so every module prints messages
in the same format and also writes them to a file. Beginner note:
`logging` is the "proper" way to print status messages in a real project
instead of scattering `print()` everywhere - it timestamps things and
lets you control verbosity.
"""
import logging
import os

os.makedirs("logs", exist_ok=True)

def get_logger(name):
    logger = logging.getLogger(name)
    if logger.handlers:
        # Avoid adding duplicate handlers if this is called more than once
        return logger

    logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Print to terminal
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Also save to a file so you have a permanent record
    file_handler = logging.FileHandler("logs/nids.log")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger
