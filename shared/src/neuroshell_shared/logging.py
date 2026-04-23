"""Logging configuration for NeuroShell services."""

import sys
from typing import Any, Optional

from loguru import logger

from neuroshell_shared.config import get_settings


def setup_logging(*, log_level: Optional[str] = None, log_file: Optional[str] = None) -> None:
    """
    Configure logging for the application.

    Args:
        log_level: Override log level from settings
        log_file: Optional file path for file logging
    """
    settings = get_settings()
    level = log_level or settings.log_level

    logger.remove()

    logger.add(
        sys.stderr,
        format=settings.log_format,
        level=level,
        colorize=True,
        backtrace=True,
        diagnose=True,
    )

    if log_file:
        logger.add(
            log_file,
            format=settings.log_format,
            level=level,
            rotation="10 MB",
            retention="7 days",
            compression="zip",
        )

    logger.info(f"Logging initialized at {level} level")


def get_logger(name: Optional[str] = None) -> Any:
    """
    Get a logger instance.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Logger instance
    """
    if name:
        return logger.bind(name=name)
    return logger