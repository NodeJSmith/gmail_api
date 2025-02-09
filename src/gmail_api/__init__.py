import logging
import os

from gmail_api.api import Gmail

LOG_LEVEL = os.getenv("GMAIL_API_LOG_LEVEL", "INFO")
LOG_FMT = "{asctime} - {module}.{funcName}:{lineno} - {levelname} - {message}"
DATE_FMT = "%Y-%m-%d %H:%M:%S%z"

logger = logging.getLogger("simplegmail")
logger.setLevel(LOG_LEVEL)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(fmt=LOG_FMT, datefmt=DATE_FMT, style="{"))
logger.addHandler(handler)


__all__ = ["Gmail"]
