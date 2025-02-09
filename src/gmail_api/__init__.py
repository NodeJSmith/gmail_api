from gmail_api import label, query
from gmail_api.api import Gmail

# import to setup logging
from gmail_api.logging import logger  # type: ignore # noqa

__all__ = ["Gmail", "label", "query"]
