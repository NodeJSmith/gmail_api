from mailparser.utils import sanitize


# replaces ported_string from mailparser.utils
@sanitize
def decode_string(s: bytes | str | None, encoding: str = "utf-8", errors: str = "ignore") -> str:
    if s is None:
        return ""
    if isinstance(s, str):  # If already a str, return as-is
        return s
    try:
        return s.decode(encoding)
    except (LookupError, UnicodeDecodeError):
        return s.decode("utf-8", errors)


def truncate_text(text: str, max_length: int) -> str:
    """
    Truncate the text to a maximum length.

    Args:
        text (string): The text to truncate
        max_length (int): The maximum length

    Returns:
        string: The truncated text
    """
    return text[:max_length] + "..." if len(text) > max_length else text
