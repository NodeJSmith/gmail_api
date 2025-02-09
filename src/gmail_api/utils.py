import typing

from mailparser.utils import sanitize
from oauth2client.client import OAuth2Credentials

if typing.TYPE_CHECKING:
    from google.oauth2.credentials import Credentials


def convert_install_app_flow_creds_to_oauth2creds(creds: "Credentials") -> OAuth2Credentials:
    token_response = {
        "access_token": creds.token,
        "expires_in": 3599,
        "refresh_token": creds.refresh_token,
        "scope": " ".join(creds.scopes),
        "token_type": "Bearer",
    }

    oauth2creds = OAuth2Credentials(
        access_token=creds.token,
        client_id=creds.client_id,
        client_secret=creds.client_secret,
        refresh_token=creds.refresh_token,
        token_expiry=creds.expiry,
        token_uri=creds.token_uri,
        id_token=None,
        scopes=creds.scopes,
        user_agent=None,
        revoke_uri="https://oauth2.googleapis.com/revoke",
        id_token_jwt=None,
        token_response=token_response,
        token_info_uri="https://oauth2.googleapis.com/tokeninfo",
    )
    return oauth2creds


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
