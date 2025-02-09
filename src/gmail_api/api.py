import atexit
import typing
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from json import JSONDecodeError
from logging import getLogger
from typing import Any

import httpx
from httplib2 import Http
from httpx import Request
from yarl import URL

from gmail_api.email_msg import EmailMsg

if typing.TYPE_CHECKING:
    import googleapiclient.http  # type: ignore
    from oauth2client.client import OAuth2Credentials


LOGGER = getLogger(__name__)

JSON_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Accept-Encoding": "gzip",
    "User-Agent": "python-gmail-api/0.0.1 (gzip)",
}

HOST = "gmail.googleapis.com"
BASE_URL = f"{HOST}/gmail/v1/users/{{user_id}}"

THREAD_BASE_URL = f"{BASE_URL}/threads"
DRAFT_BASE_URL = f"{BASE_URL}/drafts"
LABEL_BASE_URL = f"{BASE_URL}/labels"


## Drafts

# Get
GET_DRAFT_URL = "/{draft_id}"
LIST_DRAFTS_URL = "/drafts"

# Post
CREATE_DRAFT_URL = "/drafts"
SEND_DRAFT_URL = "/send"  # Draft

# Delete
DELETE_DRAFT_URL = "/{draft_id}"

## Labels

# Get
GET_LABEL_URL = "/{label_id}"
LIST_LABELS_URL = "/labels"

# Put/Patch
UPDATE_LABEL_URL = "/{label_id}"  # Label

# Post
CREATE_LABEL_URL = "/labels"  # Label


# Delete
DELETE_LABEL_URL = "/{label_id}"


## Threads

# Get
GET_THREAD_URL = "/{thread_id}"
LIST_THREADS_URL = "/threads"


# Post
TRASH_THREAD_URL = "/{thread_id}/trash"
UNTRASH_THREAD_URL = "/{thread_id}/untrash"
MODIFY_THREAD_URL = "/{thread_id}/modify"  # ModifyThreadRequest

# Delete
DELETE_THREAD_URL = "/{thread_id}"


class HttpxGmailAuth(httpx.Auth):
    def __init__(self, credentials: "OAuth2Credentials") -> None:
        """HTTPX Authentication extension for OAuth2Credentials.

        Args:
            credentials (OAuth2Credentials): OAuth2Credentials object.
        """

        self.credentials = credentials

    def auth_flow(self, request: Request) -> Generator[Request, Any, None]:
        if self.credentials.access_token_expired:
            self.credentials.refresh(Http())

        request.headers["Authorization"] = f"Bearer {self.credentials.access_token}"

        yield request


class EndpointApi:
    session: httpx.Client
    user_id: str = "me"
    credentials: "OAuth2Credentials"
    default_path_template: str

    def __init__(self, credentials: "OAuth2Credentials") -> None:
        self.credentials = credentials
        self.session = httpx.Client(
            headers=JSON_HEADERS, timeout=httpx.Timeout(20.0, connect=60.0), auth=HttpxGmailAuth(credentials)
        )
        atexit.register(self.session.close)

    def _msg_request(
        self,
        method: str,
        url: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> Any:
        """Perform an API request."""

        headers = headers or {}
        params = params or {}
        params = {k: v for k, v in params.items() if v is not None}
        url = url.lstrip("/")

        path = self.default_path_template.format(user_id=self.user_id, path=url)

        full_url = str(URL.build(scheme="https", host=HOST, path=path))

        LOGGER.debug(f"Making {method!r} request to {full_url}, params: {params}")

        request = self.session.build_request(method, full_url, headers=headers, params=params, **kwargs)
        response = self.session.send(request)

        try:
            response.raise_for_status()
        except httpx.RequestError as e:
            LOGGER.exception(f"Error making request: {e}")
            LOGGER.exception(f"Response: {response.text}")
            raise
        except Exception as e:
            LOGGER.exception(f"Error making request: {e}")
            raise

        if not response.text:
            return None

        try:
            resp = response.json()
        except JSONDecodeError as e:
            LOGGER.error(f"Error decoding JSON: {e}")
            LOGGER.error(f"Response: {response.text}")
            raise

        return resp


class Messages(EndpointApi):
    default_path_template: str = "/gmail/v1/users/{user_id}/messages/{path}"

    def batch_delete(self, message_ids: list[str] | list[EmailMsg]) -> "googleapiclient.http.HttpRequest":
        message_ids = [m.id if isinstance(m, EmailMsg) else m for m in message_ids]

        body = {"ids": message_ids}
        return self._msg_request("POST", "batchDelete", json=body)

    def batch_modify(
        self,
        message_ids: list[str] | list[EmailMsg],
        add_labels: list[str],
        remove_labels: list[str],
    ) -> "googleapiclient.http.HttpRequest":
        message_ids = [m.id if isinstance(m, EmailMsg) else m for m in message_ids]

        body = {"ids": message_ids, "addLabelIds": add_labels, "removeLabelIds": remove_labels}
        return self._msg_request("POST", "batchModify", json=body)

    def delete(self, message_id: str | EmailMsg) -> "googleapiclient.http.HttpRequest":
        message_id = message_id.id if isinstance(message_id, EmailMsg) else message_id
        return self._msg_request("DELETE", f"{message_id}")

    def get(self, message_id: str) -> "EmailMsg":
        raw_message = self._msg_request("GET", message_id, params={"alt": "json", "format": "raw"})
        return EmailMsg(raw_message)

    def list_(
        self,
        include_spam_trash: bool = False,
        label_ids: str | list[str] | None = None,
        max_results: int = 500,
        page_token: str | None = None,
        q: str | None = None,
        **kwargs: typing.Any,
    ) -> list[EmailMsg]:
        params = {
            "includeSpamTrash": include_spam_trash,
            "labelIds": label_ids,
            "maxResults": max_results,
            "pageToken": page_token,
            "q": q,
        }

        params = {k: v for k, v in params.items() if v is not None}

        all_messages = []
        resp = self._msg_request("GET", "", params=params, **kwargs)
        all_messages.extend(resp.get("messages", []))

        while "nextPageToken" in resp:
            params["pageToken"] = resp["nextPageToken"]
            resp = self._msg_request("GET", "", params=params, **kwargs)
            all_messages.extend(resp["messages"])

        with ThreadPoolExecutor() as pool:
            parsed_messages = list(pool.map(self.get, (m["id"] for m in all_messages)))

        return parsed_messages

    def modify(self, message_id: str | EmailMsg, add_labels: list[str], remove_labels: list[str]) -> "EmailMsg":
        message_id = message_id.id if isinstance(message_id, EmailMsg) else message_id
        body = {"addLabelIds": add_labels, "removeLabelIds": remove_labels}
        self._msg_request("POST", f"{message_id}/modify", json=body)
        return self.get(message_id)

    # def send(self, *, body: "Message", **kwargs: typing.Any) -> "MessageHttpRequest":
    #     return self._msg_request("POST", "send", json=body, **kwargs)

    def trash(self, message_id: str | EmailMsg) -> "EmailMsg":
        message_id = message_id.id if isinstance(message_id, EmailMsg) else message_id
        self._msg_request("POST", f"{message_id}/trash")
        return self.get(message_id)

    def untrash(self, message_id: str | EmailMsg) -> "EmailMsg":
        message_id = message_id.id if isinstance(message_id, EmailMsg) else message_id
        self._msg_request("POST", f"{message_id}/untrash")
        return self.get(message_id)


class Drafts:
    pass


class Labels:
    pass


class Threads:
    pass


class Users:
    pass


class Gmail:
    messages: Messages

    def __init__(self, credentials: "OAuth2Credentials") -> None:
        self.credentials = credentials
        self.session = httpx.Client(headers=JSON_HEADERS, timeout=httpx.Timeout(20.0, connect=60.0))
        atexit.register(self.session.close)

        self.messages = Messages(credentials=credentials)
