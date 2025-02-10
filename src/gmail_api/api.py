import atexit
import base64
import json
import typing
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from json import JSONDecodeError
from logging import getLogger
from os import PathLike
from pathlib import Path
from typing import Any

import httpx
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from httpx import Request
from yarl import URL

from gmail_api.email_msg import EmailMsg

if typing.TYPE_CHECKING:
    from email.message import Message

    import googleapiclient.http  # type: ignore


LOGGER = getLogger(__name__)
SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.settings.basic",
]
DEFAULT_CREDS_FILE_PATH = Path("credentials.json")
DEFAULT_TOKEN_FILE_PATH = Path("token.json")

JSON_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Accept-Encoding": "gzip",
    "User-Agent": "python-gmail-api/0.0.1 (gzip)",
}

HOST = "gmail.googleapis.com"

BASE_URL = URL(f"https://{HOST}/gmail/v1/users/me")

# THREAD_BASE_URL = f"{BASE_URL}/threads"
# DRAFT_BASE_URL = f"{BASE_URL}/drafts"
# LABEL_BASE_URL = f"{BASE_URL}/labels"


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
    def __init__(self, credentials: Credentials) -> None:
        """HTTPX Authentication extension for Credentials.

        Args:
            credentials (Credentials): Credentials object.
        """

        self.credentials = credentials

    def auth_flow(self, request: Request) -> Generator[Request, Any, None]:
        assert isinstance(self.credentials, Credentials)

        if self.credentials.expired:
            self.credentials.refresh(GoogleRequest())

        request.headers["Authorization"] = f"Bearer {self.credentials.token}"
        yield request


class EndpointApi:
    session: httpx.Client
    user_id: str = "me"
    endpoint: str

    def __init__(self, session: httpx.Client) -> None:
        self.session = session

    def _request(
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

        endpoint = self.endpoint.strip("/")
        url = url.lstrip("/")

        full_url = str(BASE_URL / endpoint / url)

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
    endpoint: str = "messages"

    def batch_delete(self, message_ids: list[str] | list[EmailMsg]) -> "googleapiclient.http.HttpRequest":
        message_ids = [m.id if isinstance(m, EmailMsg) else m for m in message_ids]

        body = {"ids": message_ids}
        return self._request("POST", "batchDelete", json=body)

    def batch_modify(
        self,
        message_ids: list[str] | list[EmailMsg],
        add_labels: list[str],
        remove_labels: list[str],
    ) -> "googleapiclient.http.HttpRequest":
        message_ids = [m.id if isinstance(m, EmailMsg) else m for m in message_ids]

        body = {"ids": message_ids, "addLabelIds": add_labels, "removeLabelIds": remove_labels}
        return self._request("POST", "batchModify", json=body)

    def delete(self, message_id: str | EmailMsg) -> "googleapiclient.http.HttpRequest":
        message_id = message_id.id if isinstance(message_id, EmailMsg) else message_id
        return self._request("DELETE", f"{message_id}")

    def get(self, message_id: str) -> "EmailMsg":
        raw_message = self._request("GET", message_id, params={"alt": "json", "format": "raw"})
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
        resp = self._request("GET", "", params=params, **kwargs)
        all_messages.extend(resp.get("messages", []))

        while "nextPageToken" in resp:
            params["pageToken"] = resp["nextPageToken"]
            resp = self._request("GET", "", params=params, **kwargs)
            all_messages.extend(resp["messages"])

        with ThreadPoolExecutor() as pool:
            parsed_messages = list(pool.map(self.get, (m["id"] for m in all_messages)))

        return parsed_messages

    def modify(self, message_id: str | EmailMsg, add_labels: list[str], remove_labels: list[str]) -> "EmailMsg":
        message_id = message_id.id if isinstance(message_id, EmailMsg) else message_id
        body = {"addLabelIds": add_labels, "removeLabelIds": remove_labels}
        self._request("POST", f"{message_id}/modify", json=body)
        return self.get(message_id)

    def send(self, email: "Message", **kwargs: typing.Any):
        body = {"raw": base64.urlsafe_b64encode(email.as_bytes()).decode("utf-8")}
        return self._request("POST", "send", json=body, **kwargs)

    def trash(self, message_id: str | EmailMsg) -> "EmailMsg":
        message_id = message_id.id if isinstance(message_id, EmailMsg) else message_id
        self._request("POST", f"{message_id}/trash")
        return self.get(message_id)

    def untrash(self, message_id: str | EmailMsg) -> "EmailMsg":
        message_id = message_id.id if isinstance(message_id, EmailMsg) else message_id
        self._request("POST", f"{message_id}/untrash")
        return self.get(message_id)


class Drafts(EndpointApi):
    endpoint: str = "drafts"

    def list_(self, max_results: int = 500, page_token: str | None = None, **kwargs: typing.Any):
        params = {"maxResults": max_results, "pageToken": page_token}
        return self._request("GET", "", params=params, **kwargs)


class Labels(EndpointApi):
    endpoint: str = "labels"

    def list_(self, max_results: int = 500, page_token: str | None = None, **kwargs: typing.Any):
        params = {"maxResults": max_results, "pageToken": page_token}
        return self._request("GET", "", params=params, **kwargs)


class Threads(EndpointApi):
    endpoint: str = "threads"

    def get(self, thread_id: str) -> "EmailMsg":
        raw_thread = self._request("GET", thread_id, params={"alt": "json", "format": "raw"})
        return EmailMsg(raw_thread)

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

        all_threads = []
        resp = self._request("GET", "", params=params, **kwargs)
        all_threads.extend(resp.get("threads", []))

        while "nextPageToken" in resp:
            params["pageToken"] = resp["nextPageToken"]
            resp = self._request("GET", "", params=params, **kwargs)
            all_threads.extend(resp["threads"])

        with ThreadPoolExecutor() as pool:
            parsed_threads = list(pool.map(self.get, (t["id"] for t in all_threads)))

        return parsed_threads


class Users(EndpointApi):
    endpoint: str = "users"

    def get_profile(self) -> dict[str, Any]:
        return self._request("GET", "me/profile")


class Gmail:
    messages: Messages
    drafts: Drafts
    labels: Labels
    threads: Threads
    users: Users

    @classmethod
    def authentication_flow(
        cls,
        cred_file_path: PathLike[str] = DEFAULT_CREDS_FILE_PATH,
        token_save_path: PathLike[str] = DEFAULT_TOKEN_FILE_PATH,
        skip_writing: bool = False,
    ) -> Credentials:
        cred_file_path = Path(cred_file_path)
        flow = InstalledAppFlow.from_client_secrets_file(cred_file_path, SCOPES)
        creds = flow.run_local_server(port=0)

        token_save_path = Path(token_save_path)
        if not skip_writing:
            token_save_path.write_text(creds.to_json())

        return creds

    @classmethod
    def _from_token_file(cls, token_file_path: PathLike[str] = DEFAULT_TOKEN_FILE_PATH) -> "Gmail":
        token_file_path = Path(token_file_path)
        creds = Credentials(**json.loads(token_file_path.read_text()))
        return cls(credentials=creds)

    def __init__(self, credentials: Credentials) -> None:
        self.credentials = credentials
        self.session = httpx.Client(
            headers=JSON_HEADERS, timeout=httpx.Timeout(20.0, connect=60.0), auth=HttpxGmailAuth(credentials)
        )

        atexit.register(self.session.close)

        self.messages = Messages(session=self.session)
        self.drafts = Drafts(session=self.session)
        self.labels = Labels(session=self.session)
        self.threads = Threads(session=self.session)
        self.users = Users(session=self.session)
