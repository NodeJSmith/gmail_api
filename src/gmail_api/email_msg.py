import base64
import contextlib
import email
import ipaddress
import logging
import quopri
import typing
from collections import defaultdict
from email.message import Message
from email.utils import getaddresses
from os import PathLike
from pathlib import Path

import attrs
from mailparser.const import EPILOGUE_DEFECTS, REGXIP
from mailparser.utils import (
    ADDRESSES_HEADERS,
    convert_mail_date,
    decode_header_part,
    find_between,
    get_header,
    get_mail_keys,
    get_to_domains,
    random_string,
    receiveds_parsing,
)

from gmail_api.utils import decode_string, truncate_text

if typing.TYPE_CHECKING:
    from googleapiclient._apis.gmail.v1 import Message as GmailMessage  # type: ignore

LOGGER = logging.getLogger(__name__)
REPR_TEMPLATE = "EmailMsg(to: {to}, from: {from_}, subject: {subject}, date: {date})"


@attrs.define
class Attachment:
    filename: str
    payload: bytes = attrs.field(repr=False)
    mail_content_type: str
    content_id: str
    content_disposition: str
    charset: str
    content_transfer_encoding: str

    def save_attachment(self, save_path: PathLike[str], file_name: str | None = None) -> Path:
        """Saves an attachment to disk. Will ensure the filename is safe and avoid overwriting existing files by\
        appending (1), (2), etc. to the filename.

        Args:
            save_path (PathLike): The directory to save the attachment to
            file_name (str, optional): The filename to save the attachment as. Defaults to None, which uses the\
                original filename.

        Returns:
            Path: The path to the saved attachment

        """
        save_path = Path(save_path)
        save_path.mkdir(parents=True, exist_ok=True)  # Ensure directory exists

        # Ensure filename is safe (prevents directory traversal)
        safe_filename = Path(file_name or self.filename).name
        base = Path(safe_filename).stem  # Get filename without extension
        ext = Path(safe_filename).suffix  # Get file extension

        file_path = save_path / safe_filename

        # Avoid overwriting files by appending (1), (2), etc.
        counter = 1
        while file_path.exists():
            file_path = save_path / f"{base} ({counter}){ext}"
            counter += 1

        LOGGER.debug(f"Saving attachment to {file_path!r}")
        file_path.write_bytes(self.payload)
        return file_path


class EmailMsg:
    def __init__(self, message: "GmailMessage") -> None:
        """
        Init a new object from a message object structure.
        """
        self.id = message["id"]
        self.snippet = message["snippet"]
        self.thread_id = message["threadId"]
        self.label_ids = message["labelIds"]
        self.size_estimate = message["sizeEstimate"]
        self.history_id = message["historyId"]
        self.internal_date = message["internalDate"]

        self._message = email.message_from_bytes(base64.urlsafe_b64decode(message["raw"]))

        self._attachments: list[Attachment] = []
        self._text_plain: list[str] = []
        self._text_html: list[str] = []
        self._text_not_managed = []
        self._defects: list[dict[str, list[str]]] = []
        self._defects_categories: set[str] = set()
        self._has_defects: bool = False
        self._mail: dict = {}
        self._mail_partial: dict = {}

        self.parse()

    def __repr__(self):
        subject = truncate_text(self.subject, 20)
        to = self.to[0][1] if self.to else ""
        from_ = self.from_[0][1] if self.from_ else ""
        dt = self.date.strftime("%Y-%m-%d %H:%M:%S") if self.date else ""

        return REPR_TEMPLATE.format(to=to, from_=from_, subject=subject, date=dt)

    def _append_defects(self, part: Message, part_content_type: str) -> None:
        """
        Add new defects and defects categories to object attributes.

        The defects are a list of all the problems found
        when parsing this message.

        Args:
            part (string): mail part
            part_content_type (string): content type of part
        """

        part_defects: dict[str, list[str]] = defaultdict(list)

        for e in part.defects:
            defects = f"{e.__class__.__name__}: {e.__doc__}"
            self._defects_categories.add(e.__class__.__name__)
            part_defects[part_content_type].append(defects)
            LOGGER.debug(f"Added defect {defects!r}")

        # Tag mail with defect
        if part_defects:
            self._has_defects = True

            # Save all defects
            self._defects.append(part_defects)

    def _make_mail(self, complete: bool = True) -> dict:
        """
        This method assigns the right values to all tokens of email.
        Returns a parsed object

        Args:
            complete (bool): If True return all keys, else only main keys

        Returns:
            dict -- Parsed object

        """

        mail = {}
        keys = get_mail_keys(self.message, complete)

        for i in keys:
            LOGGER.debug(f"Getting header or part {i!r}")
            mail[i] = self.try_get_header(i)

        # add defects
        mail["has_defects"] = self.has_defects
        if self.has_defects:
            mail["defects"] = self.defects
            mail["defects_categories"] = list(self.defects_categories)

        return mail

    def parse(self):
        """
        This method parses the raw email and makes the tokens.

        Returns:
            Instance of EmailMsg with raw email parsed
        """

        if not self.message:
            return self

        parts: list[Message] = []  # Normal parts plus defects

        # walk all mail parts to search defects
        for p in self.message.walk():
            part_content_type = p.get_content_type()
            self._append_defects(p, part_content_type)
            parts.append(p)

        # If defects are in epilogue defects get epilogue
        if self.defects_categories & EPILOGUE_DEFECTS:
            LOGGER.debug("Found defects in emails")
            epilogue = find_between(
                self.message.epilogue,
                "{}".format("--" + self.message.get_boundary()),
                "{}".format("--" + self.message.get_boundary() + "--"),
            )

            try:
                p = email.message_from_string(epilogue)
                parts.append(p)
            except TypeError:
                LOGGER.debug("Failed to get epilogue part for TypeError")
            except Exception:
                LOGGER.error("Failed to get epilogue part. Check raw mail.")

        # walk all mail parts
        for i, p in enumerate(parts):
            if not p.is_multipart() or decode_string(p.get_content_disposition()).lower() == "attachment":
                charset = p.get_content_charset("utf-8")
                charset_raw = p.get_content_charset()
                content_disposition = decode_string(p.get("content-disposition"))
                content_id = decode_string(p.get("content-id"))
                content_subtype = decode_string(p.get_content_subtype())
                filename = decode_header_part(p.get_filename())

                LOGGER.debug(f"Charset {charset!r} part {i!r}")
                LOGGER.debug(f"content-disposition {content_disposition!r} part {i!r}")
                LOGGER.debug(f"content-id {content_id!r} part {i!r}")
                LOGGER.debug(f"content subtype {content_subtype!r} part {i!r}")

                is_attachment = False
                if filename:
                    is_attachment = True
                else:
                    if content_id and content_subtype not in ("html", "plain"):
                        is_attachment = True
                        filename = content_id
                    elif content_subtype in ("rtf"):
                        is_attachment = True
                        filename = f"{random_string()}.rtf"
                    elif content_disposition == "attachment":
                        is_attachment = True
                        filename = f"{random_string()}.txt"

                # this is an attachment
                if is_attachment:
                    self._parse_attachment(p, i, charset, charset_raw, content_id, filename)

                # this isn't an attachments
                else:
                    self._parse_part(p, i, charset)

        # Parsed object mail with all parts
        self._mail = self._make_mail()

        # Parsed object mail with mains parts
        self._mail_partial = self._make_mail(complete=False)
        return self

    def _parse_part(self, p: Message, i: int, charset: str):
        LOGGER.debug(f"Email part {i!r} is not an attachment")

        # Get the payload using get_payload method with decode=True
        # As Python truly decodes only 'base64',
        # 'quoted-printable', 'x-uuencode',
        # 'uuencode', 'uue', 'x-uue'
        # And for other encodings it breaks the characters so
        # we need to decode them with encoding python is appying
        # To maintain the characters
        payload = p.get_payload(decode=True)
        cte = p.get("Content-Transfer-Encoding")
        if cte:
            cte = cte.lower()

        if not cte or cte in ["7bit", "8bit"]:
            try:
                payload = payload.decode("raw-unicode-escape")
            except UnicodeDecodeError:
                payload = decode_string(payload, encoding=charset)
        else:
            payload = decode_string(payload, encoding=charset)

        if payload:
            content_subtype = p.get_content_subtype()
            if content_subtype == "html":
                self._text_html.append(payload)
            elif content_subtype == "plain" or payload == "----- Message truncated -----\r\n":
                self._text_plain.append(payload)
            else:
                LOGGER.warning(f"Email content {content_subtype!r} not handled")
                self._text_not_managed.append(payload)

    def _parse_attachment(self, p: Message, i: int, charset: str, charset_raw: str, content_id: str, filename: str):
        """Parses and stores an attachment with payload always as bytes."""
        mail_content_type = decode_string(p.get_content_type())
        transfer_encoding = decode_string(p.get("content-transfer-encoding", "")).lower()
        content_disposition = decode_string(p.get("content-disposition"))

        LOGGER.debug(f"Email part {i!r} is an attachment")
        LOGGER.debug(f"Filename {filename!r} part {i!r}")
        LOGGER.debug(f"Mail content type {mail_content_type!r} part {i!r}")
        LOGGER.debug(f"Transfer encoding {transfer_encoding!r} part {i!r}")
        LOGGER.debug(f"content-disposition {content_disposition!r} part {i!r}")

        if p.is_multipart():
            LOGGER.debug(f"Filename {filename!r} part {i!r} is multipart")
            payload = b"".join(m.as_bytes() for m in p.get_payload())
        else:
            raw_payload = p.get_payload(decode=False)  # Still encoded at this point
            if transfer_encoding == "base64":
                payload = base64.b64decode(raw_payload)
            elif transfer_encoding == "quoted-printable":
                payload = quopri.decodestring(raw_payload)
            elif transfer_encoding in ["7bit", "8bit"]:
                payload = raw_payload.encode(charset or "utf-8")
            elif "uuencode" in transfer_encoding:
                payload = base64.b64encode(p.get_payload(decode=True))  # Convert uuencode to base64
            else:
                payload = raw_payload.encode(charset or "utf-8")

        attachment = Attachment(
            filename=filename,
            payload=payload,
            mail_content_type=mail_content_type,
            content_id=content_id,
            content_disposition=content_disposition,
            charset=charset_raw,
            content_transfer_encoding=transfer_encoding,
        )

        self._attachments.append(attachment)

    def get_server_ipaddress(self, trust: str) -> str | None:
        """
        Return the ip address of sender

        Overview:
        Extract a reliable sender IP address heuristically for each message.
        Although the message format dictates a chain of relaying IP
        addresses in each message, a malicious relay can easily alter that.
        Therefore we cannot simply take the first IP in
        the chain. Instead, our method is as follows.
        First we trust the sender IP reported by our mail server in the
        Received headers, and if the previous relay IP address is on our trust
        list (e.g. other well-known mail services), we continue to
        follow the previous Received line, till we reach the first unrecognized
        IP address in the email header.

        From article Characterizing Botnets from Email Spam Records:
            Li Zhuang, J. D. Tygar

        In our case we trust only our mail server with the trust string.

        Args:
            trust (string): String that identify our mail server

        Returns:
            string with the ip address
        """
        LOGGER.debug(f"Trust string is {trust!r}")

        if not trust.strip():
            return None

        received = self.message.get_all("received", [])

        for i in received:
            i = decode_string(i)
            if trust in i:
                LOGGER.debug(f"Trust string {trust!r} is in {i!r}")
                ip_str = self._extract_ip(i)
                if ip_str:
                    return ip_str
        return None

    def _extract_ip(self, received_header: str) -> str | None:
        """
        Extract the IP address from the received header if it is not private.

        Args:
            received_header (string): The received header string

        Returns:
            string with the ip address or None
        """
        check = REGXIP.findall(received_header[0 : received_header.find("by")])
        if check:
            try:
                ip_str = check[-1]
                LOGGER.debug(f"Found sender IP {ip_str!r} in {received_header!r}")
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                return None
            else:
                if not ip.is_private:
                    LOGGER.debug(f"IP {ip_str!r} not private")
                    return ip_str
        return None

    def get_header(self, name: str) -> str:
        """
        Get the value of a header

        Arguments:
            name {string} -- Header name

        Returns:
            string -- Header value
        """
        return get_header(self.message, name)

    @property
    def bcc(self):
        """
        Return the bcc email addresses
        """
        return getaddresses([decode_header_part(self.message.get("bcc", ""))])

    @property
    def cc(self):
        """
        Return the cc email addresses
        """
        return getaddresses([decode_header_part(self.message.get("cc", ""))])

    @property
    def delivered_to(self):
        """
        Return the delivered-to email addresses
        """
        return getaddresses([decode_header_part(self.message.get("delivered-to", ""))])

    @property
    def from_(self):
        """
        Return the from email addresses
        """
        return getaddresses([decode_header_part(self.message.get("from", ""))])

    @property
    def reply_to(self):
        """
        Return the reply-to email addresses
        """
        return getaddresses([decode_header_part(self.message.get("reply-to", ""))])

    @property
    def to(self):
        """
        Return the to email addresses
        """
        return getaddresses([decode_header_part(self.message.get("to", ""))])

    @property
    def attachments(self):
        """
        Return a list of all attachments in the mail
        """
        return self._attachments

    @property
    def received(self):
        """
        Return a list of all received headers parsed
        """
        output = self.received_raw
        return receiveds_parsing(output)

    @property
    def received_raw(self):
        """
        Return a list of all received headers in raw format
        """
        output = []
        for i in self.message.get_all("received", []):
            output.append(decode_header_part(i))
        return output

    @property
    def subject(self):
        """
        Return the mail subject
        """
        return decode_header_part(self.message.get("subject", "")).strip()

    @property
    def body(self):
        """
        Return all text plain and text html parts of mail delimited from string
        "--- mail_boundary ---"
        """
        return "\n--- mail_boundary ---\n".join(self.text_plain + self.text_html + self.text_not_managed)

    @property
    def headers(self):
        """
        Return only the headers as Python object
        """
        return {header: self.try_get_header(header) for header in self.message}

    @property
    def text_plain(self):
        """
        Return a list of all text plain parts of email.
        """
        return self._text_plain

    @property
    def text_html(self):
        """
        Return a list of all text html parts of email.
        """
        return self._text_html

    @property
    def text_not_managed(self):
        """
        Return a list of all text not managed of email.
        """
        return self._text_not_managed

    @property
    def date(self):
        """
        Return the mail date in datetime.datetime format and UTC.
        """
        date = self.message.get("date")
        conv = None

        with contextlib.suppress(Exception):
            conv, _ = convert_mail_date(date)
        return conv

    @property
    def timezone(self):
        """
        Return timezone. Offset from UTC.
        """
        date = self.message.get("date")
        timezone = 0

        with contextlib.suppress(Exception):
            _, timezone = convert_mail_date(date)
        return timezone

    @property
    def mail(self):
        """
        Return the Python object of mail parsed
        """
        return self._mail

    @property
    def mail_partial(self):
        """
        Return the Python object of mail parsed
        with only the mains headers
        """
        return self._mail_partial

    @property
    def defects(self):
        """
        The defects property contains a list of
        all the problems found when parsing this message.
        """
        return self._defects

    @property
    def defects_categories(self):
        """
        Return a set with only defects categories.
        """
        return self._defects_categories

    @property
    def has_defects(self):
        """
        Return a boolean: True if mail has defects.
        """
        return self._has_defects

    @property
    def message(self):
        """
        email.message.Message class.
        """
        return self._message

    @property
    def to_domains(self):
        """
        Return all domain of 'to' and 'reply-to' email addresses
        """
        return get_to_domains(self.to, self.reply_to)

    @property
    def message_id(self):
        """
        Return the message-id of mail
        """
        return self.message.get("message-id")

    @property
    def user_agent(self):
        """
        Return the user-agent of mail
        """
        return get_header(self.message, "user-agent")

    @property
    def x_mailer(self):
        """
        Return the x-mailer of mail
        """
        return get_header(self.message, "x-mailer")

    @property
    def x_original_to(self):
        """
        Return the x-original-to of mail
        """
        return get_header(self.message, "x-original-to")

    def try_get_header(self, name: str):
        name = name.strip("_").lower()
        name_header = name.replace("_", "-")

        if hasattr(self, name):
            return getattr(self, name)

        # object headers
        if name_header in ADDRESSES_HEADERS:
            h = decode_header_part(self.message.get(name_header, ""))
            return getaddresses([h])

        # others headers
        return get_header(self.message, name_header) or ""
