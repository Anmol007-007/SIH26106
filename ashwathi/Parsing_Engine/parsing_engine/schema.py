from pydantic import BaseModel
from typing import Optional
class AuthResults(BaseModel):
    raw: str = ""
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
class UrlInfo(BaseModel):
    url: str
    domain: str
    anchor_text: Optional[str] = None
class Attachment(BaseModel):
    filename: Optional[str] = None
    content_type: str
    size: int
    sha256: Optional[str] = None
class ParsedEmail(BaseModel):
    schema_version: str = "1.0"
    message_id: str
    from_addr: list[tuple[str, str]] = []
    reply_to: list[tuple[str, str]] = []
    return_path: Optional[str] = None
    subject: str = ""
    date: Optional[str] = None
    auth_results: AuthResults
    received_chain: list[str] = []
    body_plain: str = ""
    body_html: str = ""
    urls: list[UrlInfo] = []
    attachments: list[Attachment] = []
