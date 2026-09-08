from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from parsing_engine.schema import ParsedEmail
from parsing_engine.extractors.auth import parse_auth_results
from parsing_engine.extractors.urls import extract_urls
from parsing_engine.extractors.attachments import extract_attachments
class EmailParseError(Exception):
    """Raised when a .eml file is malformed beyond recovery."""
    pass
def parse_eml(file_path: str) -> ParsedEmail:
    try:
        with open(file_path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except Exception as e:
        raise EmailParseError(f"Failed to parse {file_path}: {e}")
    from_addr = getaddresses(msg.get_all("From", []))
    reply_to = getaddresses(msg.get_all("Reply-To", []))
    return_path_header = msg.get("Return-Path")
    return_path = return_path_header.strip("<>") if return_path_header else None
    auth_results = parse_auth_results(msg.get_all("Authentication-Results", []))
    received_chain = msg.get_all("Received", []) or []
    body_plain, body_html = _extract_body(msg)
    urls = extract_urls(body_plain, body_html)
    attachments = extract_attachments(msg)
    return ParsedEmail(
        message_id=msg.get("Message-ID", "") or "",
        from_addr=from_addr,
        reply_to=reply_to,
        return_path=return_path,
        subject=msg.get("Subject", "") or "",
        date=msg.get("Date"),
        auth_results=auth_results,
        received_chain=received_chain,
        body_plain=body_plain,
        body_html=body_html,
        urls=urls,
        attachments=attachments,
    )
def _extract_body(msg) -> tuple[str, str]:
    body_plain, body_html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_attachment():
                continue
            ctype = part.get_content_type()
            try:
                content = part.get_content()
            except Exception:
                continue                                                     
            if ctype == "text/plain":
                body_plain += content
            elif ctype == "text/html":
                body_html += content
    else:
        try:
            content = msg.get_content()
        except Exception:
            content = ""
        if msg.get_content_type() == "text/plain":
            body_plain = content
        else:
            body_html = content
    return body_plain, body_html
