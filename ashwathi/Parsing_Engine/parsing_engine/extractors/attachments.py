import hashlib
from parsing_engine.schema import Attachment
def extract_attachments(msg) -> list[Attachment]:
    attachments = []
    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True) or b""
        attachments.append(Attachment(
            filename=part.get_filename(),
            content_type=part.get_content_type(),
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest() if payload else None,
        ))
    return attachments
