from imapclient import IMAPClient
from app.config import IMAP_SERVER, IMAP_PORT, EMAIL_ADDRESS, EMAIL_PASSWORD
def connect_to_mailbox():
    """Connect to the IMAP server and return the mailbox connection."""
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        raise ValueError(
            "EMAIL_ADDRESS and EMAIL_PASSWORD must be set in the .env file."
        )
    client = IMAPClient(IMAP_SERVER, port=IMAP_PORT, ssl=True)
    client.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    return client
def fetch_email(client, uid):
    """Fetch one email in its complete raw RFC822 format."""
    response = client.fetch(uid, ["RFC822"])
    return response[uid][b"RFC822"]
def fetch_unread_emails(client):
    """
    Fetch only one unread email.
    This function is useful for initial/recovery processing.
    """
    client.select_folder("INBOX")
    message_uids = client.search(["UNSEEN"])[:1]
    emails = []
    for uid in message_uids:
        raw_email = fetch_email(client, uid)
        emails.append(
            {
                "uid": uid,
                "raw_email": raw_email,
            }
        )
    return emails
def mark_as_read(client, uid):
    """Mark an email as read after successful processing."""
    client.set_flags(uid, [b"\\Seen"])
def wait_for_new_email(client, timeout=60):
    """
    Wait for Gmail to notify us about mailbox changes.
    Returns:
        List of IMAP responses received while waiting.
    """
    client.idle()
    try:
        return client.idle_check(timeout=timeout)
    finally:
        client.idle_done()
def get_latest_uid(client):
    """Return the highest UID currently present in the INBOX."""
    client.select_folder("INBOX")
    message_uids = client.search(["ALL"])
    if not message_uids:
        return 0
    return message_uids[-1]
