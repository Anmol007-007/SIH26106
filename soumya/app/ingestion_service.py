import hashlib
import time
import traceback
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from app.config import STORAGE_DIR
from app.database import get_connection, initialize_database
from app.imap_client import (
    connect_to_mailbox,
    fetch_email,
    get_latest_uid,
    mark_as_read,
    wait_for_new_email,
)
from app.raw_store import save_raw_email
def generate_email_id(raw_email: bytes) -> str:
    """Generate a deterministic ID from the raw email content."""
    return hashlib.sha256(raw_email).hexdigest()
def extract_metadata(raw_email: bytes) -> dict:
    """Extract basic metadata from the original email."""
    message = BytesParser(
        policy=policy.default
    ).parsebytes(raw_email)
    return {
        "message_id": message.get("Message-ID"),
        "sender": message.get("From"),
        "recipient": message.get("To"),
        "subject": message.get("Subject"),
        "received_at": message.get("Date"),
    }
def store_metadata(
    email_id: str,
    metadata: dict,
    raw_file: str,
):
    """Store email metadata in SQLite."""
    connection = get_connection()
    try:
        connection.execute(
            """
            INSERT OR IGNORE INTO emails (
                email_id,
                message_id,
                sender,
                recipient,
                subject,
                received_at,
                raw_file,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                email_id,
                metadata["message_id"],
                metadata["sender"],
                metadata["recipient"],
                metadata["subject"],
                metadata["received_at"],
                raw_file,
                "stored",
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        connection.commit()
    finally:
        connection.close()
def process_email(client, uid: int) -> bool:
    """
    Fetch, store and mark one email as processed.
    The email is marked as read only after successful
    raw-file and database storage.
    """
    try:
        raw_email = fetch_email(client, uid)
        if not raw_email:
            raise ValueError(f"Empty email received for UID {uid}")
        email_id = generate_email_id(raw_email)
        metadata = extract_metadata(raw_email)
        raw_file = save_raw_email(
            raw_email=raw_email,
            email_id=email_id,
            storage_dir=STORAGE_DIR,
        )
        store_metadata(
            email_id=email_id,
            metadata=metadata,
            raw_file=str(raw_file),
        )
        mark_as_read(client, uid)
        print(f"Stored email: {email_id}")
        print(f"Subject: {metadata['subject']}")
        print(f"Raw file: {raw_file}")
        print("Marked as read.")
        print("-" * 60)
        return True
    except Exception as error:
        print(f"Failed to process email UID {uid}: {error}")
        traceback.print_exc()
        return False
def monitor_mailbox():
    """Continuously monitor the inbox for new emails."""
    initialize_database()
    client = connect_to_mailbox()
    client.select_folder("INBOX")
    last_seen_uid = get_latest_uid(client)
    print("Connected to Gmail.")
    print(f"Last seen UID: {last_seen_uid}")
    print("Waiting for new emails...")
    print("Press Ctrl+C to stop.")
    print("-" * 60)
    try:
        while True:
            try:
                responses = wait_for_new_email(
                    client,
                    timeout=60,
                )
            except Exception as error:
                print(f"IMAP monitoring error: {error}")
                print("Retrying connection in 5 seconds...")
                time.sleep(5)
                try:
                    client.logout()
                except Exception:
                    pass
                client = connect_to_mailbox()
                client.select_folder("INBOX")
                print("Reconnected to Gmail.")
                print("-" * 60)
                continue
            for response in responses:
                if not isinstance(response, tuple):
                    continue
                message_count, event = response
                if event != b"EXISTS":
                    continue
                print("Mailbox changed. Checking for new emails...")
                try:
                    client.select_folder("INBOX")
                    message_uids = client.search(["ALL"])
                    new_uids = [
                        uid for uid in message_uids
                        if uid > last_seen_uid
                    ]
                    if not message_uids:
                        print("No message UID found.")
                        continue
                    for uid in new_uids:
                        print(f"New email UID detected: {uid}")
                        success = process_email(client, uid)
                        if success:
                         last_seen_uid = max(last_seen_uid, uid)
                except Exception as error:
                   print(f"Error while handling new email: {error}")
                   traceback.print_exc()
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping mail ingestion service...")
    finally:
        try:
            client.logout()
        except Exception:
            pass
        print("Disconnected from Gmail.")
if __name__ == "__main__":
    monitor_mailbox()
