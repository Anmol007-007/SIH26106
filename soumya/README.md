Mail Ingestion Module

Automatically monitors a Gmail inbox using IMAP IDLE,
fetches new emails in raw RFC822 format, stores the original
email as .eml, extracts basic metadata into SQLite, and marks
successfully processed emails as read.

Run:
python -m app.ingestion_service

Required environment variables:
IMAP_SERVER
IMAP_PORT
EMAIL_ADDRESS
EMAIL_PASSWORD