import sqlite3
from app.config import DATABASE_PATH
def get_connection():
    """Create and return a connection to the SQLite database."""
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection
def initialize_database():
    """Create the emails table if it doesn't already exist."""
    connection = get_connection()
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id TEXT UNIQUE NOT NULL,
                message_id TEXT,
                sender TEXT,
                recipient TEXT,
                subject TEXT,
                received_at TEXT,
                raw_file TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'stored',
                created_at TEXT NOT NULL
            )
            """
        )
        connection.commit()
    finally:
        connection.close()
