from pathlib import Path
def save_raw_email(raw_email: bytes, email_id: str, storage_dir: Path) -> Path:
    """
    Save the original raw email as an .eml file.
    Args:
        raw_email: Complete raw email content in bytes.
        email_id: Unique identifier for the email.
        storage_dir: Directory where raw emails should be stored.
    Returns:
        Path of the saved .eml file.
    """
    storage_dir.mkdir(parents=True, exist_ok=True)
    file_path = storage_dir / f"{email_id}.eml"
    with open(file_path, "wb") as file:
        file.write(raw_email)
    return file_path
