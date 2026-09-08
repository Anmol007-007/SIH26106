import json
from pathlib import Path
from parsing_engine.parser import parse_eml, EmailParseError
def process_incoming_eml(file_path: str, message_id: str) -> dict:
    try:
        parsed = parse_eml(file_path)
        return {"status": "success", "data": parsed.model_dump()}
    except EmailParseError as e:
        return {"status": "failed", "error": str(e), "message_id": message_id}
if __name__ == "__main__":
    result = process_incoming_eml("storage.eml", "test-message-id")
    output_path = Path(__file__).resolve().parent / "sample_parsed.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
