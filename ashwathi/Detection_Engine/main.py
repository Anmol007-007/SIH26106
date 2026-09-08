import sys
import os
import json
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent / "Parsing_Engine"))
from parsing_engine.schema import ParsedEmail
from detector import run_detection
def load_test_input(path: str) -> ParsedEmail:
    with open(path, "r", encoding="utf-8") as f:
        result = json.load(f)
    return ParsedEmail(**result["data"])
if __name__ == "__main__":
    json_path = Path(__file__).resolve().parent.parent / "Parsing_Engine" / "sample_parsed.json"
    parsed = load_test_input(json_path)
    detection_result = run_detection(parsed)
    output_path = Path(__file__).resolve().parent / "sample_detected.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(detection_result, f, indent=2)
