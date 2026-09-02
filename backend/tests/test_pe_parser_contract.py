from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.pe_parser import parse_pe


class PEParserContractTests(unittest.TestCase):
    def test_named_resource_types_are_json_serializable(self):
        sample = Path(__file__).resolve().parents[2] / "samples" / "revlab_sample.exe"
        result = parse_pe(sample.read_bytes(), str(sample))
        json.dumps(result, ensure_ascii=False)
        resource_types = [item["type"] for item in result.get("resources", {}).get("tree", [])]
        self.assertTrue(all(isinstance(value, (str, int)) for value in resource_types))


if __name__ == "__main__":
    unittest.main()
