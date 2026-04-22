import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
TESTS_ROOT = os.path.dirname(os.path.abspath(__file__))
if TESTS_ROOT not in sys.path:
    sys.path.insert(0, TESTS_ROOT)

from smart_unpacker.app.cli import main
from synthetic_samples import create_cli_smoke_dataset, temporary_generated_dir


class GeneratedSamplesSmokeTest(unittest.TestCase):
    def test_cli_inspect_json_on_generated_dataset(self):
        with temporary_generated_dir("generated-cli-smoke-") as temp_dir:
            dataset_dir = Path(temp_dir)
            create_cli_smoke_dataset(dataset_dir)

            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = main(["inspect", str(dataset_dir), "--json"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(buffer.getvalue())
            items_by_name = {Path(item["path"]).name: item for item in payload["items"]}

            self.assertIn("fakepicture.jpg", items_by_name)
            self.assertEqual(items_by_name["fakepicture.jpg"]["decision"], "archive")
            self.assertTrue(items_by_name["fakepicture.jpg"]["should_extract"])

            self.assertIn("rpgmakertest.7z", items_by_name)
            self.assertEqual(items_by_name["rpgmakertest.7z"]["decision"], "archive")
            self.assertTrue(items_by_name["rpgmakertest.7z"]["should_extract"])


if __name__ == "__main__":
    unittest.main()
