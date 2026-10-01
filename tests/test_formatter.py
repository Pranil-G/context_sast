from __future__ import annotations

import json
import unittest

from context_sast.models import Finding, ScanResult
from context_sast.reports.formatter import results_to_json


class FormatterTests(unittest.TestCase):
    def test_results_to_json_excludes_evidence_blocks_by_default(self) -> None:
        result = ScanResult(
            apk_path="demo.apk",
            package_name="com.example.demo",
            findings=(
                Finding(
                    title="Intent Redirection in DemoActivity",
                    severity="HIGH",
                    confidence="HIGH",
                    owasp_category="M4: Insufficient Input/Output Validation",
                    affected_component="com.example.DemoActivity",
                    evidence="External input reaches startActivity.",
                    source_to_sink=("AndroidManifest.xml: <activity name=\"com.example.DemoActivity\" exported=true>",),
                    remediation="Validate nested intents.",
                    detector="intent_redirection",
                ),
            ),
            sha256="a" * 64,
            size_bytes=1234,
        )

        payload = json.loads(results_to_json((result,)))

        finding = payload["results"][0]["findings"][0]
        self.assertNotIn("evidence_blocks", finding)
        self.assertEqual(payload["results"][0]["sha256"], "a" * 64)
        self.assertEqual(payload["results"][0]["size_bytes"], 1234)
        self.assertIn("generated_at_utc", payload["scan_metadata"])
        self.assertIn("analyzer_version", payload["scan_metadata"])
        self.assertIn("max_call_depth", payload["scan_metadata"])
        self.assertIn("androguard_version", payload["scan_metadata"])


if __name__ == "__main__":
    unittest.main()
