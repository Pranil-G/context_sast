from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from context_sast.models import Finding
from context_sast.reports.evidence import EvidenceResolver


class EvidenceResolverTests(unittest.TestCase):
    def test_resolves_manifest_and_java_snippets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_root = Path(temp_dir)
            source_dir = artifact_root / "sources" / "com" / "example"
            resource_dir = artifact_root / "resources"
            source_dir.mkdir(parents=True)
            resource_dir.mkdir(parents=True)

            (source_dir / "DemoActivity.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import android.app.Activity;",
                        "import android.content.Intent;",
                        "import android.os.Bundle;",
                        "",
                        "public class DemoActivity extends Activity {",
                        "    @Override",
                        "    protected void onCreate(Bundle savedInstanceState) {",
                        "        super.onCreate(savedInstanceState);",
                        "        Intent nested = (Intent) getIntent().getParcelableExtra(\"intent\");",
                        "        if (nested == null) {",
                        "            return;",
                        "        }",
                        "        startActivity(nested);",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (resource_dir / "AndroidManifest.xml").write_text(
                "\n".join(
                    [
                        "<manifest package=\"com.example\">",
                        "    <application>",
                        "        <activity",
                        "            android:name=\"com.example.DemoActivity\"",
                        "            android:exported=\"true\">",
                        "            <intent-filter>",
                        "                <action android:name=\"android.intent.action.VIEW\" />",
                        "                <category android:name=\"android.intent.category.BROWSABLE\" />",
                        "            </intent-filter>",
                        "        </activity>",
                        "    </application>",
                        "</manifest>",
                    ]
                ),
                encoding="utf-8",
            )

            finding = Finding(
                title="Intent Redirection in DemoActivity",
                severity="HIGH",
                confidence="HIGH",
                owasp_category="M4: Insufficient Input/Output Validation",
                affected_component="com.example.DemoActivity",
                evidence="External input reaches startActivity.",
                source_to_sink=(
                    'AndroidManifest.xml: <activity name="com.example.DemoActivity" exported=true>',
                    "com.example.DemoActivity.onCreate: getParcelableExtra(intent)",
                    "com.example.DemoActivity.onCreate: startActivity()",
                ),
                remediation="Validate nested intents.",
                detector="intent_redirection",
                extras={
                    'manifest_entry': 'AndroidManifest.xml: <activity name="com.example.DemoActivity" exported=true>',
                },
            )

            with EvidenceResolver("demo.apk", artifact_root=artifact_root) as resolver:
                blocks = resolver.resolve_finding(finding)

        self.assertEqual(blocks[0]["file"], "AndroidManifest.xml")
        manifest_snippet = "\n".join(line["text"] for line in blocks[0]["lines"])
        self.assertIn("<activity", manifest_snippet)
        self.assertIn('android:name="com.example.DemoActivity"', manifest_snippet)
        self.assertIn("</activity>", manifest_snippet)

        java_block = blocks[-1]
        self.assertEqual(java_block["file"], "com/example/DemoActivity.java")
        self.assertEqual(java_block["highlight_line"], 15)
        java_snippet = "\n".join(line["text"] for line in java_block["lines"])
        self.assertIn('getParcelableExtra("intent")', java_snippet)
        self.assertIn("startActivity(nested);", java_snippet)


if __name__ == "__main__":
    unittest.main()
