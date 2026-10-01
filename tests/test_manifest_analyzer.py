from __future__ import annotations

import unittest
from xml.etree import ElementTree as ET

from context_sast.manifest_analyzer import ManifestAnalyzer


ANDROID_NS = "http://schemas.android.com/apk/res/android"


class FakeApk:
    def __init__(self, target_sdk: str | None, exported: str | None = None) -> None:
        exported_attr = "" if exported is None else f' android:exported="{exported}"'
        self.xml = ET.fromstring(
            f'<manifest xmlns:android="{ANDROID_NS}" package="com.example">'
            f'<application><provider android:name=".DemoProvider"{exported_attr} '
            'android:authorities="com.example.demo"/></application></manifest>'
        )
        self.target_sdk = target_sdk

    def get_android_manifest_xml(self):
        return self.xml

    def get_package(self):
        return "com.example"

    def get_min_sdk_version(self):
        return "1"

    def get_target_sdk_version(self):
        return self.target_sdk


class ManifestAnalyzerTests(unittest.TestCase):
    def test_provider_defaults_exported_for_target_16(self) -> None:
        component = ManifestAnalyzer().analyze(FakeApk("16")).components[0]
        self.assertTrue(component.exported)
        self.assertTrue(component.implicitly_exported)

    def test_provider_defaults_unexported_for_target_17(self) -> None:
        component = ManifestAnalyzer().analyze(FakeApk("17")).components[0]
        self.assertFalse(component.exported)
        self.assertFalse(component.implicitly_exported)

    def test_provider_missing_target_uses_legacy_default(self) -> None:
        component = ManifestAnalyzer().analyze(FakeApk(None)).components[0]
        self.assertTrue(component.exported)

    def test_provider_explicit_exported_overrides_target_default(self) -> None:
        self.assertFalse(ManifestAnalyzer().analyze(FakeApk("16", "false")).components[0].exported)
        self.assertTrue(ManifestAnalyzer().analyze(FakeApk("35", "true")).components[0].exported)


if __name__ == "__main__":
    unittest.main()
