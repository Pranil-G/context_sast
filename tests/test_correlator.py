from __future__ import annotations

import unittest

from context_sast.correlator.engine import Correlator
from context_sast.models import ComponentInfo, ManifestAnalysis, ManifestPermission


def _manifest(component: ComponentInfo, permissions: dict[str, ManifestPermission] | None = None) -> ManifestAnalysis:
    return ManifestAnalysis(
        package_name="com.example",
        min_sdk=None,
        target_sdk=None,
        permissions=permissions or {},
        components=(component,),
    )


class CorrelatorExposureTests(unittest.TestCase):
    def test_normal_permission_does_not_block_zero_permission_reachability(self) -> None:
        # A "normal" protection-level permission is auto-granted to any app that
        # declares it, with no user prompt. Treating it as blocking would hide
        # real vulnerabilities behind a permission that stops nobody.
        component = ComponentInfo(
            name="Lcom/example/SyncReceiver;",
            kind="receiver",
            exported=True,
            implicitly_exported=False,
            permission="com.example.perm.NORMAL_ACCESS",
        )
        manifest = _manifest(
            component,
            permissions={
                "com.example.perm.NORMAL_ACCESS": ManifestPermission(
                    name="com.example.perm.NORMAL_ACCESS", protection_level="normal"
                )
            },
        )

        contexts = Correlator().correlate(manifest, {})

        self.assertEqual(len(contexts), 1)
        self.assertTrue(contexts[0].caller_exposure.zero_permission_reachable)

    def test_dangerous_permission_blocks_zero_permission_reachability(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/SyncReceiver;",
            kind="receiver",
            exported=True,
            implicitly_exported=False,
            permission="com.example.perm.DANGEROUS_ACCESS",
        )
        manifest = _manifest(
            component,
            permissions={
                "com.example.perm.DANGEROUS_ACCESS": ManifestPermission(
                    name="com.example.perm.DANGEROUS_ACCESS", protection_level="dangerous"
                )
            },
        )

        contexts = Correlator().correlate(manifest, {})

        self.assertEqual(len(contexts), 1)
        self.assertFalse(contexts[0].caller_exposure.zero_permission_reachable)

    def test_signature_permission_blocks_zero_permission_reachability(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/SyncReceiver;",
            kind="receiver",
            exported=True,
            implicitly_exported=False,
            permission="com.example.perm.SIGNATURE_ACCESS",
        )
        manifest = _manifest(
            component,
            permissions={
                "com.example.perm.SIGNATURE_ACCESS": ManifestPermission(
                    name="com.example.perm.SIGNATURE_ACCESS", protection_level="signature"
                )
            },
        )

        contexts = Correlator().correlate(manifest, {})

        self.assertEqual(len(contexts), 1)
        self.assertFalse(contexts[0].caller_exposure.zero_permission_reachable)

    def test_privileged_permission_blocks_zero_permission_reachability(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/SyncReceiver;",
            kind="receiver",
            exported=True,
            implicitly_exported=False,
            permission="com.example.perm.PRIVILEGED_ACCESS",
        )
        manifest = _manifest(
            component,
            permissions={
                "com.example.perm.PRIVILEGED_ACCESS": ManifestPermission(
                    name="com.example.perm.PRIVILEGED_ACCESS", protection_level="signature|privileged"
                )
            },
        )

        contexts = Correlator().correlate(manifest, {})

        self.assertEqual(len(contexts), 1)
        self.assertFalse(contexts[0].caller_exposure.zero_permission_reachable)
        self.assertEqual(contexts[0].caller_exposure.permission_level, "signature")

    def test_unknown_permission_is_reported_as_blocking_uncertainty(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/SyncReceiver;",
            kind="receiver",
            exported=True,
            implicitly_exported=False,
            permission="com.example.perm.UNDECLARED_ACCESS",
        )

        contexts = Correlator().correlate(_manifest(component), {})

        self.assertEqual(len(contexts), 1)
        self.assertFalse(contexts[0].caller_exposure.zero_permission_reachable)
        self.assertEqual(contexts[0].caller_exposure.permission_level, "unknown")


if __name__ == "__main__":
    unittest.main()
