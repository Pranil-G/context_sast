from __future__ import annotations

from context_sast.detectors import (
    ArbitraryClassLoadingDetector,
    DeepLinkAbuseDetector,
    InsecureContentProviderDetector,
    IntentRedirectionDetector,
    WebViewCallbackDetector,
    WebViewMisconfigurationDetector,
)
from context_sast.models import CorrelatedComponentContext, Finding


class RuleEngine:
    def __init__(self) -> None:
        self.detectors = (
            IntentRedirectionDetector(),
            WebViewMisconfigurationDetector(),
            WebViewCallbackDetector(),
            DeepLinkAbuseDetector(),
            InsecureContentProviderDetector(),
            ArbitraryClassLoadingDetector(),
        )

    def run(self, contexts: tuple[CorrelatedComponentContext, ...]) -> tuple[Finding, ...]:
        findings = []
        for detector in self.detectors:
            findings.extend(detector.detect(contexts))
        return tuple(findings)
