from __future__ import annotations

from context_sast.apk_loader import ApkLoader
from context_sast.correlator import Correlator
from context_sast.dataflow_engine import DataflowEngine
from context_sast.dex_analyzer import DexAnalyzer
from context_sast.manifest_analyzer import ManifestAnalyzer
from context_sast.models import CallerExposureContext, CorrelatedComponentContext, ScanResult
from context_sast.rule_engine import RuleEngine


class ContextAwareSASTEngine:
    def __init__(self, max_depth: int = 4) -> None:
        self.apk_loader = ApkLoader()
        self.dex_analyzer = DexAnalyzer()
        self.manifest_analyzer = ManifestAnalyzer()
        self.dataflow_engine = DataflowEngine(max_depth=max_depth)
        self.correlator = Correlator()
        self.rule_engine = RuleEngine()

    def scan(self, apk_path: str) -> ScanResult:
        loaded = self.apk_loader.load(apk_path)
        dex_result = self.dex_analyzer.analyze(str(loaded.path))
        manifest_result = self.manifest_analyzer.analyze(dex_result.apk)
        code_analyses = self.dataflow_engine.analyze_components(manifest_result, dex_result)
        contexts = self.correlator.correlate(manifest_result, code_analyses)
        contexts = (*contexts, *self._webview_callback_contexts(dex_result))
        findings = self.rule_engine.run(contexts)

        # Every read above went back to the same path; confirm it still holds
        # the binary that was fingerprinted before attributing findings to it.
        self.apk_loader.verify_unchanged(loaded)

        return ScanResult(
            apk_path=str(loaded.path),
            package_name=manifest_result.package_name,
            findings=findings,
            sha256=loaded.sha256,
            size_bytes=loaded.size_bytes,
        )

    def _webview_callback_contexts(self, dex_result) -> tuple[CorrelatedComponentContext, ...]:
        """Contexts for WebViewClient callback hosts.

        These are reachable through the loaded page rather than through a
        component launch, so they carry their own exposure reason instead of a
        manifest entry.
        """
        analyses = self.dataflow_engine.analyze_webview_callbacks(dex_result)
        return tuple(
            CorrelatedComponentContext(
                component=analysis.component,
                code_analysis=analysis,
                caller_exposure=CallerExposureContext(
                    True,
                    "reachable through content loaded in the WebView",
                    manifest_entry=f"WebViewClient callback host: {analysis.component.name}",
                ),
            )
            for analysis in analyses.values()
        )
