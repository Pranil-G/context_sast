from __future__ import annotations

from context_sast.helpers import java_name_from_descriptor
from context_sast.models import CorrelatedComponentContext, Finding

from .base import BaseDetector
from .common import finding_context_extras, sink_context_extras, sink_has_exact_url_policy


class WebViewCallbackDetector(BaseDetector):
    """Web-controlled callback data loaded back into the WebView.

    The attacker channel is the page already loaded, not an Android component
    launch, so this rule does not require the hosting component to be exported.
    A finding is suppressed only by an exact scheme and host policy; a suffix or
    substring test is recorded as bypassable and lowers confidence instead.
    """

    detector_id = "webview_callback"

    def detect(self, contexts: tuple[CorrelatedComponentContext, ...]) -> tuple[Finding, ...]:
        findings = []
        for context in contexts:
            if context.component.kind != "webview-client":
                continue
            analysis = context.code_analysis
            if analysis is None:
                continue

            sinks = [event for event in analysis.sink_events if event.kind == "webview_callback_sink"]
            actionable = [
                sink for sink in sinks
                if not sink_has_exact_url_policy(sink)
            ]
            if not actionable:
                continue

            primary = actionable[0]
            flawed = any(
                "flawed_url_validation" in provenance.validations
                for provenance in primary.provenances
            )

            # A callback that hands the URL straight back to loadUrl only repeats
            # the navigation the WebView would have performed anyway, so on its
            # own it is not an escalation. The report needs either a gate the app
            # attempted and got wrong, or a setting that makes the load dangerous.
            risk_flags = analysis.flags & {
                "webview_js_enabled",
                "webview_allow_file_access",
                "webview_file_url_access",
                "webview_universal_file_access",
                "webview_js_interface",
            }
            if not risk_flags and not flawed:
                continue
            host_class = java_name_from_descriptor(context.component.name)
            findings.append(
                Finding(
                    title=f"WebView Callback Loading in {host_class.split('.')[-1]}",
                    severity="HIGH" if risk_flags else "MEDIUM",
                    confidence="MEDIUM" if flawed or analysis.path_sensitive_validations else "HIGH",
                    owasp_category=(
                        "M8: Security Misconfiguration"
                        if risk_flags
                        else "M4: Insufficient Input/Output Validation"
                    ),
                    affected_component=host_class,
                    evidence=(
                        f"{host_class} receives a URL or request from the loaded page in a "
                        f"WebViewClient callback and passes it back into WebView content loading "
                        f"without an exact scheme and host policy."
                        + (" A URL check exists but appears bypassable." if flawed else "")
                    ),
                    source_to_sink=(
                        f"WebViewClient callback host: {host_class}",
                        *(primary.provenances[0].trace if primary.provenances else ()),
                    ),
                    remediation=(
                        "Compare the normalized scheme and host against an exact allowlist before "
                        "loading a URL supplied by page content, and reject everything else."
                    ),
                    detector=self.detector_id,
                    extras={**finding_context_extras(context), **sink_context_extras(primary)},
                )
            )
        return tuple(findings)
