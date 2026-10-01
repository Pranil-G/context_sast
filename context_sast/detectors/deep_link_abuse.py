from __future__ import annotations

from context_sast.helpers import java_name_from_descriptor
from context_sast.models import CorrelatedComponentContext, Finding

from .base import BaseDetector
from .common import (
    browsable_filter_constraints,
    browsable_filter_precision,
    finding_context_extras,
    manifest_prefixed_trace,
    sink_context_extras,
    sink_has_any_validation,
    sink_has_exact_url_policy,
    sink_has_tag,
)


class DeepLinkAbuseDetector(BaseDetector):
    detector_id = "deep_link_abuse"

    def detect(self, contexts: tuple[CorrelatedComponentContext, ...]) -> tuple[Finding, ...]:
        findings = []
        for context in contexts:
            component = context.component
            analysis = context.code_analysis
            if analysis is None or component.kind not in {"activity", "activity-alias"}:
                continue
            if not context.caller_exposure.zero_permission_reachable:
                continue
            if not _is_browsable(component):
                continue

            sinks = [
                sink
                for sink in analysis.sink_events
                if sink_has_tag(
                    sink,
                    {
                        "external_uri",
                        "url_host",
                        "provider_path",
                        "intent_route_component",
                        "intent_route_package",
                        "intent_route_action",
                        "intent_route_data",
                        "intent_route_category",
                    },
                )
                and sink.kind in {"webview_load_sink", "intent_redirection_sink", "intent_launch_sink", "class_loading_sink"}
                and not sink_has_exact_url_policy(sink)
                and not sink_has_any_validation(sink, {"component_lock_validation"})
                and not _is_safe_callback_relay(sink)
            ]
            if not sinks:
                continue

            primary = sinks[0]
            severity = "HIGH" if primary.kind != "webview_load_sink" else "MEDIUM"
            flawed_check = any(
                not {"flawed_url_validation", "package_scope_validation"}.isdisjoint(provenance.validations)
                for provenance in primary.provenances
            )
            flaw_text = " A URL check exists but appears bypassable." if flawed_check else ""
            control_reason = _exploitability_reason(primary)
            filter_reason = _filter_reason(component)
            findings.append(
                Finding(
                    title=f"Browsable Deep Link Abuse in {java_name_from_descriptor(component.name).split('.')[-1]}",
                    severity=severity,
                    confidence="MEDIUM" if flawed_check else "HIGH",
                    owasp_category="M4: Insufficient Input/Output Validation",
                    affected_component=java_name_from_descriptor(component.name),
                    evidence=(
                        f"A browsable exported activity accepts external deep link data and {control_reason} without a strong allowlist. "
                        f"Manifest constraints: {filter_reason}.{flaw_text}"
                    ),
                    source_to_sink=manifest_prefixed_trace(context, primary),
                    remediation=(
                        "Restrict deep link hosts and schemes with exact validation before using link data in navigation, implicit intents, or WebView flows."
                    ),
                    detector=self.detector_id,
                    extras={**finding_context_extras(context), **sink_context_extras(primary)},
                )
            )
        return tuple(findings)


def _is_browsable(component) -> bool:
    for intent_filter in component.intent_filters:
        if "android.intent.category.BROWSABLE" in intent_filter.categories:
            return True
        if "android.intent.action.VIEW" in intent_filter.actions and intent_filter.data:
            return True
    return False


def _is_safe_callback_relay(sink) -> bool:
    if sink.kind != "intent_launch_sink":
        return False
    return sink.extra.get("launch_control") == "payload_only"


def _exploitability_reason(sink) -> str:
    if sink.kind == "webview_load_sink":
        return "loads it into a WebView"
    if sink.kind == "intent_redirection_sink":
        return "uses it to rewrite intent routing"
    if sink.kind == "class_loading_sink":
        return "passes it into reflective class loading"
    if sink.extra.get("launch_control") == "implicit_guarded_route":
        return "uses it to reach an implicit launch path"
    return "routes it into a launch path"


def _filter_reason(component) -> str:
    precision = browsable_filter_precision(component)
    constraints = browsable_filter_constraints(component)
    return f"{precision} browsable filter ({constraints})"
