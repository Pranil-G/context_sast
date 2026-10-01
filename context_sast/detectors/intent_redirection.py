from __future__ import annotations

from context_sast.helpers import java_name_from_descriptor
from context_sast.models import CorrelatedComponentContext, Finding

from .base import BaseDetector
from .common import finding_context_extras, manifest_prefixed_trace, sink_context_extras, sink_has_any_validation


class IntentRedirectionDetector(BaseDetector):
    detector_id = "intent_redirection"

    def detect(self, contexts: tuple[CorrelatedComponentContext, ...]) -> tuple[Finding, ...]:
        findings = []
        for context in contexts:
            component = context.component
            analysis = context.code_analysis
            if component.kind not in {"activity", "activity-alias", "service", "receiver"}:
                continue
            if not context.caller_exposure.zero_permission_reachable or analysis is None:
                continue
            if "caller_permission_check" in analysis.validations:
                continue

            sinks = [event for event in analysis.sink_events if event.kind in {"intent_redirection_sink", "intent_launch_sink"}]
            if not sinks:
                continue

            actionable = [sink for sink in sinks if self._is_actionable_sink(sink)]
            if not actionable:
                continue

            primary = actionable[0]
            same_package_only = any("same_package_route_validation" in provenance.validations for provenance in primary.provenances)
            confidence = "MEDIUM" if analysis.path_sensitive_validations or same_package_only else "HIGH"
            validation_note = (
                " The code only checks that the resolved target stays within the same app package, which still leaves internal component trampolining possible."
                if same_package_only
                else ""
            )
            finding = Finding(
                title=f"Intent Redirection in {java_name_from_descriptor(component.name).split('.')[-1]}",
                severity="HIGH" if primary.kind == "intent_launch_sink" else "MEDIUM",
                confidence=confidence,
                owasp_category="M4: Insufficient Input/Output Validation",
                affected_component=java_name_from_descriptor(component.name),
                evidence=(
                    f"{java_name_from_descriptor(component.name)} is exported and routes external intent data into "
                    f"{primary.sink_signature.split('->', 1)[1].split('(', 1)[0]} without a strong component allowlist or destination lock."
                    f"{validation_note}"
                ),
                source_to_sink=manifest_prefixed_trace(context, primary),
                remediation=(
                    "Validate nested intents, component names, or destination packages before launching them, "
                    "or make the component unexported."
                ),
                detector=self.detector_id,
                extras={**finding_context_extras(context), **sink_context_extras(primary)},
            )
            findings.append(finding)
        return tuple(findings)

    def _is_actionable_sink(self, sink) -> bool:
        if sink_has_any_validation(sink, {"component_lock_validation"}):
            return False
        tags = {provenance.tag for provenance in sink.provenances}
        if sink.kind == "intent_launch_sink":
            if sink.extra.get("launch_control") == "payload_only":
                return False
            return bool(
                tags
                & {
                    "intent",
                    "parcelable_extra",
                    "serializable_extra",
                    "intent_route_component",
                    "intent_route_package",
                    "intent_route_action",
                    "intent_route_data",
                    "intent_route_category",
                }
            )
        return bool(
            tags
            & {
                "string_extra",
                "external_uri",
                "serializable_extra",
                "parcelable_extra",
                "intent_route_component",
                "intent_route_package",
            }
        )
