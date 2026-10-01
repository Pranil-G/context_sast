from __future__ import annotations

from context_sast.helpers import java_name_from_descriptor
from context_sast.models import CorrelatedComponentContext, Finding

from .base import BaseDetector
from .common import finding_context_extras, manifest_prefixed_trace, sink_context_extras


class ArbitraryClassLoadingDetector(BaseDetector):
    detector_id = "arbitrary_class_loading"

    def detect(self, contexts: tuple[CorrelatedComponentContext, ...]) -> tuple[Finding, ...]:
        findings = []
        for context in contexts:
            if context.component.kind == "webview-client":
                continue  # not an Android component surface
            analysis = context.code_analysis
            if analysis is None:
                continue
            if not context.caller_exposure.zero_permission_reachable:
                continue
            if "caller_permission_check" in analysis.validations:
                continue

            sinks = [event for event in analysis.sink_events if event.kind == "class_loading_sink"]
            if not sinks:
                continue

            primary = sinks[0]
            confidence = "MEDIUM" if any(provenance.validations for provenance in primary.provenances) else "HIGH"
            api_name = primary.extra.get("class_loading_api", primary.sink_signature.split("->", 1)[1].split("(", 1)[0])

            # Resolution on its own is reported, but it only carries demonstrated
            # impact once the resolved class drives a concrete operation such as
            # selecting a component target or being instantiated reflectively.
            class_uses = [event for event in analysis.sink_events if event.kind == "class_use_sink"]
            severity = "HIGH" if class_uses else "MEDIUM"
            use_note = (
                f" The resolved class then controls a later operation ({class_uses[0].extra.get('class_use', 'class use')})."
                if class_uses
                else " No later operation on the resolved class was observed, so the impact is limited to class resolution."
            )
            findings.append(
                Finding(
                    title=f"Arbitrary Class Loading in {java_name_from_descriptor(context.component.name).split('.')[-1]}",
                    severity=severity,
                    confidence=confidence,
                    owasp_category="M4: Insufficient Input/Output Validation",
                    affected_component=java_name_from_descriptor(context.component.name),
                    evidence=(
                        f"{java_name_from_descriptor(context.component.name)} is externally reachable and passes caller-controlled "
                        f"class names into {api_name}, which can redirect reflective behavior into unintended code paths."
                        f"{use_note}"
                    ),
                    source_to_sink=manifest_prefixed_trace(context, primary),
                    remediation=(
                        "Do not load classes from untrusted input. Replace dynamic class-name dispatch with a fixed allowlist "
                        "or direct code paths."
                    ),
                    detector=self.detector_id,
                    extras={
                        **finding_context_extras(context),
                        **sink_context_extras(primary),
                        "class_use": class_uses[0].extra.get("class_use", "") if class_uses else "none",
                    },
                )
            )
        return tuple(findings)
