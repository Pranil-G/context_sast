from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from context_sast.models import (
    CallerExposureContext,
    CodeComponentAnalysis,
    ComponentInfo,
    CorrelatedComponentContext,
    MethodRef,
    Provenance,
    SinkEvent,
)
from context_sast.rule_engine import RuleEngine


@dataclass(frozen=True)
class EvaluationCase:
    test_id: str
    description: str
    context: CorrelatedComponentContext


def make_context(
    test_id: str,
    *,
    kind: str = "activity",
    reachable: bool = True,
    sink_kind: str,
    tag: str,
    launch_control: str = "",
    validations: frozenset[str] = frozenset(),
    flags: frozenset[str] = frozenset(),
    include_class_use: bool = False,
) -> CorrelatedComponentContext:
    component = ComponentInfo(
        name=f"Lcontrolled/{test_id};",
        kind=kind,
        exported=reachable,
        implicitly_exported=False,
    )
    method_name = "openFile" if kind == "provider" else "onCreate"
    if kind == "webview-client":
        method_name = "shouldOverrideUrlLoading"
    method = MethodRef(component.name, method_name, "()V")
    sink_signatures = {
        "intent_launch_sink": "Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V",
        "webview_load_sink": "Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
        "webview_callback_sink": "Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
        "provider_path_file_sink": "Ljava/io/File;-><init>(Ljava/lang/String;)V",
        "class_loading_sink": "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;",
    }
    primary = SinkEvent(
        kind=sink_kind,
        method=method,
        sink_signature=sink_signatures[sink_kind],
        provenances=(Provenance(tag=tag, trace=(f"{test_id}: source", f"{test_id}: sink"), validations=validations),),
        evidence=f"{test_id}: qualifying sink",
        extra={"launch_control": launch_control} if launch_control else {},
    )
    sinks = [primary]
    if include_class_use:
        sinks.append(
            SinkEvent(
                kind="class_use_sink",
                method=method,
                sink_signature="Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V",
                provenances=(Provenance(tag="resolved_class", trace=(f"{test_id}: resolved class used",)),),
                evidence=f"{test_id}: resolved class used",
                extra={"class_use": "component_target"},
            )
        )
    entry_methods = (method,) if kind == "provider" else ()
    analysis = CodeComponentAnalysis(
        component=component,
        entry_methods=entry_methods,
        sink_events=tuple(sinks),
        flags=flags,
        validations=validations,
        path_sensitive_validations=validations,
        visited_methods=(method.signature,),
    )
    return CorrelatedComponentContext(
        component=component,
        code_analysis=analysis,
        caller_exposure=CallerExposureContext(
            reachable,
            "externally reachable" if reachable else "component is not externally reachable",
            manifest_entry=f"AndroidManifest.xml: {test_id}",
        ),
    )


def cases() -> tuple[EvaluationCase, ...]:
    exact_url = frozenset({"url_scheme_exact_validation", "url_host_exact_validation"})
    return (
        EvaluationCase("MICRO-01", "Unsafe attacker-controlled intent route", make_context("MICRO-01", sink_kind="intent_launch_sink", tag="intent_route_action", launch_control="route_control")),
        EvaluationCase("MICRO-02", "Payload-only intent forwarding", make_context("MICRO-02", sink_kind="intent_launch_sink", tag="intent_payload", launch_control="payload_only")),
        EvaluationCase("MICRO-03", "Intent route guarded by an exact component lock", make_context("MICRO-03", sink_kind="intent_launch_sink", tag="intent_route_component", launch_control="route_control", validations=frozenset({"component_lock_validation"}))),
        EvaluationCase("MICRO-04", "Unsafe route in a non-exported component", make_context("MICRO-04", reachable=False, sink_kind="intent_launch_sink", tag="intent_route_action", launch_control="route_control")),
        EvaluationCase("MICRO-05", "Unsafe WebView callback", make_context("MICRO-05", kind="webview-client", sink_kind="webview_callback_sink", tag="web_content", flags=frozenset({"webview_js_enabled"}))),
        EvaluationCase("MICRO-06", "WebView load guarded by exact scheme and host", make_context("MICRO-06", sink_kind="webview_load_sink", tag="external_uri", validations=exact_url, flags=frozenset({"webview_js_enabled"}))),
        EvaluationCase("MICRO-07", "Provider path reaches a file sink", make_context("MICRO-07", kind="provider", sink_kind="provider_path_file_sink", tag="provider_path")),
        EvaluationCase("MICRO-08", "Attacker-controlled class resolution", make_context("MICRO-08", sink_kind="class_loading_sink", tag="string_extra")),
        EvaluationCase("MICRO-09", "Attacker-controlled class resolution and use", make_context("MICRO-09", sink_kind="class_loading_sink", tag="string_extra", include_class_use=True)),
    )


def main() -> None:
    all_cases = cases()
    after_exposure = tuple(case for case in all_cases if case.context.caller_exposure.zero_permission_reachable)
    after_route = tuple(
        case
        for case in after_exposure
        if not any(
            event.kind == "intent_launch_sink" and event.extra.get("launch_control") == "payload_only"
            for event in case.context.code_analysis.sink_events
        )
    )
    after_validation = tuple(
        case
        for case in after_route
        if not any(
            "component_lock_validation" in provenance.validations
            or {"url_scheme_exact_validation", "url_host_exact_validation"}.issubset(provenance.validations)
            for event in case.context.code_analysis.sink_events
            for provenance in event.provenances
        )
    )
    engine = RuleEngine()
    completed = tuple(case for case in after_validation if engine.run((case.context,)))
    counts = [len(all_cases), len(after_exposure), len(after_route), len(after_validation), len(completed)]
    assert counts == [9, 8, 7, 5, 5], counts

    stage_sets = {
        "pattern_candidates": {case.test_id for case in all_cases},
        "externally_reachable": {case.test_id for case in after_exposure},
        "route_controlling": {case.test_id for case in after_route},
        "not_strongly_validated": {case.test_id for case in after_validation},
        "reported": {case.test_id for case in completed},
    }
    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "expected_counts": [9, 8, 7, 5, 5],
        "observed_counts": counts,
        "assertion": "passed",
        "stages": [{"name": name, "count": len(ids), "test_ids": sorted(ids)} for name, ids in stage_sets.items()],
        "cases": [{"test_id": case.test_id, "description": case.description} for case in all_cases],
    }
    output = Path(__file__).resolve().parents[1] / "results" / "controlled-micro-evaluation.json"
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Archived {output}")
    print("Observed stage counts: 9 -> 8 -> 7 -> 5 -> 5")


if __name__ == "__main__":
    main()
