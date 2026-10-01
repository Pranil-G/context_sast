from __future__ import annotations

import unittest

from context_sast.detectors import (
    ArbitraryClassLoadingDetector,
    DeepLinkAbuseDetector,
    InsecureContentProviderDetector,
    IntentRedirectionDetector,
    WebViewCallbackDetector,
    WebViewMisconfigurationDetector,
)
from context_sast.detectors.common import sink_has_exact_url_policy
from context_sast.models import IntentFilterData, IntentFilterInfo
from context_sast.models import CallerExposureContext, CodeComponentAnalysis, ComponentInfo, CorrelatedComponentContext, MethodRef, Provenance, SinkEvent


class DetectorTests(unittest.TestCase):
    def test_exact_url_policy_requires_scheme_and_host_on_same_flow(self) -> None:
        method = MethodRef("Lcom/example/WebActivity;", "onCreate", "()V")
        scheme_only = SinkEvent(
            kind="webview_load_sink",
            method=method,
            sink_signature="Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
            provenances=(
                Provenance(
                    tag="external_uri",
                    trace=("trace",),
                    validations=frozenset({"url_scheme_exact_validation"}),
                ),
            ),
            evidence="loadUrl()",
        )
        complete = SinkEvent(
            kind="webview_load_sink",
            method=method,
            sink_signature="Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
            provenances=(
                Provenance(
                    tag="external_uri",
                    trace=("trace",),
                    validations=frozenset(
                        {"url_scheme_exact_validation", "url_host_exact_validation"}
                    ),
                ),
            ),
            evidence="loadUrl()",
        )
        host_only = SinkEvent(
            kind="webview_load_sink",
            method=method,
            sink_signature="Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
            provenances=(
                Provenance(
                    tag="external_uri",
                    trace=("trace",),
                    validations=frozenset({"url_host_exact_validation"}),
                ),
            ),
            evidence="loadUrl()",
        )

        self.assertFalse(sink_has_exact_url_policy(scheme_only))
        self.assertFalse(sink_has_exact_url_policy(host_only))
        self.assertTrue(sink_has_exact_url_policy(complete))

    def test_package_scope_does_not_suppress_intent_redirection(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/RedirectActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="intent_launch_sink",
            method=MethodRef("Lcom/example/RedirectActivity;", "onCreate", "()V"),
            sink_signature="Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V",
            provenances=(
                Provenance(
                    tag="intent_route_action",
                    trace=("trace",),
                    validations=frozenset({"package_scope_validation"}),
                ),
            ),
            evidence="startActivity()",
            extra={"launch_control": "route_control"},
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset(),
            validations=frozenset({"package_scope_validation"}),
            path_sensitive_validations=frozenset({"package_scope_validation"}),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "exported"),
        )

        findings = IntentRedirectionDetector().detect((context,))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].confidence, "MEDIUM")

    def test_intent_redirection_detector_flags_exported_component(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/SplashActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="intent_launch_sink",
            method=MethodRef("Lcom/example/SplashActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V",
            provenances=(
                Provenance(
                    tag="parcelable_extra",
                    trace=("com.example.SplashActivity.onCreate: Intent extras", "com.example.SplashActivity.onCreate: startActivity()"),
                ),
            ),
            evidence="com.example.SplashActivity.onCreate: startActivity()",
            extra={"launch_control": "route_control"},
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset(),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "exported without permission"),
        )

        findings = IntentRedirectionDetector().detect((context,))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_intent_redirection_detector_ignores_payload_only_forwarding(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/HubTipsActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="intent_launch_sink",
            method=MethodRef("Lcom/example/HubTipsActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V",
            provenances=(Provenance(tag="intent_payload", trace=("trace",)),),
            evidence="startActivity()",
            extra={"launch_control": "payload_only", "target_component": "Lcom/example/InternalActivity;"},
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset(),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "exported without permission"),
        )

        findings = IntentRedirectionDetector().detect((context,))
        self.assertEqual(findings, ())

    def test_webview_detector_requires_javascript_enabled(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/WebViewActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="webview_load_sink",
            method=MethodRef("Lcom/example/WebViewActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
            provenances=(Provenance(tag="external_uri", trace=("trace",)),),
            evidence="loadUrl()",
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset({"webview_js_enabled"}),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "exported without permission"),
        )

        findings = WebViewMisconfigurationDetector().detect((context,))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector, "webview_misconfiguration")

    def test_provider_detector_flags_unprotected_provider(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/UnsafeProvider;",
            kind="provider",
            exported=True,
            implicitly_exported=False,
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(MethodRef("Lcom/example/UnsafeProvider;", "openFile", "(Landroid/net/Uri;Ljava/lang/String;)V"),),
            sink_events=(),
            flags=frozenset(),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "exported without permission"),
        )

        findings = InsecureContentProviderDetector().detect((context,))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_webview_detector_suppresses_validated_sink(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/WebViewActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="webview_load_sink",
            method=MethodRef("Lcom/example/WebViewActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
            provenances=(Provenance(tag="external_uri", trace=("trace",), validations=frozenset({"url_scheme_exact_validation", "url_host_exact_validation"})),),
            evidence="loadUrl()",
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset({"webview_js_enabled"}),
            validations=frozenset({"url_scheme_exact_validation", "url_host_exact_validation"}),
            path_sensitive_validations=frozenset({"url_scheme_exact_validation", "url_host_exact_validation"}),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "exported without permission"),
        )

        findings = WebViewMisconfigurationDetector().detect((context,))
        self.assertEqual(findings, ())

    def test_webview_detector_flags_internal_component_reached_via_exported_source(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/InternalWebViewActivity;",
            kind="activity",
            exported=False,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="webview_load_sink",
            method=MethodRef("Lcom/example/InternalWebViewActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
            provenances=(Provenance(tag="string_extra", trace=("target-trace",)),),
            evidence="loadUrl()",
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset({"webview_js_enabled", "webview_allow_file_access"}),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(
                True,
                "reachable via externally reachable component com.example.DeepLinkActivity",
                manifest_entry="AndroidManifest.xml: <activity name=\"com.example.InternalWebViewActivity\" exported=false>",
                ingress_trace=(
                    "AndroidManifest.xml: <activity name=\"com.example.DeepLinkActivity\" exported=true>",
                    "com.example.DeepLinkActivity.onCreate: getQueryParameter(url)",
                    "com.example.DeepLinkActivity.onCreate: putExtra(url)",
                    "com.example.DeepLinkActivity.onCreate: startActivity()",
                ),
                ingress_validations=frozenset({"flawed_url_validation"}),
                ingress_source_component="com.example.DeepLinkActivity",
            ),
        )

        findings = WebViewMisconfigurationDetector().detect((context,))
        self.assertEqual(len(findings), 1)
        self.assertIn("bypassable", findings[0].evidence)
        self.assertEqual(findings[0].source_to_sink[0], "AndroidManifest.xml: <activity name=\"com.example.DeepLinkActivity\" exported=true>")

    def test_webview_detector_requires_external_reachability(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/InternalWebViewActivity;",
            kind="activity",
            exported=False,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="webview_load_sink",
            method=MethodRef("Lcom/example/InternalWebViewActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
            provenances=(Provenance(tag="external_uri", trace=("trace",)),),
            evidence="loadUrl()",
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset({"webview_js_enabled"}),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(False, "component is not externally reachable"),
        )

        findings = WebViewMisconfigurationDetector().detect((context,))
        self.assertEqual(findings, ())

    def test_intent_redirection_detector_does_not_suppress_plain_resolution_checks(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/RedirectActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="intent_launch_sink",
            method=MethodRef("Lcom/example/RedirectActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V",
            provenances=(Provenance(tag="parcelable_extra", trace=("trace",), validations=frozenset({"intent_resolution_check"})),),
            evidence="startActivity()",
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset(),
            validations=frozenset({"intent_resolution_check"}),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "exported without permission"),
        )

        findings = IntentRedirectionDetector().detect((context,))
        self.assertEqual(len(findings), 1)

    def test_intent_redirection_detector_suppresses_component_locked_launch(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/LockedRedirectActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="intent_launch_sink",
            method=MethodRef("Lcom/example/LockedRedirectActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V",
            provenances=(
                Provenance(
                    tag="intent_route_component",
                    trace=("trace",),
                    validations=frozenset({"component_lock_validation"}),
                ),
            ),
            evidence="startActivity()",
            extra={"launch_control": "route_control"},
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset(),
            validations=frozenset({"component_lock_validation"}),
            path_sensitive_validations=frozenset({"component_lock_validation"}),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "exported without permission"),
        )

        findings = IntentRedirectionDetector().detect((context,))
        self.assertEqual(findings, ())

    def test_intent_redirection_detector_skips_permission_checked_component(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/ProtectedRedirectActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="intent_launch_sink",
            method=MethodRef("Lcom/example/ProtectedRedirectActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V",
            provenances=(Provenance(tag="parcelable_extra", trace=("trace",)),),
            evidence="startActivity()",
            extra={"launch_control": "route_control"},
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset(),
            validations=frozenset({"caller_permission_check"}),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "exported with runtime caller check"),
        )

        findings = IntentRedirectionDetector().detect((context,))
        self.assertEqual(findings, ())

    def test_intent_redirection_detector_flags_tainted_implicit_action_route(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/ImplicitRedirectActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="intent_launch_sink",
            method=MethodRef("Lcom/example/ImplicitRedirectActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V",
            provenances=(Provenance(tag="intent_route_action", trace=("trace",)),),
            evidence="startActivity()",
            extra={"launch_control": "route_control", "intent_action": "android.intent.action.VIEW"},
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset(),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "exported without permission"),
        )

        findings = IntentRedirectionDetector().detect((context,))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_intent_redirection_detector_keeps_same_package_trampoline_but_lowers_confidence(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/OutsideJumpActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="intent_launch_sink",
            method=MethodRef("Lcom/example/OutsideJumpActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V",
            provenances=(
                Provenance(
                    tag="parcelable_extra",
                    trace=("trace",),
                    validations=frozenset({"same_package_route_validation"}),
                ),
            ),
            evidence="startActivity()",
            extra={"launch_control": "route_control"},
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset(),
            validations=frozenset({"same_package_route_validation"}),
            path_sensitive_validations=frozenset({"same_package_route_validation"}),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "exported without permission"),
        )

        findings = IntentRedirectionDetector().detect((context,))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].confidence, "MEDIUM")
        self.assertIn("same app package", findings[0].evidence)

    def test_deep_link_detector_requires_browsable_surface(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/DeepLinkActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
            intent_filters=(
                IntentFilterInfo(
                    actions=("android.intent.action.VIEW",),
                    categories=("android.intent.category.BROWSABLE",),
                    data=(IntentFilterData(scheme="https", host="example.com"),),
                ),
            ),
        )
        event = SinkEvent(
            kind="webview_load_sink",
            method=MethodRef("Lcom/example/DeepLinkActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
            provenances=(Provenance(tag="external_uri", trace=("trace",)),),
            evidence="loadUrl()",
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset({"webview_js_enabled"}),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "exported without permission"),
        )

        findings = DeepLinkAbuseDetector().detect((context,))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].extras["browsable_filter_precision"], "exact_host")

    def test_deep_link_detector_suppresses_payload_only_callback_relay(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/CallbackRelayActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
            intent_filters=(
                IntentFilterInfo(
                    actions=("android.intent.action.VIEW",),
                    categories=("android.intent.category.DEFAULT", "android.intent.category.BROWSABLE"),
                    data=(IntentFilterData(scheme="amzn", host="example.app", path="/callback"),),
                ),
            ),
        )
        event = SinkEvent(
            kind="intent_launch_sink",
            method=MethodRef("Lcom/example/CallbackRelayActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V",
            provenances=(Provenance(tag="external_uri", trace=("trace",)),),
            evidence="startActivity()",
            extra={
                "launch_control": "payload_only",
                "target_component": "Lcom/example/InternalCallbackActivity;",
            },
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset(),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "browsable exported activity without a strong permission gate"),
        )

        findings = DeepLinkAbuseDetector().detect((context,))
        self.assertEqual(findings, ())

    def test_deep_link_detector_suppresses_strong_allowlist(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/ValidatedDeepLinkActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
            intent_filters=(
                IntentFilterInfo(
                    actions=("android.intent.action.VIEW",),
                    categories=("android.intent.category.BROWSABLE",),
                    data=(IntentFilterData(scheme="https", host="example.com", path="/account"),),
                ),
            ),
        )
        event = SinkEvent(
            kind="webview_load_sink",
            method=MethodRef("Lcom/example/ValidatedDeepLinkActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
            provenances=(Provenance(tag="external_uri", trace=("trace",), validations=frozenset({"url_scheme_exact_validation", "url_host_exact_validation"})),),
            evidence="loadUrl()",
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset({"webview_js_enabled"}),
            validations=frozenset({"url_scheme_exact_validation", "url_host_exact_validation"}),
            path_sensitive_validations=frozenset({"url_scheme_exact_validation", "url_host_exact_validation"}),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "browsable exported activity without a strong permission gate"),
        )

        findings = DeepLinkAbuseDetector().detect((context,))
        self.assertEqual(findings, ())

    def test_deep_link_detector_marks_bypassable_validation(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/BrittleDeepLinkActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
            intent_filters=(
                IntentFilterInfo(
                    actions=("android.intent.action.VIEW",),
                    categories=("android.intent.category.BROWSABLE",),
                    data=(IntentFilterData(scheme="https"),),
                ),
            ),
        )
        event = SinkEvent(
            kind="webview_load_sink",
            method=MethodRef("Lcom/example/BrittleDeepLinkActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
            provenances=(Provenance(tag="external_uri", trace=("trace",), validations=frozenset({"flawed_url_validation"})),),
            evidence="loadUrl()",
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset({"webview_js_enabled"}),
            validations=frozenset({"flawed_url_validation"}),
            path_sensitive_validations=frozenset({"flawed_url_validation"}),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "browsable exported activity without a strong permission gate"),
        )

        findings = DeepLinkAbuseDetector().detect((context,))
        self.assertEqual(len(findings), 1)
        self.assertIn("bypassable", findings[0].evidence)
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_deep_link_detector_reports_launch_abuse_as_high(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/RouteDeepLinkActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
            intent_filters=(
                IntentFilterInfo(
                    actions=("android.intent.action.VIEW",),
                    categories=("android.intent.category.BROWSABLE",),
                    data=(IntentFilterData(scheme="myapp"),),
                ),
            ),
        )
        event = SinkEvent(
            kind="intent_launch_sink",
            method=MethodRef("Lcom/example/RouteDeepLinkActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V",
            provenances=(Provenance(tag="external_uri", trace=("trace",)),),
            evidence="startActivity()",
            extra={"launch_control": "implicit_guarded_route"},
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset(),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "browsable exported activity without a strong permission gate"),
        )

        findings = DeepLinkAbuseDetector().detect((context,))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertIn("implicit launch path", findings[0].evidence)

    def test_deep_link_detector_flags_reflective_class_loading(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/LaunchActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
            intent_filters=(
                IntentFilterInfo(
                    actions=("android.intent.action.VIEW",),
                    categories=("android.intent.category.BROWSABLE", "android.intent.category.DEFAULT"),
                    data=(IntentFilterData(scheme="help", host="com.example"),),
                ),
            ),
        )
        event = SinkEvent(
            kind="class_loading_sink",
            method=MethodRef("Lcom/example/LaunchActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;",
            provenances=(Provenance(tag="provider_path", trace=("trace",)),),
            evidence="Class.forName()",
            extra={"class_loading_api": "Class.forName"},
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset(),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "browsable exported activity without a strong permission gate"),
        )

        findings = DeepLinkAbuseDetector().detect((context,))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertIn("reflective class loading", findings[0].evidence)

    def test_webview_detector_escalates_with_risk_modifiers(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/DangerousWebViewActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="webview_load_sink",
            method=MethodRef("Lcom/example/DangerousWebViewActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
            provenances=(Provenance(tag="external_uri", trace=("trace",)),),
            evidence="loadUrl()",
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset(
                {
                    "webview_js_enabled",
                    "webview_allow_file_access",
                    "webview_file_url_access",
                    "webview_universal_file_access",
                    "webview_js_interface",
                }
            ),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "exported without permission"),
        )

        findings = WebViewMisconfigurationDetector().detect((context,))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertIn("file access enabled", findings[0].evidence)
        self.assertIn("JavaScript interface exposed", findings[0].evidence)

    def test_webview_detector_uses_ingress_validation_for_confidence(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/IngressWebViewActivity;",
            kind="activity",
            exported=False,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="webview_load_sink",
            method=MethodRef("Lcom/example/IngressWebViewActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
            provenances=(Provenance(tag="string_extra", trace=("trace",)),),
            evidence="loadUrl()",
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset({"webview_js_enabled"}),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(
                True,
                "reachable via externally reachable component com.example.DeepLinkActivity",
                ingress_validations=frozenset({"flawed_url_validation"}),
                ingress_trace=("AndroidManifest.xml: <activity name=\"com.example.DeepLinkActivity\" exported=true>",),
                manifest_entry="AndroidManifest.xml: <activity name=\"com.example.IngressWebViewActivity\" exported=false>",
                ingress_source_component="com.example.DeepLinkActivity",
            ),
        )

        findings = WebViewMisconfigurationDetector().detect((context,))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].confidence, "MEDIUM")
        self.assertIn("bypassable", findings[0].evidence)

    def test_provider_detector_does_not_suppress_canonicalization_without_containment(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/SafeProvider;",
            kind="provider",
            exported=True,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="provider_path_file_sink",
            method=MethodRef("Lcom/example/SafeProvider;", "openFile", "(Landroid/net/Uri;Ljava/lang/String;)V"),
            sink_signature="Ljava/io/File;-><init>(Ljava/lang/String;)V",
            provenances=(Provenance(tag="provider_path", trace=("trace",), validations=frozenset({"canonical_path_normalization"})),),
            evidence="File(path)",
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(MethodRef("Lcom/example/SafeProvider;", "openFile", "(Landroid/net/Uri;Ljava/lang/String;)V"),),
            sink_events=(event,),
            flags=frozenset(),
            validations=frozenset({"canonical_path_normalization"}),
            path_sensitive_validations=frozenset({"canonical_path_normalization"}),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "exported without permission", manifest_entry="AndroidManifest.xml: <provider name=\"com.example.SafeProvider\" exported=true>"),
        )

        findings = InsecureContentProviderDetector().detect((context,))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_provider_detector_skips_unreachable_permission_protected_provider(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/ProtectedProvider;",
            kind="provider",
            exported=True,
            implicitly_exported=False,
            read_permission="com.example.READ",
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(MethodRef("Lcom/example/ProtectedProvider;", "query", "(Landroid/net/Uri;)V"),),
            sink_events=(),
            flags=frozenset(),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(False, "protected by strong permission", permission_level="signature"),
        )

        findings = InsecureContentProviderDetector().detect((context,))
        self.assertEqual(findings, ())

    def test_provider_detector_keeps_normal_permission_provider(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/NormalProvider;",
            kind="provider",
            exported=True,
            implicitly_exported=False,
            read_permission="com.example.READ_NORMAL",
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(MethodRef("Lcom/example/NormalProvider;", "query", "(Landroid/net/Uri;)V"),),
            sink_events=(),
            flags=frozenset(),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(
                True,
                "guarded only by normal-level permission",
                permission_name="com.example.READ_NORMAL",
                permission_level="normal",
            ),
        )

        findings = InsecureContentProviderDetector().detect((context,))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].owasp_category, "M8: Security Misconfiguration")

    def test_provider_detector_suppresses_fileprovider(self) -> None:
        component = ComponentInfo(
            name="Landroidx/core/content/FileProvider;",
            kind="provider",
            exported=True,
            implicitly_exported=False,
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(MethodRef("Landroidx/core/content/FileProvider;", "query", "(Landroid/net/Uri;)V"),),
            sink_events=(),
            flags=frozenset(),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "exported framework provider"),
        )

        findings = InsecureContentProviderDetector().detect((context,))
        self.assertEqual(findings, ())

    def test_arbitrary_class_loading_detector_flags_exported_component(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/DynamicLoaderActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="class_loading_sink",
            method=MethodRef("Lcom/example/DynamicLoaderActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;",
            provenances=(Provenance(tag="string_extra", trace=("trace",)),),
            evidence="Class.forName()",
            extra={"class_loading_api": "Class.forName"},
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset(),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "exported without permission"),
        )

        findings = ArbitraryClassLoadingDetector().detect((context,))
        self.assertEqual(len(findings), 1)
        # Resolution on its own: reported, but without demonstrated impact.
        self.assertEqual(findings[0].severity, "MEDIUM")
        self.assertEqual(findings[0].extras["class_use"], "none")
        self.assertIn("Class.forName", findings[0].evidence)

    def test_arbitrary_class_loading_detector_escalates_when_the_class_is_used(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/DynamicLoaderActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
        )
        method = MethodRef("Lcom/example/DynamicLoaderActivity;", "onCreate", "(Landroid/os/Bundle;)V")
        resolution = SinkEvent(
            kind="class_loading_sink",
            method=method,
            sink_signature="Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;",
            provenances=(Provenance(tag="string_extra", trace=("trace",)),),
            evidence="Class.forName()",
            extra={"class_loading_api": "Class.forName"},
        )
        use = SinkEvent(
            kind="class_use_sink",
            method=method,
            sink_signature="Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V",
            provenances=(Provenance(tag="resolved_class", trace=("trace",)),),
            evidence="Intent(context, class)",
            extra={"class_use": "component_target"},
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(resolution, use),
            flags=frozenset(),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "exported without permission"),
        )

        findings = ArbitraryClassLoadingDetector().detect((context,))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].extras["class_use"], "component_target")

    def test_arbitrary_class_loading_detector_uses_validation_to_lower_confidence(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/GuardedLoaderActivity;",
            kind="activity",
            exported=True,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="class_loading_sink",
            method=MethodRef("Lcom/example/GuardedLoaderActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;",
            provenances=(Provenance(tag="string_extra", trace=("trace",), validations=frozenset({"url_exact_match_validation"})),),
            evidence="loadClass()",
            extra={"class_loading_api": "loadClass"},
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset(),
            validations=frozenset(),
            path_sensitive_validations=frozenset({"url_exact_match_validation"}),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "exported without permission"),
        )

        findings = ArbitraryClassLoadingDetector().detect((context,))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].confidence, "MEDIUM")

    def test_arbitrary_class_loading_detector_requires_external_reachability(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/InternalLoaderActivity;",
            kind="activity",
            exported=False,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="class_loading_sink",
            method=MethodRef("Lcom/example/InternalLoaderActivity;", "onCreate", "(Landroid/os/Bundle;)V"),
            sink_signature="Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;",
            provenances=(Provenance(tag="string_extra", trace=("trace",)),),
            evidence="Class.forName()",
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset(),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(False, "component is not externally reachable"),
        )

        findings = ArbitraryClassLoadingDetector().detect((context,))
        self.assertEqual(findings, ())

    def test_webview_callback_detector_flags_web_controlled_load(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/AppWebViewClient;",
            kind="webview-client",
            exported=False,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="webview_callback_sink",
            method=MethodRef("Lcom/example/AppWebViewClient;", "shouldOverrideUrlLoading",
                             "(Landroid/webkit/WebView;Ljava/lang/String;)Z"),
            sink_signature="Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
            provenances=(Provenance(tag="web_content", trace=("trace",)),),
            evidence="loadUrl()",
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset({"webview_js_enabled"}),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "reachable through content loaded in the WebView"),
        )

        findings = WebViewCallbackDetector().detect((context,))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].detector, "webview_callback")

    def test_webview_callback_detector_ignores_a_bare_relay(self) -> None:
        """A callback that reloads the URL it was given repeats default navigation."""
        component = ComponentInfo(
            name="Lcom/example/RelayWebViewClient;",
            kind="webview-client",
            exported=False,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="webview_callback_sink",
            method=MethodRef("Lcom/example/RelayWebViewClient;", "shouldOverrideUrlLoading",
                             "(Landroid/webkit/WebView;Ljava/lang/String;)Z"),
            sink_signature="Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
            provenances=(Provenance(tag="web_content", trace=("trace",)),),
            evidence="loadUrl()",
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset(),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "reachable through content loaded in the WebView"),
        )

        self.assertEqual(WebViewCallbackDetector().detect((context,)), ())

    def test_webview_callback_detector_suppresses_exact_host_policy(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/StrictWebViewClient;",
            kind="webview-client",
            exported=False,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="webview_callback_sink",
            method=MethodRef("Lcom/example/StrictWebViewClient;", "shouldOverrideUrlLoading",
                             "(Landroid/webkit/WebView;Ljava/lang/String;)Z"),
            sink_signature="Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
            provenances=(Provenance(tag="web_content", trace=("trace",),
                                    validations=frozenset({"url_scheme_exact_validation", "url_host_exact_validation"})),),
            evidence="loadUrl()",
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset({"webview_js_enabled"}),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "reachable through content loaded in the WebView"),
        )

        self.assertEqual(WebViewCallbackDetector().detect((context,)), ())

    def test_component_detectors_ignore_webview_callback_contexts(self) -> None:
        component = ComponentInfo(
            name="Lcom/example/AppWebViewClient;",
            kind="webview-client",
            exported=False,
            implicitly_exported=False,
        )
        event = SinkEvent(
            kind="webview_callback_sink",
            method=MethodRef("Lcom/example/AppWebViewClient;", "shouldOverrideUrlLoading",
                             "(Landroid/webkit/WebView;Ljava/lang/String;)Z"),
            sink_signature="Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
            provenances=(Provenance(tag="web_content", trace=("trace",)),),
            evidence="loadUrl()",
        )
        analysis = CodeComponentAnalysis(
            component=component,
            entry_methods=(),
            sink_events=(event,),
            flags=frozenset({"webview_js_enabled"}),
            validations=frozenset(),
            path_sensitive_validations=frozenset(),
            visited_methods=(),
        )
        context = CorrelatedComponentContext(
            component=component,
            code_analysis=analysis,
            caller_exposure=CallerExposureContext(True, "reachable through content loaded in the WebView"),
        )

        self.assertEqual(WebViewMisconfigurationDetector().detect((context,)), ())
        self.assertEqual(ArbitraryClassLoadingDetector().detect((context,)), ())


if __name__ == "__main__":
    unittest.main()
