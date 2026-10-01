from __future__ import annotations

import unittest
from dataclasses import dataclass

from context_sast.dataflow_engine.engine import DataflowEngine
from context_sast.models import ComponentInfo, DexAnalysisResult, ManifestAnalysis, MethodRef, Provenance


@dataclass(frozen=True)
class FakeInstruction:
    name: str
    output: str

    def get_name(self) -> str:
        return self.name

    def get_output(self) -> str:
        return self.output


class FakeMethod:
    def __init__(
        self,
        class_name: str,
        name: str,
        descriptor: str,
        instructions: list[FakeInstruction],
        params: tuple[int, ...],
    ) -> None:
        self._class_name = class_name
        self._name = name
        self._descriptor = descriptor
        self._instructions = instructions
        self._params = params

    def get_class_name(self) -> str:
        return self._class_name

    def get_name(self) -> str:
        return self._name

    def get_descriptor(self) -> str:
        return self._descriptor

    def get_information(self) -> dict[str, object]:
        return {"params": tuple((register, "Ljava/lang/Object;") for register in self._params)}

    def get_instructions_idx(self):
        for index, instruction in enumerate(self._instructions):
            yield index * 2, instruction


class FakeMethodAnalysis:
    def __init__(self, method: FakeMethod) -> None:
        self._method = method

    def get_method(self) -> FakeMethod:
        return self._method


def build_dex(*methods: FakeMethod) -> DexAnalysisResult:
    analyses = {}
    methods_by_class: dict[str, tuple[MethodRef, ...]] = {}
    for method in methods:
        ref = MethodRef(method.get_class_name(), method.get_name(), method.get_descriptor())
        analyses[ref.signature] = FakeMethodAnalysis(method)
        methods_by_class.setdefault(ref.class_name, tuple())
        methods_by_class[ref.class_name] = (*methods_by_class[ref.class_name], ref)
    return DexAnalysisResult(
        apk=None,
        dalvik_vms=(),
        analysis=None,
        methods=analyses,
        methods_by_class=methods_by_class,
        app_class_descriptors=frozenset(methods_by_class),
    )


class DataflowEngineIntentTests(unittest.TestCase):
    def test_analyze_components_treats_do_create_view_as_activity_entrypoint(self) -> None:
        method = FakeMethod(
            "Lcom/example/LaunchActivity;",
            "doCreateView",
            "(Landroid/os/Bundle;)V",
            [
                FakeInstruction("invoke-virtual", "v0, Lcom/example/LaunchActivity;->getIntent()Landroid/content/Intent;"),
                FakeInstruction("move-result-object", "v1"),
                FakeInstruction("invoke-virtual", "v1, Landroid/content/Intent;->getData()Landroid/net/Uri;"),
                FakeInstruction("move-result-object", "v2"),
                FakeInstruction("invoke-virtual", "v2, Landroid/net/Uri;->getPathSegments()Ljava/util/List;"),
                FakeInstruction("move-result-object", "v3"),
                FakeInstruction("const/4", "v4, 1"),
                FakeInstruction("invoke-interface", "v3, v4, Ljava/util/List;->get(I)Ljava/lang/Object;"),
                FakeInstruction("move-result-object", "v5"),
                FakeInstruction("invoke-static", "v5, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"),
                FakeInstruction("return-void", ""),
            ],
            params=(0, 1),
        )
        dex = build_dex(method)
        manifest = ManifestAnalysis(
            package_name="com.example",
            min_sdk=None,
            target_sdk=None,
            permissions={},
            components=(
                ComponentInfo(
                    name="Lcom/example/LaunchActivity;",
                    kind="activity",
                    exported=True,
                    implicitly_exported=False,
                ),
            ),
        )
        engine = DataflowEngine()

        analyses = engine.analyze_components(manifest, dex)

        self.assertIn("Lcom/example/LaunchActivity;", analyses)
        analysis = analyses["Lcom/example/LaunchActivity;"]
        self.assertIn("doCreateView", {entry.name for entry in analysis.entry_methods})
        class_loading_sinks = [sink for sink in analysis.sink_events if sink.kind == "class_loading_sink"]
        self.assertEqual(len(class_loading_sinks), 1)

    def test_analysis_continues_past_early_return_sites(self) -> None:
        method = FakeMethod(
            "Lcom/example/LaunchActivity;",
            "doCreateView",
            "(Landroid/os/Bundle;)V",
            [
                FakeInstruction("if-eqz", "v1, +004h"),
                FakeInstruction("return-void", ""),
                FakeInstruction("invoke-virtual", "v0, Lcom/example/LaunchActivity;->getIntent()Landroid/content/Intent;"),
                FakeInstruction("move-result-object", "v1"),
                FakeInstruction("const-string", "v4, \"className\""),
                FakeInstruction(
                    "invoke-virtual",
                    "v1, v4, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
                ),
                FakeInstruction("move-result-object", "v2"),
                FakeInstruction("invoke-static", "v2, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"),
                FakeInstruction("return-void", ""),
            ],
            params=(0, 1),
        )
        dex = build_dex(method)
        engine = DataflowEngine()
        engine.dex = dex

        summary = engine._analyze_method(MethodRef(method.get_class_name(), method.get_name(), method.get_descriptor()), (), 0)

        class_loading_sinks = [sink for sink in summary.sink_events if sink.kind == "class_loading_sink"]
        self.assertEqual(len(class_loading_sinks), 1)

    def test_explicit_intent_with_copied_extras_is_payload_only(self) -> None:
        method = FakeMethod(
            "Lcom/example/HubTipsActivity;",
            "onCreate",
            "(Landroid/os/Bundle;)V",
            [
                FakeInstruction("invoke-virtual", "v0, Lcom/example/HubTipsActivity;->getIntent()Landroid/content/Intent;"),
                FakeInstruction("move-result-object", "v1"),
                FakeInstruction("const-class", "v4, Lcom/example/InternalActivity;"),
                FakeInstruction(
                    "invoke-direct",
                    "v2, v0, v4, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V",
                ),
                FakeInstruction("invoke-virtual", "v2, v1, Landroid/content/Intent;->putExtras(Landroid/content/Intent;)Landroid/content/Intent;"),
                FakeInstruction("invoke-virtual", "v0, v2, Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V"),
                FakeInstruction("return-void", ""),
            ],
            params=(0, 1),
        )
        dex = build_dex(method)
        engine = DataflowEngine()
        engine.dex = dex

        summary = engine._analyze_method(MethodRef(method.get_class_name(), method.get_name(), method.get_descriptor()), (), 0)

        self.assertEqual(len(summary.sink_events), 1)
        sink = summary.sink_events[0]
        self.assertEqual(sink.kind, "intent_launch_sink")
        self.assertEqual(sink.extra.get("launch_control"), "payload_only")
        self.assertTrue(all(provenance.tag == "intent_payload" for provenance in sink.provenances))

    def test_nested_intent_launch_is_route_control(self) -> None:
        method = FakeMethod(
            "Lcom/example/WebAuthActivity;",
            "onCreate",
            "(Landroid/os/Bundle;)V",
            [
                FakeInstruction("invoke-virtual", "v0, Lcom/example/WebAuthActivity;->getIntent()Landroid/content/Intent;"),
                FakeInstruction("move-result-object", "v1"),
                FakeInstruction("const-string", "v5, \"intent\""),
                FakeInstruction(
                    "invoke-virtual",
                    "v1, v5, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;",
                ),
                FakeInstruction("move-result-object", "v2"),
                FakeInstruction("invoke-virtual", "v0, v2, Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V"),
                FakeInstruction("return-void", ""),
            ],
            params=(0, 1),
        )
        dex = build_dex(method)
        engine = DataflowEngine()
        engine.dex = dex

        summary = engine._analyze_method(MethodRef(method.get_class_name(), method.get_name(), method.get_descriptor()), (), 0)

        self.assertEqual(len(summary.sink_events), 1)
        sink = summary.sink_events[0]
        self.assertEqual(sink.extra.get("launch_control"), "route_control")
        self.assertIn("parcelable_extra", {provenance.tag for provenance in sink.provenances})

    def test_helper_returned_explicit_intent_keeps_fixed_route_across_methods(self) -> None:
        on_create = FakeMethod(
            "Lcom/example/HubTipsActivity;",
            "onCreate",
            "(Landroid/os/Bundle;)V",
            [
                FakeInstruction(
                    "invoke-virtual",
                    "v0, Lcom/example/HubTipsActivity;->buildIntent()Landroid/content/Intent;",
                ),
                FakeInstruction("move-result-object", "v2"),
                FakeInstruction("invoke-virtual", "v0, Lcom/example/HubTipsActivity;->getIntent()Landroid/content/Intent;"),
                FakeInstruction("move-result-object", "v1"),
                FakeInstruction("invoke-virtual", "v2, v1, Landroid/content/Intent;->putExtras(Landroid/content/Intent;)Landroid/content/Intent;"),
                FakeInstruction("invoke-virtual", "v0, v2, Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V"),
                FakeInstruction("return-void", ""),
            ],
            params=(0, 1),
        )
        build_intent = FakeMethod(
            "Lcom/example/HubTipsActivity;",
            "buildIntent",
            "()Landroid/content/Intent;",
            [
                FakeInstruction("const-class", "v2, Lcom/example/InternalActivity;"),
                FakeInstruction(
                    "invoke-direct",
                    "v1, v0, v2, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V",
                ),
                FakeInstruction("return-object", "v1"),
            ],
            params=(0,),
        )
        dex = build_dex(on_create, build_intent)
        engine = DataflowEngine()
        engine.dex = dex

        summary = engine._analyze_method(MethodRef(on_create.get_class_name(), on_create.get_name(), on_create.get_descriptor()), (), 0)

        self.assertEqual(len(summary.sink_events), 1)
        sink = summary.sink_events[0]
        self.assertEqual(sink.extra.get("launch_control"), "payload_only")
        self.assertEqual(sink.extra.get("target_component"), "Lcom/example/InternalActivity;")

    def test_tainted_action_on_new_implicit_intent_is_route_control(self) -> None:
        method = FakeMethod(
            "Lcom/example/ImplicitRedirectActivity;",
            "onCreate",
            "(Landroid/os/Bundle;)V",
            [
                FakeInstruction("invoke-virtual", "v0, Lcom/example/ImplicitRedirectActivity;->getIntent()Landroid/content/Intent;"),
                FakeInstruction("move-result-object", "v1"),
                FakeInstruction("const-string", "v4, \"action\""),
                FakeInstruction(
                    "invoke-virtual",
                    "v1, v4, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
                ),
                FakeInstruction("move-result-object", "v2"),
                FakeInstruction("invoke-direct", "v3, v2, Landroid/content/Intent;-><init>(Ljava/lang/String;)V"),
                FakeInstruction("invoke-virtual", "v0, v3, Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V"),
                FakeInstruction("return-void", ""),
            ],
            params=(0, 1),
        )
        dex = build_dex(method)
        engine = DataflowEngine()
        engine.dex = dex

        summary = engine._analyze_method(MethodRef(method.get_class_name(), method.get_name(), method.get_descriptor()), (), 0)

        self.assertEqual(len(summary.sink_events), 1)
        sink = summary.sink_events[0]
        self.assertEqual(sink.extra.get("launch_control"), "route_control")
        self.assertIn("intent_route_action", {provenance.tag for provenance in sink.provenances})

    def test_explicit_target_dominates_tainted_data_uri(self) -> None:
        method = FakeMethod(
            "Lcom/example/LockedRouteActivity;",
            "onCreate",
            "(Landroid/os/Bundle;)V",
            [
                FakeInstruction("const-class", "v4, Lcom/example/InternalActivity;"),
                FakeInstruction(
                    "invoke-direct",
                    "v2, v0, v4, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V",
                ),
                FakeInstruction("invoke-virtual", "v0, Lcom/example/LockedRouteActivity;->getIntent()Landroid/content/Intent;"),
                FakeInstruction("move-result-object", "v1"),
                FakeInstruction("invoke-virtual", "v1, Landroid/content/Intent;->getData()Landroid/net/Uri;"),
                FakeInstruction("move-result-object", "v3"),
                FakeInstruction("invoke-virtual", "v2, v3, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;"),
                FakeInstruction("invoke-virtual", "v0, v2, Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V"),
                FakeInstruction("return-void", ""),
            ],
            params=(0, 1),
        )
        dex = build_dex(method)
        engine = DataflowEngine()
        engine.dex = dex

        summary = engine._analyze_method(MethodRef(method.get_class_name(), method.get_name(), method.get_descriptor()), (), 0)

        self.assertEqual(summary.sink_events, ())

    def test_external_extra_into_class_for_name_is_class_loading_sink(self) -> None:
        method = FakeMethod(
            "Lcom/example/DynamicLoaderActivity;",
            "onCreate",
            "(Landroid/os/Bundle;)V",
            [
                FakeInstruction("invoke-virtual", "v0, Lcom/example/DynamicLoaderActivity;->getIntent()Landroid/content/Intent;"),
                FakeInstruction("move-result-object", "v1"),
                FakeInstruction("const-string", "v4, \"className\""),
                FakeInstruction(
                    "invoke-virtual",
                    "v1, v4, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
                ),
                FakeInstruction("move-result-object", "v2"),
                FakeInstruction("invoke-static", "v2, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"),
                FakeInstruction("return-void", ""),
            ],
            params=(0, 1),
        )
        dex = build_dex(method)
        engine = DataflowEngine()
        engine.dex = dex

        summary = engine._analyze_method(MethodRef(method.get_class_name(), method.get_name(), method.get_descriptor()), (), 0)

        self.assertEqual(len(summary.sink_events), 1)
        sink = summary.sink_events[0]
        self.assertEqual(sink.kind, "class_loading_sink")
        self.assertEqual(sink.extra.get("class_loading_api"), "Class.forName")
        self.assertIn("string_extra", {provenance.tag for provenance in sink.provenances})

    def test_cross_method_load_class_propagation_is_detected(self) -> None:
        on_create = FakeMethod(
            "Lcom/example/DynamicLoaderActivity;",
            "onCreate",
            "(Landroid/os/Bundle;)V",
            [
                FakeInstruction("invoke-virtual", "v0, Lcom/example/DynamicLoaderActivity;->getIntent()Landroid/content/Intent;"),
                FakeInstruction("move-result-object", "v1"),
                FakeInstruction("const-string", "v4, \"className\""),
                FakeInstruction(
                    "invoke-virtual",
                    "v1, v4, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
                ),
                FakeInstruction("move-result-object", "v2"),
                FakeInstruction("invoke-virtual", "v0, v2, Lcom/example/DynamicLoaderActivity;->loadByName(Ljava/lang/String;)V"),
                FakeInstruction("return-void", ""),
            ],
            params=(0, 1),
        )
        load_by_name = FakeMethod(
            "Lcom/example/DynamicLoaderActivity;",
            "loadByName",
            "(Ljava/lang/String;)V",
            [
                FakeInstruction(
                    "invoke-virtual",
                    "v0, v1, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;",
                ),
                FakeInstruction("return-void", ""),
            ],
            params=(1,),
        )
        dex = build_dex(on_create, load_by_name)
        engine = DataflowEngine()
        engine.dex = dex

        summary = engine._analyze_method(MethodRef(on_create.get_class_name(), on_create.get_name(), on_create.get_descriptor()), (), 0)

        class_loading_sinks = [sink for sink in summary.sink_events if sink.kind == "class_loading_sink"]
        self.assertEqual(len(class_loading_sinks), 1)
        sink = class_loading_sinks[0]
        self.assertEqual(sink.extra.get("class_loading_api"), "loadClass")
        self.assertIn("string_extra", {provenance.tag for provenance in sink.provenances})

    def test_uri_path_segment_into_class_for_name_is_detected(self) -> None:
        method = FakeMethod(
            "Lcom/example/LaunchActivity;",
            "onCreate",
            "(Landroid/os/Bundle;)V",
            [
                FakeInstruction("invoke-virtual", "v0, Lcom/example/LaunchActivity;->getIntent()Landroid/content/Intent;"),
                FakeInstruction("move-result-object", "v1"),
                FakeInstruction("invoke-virtual", "v1, Landroid/content/Intent;->getData()Landroid/net/Uri;"),
                FakeInstruction("move-result-object", "v2"),
                FakeInstruction("invoke-virtual", "v2, Landroid/net/Uri;->getPathSegments()Ljava/util/List;"),
                FakeInstruction("move-result-object", "v3"),
                FakeInstruction("const/4", "v4, 1"),
                FakeInstruction("invoke-interface", "v3, v4, Ljava/util/List;->get(I)Ljava/lang/Object;"),
                FakeInstruction("move-result-object", "v5"),
                FakeInstruction("invoke-static", "v5, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"),
                FakeInstruction("return-void", ""),
            ],
            params=(0, 1),
        )
        dex = build_dex(method)
        engine = DataflowEngine()
        engine.dex = dex

        summary = engine._analyze_method(MethodRef(method.get_class_name(), method.get_name(), method.get_descriptor()), (), 0)

        class_loading_sinks = [sink for sink in summary.sink_events if sink.kind == "class_loading_sink"]
        self.assertEqual(len(class_loading_sinks), 1)
        sink = class_loading_sinks[0]
        self.assertEqual(sink.extra.get("class_loading_api"), "Class.forName")
        self.assertIn("provider_path", {provenance.tag for provenance in sink.provenances})

    def test_same_package_resolution_guard_marks_route_validation(self) -> None:
        method = FakeMethod(
            "Lcom/example/OutsideJumpActivity;",
            "onCreate",
            "(Landroid/os/Bundle;)V",
            [
                FakeInstruction("invoke-virtual", "v0, Lcom/example/OutsideJumpActivity;->getIntent()Landroid/content/Intent;"),
                FakeInstruction("move-result-object", "v1"),
                FakeInstruction("const-string", "v6, \"outside_jump_intent\""),
                FakeInstruction(
                    "invoke-virtual",
                    "v1, v6, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;",
                ),
                FakeInstruction("move-result-object", "v2"),
                FakeInstruction("invoke-virtual", "v0, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;"),
                FakeInstruction("move-result-object", "v3"),
                FakeInstruction(
                    "invoke-virtual",
                    "v2, v3, Landroid/content/Intent;->resolveActivity(Landroid/content/pm/PackageManager;)Landroid/content/ComponentName;",
                ),
                FakeInstruction("move-result-object", "v4"),
                FakeInstruction("invoke-virtual", "v0, Landroid/content/Context;->getPackageName()Ljava/lang/String;"),
                FakeInstruction("move-result-object", "v5"),
                FakeInstruction("invoke-virtual", "v4, Landroid/content/ComponentName;->getPackageName()Ljava/lang/String;"),
                FakeInstruction("move-result-object", "v6"),
                FakeInstruction("invoke-virtual", "v5, v6, Ljava/lang/String;->equals(Ljava/lang/Object;)Z"),
                FakeInstruction("move-result", "v7"),
                FakeInstruction("if-eqz", "v7, +004h"),
                FakeInstruction("invoke-virtual", "v0, v2, Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V"),
                FakeInstruction("return-void", ""),
            ],
            params=(0, 1),
        )
        dex = build_dex(method)
        engine = DataflowEngine()
        engine.dex = dex

        summary = engine._analyze_method(MethodRef(method.get_class_name(), method.get_name(), method.get_descriptor()), (), 0)

        sinks = [sink for sink in summary.sink_events if sink.kind == "intent_launch_sink"]
        self.assertEqual(len(sinks), 1)
        self.assertIn("same_package_route_validation", sinks[0].provenances[0].validations)

    def test_guard_clause_early_return_marks_prefix_check_as_flawed(self) -> None:
        # A whole-URL prefix test is partial evidence, not an exact scheme/host policy.
        # pattern, which javac/dx compile using "if-nez" (branch away when the check
        # is true, i.e. when the validation actually passed) rather than "if-eqz".
        method = FakeMethod(
            "Lcom/example/WebPageActivity;",
            "onCreate",
            "(Landroid/os/Bundle;)V",
            [
                FakeInstruction("invoke-virtual", "v0, Lcom/example/WebPageActivity;->getIntent()Landroid/content/Intent;"),
                FakeInstruction("move-result-object", "v1"),
                FakeInstruction("const-string", "v4, \"url\""),
                FakeInstruction(
                    "invoke-virtual",
                    "v1, v4, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
                ),
                FakeInstruction("move-result-object", "v2"),
                FakeInstruction("const-string", "v5, \"https://trusted.com/app\""),
                FakeInstruction("invoke-virtual", "v2, v5, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z"),
                FakeInstruction("move-result", "v6"),
                FakeInstruction("if-nez", "v6, +002h"),
                FakeInstruction("return-void", ""),
                FakeInstruction("invoke-virtual", "v0, v2, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V"),
                FakeInstruction("return-void", ""),
            ],
            params=(0, 1),
        )
        dex = build_dex(method)
        engine = DataflowEngine()
        engine.dex = dex

        summary = engine._analyze_method(MethodRef(method.get_class_name(), method.get_name(), method.get_descriptor()), (), 0)

        sinks = [sink for sink in summary.sink_events if sink.kind == "webview_load_sink"]
        self.assertEqual(len(sinks), 1)
        self.assertIn("flawed_url_validation", sinks[0].provenances[0].validations)

    def test_canonical_path_containment_requires_an_absolute_directory_with_separator(self) -> None:
        engine = DataflowEngine()
        provenance = Provenance(
            tag="provider_path",
            trace=("canonical candidate",),
            validations=frozenset({"canonical_path_normalization"}),
        )

        strong = engine._classify_boolean_validation(
            "startsWith", (provenance,), ("/data/user/0/com.example/files/",)
        )
        relative = engine._classify_boolean_validation(
            "startsWith", (provenance,), ("files/",)
        )
        missing_separator = engine._classify_boolean_validation(
            "startsWith", (provenance,), ("/data/user/0/com.example/files",)
        )

        self.assertEqual(strong, "canonical_path_validation")
        self.assertEqual(relative, "flawed_url_validation")
        self.assertEqual(missing_separator, "flawed_url_validation")

    def test_validation_delegated_to_helper_method_is_still_recognized(self) -> None:
        # Models `if (!Validator.isValidUrl(url)) return; webView.loadUrl(url);` where
        # the actual `startsWith` check lives in a separate helper method/class. The
        # engine must propagate the helper's validation classification back to the
        # caller's branch instead of only recognizing inline validation calls.
        caller = FakeMethod(
            "Lcom/example/WebActivity;",
            "onCreate",
            "(Landroid/os/Bundle;)V",
            [
                FakeInstruction("invoke-virtual", "v0, Lcom/example/WebActivity;->getIntent()Landroid/content/Intent;"),
                FakeInstruction("move-result-object", "v1"),
                FakeInstruction("const-string", "v4, \"url\""),
                FakeInstruction(
                    "invoke-virtual",
                    "v1, v4, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
                ),
                FakeInstruction("move-result-object", "v2"),
                FakeInstruction("invoke-static", "v2, Lcom/example/Validator;->isValidUrl(Ljava/lang/String;)Z"),
                FakeInstruction("move-result", "v3"),
                FakeInstruction("if-nez", "v3, +002h"),
                FakeInstruction("return-void", ""),
                FakeInstruction("invoke-virtual", "v0, v2, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V"),
                FakeInstruction("return-void", ""),
            ],
            params=(0, 1),
        )
        helper = FakeMethod(
            "Lcom/example/Validator;",
            "isValidUrl",
            "(Ljava/lang/String;)Z",
            [
                FakeInstruction("const-string", "v2, \"https://trusted.com/app\""),
                FakeInstruction("invoke-virtual", "v1, v2, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z"),
                FakeInstruction("move-result", "v3"),
                FakeInstruction("return", "v3"),
            ],
            params=(1,),
        )
        dex = build_dex(caller, helper)
        engine = DataflowEngine()
        engine.dex = dex

        summary = engine._analyze_method(MethodRef(caller.get_class_name(), caller.get_name(), caller.get_descriptor()), (), 0)

        sinks = [sink for sink in summary.sink_events if sink.kind == "webview_load_sink"]
        self.assertEqual(len(sinks), 1)
        self.assertIn("flawed_url_validation", sinks[0].provenances[0].validations)

    def test_field_written_by_callee_is_visible_to_caller_after_return(self) -> None:
        # Models a setter-style helper: `storeUrl(url)` stashes a tainted value into
        # an instance field, and the caller reads that field back and sinks it after
        # the call returns. Field taint must survive the call boundary.
        caller = FakeMethod(
            "Lcom/example/WebActivity;",
            "onCreate",
            "(Landroid/os/Bundle;)V",
            [
                FakeInstruction("invoke-virtual", "v0, Lcom/example/WebActivity;->getIntent()Landroid/content/Intent;"),
                FakeInstruction("move-result-object", "v1"),
                FakeInstruction("const-string", "v4, \"url\""),
                FakeInstruction(
                    "invoke-virtual",
                    "v1, v4, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
                ),
                FakeInstruction("move-result-object", "v2"),
                FakeInstruction("invoke-virtual", "v0, v2, Lcom/example/WebActivity;->storeUrl(Ljava/lang/String;)V"),
                FakeInstruction("iget", "v3, v0, Lcom/example/WebActivity;->mUrl:Ljava/lang/String;"),
                FakeInstruction("invoke-virtual", "v0, v3, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V"),
                FakeInstruction("return-void", ""),
            ],
            params=(0, 1),
        )
        helper = FakeMethod(
            "Lcom/example/WebActivity;",
            "storeUrl",
            "(Ljava/lang/String;)V",
            [
                FakeInstruction("iput", "v1, v0, Lcom/example/WebActivity;->mUrl:Ljava/lang/String;"),
                FakeInstruction("return-void", ""),
            ],
            params=(1,),
        )
        dex = build_dex(caller, helper)
        engine = DataflowEngine()
        engine.dex = dex

        summary = engine._analyze_method(MethodRef(caller.get_class_name(), caller.get_name(), caller.get_descriptor()), (), 0)

        sinks = [sink for sink in summary.sink_events if sink.kind == "webview_load_sink"]
        self.assertEqual(len(sinks), 1)
        self.assertIn("string_extra", {provenance.tag for provenance in sinks[0].provenances})


if __name__ == "__main__":
    unittest.main()
