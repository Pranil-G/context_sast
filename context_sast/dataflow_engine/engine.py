from __future__ import annotations

import re
import sys
import traceback
from collections import defaultdict
from dataclasses import dataclass, replace

from context_sast.helpers import REGISTER_RE, cap_provenances, parse_const_class, parse_invoke_output
from context_sast.models import (
    CodeComponentAnalysis,
    ComponentInfo,
    DexAnalysisResult,
    IntentValueState,
    ManifestAnalysis,
    MethodFlowSummary,
    MethodRef,
    Provenance,
)
from context_sast.taint_engine import TaintEngine

CONST_STR_RE = re.compile(r"^(v\d+),\s*\"(.*)\"$")
CONST_NUM_RE = re.compile(r"^(v\d+),\s*(-?0x[0-9a-fA-F]+|-?\d+)$")
SINGLE_REGISTER_RE = re.compile(r"^(v\d+)$")
INSTANCE_FIELD_RE = re.compile(r"^(v\d+),\s*(v\d+),\s*(L[^;]+;->[^\s]+)$")
STATIC_FIELD_RE = re.compile(r"^(v\d+),\s*(L[^;]+;->[^\s]+)$")

BOOLEAN_VALIDATION_CALLS = {
    "startsWith",
    "endsWith",
    "matches",
    "contains",
    "equals",
    "equalsIgnoreCase",
}

BRANCH_TARGET_RE = re.compile(r"([+-][0-9a-fA-F]+h?)$")

# Tags that mark a value as coming from the caller rather than the app itself.
EXTERNAL_STRING_TAGS = {"string_extra", "external_uri", "serializable_extra", "provider_path"}

# Callbacks on a custom WebViewClient whose parameters are supplied by the
# page currently loaded, not by an Android caller.
WEBVIEW_CLIENT_DESCRIPTOR = "Landroid/webkit/WebViewClient;"
WEB_CONTENT_CALLBACKS = ("shouldOverrideUrlLoading", "shouldInterceptRequest")


FAR_FUTURE_OFFSET = 2**31


@dataclass(frozen=True)
class GuardScope:
    end_offset: int
    source_provenances: tuple[Provenance, ...]
    origins: frozenset[str]
    validation: str
    detail: str
    # Set only for "if-nez"-style guards, where the validated region begins at the
    # jump target instead of at the branch instruction itself (see _branch_guard).
    activation_offset: int | None = None


class DataflowEngine:
    def __init__(self, max_depth: int = 4) -> None:
        self.max_depth = max_depth
        self.taint_engine = TaintEngine()
        self.dex: DexAnalysisResult | None = None
        self._cache: dict[tuple[str, tuple[tuple[Provenance, ...], ...]], MethodFlowSummary] = {}
        self._stack: set[tuple[str, tuple[tuple[Provenance, ...], ...]]] = set()

    def analyze_components(
        self, manifest: ManifestAnalysis, dex: DexAnalysisResult
    ) -> dict[str, CodeComponentAnalysis]:
        self.dex = dex
        self._cache.clear()
        self._stack.clear()

        analyses: dict[str, CodeComponentAnalysis] = {}
        for component in manifest.components:
            entry_methods = self._resolve_entry_methods(component, dex)
            if not entry_methods:
                continue

            sink_events = []
            flags = set()
            validations = set()
            path_sensitive_validations = set()
            visited_methods = set()

            for entry_method, arg_taints in entry_methods:
                try:
                    summary = self._analyze_method(entry_method, arg_taints, 0)
                except Exception as exc:  # noqa: BLE001
                    print(
                        f"[dataflow] ERROR analyzing {entry_method.signature}: {exc}",
                        file=sys.stderr,
                    )
                    traceback.print_exc(file=sys.stderr)
                    summary = MethodFlowSummary()
                sink_events.extend(summary.sink_events)
                flags.update(summary.flags)
                validations.update(summary.validations)
                path_sensitive_validations.update(self._collect_path_sensitive_validations(summary))
                visited_methods.add(entry_method.signature)

            analyses[component.name] = CodeComponentAnalysis(
                component=component,
                entry_methods=tuple(entry for entry, _ in entry_methods),
                sink_events=tuple(sink_events),
                flags=frozenset(flags),
                validations=frozenset(validations),
                path_sensitive_validations=frozenset(path_sensitive_validations),
                visited_methods=tuple(sorted(visited_methods)),
            )

        return analyses

    def analyze_webview_callbacks(self, dex: DexAnalysisResult) -> dict[str, CodeComponentAnalysis]:
        """Analyse custom WebViewClient callbacks as their own attacker surface.

        The channel here is the page already loaded in the WebView rather than
        an Android component launch, so these run regardless of whether the
        hosting component is exported.
        """
        self.dex = dex
        analyses: dict[str, CodeComponentAnalysis] = {}
        for class_descriptor in self._webview_client_classes(dex):
            component = ComponentInfo(
                name=class_descriptor,
                kind="webview-client",
                exported=False,
                implicitly_exported=False,
            )
            entry_methods = []
            for method in dex.methods_by_class.get(class_descriptor, ()):
                if method.name not in WEB_CONTENT_CALLBACKS:
                    continue
                params = self._param_registers(method)
                if len(params) < 2:
                    continue
                # params[0] is the WebView; params[1] is the URL or the request.
                args = [tuple() for _ in params]
                args[1] = (
                    self.taint_engine.source_from_root(
                        method, "web_content", f"{method.name}() web content parameter"
                    ),
                )
                entry_methods.append((method, tuple(args)))

            if not entry_methods:
                continue

            sink_events, flags, validations, path_validations, visited = [], set(), set(), set(), set()
            for entry_method, arg_taints in entry_methods:
                try:
                    summary = self._analyze_method(entry_method, arg_taints, 0)
                except Exception as exc:  # noqa: BLE001
                    print(f"[dataflow] ERROR analyzing {entry_method.signature}: {exc}", file=sys.stderr)
                    summary = MethodFlowSummary()
                sink_events.extend(summary.sink_events)
                flags.update(summary.flags)
                validations.update(summary.validations)
                path_validations.update(self._collect_path_sensitive_validations(summary))
                visited.add(entry_method.signature)

            if not sink_events:
                continue
            analyses[class_descriptor] = CodeComponentAnalysis(
                component=component,
                entry_methods=tuple(entry for entry, _ in entry_methods),
                sink_events=tuple(sink_events),
                flags=frozenset(flags),
                validations=frozenset(validations),
                path_sensitive_validations=frozenset(path_validations),
                visited_methods=tuple(sorted(visited)),
            )
        return analyses

    def _webview_client_classes(self, dex: DexAnalysisResult) -> list[str]:
        """App classes that derive from WebViewClient, directly or transitively."""
        found = []
        for descriptor in dex.app_class_descriptors:
            seen, current = set(), descriptor
            while current and current not in seen:
                seen.add(current)
                parent = dex.superclasses.get(current)
                if parent == WEBVIEW_CLIENT_DESCRIPTOR:
                    found.append(descriptor)
                    break
                current = parent
        return sorted(found)

    def _resolve_entry_methods(
        self, component: ComponentInfo, dex: DexAnalysisResult
    ) -> list[tuple[MethodRef, tuple[tuple[Provenance, ...], ...]]]:
        method_names = {
            "activity": ("onCreate", "onNewIntent", "onStart", "onResume", "doCreateView"),
            "activity-alias": ("onCreate", "onNewIntent", "onStart", "onResume", "doCreateView"),
            "service": ("onStartCommand", "onBind", "onHandleIntent"),
            "receiver": ("onReceive",),
            "provider": ("query", "openFile", "openAssetFile", "insert", "update", "delete", "getType"),
        }.get(component.kind, ())
        class_methods = self.dex.methods_by_class.get(component.name, ()) if self.dex else ()
        selected = [method for method in class_methods if method.name in method_names]
        entry_points: list[tuple[MethodRef, tuple[tuple[Provenance, ...], ...]]] = []

        for method in selected:
            param_count = len(self._param_registers(method))
            args = [tuple() for _ in range(param_count)]
            if component.kind == "receiver" and method.name == "onReceive" and param_count >= 2:
                args[1] = (self.taint_engine.source_from_root(method, "intent", "external intent parameter"),)
            elif component.kind == "service" and method.name in {"onStartCommand", "onBind", "onHandleIntent"} and param_count >= 1:
                args[0] = (self.taint_engine.source_from_root(method, "intent", "external intent parameter"),)
            elif component.kind in {"activity", "activity-alias"} and method.name == "onNewIntent" and param_count >= 1:
                args[0] = (self.taint_engine.source_from_root(method, "intent", "external intent parameter"),)
            elif component.kind == "provider" and param_count >= 1:
                args[0] = (self.taint_engine.source_from_root(method, "provider_uri", "external URI parameter"),)
            entry_points.append((method, tuple(args)))
        return entry_points

    def _analyze_method(
        self, method_ref: MethodRef, incoming_args: tuple[tuple[Provenance, ...], ...], depth: int
    ) -> MethodFlowSummary:
        cache_key = (method_ref.signature, incoming_args)
        if cache_key in self._cache:
            return self._cache[cache_key]
        if cache_key in self._stack or depth > self.max_depth or self.dex is None:
            return MethodFlowSummary()

        method_analysis = self.dex.methods.get(method_ref.signature)
        if method_analysis is None:
            return MethodFlowSummary()

        self._stack.add(cache_key)
        try:
            method = method_analysis.get_method()
            reg_taints: dict[str, tuple[Provenance, ...]] = defaultdict(tuple)
            reg_consts: dict[str, int | str] = {}
            reg_classes: dict[str, str] = {}
            field_taints: dict[str, tuple[Provenance, ...]] = {}
            array_taints: dict[str, tuple[Provenance, ...]] = {}
            intent_states: dict[str, IntentValueState] = {}
            last_result: tuple[Provenance, ...] = ()
            last_validation_result: tuple[str, tuple[Provenance, ...], str] | None = None
            last_intent_alias_source: str | None = None
            last_intent_result_state: IntentValueState | None = None
            recent_tag_sources: dict[str, tuple[Provenance, ...]] = {}
            validation_registers: dict[str, tuple[str, tuple[Provenance, ...], str]] = {}
            active_guards: list[GuardScope] = []
            pending_guards: list[GuardScope] = []
            sink_events = []
            flags = set()
            validations = set()
            return_provenances: tuple[Provenance, ...] = ()
            return_intent_state: IntentValueState | None = None
            return_validation: tuple[str, tuple[Provenance, ...], str] | None = None

            for register, taints in zip(self._param_registers(method_ref), incoming_args, strict=False):
                reg_taints[register] = cap_provenances(taints)
                self._remember_recent_tag_sources(recent_tag_sources, reg_taints[register])

            for offset, instruction in method.get_instructions_idx():
                active_guards = [guard for guard in active_guards if offset < guard.end_offset]
                if pending_guards:
                    ready = [guard for guard in pending_guards if offset >= guard.activation_offset]
                    if ready:
                        active_guards.extend(ready)
                        pending_guards = [guard for guard in pending_guards if offset < guard.activation_offset]
                name = instruction.get_name()
                output = instruction.get_output()
                # Reset per-instruction carry state; keep it only for move-result.
                if not name.startswith("move-result"):
                    last_result = ()
                    last_validation_result = None
                    last_intent_alias_source = None
                    last_intent_result_state = None

                if name.startswith("const-string"):
                    parsed = self._parse_const_string(output)
                    if parsed:
                        reg, value = parsed
                        reg_consts[reg] = value
                        reg_classes.pop(reg, None)
                        reg_taints.pop(reg, None)
                    continue

                if name.startswith("const-class"):
                    parsed = parse_const_class(output)
                    if parsed:
                        reg, value = parsed
                        reg_classes[reg] = value
                        reg_taints.pop(reg, None)
                    continue

                if name.startswith("const"):
                    parsed = self._parse_const_number(output)
                    if parsed:
                        reg, value = parsed
                        reg_consts[reg] = value
                        reg_classes.pop(reg, None)
                        reg_taints.pop(reg, None)
                    continue

                if name.startswith("move-result"):
                    dest = self._parse_single_register(output)
                    if dest:
                        reg_taints[dest] = last_result
                        self._remember_recent_tag_sources(recent_tag_sources, reg_taints[dest])
                        if last_validation_result:
                            validation_registers[dest] = last_validation_result
                        else:
                            validation_registers.pop(dest, None)
                        if last_intent_alias_source:
                            state = intent_states.get(last_intent_alias_source)
                            if state:
                                intent_states[dest] = state
                        elif last_intent_result_state:
                            intent_states[dest] = last_intent_result_state
                    # carry state already reset at the top of the loop
                    continue

                if name.startswith("move"):
                    regs = REGISTER_RE.findall(output)
                    if len(regs) >= 2:
                        reg_taints[regs[0]] = reg_taints.get(regs[1], ())
                        self._remember_recent_tag_sources(recent_tag_sources, reg_taints[regs[0]])
                        if regs[1] in reg_consts:
                            reg_consts[regs[0]] = reg_consts[regs[1]]
                        if regs[1] in reg_classes:
                            reg_classes[regs[0]] = reg_classes[regs[1]]
                        if regs[1] in array_taints:
                            array_taints[regs[0]] = array_taints[regs[1]]
                        if regs[1] in intent_states:
                            intent_states[regs[0]] = intent_states[regs[1]]
                    continue

                if name.startswith("if-"):
                    regs = REGISTER_RE.findall(output)
                    if regs:
                        guard = self._branch_guard(
                            method_ref=method_ref,
                            opcode=name,
                            output=output,
                            offset=offset,
                            registers=regs,
                            validation_registers=validation_registers,
                        )
                        if guard:
                            if guard.activation_offset is not None and offset < guard.activation_offset:
                                pending_guards.append(guard)
                            else:
                                active_guards.append(guard)
                            validations.add(guard.validation)
                    continue

                if name.startswith("aget"):
                    regs = REGISTER_RE.findall(output)
                    if len(regs) >= 2:
                        reg_taints[regs[0]] = array_taints.get(regs[1], ())
                        self._remember_recent_tag_sources(recent_tag_sources, reg_taints[regs[0]])
                    continue

                if name.startswith("aput"):
                    regs = REGISTER_RE.findall(output)
                    if len(regs) >= 2:
                        array_taints[regs[1]] = cap_provenances(
                            provenance for provenance in (*array_taints.get(regs[1], ()), *reg_taints.get(regs[0], ()))
                        )
                    continue

                if name.startswith("iget") or name.startswith("iput"):
                    parsed_field = self._parse_instance_field(output)
                    if parsed_field:
                        first_reg, _, field_sig = parsed_field
                        if name.startswith("iget"):
                            reg_taints[first_reg] = field_taints.get(field_sig, ())
                            self._remember_recent_tag_sources(recent_tag_sources, reg_taints[first_reg])
                        else:
                            field_taints[field_sig] = reg_taints.get(first_reg, ())
                    continue

                if name.startswith("sget") or name.startswith("sput"):
                    parsed_static_field = self._parse_static_field(output)
                    if parsed_static_field:
                        reg, field_sig = parsed_static_field
                        if name.startswith("sget"):
                            reg_taints[reg] = field_taints.get(field_sig, ())
                            self._remember_recent_tag_sources(recent_tag_sources, reg_taints[reg])
                        else:
                            field_taints[field_sig] = reg_taints.get(reg, ())
                    continue

                if name.startswith("return"):
                    ret_reg = self._parse_single_register(output)
                    if ret_reg:
                        return_provenances = cap_provenances([*return_provenances, *reg_taints.get(ret_reg, ())])
                        if return_intent_state is None and ret_reg in intent_states:
                            return_intent_state = intent_states[ret_reg]
                        if return_validation is None and ret_reg in validation_registers:
                            return_validation = validation_registers[ret_reg]
                    continue

                # check-cast is a type-narrowing opcode that modifies a register
                # in-place (no move-result follows it in Dalvik). Preserve whatever
                # taint the register already carries.
                if name == "check-cast":
                    # reg_taints for the cast register is unchanged; nothing to do.
                    continue

                if not name.startswith("invoke-"):
                    continue

                parsed_invoke = parse_invoke_output(output)
                if not parsed_invoke:
                    continue

                registers, target = parsed_invoke
                arg_taints = tuple(self._apply_active_guards(method_ref, reg_taints.get(reg, ()), active_guards) for reg in registers)
                const_args = tuple(reg_consts.get(reg) for reg in registers)
                target_name = _target_name(target)

                last_intent_alias_source = self._update_intent_state(
                    method_ref=method_ref,
                    target=target,
                    target_name=target_name,
                    registers=registers,
                    arg_taints=arg_taints,
                    reg_classes=reg_classes,
                    reg_consts=reg_consts,
                    intent_states=intent_states,
                )

                source_result = self._source_for_call(
                    method_ref,
                    target,
                    registers,
                    arg_taints,
                    const_args,
                    intent_states,
                    recent_tag_sources,
                )
                last_result = source_result or ()
                last_validation_result = self._pending_validation_for_call(method_ref, target_name, arg_taints, const_args)

                sink_event = self._sink_for_call(
                    method_ref=method_ref,
                    target=target,
                    target_name=target_name,
                    registers=registers,
                    arg_taints=arg_taints,
                    intent_states=intent_states,
                    active_guards=active_guards,
                )
                if sink_event:
                    sink_events.append(sink_event)

                new_flag = self._flag_for_call(target, const_args)
                if new_flag:
                    flags.add(new_flag)

                immediate_validations = self._immediate_validations_for_call(method_ref, target_name, registers, arg_taints)
                for validation, affected_registers in immediate_validations:
                    self._annotate_registers(method_ref, reg_taints, affected_registers, validation, validations)
                    self._annotate_intent_states(method_ref, intent_states, affected_registers, validation, validations)

                if target_name in {"checkCallingPermission", "checkCallingOrSelfPermission", "enforceCallingPermission", "enforceCallingOrSelfPermission"}:
                    validations.add("caller_permission_check")

                if target in self.dex.methods:
                    callee_args = arg_taints if name.endswith("static") else arg_taints[1:]
                    callee_method = self.dex.methods[target].get_method()
                    callee_ref = MethodRef(
                        class_name=callee_method.get_class_name(),
                        name=callee_method.get_name(),
                        descriptor=callee_method.get_descriptor(),
                    )
                    callee_summary = self._analyze_method(callee_ref, callee_args, depth + 1)
                    sink_events.extend(callee_summary.sink_events)
                    flags.update(callee_summary.flags)
                    validations.update(callee_summary.validations)
                    if callee_summary.return_provenances:
                        last_result = callee_summary.return_provenances
                    if callee_summary.return_intent_state:
                        last_intent_result_state = callee_summary.return_intent_state
                    if callee_summary.return_validation:
                        last_validation_result = callee_summary.return_validation
                    for field_sig, taints in callee_summary.field_taints_out.items():
                        field_taints[field_sig] = cap_provenances([*field_taints.get(field_sig, ()), *taints])
                elif not source_result and self.taint_engine.should_passthrough(target):
                    last_result = cap_provenances(provenance for taints in arg_taints for provenance in taints)
                    passthrough_state = self._passthrough_intent_state(registers, intent_states)
                    if passthrough_state:
                        last_intent_result_state = passthrough_state

                if target_name in {"setComponent", "setClass", "setClassName"} and sink_event:
                    flags.add("intent_routing_configured")

            summary = MethodFlowSummary(
                return_provenances=return_provenances,
                return_intent_state=return_intent_state,
                return_validation=return_validation,
                sink_events=tuple(sink_events),
                flags=frozenset(flags),
                validations=frozenset(validations),
                field_taints_out=dict(field_taints),
            )
            self._cache[cache_key] = summary
            return summary
        finally:
            self._stack.discard(cache_key)

    def _source_for_call(
        self,
        method_ref: MethodRef,
        target: str,
        registers: tuple[str, ...],
        arg_taints: tuple[tuple[Provenance, ...], ...],
        const_args: tuple[object | None, ...],
        intent_states: dict[str, IntentValueState],
        recent_tag_sources: dict[str, tuple[Provenance, ...]],
    ) -> tuple[Provenance, ...] | None:
        target_name = _target_name(target)
        receiver_state = intent_states.get(registers[0]) if registers else None

        # The Class returned by a resolution call is tracked separately from the
        # name that produced it, so a later concrete use of that class can be
        # told apart from the resolution on its own.
        if target == "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;" and self._has_tag(
            arg_taints[:1], EXTERNAL_STRING_TAGS
        ):
            return self._derive_provenances(
                method_ref, arg_taints[0], "resolved_class", "Class.forName()"
            )
        if (
            target_name == "loadClass"
            and target.endswith("(Ljava/lang/String;)Ljava/lang/Class;")
            and len(arg_taints) > 1
            and self._has_tag(arg_taints[1:2], EXTERNAL_STRING_TAGS)
        ):
            return self._derive_provenances(
                method_ref, arg_taints[1], "resolved_class", "loadClass()"
            )

        if target_name in {"getUrl", "toString", "getPath", "getHost", "getScheme"} and self._has_tag(
            arg_taints[:1], {"web_content"}
        ):
            return self._derive_provenances(
                method_ref, arg_taints[0], "web_content", f"{target_name}()"
            )

        if target_name == "getIntent" and target.endswith(")Landroid/content/Intent;"):
            return (self.taint_engine.source_from_root(method_ref, "intent", "getIntent()"),)
        if target_name == "getExtras" and (receiver_state or self._has_tag(arg_taints[:1], {"intent"})):
            payload_taints = self._intent_payload_source(method_ref, receiver_state, arg_taints[:1], "getExtras()")
            return self._derive_provenances(
                method_ref,
                payload_taints,
                "bundle_extra",
                "getExtras()",
                preserve_origin=False,
                carry_validations=False,
            )
        if target_name in {"getStringExtra", "getString"} and (receiver_state or self._has_tag(arg_taints[:1], {"intent", "bundle_extra"})):
            payload_taints = self._intent_payload_source(
                method_ref,
                receiver_state,
                arg_taints[:1],
                self._call_detail(target_name, const_args[1] if len(const_args) > 1 else None),
            )
            return self._derive_provenances(
                method_ref,
                payload_taints,
                "string_extra",
                self._call_detail(target_name, const_args[1] if len(const_args) > 1 else None),
                preserve_origin=False,
                carry_validations=False,
            )
        if target_name in {"getParcelableExtra", "getParcelable", "getParcelableArrayList"} and (
            receiver_state or self._has_tag(arg_taints[:1], {"intent", "bundle_extra"})
        ):
            payload_taints = self._intent_payload_source(
                method_ref,
                receiver_state,
                arg_taints[:1],
                self._call_detail(target_name, const_args[1] if len(const_args) > 1 else None),
            )
            return self._derive_provenances(
                method_ref,
                payload_taints,
                "parcelable_extra",
                self._call_detail(target_name, const_args[1] if len(const_args) > 1 else None),
                preserve_origin=False,
                carry_validations=False,
            )
        if target_name in {"getSerializableExtra", "getSerializable"} and (
            receiver_state or self._has_tag(arg_taints[:1], {"intent", "bundle_extra"})
        ):
            payload_taints = self._intent_payload_source(
                method_ref,
                receiver_state,
                arg_taints[:1],
                self._call_detail(target_name, const_args[1] if len(const_args) > 1 else None),
            )
            return self._derive_provenances(
                method_ref,
                payload_taints,
                "serializable_extra",
                self._call_detail(target_name, const_args[1] if len(const_args) > 1 else None),
                preserve_origin=False,
                carry_validations=False,
            )
        if target_name == "getBundleExtra" and (receiver_state or self._has_tag(arg_taints[:1], {"intent"})):
            payload_taints = self._intent_payload_source(
                method_ref,
                receiver_state,
                arg_taints[:1],
                self._call_detail(target_name, const_args[1] if len(const_args) > 1 else None),
            )
            return self._derive_provenances(
                method_ref,
                payload_taints,
                "bundle_extra",
                self._call_detail(target_name, const_args[1] if len(const_args) > 1 else None),
                preserve_origin=False,
                carry_validations=False,
            )
        if target_name in {"getData", "getDataString"} and (receiver_state or self._has_tag(arg_taints[:1], {"intent"})):
            data_taints = receiver_state.data_taints if receiver_state and receiver_state.data_taints else arg_taints[0]
            return self._derive_provenances(
                method_ref,
                data_taints,
                "external_uri",
                f"{target_name}()",
                preserve_origin=False,
                carry_validations=False,
            )
        if target_name == "getQueryParameter" and self._has_tag(arg_taints[:1], {"external_uri"}):
            return self._derive_provenances(
                method_ref,
                arg_taints[0],
                "external_uri",
                self._call_detail(target_name, const_args[1] if len(const_args) > 1 else None),
                preserve_origin=False,
                carry_validations=False,
            )
        if target_name in {"resolveActivity", "resolveActivityInfo", "resolveService"} and self._has_tag(
            arg_taints[:1],
            {
                "intent",
                "parcelable_extra",
                "serializable_extra",
                "intent_route_component",
                "intent_route_package",
                "intent_route_action",
                "intent_route_data",
                "intent_route_category",
            },
        ):
            return self._derive_provenances(
                method_ref,
                arg_taints[0],
                "intent_route_component",
                f"{target_name}()",
                preserve_origin=True,
                carry_validations=True,
            )
        if target_name == "getPackageName" and self._has_tag(arg_taints[:1], {"intent_route_component"}):
            return self._derive_provenances(
                method_ref,
                arg_taints[0],
                "intent_route_package",
                "getPackageName()",
                preserve_origin=True,
                carry_validations=True,
            )
        if target_name == "getHost" and self._has_tag(arg_taints[:1], {"external_uri"}):
            return self._derive_provenances(method_ref, arg_taints[0], "url_host", "getHost()")
        if target_name == "getScheme" and self._has_tag(arg_taints[:1], {"external_uri"}):
            return self._derive_provenances(method_ref, arg_taints[0], "url_scheme", "getScheme()")
        if target_name in {"getLastPathSegment", "getPath", "getPathSegments"}:
            uri_taints = arg_taints[0] if self._has_tag(arg_taints[:1], {"provider_uri", "external_uri"}) else recent_tag_sources.get("external_uri", ())
            if not uri_taints:
                uri_taints = recent_tag_sources.get("provider_uri", ())
            if not uri_taints:
                return None
            return self._derive_provenances(
                method_ref,
                uri_taints,
                "provider_path",
                f"{target_name}()",
                preserve_origin=False,
                carry_validations=False,
            )
        if target_name == "get" and target.endswith(")Ljava/lang/Object;"):
            source_taints = arg_taints[0]
            if not self._has_tag((source_taints,), {"provider_path", "external_uri", "bundle_extra", "parcelable_extra"}):
                source_taints = recent_tag_sources.get("provider_path", ()) or recent_tag_sources.get("external_uri", ())
            if not source_taints:
                return None
            index = const_args[1] if len(const_args) > 1 else None
            detail = f"get({index})" if isinstance(index, int) else "get()"
            source_tag = next(
                (
                    provenance.tag
                    for provenance in source_taints
                    if provenance.tag in {"provider_path", "external_uri", "bundle_extra", "parcelable_extra"}
                ),
                "provider_path",
            )
            return self._derive_provenances(
                method_ref,
                source_taints,
                source_tag,
                detail,
                preserve_origin=False,
                carry_validations=False,
            )
        return None

    def _sink_for_call(
        self,
        method_ref: MethodRef,
        target: str,
        target_name: str,
        registers: tuple[str, ...],
        arg_taints: tuple[tuple[Provenance, ...], ...],
        intent_states: dict[str, IntentValueState],
        active_guards: list[GuardScope],
    ):
        if target_name in {"startActivity", "startActivityForResult", "startService", "sendBroadcast"}:
            sink_reg = registers[1] if len(registers) > 1 else ""
            sink_state = intent_states.get(sink_reg)
            extra: dict[str, str] = {}
            if sink_state and sink_state.target_component:
                extra["target_component"] = sink_state.target_component
            if sink_state and sink_state.package_name:
                extra["intent_package"] = sink_state.package_name
            if sink_state and sink_state.action_name:
                extra["intent_action"] = sink_state.action_name
            route_taints = self._intent_launch_route_taints(sink_state, arg_taints[1] if len(arg_taints) > 1 else ())
            payload_taints = sink_state.payload_taints if sink_state else ()
            if route_taints:
                extra["launch_control"] = "route_control"
                return self.taint_engine.build_sink_event(
                    "intent_launch_sink",
                    method_ref,
                    target,
                    route_taints,
                    f"{target_name}()",
                    extra=extra,
                )
            if payload_taints:
                extra["launch_control"] = "payload_only"
                return self.taint_engine.build_sink_event(
                    "intent_launch_sink",
                    method_ref,
                    target,
                    payload_taints,
                    f"{target_name}()",
                    extra=extra,
                )
            if sink_state and sink_state.action_name and not sink_state.target_component and active_guards:
                control_taints = cap_provenances(
                    provenance
                    for guard in active_guards
                    for provenance in self._apply_active_guards(method_ref, guard.source_provenances, [guard])
                )
                if control_taints:
                    extra["launch_control"] = "implicit_guarded_route"
                    return self.taint_engine.build_sink_event(
                        "intent_launch_sink",
                        method_ref,
                        target,
                        control_taints,
                        f"{target_name}()",
                        extra=extra,
                    )
        if target_name in {"setComponent", "setClass", "setClassName"}:
            sink_taints = arg_taints[1:]
            if self._has_tag(sink_taints, {"string_extra", "external_uri", "serializable_extra", "parcelable_extra"}):
                return self.taint_engine.build_sink_event(
                    "intent_redirection_sink",
                    method_ref,
                    target,
                    cap_provenances(provenance for taints in sink_taints for provenance in taints),
                    f"{target_name}()",
                )
        if target_name in {"loadUrl", "evaluateJavascript", "postUrl"}:
            sink_taints = arg_taints[1:2] if len(arg_taints) > 1 else ()
            if self._has_tag(sink_taints, {"web_content"}):
                return self.taint_engine.build_sink_event(
                    "webview_callback_sink",
                    method_ref,
                    target,
                    sink_taints[0],
                    f"{target_name}()",
                )
            if self._has_tag(sink_taints, {"string_extra", "external_uri", "serializable_extra", "provider_path"}):
                return self.taint_engine.build_sink_event(
                    "webview_load_sink",
                    method_ref,
                    target,
                    sink_taints[0],
                    f"{target_name}()",
                )
        if target == "Ljava/io/File;-><init>(Ljava/lang/String;)V" and len(arg_taints) > 1:
            if self._has_tag(arg_taints[1:2], {"provider_path"}):
                return self.taint_engine.build_sink_event(
                    "provider_path_file_sink",
                    method_ref,
                    target,
                    arg_taints[1],
                    "File(path)",
                )
        if target == "Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V" and len(arg_taints) > 2:
            if self._has_tag(arg_taints[2:3], {"provider_path"}):
                return self.taint_engine.build_sink_event(
                    "provider_path_file_sink",
                    method_ref,
                    target,
                    arg_taints[2],
                    "File(parent, path)",
                )
        if target == "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;" and arg_taints[:1]:
            if self._has_tag(arg_taints[:1], EXTERNAL_STRING_TAGS):
                return self.taint_engine.build_sink_event(
                    "class_loading_sink",
                    method_ref,
                    target,
                    arg_taints[0],
                    "Class.forName()",
                    extra={"class_loading_api": "Class.forName"},
                )
        if target_name == "loadClass" and target.endswith("(Ljava/lang/String;)Ljava/lang/Class;") and len(arg_taints) > 1:
            if self._has_tag(arg_taints[1:2], EXTERNAL_STRING_TAGS):
                return self.taint_engine.build_sink_event(
                    "class_loading_sink",
                    method_ref,
                    target,
                    arg_taints[1],
                    "loadClass()",
                    extra={"class_loading_api": "loadClass"},
                )
        # A resolved class that reaches a component target or reflective
        # instantiation is a class-controlled action, not just a resolution.
        if target == "Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V" and len(arg_taints) > 2:
            if self._has_tag(arg_taints[2:3], {"resolved_class"}):
                return self.taint_engine.build_sink_event(
                    "class_use_sink", method_ref, target, arg_taints[2],
                    "Intent(context, class)", extra={"class_use": "component_target"},
                )
        if target_name in {"setClass"} and len(arg_taints) > 2:
            if self._has_tag(arg_taints[2:3], {"resolved_class"}):
                return self.taint_engine.build_sink_event(
                    "class_use_sink", method_ref, target, arg_taints[2],
                    "setClass()", extra={"class_use": "component_target"},
                )
        if target == "Ljava/lang/Class;->newInstance()Ljava/lang/Object;" and arg_taints[:1]:
            if self._has_tag(arg_taints[:1], {"resolved_class"}):
                return self.taint_engine.build_sink_event(
                    "class_use_sink", method_ref, target, arg_taints[0],
                    "newInstance()", extra={"class_use": "reflective_instantiation"},
                )
        return None

    def _flag_for_call(self, target: str, const_args: tuple[object | None, ...]) -> str | None:
        if target == "Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V" and _is_true_arg(const_args, 1):
            return "webview_js_enabled"
        if target == "Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V" and _is_true_arg(const_args, 1):
            return "webview_allow_file_access"
        if target == "Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V" and _is_true_arg(const_args, 1):
            return "webview_file_url_access"
        if target == "Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V" and _is_true_arg(
            const_args, 1
        ):
            return "webview_universal_file_access"
        if target == "Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V":
            return "webview_js_interface"
        return None

    def _pending_validation_for_call(
        self,
        method_ref: MethodRef,
        target_name: str,
        arg_taints: tuple[tuple[Provenance, ...], ...],
        const_args: tuple[object | None, ...],
    ) -> tuple[str, tuple[Provenance, ...], str] | None:
        if target_name not in BOOLEAN_VALIDATION_CALLS:
            return None
        flattened = cap_provenances(provenance for taints in arg_taints for provenance in taints)
        if not flattened:
            return None
        if not any(
            provenance.tag
            in {
                "string_extra",
                "external_uri",
                "provider_path",
                "url_host",
                "url_scheme",
                "intent_route_package",
                "intent_route_component",
            }
            for provenance in flattened
        ):
            return None
        validation = self._classify_boolean_validation(target_name, flattened, const_args)
        return validation, flattened, f"{target_name}() check"

    def _immediate_validations_for_call(
        self,
        method_ref: MethodRef,
        target_name: str,
        registers: tuple[str, ...],
        arg_taints: tuple[tuple[Provenance, ...], ...],
    ) -> tuple[tuple[str, tuple[str, ...]], ...]:
        results: list[tuple[str, tuple[str, ...]]] = []
        if target_name == "setPackage" and registers[:1] and self._has_tag(arg_taints[:1], {"intent", "parcelable_extra"}):
            # A package restriction still permits attacker-controlled routing to
            # another component in that package, so it is only partial evidence.
            results.append(("package_scope_validation", registers[:1]))
        if target_name in {"setClass", "setComponent"} and registers[:1] and self._has_tag(
            arg_taints[:1], {"intent", "parcelable_extra"}
        ):
            results.append(("component_lock_validation", registers[:1]))
        if target_name in {"getCanonicalPath", "getCanonicalFile", "normalize"} and registers[:1] and self._has_tag(
            arg_taints[:1], {"provider_path"}
        ):
            # Canonicalization is necessary but is not a containment check.
            results.append(("canonical_path_normalization", registers[:1]))
        return tuple(results)

    def _annotate_registers(
        self,
        method_ref: MethodRef,
        reg_taints: dict[str, tuple[Provenance, ...]],
        registers: tuple[str, ...],
        validation: str,
        validations: set[str],
    ) -> None:
        for register in registers:
            taints = reg_taints.get(register, ())
            if not taints:
                continue
            reg_taints[register] = cap_provenances(
                self.taint_engine.annotate_validation(provenance, validation, method_ref, f"{validation} applied")
                for provenance in taints
            )
            validations.add(validation)

    def _collect_path_sensitive_validations(self, summary: MethodFlowSummary) -> set[str]:
        return {
            validation
            for sink in summary.sink_events
            for provenance in sink.provenances
            for validation in provenance.validations
        }

    def _update_intent_state(
        self,
        method_ref: MethodRef,
        target: str,
        target_name: str,
        registers: tuple[str, ...],
        arg_taints: tuple[tuple[Provenance, ...], ...],
        reg_classes: dict[str, str],
        reg_consts: dict[str, int | str],
        intent_states: dict[str, IntentValueState],
    ) -> str | None:
        if not registers:
            return None
        owner_reg = registers[0]
        state = intent_states.get(owner_reg, IntentValueState())
        if target == "Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V" and len(registers) >= 3:
            target_class = reg_classes.get(registers[2])
            intent_states[owner_reg] = replace(state, target_component=target_class) if target_class else state
            return None
        if target == "Landroid/content/Intent;-><init>()V":
            intent_states[owner_reg] = IntentValueState()
            return None
        if target == "Landroid/content/Intent;-><init>(Landroid/content/Intent;)V" and len(registers) >= 2:
            copied = intent_states.get(registers[1])
            if copied:
                intent_states[owner_reg] = copied
            elif arg_taints[1]:
                intent_states[owner_reg] = replace(state, payload_taints=self._as_intent_payload(method_ref, arg_taints[1], "Intent(copy)"))
            return None
        if target == "Landroid/content/Intent;-><init>(Ljava/lang/String;)V" and len(registers) >= 2:
            action = reg_consts.get(registers[1])
            action_taints = self._route_taints_from_args(method_ref, arg_taints[1], "intent_route_action", "Intent(action)")
            intent_states[owner_reg] = replace(
                state,
                action_name=action if isinstance(action, str) else state.action_name,
                action_taints=cap_provenances([*state.action_taints, *action_taints]),
            )
            return None
        if target == "Landroid/content/Intent;->setClass(Landroid/content/Context;Ljava/lang/Class;)Landroid/content/Intent;" and len(registers) >= 3:
            target_class = reg_classes.get(registers[2])
            component_taints = self._route_taints_from_args(method_ref, arg_taints[2], "intent_route_component", "setClass()")
            intent_states[owner_reg] = replace(
                state,
                target_component=target_class if target_class else state.target_component,
                component_taints=cap_provenances([*state.component_taints, *component_taints]),
            )
            return owner_reg
        if target == "Landroid/content/Intent;->setClassName(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;" and len(registers) >= 3:
            class_name = reg_consts.get(registers[2])
            component_taints = self._route_taints_from_args(method_ref, arg_taints[2], "intent_route_component", "setClassName()")
            package_taints = self._route_taints_from_args(method_ref, arg_taints[1], "intent_route_package", "setClassName()")
            intent_states[owner_reg] = replace(
                state,
                target_component=f"L{class_name.replace('.', '/')};" if isinstance(class_name, str) else state.target_component,
                component_taints=cap_provenances([*state.component_taints, *component_taints]),
                package_taints=cap_provenances([*state.package_taints, *package_taints]),
            )
            return owner_reg
        if target == "Landroid/content/Intent;->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;" and len(registers) >= 2:
            component_taints = self._route_taints_from_args(method_ref, arg_taints[1], "intent_route_component", "setComponent()")
            intent_states[owner_reg] = replace(
                state,
                component_taints=cap_provenances([*state.component_taints, *component_taints]),
            )
            return owner_reg
        if target_name == "setPackage" and len(registers) >= 2:
            package_name = reg_consts.get(registers[1])
            package_taints = self._route_taints_from_args(method_ref, arg_taints[1], "intent_route_package", "setPackage()")
            intent_states[owner_reg] = replace(
                state,
                package_name=package_name if isinstance(package_name, str) else state.package_name,
                package_taints=cap_provenances([*state.package_taints, *package_taints]),
            )
            return owner_reg
        if target_name == "setAction" and len(registers) >= 2:
            action_name = reg_consts.get(registers[1])
            action_taints = self._route_taints_from_args(method_ref, arg_taints[1], "intent_route_action", "setAction()")
            intent_states[owner_reg] = replace(
                state,
                action_name=action_name if isinstance(action_name, str) else state.action_name,
                action_taints=cap_provenances([*state.action_taints, *action_taints]),
            )
            return owner_reg
        if target_name == "putExtra" and len(registers) >= 3:
            key = reg_consts.get(registers[1])
            value_taints = arg_taints[2]
            if value_taints:
                detail = self._call_detail("putExtra", key)
                intent_states[owner_reg] = replace(
                    state,
                    payload_taints=cap_provenances(
                        [
                            *state.payload_taints,
                            *self._as_intent_payload(method_ref, value_taints, detail),
                        ]
                    ),
                )
            return owner_reg
        if target_name in {"putExtras", "replaceExtras"} and len(registers) >= 2:
            incoming_payload = self._payload_from_register(method_ref, registers[1], arg_taints[1], intent_states, target_name)
            if incoming_payload:
                existing_payload = () if target_name == "replaceExtras" else state.payload_taints
                intent_states[owner_reg] = replace(
                    state,
                    payload_taints=cap_provenances([*existing_payload, *incoming_payload]),
                )
            return owner_reg
        if target_name in {"setData", "setDataAndType", "setDataAndNormalize"} and len(registers) >= 2:
            data_taints = self._route_taints_from_args(method_ref, arg_taints[1], "intent_route_data", f"{target_name}()")
            intent_states[owner_reg] = replace(
                state,
                data_taints=cap_provenances([*state.data_taints, *data_taints]),
            )
            return owner_reg
        if target_name == "addCategory" and len(registers) >= 2:
            category_taints = self._route_taints_from_args(method_ref, arg_taints[1], "intent_route_category", "addCategory()")
            intent_states[owner_reg] = replace(
                state,
                category_taints=cap_provenances([*state.category_taints, *category_taints]),
            )
            return owner_reg
        return owner_reg if target.startswith("Landroid/content/Intent;->") and target.endswith(")Landroid/content/Intent;") else None

    def _annotate_intent_states(
        self,
        method_ref: MethodRef,
        intent_states: dict[str, IntentValueState],
        registers: tuple[str, ...],
        validation: str,
        validations: set[str],
    ) -> None:
        for register in registers:
            state = intent_states.get(register)
            if not state:
                continue
            intent_states[register] = IntentValueState(
                target_component=state.target_component,
                package_name=state.package_name,
                action_name=state.action_name,
                component_taints=self._annotated_taints(method_ref, state.component_taints, validation),
                package_taints=self._annotated_taints(method_ref, state.package_taints, validation),
                action_taints=self._annotated_taints(method_ref, state.action_taints, validation),
                data_taints=self._annotated_taints(method_ref, state.data_taints, validation),
                category_taints=self._annotated_taints(method_ref, state.category_taints, validation),
                payload_taints=self._annotated_taints(method_ref, state.payload_taints, validation),
            )
            validations.add(validation)

    def _apply_active_guards(
        self, method_ref: MethodRef, provenances: tuple[Provenance, ...], active_guards: list[GuardScope]
    ) -> tuple[Provenance, ...]:
        if not provenances or not active_guards:
            return provenances
        guarded = list(provenances)
        for guard in active_guards:
            for index, provenance in enumerate(guarded):
                if provenance.origin not in guard.origins or guard.validation in provenance.validations:
                    continue
                guarded[index] = self.taint_engine.annotate_validation(provenance, guard.validation, method_ref, guard.detail)
        return cap_provenances(guarded)

    def _branch_guard(
        self,
        method_ref: MethodRef,
        opcode: str,
        output: str,
        offset: int,
        registers: list[str],
        validation_registers: dict[str, tuple[str, tuple[Provenance, ...], str]],
    ) -> GuardScope | None:
        if opcode not in {"if-eqz", "if-nez"} or not registers:
            return None
        pending = validation_registers.get(registers[0])
        if not pending:
            return None
        target = self._parse_branch_target(offset, output)
        if target is None or target <= offset:
            return None
        validation, source_provenances, detail = pending
        origins = frozenset(provenance.origin for provenance in source_provenances if provenance.origin)
        if not origins:
            return None
        if opcode == "if-eqz":
            # if-eqz branches away (to `target`) when the guard register is false,
            # so the fallthrough code up to `target` is the validated region.
            return GuardScope(target, source_provenances, origins, validation, detail)
        # if-nez branches to `target` exactly when the guard register is true, which
        # is the idiomatic "if (!valid) return;" guard-clause compiled form. The
        # validated region starts at the jump target, not at the branch itself.
        return GuardScope(
            FAR_FUTURE_OFFSET, source_provenances, origins, validation, detail, activation_offset=target
        )

    def _parse_branch_target(self, offset: int, output: str) -> int | None:
        match = BRANCH_TARGET_RE.search(output.strip())
        if not match:
            return None
        raw = match.group(1)
        magnitude = raw[1:-1] if raw.endswith("h") else raw[1:]
        delta = int(magnitude, 16) if raw.endswith("h") else int(magnitude, 10)
        delta = delta * 2
        return offset + delta if raw.startswith("+") else offset - delta

    def _classify_boolean_validation(
        self, target_name: str, provenances: tuple[Provenance, ...], const_args: tuple[object | None, ...]
    ) -> str:
        literal = next((value for value in const_args if isinstance(value, str)), None)
        tags = {provenance.tag for provenance in provenances}
        if "intent_route_package" in tags:
            return "same_package_route_validation"
        if "intent_route_component" in tags:
            return "component_resolution_validation"
        if target_name in {"equals", "equalsIgnoreCase"}:
            if literal and "url_host" in tags:
                return "url_host_exact_validation"
            if literal and "url_scheme" in tags:
                return "url_scheme_exact_validation"
            return "url_exact_match_validation"
        if target_name == "endsWith":
            return "flawed_url_validation"
        if target_name == "startsWith":
            if (
                literal
                and "provider_path" in tags
                and literal.startswith(("/", "\\"))
                and literal.endswith(("/", "\\"))
                and any("canonical_path_normalization" in provenance.validations for provenance in provenances)
            ):
                return "canonical_path_validation"
            return "flawed_url_validation"
        if target_name in {"contains", "matches"}:
            return "flawed_url_validation"
        return "url_validation"

    def _call_detail(self, target_name: str, key: object | None) -> str:
        if isinstance(key, str) and key:
            return f"{target_name}({key})"
        return f"{target_name}()"

    def _derive_provenances(
        self,
        method_ref: MethodRef,
        source_provenances: tuple[Provenance, ...],
        new_tag: str,
        detail: str,
        preserve_origin: bool = True,
        carry_validations: bool = True,
    ) -> tuple[Provenance, ...]:
        if not source_provenances:
            return (self.taint_engine.source_from_root(method_ref, new_tag, detail),)
        return cap_provenances(
            self.taint_engine.derive(
                provenance,
                new_tag,
                method_ref,
                detail,
                preserve_origin=preserve_origin,
                carry_validations=carry_validations,
            )
            for provenance in source_provenances
        )

    def _parse_const_string(self, output: str) -> tuple[str, str] | None:
        match = CONST_STR_RE.match(output)
        if not match:
            return None
        return match.group(1), match.group(2)

    def _parse_const_number(self, output: str) -> tuple[str, int] | None:
        match = CONST_NUM_RE.match(output)
        if not match:
            return None
        raw = match.group(2)
        value = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
        return match.group(1), value

    def _parse_single_register(self, output: str) -> str | None:
        match = SINGLE_REGISTER_RE.match(output)
        if not match:
            return None
        return match.group(1)

    def _parse_instance_field(self, output: str) -> tuple[str, str, str] | None:
        match = INSTANCE_FIELD_RE.match(output)
        if not match:
            return None
        return match.group(1), match.group(2), match.group(3)

    def _parse_static_field(self, output: str) -> tuple[str, str] | None:
        match = STATIC_FIELD_RE.match(output)
        if not match:
            return None
        return match.group(1), match.group(2)

    def _param_registers(self, method_ref: MethodRef) -> tuple[str, ...]:
        if self.dex is None:
            return ()
        method_analysis = self.dex.methods.get(method_ref.signature)
        if method_analysis is None:
            return ()
        info = method_analysis.get_method().get_information()
        return tuple(f"v{register}" for register, _ in info.get("params", ()))

    def _has_tag(self, taints: tuple[tuple[Provenance, ...], ...], expected: set[str]) -> bool:
        return any(provenance.tag in expected for reg_taints in taints for provenance in reg_taints)

    def _remember_recent_tag_sources(
        self,
        recent_tag_sources: dict[str, tuple[Provenance, ...]],
        taints: tuple[Provenance, ...],
    ) -> None:
        for tag in {"intent", "external_uri", "provider_uri", "provider_path", "bundle_extra", "parcelable_extra", "string_extra"}:
            tagged = tuple(provenance for provenance in taints if provenance.tag == tag)
            if tagged:
                recent_tag_sources[tag] = cap_provenances(tagged)

    def _intent_payload_source(
        self,
        method_ref: MethodRef,
        state: IntentValueState | None,
        fallback_taints: tuple[tuple[Provenance, ...], ...],
        detail: str,
    ) -> tuple[Provenance, ...]:
        if state and state.payload_taints:
            return state.payload_taints
        return self._as_intent_payload(method_ref, fallback_taints[0] if fallback_taints else (), detail)

    def _as_intent_payload(
        self,
        method_ref: MethodRef,
        source_taints: tuple[Provenance, ...],
        detail: str,
    ) -> tuple[Provenance, ...]:
        if not source_taints:
            return ()
        return cap_provenances(
            self.taint_engine.derive(
                provenance,
                "intent_payload",
                method_ref,
                detail,
                preserve_origin=False,
                carry_validations=True,
            )
            for provenance in source_taints
        )

    def _route_taints_from_args(
        self,
        method_ref: MethodRef,
        source_taints: tuple[Provenance, ...],
        route_tag: str,
        detail: str,
    ) -> tuple[Provenance, ...]:
        if not source_taints:
            return ()
        return cap_provenances(
            self.taint_engine.derive(
                provenance,
                route_tag,
                method_ref,
                detail,
                preserve_origin=False,
                carry_validations=True,
            )
            for provenance in source_taints
        )

    def _payload_from_register(
        self,
        method_ref: MethodRef,
        register: str,
        arg_taints: tuple[Provenance, ...],
        intent_states: dict[str, IntentValueState],
        detail: str,
    ) -> tuple[Provenance, ...]:
        state = intent_states.get(register)
        if state and state.payload_taints:
            return state.payload_taints
        return self._as_intent_payload(method_ref, arg_taints, f"{detail}()")

    def _intent_launch_route_taints(
        self,
        state: IntentValueState | None,
        direct_taints: tuple[Provenance, ...],
    ) -> tuple[Provenance, ...]:
        route_taints = list(direct_taints)
        if state:
            route_taints.extend(state.component_taints)
            route_taints.extend(state.package_taints)
            if not state.target_component or state.component_taints or state.package_taints:
                route_taints.extend(state.action_taints)
                route_taints.extend(state.data_taints)
                route_taints.extend(state.category_taints)
        return cap_provenances(route_taints)

    def _annotated_taints(
        self,
        method_ref: MethodRef,
        taints: tuple[Provenance, ...],
        validation: str,
    ) -> tuple[Provenance, ...]:
        if not taints:
            return ()
        return cap_provenances(
            self.taint_engine.annotate_validation(provenance, validation, method_ref, f"{validation} applied")
            for provenance in taints
        )

    def _passthrough_intent_state(
        self,
        registers: tuple[str, ...],
        intent_states: dict[str, IntentValueState],
    ) -> IntentValueState | None:
        for register in registers:
            state = intent_states.get(register)
            if state:
                return state
        return None


def _target_name(target_signature: str) -> str:
    return target_signature.split("->", 1)[1].split("(", 1)[0]


def _is_true_arg(values: tuple[object | None, ...], index: int) -> bool:
    return len(values) > index and values[index] == 1
