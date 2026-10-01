from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path

from context_sast.models import Finding

EVIDENCE_DIR_PREFIX = "context-sast-evidence-"
# Only reap another run's leftovers once they are older than any plausible live
# scan: jadx itself is capped at 300 s below.
STALE_EVIDENCE_AGE_S = 3600.0

TRACE_ENTRY_RE = re.compile(r"^(?P<class>[A-Za-z0-9_.$]+)\.(?P<method>[A-Za-z0-9_$<>]+): (?P<detail>.+)$")
CALL_TOKEN_RE = re.compile(r"([A-Za-z_$][A-Za-z0-9_$]*)\(")
MANIFEST_NAME_RE = re.compile(r'name="([^"]+)"')
MANIFEST_TAG_RE = re.compile(r"<([a-zA-Z-]+)\b")


class EvidenceResolver:
    def __init__(self, apk_path: str, artifact_root: Path | None = None) -> None:
        self.apk_path = Path(apk_path)
        self._artifact_root = artifact_root
        self._temp_root: Path | None = None
        self._source_root: Path | None = None
        self._manifest_path: Path | None = None
        self._manifest_lines: list[str] | None = None
        self._errors: list[str] = []
        self._source_lines_cache: dict[Path, list[str]] = {}
        self._method_bounds_cache: dict[tuple[Path, str], tuple[int | None, int | None]] = {}
        self._class_path_cache: dict[str, Path | None] = {}
        # Tracks whether the one-shot full decompile has been attempted.
        self._jadx_decompile_done: bool = False

    def __enter__(self) -> EvidenceResolver:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        if self._temp_root is not None:
            # Evidence snippets are optional and the scan response is already
            # assembled by now, so releasing this scratch directory must never
            # be able to fail the scan.
            _remove_tree_best_effort(self._temp_root)
            self._temp_root = None

    def resolve_finding(self, finding: Finding) -> list[dict[str, object]]:
        blocks: list[dict[str, object]] = []
        seen: set[tuple[str, int | None, int | None, str]] = set()
        for entry in finding.source_to_sink:
            block = self._resolve_trace_entry(entry, finding)
            if block is None:
                block = self._fallback_block(entry)
            key = (
                str(block.get("file", "")),
                _as_optional_int(block.get("start_line")),
                _as_optional_int(block.get("highlight_line")),
                "\n".join(str(line.get("text", "")) for line in block.get("lines", [])),
            )
            if key in seen:
                continue
            seen.add(key)
            blocks.append(block)
        return blocks

    def _resolve_trace_entry(self, entry: str, finding: Finding) -> dict[str, object] | None:
        if entry.startswith("AndroidManifest.xml:"):
            return self._resolve_manifest_block(finding)

        match = TRACE_ENTRY_RE.match(str(entry))
        if not match:
            return None

        source_path = self._resolve_source_path(match.group("class"))
        if source_path is None:
            return None

        lines = self._read_source_lines(source_path)
        method_name = match.group("method")
        detail = match.group("detail")
        method_start, method_end = self._cached_method_bounds(source_path, lines, method_name)
        if method_start is None or method_end is None:
            return self._build_block(
                file=self._display_path(source_path),
                language=_language_for_path(source_path),
                lines=_line_slice(lines, 1, min(len(lines), 11), highlight=None),
                highlight_line=None,
            )

        focus_line = self._find_focus_line(lines, method_start, method_end, detail) or method_start
        snippet_start = max(method_start, focus_line - 5)
        snippet_end = min(method_end, focus_line + 5)
        return self._build_block(
            file=self._display_path(source_path),
            language=_language_for_path(source_path),
            lines=_line_slice(lines, snippet_start, snippet_end, highlight=focus_line),
            highlight_line=focus_line,
        )

    def _resolve_manifest_block(self, finding: Finding) -> dict[str, object] | None:
        manifest_path = self._manifest_file()
        if manifest_path is None or not manifest_path.exists():
            return None

        lines = self._read_manifest_lines(manifest_path)
        component_name = self._manifest_component_name(finding)
        tag_name = self._manifest_component_tag(finding)
        if not component_name or not tag_name:
            return self._build_block(
                file="AndroidManifest.xml",
                language="xml",
                lines=_line_slice(lines, 1, min(len(lines), 12), highlight=None),
                highlight_line=None,
            )

        candidate_names = {component_name}
        if "." in component_name:
            candidate_names.add(f".{component_name.rsplit('.', 1)[-1]}")

        start_line = None
        for index, line in enumerate(lines, start=1):
            if f"<{tag_name}" not in line:
                continue
            header_lines = [line]
            scan_index = index
            while ">" not in header_lines[-1] and scan_index < len(lines):
                scan_index += 1
                header_lines.append(lines[scan_index - 1])
            header_blob = "\n".join(header_lines)
            if "android:name" not in header_blob:
                continue
            if any(name in header_blob for name in candidate_names):
                start_line = index
                break

        if start_line is None:
            return None

        end_line = start_line
        current_line = lines[start_line - 1]
        if "/>" not in current_line:
            closing = f"</{tag_name}>"
            for index in range(start_line, len(lines)):
                if closing in lines[index]:
                    end_line = index + 1
                    break
            else:
                end_line = min(len(lines), start_line + 12)

        return self._build_block(
            file="AndroidManifest.xml",
            language="xml",
            lines=_line_slice(lines, start_line, end_line, highlight=start_line),
            highlight_line=start_line,
        )

    def _manifest_component_name(self, finding: Finding) -> str | None:
        manifest_entry = finding.extras.get("manifest_entry") if finding.extras else None
        if manifest_entry:
            match = MANIFEST_NAME_RE.search(manifest_entry)
            if match:
                return match.group(1)
        return finding.affected_component or None

    def _manifest_component_tag(self, finding: Finding) -> str | None:
        manifest_entry = finding.extras.get("manifest_entry") if finding.extras else None
        if not manifest_entry:
            return None
        match = MANIFEST_TAG_RE.search(manifest_entry)
        if match:
            return match.group(1)
        return None

    def _resolve_source_path(self, class_name: str) -> Path | None:
        if class_name in self._class_path_cache:
            return self._class_path_cache[class_name]

        # Ensure the one-shot jadx decompile has run before trying to find anything.
        self._ensure_artifacts()

        source_root = self._source_tree()
        if source_root is None or not source_root.exists():
            self._class_path_cache[class_name] = None
            return None

        resolved = self._find_existing_source_path(source_root, class_name)
        self._class_path_cache[class_name] = resolved
        return resolved

    def _find_method_bounds(
        self, lines: list[str], file_stem: str, method_name: str
    ) -> tuple[int | None, int | None]:
        target_name = file_stem if method_name == "<init>" else method_name
        declaration_line = None

        for index, line in enumerate(lines, start=1):
            if not _looks_like_method_declaration(line, target_name):
                continue
            declaration_line = index
            break

        if declaration_line is None:
            return None, None

        brace_line = declaration_line
        while brace_line <= len(lines) and "{" not in lines[brace_line - 1]:
            brace_line += 1
        if brace_line > len(lines):
            return declaration_line, min(len(lines), declaration_line + 10)

        balance = 0
        opened = False
        for index in range(brace_line, len(lines) + 1):
            text = lines[index - 1]
            balance += text.count("{")
            if "{" in text:
                opened = True
            balance -= text.count("}")
            if opened and balance <= 0:
                return declaration_line, index
        return declaration_line, len(lines)

    def _find_focus_line(self, lines: list[str], start_line: int, end_line: int, detail: str) -> int | None:
        token = _primary_token(detail)
        hints = _detail_hints(detail)
        best_line = None
        best_score = -1

        for line_no in range(start_line, end_line + 1):
            text = lines[line_no - 1]
            score = 0
            if token and token in text:
                score += 10
            for hint in hints:
                if hint and hint in text:
                    score += 4
            if detail.endswith(" applied") and not token and text.strip().startswith("if "):
                score += 2
            if score > best_score:
                best_score = score
                best_line = line_no

        return best_line if best_score > 0 else None

    def _build_block(
        self,
        *,
        file: str,
        language: str,
        lines: list[dict[str, object]],
        highlight_line: int | None,
    ) -> dict[str, object]:
        start_line = lines[0]["number"] if lines and lines[0]["number"] is not None else None
        end_line = lines[-1]["number"] if lines and lines[-1]["number"] is not None else None
        return {
            "file": file,
            "language": language,
            "start_line": start_line,
            "end_line": end_line,
            "highlight_line": highlight_line,
            "lines": lines,
        }

    def _fallback_block(self, entry: str) -> dict[str, object]:
        return {
            "file": "Trace",
            "language": "text",
            "start_line": None,
            "end_line": None,
            "highlight_line": None,
            "lines": [{"number": None, "text": entry, "highlight": False}],
        }

    def _display_path(self, source_path: Path) -> str:
        source_root = self._source_tree()
        if source_root is None:
            return source_path.name
        try:
            return source_path.relative_to(source_root).as_posix()
        except ValueError:
            return source_path.name

    def _source_tree(self) -> Path | None:
        if self._source_root is not None:
            return self._source_root
        self._ensure_artifacts()
        return self._source_root

    def _manifest_file(self) -> Path | None:
        if self._manifest_path is not None:
            return self._manifest_path
        self._ensure_artifacts()
        return self._manifest_path

    def _ensure_artifacts(self) -> None:
        """Resolve evidence from supplied artifacts first, then fall back to jadx."""
        if self._jadx_decompile_done:
            return
        if self._artifact_root is not None:
            source_root = _pick_existing_path(
                self._artifact_root / "sources",
                self._artifact_root,
            )
            manifest_path = _pick_existing_file(
                self._artifact_root / "resources" / "AndroidManifest.xml",
                self._artifact_root / "AndroidManifest.xml",
            )
            if source_root is not None or manifest_path is not None:
                self._source_root = source_root
                self._manifest_path = manifest_path
                self._jadx_decompile_done = True
                return
        self._jadx_decompile_done = True  # mark before the call so re-entrant callers short-circuit

        self._ensure_temp_root()
        self._run_jadx_full()

    def _ensure_temp_root(self) -> Path:
        if self._temp_root is None:
            # Deliberately not tempfile.TemporaryDirectory: on Windows its cleanup
            # path calls os.chmod on the directory outside its own error guard, so
            # a handle still held by the jadx JVM surfaces as PermissionError
            # (WinError 5) even with ignore_cleanup_errors=True. close() removes
            # this directory on our own terms instead.
            _reap_stale_evidence_dirs()
            self._temp_root = Path(tempfile.mkdtemp(prefix=EVIDENCE_DIR_PREFIX))
        return self._temp_root

    def _run_jadx_full(self) -> None:
        """Decompile the entire APK once with jadx.

        Output layout inside the temp dir:
          sources/   – decompiled Java/Kotlin sources
          resources/ – decoded resources including AndroidManifest.xml
        """
        jadx_cmd = shutil.which("jadx") or shutil.which("jadx.bat")
        if not jadx_cmd:
            self._errors.append("jadx not found on PATH; cannot resolve evidence snippets")
            return

        temp_root = self._ensure_temp_root()
        jadx_out = temp_root / "jadx_out"
        jadx_out.mkdir(parents=True, exist_ok=True)

        try:
            completed = subprocess.run(
                [
                    jadx_cmd,
                    "--output-dir", str(jadx_out),
                    "--quiet",
                    str(self.apk_path),
                ],
                capture_output=True,
                text=True,
                timeout=300,  # 5-minute hard limit; large APKs can be slow
            )
            if completed.returncode not in {0, 1}:
                self._errors.append(f"jadx failed (rc={completed.returncode}): {completed.stderr.strip()[:400]}")
        except subprocess.TimeoutExpired:
            self._errors.append("jadx timed out after 300 s")
        except OSError as error:
            self._errors.append(f"jadx OSError: {error}")
            return

        # jadx writes sources to <out>/sources/ and resources to <out>/resources/
        self._source_root = _pick_existing_path(
            jadx_out / "sources",
            jadx_out,
        )
        self._manifest_path = _pick_existing_file(
            jadx_out / "resources" / "AndroidManifest.xml",
            jadx_out / "AndroidManifest.xml",
        )

    def _read_source_lines(self, source_path: Path) -> list[str]:
        cached = self._source_lines_cache.get(source_path)
        if cached is not None:
            return cached
        lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
        self._source_lines_cache[source_path] = lines
        return lines

    def _read_manifest_lines(self, manifest_path: Path) -> list[str]:
        if self._manifest_lines is not None:
            return self._manifest_lines
        self._manifest_lines = manifest_path.read_text(encoding="utf-8", errors="replace").splitlines()
        return self._manifest_lines

    def _cached_method_bounds(
        self, source_path: Path, lines: list[str], method_name: str
    ) -> tuple[int | None, int | None]:
        key = (source_path, method_name)
        cached = self._method_bounds_cache.get(key)
        if cached is not None:
            return cached
        bounds = self._find_method_bounds(lines, source_path.stem, method_name)
        self._method_bounds_cache[key] = bounds
        return bounds

    def _find_existing_source_path(self, source_root: Path, class_name: str) -> Path | None:
        normalized = class_name.replace(".", "/")
        candidates = (normalized, normalized.split("$", 1)[0])
        for candidate in candidates:
            for extension in (".java", ".kt"):
                direct = source_root / f"{candidate}{extension}"
                if direct.exists():
                    return direct
        simple_name = normalized.rsplit("/", 1)[-1].split("$", 1)[0]
        for extension in (".java", ".kt"):
            match = next(source_root.rglob(f"{simple_name}{extension}"), None)
            if match is not None:
                return match
        return None



def _pick_existing_path(*paths: Path) -> Path | None:
    for path in paths:
        if path.exists() and path.is_dir():
            return path
    return None


def _pick_existing_file(*paths: Path) -> Path | None:
    for path in paths:
        if path.exists() and path.is_file():
            return path
    return None


def _line_slice(
    lines: list[str], start_line: int, end_line: int, *, highlight: int | None
) -> list[dict[str, object]]:
    snippet: list[dict[str, object]] = []
    for line_no in range(start_line, end_line + 1):
        snippet.append(
            {
                "number": line_no,
                "text": lines[line_no - 1],
                "highlight": highlight is not None and line_no == highlight,
            }
        )
    return snippet


def _looks_like_method_declaration(line: str, method_name: str) -> bool:
    if method_name not in line:
        return False
    match = re.search(rf"\b{re.escape(method_name)}\s*\(", line)
    if not match:
        return False
    if match.start() > 0 and line[match.start() - 1] == ".":
        return False
    stripped = line.strip()
    if stripped.startswith(("if ", "for ", "while ", "switch ", "return ", "catch ")):
        return False
    return not stripped.endswith(";")


def _primary_token(detail: str) -> str | None:
    match = CALL_TOKEN_RE.search(detail)
    if match:
        return match.group(1)
    if detail.endswith(" applied"):
        return "if"
    return None


def _detail_hints(detail: str) -> tuple[str, ...]:
    hints: list[str] = []
    call_match = CALL_TOKEN_RE.search(detail)
    if call_match:
        args = detail[call_match.end() : detail.rfind(")")]
        normalized = args.strip().strip('"').strip("'")
        if normalized:
            hints.append(normalized)
    return tuple(hints)


def _language_for_path(path: Path) -> str:
    if path.suffix == ".kt":
        return "kotlin"
    return "java"


def _as_optional_int(value: object) -> int | None:
    return value if isinstance(value, int) else None


def _clear_readonly_tree(root: Path) -> None:
    """Drop read-only attributes so a retry of rmtree can succeed. Never raises."""
    for directory, dir_names, file_names in os.walk(root, onerror=lambda _error: None):
        for name in (*dir_names, *file_names):
            try:
                os.chmod(os.path.join(directory, name), stat.S_IWRITE)
            except OSError:
                pass


def _remove_tree_best_effort(root: Path, attempts: int = 3, delay_s: float = 0.4) -> None:
    """Delete a disposable directory tree without ever raising.

    On Windows the jadx JVM can hold handles under the tree for a moment after
    the batch wrapper returns, so the first removal can legitimately fail. A
    directory that still refuses to go is left behind and reaped by a later run
    rather than turned into a scan failure.
    """
    for attempt in range(attempts):
        _clear_readonly_tree(root)
        shutil.rmtree(root, ignore_errors=True)
        if not root.exists():
            return
        if attempt + 1 < attempts:
            time.sleep(delay_s)


def _reap_stale_evidence_dirs() -> None:
    """Remove evidence directories abandoned by earlier runs. Never raises."""
    cutoff = time.time() - STALE_EVIDENCE_AGE_S
    try:
        candidates = list(Path(tempfile.gettempdir()).glob(f"{EVIDENCE_DIR_PREFIX}*"))
    except OSError:
        return
    for candidate in candidates:
        try:
            if not candidate.is_dir() or candidate.stat().st_mtime > cutoff:
                continue
        except OSError:
            continue
        _remove_tree_best_effort(candidate, attempts=1)
