(function () {
  const state = {
    busy: false,
    result: null,
  };

  const els = {
    upload: document.getElementById("apk-upload"),
    uploadTrigger: document.getElementById("upload-trigger"),
    status: document.getElementById("scan-status"),
    resultShell: document.getElementById("result-shell"),
    emptyState: document.getElementById("empty-state"),
    packageName: document.getElementById("package-name"),
    packageMeta: document.getElementById("package-meta"),
    statStrip: document.getElementById("stat-strip"),
    findingsList: document.getElementById("findings-list"),
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  function init() {
    if (!els.upload || !els.uploadTrigger) {
      return;
    }
    els.uploadTrigger.addEventListener("click", openFilePicker);
    els.upload.addEventListener("change", onUpload);
    updateUploadState();
    render();
  }

  function openFilePicker() {
    if (state.busy) {
      return;
    }
    els.upload.click();
  }

  async function onUpload(event) {
    const [file] = event.target.files || [];
    if (!file || state.busy) {
      return;
    }
    event.target.value = "";

    const formData = new FormData();
    formData.append("apk", file, file.name);

    setBusy(true, `Scanning ${file.name}...`);
    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        body: formData,
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.error || "Scan failed");
      }
      state.result = payload.results?.[0] || null;
      setBusy(false, `scanned ${file.name}`);
    } catch (error) {
      state.result = null;
      setBusy(false, `scan failed: ${error.message}`, true);
    }
  }

  function setBusy(busy, label, failed = false) {
    state.busy = busy;
    els.status.textContent = label;
    els.status.classList.toggle("busy", busy);
    els.status.classList.toggle("failed", failed);
    updateUploadState();
    render();
  }

  function updateUploadState() {
    if (!els.upload || !els.uploadTrigger) {
      return;
    }
    els.upload.disabled = state.busy;
    els.uploadTrigger.disabled = state.busy;
    els.uploadTrigger.classList.toggle("upload-button-busy", state.busy);
    els.uploadTrigger.textContent = state.busy ? "Scanning" : "Upload APK";
  }

  function render() {
    if (!state.result) {
      els.resultShell.classList.add("hidden");
      els.emptyState.classList.remove("hidden");
      return;
    }

    const findings = Array.isArray(state.result.findings) ? state.result.findings : [];
    els.emptyState.classList.add("hidden");
    els.resultShell.classList.remove("hidden");
    els.packageName.textContent = state.result.package_name || "Unknown package";
    els.packageMeta.textContent = buildHeaderMeta(state.result, findings);
    renderStatStrip(findings);
    renderFindings(findings);
  }

  function renderStatStrip(findings) {
    const counts = {
      findings: findings.length,
      high: findings.filter((finding) => finding.severity === "HIGH").length,
      medium: findings.filter((finding) => finding.severity === "MEDIUM").length,
      components: new Set(findings.map((finding) => finding.affected_component)).size,
    };
    els.statStrip.innerHTML = [
      statCell("findings", counts.findings, ""),
      statCell("high", counts.high, counts.high ? "is-high" : ""),
      statCell("medium", counts.medium, counts.medium ? "is-medium" : ""),
      statCell("components", counts.components, ""),
    ].join("");
  }

  function statCell(key, value, valueClass) {
    return `
      <div class="stat-cell">
        <dt class="stat-key">${escapeHtml(key)}</dt>
        <dd class="stat-value ${valueClass}">${escapeHtml(String(value))}</dd>
      </div>
    `;
  }

  function renderFindings(findings) {
    els.findingsList.innerHTML = "";

    if (!findings.length) {
      els.findingsList.appendChild(buildEmptyFindingsCard());
      return;
    }

    findings.forEach((finding, index) => {
      els.findingsList.appendChild(buildFindingCard(finding, index));
    });
  }

  function buildEmptyFindingsCard() {
    const row = document.createElement("article");
    row.className = "finding finding-clean";
    row.innerHTML = `
      <div class="finding-rail">00</div>
      <div class="finding-body">
        <div class="finding-head">
          <h2 class="finding-title">No findings reported by the current detector set</h2>
          <span class="severity-label severity-clean">clean</span>
        </div>
      </div>
    `;
    return row;
  }

  function buildFindingCard(finding, index) {
    const extras = finding.extras || {};
    const evidenceBlocks = buildEvidenceBlocks(finding.evidence_blocks);
    const row = document.createElement("article");
    row.className = `finding finding-${String(finding.severity || "").toLowerCase()}`;
    row.innerHTML = `
      <div class="finding-rail">${escapeHtml(ordinal(index))}</div>
      <div class="finding-body">
        <div class="finding-head">
          <h2 class="finding-title">${escapeHtml(finding.title)}</h2>
          <span class="severity-label ${severityClass(finding.severity)}">${escapeHtml(String(finding.severity || "").toLowerCase())} severity</span>
        </div>

        <div class="finding-facts">
          <span class="fact-key">component</span>
          <p class="fact-value is-mono">${escapeHtml(finding.affected_component)}</p>
          <span class="fact-key">issue</span>
          <p class="fact-value">${escapeHtml(finding.evidence)}</p>
          <span class="fact-key">fix</span>
          <p class="fact-value">${escapeHtml(finding.remediation)}</p>
        </div>

        <div class="token-row">
          <span class="token token-accent">${escapeHtml(humanDetectorName(finding.detector))}</span>
          <span class="token">${escapeHtml(String(finding.confidence || "").toLowerCase())} confidence</span>
          <span class="token">${escapeHtml(extras.component_exported === "true" ? "exported" : "internal")}</span>
          <span class="token">${escapeHtml(permissionChip(extras))}</span>
        </div>

        <div class="evidence-list">${evidenceBlocks}</div>
      </div>
    `;
    return row;
  }

  function ordinal(index) {
    return String(index + 1).padStart(2, "0");
  }

  function buildEvidenceBlocks(blocks) {
    if (!Array.isArray(blocks) || !blocks.length) {
      return `
        <section class="evidence-item">
          <div class="evidence-file"><span class="evidence-path">evidence unavailable</span></div>
          <div class="code-panel">
            <div class="code-row">
              <span class="code-number"></span>
              <span class="code-text">The scan did not return nearby code for this finding.</span>
            </div>
          </div>
        </section>
      `;
    }
    return blocks.map(renderSnippetBlock).join("");
  }

  function renderSnippetBlock(block) {
    const lines = Array.isArray(block.lines) ? block.lines : [];
    const file = String(block.file || "Trace");
    const range = formatLineRange(block.start_line, block.end_line);
    const renderedLines = lines
      .map((line) => {
        const lineNumber = line.number == null ? "" : escapeHtml(String(line.number));
        const lineText = escapeHtml(String(line.text || ""));
        const highlightClass = line.highlight ? " code-row-highlight" : "";
        return `
          <div class="code-row${highlightClass}">
            <span class="code-number">${lineNumber}</span>
            <span class="code-text">${lineText || "&nbsp;"}</span>
          </div>
        `;
      })
      .join("");

    return `
      <section class="evidence-item">
        <div class="evidence-file">
          <span class="evidence-path">${escapeHtml(file)}</span>${range ? `<span class="evidence-range">${escapeHtml(range)}</span>` : ""}
        </div>
        <div class="code-panel">${renderedLines}</div>
      </section>
    `;
  }

  function buildHeaderMeta(result, findings) {
    const apk = shortApkName(result.apk_path);
    if (!findings.length) {
      return `${apk} — no findings`;
    }
    const plural = findings.length === 1 ? "finding" : "findings";
    return `${apk} — ${findings.length} ${plural}`;
  }

  function humanDetectorName(detector) {
    switch (detector) {
      case "intent_redirection":
        return "Intent Redirection";
      case "webview_misconfiguration":
        return "WebView Misconfiguration";
      case "insecure_content_provider":
        return "Insecure Content Provider";
      case "deep_link_abuse":
        return "Deep Link Abuse";
      case "arbitrary_class_loading":
        return "Arbitrary Class Loading";
      default:
        return detector;
    }
  }

  function permissionChip(extras) {
    const level = extras.component_permission_level || "none";
    if (level === "none") {
      return "no permission gate";
    }
    return `${level} permission`;
  }

  function shortApkName(path) {
    const value = String(path || "");
    const parts = value.split(/[/\\]/);
    return parts[parts.length - 1] || value || "-";
  }

  function severityClass(severity) {
    const value = String(severity || "").toLowerCase();
    if (value === "high") {
      return "severity-high";
    }
    if (value === "medium") {
      return "severity-medium";
    }
    return "severity-clean";
  }

  function formatLineRange(startLine, endLine) {
    if (typeof startLine !== "number") {
      return "";
    }
    if (typeof endLine !== "number" || endLine === startLine) {
      return `line ${startLine}`;
    }
    return `lines ${startLine}-${endLine}`;
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }
})();
