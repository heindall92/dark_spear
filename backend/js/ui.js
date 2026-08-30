export function renderStep(step) {
  const feed = document.getElementById("steps-feed");
  const div = document.createElement("div");
  div.className = `step ${step.verdict || ""}`;
  const title = document.createElement("div");
  title.textContent = `[${step.tool} ${JSON.stringify(step.args)}] verdict=${step.verdict}`;
  div.appendChild(title);
  const detail = [step.output || step.stdout || "", step.stderr || ""].filter(Boolean).join("\n");
  if (detail) {
    const pre = document.createElement("pre");
    pre.className = "step-detail";
    pre.textContent = String(detail).slice(0, 2500);
    div.appendChild(pre);
  }
  feed.appendChild(div);
  feed.scrollTop = feed.scrollHeight;
}

export function showConfirmModal(decision, onApprove, onReject) {
  const modal = document.getElementById("confirm-modal");
  const text = document.getElementById("confirm-text");
  text.textContent = `Herramienta peligrosa: ${decision.tool} ${JSON.stringify(decision.args)} — ${decision.reasoning}`;
  modal.hidden = false;
  const approveBtn = document.getElementById("confirm-approve");
  const rejectBtn = document.getElementById("confirm-reject");
  const cleanup = () => {
    modal.hidden = true;
    approveBtn.onclick = null;
    rejectBtn.onclick = null;
  };
  approveBtn.onclick = () => { cleanup(); onApprove(); };
  rejectBtn.onclick = () => { cleanup(); onReject(); };
}

export function renderKeyList(keys, selectedLabels) {
  const container = document.getElementById("key-list");
  container.innerHTML = "";
  if (keys.length === 0) {
    container.textContent = "No hay keys guardadas todavía.";
    return;
  }
  for (const k of keys) {
    const row = document.createElement("div");
    row.className = "key-row";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.id = `key-checkbox-${k.label}`;
    checkbox.checked = selectedLabels.has(k.label);
    checkbox.onchange = () => {
      if (checkbox.checked) selectedLabels.add(k.label);
      else selectedLabels.delete(k.label);
      document.getElementById("manage-keys-btn").textContent =
        `Gestionar keys (${selectedLabels.size} seleccionadas)`;
    };
    const label = document.createElement("label");
    label.htmlFor = checkbox.id;
    label.textContent = `${k.label} (****${k.last4}) — reset cada ${k.window_hours}h`;
    row.appendChild(checkbox);
    row.appendChild(label);
    container.appendChild(row);
  }
}

function formatDuration(seconds) {
  const totalMinutes = Math.ceil(seconds / 60);
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  if (hours === 0) return `${minutes}min`;
  if (minutes === 0) return `${hours}h`;
  return `${hours}h ${minutes}min`;
}

export function renderPhaseIndicator(phase, phaseNames) {
  document.getElementById("phase-indicator").textContent = `Fase ${phase}/4: ${phaseNames[phase]}`;
  document.getElementById("advance-phase-btn").disabled = phase >= 4;
}

export function renderWaitingForQuota(retryAfterHintSeconds) {
  const feed = document.getElementById("steps-feed");
  const div = document.createElement("div");
  div.className = "step waiting_for_quota";
  div.textContent = `Todas las keys agotadas. Reintenta automáticamente en ~${formatDuration(retryAfterHintSeconds)}.`;
  feed.appendChild(div);
  feed.scrollTop = feed.scrollHeight;
}

export function renderFindingsPanel(findings, { onAccept, onReject }) {
  const container = document.getElementById("findings-list");
  container.innerHTML = "";
  const pending = findings.filter((f) => f.status === "proposed" || f.status === "edited");
  const others = findings.filter((f) => f.status === "accepted" || f.status === "rejected");
  for (const f of [...pending, ...others]) {
    const card = document.createElement("div");
    card.className = "finding-card";

    const badge = document.createElement("span");
    badge.className = `severity-badge severity-${f.severity}`;
    badge.textContent = `${f.severity} — ${f.status}`;
    card.appendChild(badge);

    const titleInput = document.createElement("input");
    titleInput.value = f.title;
    card.appendChild(titleInput);

    const assetInput = document.createElement("input");
    assetInput.value = f.asset;
    card.appendChild(assetInput);

    const severitySelect = document.createElement("select");
    for (const sev of ["Critical", "High", "Medium", "Low", "Info"]) {
      const opt = document.createElement("option");
      opt.value = sev;
      opt.textContent = sev;
      if (sev === f.severity) opt.selected = true;
      severitySelect.appendChild(opt);
    }
    card.appendChild(severitySelect);

    const descInput = document.createElement("textarea");
    descInput.value = f.description;
    card.appendChild(descInput);

    const remInput = document.createElement("textarea");
    remInput.value = f.remediation;
    card.appendChild(remInput);

    const evidenceLine = document.createElement("div");
    evidenceLine.textContent = `Evidencia: steps ${f.evidence_step_ids.join(", ") || "(ninguno)"}`;
    card.appendChild(evidenceLine);

    if (f.status === "proposed" || f.status === "edited") {
      const acceptBtn = document.createElement("button");
      acceptBtn.textContent = "Aceptar";
      acceptBtn.onclick = () => onAccept(f.id, {
        title: titleInput.value,
        asset: assetInput.value,
        severity: severitySelect.value,
        description: descInput.value,
        remediation: remInput.value,
      }, f.evidence_step_ids);
      card.appendChild(acceptBtn);

      const rejectBtn = document.createElement("button");
      rejectBtn.textContent = "Rechazar";
      rejectBtn.onclick = () => onReject(f.id);
      card.appendChild(rejectBtn);
    }

    container.appendChild(card);
  }
}

export function renderFindingMarker(finding) {
  const feed = document.getElementById("steps-feed");
  const div = document.createElement("div");
  div.className = "step finding-marker";
  div.textContent = `Hallazgo propuesto: ${finding.title}`;
  div.onclick = () => { document.getElementById("findings-panel").hidden = false; };
  feed.appendChild(div);
  feed.scrollTop = feed.scrollHeight;
}
