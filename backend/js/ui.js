export function renderStep(step) {
  const feed = document.getElementById("steps-feed");
  const div = document.createElement("div");
  div.className = `step ${step.verdict || ""}`;
  div.textContent = `[${step.tool} ${JSON.stringify(step.args)}] verdict=${step.verdict}`;
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
