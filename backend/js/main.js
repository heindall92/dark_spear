import { initDB, createEngagement, exportEngagementJSON, getStepsByIds } from "./db.js";
import { startEngagement, setSessionToken, listKeys, addKey, selectKeys, advancePhase, listFindings, reviewFinding } from "./bridge_client.js";
import { runAgentLoop, PHASE_NAMES } from "./agent.js";
import { renderStep, showConfirmModal, renderKeyList, renderWaitingForQuota, renderPhaseIndicator, renderFindingsPanel, renderFindingMarker } from "./ui.js";

async function main() {
  const params = new URLSearchParams(window.location.search);
  const token = params.get("token");
  if (!token) {
    document.getElementById("app").textContent =
      "Falta el token de sesión. Abrí la URL exacta que imprime bridge.py al arrancar (incluye ?token=...).";
    return;
  }
  setSessionToken(token);

  const db = await initDB();
  const selectedLabels = new Set();

  document.getElementById("manage-keys-btn").onclick = async () => {
    const keys = await listKeys();
    renderKeyList(keys, selectedLabels);
    document.getElementById("key-manage-panel").hidden = false;
  };

  document.getElementById("add-key-btn").onclick = async () => {
    const label = document.getElementById("new-key-label").value.trim();
    const apiKey = document.getElementById("new-key-value").value.trim();
    const windowHours = parseFloat(document.getElementById("new-key-window").value);
    if (!label || !apiKey || !windowHours) return;
    await addKey(label, apiKey, windowHours);
    document.getElementById("new-key-label").value = "";
    document.getElementById("new-key-value").value = "";
    document.getElementById("new-key-window").value = "";
    const keys = await listKeys();
    renderKeyList(keys, selectedLabels);
  };

  document.getElementById("close-keys-btn").onclick = () => {
    document.getElementById("key-manage-panel").hidden = true;
  };

  async function refreshFindingsPanel() {
    const findings = await listFindings();
    const pendingCount = findings.filter((f) => f.status === "proposed").length;
    document.getElementById("findings-btn").textContent = `Hallazgos (${pendingCount} pendientes)`;
    renderFindingsPanel(findings, {
      onAccept: async (id, editedFields, evidenceStepIds) => {
        const steps = await getStepsByIds(db, evidenceStepIds);
        const evidence_texts = steps.filter(Boolean).map((s) => ({ step_id: s.id, output: s.output }));
        await reviewFinding(id, "accept", { edited_fields: editedFields, evidence_texts });
        await refreshFindingsPanel();
      },
      onReject: async (id) => {
        await reviewFinding(id, "reject");
        await refreshFindingsPanel();
      },
    });
  }

  document.getElementById("findings-btn").onclick = async () => {
    await refreshFindingsPanel();
    document.getElementById("findings-panel").hidden = false;
  };

  document.getElementById("close-findings-btn").onclick = () => {
    document.getElementById("findings-panel").hidden = true;
  };

  document.getElementById("start-btn").onclick = async () => {
    const target = document.getElementById("target-input").value.trim();
    const scope = document.getElementById("scope-input").value.trim();
    const model = document.getElementById("model-input").value.trim();
    const endpoint = document.getElementById("endpoint-input").value.trim() || undefined;
    if (!target || !scope || !model) return;
    if (selectedLabels.size === 0) {
      alert("Elegí al menos una API key en \"Gestionar keys\" antes de arrancar.");
      return;
    }

    await selectKeys([...selectedLabels]);
    await startEngagement(target, scope);
    const engagementId = await createEngagement(db, { target, scope });

    document.getElementById("start-panel").hidden = true;
    document.getElementById("steps-panel").hidden = false;

    const phaseState = { current: 1 };
    renderPhaseIndicator(phaseState.current, PHASE_NAMES);

    document.getElementById("advance-phase-btn").onclick = async () => {
      const result = await advancePhase();
      phaseState.current = result.phase;
      renderPhaseIndicator(phaseState.current, PHASE_NAMES);
    };

    document.getElementById("export-btn").onclick = async () => {
      const data = await exportEngagementJSON(db, engagementId);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `auditor-export-${engagementId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    };

    const systemPrompt = `Eres un agente de pentest autorizado. Target en scope: ${target}. Trabaja paso a paso, una herramienta a la vez.`;

    runAgentLoop({
      db, engagementId, model, target, systemPrompt, endpoint, phaseState,
      onStep: renderStep,
      onPauseForConfirmation: (decision, resolve) => {
        showConfirmModal(decision, () => resolve(true), () => resolve(false));
      },
      onWaitingForQuota: renderWaitingForQuota,
      onFindingProposed: async (finding) => {
        renderFindingMarker(finding);
        await refreshFindingsPanel();
      },
    });
  };
}

main();
