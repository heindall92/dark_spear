const DB_NAME = "auditor";
const DB_VERSION = 2;

export function initDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (event.oldVersion < 1) {
        const eng = db.createObjectStore("engagement", { keyPath: "id", autoIncrement: true });
        eng.createIndex("status", "status");
        const steps = db.createObjectStore("steps", { keyPath: "id", autoIncrement: true });
        steps.createIndex("engagementId", "engagementId");
        const axis = db.createObjectStore("axis_ledger", { keyPath: "id", autoIncrement: true });
        axis.createIndex("engagementId", "engagementId");
        axis.createIndex("lookup", ["engagementId", "tool", "paramsHash"]);
      }
      if (event.oldVersion < 2) {
        if (db.objectStoreNames.contains("findings")) {
          db.deleteObjectStore("findings");
        }
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function tx(db, storeName, mode = "readonly") {
  return db.transaction(storeName, mode).objectStore(storeName);
}

export function createEngagement(db, { target, scope }) {
  return new Promise((resolve, reject) => {
    const store = tx(db, "engagement", "readwrite");
    const req = store.add({ target, scope, startedAt: Date.now(), status: "active" });
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export function getActiveEngagement(db) {
  return new Promise((resolve, reject) => {
    const store = tx(db, "engagement");
    const req = store.index("status").getAll("active");
    req.onsuccess = () => resolve(req.result[0] || null);
    req.onerror = () => reject(req.error);
  });
}

/** Reusa engagement activo del mismo target o crea uno nuevo. */
export async function getOrCreateEngagement(db, { target, scope }) {
  const want = String(target || "").trim();
  const active = await getActiveEngagement(db);
  if (active && String(active.target || "").trim() === want) {
    return active.id;
  }
  // Si hay otro activo distinto, lo marcamos cerrado para no mezclar steps
  if (active && active.id != null) {
    await new Promise((resolve, reject) => {
      const store = tx(db, "engagement", "readwrite");
      const req = store.put({ ...active, status: "closed", closedAt: Date.now() });
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }
  return createEngagement(db, { target: want, scope: scope || want });
}

export function addStep(db, { engagementId, tool, args, output, stderr, exitCode, verdict, phase }) {
  return new Promise((resolve, reject) => {
    const store = tx(db, "steps", "readwrite");
    const req = store.add({ engagementId, tool, args, output, stderr, exitCode, verdict, phase: phase ?? null, timestamp: Date.now() });
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export function getSteps(db, engagementId) {
  return new Promise((resolve, reject) => {
    const store = tx(db, "steps");
    const req = store.index("engagementId").getAll(engagementId);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export function getStepsByIds(db, stepIds) {
  return new Promise((resolve, reject) => {
    const ids = Array.isArray(stepIds)
      ? stepIds.map((id) => {
          if (typeof id === "number" && Number.isFinite(id)) return id;
          const n = parseInt(String(id).replace(/^#/, ""), 10);
          return Number.isFinite(n) ? n : id;
        })
      : [];
    if (ids.length === 0) {
      resolve([]);
      return;
    }
    const store = tx(db, "steps");
    const results = new Array(ids.length);
    let remaining = ids.length;
    ids.forEach((id, i) => {
      const req = store.get(id);
      req.onsuccess = () => {
        results[i] = req.result;
        remaining -= 1;
        if (remaining === 0) resolve(results);
      };
      req.onerror = () => reject(req.error);
    });
  });
}

export function getAxisEntry(db, engagementId, tool, paramsHash) {
  return new Promise((resolve, reject) => {
    const store = tx(db, "axis_ledger");
    const req = store.index("lookup").get([engagementId, tool, paramsHash]);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

export function upsertAxisEntry(db, entry) {
  return new Promise(async (resolve, reject) => {
    const existing = await getAxisEntry(db, entry.engagementId, entry.tool, entry.paramsHash);
    const store = tx(db, "axis_ledger", "readwrite");
    const record = existing ? { ...existing, ...entry } : { ...entry };
    const req = store.put(record);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

export async function exportEngagementJSON(db, engagementId) {
  const steps = await getSteps(db, engagementId);
  const axis = await new Promise((resolve, reject) => {
    const store = tx(db, "axis_ledger");
    const req = store.index("engagementId").getAll(engagementId);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return { engagementId, steps, axis_ledger: axis };
}
