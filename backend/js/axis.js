import { getAxisEntry, upsertAxisEntry } from "./db.js";

function simpleHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (h * 31 + str.charCodeAt(i)) | 0;
  }
  return h.toString(16);
}

export function paramsHash(tool, args) {
  return simpleHash(`${tool}:${JSON.stringify(args)}`);
}

export function resultHash(output) {
  return simpleHash(String(output).slice(0, 500));
}

export async function checkAndRecordAxis(db, engagementId, tool, args, output) {
  const pHash = paramsHash(tool, args);
  const rHash = resultHash(output);
  const existing = await getAxisEntry(db, engagementId, tool, pHash);
  const sameAsLast = existing && existing.lastResultHash === rHash;
  const attemptCount = existing ? existing.attemptCount + 1 : 1;
  await upsertAxisEntry(db, {
    engagementId,
    tool,
    paramsHash: pHash,
    attemptCount,
    lastResultHash: rHash,
  });
  const warn = attemptCount >= 3 && sameAsLast;
  return { attemptCount, warn };
}
