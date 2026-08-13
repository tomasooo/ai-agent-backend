// utils.js — čisté pomocné funkce bez závislostí na stavu aplikace.
// Vytaženo ze server.js kvůli testovatelnosti (viz utils.test.js).
import crypto from 'node:crypto';

// EU AI Act (nařízení (EU) 2024/1689, čl. 50) – transparentnost: příjemce musí být
// informován, že komunikuje s AI systémem. Připojuje se POUZE k plně automatickým
// odpovědím (bez lidského schválení).
export const AI_DISCLOSURE_TEXT = 'Tato odpověď byla vygenerována AI asistentem (EU AI Act).';

export function appendAiDisclosure(body) {
  const text = String(body || '').trimEnd();
  if (text.includes(AI_DISCLOSURE_TEXT)) return text;
  return `${text}\n\n--\n${AI_DISCLOSURE_TEXT}`;
}

// Časově konstantní porovnání tajemství (ochrana proti timing útokům)
export function safeSecretEqual(a, b) {
  const bufA = Buffer.from(String(a || ''), 'utf8');
  const bufB = Buffer.from(String(b || ''), 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// Spustí async mapovací funkci nad polem s omezenou souběžností (např. Gmail API volání).
export async function mapWithConcurrency(items, limit, fn) {
  const arr = Array.from(items || []);
  const results = new Array(arr.length);
  let idx = 0;
  const workers = Array.from({ length: Math.min(limit, arr.length) }, async () => {
    while (idx < arr.length) {
      const cur = idx++;
      results[cur] = await fn(arr[cur], cur);
    }
  });
  await Promise.all(workers);
  return results;
}

export function firstLineSnippet(text = '', max = 280) {
  return String(text || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, Math.max(0, max));
}

export function stripJsonFence(s = '') {
  return String(s).replace(/^\s*```json\s*/i, '').replace(/\s*```\s*$/i, '').trim();
}
