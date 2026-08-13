// utils.js — čisté pomocné funkce bez závislostí na stavu aplikace.
// Vytaženo ze server.js kvůli testovatelnosti (viz utils.test.js).
import crypto from 'node:crypto';

// EU AI Act (nařízení (EU) 2024/1689, čl. 50) – transparentnost: příjemce musí být
// informován, že komunikuje s AI systémem. Připojuje se POUZE k plně automatickým
// odpovědím (bez lidského schválení).
export const AI_DISCLOSURE_TEXT = 'Tato odpověď byla vygenerována AI asistentem.';

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

// ============================================================================
// === SPAM DETEKCE (skórovací systém) ========================================
// ============================================================================
// Zásady proti falešným poplachům:
// - podřetězce nestačí: "reklamace" obsahuje "reklama" i "akce" -> porovnáváme CELÁ slova
// - jeden slabý signál nikdy nestačí (zákazník ptající se na slevu není spam)
// - hraniční případy ('suspect') rozhoduje AI s plným kontextem, ne tvrdý filtr

// Cílené fráze cold-outreach spamu (vysoká přesnost) - 2 body
export const SPAM_STRONG_PHRASES = [
  'seo audit', 'seo services', 'seo proposal', 'ranking on google',
  'google rankings', 'google ranking', 'front page of google', 'first page of google',
  'organic traffic', 'mobile app development services',
  'app development services', 'google play developer program',
  'avaya users list', 'technologies users list', 'contact details of users',
  'benefit klub', 'jobstip', 'supermax', 'teamiu', 'everbot',
];

// Obecné promo signály - 1 bod, POUZE jako celá slova
export const SPAM_PROMO_WORDS = ['newsletter', 'unsubscribe', 'inzerce'];
// Obecné promo fráze - 1 bod (víceslovné, substring je tu bezpečný)
export const SPAM_PROMO_PHRASES = ['kup nyní', '% sleva', 'akční nabídka'];

function textWords(text) {
  return new Set(String(text).toLowerCase().split(/[^a-zà-ž0-9%]+/i).filter(Boolean));
}

/**
 * Vyhodnotí spam signály e-mailu.
 * @returns {{verdict: 'spam'|'suspect'|'ok', score: number, reasons: string[]}}
 *  - 'spam'    = jistý spam (rovnou odfiltrovat)
 *  - 'suspect' = podezřelé, ale nechat rozhodnout AI
 *  - 'ok'      = žádný signál
 */
export function evaluateSpamSignals({
  subject = '',
  body = '',
  listUnsubscribe = false,
  precedenceBulk = false,
  autoSubmitted = false,
  explicitSpam = false,   // X-Spam-Flag/Status: yes, [SPAM] v předmětu
  knownSender = false,    // odesílatel, kterému jsme už dřív odpověděli
} = {}) {
  if (explicitSpam) return { verdict: 'spam', score: 99, reasons: ['explicit-spam-header'] };
  // Známému korespondentovi nikdy nefiltrujeme poštu heuristikou
  if (knownSender) return { verdict: 'ok', score: 0, reasons: ['known-sender'] };

  const text = `${String(subject)} ${String(body)}`.toLowerCase();
  const words = textWords(text);
  let score = 0;
  const reasons = [];

  if (SPAM_STRONG_PHRASES.some(p => text.includes(p))) { score += 2; reasons.push('strong-phrase'); }
  if (SPAM_PROMO_WORDS.some(w => words.has(w))) { score += 1; reasons.push('promo-word'); }
  if (SPAM_PROMO_PHRASES.some(p => text.includes(p))) { score += 1; reasons.push('promo-phrase'); }
  if (listUnsubscribe) { score += 1; reasons.push('list-unsubscribe'); }
  if (precedenceBulk) { score += 1; reasons.push('precedence-bulk'); }
  if (autoSubmitted) { score += 1; reasons.push('auto-submitted'); }

  if (score >= 2) return { verdict: 'spam', score, reasons };
  if (score === 1) return { verdict: 'suspect', score, reasons };
  return { verdict: 'ok', score, reasons };
}
