// Testy čistých pomocných funkcí: node --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AI_DISCLOSURE_TEXT,
  appendAiDisclosure,
  safeSecretEqual,
  mapWithConcurrency,
  firstLineSnippet,
  stripJsonFence,
  evaluateSpamSignals,
} from './utils.js';

test('appendAiDisclosure přidá upozornění na konec', () => {
  const out = appendAiDisclosure('Dobrý den,\nděkujeme za zprávu.');
  assert.ok(out.endsWith(`--\n${AI_DISCLOSURE_TEXT}`));
  assert.ok(out.startsWith('Dobrý den,'));
});

test('appendAiDisclosure nepřidá upozornění dvakrát', () => {
  const once = appendAiDisclosure('Text odpovědi.');
  const twice = appendAiDisclosure(once);
  assert.equal(once, twice);
  assert.equal(twice.split(AI_DISCLOSURE_TEXT).length - 1, 1);
});

test('appendAiDisclosure zvládne prázdný vstup', () => {
  const out = appendAiDisclosure('');
  assert.ok(out.includes(AI_DISCLOSURE_TEXT));
});

test('safeSecretEqual: shodná a neshodná tajemství', () => {
  assert.equal(safeSecretEqual('tajne-heslo', 'tajne-heslo'), true);
  assert.equal(safeSecretEqual('tajne-heslo', 'jine-heslo'), false);
  assert.equal(safeSecretEqual('a', 'ab'), false);
  assert.equal(safeSecretEqual('', ''), true);
  assert.equal(safeSecretEqual(null, undefined), true); // oba prázdné stringy
});

test('mapWithConcurrency zachová pořadí výsledků', async () => {
  const input = [50, 10, 30, 5, 20];
  const out = await mapWithConcurrency(input, 3, async (ms) => {
    await new Promise(r => setTimeout(r, ms));
    return ms * 2;
  });
  assert.deepEqual(out, [100, 20, 60, 10, 40]);
});

test('mapWithConcurrency nepřekročí limit souběhu', async () => {
  let active = 0, maxActive = 0;
  await mapWithConcurrency(Array.from({ length: 20 }, (_, i) => i), 4, async () => {
    active++;
    maxActive = Math.max(maxActive, active);
    await new Promise(r => setTimeout(r, 5));
    active--;
  });
  assert.ok(maxActive <= 4, `max souběh byl ${maxActive}`);
});

test('firstLineSnippet zplošťuje whitespace a ořezává délku', () => {
  assert.equal(firstLineSnippet('  Ahoj\n\n  světe\t! '), 'Ahoj světe !');
  assert.equal(firstLineSnippet('abcdef', 3), 'abc');
  assert.equal(firstLineSnippet(null), '');
});

test('stripJsonFence odstraní markdown fence', () => {
  assert.equal(stripJsonFence('```json\n{"a":1}\n```'), '{"a":1}');
  assert.equal(stripJsonFence('{"a":1}'), '{"a":1}');
  assert.equal(JSON.parse(stripJsonFence('```json {"x": "y"} ```')).x, 'y');
});

// === Spam detekce: falešné poplachy, které dřív procházely ===

test('spam: reklamace od zákazníka NENÍ spam (podřetězce reklama/akce)', () => {
  const r = evaluateSpamSignals({
    subject: 'Reklamace objednávky č. 12345',
    body: 'Dobrý den, chtěl bych uplatnit reklamaci křesla, po týdnu se rozbilo.',
  });
  assert.equal(r.verdict, 'ok');
});

test('spam: dotaz na slevu/akci NENÍ spam', () => {
  const r = evaluateSpamSignals({
    subject: 'Dotaz na slevu',
    body: 'Dobrý den, máte teď nějakou akci na pohovky? Případně jaká je sleva při odběru dvou kusů?',
  });
  assert.equal(r.verdict, 'ok');
});

test('spam: jediný slabý signál = suspect (rozhodne AI), ne spam', () => {
  const r = evaluateSpamSignals({
    subject: 'Nabídka spolupráce',
    body: 'Text bez promo slov',
    listUnsubscribe: true,
  });
  assert.equal(r.verdict, 'suspect');
});

test('spam: newsletter s bulk hlavičkou a unsubscribe = spam', () => {
  const r = evaluateSpamSignals({
    subject: 'Náš týdenní newsletter',
    body: 'Pokud už nechcete dostávat tyto e-maily, klikněte na unsubscribe.',
    listUnsubscribe: true,
  });
  assert.equal(r.verdict, 'spam');
});

test('spam: cold outreach (seo audit) = spam i bez bulk hlaviček', () => {
  const r = evaluateSpamSignals({
    subject: 'Free SEO audit for your website',
    body: 'We noticed your ranking on Google could be better...',
  });
  assert.equal(r.verdict, 'spam');
});

test('spam: explicitní X-Spam hlavička = spam vždy', () => {
  const r = evaluateSpamSignals({ subject: 'Cokoliv', body: 'Cokoliv', explicitSpam: true });
  assert.equal(r.verdict, 'spam');
});

test('spam: známý korespondent se heuristikou nefiltruje', () => {
  const r = evaluateSpamSignals({
    subject: 'Náš newsletter pro vás',
    body: 'unsubscribe zde',
    listUnsubscribe: true,
    knownSender: true,
  });
  assert.equal(r.verdict, 'ok');
});
