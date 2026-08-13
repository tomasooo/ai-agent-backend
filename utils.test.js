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
