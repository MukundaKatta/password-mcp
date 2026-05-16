import { strict as assert } from 'node:assert';
import { test } from 'node:test';

import { generate, strength } from '../src/server.js';

test('generates a password of the right length', () => {
  const p = generate({ length: 20 });
  assert.equal(p.length, 20);
});

test('includes at least one of each enabled class', () => {
  const p = generate({ length: 30, lowercase: true, uppercase: true, digits: true, symbols: true });
  assert.match(p, /[a-z]/);
  assert.match(p, /[A-Z]/);
  assert.match(p, /\d/);
  assert.match(p, /[!@#$%^&*()\-_=+\[\]{};:,.<>/?]/);
});

test('respects disabled classes', () => {
  const p = generate({ length: 16, symbols: false, digits: false });
  assert.equal(/[\d!@#$%^&*]/.test(p), false);
});

test('exclude_ambiguous drops 0/O/1/l/I/|', () => {
  for (let i = 0; i < 10; i++) {
    const p = generate({ length: 40, exclude_ambiguous: true });
    assert.equal(/[0O1lI|]/.test(p), false);
  }
});

test('rejects length out of range', () => {
  assert.throws(() => generate({ length: 3 }));
  assert.throws(() => generate({ length: 500 }));
});

test('rejects all-classes-disabled', () => {
  assert.throws(() =>
    generate({ lowercase: false, uppercase: false, digits: false, symbols: false }),
  );
});

test('strength: trivial password scores 0', () => {
  const r = strength('password');
  assert.ok(r.score <= 1);
});

test('strength: long random password scores high', () => {
  const r = strength('aB3$gH9!fK2#mP7&vQ4');
  assert.ok(r.score >= 3);
});

test('strength: returns feedback shape', () => {
  const r = strength('hello');
  assert.equal(typeof r.score, 'number');
  assert.equal(typeof r.guesses_log10, 'number');
  assert.equal(typeof r.crack_time_display, 'string');
  assert.ok(Array.isArray(r.suggestions));
});

test('passwords are unique across calls', () => {
  const set = new Set();
  for (let i = 0; i < 20; i++) set.add(generate({ length: 16 }));
  assert.equal(set.size, 20);
});
