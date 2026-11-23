'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { baseScore, parseVector, formatVector, severityBand } = require('../src/cvss');

test('known published vectors score exactly', () => {
  // Log4Shell (CVE-2021-44228) — 10.0
  assert.equal(baseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H').score, 10.0);
  // Full-impact scope-unchanged RCE pattern (BlueKeep class) — 9.8
  assert.equal(baseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').score, 9.8);
  // Canonical reflected XSS — 6.1
  assert.equal(baseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N').score, 6.1);
  // Confidentiality-only network issue (Heartbleed class) — 7.5
  assert.equal(baseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N').score, 7.5);
  // No impact at all — 0.0
  assert.equal(baseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N').score, 0.0);
});

test('severity bands follow the qualitative scale', () => {
  assert.equal(severityBand(0), 'none');
  assert.equal(severityBand(0.1), 'low');
  assert.equal(severityBand(3.9), 'low');
  assert.equal(severityBand(4.0), 'medium');
  assert.equal(severityBand(6.9), 'medium');
  assert.equal(severityBand(7.0), 'high');
  assert.equal(severityBand(8.9), 'high');
  assert.equal(severityBand(9.0), 'critical');
  assert.equal(severityBand(10), 'critical');
});

test('vector parse/format round-trips and validates', () => {
  const v = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
  assert.equal(formatVector(parseVector(v)), v);
  assert.throws(() => parseVector('CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), /Invalid value/);
  assert.throws(() => parseVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H'), /missing metric/);
  assert.throws(() => parseVector('CVSS:9.9/AV:N'), /Unsupported/);
  assert.throws(() => baseScore('nonsense'), /non-empty|Unsupported/);
});

test('scope-changed PR weights differ from scope-unchanged', () => {
  const su = baseScore('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N').score;
  const sc = baseScore('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N').score;
  assert.notEqual(su, sc);
});
