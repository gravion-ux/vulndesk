'use strict';

/**
 * CVSS v3.1 base-score engine (FIRST specification, section 7.1).
 *
 * VulnDesk scores every finding with a real CVSS 3.1 vector so severity is
 * reproducible and comparable across programmes, instead of a hand-waved
 * label. The equations implemented here are the published ones:
 *
 *   ISS           = 1 - [(1-C) x (1-I) x (1-A)]
 *   Impact        = 6.42 x ISS                                  (Scope Unchanged)
 *                 = 7.52 x (ISS - 0.029) - 3.25 x (ISS - 0.02)^15 (Scope Changed)
 *   Exploitability = 8.22 x AV x AC x PR x UI
 *   BaseScore     = Roundup(min(Impact + Exploitability, 10))            (S:U)
 *                 = Roundup(min(1.08 x (Impact + Exploitability), 10))   (S:C)
 *                 = 0 when Impact <= 0
 */

const METRICS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  // PR weights depend on Scope; stored as [scopeUnchanged, scopeChanged].
  PR: { N: [0.85, 0.85], L: [0.62, 0.68], H: [0.27, 0.5] },
  UI: { N: 0.85, R: 0.62 },
  S: { U: 'U', C: 'C' },
  C: { N: 0, L: 0.22, H: 0.56 },
  I: { N: 0, L: 0.22, H: 0.56 },
  A: { N: 0, L: 0.22, H: 0.56 },
};

const ORDER = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

/**
 * CVSS 3.1 "round up" (Appendix A): the smallest number with one decimal
 * place that is >= the input, computed on integers to avoid float drift.
 */
function roundUp(input) {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) {
    return intInput / 100000;
  }
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/**
 * Parse a vector string such as
 * "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" into a metrics object.
 * Throws on malformed input, unknown metrics or invalid values.
 */
function parseVector(vector) {
  if (typeof vector !== 'string' || vector.trim() === '') {
    throw new Error('CVSS vector must be a non-empty string');
  }
  const parts = vector.trim().split('/');
  const header = parts.shift();
  if (header !== 'CVSS:3.1' && header !== 'CVSS:3.0') {
    throw new Error(`Unsupported CVSS vector header: ${header}`);
  }
  const metrics = {};
  for (const part of parts) {
    const [key, value] = part.split(':');
    if (!ORDER.includes(key)) {
      throw new Error(`Unknown CVSS metric: ${key}`);
    }
    if (!(value in METRICS[key])) {
      throw new Error(`Invalid value "${value}" for CVSS metric ${key}`);
    }
    metrics[key] = value;
  }
  for (const key of ORDER) {
    if (!(key in metrics)) {
      throw new Error(`CVSS vector is missing metric ${key}`);
    }
  }
  return metrics;
}

/** Serialise a metrics object back to the canonical vector string. */
function formatVector(metrics) {
  return 'CVSS:3.1/' + ORDER.map((k) => `${k}:${metrics[k]}`).join('/');
}

/**
 * Compute the CVSS 3.1 base score for a vector string or metrics object.
 * Returns { score, vector, metrics }.
 */
function baseScore(input) {
  const metrics = typeof input === 'string' ? parseVector(input) : { ...input };
  for (const key of ORDER) {
    if (!(key in metrics) || !(metrics[key] in METRICS[key])) {
      throw new Error(`Invalid or missing CVSS metric ${key}`);
    }
  }
  const scopeChanged = metrics.S === 'C';
  const iss =
    1 - (1 - METRICS.C[metrics.C]) * (1 - METRICS.I[metrics.I]) * (1 - METRICS.A[metrics.A]);
  let impact;
  if (!scopeChanged) {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }
  const pr = METRICS.PR[metrics.PR][scopeChanged ? 1 : 0];
  const exploitability =
    8.22 * METRICS.AV[metrics.AV] * METRICS.AC[metrics.AC] * pr * METRICS.UI[metrics.UI];

  let score;
  if (impact <= 0) {
    score = 0;
  } else if (!scopeChanged) {
    score = roundUp(Math.min(impact + exploitability, 10));
  } else {
    score = roundUp(Math.min(1.08 * (impact + exploitability), 10));
  }
  // Normalise -0 / float dust.
  score = Math.round(score * 10) / 10;
  return { score, vector: formatVector(metrics), metrics };
}

/** Map a numeric score to its qualitative severity band. */
function severityBand(score) {
  if (score <= 0) return 'none';
  if (score < 4.0) return 'low';
  if (score < 7.0) return 'medium';
  if (score < 9.0) return 'high';
  return 'critical';
}

const BANDS = ['none', 'low', 'medium', 'high', 'critical'];

module.exports = { parseVector, formatVector, baseScore, severityBand, roundUp, BANDS };
