'use strict';

/**
 * Seed a realistic demo workspace.
 *
 *   node scripts/seed.js           (refuses to run twice against the same DB)
 *   node scripts/seed.js --force   (wipe the demo users/workspace and reseed)
 *
 * Demo accounts (local/demo use only — change before any real deployment):
 *   owner@vulndesk.local   / OwnerPass#2026   (workspace owner)
 *   analyst@vulndesk.local / AnalystPass#2026 (analyst)
 *   viewer@vulndesk.local  / ViewerPass#2026  (viewer)
 *
 * The demo workspace "Northwind Security" runs two programmes and holds 12
 * findings across every severity band and lifecycle state — including an
 * exact duplicate pair (same target + class + parameter fingerprint) so the
 * dedupe engine's flag is visible immediately.
 */

const { createStore } = require('../src/store');
const { hashPassword, newId } = require('../src/auth');
const cvss = require('../src/cvss');
const dedupe = require('../src/dedupe');

const DEMO_USERS = [
  { email: 'owner@vulndesk.local', name: 'Olivia Owner', password: 'OwnerPass#2026', role: 'owner' },
  { email: 'analyst@vulndesk.local', name: 'Arjun Analyst', password: 'AnalystPass#2026', role: 'analyst' },
  { email: 'viewer@vulndesk.local', name: 'Vera Viewer', password: 'ViewerPass#2026', role: 'viewer' },
];

const DAY = 24 * 60 * 60 * 1000;
const daysAgo = (n) => new Date(Date.now() - n * DAY).toISOString();

const FINDINGS = [
  {
    programme: 0, title: 'IDOR on order details exposes other customers\u2019 invoices',
    vulnClass: 'idor', target: 'https://shop.northwind.example/api/orders', parameter: 'order_id',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', status: 'accepted',
    reporter: 'bugbountypkt143',
    description: 'Changing the order_id in the order-details request returns invoices belonging to other customers. No ownership check is performed server-side.',
    reproduction: '1. Log in as customer A.\n2. GET /api/orders/{id-of-customer-B}.\n3. The response contains customer B\u2019s invoice, including name, address and payment reference.',
    impact: 'Any authenticated customer can read every other customer\u2019s invoices — bulk PII exposure.',
    remediation: 'Enforce per-object authorization on the server: verify the order belongs to the requesting user before returning it.',
    days: 9,
  },
  {
    programme: 0, title: 'IDOR on order details (duplicate report)',
    vulnClass: 'idor', target: 'https://shop.northwind.example/api/orders/', parameter: 'order_id',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', status: 'duplicate', duplicateOfTitle: 0,
    reporter: 'second-researcher',
    description: 'Same order IDOR as the earlier report — submitted via a different programme intake form.',
    reproduction: 'GET /api/orders/{other-user-id} returns their invoice.',
    impact: 'Same as original report.',
    remediation: 'Same as original report.',
    days: 7,
  },
  {
    programme: 0, title: 'Stored XSS in product review comments',
    vulnClass: 'stored-xss', target: 'https://shop.northwind.example/products/reviews', parameter: 'comment',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N', status: 'triaged',
    reporter: 'bugbountypkt143',
    description: 'Review comments are stored and rendered without output encoding, allowing script injection into product pages viewed by other shoppers and support staff.',
    reproduction: '1. Post a review containing an HTML event-handler payload.\n2. Open the product page as another user.\n3. The payload executes in the victim\u2019s browser.',
    impact: 'Session theft and admin-action hijacking via support staff browsers.',
    remediation: 'Contextual output encoding on render; add a Content-Security-Policy as defence in depth.',
    days: 6,
  },
  {
    programme: 0, title: 'SSRF in image import lets attackers reach cloud metadata',
    vulnClass: 'ssrf', target: 'https://shop.northwind.example/api/import/image', parameter: 'url',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N', status: 'new',
    reporter: 'cloudhunter',
    description: 'The image-import endpoint fetches arbitrary URLs server-side with no allowlist, including the link-local cloud metadata address.',
    reproduction: '1. POST /api/import/image with url pointing at the metadata endpoint.\n2. The response body contains instance credentials.',
    impact: 'Cloud credential theft and lateral movement into the production account.',
    remediation: 'Allowlist remote hosts, block private/link-local ranges, and fetch through an egress proxy.',
    days: 2,
  },
  {
    programme: 0, title: 'Missing rate limit on coupon redemption endpoint',
    vulnClass: 'business-logic', target: 'https://shop.northwind.example/api/coupons/redeem', parameter: 'code',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N', status: 'informative',
    reporter: 'logicwalker',
    description: 'Coupon codes can be brute-forced; no throttling or lockout observed after 500 attempts.',
    reproduction: 'Script 500 redemption attempts with sequential codes; all are processed.',
    impact: 'Discount abuse at scale if valid code patterns leak.',
    remediation: 'Rate-limit per account and IP; alert on enumeration patterns.',
    days: 5,
  },
  {
    programme: 0, title: 'Reflected XSS in search query parameter',
    vulnClass: 'reflected-xss', target: 'https://shop.northwind.example/search', parameter: 'q',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', status: 'fixed',
    reporter: 'bugbountypkt143',
    description: 'The search term was reflected unencoded into the results page.',
    reproduction: 'Visit /search?q=<payload> and observe execution.',
    impact: 'Phishing and session theft via crafted links.',
    remediation: 'Encode reflected output. Fixed in release 4.2.1 and verified by retest.',
    days: 14,
  },
  {
    programme: 1, title: 'Broken access control: partner API returns all tenants\u2019 payouts',
    vulnClass: 'broken-access-control', target: 'https://api.northwind.example/v1/payouts', parameter: 'partner_id',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N', status: 'accepted',
    reporter: 'tenantwatch',
    description: 'The payouts endpoint trusts the partner_id supplied by the caller and returns payout records for every tenant.',
    reproduction: '1. Authenticate as partner A.\n2. GET /v1/payouts?partner_id={partner-B}.\n3. Partner B\u2019s payout history is returned.',
    impact: 'Cross-tenant financial data exposure for every partner on the platform.',
    remediation: 'Derive the tenant from the authenticated principal; never trust a client-supplied tenant id.',
    days: 8,
  },
  {
    programme: 1, title: 'JWT accepted with alg=none on partner API',
    vulnClass: 'auth-bypass', target: 'https://api.northwind.example/v1/auth/token', parameter: 'token',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', status: 'triaged',
    reporter: 'jwtsleuth',
    description: 'The token verification library accepts unsigned tokens when the header declares alg=none.',
    reproduction: 'Forge a token with alg=none and an admin subject; the API accepts it.',
    impact: 'Full authentication bypass and account takeover for any partner account.',
    remediation: 'Pin the expected algorithm server-side and reject none; rotate signing keys.',
    days: 4,
  },
  {
    programme: 1, title: 'SQL injection in reporting filter parameter',
    vulnClass: 'sqli', target: 'https://api.northwind.example/v1/reports', parameter: 'filter',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N', status: 'new',
    reporter: 'bugbountypkt143',
    description: 'The filter parameter is concatenated into a SQL query; boolean-based extraction confirmed.',
    reproduction: 'Append a boolean condition to filter and observe result-set differences.',
    impact: 'Database contents, including credentials hashes, can be extracted.',
    remediation: 'Use parameterised queries everywhere; add a regression test with injection payloads.',
    days: 1,
  },
  {
    programme: 1, title: 'Verbose error messages leak stack traces and SQL fragments',
    vulnClass: 'information-disclosure', target: 'https://api.northwind.example/v1/reports', parameter: 'filter',
    vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N', status: 'informative',
    reporter: 'jwtsleuth',
    description: 'Malformed input returns full stack traces including internal package paths and SQL fragments.',
    reproduction: 'Send an invalid filter value and read the error body.',
    impact: 'Reconnaissance value for attackers; no direct data exposure.',
    remediation: 'Return generic errors to clients; log details server-side only.',
    days: 3,
  },
  {
    programme: 1, title: 'Password reset token does not expire after use',
    vulnClass: 'auth-bypass', target: 'https://api.northwind.example/v1/auth/reset', parameter: 'token',
    vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N', status: 'new',
    reporter: 'resetrover',
    description: 'A consumed password-reset token remains valid and can be replayed within the 24-hour window.',
    reproduction: '1. Request a reset token.\n2. Use it to set a new password.\n3. Use the same token again — it is accepted.',
    impact: 'Anyone who obtains a used token (logs, referers) can take over the account.',
    remediation: 'Invalidate tokens on first use; store only hashes of tokens.',
    days: 2,
  },
  {
    programme: 0, title: 'Outdated jQuery version with known XSS CVE on checkout page',
    vulnClass: 'known-vulnerable-component', target: 'https://shop.northwind.example/checkout', parameter: '',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', status: 'triaged',
    reporter: 'depchecker',
    description: 'Checkout loads jQuery 3.4.1, affected by a known DOM XSS issue in htmlPrefilter.',
    reproduction: 'Inspect page source on /checkout; library version is 3.4.1.',
    impact: 'Potential DOM XSS on the payment page if untrusted HTML reaches the sink.',
    remediation: 'Upgrade to a supported jQuery release or remove the dependency.',
    days: 11,
  },
];

function main() {
  const force = process.argv.includes('--force');
  const store = createStore();

  const existingOwner = store.getUserByEmail(DEMO_USERS[0].email);
  if (existingOwner && !force) {
    console.log('Demo data already seeded (found owner@vulndesk.local). Re-run with --force to reseed.');
    store.close();
    return;
  }
  if (existingOwner && force) {
    for (const w of store.listWorkspacesForUser(existingOwner.id)) store.deleteWorkspace(w.id);
    console.log('Removed previous demo workspace(s).');
  }

  const users = {};
  for (const spec of DEMO_USERS) {
    let user = store.getUserByEmail(spec.email);
    if (!user) {
      user = store.createUser({
        id: newId('usr'),
        email: spec.email,
        name: spec.name,
        passwordHash: hashPassword(spec.password),
        createdAt: daysAgo(15),
      });
    }
    users[spec.role] = user;
  }

  const workspace = store.createWorkspace({
    id: newId('wsp'),
    name: 'Northwind Security',
    slug: 'northwind-security',
    createdBy: users.owner.id,
    createdAt: daysAgo(15),
  });
  for (const spec of DEMO_USERS) {
    store.setMembership({
      id: newId('mem'),
      workspaceId: workspace.id,
      userId: users[spec.role].id,
      role: spec.role,
      createdAt: daysAgo(15),
    });
  }

  const programmes = [
    store.createProgramme({
      id: newId('prg'), workspaceId: workspace.id,
      name: 'Northwind Storefront — Web Bounty',
      platform: 'HackerOne',
      scope: 'shop.northwind.example — web app, checkout and account areas in scope',
      status: 'active', createdAt: daysAgo(14), updatedAt: daysAgo(14),
    }),
    store.createProgramme({
      id: newId('prg'), workspaceId: workspace.id,
      name: 'Northwind Partner API',
      platform: 'Bugcrowd',
      scope: 'api.northwind.example/v1 — partner API, auth and payouts in scope',
      status: 'active', createdAt: daysAgo(14), updatedAt: daysAgo(14),
    }),
  ];

  const created = [];
  for (const spec of FINDINGS) {
    const scored = cvss.baseScore(spec.vector);
    const draft = { vulnClass: spec.vulnClass, target: spec.target, parameter: spec.parameter };
    const createdAt = daysAgo(spec.days);
    const finding = {
      id: newId('fnd'),
      workspaceId: workspace.id,
      programmeId: programmes[spec.programme].id,
      title: spec.title,
      vulnClass: spec.vulnClass,
      target: spec.target,
      parameter: spec.parameter,
      cvssVector: scored.vector,
      severityScore: scored.score,
      severityBand: cvss.severityBand(scored.score),
      status: spec.status,
      reporter: spec.reporter,
      assigneeId: spec.status === 'new' ? null : users.analyst.id,
      description: spec.description,
      reproduction: spec.reproduction,
      impact: spec.impact,
      remediation: spec.remediation,
      fingerprint: dedupe.fingerprint(draft),
      duplicateOf: null,
      createdBy: users.analyst.id,
      createdAt,
      updatedAt: createdAt,
    };
    if (typeof spec.duplicateOfTitle === 'number') {
      finding.duplicateOf = created[spec.duplicateOfTitle].id;
    }
    store.createFinding(finding);
    created.push(finding);
  }

  store.insertAudit({
    id: newId('aud'), workspaceId: workspace.id, userId: users.owner.id,
    action: 'workspace.seed', entity: 'workspace', entityId: workspace.id,
    detail: `Seeded demo workspace with ${programmes.length} programmes and ${created.length} findings`,
    createdAt: daysAgo(0),
  });

  console.log('Seed complete.');
  console.log(`  Workspace : ${workspace.name} (${workspace.id})`);
  console.log(`  Programmes: ${programmes.length}`);
  console.log(`  Findings  : ${created.length} (incl. 1 duplicate pair)`);
  console.log('  Accounts  :');
  for (const spec of DEMO_USERS) console.log(`    ${spec.email} / ${spec.password} (${spec.role})`);
  store.close();
}

main();
