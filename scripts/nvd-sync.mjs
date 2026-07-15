// Copyright 2026 Küstenlogik
// SPDX-License-Identifier: Apache-2.0

/**
 * Monthly NVD sync — open tracking issues for freshly-published CVEs on the
 * multi-protocol surfaces Bowire probes that don't yet have a template.
 *
 * The corpus is community-maintained: this closes the "how does a new CVE
 * become a template?" loop by turning the National Vulnerability Database's
 * recent entries into actionable, deduplicated GitHub issues. It never writes
 * a template itself — a human assesses relevance and authors (or declines)
 * the probe.
 *
 * Flow:
 *   1. Collect the CVE ids already covered by a template (union of every
 *      template's vulnerability.cve array).
 *   2. Query NVD 2.0 for each distinctive protocol keyword over the lookback
 *      window (default 30 days), keeping CVEs at/above a CVSS floor.
 *   3. Drop CVEs already covered by a template OR already tracked by an
 *      `nvd-sync`-labelled issue (so a monthly run doesn't re-open the same
 *      ticket).
 *   4. Open up to a capped number of issues, highest-severity first.
 *
 * On the cap: keyword hits are dominated by library-internal CVEs with no
 * request-shaped signal Bowire could probe, so the run files only the top
 * NVD_SYNC_MAX_ISSUES by severity. The un-opened tail is NOT carried over —
 * the next scheduled run's window starts NVD_SYNC_DAYS before *that* run, so
 * today's tail falls out of scope for good. That's the intended signal/noise
 * trade-off, not a queue; reach the tail by dispatching manually with a wider
 * `days` window and a raised cap / CVSS floor.
 *
 * Zero dependencies — Node 20+ global fetch only, matching
 * generate-templates-index.mjs. Runs read-only in --dry-run (the default when
 * GITHUB_TOKEN is absent), so it's safe to run locally against live NVD.
 *
 * Env:
 *   GITHUB_TOKEN        issues:write token (Actions provides it). Absent → dry-run.
 *   GITHUB_REPOSITORY   owner/repo (Actions provides it). Default Kuestenlogik/Bowire.VulnDb.
 *   NVD_API_KEY         optional — raises the NVD rate limit (50 vs 5 req / 30s).
 *   NVD_SYNC_DAYS       lookback window in days (default 30, NVD max 120).
 *   NVD_SYNC_MIN_CVSS   only surface CVEs at/above this base score (default 4.0).
 *   NVD_SYNC_MAX_ISSUES cap on issues opened per run (default 8) — flood guard.
 *
 * Flags: --dry-run (force no writes, print the plan).
 */

import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

const REPO_ROOT = new URL('..', import.meta.url).pathname.replace(/^\/([A-Z]:\/)/, '$1');
const TEMPLATES_DIR = join(REPO_ROOT, 'templates');

const REPO = process.env.GITHUB_REPOSITORY || 'Kuestenlogik/Bowire.VulnDb';
const TOKEN = process.env.GITHUB_TOKEN || '';
const NVD_KEY = process.env.NVD_API_KEY || '';
const DAYS = clampInt(process.env.NVD_SYNC_DAYS, 30, 1, 120);
const MIN_CVSS = Number(process.env.NVD_SYNC_MIN_CVSS ?? 4.0);
const MAX_ISSUES = clampInt(process.env.NVD_SYNC_MAX_ISSUES, 8, 1, 50);
const DRY_RUN = process.argv.includes('--dry-run') || !TOKEN;

const LABEL = 'nvd-sync';

// The distinctive, multi-protocol surfaces worth a keyword search. Generic
// terms (rest / http / udp) are deliberately excluded — they return thousands
// of unrelated CVEs and would drown the signal. `protocol` maps to the
// templates/<protocol>/ folder so the issue can point authors at the right bucket.
//
// `nativeOnly` marks a surface this corpus CANNOT express: a template's probe is
// replayed over HTTP (the scanner's runner is HttpClient-based), so protocols
// that reach their native transport without an HTTP handshake have no template
// shape. MQTT-over-TCP is the case — its coverage lives as native probes in the
// scanner (MqttAuthProbe / MqttWildcardSubscribeProbe / …) over in
// Kuestenlogik/Bowire. The keyword still earns its place: a new MQTT CVE is
// worth triaging, it just lands as a probe there, not a template here. Every
// other surface below is reachable over HTTP (WS/SignalR/Socket.IO/SSE via their
// handshake, MCP + GraphQL + gRPC-Web + OData natively).
const PROTOCOL_KEYWORDS = [
    { keyword: 'graphql', protocol: 'graphql' },
    { keyword: 'grpc', protocol: 'grpc' },
    { keyword: 'mqtt', protocol: 'mqtt', nativeOnly: true },
    { keyword: 'odata', protocol: 'odata' },
    { keyword: 'signalr', protocol: 'signalr' },
    { keyword: 'websocket', protocol: 'websocket' },
    { keyword: 'socket.io', protocol: 'socketio' },
    { keyword: 'model context protocol', protocol: 'mcp' },
];

function clampInt(raw, def, lo, hi) {
    const n = Number(raw);
    if (!Number.isFinite(n)) return def;
    return Math.min(hi, Math.max(lo, Math.trunc(n)));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- template corpus ----------------------------------------------------

async function walk(dir) {
    const out = [];
    let entries;
    try {
        entries = await readdir(dir, { withFileTypes: true });
    } catch {
        return out; // no templates/ yet
    }
    for (const e of entries) {
        const p = join(dir, e.name);
        if (e.isDirectory()) out.push(...(await walk(p)));
        else if (e.isFile() && e.name.endsWith('.json')) out.push(p);
    }
    return out;
}

async function coveredCveIds() {
    const covered = new Set();
    for (const file of await walk(TEMPLATES_DIR)) {
        try {
            const doc = JSON.parse(await readFile(file, 'utf8'));
            const cves = doc?.vulnerability?.cve;
            if (Array.isArray(cves)) {
                for (const c of cves) if (typeof c === 'string') covered.add(c.toUpperCase());
            }
        } catch {
            // A malformed template shouldn't sink the sync — skip it.
        }
    }
    return covered;
}

// ---- NVD -----------------------------------------------------------------

function nvdDate(d) {
    // NVD 2.0 wants an ISO-8601 extended timestamp; it treats a zone-less
    // value as UTC. Strip the trailing Z the Date emits.
    return d.toISOString().replace('Z', '');
}

function bestScore(cve) {
    const m = cve.metrics || {};
    for (const key of ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']) {
        const arr = m[key];
        if (Array.isArray(arr) && arr.length > 0) {
            const data = arr[0].cvssData || {};
            const score = typeof data.baseScore === 'number' ? data.baseScore : null;
            const severity = arr[0].baseSeverity || data.baseSeverity || null;
            if (score !== null) return { score, severity: severity || severityFromScore(score) };
        }
    }
    return { score: null, severity: null };
}

function severityFromScore(s) {
    if (s >= 9) return 'CRITICAL';
    if (s >= 7) return 'HIGH';
    if (s >= 4) return 'MEDIUM';
    if (s > 0) return 'LOW';
    return 'NONE';
}

async function nvdSearch(keyword, startDate, endDate) {
    const params = new URLSearchParams({
        keywordSearch: keyword,
        pubStartDate: nvdDate(startDate),
        pubEndDate: nvdDate(endDate),
        resultsPerPage: '200',
    });
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?${params}`;
    const headers = { 'User-Agent': 'bowire-nvd-sync' };
    if (NVD_KEY) headers.apiKey = NVD_KEY;

    // One gentle retry on the rate-limit / transient 5xx path.
    for (let attempt = 0; attempt < 2; attempt++) {
        const res = await fetch(url, { headers });
        if (res.ok) {
            const data = await res.json();
            return (data.vulnerabilities || []).map((v) => v.cve).filter(Boolean);
        }
        if (attempt === 0 && (res.status === 403 || res.status === 429 || res.status >= 500)) {
            await sleep(NVD_KEY ? 2000 : 8000);
            continue;
        }
        throw new Error(`NVD ${res.status} for "${keyword}": ${res.statusText}`);
    }
    return [];
}

function englishDesc(cve) {
    const d = (cve.descriptions || []).find((x) => x.lang === 'en');
    return d ? d.value : '(no English description)';
}

// ---- GitHub --------------------------------------------------------------

function gh(path, init = {}) {
    return fetch(`https://api.github.com${path}`, {
        ...init,
        headers: {
            Authorization: `Bearer ${TOKEN}`,
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'bowire-nvd-sync',
            ...(init.body ? { 'Content-Type': 'application/json' } : {}),
            ...(init.headers || {}),
        },
    });
}

async function existingTrackedCves() {
    // CVE ids already tracked by an nvd-sync issue (any state) so we never
    // re-open. Paginates the labelled issue list.
    const tracked = new Set();
    for (let page = 1; page <= 10; page++) {
        const res = await gh(`/repos/${REPO}/issues?state=all&labels=${LABEL}&per_page=100&page=${page}`);
        if (!res.ok) throw new Error(`GitHub issue list ${res.status}: ${res.statusText}`);
        const issues = await res.json();
        if (issues.length === 0) break;
        for (const issue of issues) {
            const m = /CVE-\d{4}-\d{4,}/i.exec(issue.title || '');
            if (m) tracked.add(m[0].toUpperCase());
        }
        if (issues.length < 100) break;
    }
    return tracked;
}

async function ensureLabel() {
    const res = await gh(`/repos/${REPO}/labels/${LABEL}`);
    if (res.ok) return;
    if (res.status !== 404) throw new Error(`GitHub label check ${res.status}: ${res.statusText}`);
    const create = await gh(`/repos/${REPO}/labels`, {
        method: 'POST',
        body: JSON.stringify({
            name: LABEL,
            color: '5319e7',
            description: 'Auto-opened by the monthly NVD sync — a new CVE that may need a template',
        }),
    });
    if (!create.ok && create.status !== 422 /* already exists, race */) {
        throw new Error(`GitHub label create ${create.status}: ${create.statusText}`);
    }
}

function issueTitle(c) {
    return c.nativeOnly
        ? `${c.id} — needs a ${c.protocol} probe?`
        : `${c.id} — needs a ${c.protocol} template?`;
}

function issueBody(c) {
    // The "author it" step differs by surface: a template lives here, but a
    // native-transport surface (MQTT) has no template shape — its probe lives
    // in the scanner. Pointing an author at `templates/mqtt/…` would send them
    // after a file the engine could never replay.
    const authorStep = c.nativeOnly
        ? `- [ ] If yes: this surface has **no template shape** — a template's probe is replayed over HTTP, and ${c.protocol} reaches its native transport without an HTTP handshake. Add a native probe in [\`Kuestenlogik/Bowire\`](https://github.com/Kuestenlogik/Bowire) next to the existing \`${c.protocol}\` probes in \`src/Kuestenlogik.Bowire.Security.Scanner/\`, and close this issue with a link to that PR.`
        : `- [ ] If yes: author \`templates/${c.protocol}/<name>.json\` per [\`docs/template-schema.md\`](../blob/main/docs/template-schema.md) + [\`CONTRIBUTING.md\`](../blob/main/CONTRIBUTING.md), listing \`${c.id}\` in \`vulnerability.cve\`.`;

    const lede = c.nativeOnly
        ? `A recently-published CVE matched the **${c.protocol}** keyword search. ${c.protocol.toUpperCase()} coverage lives as native scanner probes (not templates — see below), so triage whether this CVE warrants a new probe; otherwise close as not-applicable.`
        : `A recently-published CVE matched the **${c.protocol}** keyword search and has no template in this corpus yet. Assess whether it maps to a probeable, multi-protocol misconfiguration/vulnerability Bowire can detect — and if so, author a template; otherwise close as not-applicable.`;

    return [
        lede,
        '',
        `- **CVE:** [${c.id}](https://nvd.nist.gov/vuln/detail/${c.id})`,
        `- **Published:** ${c.published.slice(0, 10)}`,
        `- **CVSS:** ${c.score ?? 'n/a'}${c.severity ? ` (${c.severity})` : ''}`,
        `- **Matched surface:** \`${c.protocol}\` (keyword \`${c.keyword}\`)`,
        '',
        '**NVD description**',
        '',
        '> ' + englishDesc(c.raw).replace(/\n+/g, ' ').slice(0, 900),
        '',
        '---',
        '',
        '- [ ] Relevant to a Bowire-probeable surface (not a library-internal bug with no request-shaped signal)?',
        authorStep,
        '- [ ] If not: close as not-applicable (a comment on why helps the next triage).',
        '',
        `<sub>Opened automatically by \`scripts/nvd-sync.mjs\`. Re-runs skip any CVE that already has an \`${LABEL}\` issue or a covering template.</sub>`,
    ].join('\n');
}

async function createIssue(c) {
    const res = await gh(`/repos/${REPO}/issues`, {
        method: 'POST',
        body: JSON.stringify({ title: issueTitle(c), body: issueBody(c), labels: [LABEL] }),
    });
    if (!res.ok) throw new Error(`GitHub issue create ${res.status} for ${c.id}: ${res.statusText}`);
    const issue = await res.json();
    return issue.html_url;
}

// ---- main ----------------------------------------------------------------

async function main() {
    const now = new Date();
    const start = new Date(now.getTime() - DAYS * 86400 * 1000);
    console.log(`NVD sync — repo ${REPO}, lookback ${DAYS}d, CVSS ≥ ${MIN_CVSS}, cap ${MAX_ISSUES}, ${DRY_RUN ? 'DRY-RUN' : 'LIVE'}`);

    const covered = await coveredCveIds();
    console.log(`Templates cover ${covered.size} CVE id(s).`);

    const tracked = DRY_RUN ? new Set() : await existingTrackedCves();
    if (!DRY_RUN) console.log(`${tracked.size} CVE(s) already tracked by an ${LABEL} issue.`);

    // Gather candidates across every keyword, de-duplicating by CVE id (a CVE
    // that matches two keywords is filed once, under the first match).
    const seen = new Set();
    const candidates = [];
    for (const { keyword, protocol, nativeOnly = false } of PROTOCOL_KEYWORDS) {
        let cves;
        try {
            cves = await nvdSearch(keyword, start, now);
        } catch (err) {
            // A single flaky keyword shouldn't abort the whole monthly run.
            console.warn(`  ! ${keyword}: ${err.message}`);
            continue;
        }
        let kept = 0;
        for (const cve of cves) {
            const id = (cve.id || '').toUpperCase();
            if (!id || seen.has(id) || covered.has(id) || tracked.has(id)) continue;
            const { score, severity } = bestScore(cve);
            if (score === null || score < MIN_CVSS) continue;
            seen.add(id);
            candidates.push({ id, protocol, keyword, nativeOnly, published: cve.published || '', score, severity, raw: cve });
            kept++;
        }
        console.log(`  ${keyword}: ${cves.length} CVE(s) in window, ${kept} new candidate(s).`);
        // Be a good NVD citizen: stay under 5 req / 30s (no key) or 50 (key).
        await sleep(NVD_KEY ? 800 : 6500);
    }

    // Highest-severity first, then newest, then capped.
    candidates.sort((a, b) => (b.score - a.score) || (b.published < a.published ? -1 : 1));
    const planned = candidates.slice(0, MAX_ISSUES);

    console.log(`\n${candidates.length} candidate(s); opening ${planned.length}${candidates.length > planned.length ? ` (capped at ${MAX_ISSUES}; ${candidates.length - planned.length} NOT opened — see the note below)` : ''}:`);
    if (planned.length === 0) {
        console.log('  (nothing to open)');
        return;
    }

    if (!DRY_RUN) await ensureLabel();

    for (const c of planned) {
        if (DRY_RUN) {
            console.log(`  [dry-run] ${c.id}  ${String(c.score).padStart(4)} ${c.severity ?? ''}  →  ${issueTitle(c)}`);
        } else {
            const url = await createIssue(c);
            console.log(`  opened ${c.id} → ${url}`);
        }
    }

    if (candidates.length > planned.length) {
        const dropped = candidates.length - planned.length;
        const lowest = planned.at(-1)?.score;
        console.log(
            `\nNote: ${dropped} candidate(s) below CVSS ${lowest} were NOT opened (cap ${MAX_ISSUES}/run) and the next scheduled run will NOT surface them —\n` +
            `      its lookback window starts ${DAYS}d before *that* run, so today's un-opened tail falls out of scope permanently.\n` +
            `      This is a deliberate signal/noise trade-off: keyword matches are dominated by library-internal CVEs with no\n` +
            `      request-shaped probe, so the sync files only the top ${MAX_ISSUES} by severity. To reach the tail, dispatch the\n` +
            `      workflow manually with a larger 'days' window and NVD_SYNC_MAX_ISSUES / NVD_SYNC_MIN_CVSS raised.`);
    }
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
