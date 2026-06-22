// Copyright 2026 Küstenlogik
// SPDX-License-Identifier: Apache-2.0

/**
 * Walk templates/<protocol>/<name>.json and emit templates-index.json
 * at the repo root. The index summarises every template's metadata
 * so consumers (Bowire's Security rail, the CLI scanner) can filter
 * without parsing every template at runtime.
 *
 * Shape (schema 1):
 *
 *   {
 *     "schema": 1,
 *     "generatedAt": <unix-millis>,
 *     "count": <int>,
 *     "templates": [
 *       {
 *         "id": "bwr-graphql-001-introspection",       // template.id verbatim
 *         "path": "graphql/introspection-enabled.json", // relative to templates/
 *         "name": "...",                                // template.name
 *         "protocol": "graphql",                        // folder under templates/
 *         "protocols": ["graphql"],                     // template.vulnerability.protocols
 *         "severity": "medium",                         // .vulnerability.severity
 *         "cvss": 5.3,                                  // .vulnerability.cvss
 *         "cwe": "CWE-200",                             // .vulnerability.cwe
 *         "owaspApi": "API3-2023-BOPLA"                 // .vulnerability.owaspApi
 *       },
 *       ...
 *     ]
 *   }
 *
 * Sorted by protocol then id so the index is reproducible across
 * runs (no timestamp-driven ordering noise in git diffs).
 *
 * Idempotent. Run as `node scripts/generate-templates-index.mjs`
 * from the repo root, or via the Release workflow which invokes it
 * before the dotnet pack step.
 */

import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';

const REPO_ROOT = new URL('..', import.meta.url).pathname.replace(/^\/([A-Z]:\/)/, '$1');
const TEMPLATES_DIR = join(REPO_ROOT, 'templates');
const OUT_FILE = join(REPO_ROOT, 'templates-index.json');

async function walk(dir) {
    const entries = await readdir(dir, { withFileTypes: true });
    const out = [];
    for (const e of entries) {
        const p = join(dir, e.name);
        if (e.isDirectory()) out.push(...(await walk(p)));
        else if (e.isFile() && e.name.endsWith('.json')) out.push(p);
    }
    return out;
}

async function main() {
    const files = await walk(TEMPLATES_DIR);
    files.sort();

    const templates = [];
    for (const f of files) {
        const relPath = relative(TEMPLATES_DIR, f).replaceAll('\\', '/');
        const raw = await readFile(f, 'utf8');
        let doc;
        try {
            doc = JSON.parse(raw);
        } catch (err) {
            console.error(`Failed to parse ${relPath}: ${err.message}`);
            process.exit(2);
        }
        const v = doc.vulnerability || {};
        templates.push({
            id: doc.id,
            path: relPath,
            name: doc.name,
            // Folder-derived protocol; some templates declare additional
            // protocols in .vulnerability.protocols but the folder is the
            // canonical bucket for the corpus layout.
            protocol: relPath.split('/')[0],
            protocols: Array.isArray(v.protocols) ? v.protocols : [],
            severity: v.severity || null,
            cvss: typeof v.cvss === 'number' ? v.cvss : null,
            cwe: v.cwe || null,
            owaspApi: v.owaspApi || null
        });
    }

    // Stable sort: protocol → id. Keeps git diffs of the index small
    // when a single template is added or edited.
    templates.sort((a, b) => {
        if (a.protocol !== b.protocol) return a.protocol < b.protocol ? -1 : 1;
        return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    });

    const index = {
        schema: 1,
        // Pinned to repo-root so CI re-runs produce identical hashes.
        // Override via INDEX_GENERATED_AT env var when a real timestamp
        // is genuinely useful (e.g. a published release).
        generatedAt: process.env.INDEX_GENERATED_AT
            ? Number(process.env.INDEX_GENERATED_AT)
            : 0,
        count: templates.length,
        templates
    };

    await writeFile(OUT_FILE, JSON.stringify(index, null, 2) + '\n', 'utf8');
    console.log(`Wrote ${OUT_FILE}: ${templates.length} template(s)`);
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
