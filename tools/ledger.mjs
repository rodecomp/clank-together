// The byte ledger of a checkout's target: compiles and compares every unit with the strict check and
// partitions the original into proven, matched, differing, copied and open bytes (src/shared/ledger.js).
// Usage: node tools/ledger.mjs <checkout> [--json out.json] [--from check.json]
//   --from: take the functions from a saved check (a JSON with units[].functions[]) instead of compiling.
import fs from 'node:fs';
import path from 'node:path';
import { Workspace } from '../src/client/workspace.js';
import { checkUnits, summarizeCheck } from '../src/shared/check.js';
import { reconcile } from '../src/shared/reconcile.js';
import { scanAnnotations } from '../src/shared/project.js';
import { ledger, ledgerText } from '../src/shared/ledger.js';

const args = process.argv.slice(2);
const option = (name) => (args.includes(name) ? args.splice(args.indexOf(name), 2)[1] : null);
const json = option('--json');
const from = option('--from');
const [dir] = args;
if (!dir) throw new Error('usage: ledger.mjs <checkout> [--json out.json] [--from check.json]');
const ws = new Workspace(dir);
let units;
if (from) units = JSON.parse(fs.readFileSync(from, 'utf8')).units;
else {
  const project = ws.project;
  const result = await checkUnits({
    repoDir: ws.dir,
    jobDir: path.join(ws.tdDir, 'build-ledger'),
    incremental: true,
    scan: scanAnnotations(ws.dir, project, {}),
    project,
    units: Object.keys(project.compile?.units ?? {}).filter((u) => fs.existsSync(path.join(ws.dir, u))),
    symbols: ws.symbols,
    nameIndex: ws.nameIndex,
    pe: ws.pe,
    runners: ws.config.runners,
    timeoutMs: 3 * 3600_000,
    strict: true,
  });
  units = summarizeCheck(result, reconcile(result, ws.symbols, ws.pe)).units;
}
const l = ledger({ pe: ws.pe, manifest: ws.project.target, symbols: ws.symbols, functions: units.flatMap((u) => u.functions) });
if (json) fs.writeFileSync(json, JSON.stringify(l, null, 1));
console.log(ledgerText(l));
