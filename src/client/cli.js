#!/usr/bin/env node
// `td` - contributor CLI for Clank Together.

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { Workspace } from './workspace.js';
import * as ops from './ops.js';
import * as ghidra from './ghidra.js';
import { startMcp } from './mcp.js';
import { maybeUpdate } from './update.js';
import { hex } from '../shared/annotations.js';

const HELP = `td - Clank Together contributor client

Setup
  td setup <server-url> <dir> --token T       clone the repo,
       [--exe <your copy of the target>]      verify your exe, check the token,
       [--runner docker|native|wine]          configure the compiler
       [--toolchain <toolchain root>]         compiler layout of the project (e.g. re/toolchain)
       [--vc <VC dir>] [--sdk <SDK dir>] [--image <docker image>]
  td toolchain install                        download the compiler (approved accounts) for local checks
  td sync                                     pull main (clean tree only), verify/update target.exe and refresh symbols
  td ghidra download                          the server's Ghidra project (names applied, refreshed after merges)
  td ghidra install | build | sync            pinned Ghidra: install it, analyze locally, re-apply symbols
  td update                                   update td now (it also checks by itself once an hour)
  td connect [--workspace <dir>]              connect your AI (registers with Claude Code, prints MCP settings)
  td mcp [--workspace <dir>]                  run the MCP server for your agent (stdio)

Work (a region: a source file, a class, or a run of unplaced functions, done as a whole)
  td regions [--free] [--prefix P]            regions with open functions: free ones first
  td region claim <file> | --class <Name> | --range 0xA-0xB   claim a region (several agents may share one)
  td region release <file> | --class <Name> | --range 0xA-0xB give a region back
  td place <taskId>=<file.cpp>[:Class::Method] ...  put held functions that are in no source file into one
  td check [files...] [--includers]           compile + compare on this machine; named files over a clean HEAD
                                              (--includers: every unit that includes a changed header)
  td compile [--out DIR] [--jobs N] [--link-only]   build the whole program on this machine with the
                                              project's exeBuild command (data/decomp.json); incremental
  td submit [--notes T]                       submit the region's work as one batch
  td tasks [--state S] [--limit N]            list claimable tasks
  td improvable [--max-score 60] [--min-size 16]   merged functions that still differ, lowest % first:
       [--prefix P] [--by-unit] [--sort score|gain|size] [--all] [--limit N] [--json]
                                              claim the file (td region claim) and submit improvements
  td claim <taskId>                           claim a function that came back, to fix it
  td task <taskId>                            show a task's context
  td submit [taskId...] [--files a.cpp,b.h]   submit everything you hold (or these tasks, or only these files)
  td batch <batchId>                          state of a submitted batch, per function
  td returned [--watch] [--json]              your functions that came back (sent back, rejected, returned), per batch,
                                              with why; --watch polls and prints new ones as they come back
  td result <attemptId>                       show a verification result
  td withdraw <attemptId>                     take back a function waiting for review, to fix it
  td cancel <batchId>                         cancel a whole batch that has not finished (any kind); its functions return to your claim
  td heartbeat [taskId] | td release <taskId> extend your leases (all without an id)
  td config [ghidraHome|server <value>]       show or change workspace settings
  td symbol <id|name|0xaddr>                  look up a symbol
  td symbol new <kind> <0xaddr> [--name N]    get a stable ID for a new global/vtable/string/function
  td decompile <symbol> | td disasm <symbol>  query the local Ghidra project

Maintenance (maintainers: structural changes with no function tasks)
  td maintenance submit --files a.cpp,b.h --notes T [--force]   verified like a batch; merges only when no
                                              function's compiled code changes (--force, admins: merge
                                              despite lower scores or changed code; every other gate still runs)
       [--delete c.h,d.cpp]                   also remove these tracked files (units leave the build list)
                                              --files/--delete @list.txt read one path per line (large changes)
  td maintenance symbol <id> [--size N] [--name N] [--retire] --reason T   correct the symbol database
       [--decorated N | --swap-decorated-with ID]   correct a decorated name or atomically swap two
  td maintenance task <taskId> --close --batch B --reason T   admins: mark a task done whose code reached main
                                              through merged maintenance batch B
  td maintenance no-decompile <id|taskId>... --category C --reason T   claim functions already on main need
                                              no source (category: unreferenced, compiler_generated,
                                              runtime_library, generated_from_global, not_code, duplicate);
                                              peer review decides, then a maintenance batch may delete them

Peer review (attempts that are not byte-identical; judge by reading, not by tools)
  td peer list                                attempts waiting for review
  td peer claim [attemptId]                   claim one, prints instructions, original and submission
  td peer verdict <attemptId> same|different --reason "..."
  td peer release <attemptId>
`;

const print = (x) => console.log(typeof x === 'string' ? x : JSON.stringify(x, null, 2));

function printCheck(r) {
  for (const e of r.annotationErrors) console.log(`annotation: ${e.file}:${e.line} ${e.message}`);
  for (const u of r.units) {
    console.log(`\n${u.file}: ${u.compiled ? 'compiled' : 'FAILED'}`);
    if (!u.compiled) console.log(u.log);
    for (const e of [...u.lintErrors, ...u.errors]) console.log(`  ! ${e.message}`);
    for (const f of u.functions) {
      console.log(`  ${f.id} ${f.addr ?? '?'} ${(f.name ?? '').padEnd(30)} ${f.status.padEnd(17)} ${(f.score * 100).toFixed(1)}%  size ${f.size?.ours ?? '-'}/${f.size?.original ?? '?'}${f.effectiveHash ? `  ${f.effectiveHash}` : ''}`);
      if (f.deletingDestructor) console.log(`      ${f.id} is a scalar deleting destructor in the original: remove this annotation and claim it no-decompile (compiler_generated)`);
      for (const d of f.diffRegions ?? []) console.log(`      +0x${d.offset.toString(16)}: ours ${d.ours} orig ${d.original}  ${d.ourInstruction ?? ''}${d.sourceLine ? ` (line ${d.sourceLine})` : ''}`);
      for (const x of f.relocations ?? []) console.log(`      reloc +0x${x.offset.toString(16)} ${x.symbol}: ${x.ok ? `not yet named, original points at 0x${hex(x.actual)}` : x.reason}`);
    }
    for (const f of u.folded ?? []) console.log(`  FOLDED ${f.id} (line ${f.line})${''.padEnd(22)} ${f.status.padEnd(17)} ${(f.score * 100).toFixed(1)}%  size ${f.size?.ours ?? '-'}/${f.size?.original ?? '?'}`);
    if (u.unannotated.length) console.log(`  unannotated: ${u.unannotated.join(', ')}`);
  }
  for (const c of r.referenceConflicts) console.log(`conflict: ${c.message ?? c}`);
}

function printImprovable(r, json) {
  if (json) return print(r);
  const pct = (x) => `${Math.round(x * 100)}%`.padStart(4);
  const who = (c) => (c?.length ? `  claimed: ${c.join(', ')}` : '');
  if (!r.items.length) console.log('nothing below this score');
  else if (r.by === 'unit') {
    console.log('lowest  avg  below  bytes  file');
    for (const u of r.items) console.log(`  ${pct(u.minScore)} ${pct(u.avgScore)}  ${String(u.below).padStart(5)}  ${String(u.bytes).padStart(5)}  ${u.unit}${who(u.claimedBy)}`);
  } else {
    console.log('score   size  symbol    name  (file)');
    for (const f of r.items) console.log(` ${pct(f.score)}  ${String(f.size ?? '?').padStart(5)}  ${f.symbol.padEnd(8)}  ${f.name ?? '?'}  (${f.unit})${f.relocOnly ? '  [code matches]' : ''}${who(f.claimedBy)}`);
  }
  const shown = r.items.length < r.total ? `${r.items.length} of ${r.total}` : `${r.total}`;
  const notes = [];
  if (r.hidden?.inFlight) notes.push(`${r.hidden.inFlight} already on their way to main`);
  if (r.hidden?.relocOnly) notes.push(`${r.hidden.relocOnly} whose code already matches (only a reference the original has no relocation for differs; --all shows them)`);
  console.log(`\n${shown} ${r.by === 'unit' ? 'files' : 'functions'}${notes.length ? `; not listed: ${notes.join(', ')}` : ''}`);
  if (r.items.length) console.log('next: td region claim <file>, td check <file>, improve, then td submit <taskIds> --files <file> (a revision: peer reviewed, main stays as it is if it goes back)');
}

function printReturned(r) {
  for (const b of r.batches) {
    console.log(`\nbatch ${b.batchId}${b.returned ? `: ${b.returned}` : ''}`);
    for (const f of b.functions) {
      const score = f.score == null ? '-' : `${(f.score * 100).toFixed(1)}%`;
      const held = f.taskState === 'leased' ? ` held by ${f.holder}` : ` task ${f.taskState}`;
      console.log(`  #${f.taskId} ${f.symbol} ${(f.name ?? '').padEnd(30)} ${f.state.padEnd(13)} ${score.padStart(6)} attempt ${f.attemptId}${held}  ${f.unit ?? ''}`);
      if (f.summary) console.log(`      ${f.summary}`);
      if (f.peerOutcome) console.log(`      ${f.peerOutcome}`);
      for (const v of f.peerDifferent) console.log(`      different (${v.reviewer}): ${v.reason?.text ?? v.reason ?? ''}`);
      for (const c of f.reviewerComments) console.log(`      ${c.action}: ${c.comment?.text ?? ''}`);
    }
  }
  console.log(`\n${r.functions} function(s) to fix in ${r.batches.length} batch(es); td claim <taskId>, fix, td check, td submit <taskIds> --files ...`);
}

async function watchReturned(client, json) {
  const seen = new Set();
  for (;;) {
    const r = await client.get('/api/me/returned');
    const fresh = r.batches.map((b) => ({ ...b, functions: b.functions.filter((f) => !seen.has(f.attemptId)) })).filter((b) => b.functions.length);
    for (const b of r.batches) for (const f of b.functions) seen.add(f.attemptId);
    if (fresh.length) {
      const out = { functions: fresh.reduce((n, b) => n + b.functions.length, 0), batches: fresh };
      json ? console.log(JSON.stringify(out)) : (console.log(`== ${new Date().toISOString()}`), printReturned(out));
    }
    await new Promise((done) => setTimeout(done, 60_000));
  }
}

/** How an MCP client starts us: the td binary itself, or node + this script when run from source. */
async function launcher() {
  const sea = await import('node:sea').catch(() => null);
  return sea?.isSea?.() ? { command: process.execPath, args: [] } : { command: process.execPath, args: [path.resolve(process.argv[1])] };
}

/**
 * Registers the MCP server with Claude Code when it is installed, and prints the settings
 * for every other MCP client.
 */
async function connect(dir) {
  const ws = Workspace.find(dir);
  const l = await launcher();
  const args = [...l.args, 'mcp', '--workspace', ws.dir];
  const claude = spawnSync(process.platform === 'win32' ? 'claude.cmd' : 'claude', ['mcp', 'add', '--scope', 'user', 'clank-together', '--', l.command, ...args], { encoding: 'utf8', shell: process.platform === 'win32' });
  if (claude.status === 0) console.log('Claude Code: connected (MCP server "clank-together"). Start claude and ask it to read AGENTS.md and claim a task.');
  else console.log('Claude Code: not found, or already connected (claude mcp list shows it).');
  console.log(`\nOther MCP clients (Claude Desktop, Cursor, Windsurf, VS Code, Cline, Codex, Gemini CLI, ...): add this to their MCP server settings:
${JSON.stringify({ mcpServers: { 'clank-together': { command: l.command, args } } }, null, 2)}

Agents without MCP can run the td commands directly: td tasks, td claim, td check, td submit, td peer ...`);
}

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      name: { type: 'string' },
      token: { type: 'string' },
      exe: { type: 'string' },
      toolchain: { type: 'string' },
      runner: { type: 'string' },
      vc: { type: 'string' },
      sdk: { type: 'string' },
      image: { type: 'string' },
      state: { type: 'string' },
      limit: { type: 'string', default: '20' },
      notes: { type: 'string' },
      unit: { type: 'string' },
      range: { type: 'string' },
      files: { type: 'string' },
      delete: { type: 'string' },
      reason: { type: 'string' },
      category: { type: 'string' },
      size: { type: 'string' },
      decorated: { type: 'string' },
      'swap-decorated-with': { type: 'string' },
      'clear-decorated': { type: 'boolean', default: false },
      retire: { type: 'boolean', default: false },
      close: { type: 'boolean', default: false },
      batch: { type: 'string' },
      json: { type: 'boolean', default: false },
      free: { type: 'boolean', default: false },
      includers: { type: 'boolean', default: false },
      prefix: { type: 'string' },
      class: { type: 'string' },
      force: { type: 'boolean', default: false },
      workspace: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
      watch: { type: 'boolean', default: false },
      'max-score': { type: 'string' },
      'min-size': { type: 'string' },
      sort: { type: 'string' },
      'by-unit': { type: 'boolean', default: false },
      all: { type: 'boolean', default: false },
      out: { type: 'string' },
      jobs: { type: 'string' },
      'link-only': { type: 'boolean', default: false },
    },
  });
  const [cmd, ...args] = positionals;
  if (!cmd || values.help) return print(HELP);

  // Self-update (standalone binary only): at most once an hour, never fatal.
  const serverHint = cmd === 'setup' ? args[0] : (() => { try { return Workspace.find(values.workspace ?? process.cwd()).config.server; } catch { return null; } })();
  const updated = await maybeUpdate({ server: serverHint, force: cmd === 'update' });
  if (updated) process.stderr.write(`${updated}\n`);
  if (cmd === 'update') return print(updated ?? 'td is up to date');

  if (cmd === 'setup') {
    const [server, dir] = args;
    if (!server || !dir) throw new Error('usage: td setup <server-url> <dir> --token <API token from the website>');
    const ws = await ops.setup({ server, dir, token: values.token, exe: values.exe, toolchain: values.toolchain, runner: values.runner, vc: values.vc, sdk: values.sdk, image: values.image });
    const remote = ws.config.runners?.[ws.project.toolchain]?.type === 'remote';
    console.log(`\nworkspace ready at ${ws.dir}
  compiling: ${remote ? 'not set up yet: run td toolchain install (downloads the compiler; checks compile on your machine)' : 'locally'}
  original code: ${ws.config.ghidraHome ? 'local Ghidra' : "from the server; a local Ghidra is optional (td ghidra install && td ghidra build)"}
connect your AI with:  td connect --workspace "${ws.dir}"`);
    return;
  }
  if (cmd === 'connect') return connect(values.workspace ?? process.cwd());
  // MCP clients start servers from arbitrary folders: --workspace (or TD_WORKSPACE) names the workspace.
  if (cmd === 'mcp') return startMcp(values.workspace ?? process.env.TD_WORKSPACE ?? process.cwd());

  const ws = Workspace.find();
  const client = ops.api(ws);
  switch (cmd) {
    case 'sync':
      return print(await ops.sync(ws));
    case 'tasks':
      for (const t of await client.get(`/api/tasks?limit=${values.limit}${values.state ? `&state=${values.state}` : ''}`)) {
        console.log(`#${String(t.id).padEnd(6)} ${t.symbol_id} ${t.addr} size ${String(t.size ?? '?').padEnd(6)} d${t.difficulty} ${t.state.padEnd(13)} best ${(t.best_score * 100).toFixed(0)}% ${t.name ?? ''} ${t.unit ?? ''}`);
      }
      return;
    case 'improvable':
      return printImprovable(await ops.improvable(ws, {
        maxScore: values['max-score'],
        minSize: values['min-size'],
        prefix: values.prefix,
        byUnit: values['by-unit'],
        sort: values.sort,
        limit: values.limit,
        includeRelocOnly: values.all,
      }), values.json);
    case 'claim': {
      // td claim [taskId] | td claim --unit <file> | td claim --range 0x140001000-0x140002000 [--limit N]
      if (values.unit) return print(await ops.claimRegion(ws, { kind: 'unit', key: ops.relPath(ws, values.unit) }));
      if (!args[0]) throw new Error('claim new work by region: td regions, then td region claim <file>; td claim <taskId> fixes a function that came back');
      return print(await client.post('/api/tasks/claim', { taskId: Number(args[0]) }));
    }
    case 'task':
      return print(await client.get(`/api/tasks/${args[0]}`));
    case 'heartbeat':
      return print(args[0] ? await client.post(`/api/tasks/${args[0]}/heartbeat`) : await client.post('/api/tasks/heartbeat-all'));
    case 'batch':
      return print(await client.get(`/api/batches/${args[0]}`));
    case 'returned':
      if (values.watch) return watchReturned(client, values.json);
      return values.json ? print(await client.get('/api/me/returned')) : printReturned(await client.get('/api/me/returned'));
    case 'release':
      return print(await client.post(`/api/tasks/${args[0]}/release`));
    case 'withdraw':
      return print(await client.post(`/api/attempts/${args[0]}/withdraw`));
    case 'cancel':
      if (!args[0]) throw new Error('usage: td cancel <batchId>');
      return print(await client.post(`/api/batches/${args[0]}/cancel`));
    case 'toolchain':
      if (args[0] === 'install') return print(await ops.toolchainInstall(ws));
      throw new Error('usage: td toolchain install');
    case 'regions': {
      const r = await ops.regions(ws, { free: values.free, prefix: values.prefix, limit: Number(values.limit) || 30 });
      if (values.json) return print(r);
      for (const g of r.regions) {
        console.log(`${g.free ? 'free   ' : g.blocked ? 'blocked' : 'shared '} ${String(g.open).padStart(4)} open ${String(g.done).padStart(4)} done  ${g.key}${g.claimedBy.length ? `  (claimed by ${g.claimedBy.join(', ')})` : ''}`);
      }
      return console.log(`${r.regions.length} of ${r.total} regions`);
    }
    case 'region': {
      const [sub, key] = args;
      const target = values.class ? { kind: 'class', key: values.class } : values.range ? { kind: 'range', key: values.range } : { kind: 'unit', key: key ? ops.relPath(ws, key) : null };
      if (sub === 'claim') return print(await ops.claimRegion(ws, target));
      if (sub === 'release') return print(await ops.releaseRegion(ws, target));
      throw new Error('usage: td region claim|release <file> | --class <Name> | --range 0x<start>-0x<end>');
    }
    case 'place': {
      const assignments = args.map((x) => {
        const m = /^(\d+)=([^:]+)(?::(.+))?$/.exec(x);
        if (!m) throw new Error('usage: td place <taskId>=<file.cpp>[:Class::Method] ...');
        return { taskId: Number(m[1]), unit: ops.relPath(ws, m[2]), ...(m[3] && { name: m[3] }) };
      });
      if (!assignments.length) throw new Error('usage: td place <taskId>=<file.cpp>[:Class::Method] ...');
      const r = await client.post('/api/tasks/place', { assignments });
      await ops.refreshSymbols(ws);
      return print(r);
    }
    case 'check': {
      const r = await ops.check(ws, args.map((f) => ops.relPath(ws, f)), { includers: values.includers });
      return values.json ? print(r) : printCheck(r);
    }
    case 'compile': {
      const command = ws.project.exeBuild;
      if (!Array.isArray(command) || !command.length) throw new Error('this project has no exeBuild command in data/decomp.json');
      const extra = [...(values.out ? ['--out', values.out] : []), ...(values.jobs ? ['--jobs', values.jobs] : []), ...(values['link-only'] ? ['--link-only'] : [])];
      const r = spawnSync(command[0], [...command.slice(1), ...extra, ...args], { cwd: ws.dir, stdio: 'inherit', shell: process.platform === 'win32' });
      if (r.error) throw r.error;
      process.exitCode = r.status ?? 1;
      return;
    }
    case 'submit': {
      // td submit                 everything you hold, as one batch
      // td submit <taskId>... [--files a.cpp,b.h]
      const ids = args.filter((x) => /^\d+$/.test(x)).map(Number);
      const files = values.files ? values.files.split(',').map((f) => ops.relPath(ws, f)) : [];
      return print(await ops.submit(ws, ids, { files, notes: values.notes, agentMeta: { client: 'td-cli' } }));
    }
    case 'maintenance': {
      const [sub, id] = args;
      if (sub === 'submit') {
        if (!values.files && !values.delete) throw new Error('usage: td maintenance submit [--files a.cpp,b.h | --files @list.txt] [--delete c.h | --delete @list.txt] --notes "what and why" [--force]');
        // @file: one path per line (or comma-separated), for changes too large for a command line.
        const list = (v) => (v.startsWith('@') ? fs.readFileSync(v.slice(1), 'utf8') : v).split(/[\r\n,]+/).map((f) => f.trim()).filter(Boolean);
        const files = values.files ? list(values.files).map((f) => ops.relPath(ws, f)) : [];
        const deleted = values.delete ? list(values.delete).map((f) => ops.relPath(ws, f)) : [];
        return print(await ops.submitMaintenance(ws, files, { notes: values.notes, force: values.force, deleted }));
      }
      if (sub === 'symbol') {
        if (!id || !values.reason) throw new Error('usage: td maintenance symbol <id> [--size N] [--name N] [--retire] [--decorated N | --clear-decorated | --swap-decorated-with ID] --reason "evidence"');
        if (values['clear-decorated'] && values.decorated !== undefined) throw new Error('--clear-decorated and --decorated are exclusive');
        const body = {
          reason: values.reason,
          ...(values.size !== undefined && { size: Number(values.size) }),
          ...(values.name !== undefined && { name: values.name }),
          ...(values.retire && { retire: true }),
          ...(values.decorated !== undefined && { decorated: values.decorated }),
          ...(values['clear-decorated'] && { decorated: null }),
          ...(values['swap-decorated-with'] !== undefined && { swapDecoratedWith: values['swap-decorated-with'] }),
        };
        return print(await ops.correctSymbol(ws, id, body));
      }
      if (sub === 'task') {
        if (!/^\d+$/.test(id ?? '') || !values.close || !values.batch || !values.reason) throw new Error('usage: td maintenance task <taskId> --close --batch <maintenanceBatchId> --reason "why"');
        return print(await client.post(`/api/admin/tasks/${id}`, { state: 'done', batch: Number(values.batch), reason: values.reason }));
      }
      if (sub === 'no-decompile') {
        const targets = args.slice(1);
        if (!targets.length || !values.category || !values.reason) throw new Error('usage: td maintenance no-decompile <fn_id|taskId>... --category unreferenced|compiler_generated|runtime_library|generated_from_global|not_code|duplicate --reason "what in the original shows it"');
        const items = targets.map((t) => ({ ...(/^\d+$/.test(t) ? { taskId: Number(t) } : { symbolId: t }), category: values.category, reason: values.reason }));
        return print(await client.post('/api/tasks/no-decompile', { onMain: true, items }));
      }
      throw new Error('usage: td maintenance submit|symbol|task|no-decompile ...');
    }
    case 'result': {
      const r = await client.get(`/api/attempts/${args[0]}`);
      delete r.files;
      return print(r);
    }
    case 'symbol': {
      if (args[0] === 'new') {
        const r = await client.post('/api/symbols', { kind: args[1], addr: args[2], name: values.name });
        await ops.refreshSymbols(ws);
        return print(r);
      }
      const s = ws.findSymbol(args[0]);
      return print(s ? { ...s, addr: s.addr != null ? '0x' + hex(s.addr) : null } : 'not found');
    }
    case 'peer': {
      const [sub, id, verdict] = args;
      if (sub === 'list') return print(await client.get('/api/peer-reviews'));
      if (sub === 'claim') return print(await client.post('/api/peer-reviews/claim', { attemptId: id ? Number(id) : undefined }));
      if (sub === 'show') return print(await client.get(`/api/peer-reviews/${id}`));
      if (sub === 'verdict') return print(await client.post(`/api/peer-reviews/${id}/verdict`, { verdict, reason: values.reason, agentMeta: { client: 'td-cli' } }));
      if (sub === 'release') return print(await client.post(`/api/peer-reviews/${id}/release`));
      throw new Error('usage: td peer list|claim [id]|show <id>|verdict <id> same|different --reason ...|release <id>');
    }
    case 'config': {
      // td config                    show settings (token hidden)
      // td config <key> <value>      set one, e.g. `td config ghidraHome D:\ghidra_12.2_PUBLIC`
      const [key, value] = args;
      const SETTABLE = ['ghidraHome', 'server'];
      if (!key) return print({ ...ws.config, token: ws.config.token ? '(set)' : null });
      if (!SETTABLE.includes(key)) throw new Error(`settable keys: ${SETTABLE.join(', ')}`);
      ws.config[key] = value;
      ws.save();
      return print(`${key} = ${value}`);
    }
    case 'ghidra':
      if (args[0] === 'install') return print(`Ghidra installed at ${await ghidra.installGhidra(ws)}`);
      if (args[0] === 'build') return void (await ghidra.buildGhidraProject(ws), print('Ghidra project built'));
      if (args[0] === 'sync') return void (await ghidra.syncGhidraProject(ws), print('symbols applied'));
      if (args[0] === 'download') {
        const r = await ghidra.downloadGhidraProject(ws, { force: values.force });
        return print(r.updated ? `Ghidra project of ${r.info.version} downloaded${ws.config.ghidraHome ? '' : ` (open it with Ghidra ${r.info.ghidra}, or run td ghidra install)`}` : 'the Ghidra project is up to date');
      }
      throw new Error('usage: td ghidra install|download|build|sync');
    case 'decompile':
    case 'disasm': {
      // Local Ghidra if configured, otherwise the server's export.
      return print(await ops.original(ws, args[0], cmd === 'decompile' ? 'c' : 'asm'));
    }
    default:
      print(HELP);
      process.exitCode = 1;
  }
}

main().catch((e) => {
  console.error(e.message);
  process.exitCode = 1;
});
