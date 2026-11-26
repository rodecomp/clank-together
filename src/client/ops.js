// Contributor operations, shared by the `td` CLI and the MCP server.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { Api } from './api.js';
import { Workspace, sha256File } from './workspace.js';
import { checkUnits, summarizeCheck } from '../shared/check.js';
import { reconcile } from '../shared/reconcile.js';
import { lintSubmission, matchesAny } from '../shared/lint.js';
import { isUnit, loadToolchainLock, scanAnnotations } from '../shared/project.js';
import { hex } from '../shared/annotations.js';
import { run, unitPrelude } from '../shared/build.js';
import { rememberServer } from './update.js';
import { extractTarGz } from '../shared/tar.js';
import { functionRegions } from '../server/split.js';

export function api(ws) {
  return new Api(ws.config.server, ws.config.token);
}

/**
 * Creates a workspace: clones the repo, downloads and verifies the target,
 * fetches the symbol snapshot and records toolchain settings.
 */
export async function setup({ server, dir, token, exe, runner, vc, sdk, image, toolchain, log = console.log }) {
  const anon = new Api(server);
  const info = await anon.get('/api/info');
  if (!info.version) throw new Error('the server has no target version yet');

  const abs = path.resolve(dir);
  const existing = new Workspace(abs);
  const useToken = token ?? existing.config.token;
  if (!useToken) {
    throw new Error(`pass --token <API token>. Register at ${server}, wait for an admin to approve you, then create a token under "Account"`);
  }
  // Check the token first: the target download may be limited to approved contributors.
  const authed = new Api(server, useToken);
  const me = await authed.get('/api/me');
  log(`authenticated as ${me.name} (${me.role})`);

  if (!fs.existsSync(path.join(abs, '.git'))) {
    log(`cloning ${info.git} into ${abs}`);
    execFileSync('git', ['clone', '-q', info.git, abs], { stdio: 'inherit' });
  }
  const ws = new Workspace(abs);
  ws.config.server = server.replace(/\/+$/, '');
  rememberServer(ws.config.server);
  ws.config.token = useToken;
  ws.config.user = me.name;
  fs.mkdirSync(ws.tdDir, { recursive: true });
  ensureIgnored(ws);

  if (exe) {
    const got = sha256File(exe);
    if (got !== info.version.sha256) throw new Error(`${exe} is not the target of version ${info.version.id}: sha256 ${got}, expected ${info.version.sha256}`);
    fs.copyFileSync(exe, ws.targetFile);
  } else {
    await refreshTarget(ws, info.version, log);
  }
  log(`target verified: sha256 ${info.version.sha256}`);

  const lock = loadToolchainLock(abs)[info.toolchain] ?? {};
  ws.config.runners = { [info.toolchain]: runnerConfig({ runner, vc, sdk, image: image ?? (runner === 'docker' ? lock.image : undefined), toolchain, project: ws.project }) };
  ws.save();
  await refreshSymbols(ws, info.version.id);
  ws.config.envDigest = await computeEnvDigest(ws, info.toolchain);
  if (lock.clSha256 && ws.config.envDigest && ws.config.envDigest !== lock.clSha256) {
    log(`WARNING: your cl.exe (sha256 ${ws.config.envDigest}) is not the pinned one (${lock.clSha256}); results may differ from the server`);
  }
  ws.save();
  writeEditorCompileDb(ws);
  return ws;
}

function ensureIgnored(ws) {
  const gi = path.join(ws.dir, '.git', 'info', 'exclude');
  const cur = fs.existsSync(gi) ? fs.readFileSync(gi, 'utf8') : '';
  if (!cur.split(/\r?\n/).includes('.td/')) fs.appendFileSync(gi, `${cur.endsWith('\n') || !cur ? '' : '\n'}.td/\n`);
}

function runnerConfig({ runner, vc, sdk, image, toolchain, project }) {
  // --toolchain: a toolchain root laid out like the project's compile commands expect (${TC});
  // the compiler path and include environment come from config/compile.json.
  if (toolchain) {
    if (!project.compile?.compiler) throw new Error('this project has no compile.json compiler entry; use --vc instead of --toolchain');
    const type = runner ?? (os.platform() === 'win32' ? 'native' : 'wine');
    const root = type === 'wine' ? 'Z:' + path.posix.resolve(toolchain).replace(/\//g, '\\') : path.win32.resolve(toolchain);
    const clPath = project.compile.compiler.replaceAll('${TC}', type === 'wine' ? path.posix.resolve(toolchain) : root).replace(type === 'wine' ? /\\/g : /\//g, type === 'wine' ? '/' : '\\');
    if (!fs.existsSync(clPath)) throw new Error(`compiler not found at ${clPath}`);
    const jobs = Math.max(1, os.cpus().length - 2);
    if (type === 'wine') return { type, clPath, wine: 'wine', toolchainRoot: root, jobs, env: { WINEDEBUG: '-all' } };
    return { type, clPath, toolchainRoot: root, jobs, env: { PATH: `${path.dirname(clPath)};${process.env.PATH ?? ''}` } };
  }
  // Nothing local given: compile on the server (remote check).
  if (!runner && !vc && !image) return { type: 'remote' };
  const type = runner ?? (os.platform() === 'win32' && vc ? 'native' : 'docker');
  if (type === 'remote') return { type };
  if (type === 'docker') {
    if (!image) throw new Error('no docker image configured; pass --image or set it in data/toolchain.lock.json');
    return { type, image };
  }
  if (!vc) throw new Error(`--vc <path to the VC directory of Visual Studio 2010> is required for the ${type} runner`);
  const p = type === 'wine' ? path.posix : path.win32;
  const clPath = p.join(vc, 'bin', 'cl.exe');
  if (type === 'wine') return { type, clPath, wine: 'wine', env: { WINEDEBUG: '-all' } };
  const include = [p.join(vc, 'include'), ...(sdk ? [p.join(sdk, 'Include')] : [])].join(';');
  const lib = [p.join(vc, 'lib'), ...(sdk ? [p.join(sdk, 'Lib')] : [])].join(';');
  const ide = p.join(vc, '..', 'Common7', 'IDE');
  return { type, clPath, env: { INCLUDE: include, LIB: lib, PATH: `${p.join(vc, 'bin')};${ide};${process.env.PATH ?? ''}` } };
}

async function computeEnvDigest(ws, toolchain) {
  const r = ws.config.runners?.[toolchain];
  if (!r) return null;
  if (r.type === 'remote') return null; // the server's compiler is the pinned one
  if (r.type !== 'docker') return fs.existsSync(r.clPath) ? sha256File(r.clPath) : null;
  const out = await run('docker', ['run', '--rm', '--network', 'none', r.image, 'sha256sum', '/opt/msvc/bin/cl.exe'], { timeoutMs: 120_000 });
  return /^[0-9a-f]{64}/.exec(out.output)?.[0] ?? null;
}

async function refreshTarget(ws, version, log) {
  if (!version?.sha256) throw new Error('the server has no target checksum');
  const updated = !fs.existsSync(ws.targetFile) || sha256File(ws.targetFile) !== version.sha256;
  if (updated) {
    if (!version.download) throw new Error(`this project does not distribute the target; provide ${ws.targetFile} for version ${version.id} (expected sha256 ${version.sha256})`);
    log?.(`downloading target ${version.id} (${(version.size / 1048576).toFixed(1)} MiB)`);
    await api(ws).download(version.download, ws.targetFile, version.sha256);
  }
  // Another process may already have replaced the file under a long-running MCP workspace.
  ws._pe = null;
  return updated;
}

export async function refreshSymbols(ws, version) {
  // The symbol table is large and changes in bursts; download it only when it changed.
  const etagFile = ws.symbolsFile + '.etag';
  const known = fs.existsSync(ws.symbolsFile) && fs.existsSync(etagFile) ? fs.readFileSync(etagFile, 'utf8') : null;
  const url = version ? `/api/symbols?version=${encodeURIComponent(version)}` : '/api/symbols';
  const r = await api(ws).getIfChanged(url, known);
  if (!r) return JSON.parse(fs.readFileSync(ws.symbolsFile, 'utf8'));
  fs.writeFileSync(ws.symbolsFile, JSON.stringify(r.data));
  if (r.etag) fs.writeFileSync(etagFile, r.etag);
  ws._symbols = null;
  return r.data;
}

/**
 * Writes the clangd compile database the repo's `.clangd` points at (`CompilationDatabase:`), from
 * data/compile.json with this clone's paths and the local toolchain. Every clone (main or worker
 * slot) gets its own, so editor diagnostics resolve includes of the clone being edited.
 */
export function writeEditorCompileDb(ws) {
  const clangd = path.join(ws.dir, '.clangd');
  const compile = ws.project.compile;
  const runner = ws.config.runners?.[ws.project.toolchain];
  if (!compile?.units || !runner?.toolchainRoot || !fs.existsSync(clangd)) return null;
  const dbDir = /^\s*CompilationDatabase:\s*(\S+)\s*$/m.exec(fs.readFileSync(clangd, 'utf8'))?.[1];
  if (!dbDir) return null;
  const toolchain = (runner.type === 'wine' ? runner.toolchainRoot.replace(/^Z:/i, '') : runner.toolchainRoot).replace(/\\/g, '/');
  const source = path.resolve(ws.dir).replace(/\\/g, '/');
  const expand = (s) => s.replaceAll('${TC}', toolchain).replaceAll('${SRC}', source);
  const compiler = expand(compile.compiler ?? runner.clPath);
  const includes = (compile.env?.INCLUDE ?? '').split(';').filter(Boolean).map((p) => `/imsvc${expand(p)}`);
  const entries = Object.entries(compile.units).map(([unit, shape]) => {
    const file = `${source}/${unit}`;
    const flags = compile.shapes[shape].filter((f) => !/^[/-]execution-charset:\./i.test(f)).map(expand);
    const prelude = unitPrelude(ws.project, unit, (rel) => fs.existsSync(path.join(ws.dir, rel)));
    const forced = prelude ? [`/FI${source}/${prelude}`] : [];
    return { directory: source, file, arguments: [compiler, ...flags, ...includes, ...forced, file] };
  });
  const out = path.join(ws.dir, dbDir, 'compile_commands.json');
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify(entries, null, 1));
  return out;
}

/**
 * Fast-forwards the clone to the server's main and refreshes its target and symbols. Only a clean
 * working tree moves: in a shared checkout, uncommitted files may be someone's unfinished work.
 * When main was rewritten (same changes, new commit IDs), the clone's own commits no longer lie on
 * it and a fast-forward is impossible; if each of them is on main by content, nothing would be lost,
 * so the clone is moved to main. A local commit main does not have keeps the clone where it is.
 */
export async function sync(ws) {
  ws.git('fetch', '-q', 'origin');
  const changed = ws.changedFiles();
  let pulled = !changed.length;
  let rewritten = false;
  if (pulled) {
    try {
      ws.git('merge', '-q', '--ff-only', '@{u}');
    } catch {
      pulled = false;
      if (localCommitsOnUpstream(ws)) {
        ws.git('reset', '-q', '--keep', '@{u}');
        pulled = rewritten = true;
      }
    }
  }
  const { version } = await api(ws).get('/api/info');
  const updated = await refreshTarget(ws, version);
  const snap = await refreshSymbols(ws, version.id);
  // A newer Ghidra project on the server is only announced (it is a large download).
  let ghidra = null;
  try {
    const g = await api(ws).get('/api/ghidra-project');
    if (g.sha256 !== ws.config.ghidraPackage) ghidra = `a newer Ghidra project is available (${(g.size / 1048576).toFixed(0)} MB): td ghidra download`;
  } catch {}
  const note = changed.length
    ? `not fast-forwarded: ${changed.length} uncommitted files (${changed.slice(0, 5).join(', ')}); submit or set them aside first`
    : 'could not fast-forward (local commits or conflicting changes); merge origin/main yourself';
  writeEditorCompileDb(ws);
  return { head: ws.head(), fastForwarded: pulled, ...(rewritten && { rewrittenMain: true }), target: { version: version.id, sha256: version.sha256, updated }, symbols: snap.symbols.length, ghidra, note: pulled ? null : note };
}

/**
 * Whether every commit the clone has that its upstream lacks is on the upstream all the same: the
 * same change (git's patch-id, as `--cherry-pick` compares them), as after the server rewrote
 * main's history. Merge commits carry no patch of their own; one counts when its tree is on the
 * upstream too.
 */
export function localCommitsOnUpstream(ws) {
  const list = (...args) => ws.git(...args).split('\n').filter(Boolean);
  // --cherry-pick drops a commit whose change is also on the other side; --left-only keeps ours.
  if (list('rev-list', '--no-merges', '--left-only', '--cherry-pick', 'HEAD...@{u}').length) return false;
  const merges = list('rev-list', '--merges', '@{u}..HEAD');
  if (!merges.length) return true;
  const trees = new Set(list('log', '--format=%T', `${ws.git('merge-base', 'HEAD', '@{u}')}..@{u}`));
  return merges.every((m) => trees.has(ws.git('rev-parse', `${m}^{tree}`)));
}

/**
 * Compiles and compares locally with the same pipeline the server uses. `includers`: also every
 * unit that includes a changed header (what the server compiles before it merges), so a header
 * change is known to build everywhere before it is submitted.
 * Named files are compiled over a clean copy of HEAD, so other edits in a shared checkout (another
 * agent's unfinished work) are not part of the check. Without files: the working tree as it is.
 */
export async function check(ws, files, { wait = true, includers = false } = {}) {
  const project = ws.project;
  const explicit = !!files?.length;
  const targets = explicit ? files.map((f) => f.replace(/\\/g, '/')) : ws.changedFiles();
  const runner = ws.config.runners?.[project.toolchain];
  if (!runner || runner.type === 'remote') {
    if (ws.config.remoteChecks) return remoteCheck(ws, targets, { wait, explicit });
    throw new Error('no local compiler set up: run "td toolchain install" once (it downloads the compiler from the server, for approved accounts), then check again. The server only compiles submissions.');
  }
  const units = new Set(targets.filter(isUnit));
  const headers = targets.filter((f) => !isUnit(f) && /\.(h|hpp|inl)$/i.test(f));
  if (headers.length) {
    const { includers: map } = await api(ws).post('/api/includers', { headers });
    for (const list of Object.values(map)) {
      // Without includers: one unit per header, enough to see it compile and what it expands to.
      for (const u of includers ? list : list.slice(0, 1)) units.add(u);
    }
  }
  if (!units.size) throw new Error('nothing to check: pass .cpp files or modify some');
  const repoDir = explicit ? headTree(ws) : ws.dir;
  const overrides = explicit ? readFiles(ws, targets) : {};
  // One job directory per source tree, kept between checks and brought up to date by size and
  // mtime: copying the whole tree each time costs more than compiling a small unit.
  const tree = explicit ? 'head' : 'work';
  // Before per-tree job directories, every check recopied the tree into .td/build.
  fs.rmSync(path.join(ws.tdDir, 'build'), { recursive: true, force: true });
  const result = await checkUnits({
    repoDir,
    overrides,
    jobDir: path.join(ws.tdDir, `build-${tree}`),
    incremental: true,
    scan: scanAnnotations(repoDir, project, overrides, { cacheFile: path.join(ws.tdDir, `annotations-${tree}.json`) }),
    project,
    units: [...units],
    symbols: ws.symbols,
    nameIndex: ws.nameIndex,
    pe: ws.pe,
    runners: ws.config.runners,
  });
  const rec = reconcile(result, ws.symbols, ws.pe);
  return summarizeCheck(result, rec, new Set(targets));
}

/** A detached worktree at HEAD under .td/, updated on each use. */
function headTree(ws) {
  const dir = path.join(ws.tdDir, 'head');
  if (!fs.existsSync(path.join(dir, '.git'))) ws.git('worktree', 'add', '-q', '--detach', '-f', dir, 'HEAD');
  // -f: the tree is only read; anything left in it is discarded.
  execFileSync('git', ['checkout', '-q', '-f', '--detach', ws.head()], { cwd: dir, stdio: 'ignore' });
  return dir;
}

function readFiles(ws, files) {
  const out = {};
  for (const f of files) out[f] = fs.readFileSync(path.join(ws.dir, f), 'utf8');
  return out;
}

/**
 * Compiles and compares on the server (its sandboxed compiler), for contributors without a
 * local toolchain. Sends the changed files and the commit they are based on; nothing is submitted.
 */
async function remoteCheck(ws, targets, { wait = true, explicit = false } = {}) {
  const files = {};
  for (const f of new Set(explicit ? targets : [...targets, ...ws.changedFiles()])) {
    const abs = path.join(ws.dir, f);
    if (fs.existsSync(abs) && /\.(c|cc|cpp|cxx|h|hpp|inl)$/i.test(f)) files[f.replace(/\\/g, '/')] = fs.readFileSync(abs, 'utf8');
  }
  const r = await api(ws).post('/api/check', { baseCommit: ws.head(), files, ...(wait ? {} : { wait: false }) });
  if (r.checkId && !r.units) return { ...r, compiledOn: 'server' };
  if (r.gate === 'rejected') {
    const e = new Error('the static gate rejects this code:\n' + r.lintErrors.map((x) => `  ${x.file ?? ''}${x.line ? ':' + x.line : ''} ${x.message}`).join('\n'));
    e.details = r.lintErrors;
    throw e;
  }
  if (r.gate === 'conflict') throw new Error(`your changes conflict with newer work on main (${r.conflicts.join(', ')}); run td sync and merge`);
  return { ...r, compiledOn: 'server' };
}

/**
 * The original function as text. A local Ghidra (td ghidra install/build) answers locally;
 * otherwise, or when it is older than the release td pins (it cannot open the server's project),
 * the server's Ghidra export does.
 */
export async function original(ws, query, kind) {
  const { ghidraVersionAt, ghidraAtLeast, GHIDRA_RELEASE } = await import('../shared/ghidra.js');
  const local = ws.config.ghidraHome ? ghidraVersionAt(ws.config.ghidraHome) : null;
  if (local && ghidraAtLeast(local, GHIDRA_RELEASE.version)) {
    const { decompile, disassemble } = await import('./ghidra.js');
    const s = ws.findSymbol(query);
    const addr = s?.addr ?? (/^0x[0-9a-f]+$/i.test(query) ? Number.parseInt(query, 16) : null);
    if (addr == null) throw new Error(`unknown symbol ${query}`);
    return kind === 'asm' ? disassemble(ws, addr) : decompile(ws, addr);
  }
  const r = await api(ws).get(`/api/original/${encodeURIComponent(query)}`);
  if (kind === 'asm') return r.asm;
  return r.pseudocode ?? `// no pseudocode for ${r.symbol ?? query} yet (${r.source}); the assembly is available with td disasm`;
}

/**
 * Submits work. `taskIds` empty = every task you hold, as one batch (the regions you claimed,
 * plus functions you took back to fix). Defaults to all changed files those tasks allow; named
 * `files` are the whole submission, and only functions rewritten in them count as new work.
 */
export async function submit(ws, taskIds = [], { files, notes, agentMeta } = {}) {
  const me = await api(ws).get('/api/me');
  let ids = taskIds.length ? taskIds.map(Number) : me.leases;
  // Held functions whose code was not touched stay held; they are not new work.
  if (!taskIds.length && ids.length) {
    const rewritten = rewrittenFunctions(ws, me.leasedAllowedPaths ?? [], files);
    const symbols = me.leasedSymbols ?? [];
    ids = symbols.filter((t) => rewritten.has(t.symbol)).map((t) => t.taskId);
  }
  let allowed = taskIds.length ? (await api(ws).post('/api/tasks/allowed-paths', { taskIds: ids })).allowedPaths : me.leasedAllowedPaths;
  // Shared regions: functions another agent holds are submitted as competing candidates, but only
  // the ones this agent actually rewrote.
  if (!taskIds.length && me.regionTasks?.length) {
    const rewritten = rewrittenFunctions(ws, me.regionAllowedPaths ?? [], files);
    const extra = me.regionTasks.filter((t) => rewritten.has(t.symbol)).map((t) => t.taskId);
    if (extra.length) {
      ids = [...new Set([...ids, ...extra])];
      allowed = [...new Set([...allowed, ...(me.regionAllowedPaths ?? [])])];
    }
  }
  if (!ids.length && me.leases.length) {
    // Held, but none of them differs from HEAD in the working tree (committed locally, edited in
    // another clone, or written in a file outside the held ones' paths).
    throw new Error(
      `none of the ${me.leases.length} functions you hold has changed code in this working tree compared with HEAD (${(me.leasedAllowedPaths ?? []).slice(0, 5).join(', ')}). ` +
        'Leave your work uncommitted in this clone, or name the tasks: td_submit taskIds: [...]',
    );
  }
  if (!ids.length) throw new Error('you hold no tasks; claim a region first (td_regions, then td_claim_region)');
  const candidates = files?.length ? files : ws.changedFiles().filter((f) => matchesAny(f, allowed));
  if (!candidates.length) throw new Error(`no changed files match the allowed paths of your tasks (${allowed.join(', ')})`);
  const contents = {};
  for (const f of candidates) contents[f.replace(/\\/g, '/')] = fs.readFileSync(path.join(ws.dir, f), 'utf8');
  const errors = lintSubmission(contents, { allowedPaths: allowed, limits: ws.project.lintLimits, allowedPragmas: ws.project.allowedPragmas, baseSize: (f) => ws.size(f), trackedPaths: ws.trackedPaths(), unitPrelude: ws.project.unitPrelude, baseText: (f) => ws.show(f) });
  if (errors.length) {
    const e = new Error('submission fails the static gate:\n' + errors.map((x) => `  ${x.file ?? ''}${x.line ? ':' + x.line : ''} ${x.message}`).join('\n'));
    e.details = errors;
    throw e;
  }
  return api(ws).post('/api/batches', { taskIds: ids, baseCommit: ws.head(), files: contents, notes, agentMeta, envDigest: ws.config.envDigest });
}

/**
 * A maintenance batch (maintainers): the named files, with no function tasks. The server checks it
 * like any batch and merges it only when no function's compiled code changes.
 */
export async function submitMaintenance(ws, files, { notes, force = false, deleted = [] } = {}) {
  if (!files.length && !deleted.length) throw new Error('name the files of the change (--files a.cpp,b.h and/or --delete c.h)');
  const contents = {};
  for (const f of files) contents[f.replace(/\\/g, '/')] = fs.readFileSync(path.join(ws.dir, f), 'utf8');
  const tracked = new Set(ws.trackedPaths());
  for (const f of deleted.map((x) => x.replace(/\\/g, '/'))) {
    if (Object.hasOwn(contents, f)) throw new Error(`${f} is both submitted and deleted`);
    if (!tracked.has(f)) throw new Error(`${f} is not tracked on main; nothing to delete`);
    contents[f] = null;
  }
  const errors = lintSubmission(contents, { allowedPaths: [`${ws.project.sourceDirs[0]}/**`, ...ws.project.headerGlobs], limits: ws.project.lintLimits, allowedPragmas: ws.project.allowedPragmas, baseSize: (f) => ws.size(f), trackedPaths: [...tracked], allowDeletions: true, unitPrelude: ws.project.unitPrelude, baseText: (f) => ws.show(f) });
  if (errors.length) {
    const e = new Error('submission fails the static gate:\n' + errors.map((x) => `  ${x.file ?? ''}${x.line ? ':' + x.line : ''} ${x.message}`).join('\n'));
    e.details = errors;
    throw e;
  }
  return api(ws).post('/api/maintenance', { baseCommit: ws.head(), files: contents, notes, ...(force && { force: true }) });
}

/** Correct symbol metadata and immediately replace the workspace's cached name mappings. */
export async function correctSymbol(ws, id, correction) {
  const result = await api(ws).post(`/api/admin/symbols/${encodeURIComponent(id)}`, correction);
  await refreshSymbols(ws);
  return result;
}

/** Annotated functions whose definition differs from HEAD in the changed (or named) files under allowed paths. */
function rewrittenFunctions(ws, allowed, files) {
  const out = new Set();
  const changed = files?.length ? files.map((f) => f.replace(/\\/g, '/')) : ws.changedFiles();
  for (const f of changed.filter((x) => matchesAny(x, allowed))) {
    const abs = path.join(ws.dir, f);
    if (!fs.existsSync(abs)) continue;
    const text = fs.readFileSync(abs, 'utf8').replace(/\r\n/g, '\n');
    let before = null;
    try {
      before = ws.gitRaw('show', 'HEAD:' + f.replace(/\\/g, '/'));
    } catch {}
    const now = functionRegions(text);
    const old = before ? functionRegions(before) : new Map();
    if (!now) continue;
    const body = (t, r) => t.split('\n').slice(r.start, r.end).join('\n');
    for (const [id, r] of now) {
      const o = old?.get(id);
      if (!o || body(before, o) !== body(text, r)) out.add(id);
    }
  }
  return out;
}

// --- regions (a source file or class worked on as a whole)

export function regions(ws, { free = false, prefix = null, limit = 30 } = {}) {
  return api(ws).get('/api/regions?limit=' + limit + (free ? '&free=1' : '') + (prefix ? '&prefix=' + encodeURIComponent(prefix) : ''));
}

export function claimRegion(ws, { kind = 'unit', key }) {
  if (!key) throw new Error('name the region: the source file (kind unit) or the class (kind class)');
  return api(ws).post('/api/regions/claim', { kind, key });
}

/** Merged functions that still differ from the original, lowest score first. `maxScore` is a percent. */
export function improvable(ws, { maxScore, minSize, prefix, byUnit = false, sort, limit, includeRelocOnly = false } = {}) {
  const q = new URLSearchParams();
  if (maxScore != null && maxScore !== '') {
    const pct = Number(maxScore);
    if (!Number.isFinite(pct) || pct < 0 || pct > 100) throw new Error('--max-score is a percentage from 0 to 100');
    q.set('maxScore', String(pct / 100));
  }
  if (minSize != null && minSize !== '') q.set('minSize', String(minSize));
  if (prefix) q.set('prefix', prefix);
  if (byUnit) q.set('by', 'unit');
  if (sort) q.set('sort', sort);
  if (limit != null && limit !== '') q.set('limit', String(limit));
  if (includeRelocOnly) q.set('includeRelocOnly', '1');
  return api(ws).get('/api/improvable?' + q.toString());
}

export function releaseRegion(ws, { kind = 'unit', key }) {
  return api(ws).post('/api/regions/release', { kind, key });
}

/**
 * Downloads the compiler package from the server (approved accounts only), unpacks it into
 * ~/.clank/toolchains/<hash> (shared by every workspace) and points this workspace at it.
 */
export async function toolchainInstall(ws, { log = console.log } = {}) {
  const meta = await api(ws).get('/api/toolchain');
  if (!meta.available) throw new Error(meta.note ?? 'the server has no compiler package');
  if (os.platform() !== 'win32') {
    try {
      execFileSync('wine', ['--version'], { stdio: 'ignore' });
    } catch {
      throw new Error(process.arch === 'x64'
        ? 'the compiler is a Windows program: install wine first (e.g. apt install wine64), then run td toolchain install again'
        : `the compiler is an x86 Windows program: on ${process.arch} it needs x86 wine under emulation (box64 + wine, or an x86-64 container: docker run --platform linux/amd64), then run td toolchain install again`);
    }
  }
  const base = path.join(os.homedir(), '.clank', 'toolchains', meta.sha256.slice(0, 16));
  const done = path.join(base, '.complete');
  if (!fs.existsSync(done)) {
    fs.mkdirSync(base, { recursive: true });
    const archive = path.join(base, 'toolchain.tar.gz');
    if (!fs.existsSync(archive) || sha256File(archive) !== meta.sha256) {
      log('downloading the compiler package (' + (meta.size / 1048576).toFixed(0) + ' MB)');
      await api(ws).download(ws.config.server + '/api/toolchain/download', archive, meta.sha256);
    }
    log('unpacking');
    const n = await extractTarGz(archive, base);
    fs.rmSync(archive, { force: true });
    fs.writeFileSync(done, JSON.stringify({ files: n, sha256: meta.sha256, at: new Date().toISOString() }));
  }
  const root = path.join(base, meta.root ?? 'toolchain');
  ws.config.runners = { [ws.project.toolchain]: runnerConfig({ toolchain: root, project: ws.project }) };
  ws.config.envDigest = await computeEnvDigest(ws, ws.project.toolchain);
  ws.save();
  writeEditorCompileDb(ws);
  const pinned = loadToolchainLock(ws.dir)[ws.project.toolchain]?.clSha256;
  return {
    installed: root,
    runner: ws.config.runners[ws.project.toolchain].type,
    clSha256: ws.config.envDigest,
    matchesServer: !pinned || pinned === ws.config.envDigest,
    note: 'td_check now compiles on this machine. Check your whole region (and td_check includers: true after header changes) before td_submit.',
  };
}


export function relPath(ws, f) {
  return path.relative(ws.dir, path.resolve(f)).replace(/\\/g, '/');
}
