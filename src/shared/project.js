// Loads the decomp repo's configuration (data/decomp.json) and scans its sources.

import fs from 'node:fs';
import path from 'node:path';
import { parseAnnotations } from './annotations.js';
import { matchesAny } from './lint.js';

export const DEFAULT_PROJECT = {
  name: 'decomp',
  sourceDirs: ['src'],
  includeDirs: ['include'],
  headerGlobs: ['include/**'],
  toolchain: 'msvc2010',
  cflags: ['/nologo', '/c', '/O2', '/Gy', '/GS-', '/EHsc', '/MT'],
  fileOverrides: [],
  allowedPragmas: undefined,
  lintLimits: {},
  globalRules: false, // opt-in source storage/provenance checks; no symbol-database definition exemption
  // encodedLiterals: literals the original stores encoded, MACRO("text", key); see freetext.js.
  encodedLiterals: [],
  // vmLiterals: strings the original keeps only in the protector's encrypted VM data; see freetext.js.
  vmLiterals: [],
  // vendored: { path: sha256 } of bundled upstream files whose own comments and strings may stay; see freetext.js.
  vendored: {},
  // offsetAnnotations: every FUNCTION/STUB line has its // OFFSET: address right above it; see offsets.js.
  offsetAnnotations: false,
  // reviewAt: 'exact' requires every relocation target to be a known symbol;
  // 'match_unresolved' also accepts byte matches that reference not-yet-known data
  // (those symbols are created automatically on merge).
  // peerReviews: attempts that are not byte-identical need this many other agents to judge the logic the same.
  matchPolicy: { reviewAt: 'match_unresolved', maxCleanupCycles: 5, approvals: 1, approvalsWithHeaderChanges: 2, peerReviews: 3, peerLeaseMinutes: 5 },
};

const UNIT_EXT = new Set(['.c', '.cpp', '.cc', '.cxx']);
const SOURCE_EXT = new Set([...UNIT_EXT, '.h', '.hpp', '.inl', '.inc']);

export function loadProject(repoDir, readFile = (file) => readProjectFile(repoDir, file)) {
  const cfg = JSON.parse(readFile('data/decomp.json') ?? '{}');
  const project = { ...DEFAULT_PROJECT, ...cfg, matchPolicy: { ...DEFAULT_PROJECT.matchPolicy, ...(cfg.matchPolicy ?? {}) } };
  // Optional exact per-unit command lines: { env, shapes: [[args]], units: { file: shapeIndex } }.
  // Args may use ${SRC} (repo root) and ${TC} (toolchain root); the runner fills them in.
  if (cfg.compileCommands) {
    const commands = readFile(cfg.compileCommands);
    if (commands === null) throw new Error(`missing compile commands: ${cfg.compileCommands}`);
    project.compile = JSON.parse(commands);
  }
  // Optional description of the original image: { image, sections, patches }. sections name what
  // is not the linker's output (a protector's sections, resources, what a dumping tool rebuilt),
  // patches: [{ addr, length, note }] bytes someone wrote over the linker's after the build.
  if (cfg.targetManifest) {
    const manifest = readFile(cfg.targetManifest);
    if (manifest === null) throw new Error(`missing target manifest: ${cfg.targetManifest}`);
    project.target = JSON.parse(manifest);
    project.target.patches = (project.target.patches ?? []).map((p) => ({ ...p, addr: Number(p.addr) }));
  }
  return project;
}

/**
 * The command shape a unit that is not in the build list yet gets: the one most units of its
 * folder use (or of the nearest parent folder that has units), else the most common one.
 */
export function inferShape(project, file) {
  const units = project.compile?.units;
  if (!units) return null;
  if (units[file] !== undefined) return units[file];
  const tally = (prefix) => {
    const n = new Map();
    for (const [f, s] of Object.entries(units)) if (f.startsWith(prefix)) n.set(s, (n.get(s) ?? 0) + 1);
    return [...n].sort((a, b) => b[1] - a[1] || a[0] - b[0])[0]?.[0];
  };
  const parts = file.split('/');
  for (let i = parts.length - 1; i > 0; i--) {
    const s = tally(parts.slice(0, i).join('/') + '/');
    if (s !== undefined) return s;
  }
  return tally('') ?? 0;
}

/**
 * The build list with new units added (each with its inferred shape, or the one `shapes` gives: a
 * moved unit keeps its own), as the text the repository stores it in, or null when nothing is new.
 * `text` is the list as it is on main.
 */
export function addUnitsToCompileCommands(project, text, files, shapes = new Map()) {
  if (!project.compile?.units || text === null) return null;
  const doc = JSON.parse(text);
  const added = files.filter((f) => isUnit(f) && doc.units[f] === undefined && !/(^|\/)Win32\//.test(f));
  if (!added.length) return null;
  for (const f of added) doc.units[f] = shapes.has(f) ? shapes.get(f) : inferShape({ compile: doc }, f);
  doc.units = Object.fromEntries(Object.entries(doc.units).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
  return { text: JSON.stringify(doc, null, 1), added, units: doc.units };
}

/** The build list without the given units, or null when none of them is listed. */
export function removeUnitsFromCompileCommands(project, text, files) {
  if (!project.compile?.units || text === null) return null;
  const doc = JSON.parse(text);
  const removed = files.filter((f) => doc.units[f] !== undefined);
  if (!removed.length) return null;
  for (const f of removed) delete doc.units[f];
  return { text: JSON.stringify(doc, null, 1), removed, units: doc.units };
}

/**
 * Units a batch moves: a listed unit it deletes and exactly one new unit (not listed yet) of the same
 * file name it adds elsewhere. A moved unit keeps the command shape it had, instead of the one its new
 * folder would infer (a move changes paths, not how a unit compiles). new path -> old path.
 */
export function movedUnits(units, files) {
  if (!units) return new Map();
  const name = (f) => f.slice(f.lastIndexOf('/') + 1).toLowerCase();
  const deleted = new Map();
  const added = new Map();
  for (const [f, text] of Object.entries(files)) {
    if (!isUnit(f)) continue;
    const list = text === null ? (units[f] !== undefined ? deleted : null) : (units[f] === undefined ? added : null);
    if (!list) continue;
    if (!list.has(name(f))) list.set(name(f), []);
    list.get(name(f)).push(f);
  }
  const out = new Map();
  for (const [n, from] of deleted) {
    const to = added.get(n);
    if (from.length === 1 && to?.length === 1) out.set(to[0], from[0]);
  }
  return out;
}

/** `units` with every moved unit listed under its new path with its old shape (a copy). */
export function withMovedUnits(units, moves) {
  if (!units || !moves.size) return units;
  const out = { ...units };
  for (const [to, from] of moves) out[to] = units[from];
  return out;
}

export function loadToolchainLock(repoDir, readFile = (file) => readProjectFile(repoDir, file)) {
  return JSON.parse(readFile('data/toolchain.lock.json') ?? '{}');
}

function readProjectFile(repoDir, file) {
  const absolute = path.join(repoDir, file);
  return fs.existsSync(absolute) ? fs.readFileSync(absolute, 'utf8') : null;
}

/** Compiler flags and toolchain for one translation unit. */
export function unitSettings(project, file) {
  // A unit the build list does not have yet compiles the way it will once it is added (merge.js).
  const shape = project.compile?.units ? inferShape(project, file) : undefined;
  if (shape !== undefined && shape !== null) return { cflags: project.compile.shapes[shape], toolchain: project.toolchain, env: project.compile.env ?? {} };
  let cflags = project.cflags;
  let toolchain = project.toolchain;
  for (const o of project.fileOverrides ?? []) {
    if (matchesAny(file, [o.glob])) {
      if (o.cflags) cflags = o.cflags;
      if (o.toolchain) toolchain = o.toolchain;
    }
  }
  return { cflags, toolchain, env: {} };
}

/** Repo-relative paths of all source files (forward slashes). */
export function listSources(repoDir, project, { unitsOnly = false } = {}) {
  // With exact compile commands, the build's own unit list is authoritative.
  if (unitsOnly && project.compile?.units) return Object.keys(project.compile.units).sort();
  const out = [];
  const dirs = [...new Set([...project.sourceDirs, ...project.includeDirs])];
  for (const d of dirs) walk(path.join(repoDir, d), d, out);
  return out.filter((f) => (unitsOnly ? UNIT_EXT : SOURCE_EXT).has(path.posix.extname(f).toLowerCase())).sort();
}

function walk(abs, rel, out) {
  if (!fs.existsSync(abs)) return;
  for (const e of fs.readdirSync(abs, { withFileTypes: true })) {
    if (e.name.startsWith('.')) continue;
    const r = `${rel}/${e.name}`;
    if (e.isDirectory()) walk(path.join(abs, e.name), r, out);
    else out.push(r);
  }
}

export function isUnit(file) {
  return UNIT_EXT.has(path.posix.extname(file).toLowerCase());
}

/**
 * Annotations of the whole repo, optionally with some files replaced
 * (the contents of a submission).
 * `cacheFile`: a JSON file keeping each file's parse result by size and mtime, so a repeated scan
 * only parses what changed (the client's checks; the server scans its own repo in memory).
 */
export function scanAnnotations(repoDir, project, overrides = {}, { cacheFile = null } = {}) {
  const files = new Set(listSources(repoDir, project));
  for (const [f, text] of Object.entries(overrides)) {
    if (text === null) files.delete(f);
    else files.add(f);
  }
  let cache = {};
  if (cacheFile) {
    try {
      cache = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
    } catch {}
  }
  const fresh = {};
  const annotations = [];
  const errors = [];
  for (const f of [...files].sort()) {
    let r;
    if (f in overrides) r = parseAnnotations(overrides[f], f);
    else if (cacheFile) {
      const abs = path.join(repoDir, f);
      const st = fs.statSync(abs);
      const stamp = `${st.size}:${st.mtimeMs}`;
      r = cache[f]?.stamp === stamp ? cache[f].r : parseAnnotations(fs.readFileSync(abs, 'utf8'), f);
      fresh[f] = { stamp, r };
    } else r = parseAnnotations(fs.readFileSync(path.join(repoDir, f), 'utf8'), f);
    // Copies: callers may annotate the objects, which must not leak into the cache.
    annotations.push(...(cacheFile ? r.annotations.map((a) => ({ ...a })) : r.annotations));
    errors.push(...(cacheFile ? r.errors.map((e) => ({ ...e })) : r.errors));
  }
  if (cacheFile) {
    try {
      fs.mkdirSync(path.dirname(cacheFile), { recursive: true });
      const tmp = `${cacheFile}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(fresh));
      fs.renameSync(tmp, cacheFile);
    } catch {}
  }
  return { annotations, errors };
}
