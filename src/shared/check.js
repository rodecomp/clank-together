// The compile + compare pipeline. The server's verifier and the contributor's
// `td check` both run this, so a local result predicts the server result.

import fs from 'node:fs';
import path from 'node:path';
import { CoffObject } from './coff.js';
import { parseListing, normalizePath } from './listing.js';
import { compareObject } from './compare.js';
import { foldedErrors } from './folded.js';
import { lintAnnotations, hex } from './annotations.js';
import { lintPreprocessed } from './lint.js';
import { compileUnits, prepareJobDir } from './build.js';
import { scanAnnotations, unitSettings } from './project.js';

/**
 * @param {object} p
 * @param {string} p.repoDir
 * @param {string} p.jobDir
 * @param {object} p.project
 * @param {string[]} p.units                  .cpp files to compile and compare
 * @param {Record<string,string>} [p.overrides] submitted file contents
 * @param {Map<string,object>} p.symbols      ID -> {kind, addr, size, library}
 * @param {Map<string,string>} p.nameIndex    decorated name -> ID
 * @param {import('./pe.js').PEImage} p.pe
 * @param {Record<string,object>} p.runners
 */
// lintUnits: units whose preprocessed output is scanned (default: all compiled units).
// analyze: replaces the in-process analysis of the compiler output (the server runs it in worker
// threads, so a check of many units doesn't block it).
// bindGlobals: likewise for withGlobalBindings, which parses every unit's listing: resolves to one
// list of [decorated name, ID] per compiled unit, in order.
// incremental: update a job directory left by an earlier check instead of copying the tree anew
// (prepareJobDir); for a job directory only ever filled from the same repoDir.
// compileCache: {dir, capMb} of a compile-output cache for docker runners (compileUnits).
export async function checkUnits({ repoDir, jobDir, project, units, overrides = {}, symbols, nameIndex, pe, runners, timeoutMs, scaleTimeout = false, lintUnits = null, analyze = null, bindGlobals = null, cachedUnits = [], unitOrder = null, incremental = false, compileCache = null, strict = false, selfcheck = null, scan = scanAnnotations(repoDir, project, overrides) }) {
  const annotationErrors = [...scan.errors, ...lintAnnotations(scan.annotations, symbols)];

  prepareJobDir({ repoDir, jobDir, project, overrides, incremental });
  const compiled = await compileUnits({ jobDir, units, project, runners, timeoutMs, scaleTimeout, cache: compileCache, preprocess: (f) => !lintUnits || lintUnits.has(f) });

  const roots = { sourceDirs: project.sourceDirs, includeDirs: project.includeDirs };
  const evidence = new Map(cachedUnits.map((u) => [u.file, u.globalBindings ?? []]));
  const bound = bindGlobals
    ? await bindGlobals({ compiled, annotations: scan.annotations })
    : compiled.map((c) => [...withGlobalBindings([c], scan.annotations, new Map())]);
  compiled.forEach((c, i) => evidence.set(c.file, bound[i]));
  // compileUnits groups by toolchain. Preserve that first-binding-wins order for fresh and
  // partial checks, including when a newly required unit joins an earlier toolchain group.
  const groups = new Map();
  for (const file of unitOrder ?? compiled.map((c) => c.file)) {
    const { toolchain } = unitSettings(project, file);
    if (!groups.has(toolchain)) groups.set(toolchain, []);
    groups.get(toolchain).push(file);
  }
  const analysisOrder = [...groups.values()].flat();
  const names = new Map(nameIndex);
  for (const file of analysisOrder) for (const [name, id] of evidence.get(file) ?? []) if (!names.has(name)) names.set(name, id);
  const results = analyze
    ? await analyze({ compiled, annotations: scan.annotations, roots, nameIndex: names })
    : analyzeCompiled({ compiled, annotations: scan.annotations, roots, symbols, nameIndex: names, pe, strict, selfcheck });
  for (const u of results) u.globalBindings = evidence.get(u.file) ?? [];
  return { annotationErrors, units: results, annotations: scan.annotations, analysisNames: [...names], analysisOrder };
}

/**
 * A GLOBAL annotation binds its variable's decorated name in the unit that defines it, or that
 * declares it (an annotated extern: the listing names it as EXTRN). References from the other
 * units of the same check resolve to that ID too, as they do on main once the name is learned:
 * the name index the units are compared with includes them.
 */
export function withGlobalBindings(compiled, annotations, nameIndex) {
  const globals = annotations.filter((a) => a.kind === 'GLOBAL' && a.name);
  if (!globals.length) return nameIndex;
  const byFile = new Map();
  for (const a of globals) byFile.set(a.file, [...(byFile.get(a.file) ?? []), a]);
  const out = new Map(nameIndex);
  for (const c of compiled) {
    if (!c.ok || !c.cod) continue;
    const anns = [...(byFile.get(c.file) ?? []), ...(c.includes ?? []).flatMap((h) => byFile.get(h) ?? [])];
    if (!anns.length) continue;
    const listing = parseListing(fs.readFileSync(c.cod, 'latin1'));
    for (const a of anns) {
      const matches = (d) => d === a.name || (d && d.endsWith('::' + a.name));
      const hit = listing.data.find((d) => matches(d.demangled))?.symbol ?? [...listing.names].find(([sym, d]) => sym.startsWith('?') && matches(d))?.[0];
      if (hit && !out.has(hit)) out.set(hit, a.id);
    }
  }
  return out;
}

/**
 * What a comparison looked up in a map, hits and misses: its result holds for as long as these
 * lookups answer the same (inputsCurrent).
 */
class Reads {
  constructor(map) {
    this.map = map;
    this.seen = new Map();
  }

  get(key) {
    const value = this.map.get(key);
    this.seen.set(key, value);
    return value;
  }
}

// What compare.js reads of a symbol.
const symbolInput = (s) => (s ? [s.addr ?? null, s.size ?? null, s.decorated ?? null] : null);

/**
 * Whether a unit's comparison would read the same from `symbols` (ID -> symbol) and `nameIndex`
 * (decorated name -> ID) as it did: every other symbol and name may change without changing its
 * result. A unit analyzed before its lookups were recorded is never current.
 */
export function inputsCurrent(unit, symbols, nameIndex) {
  const inputs = unit?.inputs;
  if (!inputs) return false;
  if (inputs.addresses?.some(([addr, id]) => (addressIndex(symbols).get(addr) ?? null) !== id)) return false;
  return inputs.names.every(([name, id]) => (nameIndex.get(name) ?? null) === id)
    && inputs.symbols.every(([id, was]) => JSON.stringify(symbolInput(symbols.get(id))) === JSON.stringify(was));
}

// address -> ID of the symbol there, once per symbol map.
const addressIndexes = new WeakMap();
function addressIndex(symbols) {
  let index = addressIndexes.get(symbols);
  if (!index) {
    index = new Map();
    for (const [id, s] of symbols) if (s.addr != null) index.set(s.addr, id);
    addressIndexes.set(symbols, index);
  }
  return index;
}

/** Lints and compares the compiler output of each unit against the original. */
export function analyzeCompiled({ compiled, annotations, roots, symbols, nameIndex, pe, strict = false, selfcheck = null }) {
  const projectRoots = [...roots.sourceDirs, ...roots.includeDirs].map((d) => '/' + normalizePath(d) + '/');
  const isProjectFile = (f) => projectRoots.some((r) => f.includes(r));

  const results = [];
  for (const c of compiled) {
    const unit = { file: c.file, compiled: c.ok, timedOut: c.timedOut ?? false, ...(c.cached && { cached: true }), log: trimLog(c.log), includes: c.includes ?? [], lintErrors: [], functions: [], inferred: [], bindings: {}, unannotated: [], errors: [] };
    const names = new Reads(nameIndex);
    const read = new Reads(symbols);
    // The strict check also asks which symbol is at an address (reach.js).
    const addresses = new Map();
    const symbolAt = (addr) => {
      const id = addressIndex(symbols).get(addr) ?? null;
      // A damaged original asks about addresses the real one never names.
      if (!selfcheck) addresses.set(addr, id);
      return id;
    };
    if (c.pre) unit.lintErrors = lintPreprocessed(fs.readFileSync(c.pre, 'latin1'), isProjectFile);
    if (c.ok) {
      try {
        const obj = new CoffObject(fs.readFileSync(c.obj));
        const listing = parseListing(c.cod ? fs.readFileSync(c.cod, 'latin1') : '');
        Object.assign(unit, compareObject({ obj, listing, file: c.file, annotations, symbols: read, nameIndex: names, pe, strict, symbolAt, selfcheck }));
      } catch (e) {
        unit.errors.push({ file: c.file, message: `could not analyze compiler output: ${e.message}` });
      }
    }
    unit.inputs = { names: [...names.seen].map(([name, id]) => [name, id ?? null]), symbols: [...read.seen].map(([id, s]) => [id, symbolInput(s)]), ...(addresses.size && { addresses: [...addresses] }) };
    results.push(unit);
  }
  return results;
}

function trimLog(log) {
  if (!log) return '';
  // Drop the noise cl.exe prints for every file, keep diagnostics.
  const lines = log.split(/\r?\n/).filter((l) => l.trim() && !/^(== |Microsoft \(R\)|Copyright \(C\)|Note: including file:)/.test(l) && !/^\S+\.(c|cpp|cc|cxx)$/i.test(l.trim()));
  return lines.slice(0, 200).join('\n');
}

/** Flattens a check result into per-ID function results. */
export function functionResults(check) {
  const out = new Map();
  for (const u of check.units) for (const f of u.functions) out.set(f.id, { ...f, file: u.file });
  return out;
}

export function jobDirFor(base, name) {
  return path.join(base, name.replace(/[^A-Za-z0-9_-]/g, '_'));
}

/** `files`: the files the user asked about; annotation problems elsewhere in the repo are not theirs. */
export function summarizeCheck(result, rec, files = null) {
  return {
    annotationErrors: [...(files ? result.annotationErrors.filter((e) => files.has(e.file)) : result.annotationErrors), ...foldedErrors(result, files ?? new Set(result.units.flatMap((u) => (u.folded ?? []).map((f) => f.file))))],
    units: result.units.map((u) => ({
      file: u.file,
      compiled: u.compiled,
      timedOut: u.timedOut ?? false,
      log: u.compiled ? undefined : u.log,
      lintErrors: u.lintErrors,
      errors: u.errors,
      unannotated: u.unannotated,
      functions: u.functions.map((f) => ({
        id: f.id,
        name: f.demangled,
        addr: f.addr != null ? '0x' + hex(f.addr) : null,
        status: f.status,
        score: f.score,
        size: f.size,
        ...(f.effectiveHash && { effectiveHash: f.effectiveHash }),
        diffRegions: f.diffRegions?.slice(0, 12),
        relocations: f.relocations,
        ...(f.deletingDestructor && { deletingDestructor: true }),
        ...(f.reach && { reach: f.reach }),
        ...(f.selfcheck && { selfcheck: f.selfcheck }),
      })),
      folded: (u.folded ?? []).map((f) => ({ id: f.id, line: f.line, status: f.status, score: f.score, size: f.size })),
    })),
    referenceConflicts: rec.conflicts,
    unknownReferences: rec.unknown.map((x) => ({ symbol: x.decorated, addr: '0x' + hex(x.addr) })),
  };
}
