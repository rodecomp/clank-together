// Compares compiled functions (COFF object + listing) against the original
// executable, using the symbol database to locate each annotated function.

import crypto from 'node:crypto';
import { insnAt, normalizePath } from './listing.js';
import { FUNCTION_KINDS, hex } from './annotations.js';
import { reachOf } from './reach.js';
import { selfcheckFunction } from './selfcheck.js';

export const STATUS = {
  EXACT: 'exact', // every byte and every relocation target matches
  UNRESOLVED: 'match_unresolved', // bytes match, but some relocation targets are not yet known symbols
  MISMATCH: 'mismatch',
  MISSING: 'missing', // annotated, but the compiler emitted no such function
  NO_ADDRESS: 'no_address', // annotated ID has no address in the current target version
};

export const NO_BASE_RELOC = 'original has no absolute pointer at this offset';

/**
 * A mismatch no source change can fix: every byte matches and the only failing references are
 * absolute pointers the original carries without a base relocation (packer-stripped tables).
 */
export function relocOnly(f) {
  if (f.status !== STATUS.MISMATCH) return false;
  if (f.size?.original != null && f.size.ours !== f.size.original) return false;
  if (f.diffRegions?.length) return false;
  const bad = (f.relocations ?? []).filter((r) => !r.ok);
  return bad.length > 0 && bad.every((r) => r.reason === NO_BASE_RELOC);
}

// Above this size the similarity score (only a hint for size-mismatched functions) is per-offset.
const MAX_LCS = 2048;
const MAX_DIFF_REGIONS = 24;

/**
 * Binds annotations to the functions/data the compiler emitted for one unit.
 * Function annotations of the unit itself and of every header the listing shows
 * code from are bound by source line; stacked annotations on one definition
 * take its template instances in order, or by their `<detail>`.
 *
 * @returns {{byAnn: Map<object,string>, bindings: Map<string,string>, errors: object[]}}
 *          byAnn: annotation -> decorated name (per definition: folded functions share an ID
 *          across many definitions, each is compared only with code compiled from itself);
 *          bindings: decorated name -> ID (only names that stand for exactly one ID)
 *          (only names that stand for exactly one ID, so they can be learned)
 */
// The compiler's first listed line of a function (its opening brace) is at most this many lines
// below the annotated signature; anything further is another function.
const MAX_SIGNATURE_LINES = 12;

// `locations`: decorated name -> {file, line} of each function's definition, from the object's
// debug info (CoffObject.functionLines). The listing's first source line belongs to whatever code
// the optimizer scheduled first, which may be inlined from a header; it is only the fallback.
export function bindAnnotations({ listing, file, annotations, nameIndex = new Map(), symbols = new Map(), sizes = new Map(), locations = new Map() }) {
  const byAnn = new Map();
  const skipped = new Set();
  const errors = [];
  // A compiled function whose decorated name is already known to be another ID is never taken.
  const ownerOf = (p) => nameIndex.get(p.symbol) ?? null;

  // Procs per source file of their definition, and the annotation files they belong to.
  const procsByFile = new Map();
  for (const proc of listing.procs) {
    const loc = locations.get(proc.symbol);
    const p = loc ? { ...proc, sourceFile: normalizePath(loc.file), firstLine: loc.line } : proc;
    if (!p.sourceFile || p.firstLine === null) continue;
    if (!procsByFile.has(p.sourceFile)) procsByFile.set(p.sourceFile, []);
    procsByFile.get(p.sourceFile).push(p);
  }
  const annsByFile = new Map();
  for (const a of annotations) {
    if (!FUNCTION_KINDS.includes(a.kind)) continue;
    if (!annsByFile.has(a.file)) annsByFile.set(a.file, []);
    annsByFile.get(a.file).push(a);
  }
  const sourceFiles = [...procsByFile.keys()];

  for (const [annFile, anns] of annsByFile) {
    const key = '/' + normalizePath(annFile);
    const sf = sourceFiles.find((s) => s.endsWith(key));
    const own = annFile === file;
    if (!sf) {
      if (own) for (const a of anns) if (a.kind === 'FUNCTION') errors.push({ file, line: a.line, message: `${a.id}: no compiled function found after this annotation (inlined or not emitted?)` });
      continue;
    }
    const procs = procsByFile.get(sf).slice().sort((a, b) => a.firstLine - b.firstLine);
    const lines = [...new Set(anns.map((a) => a.targetLine))].sort((a, b) => a - b);
    lines.forEach((line, i) => {
      const next = Math.min(i + 1 < lines.length ? lines[i + 1] : Infinity, line + MAX_SIGNATURE_LINES + 1);
      const group = anns.filter((a) => a.targetLine === line);
      const groupIds = new Set(group.map((a) => a.id));
      const candidates = procs.filter((p) => p.firstLine >= line && p.firstLine < next && (!ownerOf(p) || groupIds.has(ownerOf(p))));
      if (!candidates.length) {
        if (own) for (const a of group) if (a.kind === 'FUNCTION') errors.push({ file, line: a.line, message: `${a.id}: no compiled function found after this annotation (inlined or not emitted?)` });
        return;
      }
      const used = new Set();
      const take = (a, p) => (used.add(p.symbol), byAnn.set(a, p.symbol));
      const free = () => candidates.filter((p) => !used.has(p.symbol));
      // 1. The decorated name the database knows for this ID (template instance, overload).
      for (const a of group) {
        const known = symbols.get(a.id)?.decorated;
        if (!known) continue;
        const hit = candidates.find((p) => p.symbol === known);
        if (hit) take(a, hit);
        // Known name but not compiled here: this unit holds other instances only.
        else if (candidates.every((p) => p.symbol !== known) && !own) skipped.add(a);
      }
      const pending = () => group.filter((a) => !byAnn.has(a) && !skipped.has(a));
      // 2. The template arguments given as detail.
      for (const a of pending().filter((g) => g.detail)) {
        const inner = a.detail.replace(/^<|>$/g, '');
        const hit = free().find((p) => p.demangled?.includes(`<${inner}>`)) ?? free().find((p) => p.demangled?.includes(inner));
        if (hit) take(a, hit);
      }
      // 3. The size of the original function.
      for (const a of pending()) {
        const size = symbols.get(a.id)?.size;
        const hit = size ? free().find((p) => sizes.get(p.symbol) === size) : null;
        if (hit && free().filter((p) => sizes.get(p.symbol) === size).length === 1) take(a, hit);
      }
      // 4. In order; more addresses than compiled copies means one body stands for several identical functions.
      for (const a of pending()) {
        const f = free()[0];
        byAnn.set(a, f ? (used.add(f.symbol), f.symbol) : candidates[0].symbol);
      }
    });
  }

  // A FOLDED definition is a different source function that shares the ID's address: it never
  // names that address (the decorated name belongs to the function annotated FUNCTION).
  const idsPerSymbol = new Map();
  for (const [a, sym] of byAnn) if (a.kind !== 'FOLDED') idsPerSymbol.set(sym, [...new Set([...(idsPerSymbol.get(sym) ?? []), a.id])]);
  const bindings = new Map([...idsPerSymbol].filter(([, ids]) => ids.length === 1).map(([sym, ids]) => [sym, ids[0]]));

  for (const a of annotations) {
    if (a.file !== file) continue;
    if (a.kind === 'GLOBAL' && a.name) {
      const hit = listing.data.find((d) => d.demangled === a.name || (d.demangled && d.demangled.endsWith('::' + a.name)));
      if (hit) bindings.set(hit.symbol, a.id);
    } else if (a.kind === 'VTABLE') {
      const cls = /\b(?:class|struct)\s+(?:__declspec\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_:]*)/.exec(a.targetText);
      if (cls) {
        const want = `${cls[1]}::\`vftable'`;
        for (const [sym, dem] of listing.names) if (dem && dem.endsWith(want) && sym.startsWith('??_7')) bindings.set(sym, a.id);
      }
    }
  }
  return { byAnn, bindings, errors };
}

/**
 * @param {object} p
 * @param {import('./coff.js').CoffObject} p.obj
 * @param {object} p.listing                parsed listing
 * @param {string} p.file                   repo-relative source path of this TU
 * @param {Array<object>} p.annotations     annotations of this file
 * @param {Map<string, object>} p.symbols   ID -> {kind, addr, size} for the current target version
 * @param {Map<string, string>} p.nameIndex decorated name -> ID, learned from already-merged code
 * @param {import('./pe.js').PEImage} p.pe
 */
// strict: also compare what each matching function reaches (reach.js).
// selfcheck: {stride} also damages the original under each matching function (selfcheck.js).
export function compareObject({ obj, listing, file, annotations, symbols, nameIndex = new Map(), pe, strict = false, symbolAt = () => null, selfcheck = null }) {
  const objFns = new Map(obj.functions().map((f) => [f.name, f]));
  const sizes = new Map([...objFns].map(([n, f]) => [n, f.bytes.length]));
  const found = bindAnnotations({ listing, file, annotations, nameIndex, symbols, sizes, locations: obj.functionLines() });
  const { byAnn, errors } = found;
  // A file-local static (s_ScriptFunctions, a function's static local) has the same name in every
  // unit that defines one: it is known by its object and name (Foo_Scripts.obj|s_ScriptFunctions),
  // never by the name alone, which would tie every unit's table to one address.
  const unitObj = file.replace(/\.[^./\\]+$/, '') + '.obj';
  const local = new Set(obj.dataSymbols().filter((s) => s.storageClass === 3 && !obj.literal(s)).map((s) => s.name));
  const qualify = (name) => (local.has(name) ? `${unitObj}|${name}` : name);
  const bindings = new Map([...found.bindings].map(([sym, id]) => [qualify(sym), id]));
  const resolve = (name) => bindings.get(name) ?? nameIndex.get(name) ?? null;
  const withLocalNames = (fn) =>
    fn.relocs.some((r) => local.has(r.symbol?.name)) ? { ...fn, relocs: fn.relocs.map((r) => (local.has(r.symbol?.name) ? { ...r, symbol: { ...r.symbol, name: qualify(r.symbol.name) } } : r)) } : fn;
  const procsBySymbol = new Map(listing.procs.map((p) => [p.symbol, p]));

  const functions = [];
  const folded = [];
  const inferred = [];
  // The unit's own annotations, plus header annotations that bound to code compiled here.
  const toCompare = annotations.filter((x) => FUNCTION_KINDS.includes(x.kind) && (x.file === file || byAnn.has(x)));
  for (const a of toCompare) {
    const symbol = byAnn.get(a) ?? null;
    const sym = symbols.get(a.id);
    const base = { id: a.id, kind: a.kind, file: a.file, line: a.line, symbol, demangled: symbol ? listing.names.get(symbol) ?? null : null };
    const fn = symbol && sym?.addr != null ? objFns.get(symbol) : null;
    // A FOLDED definition must compile to the bytes at its ID's address, as the original linker
    // could only fold identical code. It is proof, not a result: it never stands for the ID's status.
    if (a.kind === 'FOLDED') {
      if (!fn) {
        folded.push({ ...base, status: sym?.addr == null ? STATUS.NO_ADDRESS : STATUS.MISSING, score: 0 });
        continue;
      }
      const r = compareFunction({ fn: withLocalNames(fn), addr: sym.addr, origSize: sym.size, pe, resolve, symbols, proc: procsBySymbol.get(symbol), literalOf: (s) => obj.literal(s) });
      folded.push({ ...base, addr: sym.addr, status: r.status, score: r.score, size: r.size });
      continue;
    }
    if (!sym || sym.addr == null) {
      functions.push({ ...base, status: STATUS.NO_ADDRESS, score: 0 });
      continue;
    }
    if (!fn) {
      functions.push({ ...base, addr: sym.addr, status: STATUS.MISSING, score: 0 });
      continue;
    }
    const proc = procsBySymbol.get(symbol);
    // The function against an image: the original, or a damaged copy of it.
    const judge = (image, trace = null) => {
      const r = compareFunction({ fn: withLocalNames(fn), addr: sym.addr, origSize: sym.size, pe: image, resolve, symbols, proc, literalOf: (s) => obj.literal(s), trace });
      const reach = strict && r.status !== STATUS.MISMATCH
        ? reachOf({ obj, fn, addr: sym.addr, pe: image, resolve, qualify, symbols, symbolAt, trace })
        : null;
      return { r, reach };
    };
    const { r, reach } = judge(pe);
    const damage = selfcheck && r.status !== STATUS.MISMATCH ? selfcheckFunction({ pe, addr: sym.addr, length: fn.bytes.length, judge, stride: selfcheck.stride }) : null;
    inferred.push(...r.inferred);
    delete r.inferred;
    const deletingDestructor = /^\?\?1/.test(symbol) && isDeletingDestructor(pe, sym.addr, sym.size);
    // Names without an ID that the reached pieces refer to are claims like the function's own.
    if (reach?.pending) inferred.push(...reach.pending.map((p) => ({ symbol: p.symbol, addr: p.actual })));
    functions.push({ ...base, addr: sym.addr, ...r, ...(reach && { reach }), ...(damage && { selfcheck: damage }), ...(deletingDestructor && { deletingDestructor: true }), asm: procText(proc) });
  }

  const boundSymbols = new Set([...bindings.keys(), ...byAnn.values()]);
  const unannotated = [...objFns.keys()].filter((n) => !boundSymbols.has(n) && !isCompilerGenerated(n));
  return { file, functions, folded, bindings: Object.fromEntries(bindings), inferred: dedupeInferred(inferred), unannotated, errors };
}

// Our compiled code as the listing shows it, for reviewers to read next to the original.
function procText(proc) {
  if (!proc) return null;
  return proc.insns.slice(0, 4000).map((i) => `${i.offset.toString(16).padStart(4, '0')}  ${i.text}`).join('\n');
}

/**
 * Compiler-made code that has no source line of its own: scalar/vector deleting destructors,
 * thunks, EH handlers and funclets (__ehhandler$, __unwindfunclet$, __catch$), CRT helpers.
 */
export function isCompilerGenerated(name) {
  return /^\?\?_[GEH]|^__|^\$|^_\$E/.test(name);
}

// MSVC's scalar deleting destructor: tests bit 0 of its flags argument ([ebp+8] or [esp+4/8]),
// calls operator delete on it, and returns this with `retn 4`. A plain destructor takes no argument.
export function isDeletingDestructor(pe, addr, size) {
  if (!size || size < 8) return false;
  let code;
  try {
    code = pe.read(addr, size);
  } catch {
    return false;
  }
  const tail = code.subarray(code.length - 3);
  if (tail[0] !== 0xc2 || tail[1] !== 0x04 || tail[2] !== 0x00) return false;
  return [[0xf6, 0x45, 0x08, 0x01], [0xf6, 0x44, 0x24, 0x04, 0x01], [0xf6, 0x44, 0x24, 0x08, 0x01]].some((sig) => code.indexOf(Buffer.from(sig)) >= 0);
}

function dedupeInferred(list) {
  const m = new Map();
  for (const x of list) m.set(x.symbol, x);
  return [...m.values()];
}

// A __FILE__ value: a source file name, with or without directories (the 15890 client has bare names).
const SOURCE_PATH_RE = /(?:^|[\\/])([^\\/]+\.(?:c|cc|cpp|cxx|h|hpp|inl))$/i;

/**
 * A constant matches when the original holds the same bytes where it points. __FILE__ strings
 * hold the build machine's path, so two source paths match when their file names agree.
 */
export function compareLiteral(ours, addr, pe, name) {
  let orig;
  try {
    orig = pe.read(addr, ours.length);
  } catch {
    return { ok: false, reason: 'original points outside the image' };
  }
  // A constant is initialized data. Zero-filled storage would pass for any constant of zeros ("", 0.0).
  if (!pe.inFile(addr)) return { ok: false, reason: 'original points at uninitialized storage, not at a constant' };
  if (orig.equals(ours)) return { ok: true, reason: null };
  const wide = name.startsWith('??_C@_1');
  const decode = (b) => (wide ? b.toString('utf16le') : b.toString('latin1')).replace(/\0+$/, '');
  const a = decode(ours);
  // The original string may be longer than ours; read it to its terminator for the message and path check.
  let full = decode(orig);
  try {
    const more = pe.read(addr, 520);
    const end = wide ? more.indexOf(Buffer.from([0, 0])) : more.indexOf(0);
    full = decode(more.subarray(0, end < 0 ? more.length : end + (wide ? 2 : 1)));
  } catch {}
  const pa = SOURCE_PATH_RE.exec(a);
  const pb = SOURCE_PATH_RE.exec(full);
  if (pa && pb && pa[1].toLowerCase() === pb[1].toLowerCase()) return { ok: true, reason: null };
  const show = (s) => JSON.stringify(s.length > 60 ? s.slice(0, 57) + '...' : s);
  return { ok: false, reason: `constant differs: ours ${show(a)}, original ${show(full)}` };
}

/** Whether a constant is a __FILE__ value, which compareLiteral judges by its file name only. */
function isSourcePath(bytes, name) {
  return SOURCE_PATH_RE.test((name.startsWith('??_C@_1') ? bytes.toString('utf16le') : bytes.toString('latin1')).replace(/\0+$/, ''));
}

/**
 * What a constant is to the code that refers to it (effectiveHash): its bytes, or for a __FILE__
 * string its file name, as compareLiteral judges it (the directories are the build machine's).
 */
function literalKey(bytes, name) {
  const text = (name.startsWith('??_C@_1') ? bytes.toString('utf16le') : bytes.toString('latin1')).replace(/\0+$/, '');
  const path = SOURCE_PATH_RE.exec(text);
  return crypto.createHash('sha1').update(path ? `file:${path[1].toLowerCase()}` : bytes).digest('hex').slice(0, 16);
}

/** Compares one compiled function with the original bytes at `addr`. */
// trace: collects what the comparison leaves out on purpose and the constants it read (selfcheck.js).
export function compareFunction({ fn, addr, origSize, pe, resolve, symbols, proc, literalOf, trace = null }) {
  const ours = fn.bytes;
  const compareLen = Math.max(ours.length, origSize || 0);
  const orig = pe.read(addr, compareLen);
  const masked = new Uint8Array(compareLen);
  const relocResults = [];
  // What each reference reaches: a symbol's address plus the addend, so `g_object + 0x18` and a
  // name bound to that same address count as the same code (effectiveHash).
  const effective = [];
  const unresolvedRefs = [];
  const inferred = [];
  const baseRelocs = pe.baseRelocations();
  // Without a relocation table every absolute pointer is unmarked, so its value is the only evidence:
  // it is then judged like any other reference, by the address it reaches.
  const absByValue = pe.relocsStripped && baseRelocs.size === 0;

  // x86 address arithmetic wraps at 32 bits; x64 image addresses do not wrap.
  const wrap = pe.is64 ? (x) => x : (x) => x >>> 0;
  // Thread-local variables are reached by their offset in the TLS template, not by address.
  const tlsBase = pe.tlsBase();

  // What a reference stands for in effectiveHash.
  // MSVC names an anonymous namespace (?A0x0c4fce31) and a lambda's closure wrapper
  // (_Closure_wrapper_63e67006_4) after the unit's contents: editing the file renames these
  // file-local symbols, which is no change to the code that calls them.
  // A label inside the function itself ($LN12@Name, a jump-table target) is numbered by the
  // compiler across the whole unit: it is identified by where it lands in the function instead.
  const note = (r, symName, target, addend) => {
    const s = r.symbol;
    const ownLabel = s && symName.startsWith('$') && s.section === fn.section && s.value >= fn.offset && s.value < fn.offset + ours.length;
    const stable = ownLabel
      ? `$@${s.value - fn.offset}`
      : symName.replace(/\?A0x[0-9a-f]{8}@/g, '?A@').replace(/_Closure_wrapper_[0-9a-f]{8}_/g, '_Closure_wrapper__');
    effective.push(`${r.offset}:${r.kind}:${target && target.addr != null ? wrap(target.addr + addend) : `?${stable}+${addend}`}`);
    if (!(target && target.addr != null)) unresolvedRefs.push({ index: effective.length - 1, name: symName, addend, prefix: `${r.offset}:${r.kind}:` });
  };

  for (const r of fn.relocs) {
    for (let k = 0; k < r.width && r.offset + k < compareLen; k++) masked[r.offset + k] = 1;
    if (r.kind === 'other' || (r.kind === 'secrel' && tlsBase === null) || r.offset + r.width > compareLen) {
      trace?.exempt.push({ start: r.offset, end: r.offset + r.width, why: 'relocation of a kind that is not judged' });
      continue;
    }

    const symName = r.symbol?.name ?? '?';
    const id = resolve(symName);
    const target = id ? symbols.get(id) : null;
    const addend = r.width === 8 ? Number(ours.readBigInt64LE(r.offset)) : ours.readInt32LE(r.offset);
    let actual = null;
    let ok = true;
    let reason = null;

    if (r.kind === 'abs') {
      if (!absByValue && !baseRelocs.has(addr + r.offset)) {
        ok = false;
        reason = NO_BASE_RELOC;
      }
      const value = r.width === 8 ? Number(orig.readBigUInt64LE(r.offset)) : orig.readUInt32LE(r.offset);
      actual = wrap(value - addend);
    } else if (r.kind === 'rva') {
      actual = wrap(pe.imageBase + orig.readUInt32LE(r.offset) - addend);
    } else if (r.kind === 'secrel') {
      actual = wrap(tlsBase + orig.readUInt32LE(r.offset) - addend);
    } else {
      // rel: value = target + addend - (field end + bias)
      actual = wrap(addr + r.offset + 4 + r.bias + orig.readInt32LE(r.offset) - addend);
    }

    // Constants (string literals, float/SIMD constants) defined in our object are checked by content.
    const literal = ok ? literalOf?.(r.symbol) : null;
    if (literal) {
      const res = compareLiteral(literal, actual, pe, symName);
      trace?.literals.push({ addr: actual, len: literal.length, what: `constant ${symName}`, ...(isSourcePath(literal, symName) && { exempt: 'source path (__FILE__)' }) });
      relocResults.push({ offset: r.offset, symbol: symName, id: null, ok: res.ok, unresolved: false, actual, reason: res.reason, literal: true });
      // A constant has no address of its own: what the code reaches is its content.
      effective.push(`${r.offset}:${r.kind}:=${literalKey(literal, symName)}+${addend}`);
      continue;
    }

    // A label of the function itself (a switch table's entry) has no name to look up: it is the
    // same place in the original's function, or the table sends that case somewhere else.
    const label = r.symbol;
    if (ok && !target && label && symName.startsWith('$') && label.section === fn.section && label.value >= fn.offset && label.value < fn.offset + ours.length) {
      const at = label.value - fn.offset;
      const same = actual === wrap(addr + at);
      relocResults.push({ offset: r.offset, symbol: symName, id: null, ok: same, unresolved: false, actual, reason: same ? null : `refers to +0x${at.toString(16)} of the function (0x${hex(wrap(addr + at))}) but original references 0x${hex(actual)}` });
      note(r, symName, target, addend);
      continue;
    }

    if (ok && target && target.addr != null) {
      if (target.addr !== actual && !sameTarget(pe, target, actual)) {
        ok = false;
        reason = `references ${id} (0x${hex(target.addr)}) but original references 0x${hex(actual)}`;
      }
    } else if (ok) {
      // Unknown symbol: record where the original points, so the symbol can be identified.
      const isSection = symName.startsWith('.') || symName.startsWith('$');
      if (!isSection) inferred.push({ symbol: symName, addr: actual });
    }
    relocResults.push({ offset: r.offset, symbol: symName, id, ok, unresolved: ok && !(target && target.addr != null), actual, reason });
    note(r, symName, target, addend);
  }

  const sameLength = !origSize || origSize === ours.length;
  // Relocated fields only, before line numbers are masked against the original (effectiveHash).
  const relocMasked = Uint8Array.from(masked);
  if (sameLength && proc) maskLineNumbers({ ours, orig, masked, proc, trace });

  // Byte comparison outside relocated fields.
  const diffs = [];
  let matched = 0;
  let considered = 0;
  if (sameLength) {
    for (let i = 0; i < ours.length; i++) {
      if (masked[i]) continue;
      considered++;
      if (ours[i] === orig[i]) matched++;
      else diffs.push(i);
    }
  }
  const badRelocs = relocResults.filter((r) => !r.ok);
  const relocBytes = relocResults.length * 4; // weight per checked reference, whatever its width
  let score;
  if (sameLength) {
    score = (matched + (relocResults.length - badRelocs.length) * 4) / Math.max(1, considered + relocBytes);
  } else {
    score = lcsRatio(maskBytes(ours, masked), maskBytes(orig.subarray(0, origSize), masked));
  }

  let status;
  if (sameLength && diffs.length === 0 && badRelocs.length === 0) {
    status = relocResults.some((r) => r.unresolved) ? STATUS.UNRESOLVED : STATUS.EXACT;
  } else {
    status = STATUS.MISMATCH;
  }

  return {
    status,
    score: Math.round(score * 10000) / 10000,
    size: { ours: ours.length, original: origSize ?? null },
    // Regions can include equal positions between differences and are capped for display.
    differingBytes: origSize > 0 && sameLength ? diffs.length : null,
    codeHash: codeHash(ours, proc),
    ...effectiveFingerprint(ours, relocMasked, effective, unresolvedRefs, pe.is64),
    diffRegions: sameLength ? diffRegions(diffs, ours, orig, proc) : [],
    relocations: relocResults.filter((r) => !r.ok || r.unresolved),
    // Where the original points is only meaningful when the code lines up.
    inferred: status === STATUS.MISMATCH ? [] : inferred,
  };
}

/**
 * __LINE__ arguments (SMemAlloc(size, __FILE__, __LINE__, ...), error macros) carry the line
 * numbers of our files, not the original's. A 16/32-bit immediate equal to the source line of its
 * instruction is masked, but only when that line spells __LINE__: a
 * constant that merely equals its line number is code, and its score must not depend on where
 * the function sits in the file.
 */
function maskLineNumbers({ ours, orig, masked, proc, trace = null }) {
  const insns = proc.insns;
  for (let k = 0; k < insns.length; k++) {
    const insn = insns[k];
    if (!insn.srcLine || !insn.lineMacro) continue;
    const start = insn.offset;
    const end = Math.min(ours.length, k + 1 < insns.length ? insns[k + 1].offset : ours.length);
    for (let p = start + 1; p + 2 <= end; p++) {
      const width = p + 4 <= end && ours.readUInt32LE(p) === insn.srcLine ? 4 : ours.readUInt16LE(p) === insn.srcLine && p + 2 === end ? 2 : 0;
      if (!width) continue;
      trace?.exempt.push({ start: p, end: p + width, why: 'line number (__LINE__)' });
      let differs = false;
      for (let i = p; i < p + width; i++) if (ours[i] !== orig[i]) differs = true;
      if (differs) for (let i = p; i < p + width; i++) masked[i] = 1;
      break;
    }
  }
}

function maskBytes(buf, masked) {
  const out = Buffer.from(buf);
  for (let i = 0; i < out.length; i++) if (masked[i]) out[i] = 0;
  return out;
}

function diffRegions(diffs, ours, orig, proc) {
  const regions = [];
  for (const off of diffs) {
    const last = regions[regions.length - 1];
    if (last && off - last.end <= 2) last.end = off + 1;
    else regions.push({ start: off, end: off + 1 });
  }
  return regions.slice(0, MAX_DIFF_REGIONS).map((r) => {
    const insn = proc ? insnAt(proc, r.start) : null;
    return {
      offset: r.start,
      length: r.end - r.start,
      ours: ours.subarray(r.start, r.end).toString('hex'),
      original: orig.subarray(r.start, r.end).toString('hex'),
      ourInstruction: insn ? `+0x${insn.offset.toString(16)}: ${insn.text}` : null,
      sourceLine: insn?.srcLine ?? null,
    };
  });
}

/**
 * Whether two functions of the original are the same code: the same size and bytes, where a
 * 4-byte field may differ only as a relative reference (call, jump, RIP-relative operand) to the
 * same target from both places. Jumps inside the function are relative to it and so already equal.
 */
export function sameOriginal(pe, addrA, addrB, size) {
  if (!size) return false;
  if (addrA === addrB) return true;
  const a = pe.read(addrA, size);
  const b = pe.read(addrB, size);
  for (let i = 0; i < size; i++) {
    if (a[i] === b[i]) continue;
    // The field this byte belongs to starts at most three bytes earlier (which were equal).
    let field = -1;
    for (let p = Math.max(0, i - 3); p <= i && field < 0; p++) {
      if (p + 4 <= size && a.readInt32LE(p) - b.readInt32LE(p) === addrB - addrA) field = p;
    }
    if (field < 0) return false;
    i = field + 3;
  }
  return true;
}

const EH_PROLOG = Buffer.from([0x55, 0x8b, 0xec, 0x6a, 0xff, 0x68]);

/**
 * Whether the original's reference to `actual` reaches the same code as `target`: the linker kept
 * an incremental-link thunk (`jmp target`) or a second copy of the function that ICF did not fold
 * only because each copy has its own exception-handling tables. Such a copy is the same size and
 * bytes, except relative references to the same targets and the handler pushed by the x86 EH
 * prologue (`push ebp; mov ebp,esp; push -1; push handler`), whose stubs differ only in the FuncInfo
 * they load. Two import address table slots that import the same DLL export also reach the same
 * code: the loader fills both with that export's address.
 */
export function sameTarget(pe, target, actual) {
  try {
    const imports = pe.imports();
    const slot = imports.get(actual);
    if (slot !== undefined && slot === imports.get(target.addr)) return true;
    if (pe.is64) return false;
    const head = pe.read(actual, 5);
    if (head[0] === 0xe9 && actual + 5 + head.readInt32LE(1) === target.addr) return true;
    const size = target.size;
    if (!size || size < EH_PROLOG.length + 4 || !pe.isCode(actual)) return false;
    const a = pe.read(target.addr, size);
    const b = pe.read(actual, size);
    if (!a.subarray(0, EH_PROLOG.length).equals(EH_PROLOG) || !b.subarray(0, EH_PROLOG.length).equals(EH_PROLOG)) return false;
    const at = EH_PROLOG.length;
    const relocs = pe.baseRelocations();
    if (relocs.size && !(relocs.has(target.addr + at) && relocs.has(actual + at))) return false;
    if (!sameHandlerStub(pe, a.readUInt32LE(at), b.readUInt32LE(at))) return false;
    a.writeUInt32LE(b.readUInt32LE(at), at);
    return sameBytes(a, b, actual - target.addr);
  } catch {
    return false;
  }
}

/** MSVC x86 EH handler stubs (`... mov eax, FuncInfo; jmp __CxxFrameHandler3`) equal but for the FuncInfo. */
function sameHandlerStub(pe, x, y) {
  if (x === y) return true;
  const N = 0x20;
  const a = pe.read(x, N);
  const b = pe.read(y, N);
  let mov = -1;
  for (let i = 0; i + 10 <= N && mov < 0; i++) if (a[i] === 0xb8 && a[i + 5] === 0xe9 && b[i] === 0xb8 && b[i + 5] === 0xe9) mov = i;
  if (mov < 0) return false;
  a.writeUInt32LE(b.readUInt32LE(mov + 1), mov + 1);
  return sameBytes(a.subarray(0, mov + 10), b.subarray(0, mov + 10), y - x);
}

/** Equal bytes, where a 4-byte field may differ only as a relative reference to the same target. */
function sameBytes(a, b, delta) {
  for (let i = 0; i < a.length; i++) {
    if (a[i] === b[i]) continue;
    let field = -1;
    for (let p = Math.max(0, i - 3); p <= i && field < 0; p++) {
      if (p + 4 <= a.length && ((a.readInt32LE(p) - b.readInt32LE(p)) | 0) === delta) field = p;
    }
    if (field < 0) return false;
    i = field + 3;
  }
  return true;
}

/** Similarity ratio based on the longest common subsequence, like difflib. */
export function lcsRatio(a, b) {
  if (a.length === 0 && b.length === 0) return 1;
  if (a.length > MAX_LCS || b.length > MAX_LCS) {
    let same = 0;
    for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] === b[i]) same++;
    return (2 * same) / (a.length + b.length);
  }
  let prev = new Uint16Array(b.length + 1);
  let cur = new Uint16Array(b.length + 1);
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      cur[j] = a[i - 1] === b[j - 1] ? prev[j - 1] + 1 : Math.max(prev[j], cur[j - 1]);
    }
    [prev, cur] = [cur, prev];
  }
  return (2 * prev[b.length]) / (a.length + b.length);
}

/**
 * Fingerprint of our compiled code, to tell whether a function changed between two builds:
 * the bytes (relocated fields are zero in an object file) with __LINE__ immediates zeroed, so
 * editing lines above a function does not count as changing it. Like maskLineNumbers, only lines
 * that spell __LINE__ are masked.
 */
export function codeHash(bytes, proc) {
  const b = Buffer.from(bytes);
  const insns = proc?.insns ?? [];
  for (let k = 0; k < insns.length; k++) {
    const insn = insns[k];
    if (!insn.srcLine || !insn.lineMacro) continue;
    const end = Math.min(b.length, k + 1 < insns.length ? insns[k + 1].offset : b.length);
    for (let p = insn.offset + 1; p + 2 <= end; p++) {
      if (p + 4 <= end && b.readUInt32LE(p) === insn.srcLine) b.fill(0, p, p + 4);
      else if (p + 2 === end && b.readUInt16LE(p) === insn.srcLine) b.fill(0, p, p + 2);
    }
  }
  return crypto.createHash('sha1').update(b).digest('hex').slice(0, 20);
}

/**
 * Fingerprint of what a function does once linked: its bytes outside relocated fields plus where
 * each reference lands (for a string or numeric constant, what it holds). Renaming a global, or reaching a member of an object through the object's
 * symbol instead of a symbol of its own at that address, leaves it unchanged. Source lines play no
 * part (unlike codeHash): an operand that happens to equal its line number would make moving the
 * function look like changing it.
 */
export function effectiveHash(bytes, masked, effective) {
  return effectiveFromParts(maskedBytesHash(bytes, masked), effective);
}

function maskedBytesHash(bytes, masked) {
  const b = Buffer.from(bytes);
  for (let i = 0; i < b.length; i++) if (masked[i]) b[i] = 0;
  return crypto.createHash('sha1').update(b).digest('hex');
}

function effectiveFromParts(bytesHash, effective) {
  return crypto.createHash('sha1').update(bytesHash).update('|').update(effective.join('|')).digest('hex').slice(0, 20);
}

// References to names no symbol of the database has yet (a function renamed in the same
// submission) keep what is needed to hash them again once the submission's bindings are known.
function effectiveFingerprint(bytes, masked, effective, unresolvedRefs, is64) {
  const bytesHash = maskedBytesHash(bytes, masked);
  return {
    effectiveHash: effectiveFromParts(bytesHash, effective),
    ...(unresolvedRefs.length && { effectiveParts: { bytesHash, effective, unresolvedRefs, is64 } }),
  };
}

/**
 * effectiveHash with references resolved through `addressOf` (decorated name -> address or null),
 * e.g. the bindings of every unit a check compiled. Without effectiveParts it is effectiveHash.
 */
export function resolvedEffectiveHash(f, addressOf) {
  const parts = resolvedEffectiveParts(f, addressOf);
  return parts ? effectiveFromParts(parts.bytesHash, parts.effective) : f.effectiveHash ?? null;
}

/**
 * The pieces resolvedEffectiveHash hashes, with the names still unresolved by entry index; null
 * without effectiveParts (every reference was resolved when the function was compared).
 */
export function resolvedEffectiveParts(f, addressOf) {
  const parts = f.effectiveParts;
  if (!parts) return null;
  const effective = [...parts.effective];
  const unresolved = new Map();
  for (const u of parts.unresolvedRefs) {
    const addr = addressOf(u.name);
    if (addr == null) {
      unresolved.set(u.index, u.name);
      continue;
    }
    effective[u.index] = `${u.prefix}${parts.is64 ? addr + u.addend : (addr + u.addend) >>> 0}`;
  }
  return { bytesHash: parts.bytesHash, effective, unresolved };
}

export function hashEffectiveParts(parts) {
  return effectiveFromParts(parts.bytesHash, parts.effective);
}
