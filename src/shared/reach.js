// What a function reaches besides its own bytes, compared with the original (the strict check).
//
// compare.js judges a function by its bytes and by where each reference lands. That leaves out
// what the compiler emitted for the function elsewhere in the object: the exception handler it
// registers, the tables that handler reads, the funclets that unwind its objects and the bodies of
// its catch blocks; the tables and vtables it loads; initialized statics. Here each of those is
// compared too, piece by piece: a piece's bytes with the original's at the address the original
// refers to, and every reference inside it the same way, until what is left has an ID (and so a
// result of its own) or is a constant.
//
//   verified    everything reached agrees
//   code-exact  the function's code agrees, something it reaches differs
//   unknown     nothing differs, but something reached cannot be decided
//
// Two things cannot be decided from the image: a name without an ID that this unit does not
// define (settled like compare.js's own unnamed references, see reconcile.js), and writable data,
// when the original is a memory dump: what the program stored there since it started is not what
// the linker wrote.

import { relocInfo } from './coff.js';
import { hex } from './annotations.js';
import { compareLiteral, sameTarget } from './compare.js';

export const REACH = { VERIFIED: 'verified', CODE_EXACT: 'code-exact', UNKNOWN: 'unknown' };

const IMAGE_SCN_MEM_WRITE = 0x80000000;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
const MAX_FINDINGS = 12;

/** Where the object's pieces start: per section, the offsets of its symbols, in order. */
function boundaries(obj) {
  if (obj._bounds) return obj._bounds;
  const by = new Map();
  for (const s of obj.symbols) {
    if (!s || s.section <= 0 || (s.storageClass !== 2 && s.storageClass !== 3)) continue;
    const sec = obj.section(s.section);
    // A label inside a function ($LN12@f) starts no piece of its own.
    if (sec.isCode && (s.type & 0x30) !== 0x20) continue;
    if (!by.has(s.section)) by.set(s.section, new Set());
    by.get(s.section).add(s.value);
  }
  obj._bounds = new Map([...by].map(([k, v]) => [k, [...v].sort((a, b) => a - b)]));
  return obj._bounds;
}

/** The piece of a section that holds `offset`: the whole of a COMDAT section, else up to the next symbol. */
function pieceAt(obj, secIndex, offset) {
  const sec = obj.section(secIndex);
  if (sec.isComdat) return { start: 0, end: sec.size };
  const marks = boundaries(obj).get(secIndex) ?? [];
  let start = 0;
  let end = sec.size;
  for (const m of marks) {
    if (m <= offset) start = m;
    else {
      end = m;
      break;
    }
  }
  if (sec.isCode) while (end > start && sec.data[end - 1] === 0xcc) end--;
  return { start, end };
}

/**
 * @param {object} p
 * @param {import('./coff.js').CoffObject} p.obj
 * @param {object} p.fn       the function, from obj.functions()
 * @param {number} p.addr     its address in the original
 * @param {import('./pe.js').PEImage} p.pe
 * @param {(name: string) => string|null} p.resolve  decorated name -> ID
 * @param {(name: string) => string} p.qualify       a file-local name as the name index knows it
 * @param {Map<string, object>} p.symbols
 * @param {(addr: number) => string|null} [p.symbolAt]  the ID of the symbol at an address
 * @param {object} [p.trace]  collects the pieces that agreed (selfcheck.js)
 */
// MSVC's vector deleting destructor tests bit 1 of its flags argument first (`test byte ptr [ebp+8], 2`).
function isVectorDeleting(code) {
  return [[0xf6, 0x45, 0x08, 0x02], [0xf6, 0x44, 0x24, 0x04, 0x02], [0xf6, 0x44, 0x24, 0x08, 0x02]].some((sig) => code.indexOf(Buffer.from(sig)) >= 0);
}

/** A reach result's verdict from what is still open in it. */
export function reachVerdict(reach) {
  if (reach.differs) return REACH.CODE_EXACT;
  return reach.undecided || reach.pending?.length ? REACH.UNKNOWN : REACH.VERIFIED;
}

export function reachOf({ obj, fn, addr, pe, resolve, qualify = (n) => n, symbols, symbolAt = () => null, trace = null }) {
  const wrap = pe.is64 ? (x) => x : (x) => x >>> 0;
  const tlsBase = pe.tlsBase();
  const findings = [];
  const seen = new Map(); // piece -> true once compared (a cycle counts as agreeing until proven otherwise)
  // References to names without an ID, to settle as compare.js's own are (reconcile.js).
  const pending = [];
  // The function's own references to names without an ID that are decided here, by content.
  const decided = new Set();
  let pieces = 0;
  let bytes = 0;
  const report = (kind, where, reason, extra = {}) => findings.push({ kind, where, reason, ...extra });

  const read = (at, n) => {
    try {
      return pe.read(at, n);
    } catch {
      return null;
    }
  };

  // opts.from: compare bytes from this offset only; opts.stable: writable, but never written to;
  // opts.describe: says what the original holds instead.
  function piece(secIndex, start, end, origStart, where, skip = null, opts = {}) {
    const key = `${secIndex}:${start}:${origStart}`;
    if (seen.has(key)) return;
    seen.set(key, true);
    const sec = obj.section(secIndex);
    const writable = (sec.characteristics & IMAGE_SCN_MEM_WRITE) !== 0;
    const orig = read(origStart, end - start);
    if (!orig) {
      report('undecided', where, `the original's bytes at 0x${hex(origStart)} are not in the file`);
      return;
    }
    const ours = sec.data.subarray(start, end);
    const masked = new Uint8Array(end - start);
    const relocs = sec.relocs.filter((r) => r.offset >= start && r.offset < end).map((r) => ({ ...relocInfo(obj.machine, r.type), at: r.offset - start, symbol: obj.symbols[r.symbolIndex] }));
    for (const r of relocs) masked.fill(1, r.at, Math.min(r.at + r.width, masked.length));
    if (skip === null) {
      pieces++;
      bytes += ours.length;
      let first = -1;
      let n = 0;
      for (let i = opts.from ?? 0; i < ours.length; i++) {
        if (masked[i] || ours[i] === orig[i]) continue;
        if (first < 0) first = i;
        n++;
      }
      if (n) {
        const what = `${n} of ${ours.length} bytes differ from 0x${hex(origStart)}, first at +0x${first.toString(16)}`;
        if (writable && !opts.stable) report('undecided', where, `${what}, in writable data`);
        else report('differs', where, opts.describe?.(orig) ?? what);
        return;
      }
      const from = opts.from ?? 0;
      trace?.pieces.push({ addr: origStart + from, len: ours.length - from, what: where });
    }
    for (const r of relocs) {
      if (skip?.(r.at) || r.at + r.width > ours.length) continue;
      if (r.kind === 'other' || (r.kind === 'secrel' && tlsBase === null)) continue;
      const addend = r.width === 8 ? Number(ours.readBigInt64LE(r.at)) : ours.readInt32LE(r.at);
      const field = origStart + r.at;
      let actual;
      if (r.kind === 'abs') actual = wrap((r.width === 8 ? Number(orig.readBigUInt64LE(r.at)) : orig.readUInt32LE(r.at)) - addend);
      else if (r.kind === 'rva') actual = wrap(pe.imageBase + orig.readUInt32LE(r.at) - addend);
      else if (r.kind === 'secrel') actual = wrap(tlsBase + orig.readUInt32LE(r.at) - addend);
      else actual = wrap(field + 4 + r.bias + orig.readInt32LE(r.at) - addend);
      reference(r.symbol, addend, actual, `${where} +0x${r.at.toString(16)}`, skip !== null);
    }
  }

  // `top`: a reference of the function itself, which compare.js has judged by address already.
  function reference(sym, addend, actual, where, top) {
    if (!sym) return;
    // Nothing else defines a weak external here: it is its default.
    sym = obj.weakDefault(sym) ?? sym;
    const name = sym.name;
    const to = `${where} -> ${name}`;
    const literal = obj.literal(sym);
    if (literal) {
      if (top) return;
      const res = compareLiteral(literal, actual, pe, name);
      if (!res.ok) report('differs', to, res.reason);
      else trace?.pieces.push({ addr: actual, len: literal.length, what: to });
      return;
    }
    const id = resolve(qualify(name));
    const target = id ? symbols.get(id) : null;
    const known = target && target.addr != null;
    if (known && !top && target.addr !== actual && !sameTarget(pe, target, actual)) {
      report('differs', to, `is ${id} (0x${hex(target.addr)}) but the original has 0x${hex(actual)} there`);
      return;
    }
    if (sym.section <= 0) {
      // compare.js records the function's own unnamed references; these are the ones further on.
      if (!known && !top) pending.push({ symbol: qualify(name), actual, where: to });
      return;
    }
    const sec = obj.section(sym.section);
    // A function with an ID has a result of its own.
    if (known && sec.isCode) return;
    // A label of the function itself (a jump table's entry): the original's must be the same place.
    if (sym.section === fn.section && sym.value >= fn.offset && sym.value < fn.offset + fn.bytes.length) {
      const expected = wrap(addr + sym.value - fn.offset);
      if (actual !== expected) report('differs', to, `is +0x${(sym.value - fn.offset).toString(16)} of this function (0x${hex(expected)}), the original has 0x${hex(actual)} there`);
      return;
    }
    // Code where the database has a symbol is a function with a result of its own, whichever name
    // it has here: that the name stands for it is a claim, as it is for compare.js.
    if (!known && sec.isCode && symbolAt(actual)) {
      if (!top) pending.push({ symbol: qualify(name), actual, where: to });
      return;
    }
    if ((sec.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) !== 0) {
      if (!known && !top) pending.push({ symbol: qualify(name), actual, where: to });
      return;
    }
    // Writable data without an ID is not told apart by what it holds: zeroes prove nothing, and the
    // program has written to it since. Which address the name stands for is a claim. (A type
    // descriptor is writable too, but it is its name.)
    if (!known && (sec.characteristics & IMAGE_SCN_MEM_WRITE) !== 0 && !name.startsWith('??_R0')) {
      if (!top) pending.push({ symbol: qualify(name), actual, where: to });
      return;
    }
    if (top && !known) decided.add(qualify(name));
    // A reference to the section itself (a file-local table, a switch table) names its piece by the addend.
    const isSection = sym.storageClass === 3 && sym.value === 0 && sym.numAux > 0 && name.startsWith('.');
    const offset = isSection ? Math.max(0, Math.min(addend, sec.size - 1)) : sym.value;
    const { start, end } = pieceAt(obj, sym.section, offset);
    // `actual` is where the original has the symbol: for a section, its first byte.
    const origStart = wrap(isSection ? actual + start : actual - (sym.value - start));
    if (name.startsWith('??_R0')) {
      // A type descriptor: the type_info vftable, a pointer the runtime fills in, the decorated name.
      const text = (b) => b.subarray(8, b.indexOf(0, 8) < 0 ? b.length : b.indexOf(0, 8)).toString('latin1');
      piece(sym.section, start, end, origStart, to, null, { from: 8, stable: true, describe: (orig) => `the type is ${text(read(origStart, 264) ?? orig)} in the original, ${text(sec.data.subarray(start, end))} here` });
    } else if (/^\?\?_[GE]/.test(name)) {
      // A deleting destructor: the original's may be the vector one, which only some other unit's delete[] brings in.
      piece(sym.section, start, end, origStart, to, null, { describe: (orig) => (isVectorDeleting(read(origStart, 96) ?? orig) ? "the original has the vector deleting destructor here, this unit only the scalar one" : null) });
    } else piece(sym.section, start, end, origStart, to);
  }

  // The function's own bytes are compareFunction's to judge: only its references are followed.
  piece(fn.section, fn.offset, fn.offset + fn.bytes.length, addr, 'code', () => false);

  if (trace) trace.findings = findings;
  const differs = findings.filter((f) => f.kind === 'differs');
  const out = {
    pieces,
    bytes,
    differs: differs.length,
    undecided: findings.length - differs.length,
    ...(pending.length && { pending }),
    ...(decided.size && { decided: [...decided] }),
    findings: [...differs, ...findings.filter((f) => f.kind !== 'differs')].slice(0, MAX_FINDINGS),
  };
  return { verdict: reachVerdict(out), ...out };
}
