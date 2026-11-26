// Resolves relocation targets the compare step could not name, using the
// symbol database's addresses. A call to an undecompiled function compiles to
// a reference to e.g. `?Foo@@YAXXZ`; the original points at 0x401230, which the
// database knows is fn_00042. If nothing contradicts it, that reference is
// correct and `?Foo@@YAXXZ` is learned as fn_00042's decorated name on merge.

import { STATUS, sameTarget } from './compare.js';
import { hex } from './annotations.js';
import { REACH, reachVerdict } from './reach.js';

/**
 * @param {object} check                     result of checkUnits
 * @param {Map<string,object>} symbols       ID -> symbol (with addr for the current version)
 * @param {import('./pe.js').PEImage} [pe]   the original: a reference through a thunk or to an
 *                                           EH-only copy of a named function is not a conflict
 * @returns {{learned: Array<{decorated, id, addr}>, unknown: Array<{decorated, addr}>, conflicts: string[]}}
 */
export function reconcile(check, symbols, pe = null) {
  const byAddr = new Map();
  const byDecorated = new Map();
  for (const s of symbols.values()) {
    if (s.addr != null) byAddr.set(s.addr, s);
    if (s.decorated) byDecorated.set(s.decorated, s);
  }

  const claims = new Map(); // decorated -> addr
  const conflicts = [];
  for (const u of check.units) {
    for (const [decorated, id] of Object.entries(u.bindings)) {
      const s = symbols.get(id);
      if (s?.addr != null) addClaim(claims, conflicts, decorated, s.addr);
    }
    for (const x of u.inferred) addClaim(claims, conflicts, x.symbol, x.addr);
  }

  const learned = [];
  const learnedAddresses = [];
  const unknown = [];
  const ok = new Set();
  for (const [decorated, addr] of claims) {
    const atAddr = byAddr.get(addr);
    const named = byDecorated.get(decorated);
    if (named && named.addr == null) {
      // A known symbol without an address in this version, referenced by matching code: the
      // original's target is its address here (unless another symbol already holds it).
      ok.add(decorated);
      if (!atAddr) learnedAddresses.push({ id: named.id, decorated, addr });
    } else if (named && named.addr !== addr && pe && sameTarget(pe, named, addr)) {
      // The original reaches the named function through a thunk or an EH-only copy of it.
      ok.add(decorated);
    } else if (named && named.addr !== addr) {
      // Definitive: the name is known to live elsewhere, so the reference is wrong.
      conflicts.push({ symbol: decorated, actual: addr, hard: true, message: `${decorated} is ${named.id} at 0x${hex(named.addr)}, but the original references 0x${hex(addr)}` });
    } else if (atAddr && atAddr.decorated && atAddr.decorated !== decorated) {
      // Another name at a known address: the linker folded identical functions or data into one.
      // Accepted, but not learned (the address keeps the name it has).
      ok.add(decorated);
    } else if (atAddr) {
      ok.add(decorated);
      if (!atAddr.decorated) learned.push({ decorated, id: atAddr.id, addr });
    } else {
      ok.add(decorated);
      unknown.push({ decorated, addr });
    }
  }

  const conflictSymbols = new Set(conflicts.map((c) => c.symbol));
  const wrongSymbols = new Set(conflicts.filter((c) => c.hard).map((c) => c.symbol));

  // Upgrade functions whose only problem was unnamed relocation targets.
  for (const u of check.units) {
    for (const f of u.functions) {
      if (f.status !== STATUS.UNRESOLVED) continue;
      const pending = (f.relocations ?? []).filter((r) => r.unresolved);
      const allKnown = pending.every((r) => ok.has(r.symbol) && byAddr.has(r.actual));
      // An ambiguous name only means it cannot be learned; the function's own bytes and
      // references were fine, so it stays unresolved (reviewers see why) instead of failing.
      const conflicted = pending.filter((r) => conflictSymbols.has(r.symbol)).map((r) => r.symbol);
      if (conflicted.some((s) => wrongSymbols.has(s))) f.status = STATUS.MISMATCH;
      else if (conflicted.length) f.conflictedReferences = conflicted;
      else if (allKnown) f.status = STATUS.EXACT;
    }
  }
  // The strict check's verdict (reach.js) settles the same way: a reached name is decided once it
  // stands for one known address, and a function whose own references are open is undecided too.
  for (const u of check.units) {
    for (const f of u.functions) {
      if (!f.reach) continue;
      if (f.status === STATUS.MISMATCH) {
        delete f.reach;
        continue;
      }
      const open = [];
      for (const p of f.reach.pending ?? []) {
        if (wrongSymbols.has(p.symbol)) {
          f.reach.differs++;
          f.reach.findings.unshift({ kind: 'differs', where: p.where, reason: `is known at another address than 0x${hex(p.actual)}` });
        } else if (!(ok.has(p.symbol) && byAddr.has(p.actual)) || conflictSymbols.has(p.symbol)) open.push(p);
      }
      if (open.length) f.reach.pending = open;
      else delete f.reach.pending;
      f.reach.verdict = reachVerdict(f.reach);
      // What is left open of the function's own references, the ones decided by content aside.
      const decided = new Set(f.reach.decided ?? []);
      const openOwn = f.status !== STATUS.EXACT && (f.relocations ?? []).some((r) => r.unresolved && !decided.has(r.symbol) && !(ok.has(r.symbol) && byAddr.has(r.actual)));
      if (f.reach.verdict === REACH.VERIFIED && (openOwn || f.conflictedReferences)) f.reach.verdict = REACH.UNKNOWN;
    }
  }
  // Ambiguous names are not learned.
  return {
    learned: learned.filter((l) => !conflictSymbols.has(l.decorated)),
    learnedAddresses: learnedAddresses.filter((l) => !conflictSymbols.has(l.decorated)),
    unknown: unknown.filter((u) => !conflictSymbols.has(u.decorated)),
    conflicts,
    conflictSymbols,
  };
}

function addClaim(claims, conflicts, decorated, addr) {
  const prev = claims.get(decorated);
  if (prev === undefined) claims.set(decorated, addr);
  else if (prev !== addr) conflicts.push({ symbol: decorated, message: `${decorated} is referenced as both 0x${hex(prev)} and 0x${hex(addr)}` });
}
