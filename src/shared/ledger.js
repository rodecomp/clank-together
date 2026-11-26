// The whole original, byte by byte: what is proven from source, what is copied from it, what is
// still open. A partition: every byte of the file is in exactly one class, so the classes add up to
// the file's size and nothing is counted twice or left out.
//
//   proven    a function whose strict verdict is verified, and the pieces and constants such
//             functions reach (compared equal)
//   matched   a function whose code matches but whose verdict is code-exact or unknown, or that was
//             checked without --strict
//   differs   a function the tree has that does not match
//   copied    what no compiler produces, by reason: the file's headers, sections the target manifest
//             gives a class (protector, dump, patch, resources), listed patches
//   library   a function the database marks as library code and the tree does not have
//   missing   any other function of the database the tree does not have
//   padding   int3 between functions
//   open      everything else: data nothing reached, code no symbol covers

export const LEDGER_CLASSES = ['open', 'padding', 'missing', 'library', 'differs', 'matched', 'proven', 'copied'];

/**
 * @param {object} p
 * @param {import('./pe.js').PEImage} p.pe
 * @param {object} [p.manifest]             the target manifest ({ sections, patches })
 * @param {Map<string, object>} p.symbols   ID -> { kind, addr, size, library }
 * @param {Array<object>} p.functions       results of a check, with reach when it was strict
 * @returns {{bytes: number, total: Record<string, number>, copied: Record<string, number>, sections: Array<object>}}
 */
export function ledger({ pe, manifest = {}, symbols, functions }) {
  const rank = new Map(LEDGER_CLASSES.map((c, i) => [c, i]));
  const sections = pe.sections.map((s) => ({ ...s, start: pe.imageBase + s.rva, classes: new Uint8Array(s.rawSize), why: new Map() }));
  const at = (va) => sections.find((s) => va >= s.start && va < s.start + s.rawSize);
  // A byte keeps the highest class painted on it.
  const paint = (va, length, cls, why = null) => {
    const r = rank.get(cls);
    for (let done = 0; done < length; ) {
      const s = at(va + done);
      if (!s) return;
      const from = va + done - s.start;
      const n = Math.min(length - done, s.rawSize - from);
      for (let i = from; i < from + n; i++) {
        if (s.classes[i] >= r) continue;
        s.classes[i] = r;
        if (why) s.why.set(i, why);
      }
      done += n;
    }
  };

  const copiedSection = new Map((manifest.sections ?? []).map((s) => [s.name, s.class]));
  for (const s of sections) if (copiedSection.has(s.name)) paint(s.start, s.rawSize, 'copied', copiedSection.get(s.name));
  for (const p of manifest.patches ?? []) paint(Number(p.addr), p.length, 'copied', 'patch');

  for (const sym of symbols.values()) {
    if (sym.kind !== 'function' || sym.addr == null || !sym.size) continue;
    paint(sym.addr, sym.size, sym.library ? 'library' : 'missing');
  }
  for (const f of functions) {
    if (f.addr == null) continue;
    const addr = typeof f.addr === 'string' ? Number(f.addr) : f.addr;
    const size = f.size?.original ?? f.size?.ours ?? 0;
    if (f.status === 'mismatch') paint(addr, size, 'differs');
    else if (f.status === 'exact' || f.status === 'match_unresolved') {
      paint(addr, size, f.reach?.verdict === 'verified' ? 'proven' : 'matched');
      for (const [va, length] of f.reach?.ranges ?? []) paint(va, length, 'proven');
    }
  }
  // int3 runs that nothing else claimed, in code.
  for (const s of sections) {
    if ((s.characteristics & 0x20000000) === 0 || copiedSection.has(s.name)) continue;
    const raw = pe.buf.subarray(s.rawPtr, s.rawPtr + s.rawSize);
    for (let i = 0; i < raw.length; i++) if (raw[i] === 0xcc && s.classes[i] === 0) s.classes[i] = rank.get('padding');
  }

  const total = Object.fromEntries(LEDGER_CLASSES.map((c) => [c, 0]));
  const copied = {};
  const out = sections.map((s) => {
    const classes = Object.fromEntries(LEDGER_CLASSES.map((c) => [c, 0]));
    for (let i = 0; i < s.classes.length; i++) classes[LEDGER_CLASSES[s.classes[i]]]++;
    for (const why of s.why.values()) copied[why] = (copied[why] ?? 0) + 1;
    for (const c of LEDGER_CLASSES) total[c] += classes[c];
    return { name: s.name, bytes: s.rawSize, classes };
  });
  // Headers and whatever the file holds outside its sections.
  const outside = pe.buf.length - sections.reduce((n, s) => n + s.rawSize, 0);
  total.copied += outside;
  copied.headers = outside;
  return { bytes: pe.buf.length, total, copied, sections: [{ name: '(headers)', bytes: outside, classes: { ...Object.fromEntries(LEDGER_CLASSES.map((c) => [c, 0])), copied: outside } }, ...out] };
}

/** The ledger as lines of text. */
export function ledgerText(l) {
  const pct = (n) => `${((100 * n) / l.bytes).toFixed(2)}%`.padStart(7);
  const shown = [...LEDGER_CLASSES].reverse();
  const lines = [`${l.bytes} bytes`, ...shown.map((c) => `  ${c.padEnd(8)} ${String(l.total[c]).padStart(9)} ${pct(l.total[c])}`)];
  lines.push('copied, by reason:', ...Object.entries(l.copied).sort((a, b) => b[1] - a[1]).map(([why, n]) => `  ${why.padEnd(16)} ${String(n).padStart(9)}`));
  lines.push(`${'section'.padEnd(10)} ${'bytes'.padStart(9)}  ${shown.map((c) => c.padStart(9)).join(' ')}`);
  for (const s of l.sections) lines.push(`${s.name.padEnd(10)} ${String(s.bytes).padStart(9)}  ${shown.map((c) => String(s.classes[c]).padStart(9)).join(' ')}`);
  return lines.join('\n');
}
