// Proof that the comparison notices: every byte of the original that a result rests on is damaged
// in turn, and a result that stays the same is a defect of the comparison (or of this list).
//
// The bytes are the function's own, the constants it loads and, with the strict check, every piece
// it reaches. What the comparison leaves out on purpose is not damaged but counted, by reason, so
// a rule that exempts more than it should shows as a number: line numbers (__LINE__ arguments),
// source paths (__FILE__), relocations of a kind that is not judged.

const FLIP = 0x55;

/** The image with one byte changed. */
function damaged(pe, va) {
  const image = Object.create(pe);
  image.read = (at, len) => {
    const out = pe.read(at, len);
    if (va >= at && va < at + len) out[va - at] ^= FLIP;
    return out;
  };
  return image;
}

/** What a result says, as far as a change to the original could show in it. */
function fingerprint({ r, reach }, trace) {
  return JSON.stringify([
    r.status,
    r.score,
    r.diffRegions?.length ?? 0,
    (r.relocations ?? []).map((x) => [x.offset, x.ok, x.actual]),
    reach ? [reach.verdict, (trace.findings ?? []).map((f) => [f.kind, f.where, f.reason]), (reach.pending ?? []).map((p) => p.actual)] : null,
  ]);
}

/**
 * @param {object} p
 * @param {import('./pe.js').PEImage} p.pe
 * @param {number} p.addr    the function's address in the original
 * @param {number} p.length  its length
 * @param {(image: object, trace?: object) => {r: object, reach: object|null}} p.judge  compares the function with an image
 * @param {number} [p.stride]  damage every stride-th byte (1: all of them)
 * @returns {{bytes: number, tried: number, exempt: Record<string, number>, survived: Array<{addr: number, what: string}>}}
 */
export function selfcheckFunction({ pe, addr, length, judge, stride = 1 }) {
  const trace = { exempt: [], literals: [], pieces: [] };
  const before = fingerprint(judge(pe, trace), trace);
  const exempt = {};
  const skip = new Uint8Array(length);
  for (const e of trace.exempt) {
    for (let i = Math.max(0, e.start); i < Math.min(length, e.end); i++) {
      if (skip[i]) continue;
      skip[i] = 1;
      exempt[e.why] = (exempt[e.why] ?? 0) + 1;
    }
  }
  const sites = new Map();
  for (let i = 0; i < length; i++) if (!skip[i]) sites.set(addr + i, 'code');
  for (const l of trace.literals) {
    if (l.exempt) exempt[l.exempt] = (exempt[l.exempt] ?? 0) + l.len;
    else for (let i = 0; i < l.len; i++) if (!sites.has(l.addr + i)) sites.set(l.addr + i, l.what);
  }
  for (const p of trace.pieces) for (let i = 0; i < p.len; i++) if (!sites.has(p.addr + i)) sites.set(p.addr + i, p.what);

  const survived = [];
  let tried = 0;
  let n = addr % stride;
  for (const [va, what] of sites) {
    if (n++ % stride) continue;
    tried++;
    const after = { exempt: [], literals: [], pieces: [] };
    if (fingerprint(judge(damaged(pe, va), after), after) === before) survived.push({ addr: va, what });
  }
  return { bytes: sites.size, tried, exempt, survived: survived.slice(0, 20), ...(survived.length > 20 && { moreSurvived: survived.length - 20 }) };
}
