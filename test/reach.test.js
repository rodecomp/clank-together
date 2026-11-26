import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildCoff, buildPe, FN_ADDR, CALLEE_ADDR } from './helpers.js';
import { PEImage } from '../src/shared/pe.js';
import { CoffObject } from '../src/shared/coff.js';
import { parseListing } from '../src/shared/listing.js';
import { parseAnnotations } from '../src/shared/annotations.js';
import { compareObject, STATUS } from '../src/shared/compare.js';
import { reconcile } from '../src/shared/reconcile.js';
import { reachOf, REACH } from '../src/shared/reach.js';
import { selfcheckFunction } from '../src/shared/selfcheck.js';

// Thing::Init at 0x401000 stores the address of a table; the table holds a pointer to Helper
// (0x401100) and the number 42. The function's own bytes say nothing of what the table holds.
//
//   c7 01 imm32    mov dword ptr [ecx], offset table
//   c3             ret
const TABLE_ADDR = 0x403000;
const OTHER_ADDR = 0x401180;
const RDATA = 0x40301040; // initialized data, COMDAT, read
const DATA = 0xc0301040; // the same, writable
const FILE = 'src/thing.cpp';

function build({ number = 42, slot = CALLEE_ADDR, tableName = '?table@@3QBUEntry@@B', tableSection = RDATA, ours = null } = {}) {
  const text = Buffer.alloc(0x200, 0xcc);
  Buffer.from([0xc7, 0x01, 0, 0, 0, 0, 0xc3]).copy(text, 0);
  text.writeUInt32LE(TABLE_ADDR, 2);
  text[CALLEE_ADDR - FN_ADDR] = 0xc3;
  text[OTHER_ADDR - FN_ADDR] = 0xc3;
  const table = Buffer.alloc(0x40);
  table.writeUInt32LE(slot, 0);
  table.writeUInt32LE(number, 4);
  const pe = buildPe({
    sections: [
      { name: '.text', rva: 0x1000, data: text },
      { name: '.rdata', rva: 0x3000, data: table, characteristics: 0x40000040 },
    ],
    baseRelocs: [FN_ADDR + 2, TABLE_ADDR],
  });
  const tableData = ours ?? Buffer.from([0, 0, 0, 0, 42, 0, 0, 0]);
  const obj = buildCoff({
    sections: [
      { name: '.text$mn', data: Buffer.from([0xc7, 0x01, 0, 0, 0, 0, 0xc3]), characteristics: 0x60501020, relocs: [{ offset: 2, symbolIndex: 2, type: 0x06 }] },
      { name: tableSection === DATA ? '.data' : '.rdata', data: tableData, characteristics: tableSection, relocs: [{ offset: 0, symbolIndex: 3, type: 0x06 }] },
    ],
    symbols: [
      { name: '.text$mn', section: 1, storageClass: 3 },
      { name: '?Init@Thing@@QAEXXZ', section: 1, type: 0x20, storageClass: 2 },
      { name: tableName, section: 2, storageClass: 2 },
      { name: '?Helper@@YAXXZ', section: 0, type: 0x20, storageClass: 2 },
    ],
  });
  return { pe, obj };
}

const symbols = (extra = []) =>
  new Map([{ id: 'fn_00001', kind: 'function', addr: FN_ADDR, size: 7 }, { id: 'fn_00002', kind: 'function', addr: CALLEE_ADDR, size: 1 }, ...extra].map((s) => [s.id, s]));

function reach(opts = {}, { names = new Map([['?Helper@@YAXXZ', 'fn_00002']]), syms = symbols() } = {}) {
  const f = build(opts);
  const obj = new CoffObject(f.obj);
  const byAddr = new Map([...syms].map(([id, s]) => [s.addr, id]));
  return reachOf({ obj, fn: obj.functions()[0], addr: FN_ADDR, pe: new PEImage(f.pe), resolve: (n) => names.get(n) ?? null, symbols: syms, symbolAt: (a) => byAddr.get(a) ?? null });
}

test('a function is verified when the data it reaches holds what the original holds', () => {
  const r = reach();
  assert.equal(r.verdict, REACH.VERIFIED);
  assert.deepEqual([r.pieces, r.bytes, r.findings], [1, 8, []]);
});

test('a table that holds another number than the original leaves the function code-exact', () => {
  const r = reach({ number: 43 });
  assert.equal(r.verdict, REACH.CODE_EXACT);
  assert.match(r.findings[0].where, /^code \+0x2 -> \?table@@3QBUEntry@@B$/);
  assert.match(r.findings[0].reason, /^1 of 8 bytes differ from 0x0*403000, first at \+0x4$/);
});

test('a pointer in reached data is judged like a reference of the function', () => {
  const r = reach({ slot: OTHER_ADDR });
  assert.equal(r.verdict, REACH.CODE_EXACT);
  assert.match(r.findings[0].where, /-> \?table@@3QBUEntry@@B \+0x0 -> \?Helper@@YAXXZ$/);
  assert.match(r.findings[0].reason, /is fn_00002 \(0x0*401100\) but the original has 0x0*401180 there/);
});

test('a reached name without an ID leaves the function unknown until the name is settled', () => {
  const r = reach({}, { names: new Map() });
  assert.equal(r.verdict, REACH.UNKNOWN);
  assert.deepEqual(r.pending.map((p) => [p.symbol, p.actual]), [['?Helper@@YAXXZ', CALLEE_ADDR]]);
  assert.deepEqual(r.findings, []);
});

test('writable data that differs is undecided: a memory dump holds what the program stored there', () => {
  const syms = symbols([{ id: 'gl_00001', kind: 'global', addr: TABLE_ADDR, size: 8 }]);
  const names = new Map([['?Helper@@YAXXZ', 'fn_00002'], ['?table@@3UEntry@@A', 'gl_00001']]);
  const r = reach({ number: 43, tableSection: DATA, tableName: '?table@@3UEntry@@A' }, { names, syms });
  assert.equal(r.verdict, REACH.UNKNOWN);
  assert.equal(r.findings[0].kind, 'undecided');
  assert.match(r.findings[0].reason, /in writable data$/);
});

test('writable data without an ID is not decided by what it holds', () => {
  // Equal bytes would prove nothing (zeroes mostly): which address the name stands for stays the
  // function's own open reference, for compare.js and reconcile to settle.
  const r = reach({ tableSection: DATA, tableName: '?table@@3UEntry@@A' });
  assert.deepEqual([r.pieces, r.decided, r.findings], [0, undefined, []]);
  const readOnly = reach();
  assert.deepEqual([readOnly.pieces, readOnly.decided], [1, ['?table@@3QBUEntry@@B']]);
});

test('a type descriptor is compared by its name, whatever the runtime wrote before it', () => {
  // vftable pointer, the runtime's cached name, then the decorated name.
  const descriptor = (name) => Buffer.concat([Buffer.alloc(8), Buffer.from(name + '\0', 'latin1')]);
  const f = build({ tableSection: DATA, tableName: '??_R0?AVThing@@@8', ours: descriptor('.?AVThing@@') });
  const image = (name, cached) => {
    const pe = Buffer.from(f.pe);
    const at = pe.indexOf(Buffer.from([0x00, 0x11, 0x40, 0x00, 42, 0, 0, 0]));
    pe.writeUInt32LE(cached, at + 4);
    Buffer.from(name + '\0', 'latin1').copy(pe, at + 8);
    return new PEImage(pe);
  };
  const obj = new CoffObject(f.obj);
  const run = (pe) => reachOf({ obj, fn: obj.functions()[0], addr: FN_ADDR, pe, resolve: (n) => (n === '?Helper@@YAXXZ' ? 'fn_00002' : null), symbols: symbols() });
  assert.equal(run(image('.?AVThing@@', 0x12345678)).verdict, REACH.VERIFIED);
  const other = run(image('.?AVCThing@@', 0));
  assert.equal(other.verdict, REACH.CODE_EXACT);
  assert.equal(other.findings[0].reason, 'the type is .?AVCThing@@ in the original, .?AVThing@@ here');
});

test('the strict verdict joins the result and settles with the names reconcile accepts', () => {
  const source = ['#include "thing.h"', '', '// FUNCTION: fn_00001', 'void Thing::Init()', '{', '    entries = table;', '}', ''].join('\n');
  const listing = [
    'PUBLIC\t?Init@Thing@@QAEXXZ\t\t\t\t; Thing::Init',
    '; File z:\\job\\src\\thing.cpp',
    ';\tCOMDAT ?Init@Thing@@QAEXXZ',
    '_TEXT\tSEGMENT',
    '?Init@Thing@@QAEXXZ PROC\t\t\t\t; Thing::Init, COMDAT',
    '',
    '; 5    : {',
    '',
    '  00000\tc7 01 00 00 00 00\t mov\t DWORD PTR [ecx], OFFSET ?table@@3QBUEntry@@B',
    '  00006\tc3\t\t ret\t 0',
    '?Init@Thing@@QAEXXZ ENDP\t\t\t\t; Thing::Init',
    '_TEXT\tENDS',
    'END',
  ].join('\r\n');
  const check = (opts, strict = true, selfcheck = null) => {
    const f = build(opts);
    const syms = symbols();
    const unit = compareObject({ obj: new CoffObject(f.obj), listing: parseListing(listing), file: FILE, annotations: parseAnnotations(source, FILE).annotations, symbols: syms, pe: new PEImage(f.pe), strict, selfcheck, symbolAt: (a) => [...syms].find(([, s]) => s.addr === a)?.[0] ?? null });
    reconcile({ units: [unit] }, syms, new PEImage(f.pe));
    return unit.functions[0];
  };
  assert.equal(check({}, false).reach, undefined, 'only when asked for');
  const good = check({});
  // The table has no ID: the function is match_unresolved, yet all it reaches is decided.
  assert.equal(good.status, STATUS.UNRESOLVED);
  assert.equal(good.reach.verdict, REACH.VERIFIED, 'Helper is the function at the address the table points to');
  assert.equal(good.reach.pending, undefined);
  assert.equal(check({ number: 43 }).reach.verdict, REACH.CODE_EXACT);
  // Nothing is known at the address the original's table points to: the name stays open.
  assert.equal(check({ slot: OTHER_ADDR }).reach.verdict, REACH.UNKNOWN);

  // Selfcheck: each of the function's 7 bytes and the table's 8 is damaged in the original, and
  // each time the result changes.
  assert.deepEqual(check({}, true, { stride: 1 }).selfcheck, { bytes: 15, tried: 15, exempt: {}, survived: [] });
  // Without the strict check only the function's own bytes are evidence.
  assert.deepEqual(check({}, false, { stride: 1 }).selfcheck, { bytes: 7, tried: 7, exempt: {}, survived: [] });
  assert.equal(check({}, true, { stride: 4 }).selfcheck.tried, 4);
});

test('selfcheck reports the damage a comparison does not notice, and counts what is exempt', () => {
  const pe = new PEImage(build().pe);
  // A comparison that looks at the first four bytes only, and declares the last one exempt.
  const judge = (image, trace) => {
    trace?.exempt.push({ start: 6, end: 7, why: 'by rule' });
    const same = image.read(FN_ADDR, 4).equals(pe.read(FN_ADDR, 4));
    return { r: { status: same ? STATUS.EXACT : STATUS.MISMATCH, score: 1 }, reach: null };
  };
  const r = selfcheckFunction({ pe, addr: FN_ADDR, length: 7, judge });
  assert.deepEqual([r.bytes, r.tried, r.exempt], [6, 6, { 'by rule': 1 }]);
  assert.deepEqual(r.survived, [{ addr: FN_ADDR + 4, what: 'code' }, { addr: FN_ADDR + 5, what: 'code' }]);
});
