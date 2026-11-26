// Minimal reader for i386 and AMD64 COFF object files as produced by MSVC
// (cl.exe /c), including the /bigobj variant.

export const MACHINE_I386 = 0x14c;
export const MACHINE_AMD64 = 0x8664;

// What each relocation type writes into the code:
//   abs  absolute address of the target (+ addend stored in place), `width` bytes
//   rva  target address minus the image base
//   rel  target minus the address `bias` bytes after the 4-byte field
//   secrel  target minus the start of its section: in code, the offset of a thread-local variable
//           in the TLS template (mov eax, [ecx + _var@SECREL])
//   other  section index and similar: masked, not checked
const RELOCS = {
  [MACHINE_I386]: {
    0x01: { kind: 'other', width: 2 }, // DIR16
    0x02: { kind: 'other', width: 2 }, // REL16
    0x06: { kind: 'abs', width: 4 }, // DIR32
    0x07: { kind: 'rva', width: 4 }, // DIR32NB
    0x0a: { kind: 'other', width: 2 }, // SECTION
    0x0b: { kind: 'secrel', width: 4 }, // SECREL
    0x0c: { kind: 'other', width: 4 }, // TOKEN
    0x0d: { kind: 'other', width: 1 }, // SECREL7
    0x14: { kind: 'rel', width: 4, bias: 0 }, // REL32
  },
  [MACHINE_AMD64]: {
    0x01: { kind: 'abs', width: 8 }, // ADDR64
    0x02: { kind: 'abs', width: 4 }, // ADDR32
    0x03: { kind: 'rva', width: 4 }, // ADDR32NB
    0x04: { kind: 'rel', width: 4, bias: 0 }, // REL32
    0x05: { kind: 'rel', width: 4, bias: 1 }, // REL32_1
    0x06: { kind: 'rel', width: 4, bias: 2 }, // REL32_2
    0x07: { kind: 'rel', width: 4, bias: 3 }, // REL32_3
    0x08: { kind: 'rel', width: 4, bias: 4 }, // REL32_4
    0x09: { kind: 'rel', width: 4, bias: 5 }, // REL32_5
    0x0a: { kind: 'other', width: 2 }, // SECTION
    0x0b: { kind: 'secrel', width: 4 }, // SECREL
    0x0c: { kind: 'other', width: 1 }, // SECREL7
    0x0d: { kind: 'other', width: 4 }, // TOKEN
    0x0e: { kind: 'other', width: 4 }, // SREL32
    0x10: { kind: 'other', width: 4 }, // SSPAN32
  },
};

export const LITERAL_RE = /^(\?\?_C@|__real@|__xmm@|__mask@|__ymm@)/;

/** How a relocation of `type` on `machine` patches the code ({kind, width, bias}). */
export function relocInfo(machine, type) {
  return RELOCS[machine]?.[type] ?? { kind: 'other', width: 0 };
}

const IMAGE_SCN_CNT_CODE = 0x00000020;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
const IMAGE_SCN_LNK_COMDAT = 0x00001000;
const IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000;
const IMAGE_SYM_DTYPE_FUNCTION = 0x20;

// CodeView (C13) debug info, as /Z7 writes it into .debug$S.
const CV_SIGNATURE_C13 = 4;
const DEBUG_S_LINES = 0xf2;
const DEBUG_S_STRINGTABLE = 0xf3;
const DEBUG_S_FILECHKSMS = 0xf4;

export class CoffObject {
  /** @param {Buffer} buf */
  constructor(buf) {
    this.buf = buf;
    const sig1 = buf.readUInt16LE(0);
    const sig2 = buf.readUInt16LE(2);
    this.bigobj = sig1 === 0 && sig2 === 0xffff && buf.readUInt16LE(4) >= 2;

    let numSections, symPtr, numSymbols, secTable;
    if (this.bigobj) {
      this.machine = buf.readUInt16LE(6);
      numSections = buf.readUInt32LE(44);
      symPtr = buf.readUInt32LE(48);
      numSymbols = buf.readUInt32LE(52);
      secTable = 56;
    } else {
      this.machine = sig1;
      numSections = buf.readUInt16LE(2);
      symPtr = buf.readUInt32LE(8);
      numSymbols = buf.readUInt32LE(12);
      secTable = 20 + buf.readUInt16LE(16);
    }
    if (this.machine !== MACHINE_I386 && this.machine !== MACHINE_AMD64) throw new Error(`unsupported machine 0x${this.machine.toString(16)} (expected i386 or AMD64)`);
    this.is64 = this.machine === MACHINE_AMD64;

    const symSize = this.bigobj ? 20 : 18;
    this.stringTableOffset = symPtr + numSymbols * symSize;
    this.symbolTable = { offset: symPtr, entrySize: symSize };

    this.sections = [];
    for (let i = 0; i < numSections; i++) {
      const o = secTable + i * 40;
      const characteristics = buf.readUInt32LE(o + 36);
      let relocPtr = buf.readUInt32LE(o + 24);
      let numRelocs = buf.readUInt16LE(o + 32);
      if (characteristics & IMAGE_SCN_LNK_NRELOC_OVFL && numRelocs === 0xffff) {
        numRelocs = buf.readUInt32LE(relocPtr) - 1;
        relocPtr += 10;
      }
      const relocs = [];
      for (let r = 0; r < numRelocs; r++) {
        const ro = relocPtr + r * 10;
        relocs.push({ offset: buf.readUInt32LE(ro), symbolIndex: buf.readUInt32LE(ro + 4), type: buf.readUInt16LE(ro + 8) });
      }
      const rawSize = buf.readUInt32LE(o + 16);
      const rawPtr = buf.readUInt32LE(o + 20);
      const bss = (characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) !== 0;
      this.sections.push({
        index: i + 1,
        name: this._name(buf, o),
        size: rawSize,
        data: bss || rawPtr === 0 ? Buffer.alloc(rawSize) : buf.subarray(rawPtr, rawPtr + rawSize),
        characteristics,
        isCode: (characteristics & IMAGE_SCN_CNT_CODE) !== 0,
        isComdat: (characteristics & IMAGE_SCN_LNK_COMDAT) !== 0,
        relocs,
      });
    }

    this.symbols = [];
    for (let i = 0; i < numSymbols; ) {
      const o = symPtr + i * symSize;
      const numAux = buf.readUInt8(o + symSize - 1);
      const sym = {
        index: i,
        name: this._name(buf, o, true),
        value: buf.readUInt32LE(o + 8),
        section: this.bigobj ? buf.readInt32LE(o + 12) : buf.readInt16LE(o + 12),
        type: buf.readUInt16LE(o + (this.bigobj ? 16 : 14)),
        storageClass: buf.readUInt8(o + (this.bigobj ? 18 : 16)),
        numAux,
      };
      this.symbols[i] = sym;
      i += 1 + numAux;
    }
  }

  _name(buf, o, isSymbol = false) {
    if (isSymbol && buf.readUInt32LE(o) === 0) return this._string(buf.readUInt32LE(o + 4));
    const raw = buf.toString('latin1', o, o + 8).replace(/\0.*$/s, '');
    if (!isSymbol && raw.startsWith('/')) return this._string(parseInt(raw.slice(1), 10));
    return raw;
  }

  _string(offset) {
    const start = this.stringTableOffset + offset;
    const end = this.buf.indexOf(0, start);
    return this.buf.toString('latin1', start, end < 0 ? undefined : end);
  }

  section(index) {
    return this.sections[index - 1];
  }

  /**
   * Functions defined in this object, with their bytes and relocations
   * (relocation offsets are relative to the function start).
   */
  functions() {
    const bySection = new Map();
    for (const s of this.symbols) {
      if (!s || s.section <= 0) continue;
      if ((s.type & 0x30) !== IMAGE_SYM_DTYPE_FUNCTION) continue;
      if (s.storageClass !== 2 && s.storageClass !== 3) continue;
      if (!bySection.has(s.section)) bySection.set(s.section, []);
      bySection.get(s.section).push(s);
    }
    const out = [];
    for (const [secIndex, syms] of bySection) {
      const sec = this.section(secIndex);
      syms.sort((a, b) => a.value - b.value);
      syms.forEach((s, i) => {
        const end = i + 1 < syms.length ? syms[i + 1].value : sec.size;
        let bytes = sec.data.subarray(s.value, end);
        // Shared .text sections pad between functions; COMDAT sections hold exactly one function.
        if (syms.length > 1) {
          let n = bytes.length;
          while (n > 0 && bytes[n - 1] === 0xcc) n--;
          bytes = bytes.subarray(0, n);
        }
        const relocs = sec.relocs
          .filter((r) => r.offset >= s.value && r.offset < s.value + bytes.length)
          .map((r) => ({ offset: r.offset - s.value, type: r.type, ...relocInfo(this.machine, r.type), symbol: this.symbols[r.symbolIndex] }));
        out.push({ name: s.name, section: secIndex, sectionName: sec.name, offset: s.value, bytes, relocs, isStatic: s.storageClass === 3 });
      });
    }
    return out;
  }

  /**
   * Where each function is defined, from the CodeView line tables in .debug$S (compiled with /Z7):
   * decorated name -> {file, line} of its first instruction. Code inlined into a function has
   * records of its own, so this is the function's own definition even when the optimizer put
   * inlined code first. Empty without debug info.
   */
  functionLines() {
    const out = new Map();
    const debug = this.sections.filter((s) => s.name === '.debug$S' && s.size >= 4 && s.data.readUInt32LE(0) === CV_SIGNATURE_C13);
    const subsections = (s) => {
      const list = [];
      for (let p = 4; p + 8 <= s.size; ) {
        const type = s.data.readUInt32LE(p);
        const len = s.data.readUInt32LE(p + 4);
        list.push({ type, off: p + 8, len });
        p = (p + 8 + len + 3) & ~3;
      }
      return list;
    };
    let strings = null;
    let checksums = null;
    for (const s of debug) {
      for (const sub of subsections(s)) {
        if (sub.type === DEBUG_S_STRINGTABLE) strings ??= { data: s.data, off: sub.off };
        if (sub.type === DEBUG_S_FILECHKSMS) checksums ??= { data: s.data, off: sub.off };
      }
    }
    if (!strings || !checksums) return out;
    const fileName = (fileId) => {
      const start = strings.off + checksums.data.readUInt32LE(checksums.off + fileId);
      return strings.data.toString('latin1', start, strings.data.indexOf(0, start));
    };
    for (const s of debug) {
      const relocAt = new Map(s.relocs.map((r) => [r.offset, r]));
      for (const sub of subsections(s)) {
        // Header (offset, segment, flags, code size), then file blocks (file id, line count,
        // block size) whose line entries (code offset, line) run in code order.
        if (sub.type !== DEBUG_S_LINES || sub.len < 32) continue;
        const sym = this.symbols[relocAt.get(sub.off)?.symbolIndex];
        const block = sub.off + 12;
        if (!sym || out.has(sym.name) || s.data.readUInt32LE(block + 4) === 0) continue;
        out.set(sym.name, { file: fileName(s.data.readUInt32LE(block)), line: s.data.readUInt32LE(block + 16) & 0xffffff });
      }
    }
    return out;
  }

  /**
   * Bytes of a constant defined in this object (string literal ??_C@..., __real@/__xmm@/__mask@
   * floating-point and SIMD constants), or null. Each such constant is its own COMDAT section.
   */
  literal(symbol) {
    if (!symbol || symbol.section <= 0 || !LITERAL_RE.test(symbol.name)) return null;
    const sec = this.section(symbol.section);
    if (!sec || sec.isCode || sec.relocs.length) return null;
    let end = sec.size;
    for (const s of this.symbols) if (s && s.section === symbol.section && s.value > symbol.value && s.value < end) end = s.value;
    return sec.data.subarray(symbol.value, end);
  }

  /**
   * The symbol a weak external stands for when nothing else defines it (its auxiliary record's
   * tag index), or null: `??_E` (vector deleting destructor) falls back to `??_G` this way.
   */
  weakDefault(symbol) {
    if (!symbol || symbol.storageClass !== 105 || symbol.section !== 0 || !symbol.numAux) return null;
    const aux = this.symbolTable.offset + (symbol.index + 1) * this.symbolTable.entrySize;
    return this.symbols[this.buf.readUInt32LE(aux)] ?? null;
  }

  /** Data symbols (globals and statics) defined in this object. */
  dataSymbols() {
    return this.symbols.filter((s) => s && s.section > 0 && (s.type & 0x30) !== IMAGE_SYM_DTYPE_FUNCTION && (s.storageClass === 2 || s.storageClass === 3) && !this.section(s.section).isCode && !s.name.startsWith('.') && !s.name.startsWith('$'));
  }
}
