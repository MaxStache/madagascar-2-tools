"""Extract Alchemy 'ark' reflection metadata from Madagascar 2 DLLs.

For every class the engine registers we recover:
  * reflected type name + object size + parent class   (arkRegisterInternal)
  * own fields: name, byte offset, metafield type      (arkRegisterInitialize)

Decoded from real x86 disassembly (capstone). Cross-DLL references are resolved
through the import tables + jmp-thunks, so parents/field types that live in
another module still link up.
"""
import struct, glob, os, sys, json, re
from capstone import *
from capstone.x86 import *


class PE:
    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path)
        d = self.d = open(path, 'rb').read()
        pe = struct.unpack_from('<I', d, 0x3c)[0]
        nsec = struct.unpack_from('<H', d, pe+6)[0]
        opt = pe+24
        magic = struct.unpack_from('<H', d, opt)[0]
        self.base = struct.unpack_from('<I', d, opt+28)[0]
        dd = opt + (96 if magic == 0x10b else 112)
        self.edir = struct.unpack_from('<2I', d, dd)[0]
        self.idir = struct.unpack_from('<2I', d, dd+8)[0]
        secoff = opt + struct.unpack_from('<H', d, pe+20)[0]
        self.secs = []
        for i in range(nsec):
            o = secoff+40*i
            nm = d[o:o+8].rstrip(b'\0').decode('latin1')
            vs, va, rs, ra = struct.unpack_from('<4I', d, o+8)
            self.secs.append((va, vs, ra, rs, nm))

    def r2o(self, rva):
        for va, vs, ra, rs, nm in self.secs:
            if va <= rva < va+max(vs, rs):
                off = ra+(rva-va)
                return off if off < len(self.d) else None
        return None

    def va2o(self, va): return self.r2o(va - self.base)

    def cstr(self, va, maxlen=300):
        o = self.va2o(va)
        if o is None: return None
        e = self.d.find(b'\0', o, o+maxlen)
        if e < 0: return None
        try: return self.d[o:e].decode('ascii')
        except Exception: return None

    def exports(self):
        d = self.d
        if not self.edir: return []
        e = self.r2o(self.edir)
        nnames, = struct.unpack_from('<I', d, e+24)
        afun, anames, aord = struct.unpack_from('<3I', d, e+28)
        fo, ao, oo = self.r2o(afun), self.r2o(anames), self.r2o(aord)
        out = []
        for i in range(nnames):
            nr, = struct.unpack_from('<I', d, ao+4*i)
            o = self.r2o(nr); s = d[o:d.index(b'\0', o)].decode('latin1')
            ordi, = struct.unpack_from('<H', d, oo+2*i)
            rva, = struct.unpack_from('<I', d, fo+4*ordi)
            out.append((s, rva+self.base))
        return out

    def imports(self):
        """-> {IAT virtual address: symbol name}"""
        d, out = self.d, {}
        if not self.idir: return out
        o = self.r2o(self.idir)
        while True:
            oft, _, _, nrva, first = struct.unpack_from('<5I', d, o)
            if not (oft or first): break
            t = self.r2o(oft or first)
            iat = first + self.base
            while True:
                ent, = struct.unpack_from('<I', d, t)
                if ent == 0: break
                if not (ent & 0x80000000):
                    no = self.r2o(ent)
                    if no is not None:
                        nm = d[no+2:d.index(b'\0', no+2)].decode('latin1')
                        out[iat] = nm
                t += 4; iat += 4
            o += 20
        return out

    def thunks(self, iatmap):
        """scan for `jmp dword ptr [IAT]` stubs -> {thunk va: symbol name}"""
        out = {}
        for va, vs, ra, rs, nm in self.secs:
            if nm not in ('.text', 'CODE'): continue
            blob = self.d[ra:ra+min(vs, rs)]
            for m in re.finditer(b'\xff\x25', blob):
                p = m.start()
                if p + 6 > len(blob): continue
                tgt, = struct.unpack_from('<I', blob, p+2)
                if tgt in iatmap:
                    out[self.base + va + p] = iatmap[tgt]
        return out

    def code_at(self, va, n=0x2000):
        o = self.va2o(va)
        return b'' if o is None else self.d[o:o+n]


md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True

def insns(pe, va, limit=0x2000):
    out = []
    for ins in md.disasm(pe.code_at(va, limit), va):
        out.append(ins)
        if ins.mnemonic == 'ret': break
    return out


GP = {X86_REG_EAX: 'a', X86_REG_EBX: 'b', X86_REG_ECX: 'c', X86_REG_EDX: 'd',
      X86_REG_ESI: 'si', X86_REG_EDI: 'di', X86_REG_EBP: 'bp',
      X86_REG_AX: 'a', X86_REG_BX: 'b', X86_REG_CX: 'c', X86_REG_DX: 'd',
      X86_REG_AL: 'a', X86_REG_BL: 'b', X86_REG_CL: 'c', X86_REG_DL: 'd'}


def trace(pe, va, resolve, popbytes=lambda s: 0):
    """Tiny constant/ESP tracker over one function.

    Stack slots are normalised to an offset from ESP-at-entry so that values
    stored before and after intervening pushes share one coordinate system.

    Returns (slots, calls):
      slots : {(norm_off, size): ('imm', v) | ('sym', name) | ('stack', off)}
      calls : [(callee_symbol_or_None, [args...])]  args in source order
    """
    regs, slots, pushes, calls = {}, {}, [], []
    esp = 0                                  # delta from ESP at entry

    def val_of(op):
        if op.type == X86_OP_IMM: return ('imm', op.imm & 0xFFFFFFFF)
        if op.type == X86_OP_REG: return regs.get(GP.get(op.reg))
        if op.type == X86_OP_MEM and op.mem.base == 0 and not op.mem.index:
            s = resolve(pe, op.mem.disp & 0xFFFFFFFF)          # mov reg,[IAT]
            return ('sym', s) if s else None
        return None

    for ins in insns(pe, va):
        m, ops = ins.mnemonic, ins.operands
        if m == 'push':
            pushes.append(val_of(ops[0])); esp -= 4
        elif m == 'pop':
            esp += 4
            if ops and ops[0].type == X86_OP_REG: regs.pop(GP.get(ops[0].reg), None)
        elif m in ('sub', 'add') and len(ops) == 2 and ops[0].type == X86_OP_REG \
                and ops[0].reg == X86_REG_ESP and ops[1].type == X86_OP_IMM:
            esp += -ops[1].imm if m == 'sub' else ops[1].imm
        elif m == 'call':
            tgt = None
            op = ops[0]
            if op.type == X86_OP_IMM: tgt = resolve(pe, op.imm & 0xFFFFFFFF)
            elif op.type == X86_OP_MEM and op.mem.base == 0:
                tgt = resolve(pe, op.mem.disp & 0xFFFFFFFF)
            elif op.type == X86_OP_REG:
                # the compiler caches IAT pointers in callee-saved regs and
                # calls them repeatedly (`mov ebp,[IAT]` ... `call ebp`)
                v = regs.get(GP.get(op.reg))
                if v and v[0] == 'sym': tgt = v[1]
            calls.append((tgt, list(pushes)))
            # stdcall/thiscall callees pop their own args: ask the callee's `ret imm16`
            direct = op.imm & 0xFFFFFFFF if op.type == X86_OP_IMM else None
            esp += popbytes(tgt, pe, direct)
            pushes = []
            regs.pop('a', None); regs.pop('c', None); regs.pop('d', None)
        elif m == 'lea' and ops[0].type == X86_OP_REG and ops[1].mem.base == X86_REG_ESP \
                and not ops[1].mem.index:
            r = GP.get(ops[0].reg)
            if r: regs[r] = ('stack', esp + ops[1].mem.disp)
        elif m == 'mov' and len(ops) == 2:
            dst, src = ops
            if dst.type == X86_OP_REG:
                r = GP.get(dst.reg)
                if r: regs[r] = val_of(src)
            elif dst.type == X86_OP_MEM and dst.mem.base == X86_REG_ESP and not dst.mem.index:
                v = val_of(src)
                if v is not None: slots[(esp + dst.mem.disp, dst.size)] = v
        elif m == 'xor' and len(ops) == 2 and ops[0].type == ops[1].type == X86_OP_REG \
                and ops[0].reg == ops[1].reg:
            r = GP.get(ops[0].reg)
            if r: regs[r] = ('imm', 0)
        elif ops and ops[0].type == X86_OP_REG:
            regs.pop(GP.get(ops[0].reg), None)
    return slots, calls


def scope_of(sym):
    """'?arkRegister@Foo@Bar@Gap@@SAXXZ' -> ('arkRegister', 'Foo')"""
    if not sym.startswith('?'): return None
    at = sym.find('@@')
    if at < 0: return None
    parts = sym[1:at].split('@')
    return (parts[0], parts[1]) if len(parts) >= 2 else None


def runs(slots, stride):
    """longest run of stack slots spaced exactly `stride` apart"""
    if not slots: return []
    slots = sorted(slots, key=lambda s: (s[0], s[1]))
    best, cur = [], [slots[0]]
    for a, b in zip(slots, slots[1:]):
        if a[0] == b[0] and b[1]-a[1] == stride: cur.append(b)
        else:
            if len(cur) > len(best): best = cur
            cur = [b]
    return cur if len(cur) > len(best) else best


def collect(dlls):
    pes = [PE(p) for p in dlls]
    sym_at = {}          # (dll, va) -> symbol name  (own exports + thunks)
    ari_sym = {}         # arkRegisterInternal symbol -> class record
    fac_sym = {}         # instantiateFromPool symbol -> metafield class name
    records = []

    for pe in pes:
        try: ex = pe.exports()
        except Exception: ex = []
        pe._ex = ex
        try: iat = pe.imports()
        except Exception: iat = {}
        th = pe.thunks(iat)
        for va, nm in th.items(): sym_at[(pe.name, va)] = nm
        for s, va in ex:
            sym_at.setdefault((pe.name, va), s)
            sc = scope_of(s)
            if sc and sc[0] == 'instantiateFromPool': fac_sym[s] = sc[1]
        pe._iat = iat

    def resolve(pe, va):
        if va is None: return None
        return sym_at.get((pe.name, va)) or pe._iat.get(va)

    # symbol -> (pe, va) so we can ask any callee how many bytes it pops
    sym_def = {}
    for pe in pes:
        for s, va in pe._ex: sym_def.setdefault(s, (pe, va))

    _popcache = {}
    def popbytes(sym, cpe=None, cva=None):
        """bytes the callee removes from the stack (0 for cdecl).

        Works for exported symbols and for purely local helpers, which are
        reached by address -- those still pop their args and would otherwise
        desynchronise our ESP model.
        """
        if sym and sym in sym_def: cpe, cva = sym_def[sym]
        key = sym or (cpe.name, cva) if cpe else None
        if key is None: return 0
        if key in _popcache: return _popcache[key]
        _popcache[key] = 0                       # guard against recursion
        if cpe is not None and cva is not None:
            for k, ins in enumerate(insns(cpe, cva, 0x4000)):
                if ins.mnemonic == 'jmp' and k == 0:   # thunk: follow one hop
                    op = ins.operands[0]
                    t = resolve(cpe, op.imm & 0xFFFFFFFF) if op.type == X86_OP_IMM else \
                        (resolve(cpe, op.mem.disp & 0xFFFFFFFF) if op.type == X86_OP_MEM
                         and not op.mem.base else None)
                    if t and t != sym: _popcache[key] = popbytes(t)
                    break
                if ins.mnemonic == 'ret':
                    _popcache[key] = ins.operands[0].imm if ins.operands else 0
                    break
        return _popcache[key]

    # ---- pass 1: arkRegisterInternal -> name / size / parent ----
    for pe in pes:
        for s, va in pe._ex:
            sc = scope_of(s)
            if not sc or sc[0] != 'arkRegisterInternal': continue
            _, calls = trace(pe, va, resolve, popbytes)
            args = None
            for tgt, ps in calls:
                if len(ps) >= 5: args = list(reversed(ps[-9:])); break
            if not args or len(args) < 5: continue

            def tag(i, want):
                v = args[i]
                return v[1] if v and v[0] == want else None
            name = pe.cstr(tag(3, 'imm') or 0)
            if not name or not re.match(r'^[A-Za-z_][\w:<>, ]*$', name): continue
            pa = args[1]
            parent_sym = pa[1] if pa and pa[0] == 'sym' else (
                resolve(pe, pa[1]) if pa and pa[0] == 'imm' else None)
            rec = dict(name=name, dll=pe.name, cls=sc[1], size=tag(4, 'imm'),
                       parent_sym=parent_sym, fields=[])
            ari_sym[s] = rec
            records.append((pe, rec))

    for pe, rec in records:
        p = ari_sym.get(rec.pop('parent_sym'))
        rec['parent'] = p['name'] if p else None

    by_cls = {}
    for pe, rec in records: by_cls.setdefault((pe.name, rec['cls']), rec)

    # ---- pass 2: arkRegisterInitialize -> own fields ----
    for pe in pes:
        for s, va in pe._ex:
            sc = scope_of(s)
            if not sc or sc[0] != 'arkRegisterInitialize': continue
            rec = by_cls.get((pe.name, sc[1]))
            if rec is None: continue
            slots, calls = trace(pe, va, resolve, popbytes)

            # locate the two engine calls and read their array-base arguments
            n = fac_base = name_base = off_base = None
            for tgt, ps in calls:
                if not tgt: continue
                if 'instantiateAndAppendFields' in tgt and len(ps) >= 2:
                    a = list(reversed(ps[-2:]))
                    if a[0] and a[0][0] == 'stack': fac_base = a[0][1]
                    if a[1] and a[1][0] == 'imm': n = a[1][1]
                elif 'setMetaFieldBasicPropertiesAndValidateAll' in tgt and len(ps) >= 4:
                    a = list(reversed(ps[-4:]))
                    if a[0] and a[0][0] == 'stack': name_base = a[0][1]
                    if a[2] and a[2][0] == 'stack': off_base = a[2][1]
                    if n is None and a[3] and a[3][0] == 'imm': n = a[3][1]
            if os.environ.get('ARKDBG') == rec['name']:
                print('DBG %s n=%s fac=%s name=%s off=%s' % (rec['name'], n,
                      fac_base, name_base, off_base))
                for tgt, ps in calls:
                    print('   call %-58s %s' % ((tgt or '?')[:58], ps[-5:]))
            if not n or n > 400: rec['ok'] = False; continue

            # Flatten stores into a byte image so that packed writes (MSVC likes
            # to fold two adjacent 16-bit offsets into one dword) still decode.
            image, symat = {}, {}
            for (off, size), (kind, val) in slots.items():
                if kind == 'imm':
                    for k in range(size): image[off+k] = (val >> (8*k)) & 0xFF
                else:
                    symat[off] = (kind, val)

            def rdint(addr, size):
                v = 0
                for k in range(size):
                    b = image.get(addr+k)
                    if b is None: return None
                    v |= b << (8*k)
                return v

            def facat(a):
                if a in symat and symat[a][0] == 'sym':
                    return fac_sym.get(symat[a][1])
                p = rdint(a, 4)
                return fac_sym.get(resolve(pe, p)) if p else None

            def nameat(a):
                p = rdint(a, 4)
                if not p: return None
                t = pe.cstr(p, 64)
                return t if t and re.match(r'^[A-Za-z_]\w{0,40}$', t) else None

            # The ESP model can still drift a little in long functions, so treat
            # the lea-derived bases as hints and confirm each array by requiring
            # n consecutive valid entries; that is self-validating.
            cands = sorted(set(list(image) + list(symat)))
            def find(hint, stride, good, extra=None):
                if hint is not None and all(good(hint + stride*i) for i in range(n)):
                    return hint
                best = None
                for b in cands:
                    if not all(good(b + stride*i) for i in range(n)): continue
                    if extra and not extra([b + stride*i for i in range(n)]): continue
                    if best is None or (hint is not None and abs(b-hint) < abs(best-hint)):
                        best = b
                return best

            hint_name = name_base
            fac_base = find(fac_base, 4, lambda a: facat(a) is not None)
            name_base = find(name_base, 4, lambda a: nameat(a) is not None)

            # The names and offsets pointers are formed by adjacent LEAs, so any
            # residual ESP drift is identical for both: correct offsets by the
            # very same delta rather than searching for them independently.
            lim = rec['size'] or 0x8000
            def okoff(b):
                if b is None or b % 2: return False
                vs = [rdint(b + 2*i, 2) for i in range(n)]
                return all(v is not None and 4 <= v < lim for v in vs) and len(set(vs)) == n
            if name_base is not None and hint_name is not None and off_base is not None:
                shifted = off_base + (name_base - hint_name)
                off_base = shifted if okoff(shifted) else off_base
            if not okoff(off_base):
                off_base = find(off_base, 2, lambda a: True, lambda addrs: okoff(addrs[0]))

            fields = []
            for i in range(n):
                fields.append(dict(
                    name=nameat(name_base + 4*i) if name_base is not None else None,
                    offset=rdint(off_base + 2*i, 2) if off_base is not None else None,
                    type=facat(fac_base + 4*i) if fac_base is not None else None))
            rec['fields'] = fields
            rec['ok'] = all(f['name'] and f['offset'] is not None and f['type'] for f in fields)
    return {r['name']: r for _, r in records}


if __name__ == '__main__':
    gamedir = sys.argv[1] if len(sys.argv) > 1 else '.'
    out = collect(sorted(glob.glob(os.path.join(gamedir, '*.dll'))))
    withf = [r for r in out.values() if r['fields']]
    bad = [r['name'] for r in withf if not r.get('ok')]
    noparent = [r['name'] for r in out.values() if r['parent'] is None]
    print('classes=%d  with-fields=%d  inconsistent=%d  no-parent=%d'
          % (len(out), len(withf), len(bad), len(noparent)))
    if bad: print('  inconsistent sample:', bad[:15])
    json.dump(out, open('ark_meta.json', 'w'), indent=1)
    print('wrote ark_meta.json')
    for nm in ('igIGZSaverStat', 'igObjectList', 'StringInfo', 'igInfo', 'SpriteInfo', 'igImage2'):
        r = out.get(nm)
        if not r: continue
        print('\n%s  size=%s parent=%s [%s] ok=%s' % (nm, r['size'], r['parent'], r['dll'], r.get('ok')))
        for f in r['fields']:
            print('   +%-6s %-30s %s' % (hex(f['offset']) if f['offset'] is not None else '?',
                                          f['name'], f['type']))
