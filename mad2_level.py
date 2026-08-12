#!/usr/bin/env python3
"""
Madagascar 2 (.bld) level reader.

A .bld is an **igArchive version 2** container (magic "IGA\\x1a") holding one or
more **IGZ version 4** files -- the Alchemy engine's serialised C++ heap. An IGZ
is essentially a RAM image of the object graph plus side tables ("fixups") that
say which words are pointers, string ids, etc. Loading is therefore just a
relocation pass, which is why the engine can load levels so fast.

This module reproduces that load in Python and, using the reflection metadata
recovered from the game's DLLs (ark_meta.json), presents every object as a typed
record with named fields.

Usage:
    python mad2_level.py <file.bld> [--list] [--dump-files DIR]
    python mad2_level.py <file.bld> --tree [--max N]
    python mad2_level.py <file.bld> --json out.json
    python mad2_level.py <file.bld> --type SpriteInfo
"""

import argparse, json, os, struct, sys, zlib

# --------------------------------------------------------------------------
# igArchive v2  (.bld / .arc)
# --------------------------------------------------------------------------

SECTOR = 0x800          # v2 archives always use 2 KiB sectors
HDR_SIZE = 0x30
FILEINFO_SIZE = 0xC


class ArchiveFile:
    __slots__ = ('block_index', 'hash', 'length', 'name', 'offset')

    def __init__(self, name, hash_, offset, length, block_index):
        self.name, self.hash = name, hash_
        self.offset, self.length, self.block_index = offset, length, block_index

    def __repr__(self):
        return '<%s %d bytes>' % (self.name, self.length)


class IGArchive:
    """igArchive version 2 reader (the version igRewrite8 does not cover)."""

    def __init__(self, path):
        self.path = path
        self.f = open(path, 'rb')
        hdr = self.f.read(HDR_SIZE)
        (magic, self.version, self.toc_size, num_files, self.hash_divider,
         self.hash_slop, self.name_table_offset, self.name_table_size,
         self.num_large, self.num_medium, self.num_small,
         self.flags) = struct.unpack('<12I', hdr)
        if magic != 0x1A414749:
            raise ValueError('%s is not an igArchive (magic %#x)' % (path, magic))
        if self.version != 2:
            raise NotImplementedError('igArchive version %d not supported' % self.version)

        hashes = struct.unpack('<%dI' % num_files, self.f.read(4 * num_files))
        info = [struct.unpack('<3I', self.f.read(FILEINFO_SIZE)) for _ in range(num_files)]

        self.f.seek(HDR_SIZE + num_files * (4 + FILEINFO_SIZE))
        self.large = struct.unpack('<%dI' % self.num_large, self.f.read(4 * self.num_large))
        self.medium = struct.unpack('<%dH' % self.num_medium, self.f.read(2 * self.num_medium))
        self.small = struct.unpack('<%dB' % self.num_small, self.f.read(self.num_small))

        self.files = []
        for i in range(num_files):
            self.f.seek(self.name_table_offset + i * 4)
            rel, = struct.unpack('<I', self.f.read(4))
            self.f.seek(self.name_table_offset + rel)
            self.files.append(ArchiveFile(self._cstr(), hashes[i], *info[i]))

    def _cstr(self):
        out = bytearray()
        while True:
            c = self.f.read(1)
            if c in (b'\0', b''):
                return out.decode('latin1')
            out += c

    @staticmethod
    def _block_kind(length):
        if 0x7F * SECTOR < length:
            return 'large' if 0x7FFF * SECTOR < length else 'medium'
        return 'small'

    def _blocks(self, fi):
        """-> ([(compressed, sector)], total_sectors)"""
        if fi.block_index == 0xFFFFFFFF:
            return None, 0
        table, mask, shift = {
            'large':  (self.large,  0x7FFFFFFF, 31),
            'medium': (self.medium, 0x7FFF, 15),
            'small':  (self.small,  0x7F, 7),
        }[self._block_kind(fi.length)]
        base = fi.block_index & 0x0FFFFFFF
        out, sectors = [], 0
        for j in range((fi.length + 0x7FFF) >> 15):          # 32 KiB per block
            raw = table[base + j]
            start = raw & mask
            out.append(((raw >> shift) & 1, start))
            sectors += (table[base + j + 1] & mask) - start
        return out, sectors

    def read(self, fi):
        """Decompress one member to bytes."""
        blocks, sectors = self._blocks(fi)
        self.f.seek(fi.offset)
        if blocks is None:
            return self.f.read(fi.length)
        raw = self.f.read(sectors * SECTOR)
        out = bytearray()
        for j, (compressed, sector) in enumerate(blocks):
            want = (fi.length & 0x7FFF) if fi.length < (j + 1) * 0x8000 else 0x8000
            pos = sector * SECTOR
            if not compressed:
                out += raw[pos:pos + want]
                continue
            # v<=4 stores the compressed size big-endian, payload is zlib
            size, = struct.unpack_from('>H', raw, pos)
            out += zlib.decompressobj(15).decompress(raw[pos + 2:pos + 2 + size], want)
        return bytes(out)

    def find(self, suffix):
        low = suffix.lower()
        for fi in self.files:
            if fi.name.lower().endswith(low):
                return fi
        return None


# --------------------------------------------------------------------------
# IGZ version 4
# --------------------------------------------------------------------------

# Fixup ids used by IGZ v4. Verified against Madagascar 2 data: TMET/TSTR by
# content, RVTB/ROOT/ROFS by graph traversal, RSTR by string-index range and
# MTSZ by matching every type size against the DLL reflection data.
FIX_TMET = 0x00   # type (meta object) name table
FIX_TSTR = 0x01   # string table
FIX_EXID = 0x02   # external ids
FIX_RSTR = 0x04   # locations holding a string-table index
FIX_RVTB = 0x05   # locations of objects (each starts with its type index)
FIX_ROFS = 0x06   # locations holding a pointer
FIX_REXT = 0x07   # locations holding an external reference
FIX_ROOT = 0x08   # the root object
FIX_ONAM = 0x09   # named-object list
FIX_TMHN = 0x0B   # memory-handle table (8 bytes per entry)
FIX_RMHN = 0x0C   # locations holding a memory-handle index
FIX_MTSZ = 0x0D   # per-type object size
FIX_UNK0E = 0x0E


def _cstr(buf, off):
    end = buf.index(b'\0', off)
    return buf[off:end].decode('latin1'), end + 1


class IGZ:
    """IGZ version 4 image: sections, fixups and the raw object heap."""

    MEMPOOL_NAMES_AT = 0x56C     # for version < 7

    def __init__(self, data):
        self.d = data
        magic, self.version, self.meta_version = struct.unpack_from('<3I', data, 0)
        if magic != 0x49475A01:
            raise ValueError('not an IGZ file (magic %#x)' % magic)
        if self.version >= 7:
            raise NotImplementedError('IGZ version %d not supported' % self.version)

        self.sections = []
        for i in range(32):
            name_off, off, length, align = struct.unpack_from('<4I', data, 0xC + 0x10 * i)
            if off == 0:
                break
            self.sections.append((name_off, off, length, align))
        self.pool_names = [_cstr(data, self.MEMPOOL_NAMES_AT + s[0])[0] for s in self.sections]

        # section 0 holds the fixups; the rest are memory pools
        self.fixup_off = self.sections[0][1]
        self.pools = [s[1] for s in self.sections[1:]]

        self.platform, = struct.unpack_from('<h', data, self.fixup_off + 8)
        count, = struct.unpack_from('<I', data, self.fixup_off + 0x10)
        self.fixups = {}
        cursor = 0x1C
        for _ in range(count):
            base = self.fixup_off + cursor
            fid, = struct.unpack_from('<I', data, base)
            n, length, start = struct.unpack_from('<3I', data, base + 12)
            self.fixups[fid] = (base + start, n, length - start)
            cursor += length

        self.types = self._strings(FIX_TMET)
        self.strings = self._strings(FIX_TSTR)
        self.type_sizes = self._u32s(FIX_MTSZ)

        self.object_offsets = self.unpack(FIX_RVTB)
        self.pointer_locs = set(self.unpack(FIX_ROFS))
        self.string_locs = set(self.unpack(FIX_RSTR))
        self.handle_locs = set(self.unpack(FIX_RMHN))
        self.external_locs = set(self.unpack(FIX_REXT))

    # -- tables -----------------------------------------------------------
    def _strings(self, fid):
        if fid not in self.fixups:
            return []
        off, n, _ = self.fixups[fid]
        out = []
        for _ in range(n):
            s, off = _cstr(self.d, off)
            out.append(s)
        return out

    def _u32s(self, fid):
        if fid not in self.fixups:
            return []
        off, n, _ = self.fixups[fid]
        return list(struct.unpack_from('<%dI' % n, self.d, off))

    def deserialize(self, value):
        """serialised offset -> absolute file offset (v<=6: pool index in top byte)"""
        return self.pools[value >> 24] + (value & 0x00FFFFFF)

    def unpack(self, fid):
        """Decode one of the R* tables: a stream of 3-bit-chunk varints packed
        two-per-byte, delta encoded, scaled by 4."""
        if fid not in self.fixups:
            return []
        off, n, length = self.fixups[fid]
        buf = self.d[off:off + length]
        out, running, pos, high = [], 0, 0, False

        def nibble():
            nonlocal pos, high
            if not high:
                v = buf[pos] & 0xF
                high = True
            else:
                v = buf[pos] >> 4
                pos += 1
                high = False
            return v

        for _ in range(n):
            c = nibble()
            value, shift = c & 7, 3
            while c & 8:
                c = nibble()
                value |= (c & 7) << shift
                shift += 3
            running += value * 4 + (4 if self.version < 9 else 0)
            out.append(self.deserialize(running))
        return out

    def root_offset(self):
        off, _, _ = self.fixups[FIX_ROOT]
        return self.deserialize(struct.unpack_from('<I', self.d, off)[0])


# --------------------------------------------------------------------------
# reflection metadata
# --------------------------------------------------------------------------

# byte width of each metafield type; anything absent is read as raw bytes
FIELD_SIZES = {
    'igBoolMetaField': 1, 'igCharMetaField': 1, 'igUnsignedCharMetaField': 1,
    'igShortMetaField': 2, 'igUnsignedShortMetaField': 2,
    'igIntMetaField': 4, 'igUnsignedIntMetaField': 4, 'igEnumMetaField': 4,
    'igFloatMetaField': 4, 'igDoubleMetaField': 8,
    'igLongMetaField': 8, 'igUnsignedLongMetaField': 8,
    'igObjectRefMetaField': 4, 'igHandleMetaField': 4, 'igRawRefMetaField': 4,
    'igStringMetaField': 4, 'igNameMetaField': 4, 'igIntPtrMetaField': 4,
    'igMemoryRefMetaField': 8, 'igMemoryRefHandleMetaField': 8,
    'igVec2fMetaField': 8, 'igVec3fMetaField': 12, 'igVec4fMetaField': 16,
    'igVec2iMetaField': 8, 'igVec3iMetaField': 12, 'igVec4iMetaField': 16,
    'igVec2ucMetaField': 2, 'igVec3ucMetaField': 3, 'igVec4ucMetaField': 4,
    'igQuaternionfMetaField': 16, 'igMatrix44fMetaField': 64,
    'igShortArrayMetaField': 4, 'igStructMetaField': 4,
}

_SCALAR = {
    'igBoolMetaField': ('<B', lambda v: bool(v)),
    'igCharMetaField': ('<b', int), 'igUnsignedCharMetaField': ('<B', int),
    'igShortMetaField': ('<h', int), 'igUnsignedShortMetaField': ('<H', int),
    'igIntMetaField': ('<i', int), 'igUnsignedIntMetaField': ('<I', int),
    'igEnumMetaField': ('<i', int), 'igFloatMetaField': ('<f', float),
    'igDoubleMetaField': ('<d', float),
    'igLongMetaField': ('<q', int), 'igUnsignedLongMetaField': ('<Q', int),
}

_VECTOR = {
    'igVec2fMetaField': '<2f', 'igVec3fMetaField': '<3f', 'igVec4fMetaField': '<4f',
    'igVec2iMetaField': '<2i', 'igVec3iMetaField': '<3i', 'igVec4iMetaField': '<4i',
    'igVec2ucMetaField': '<2B', 'igVec3ucMetaField': '<3B', 'igVec4ucMetaField': '<4B',
    'igQuaternionfMetaField': '<4f',
}


class ArkMeta:
    """Class layouts recovered from the game DLLs' arkRegister* functions."""

    def __init__(self, path):
        with open(path) as fh:
            self.classes = json.load(fh)
        self._cache = {}

    def fields(self, type_name):
        """Full field list including inherited ones, ordered by offset."""
        if type_name in self._cache:
            return self._cache[type_name]
        out, seen, name = [], set(), type_name
        while name:
            rec = self.classes.get(name)
            if not rec:
                break
            for f in rec['fields']:
                key = f.get('offset')
                if f.get('name') and key is not None and key not in seen:
                    seen.add(key)
                    out.append(dict(f, owner=name))
            name = rec.get('parent')
        out.sort(key=lambda f: f['offset'])
        self._cache[type_name] = out
        return out

    def size(self, type_name):
        rec = self.classes.get(type_name)
        return rec['size'] if rec else None


# --------------------------------------------------------------------------
# object model
# --------------------------------------------------------------------------

class Ref:
    """An unresolved pointer to another object."""
    __slots__ = ('offset',)

    def __init__(self, offset):
        self.offset = offset

    def __repr__(self):
        return '<ref %#x>' % self.offset


class Obj:
    """One deserialised C++ object."""
    __slots__ = ('type', 'offset', 'fields', 'level')

    def __init__(self, type_name, offset, level):
        self.type, self.offset, self.level = type_name, offset, level
        self.fields = {}

    def get(self, name, default=None):
        return self.fields.get(name, default)

    def resolve(self, value):
        """Ref -> Obj (or None). Leaves anything else untouched."""
        if isinstance(value, Ref):
            return self.level.objects.get(value.offset)
        return value

    def children(self):
        """For list-like objects, the resolved element objects."""
        return [c for c in (self.resolve(v) for v in self.elements()) if c is not None]

    def elements(self):
        """Raw elements of an igDataList-style object ( _count / _data )."""
        return self.level.list_elements(self)

    def __repr__(self):
        return '<%s @%#x %d fields>' % (self.type, self.offset, len(self.fields))


class Level:
    """A parsed IGZ: every object, typed, with named fields."""

    def __init__(self, igz, meta):
        self.igz, self.meta = igz, meta
        self.objects = {}
        d = igz.d

        for off in igz.object_offsets:
            tindex, = struct.unpack_from('<I', d, off)
            if tindex >= len(igz.types):
                continue
            self.objects[off] = Obj(igz.types[tindex], off, self)

        for obj in self.objects.values():
            self._read_fields(obj)

        self.root = self.objects.get(igz.root_offset())

    def _read_fields(self, obj):
        d, igz = self.igz.d, self.igz
        for f in self.meta.fields(obj.type):
            addr = obj.offset + f['offset']
            ftype = f.get('type')
            size = FIELD_SIZES.get(ftype, 4)
            if addr + size > len(d):
                continue
            obj.fields[f['name']] = self._read_one(addr, ftype, size)

    def _read_one(self, addr, ftype, size):
        d, igz = self.igz.d, self.igz
        # The fixup tables are authoritative about what a word really is.
        if addr in igz.pointer_locs:
            raw, = struct.unpack_from('<I', d, addr)
            return Ref(igz.deserialize(raw)) if raw else None
        if addr in igz.string_locs:
            idx, = struct.unpack_from('<I', d, addr)
            return igz.strings[idx] if idx < len(igz.strings) else None
        if addr in igz.handle_locs:
            idx, = struct.unpack_from('<I', d, addr)
            return {'__memhandle__': idx}
        if addr in igz.external_locs:
            idx, = struct.unpack_from('<I', d, addr)
            return {'__external__': idx}

        if ftype in _SCALAR:
            fmt, conv = _SCALAR[ftype]
            return conv(struct.unpack_from(fmt, d, addr)[0])
        if ftype in _VECTOR:
            return list(struct.unpack_from(_VECTOR[ftype], d, addr))
        if ftype == 'igMatrix44fMetaField':
            return list(struct.unpack_from('<16f', d, addr))
        if ftype in ('igMemoryRefMetaField', 'igMemoryRefHandleMetaField'):
            count, ptr = struct.unpack_from('<2I', d, addr)
            return {'size': count & 0x7FFFFFFF,
                    'data': Ref(igz.deserialize(ptr)) if ptr else None}
        if ftype in ('igObjectRefMetaField', 'igHandleMetaField',
                     'igRawRefMetaField', 'igStringMetaField', 'igNameMetaField'):
            return None                      # a pointer the fixups left null
        return d[addr:addr + size].hex()

    def list_elements(self, obj):
        """Elements of an igDataList-derived object, honouring the fixups."""
        d, igz = self.igz.d, self.igz
        count = obj.fields.get('_count')
        mem = obj.fields.get('_data')
        if not isinstance(count, int) or not isinstance(mem, dict):
            return []
        data = mem.get('data')
        if not isinstance(data, Ref):
            return []
        base, out = data.offset, []
        for i in range(count):
            addr = base + 4 * i
            if addr + 4 > len(d):
                break
            out.append(self._read_one(addr, 'igObjectRefMetaField', 4))
        return out

    # -- reporting --------------------------------------------------------
    def by_type(self):
        counts = {}
        for o in self.objects.values():
            counts[o.type] = counts.get(o.type, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    def of_type(self, name):
        return [o for o in self.objects.values() if o.type == name]

    def to_jsonable(self):
        def enc(v):
            if isinstance(v, Ref):
                o = self.objects.get(v.offset)
                return {'__ref__': '%#x' % v.offset, 'type': o.type if o else None}
            if isinstance(v, dict):
                return {k: enc(x) for k, x in v.items()}
            if isinstance(v, list):
                return [enc(x) for x in v]
            return v
        return {'%#x' % o.offset: {'type': o.type,
                                   'fields': {k: enc(v) for k, v in o.fields.items()}}
                for o in self.objects.values()}


# --------------------------------------------------------------------------

def load(path, meta_path=None):
    """Open a .bld and return (archive, Level) for the level IGZ inside it."""
    meta_path = meta_path or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                          'ark_meta.json')
    meta = ArkMeta(meta_path)
    arc = IGArchive(path)
    fi = arc.find('level.bld') or arc.files[0]
    return arc, Level(IGZ(arc.read(fi)), meta)


def _print_tree(level, node, depth, limit, seen, out):
    if node is None or len(out) >= limit:
        return
    label = node.get('_name') or node.get('_objectName') or ''
    out.append('%s%s%s' % ('  ' * depth, node.type,
                           ' %r' % label if isinstance(label, str) and label else ''))
    if node.offset in seen:
        return
    seen.add(node.offset)
    for child in node.children():
        _print_tree(level, child, depth + 1, limit, seen, out)


def main(argv=None):
    ap = argparse.ArgumentParser(description='Parse Madagascar 2 .bld levels')
    ap.add_argument('bld')
    ap.add_argument('--meta', help='path to ark_meta.json')
    ap.add_argument('--list', action='store_true', help='list archive members')
    ap.add_argument('--dump-files', metavar='DIR', help='extract archive members')
    ap.add_argument('--tree', action='store_true', help='print the object tree')
    ap.add_argument('--max', type=int, default=200, help='max tree lines')
    ap.add_argument('--type', help='dump all objects of this type')
    ap.add_argument('--json', metavar='OUT', help='write every object to JSON')
    args = ap.parse_args(argv)

    arc = IGArchive(args.bld)
    if args.list or args.dump_files:
        for fi in arc.files:
            print('%-28s %10d bytes  offset %#x' % (fi.name, fi.length, fi.offset))
        if args.dump_files:
            os.makedirs(args.dump_files, exist_ok=True)
            for fi in arc.files:
                out = os.path.join(args.dump_files, os.path.basename(fi.name))
                with open(out, 'wb') as fh:
                    fh.write(arc.read(fi))
                print('wrote', out)
        if not (args.tree or args.type or args.json):
            return 0

    meta_path = args.meta or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                          'ark_meta.json')
    meta = ArkMeta(meta_path)
    fi = arc.find('level.bld') or arc.files[0]
    igz = IGZ(arc.read(fi))
    level = Level(igz, meta)

    print('%s: IGZ v%d, platform %d, %d objects, %d types, %d strings'
          % (fi.name, igz.version, igz.platform, len(level.objects),
             len(igz.types), len(igz.strings)))
    known = sum(1 for o in level.objects.values() if meta.classes.get(o.type))
    print('reflection coverage: %d/%d objects have a known layout'
          % (known, len(level.objects)))

    if args.tree:
        out = []
        _print_tree(level, level.root, 0, args.max, set(), out)
        print('\n'.join(out))
    elif args.type:
        for o in level.of_type(args.type):
            print('\n%s @%#x' % (o.type, o.offset))
            for k, v in o.fields.items():
                print('   %-24s %r' % (k, v))
    elif not args.json:
        print('\ntop object types:')
        for t, n in list(level.by_type().items())[:25]:
            mark = '' if meta.classes.get(t) else '   (no layout)'
            print('   %-32s %5d%s' % (t, n, mark))

    if args.json:
        with open(args.json, 'w') as fh:
            json.dump(level.to_jsonable(), fh, indent=1)
        print('wrote', args.json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
