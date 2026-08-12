# Madagascar 2 `.bld` level format

## DISCLAMER: THIS IS COMPLETELY AI GENERATED
IM SORRY FOR MY SINS 😭

Fully reverse-engineered reader for Madagascar 2 (PC) level files, plus the tool
that recovers the engine's reflection metadata from the game DLLs.

Verified on **all 46 `.bld` files — 1,956,823 objects, 100 % of them with a known
class layout, zero unknown types.**

```
python mad2_level.py <file.bld>              # summary + type histogram
python mad2_level.py <file.bld> --tree       # object tree with names
python mad2_level.py <file.bld> --type ActorInfo
python mad2_level.py <file.bld> --json out.json
python mad2_level.py <file.bld> --list --dump-files out/
```

```python
import mad2_level
arc, level = mad2_level.load("Waterhole.bld")
for actor in level.of_type("ActorInfo"):
    print(actor.get("_name"), actor.get("_initMatrix")[12:15])   # world position
```

## Layer 1 — `.bld` is an igArchive **version 2**

Not an IGZ directly. Magic `IGA\x1a` (`0x1A414749`). igRewrite8 implements
versions 4 and 11 only; version 2's header differs and is documented here.
Header is `0x30` bytes, all little-endian `u32`:

| off | field | off | field |
|-----|-------|-----|-------|
|0x00|magic `0x1A414749`|0x18|nameTableOffset|
|0x04|version = 2|0x1C|nameTableSize|
|0x08|tocSize|0x20|numLargeFileBlocks|
|0x0C|numFiles|0x24|numMediumFileBlocks|
|0x10|hashSearchDivider|0x28|numSmallFileBlocks|
|0x14|hashSearchSlop|0x2C|flags|

Then `numFiles × u32` hashes, then `numFiles × 0xC` file records
(`offset, length, blockIndex`), then the large/medium/small block tables
(`u32`/`u16`/`u8`). Sector size is fixed at **0x800**.

* Block-size class: `small` if `len ≤ 0x7F*0x800`, else `medium` if
  `len ≤ 0x7FFF*0x800`, else `large`.
* Each block covers 32 KiB of output. Top bit of a block entry = compressed.
* A compressed block is `u16 compressedSize` **big-endian**, then a
  **zlib stream (with header)** — not raw deflate, and not the little-endian
  size used by later versions.

A level `.bld` typically contains `level.bld` (the real level) plus the
per-language `*.pak` string files; every member is itself an IGZ.

## Layer 2 — IGZ **version 4**

Magic `IGZ\x01` (`0x49475A01`), then `version=4`, `metaVersion`. The file is a
serialised image of the C++ heap: loading is just pointer relocation.

* Section table at `0x0C`, 16 bytes each (`nameOffset, offset, length, align`),
  terminated by `offset == 0`. Memory-pool names live at **`0x56C`**.
* Section 0 is the **fixup block**; sections 1..N are memory pools.
* A serialised pointer is `poolIndex << 24 | offsetInPool`.
* Fixup block: `platform` (`i16`) at `+0x08`, `numFixups` at `+0x10`, entries
  start at `+0x1C`. Each entry is `id(u32), 8 reserved, count, length, start`.

Fixup ids are **small integers**, not the FourCCs of later (Skylanders) IGZ:

| id | meaning | how it was confirmed |
|----|---------|----------------------|
|0x00|`TMET` type-name table|content |
|0x01|`TSTR` string table|content |
|0x02|`EXID` external ids| |
|0x04|`RSTR` locations holding a string index|every value < string count|
|0x05|`RVTB` object locations (word 0 = type index)|all indices valid; graph walks|
|0x06|`ROFS` locations holding a pointer|predicts array/pointer slots exactly|
|0x07|`REXT` locations holding an external ref| |
|0x08|`ROOT` the root object|resolves to the root `igObjectList`|
|0x09|`ONAM` named-object list| |
|0x0B|memory-handle table (8 bytes/entry)|count matches 0x0C|
|0x0C|locations holding a memory-handle index|values are 0..n-1|
|0x0D|`MTSZ` per-type object size|**matches DLL reflection sizes for every type**|

The `R*` tables are delta-encoded varints: 3 payload bits per nibble, high bit
continues, two nibbles per byte, each delta scaled by 4 with `+4` per entry for
version < 9.

The fixup tables are authoritative about what a given word *is*, so field
decoding consults them before falling back to the declared field type.

## Layer 3 — reflection metadata (`dump_ark.py` → `ark_meta.json`)

The engine DLLs (`igCore.dll`, `ScriptInfoLib.dll`, …) export ~11 800 fully
mangled symbols, including per class:

* `arkRegisterInternal` — calls `igArkRegister(&_Meta, parentArkRegisterInternal,
  parentGetClassMeta, "TypeName", objectSize, …)` → **name, size, parent**.
* `arkRegisterInitialize` — builds three parallel stack arrays (field-name
  `char*`s, `instantiateFromPool` factory pointers, `u16` offsets) and passes
  them to `igMetaObject::instantiateAndAppendFields` and
  `setMetaFieldBasicPropertiesAndValidateAll` → **field name, offset, type**.

`dump_ark.py` recovers all of it statically with capstone: it resolves
cross-module references through the import tables and `jmp` thunks, models ESP
(asking each callee's `ret imm16` how much it pops, including calls made through
IAT pointers cached in registers), then confirms each array by requiring `n`
consecutive valid entries so any residual drift cannot misalign the result.

Result: **1473 classes, 747 with fields, 739 fully consistent.** The 8 stragglers
(`OpCutScene`, `OpFlow`, `OpFlowBehavior`, `OpFlowBuiltInBehavior`, `OpFlowLoop`,
`OpPreScript`, `OpShutDown`, `OpStartUp`) each miss the type of one field; names
and offsets are present.

Regenerate with:

```
python dump_ark.py "C:/Program Files (x86)/Activision/Madagascar 2(TM)"
```

### Independent cross-check

`ark_meta.json` is derived purely from DLL code, while fixup `0x0D` is a table of
object sizes stored in the level data. They agree for **every type in every
level** — two independent sources confirming the layouts.

## Notes

* `Mad2.exe` is SecuROM-wrapped and not useful for this; all reflection lives in
  the plain DLLs next to it.
* Field values that are pointers the fixups left null decode as `None`; raw
  function-pointer fields (`_getFunc`, `_setFunc`) decode as hex.
