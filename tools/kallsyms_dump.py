#!/usr/bin/env python3
"""Decode dada kallsyms (6.6 BASE_RELATIVE) from the raw arm64 Image.

Layout (scripts/kallsyms.c, v6.6):
    num_syms(u32) | names | markers[] | token_table | token_index[] | offsets[] | relative_base(u64)
Symbol lengths in `names` are ULEB128 (1 or 2 bytes).
"""
import struct, sys

if len(sys.argv) < 2:
    sys.exit("usage: kallsyms_dump.py <kernel.bin> [out.txt]")
d = open(sys.argv[1], "rb").read()
out_path = sys.argv[2] if len(sys.argv) > 2 else "kallsyms.txt"

# Offsets inside this build's image; re-derive them for another device with the
# token-table/marker/offsets search described in the module docstring.
TT, TI = 0x14c5a40, 0x14c5dd0
NUM = 110306
OFF_POS = 0x14c5fd0
BASE_POS = OFF_POS + 4 * NUM
BASE = struct.unpack_from("<Q", d, BASE_POS)[0]
MARKERS = 0x14c5380
assert BASE == 0xffffffc080000000, hex(BASE)

ti = struct.unpack_from("<256H", d, TI)
tok = [d[TT + ti[i]: d.find(b"\0", TT + ti[i])] for i in range(256)]
offs = struct.unpack_from("<%dI" % NUM, d, OFF_POS)
markers = struct.unpack_from("<%dI" % ((NUM + 255) // 256), d, MARKERS)

def addr(o):
    return BASE - (0x100000000 - o) if o >= 0x80000000 else BASE + o

def walk(start, want):
    """Decode `want` records; return (position, first-record-bytes) or None."""
    p, out = start, []
    for _ in range(want):
        if p >= MARKERS:
            return None
        ln = d[p]
        p += 1
        if ln & 0x80:                       # ULEB128, two bytes
            ln = (ln & 0x7F) | (d[p] << 7)
            p += 1
        if ln == 0 or p + ln > MARKERS:
            return None
        out.append(d[p:p + ln])
        p += ln
    return p, out

# loc.py: names_start + markers[i] == position of symbol i*256
# so walking 256 symbols from names_start + markers[1] must land on
# names_start + markers[2], and likewise for every i.
def solve_names_start():
    for ns in range(0x1348000, 0x134d000):
        ok = True
        for i in range(1, len(markers) - 1, 37):     # sparse but global check
            r = walk(ns + markers[i], 256)
            if r is None or r[0] != ns + markers[i + 1]:
                ok = False
                break
        if not ok:
            continue
        total = walk(ns, NUM)
        if total is None or not (0 <= MARKERS - total[0] <= 7):
            continue
        return ns
    return None

ns = solve_names_start()
assert ns, "names_start not solved"
print(f"# names_start={ns:#x} num_syms={NUM} relative_base={BASE:#x}")

records = walk(ns, NUM)[1]
out = []
for raw, o in zip(records, offs):
    out.append((b"".join(tok[b] for b in raw).decode("latin1"), addr(o)))

mono = sum(1 for i in range(1, NUM) if out[i][1] >= out[i - 1][1])
print(f"# monotonic={mono}/{NUM-1}  first={out[0][0][:24]!r} addr={out[0][1]:#x}")
with open(out_path, "w") as f:
    for nm, a in out:
        f.write(f"{a:016x} {nm}\n")
print(f"# wrote {out_path}")

want = ("_text", "stext", "init_cred", "init_user_ns", "init_ucounts",
        "init_groups", "root_user", "selinux_state", "panic_on_warn",
        "init_task", "do_timer_create", "copy_process", "commit_creds",
        "panic", "__arm64_sys_timer_create")
sym = {}
for nm, a in out:
    sym.setdefault(nm, a)
for w in want:
    print(f"{w:28s} {sym.get(w, 0):#018x}")
