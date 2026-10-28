#!/usr/bin/env python3
"""Minimal BTF reader: dump struct member offsets for a few types."""
import struct, sys

if len(sys.argv) < 2:
    sys.exit("usage: btf_dump.py <vmlinux.btf>")
raw = open(sys.argv[1], "rb").read()
assert raw[:2] == b"\x9f\xeb", raw[:2]
hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from("<5I", raw, 4)
types = raw[hdr_len + type_off: hdr_len + type_off + type_len]
strs = raw[hdr_len + str_off: hdr_len + str_off + str_len]

def s(o):
    if o == 0:
        return ""
    e = strs.find(b"\0", o)
    return strs[o:e].decode("utf-8", "replace")

KIND = {0:"void",1:"int",2:"ptr",3:"array",4:"struct",5:"union",6:"enum",
        7:"fwd",8:"typedef",9:"volatile",10:"const",11:"restrict",
        12:"func",13:"func_proto",14:"var",15:"datasec",16:"float",17:"decl_tag",
        18:"type_tag",19:"enum64"}

# parse all types
off = 0
T = [None]
while off < len(types):
    name_off, info, size_type = struct.unpack_from("<III", types, off)
    off += 12
    kind = (info >> 24) & 0x1f
    vlen = info & 0xffff
    kflag = (info >> 31) & 1
    ent = {"name": s(name_off), "kind": kind, "vlen": vlen,
           "size": size_type, "members": [], "id": len(T)}
    for _ in range(vlen):
        if kind in (4, 5):
            mo, mt, mof = struct.unpack_from("<III", types, off)
            off += 12
            if kflag:
                bit_off = mof & 0xffffff
                bit_sz = mof >> 24
            else:
                bit_off, bit_sz = mof, 0
            ent["members"].append((s(mo), mt, bit_off, bit_sz))
        elif kind == 1:
            off += 4
        elif kind == 6:
            off += 8
        elif kind == 19:
            off += 12
        elif kind == 13:
            off += 8
        elif kind == 3:
            off += 12
        elif kind == 14:
            off += 4
        elif kind == 15:
            off += 12
        elif kind == 17:
            off += 8
        else:
            off += 0
    T.append(ent)

def find(name, kind=None):
    for t in T[1:]:
        if t["name"] == name and (kind is None or t["kind"] == kind):
            return t
    return None

def dump(name, want=None):
    t = find(name)
    if not t:
        print(f"{name}: NOT FOUND")
        return
    print(f"{name}: kind={KIND.get(t['kind'])} size={t['size']:#x} vlen={t['vlen']}")
    for mn, mt, bo, bs in t["members"]:
        if want and mn not in want:
            continue
        print(f"   {mn:28s} off={bo//8:#06x} bit={bo} bitsz={bs} type={mt}")

dump("cred")
dump("k_itimer")
dump("task_struct", {"cred", "real_cred", "pid", "tgid", "comm", "tasks", "thread_pid"})
