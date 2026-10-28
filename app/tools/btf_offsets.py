#!/usr/bin/env python3
"""Dump the struct offsets used by the CVE-2026-98260 Android port.

Usage: btf_offsets.py /tmp/vmlinux-full.btf
The BTF blob can be carved from the raw arm64 Image (search for the 0xeb9f
header and use hdr_len/type_len/str_len from the header).
"""
import struct
import sys


def load(path):
    data = open(path, "rb").read()
    magic, ver, flags, hdr_len, type_off, type_len, str_off, str_len = \
        struct.unpack_from("<HBBIIIII", data, 0)
    if magic != 0xEB9F or ver != 1:
        raise SystemExit("not a BTF blob")
    type_base = hdr_len + type_off
    str_base = hdr_len + str_off
    return data, type_base, type_base + type_len, str_base


def parse(path):
    data, pos, end, str_base = load(path)

    def string(off):
        stop = data.find(b"\0", str_base + off)
        return data[str_base + off:stop].decode("utf-8", "replace")

    types = [None]
    while pos < end:
        name_off, info, size = struct.unpack_from("<III", data, pos)
        pos += 12
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        members = []
        if kind in (4, 5):
            for _ in range(vlen):
                m_name, m_type, m_off = struct.unpack_from("<III", data, pos)
                pos += 12
                members.append((string(m_name), m_type, m_off))
        elif kind == 1:
            pos += 4
        elif kind == 3:
            pos += 12
        elif kind == 6:
            pos += vlen * 8
        elif kind == 13:
            pos += vlen * 8
        elif kind == 14:
            pos += 4
        elif kind == 15:
            pos += vlen * 12
        elif kind == 17:
            pos += 4
        elif kind == 19:
            pos += vlen * 12
        types.append({"name": string(name_off), "kind": kind,
                      "size": size, "members": members})
    return types


def show(types, name, fields=None):
    for index, entry in enumerate(types):
        if not entry or entry["name"] != name or entry["kind"] not in (4, 5):
            continue
        print(f"\n{name} id={index} size={entry['size']:#x}")
        for member, _, offset in entry["members"]:
            if fields is None or any(word in member for word in fields):
                print(f"  {member:30s} {offset // 8:#05x}")
        return
    print(f"\n{name}: not found")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    all_types = parse(sys.argv[1])
    show(all_types, "k_itimer")
    show(all_types, "cpu_timer")
    show(all_types, "posix_cputimers")
    show(all_types, "posix_cputimer_base")
    show(all_types, "task_struct", ["posix", "cred", "comm", "signal"])
    show(all_types, "cred")
    show(all_types, "user_namespace")
    show(all_types, "task_security_struct")
    funcs = {t["name"] for t in all_types if t and t["kind"] == 12}
    for name in ("posixtimer_exec", "posix_cpu_timers_exit", "exit_itimers"):
        print(f"\nfunc {name}: {'present' if name in funcs else 'absent'}")
