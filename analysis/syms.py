#!/usr/bin/env python3
"""Parse symbols out of a reconstructed vmlinux ELF (no external tools)."""
import struct
import sys


def load_syms(path):
    d = open(path, 'rb').read()
    assert d[:4] == b'\x7fELF', 'not an ELF'
    is64 = d[4] == 2
    assert is64, 'expect ELF64'
    e_shoff = struct.unpack_from('<Q', d, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', d, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', d, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', d, 0x3E)[0]

    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (name, typ, flags, addr, offset, size, link, info, align,
         entsize) = struct.unpack_from('<IIQQQQIIQQ', d, off)
        secs.append(dict(name=name, typ=typ, addr=addr, offset=offset,
                         size=size, link=link, entsize=entsize))

    shstr = secs[e_shstrndx]
    base = shstr['offset']

    def sname(o):
        s = base + o
        return d[s:d.index(b'\0', s)].decode('latin-1')

    for s in secs:
        s['sname'] = sname(s['name'])

    symtab = next((s for s in secs if s['typ'] == 2), None)  # SHT_SYMTAB
    if symtab is None:
        raise SystemExit('no SHT_SYMTAB')
    strtab = secs[symtab['link']]

    syms = []
    n = symtab['size'] // 24
    for i in range(n):
        off = symtab['offset'] + i * 24
        st_name, st_info, st_other, st_shndx, st_value, st_size = \
            struct.unpack_from('<IBBHQQ', d, off)
        so = strtab['offset'] + st_name
        nm = d[so:d.index(b'\0', so)].decode('latin-1')
        if not nm:
            continue
        typ = st_info & 0xF
        syms.append((st_value, typ, nm, st_shndx))
    return secs, syms


TYPEMAP = {0: 'NOTYPE', 1: 'OBJECT', 2: 'FUNC', 3: 'SECTION', 4: 'FILE',
           5: 'COMMON', 6: 'TLS', 10: 'IFUNC'}

if __name__ == '__main__':
    path = sys.argv[1]
    secs, syms = load_syms(path)
    print('# sections:')
    for s in secs:
        print(f"#  {s['sname']:<20} type={s['typ']} addr=0x{s['addr']:016x} "
              f"size=0x{s['size']:x} entsize={s['entsize']}")
    print(f'# symbols: {len(syms)}')
    want = ['_text', '_stext', 'init_task', 'init_cred', 'selinux_state',
            'ashmem_ioctl', 'kallsyms_relative_base', 'kallsyms_num_syms']
    byname = {}
    for v, t, n, sh in syms:
        byname.setdefault(n.split('$')[0], (v, t, sh))
    for w in want:
        if w in byname:
            v, t, sh = byname[w]
            print(f'{w}: 0x{v:016x} {TYPEMAP.get(t, t)} shndx={sh}')
        else:
            print(f'{w}: MISSING')
    if len(sys.argv) > 2 and sys.argv[2] == '--dump':
        out = sys.argv[3]
        with open(out, 'w') as f:
            for v, t, n, sh in syms:
                if v == 0:
                    continue
                f.write(f'{v:016x} {TYPEMAP.get(t, t)} {n}\n')
        print('wrote', out)
