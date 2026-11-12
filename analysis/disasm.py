#!/usr/bin/env python3
"""Disassemble a symbol from analysis/vmlinux with capstone (arm64)."""
import sys

sys.path.insert(0, r'C:\Users\walleo\Downloads\GhostLock-HonorFne\analysis')
from syms import load_syms

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG

VMLINUX = r'C:\Users\walleo\Downloads\GhostLock-HonorFne\analysis\vmlinux'


def main():
    secs, syms = load_syms(VMLINUX)
    blob = open(VMLINUX, 'rb').read()
    load = [s for s in secs if s['typ'] == 1 and s['addr']]
    name = sys.argv[1]
    want_off = [int(x, 0) for x in sys.argv[2:]]

    hits = [s for s in syms if s[2].split('$')[0] == name]
    if not hits:
        print('symbol not found:', name)
        return
    va, typ, full, sh = min(hits, key=lambda h: h[0])
    print(f'{full} @ {va:#x} (type {typ})')

    def read_va(a, n):
        for s in load:
            if s['addr'] <= a < s['addr'] + s['size']:
                o = s['offset'] + (a - s['addr'])
                return blob[o:o + n]
        return b''

    data = read_va(va, 0x1200)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    n = 0
    for ins in md.disasm(data, va):
        if n > 400:
            break
        n += 1
        note = ''
        for op in ins.operands:
            if op.type == ARM64_OP_MEM and op.mem.disp in want_off:
                note = f'   <== disp {op.mem.disp:#x}'
        print(f'{ins.address:016x}: {ins.mnemonic:<8} {ins.op_str}{note}')
        if ins.mnemonic == 'ret' and n > 8:
            break


if __name__ == '__main__':
    main()
