#!/usr/bin/env python3
"""Compute GhostLock kernel_offsets fields from analysis/vmlinux + analysis/kernel."""
import struct
import sys

sys.path.insert(0, r'C:\Users\walleo\Downloads\GhostLock-HonorFne\analysis')
from syms import load_syms

VMLINUX = r'C:\Users\walleo\Downloads\GhostLock-HonorFne\analysis\vmlinux'
KERNEL = r'C:\Users\walleo\Downloads\GhostLock-HonorFne\analysis\kernel'

WANT = [
    'init_task', 'init_cred', 'init_uts_ns', 'empty_zero_page',
    'root_task_group', 'selinux_state', 'sig_enforce', 'kptr_restrict',
    'selinux_blob_sizes', 'security_hook_heads', 'kmalloc_caches',
    'anon_pipe_buf_ops', 'ashmem_misc', 'ashmem_fops', 'ashmem_ioctl',
    'ashmem_mmap', 'ashmem_open', 'ashmem_release', 'ashmem_show_fdinfo',
    'configfs_read_file', 'configfs_write_bin_file', 'copy_splice_read',
    'default_file_splice_read', 'noop_llseek', 'nfulnl_logger', 'loggers',
    'system_unbound_wq', 'call_usermodehelper_exec_work', '_text',
    'security_hook_active_capable_0', 'security_hook_active_capable',
]


def main():
    secs, syms = load_syms(VMLINUX)
    table = {}
    for v, t, n, sh in syms:
        key = n.split('$')[0]
        if key not in table or v < table[key][0]:
            table[key] = (v, t, n)

    base = table['_text'][0]
    print(f'# _text = {base:#x}')

    def off(name):
        if name not in table:
            return None
        return table[name][0] - base

    missing = []
    out = {}
    for n in WANT:
        o = off(n)
        if o is None:
            missing.append(n)
        out[n] = o

    for n in missing:
        print(f'# MISSING: {n}')

    # boot_id bss scan
    kernel = open(KERNEL, 'rb').read()
    img_end = base + len(kernel)

    def find_boot_id():
        start = 0
        while True:
            f = kernel.find(b'boot_id\x00', start)
            if f < 0:
                return None
            start = f + 1
            str_va = base + f
            pat = struct.pack('<Q', str_va)
            g = 0
            while True:
                g = kernel.find(pat, g)
                if g < 0:
                    break
                vd = struct.unpack_from('<Q', kernel, g + 0x18)[0]
                if img_end <= vd < base + 0x20000000:
                    return vd - base
                g += 1
        return None

    bid = find_boot_id()
    print(f'# boot_id -> {bid if bid is None else hex(bid)}')

    fields = []
    fields.append(('off_init_task', out['init_task']))
    fields.append(('off_init_cred', out['init_cred']))
    fields.append(('off_init_uts_ns', out['init_uts_ns']))
    fields.append(('off_empty_zero_page', out['empty_zero_page']))
    fields.append(('off_root_task_group', out['root_task_group']))
    fields.append(('off_selinux_enforcing',
                   None if out['selinux_state'] is None else out['selinux_state'] + 1))
    fields.append(('off_sig_enforce', out['sig_enforce']))
    fields.append(('off_kptr_restrict', out['kptr_restrict']))
    fields.append(('off_selinux_blob_sizes', out['selinux_blob_sizes']))
    fields.append(('off_security_hook_heads', out['security_hook_heads']))
    fields.append(('off_kmalloc_caches', out['kmalloc_caches']))
    fields.append(('off_anon_pipe_buf_ops', out['anon_pipe_buf_ops']))
    fields.append(('off_ashmem_misc_fops', out['ashmem_misc']))
    fields.append(('off_ashmem_fops', out['ashmem_fops']))
    fields.append(('off_ashmem_ioctl', out['ashmem_ioctl']))
    fields.append(('off_ashmem_compat_ioctl', out['ashmem_ioctl']))
    fields.append(('off_ashmem_mmap', out['ashmem_mmap']))
    fields.append(('off_ashmem_open', out['ashmem_open']))
    fields.append(('off_ashmem_release', out['ashmem_release']))
    fields.append(('off_ashmem_show_fdinfo', out['ashmem_show_fdinfo']))
    fields.append(('off_configfs_read_iter', out['configfs_read_file']))
    fields.append(('off_configfs_bin_write_iter', out['configfs_write_bin_file']))
    fields.append(('off_copy_splice_read',
                   out['copy_splice_read'] if out['copy_splice_read'] is not None
                   else out['default_file_splice_read']))
    fields.append(('off_noop_llseek', out['noop_llseek']))
    fields.append(('off_cap_capable_active', 0))
    fields.append(('off_slide_nfulnl_logger', out['nfulnl_logger']))
    fields.append(('off_slide_loggers_0_1',
                   None if out['loggers'] is None else out['loggers'] + 0x10))
    fields.append(('off_slide_boot_id', bid))
    fields.append(('off_system_unbound_wq', out['system_unbound_wq']))
    fields.append(('off_call_usermodehelper_exec_work',
                   out['call_usermodehelper_exec_work']))

    print()
    for k, v in fields:
        print(f'  .{k}=' + ('/* MISSING */,' if v is None else f'0x{v:08X},'))

    print('\n# extra:')
    for n in ['security_hook_active_capable_0', 'sig_enforce', 'loggers',
              'nfulnl_logger', 'ashmem_misc', 'ashmem_fops']:
        print(f'#   {n} = ' + ('MISSING' if out.get(n) is None else f'{out[n]:#x}'))


if __name__ == '__main__':
    main()
