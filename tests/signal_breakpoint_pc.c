/* 双架构 musl 用户态回归：验证断点地址、恢复 PC 和 sigreturn。 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <ucontext.h>
#include <unistd.h>

extern const char breakpoint[], resume[];
static volatile sig_atomic_t delivered;

static void on_break(int sig, siginfo_t *info, void *context) {
    ucontext_t *uc = context;
#ifdef __loongarch__
    unsigned long *pc = &uc->uc_mcontext.__pc;
#else
    unsigned long *pc = &uc->uc_mcontext.__gregs[0];
#endif
    if (sig != SIGTRAP || info->si_code != TRAP_BRKPT ||
        (uintptr_t)info->si_addr != (uintptr_t)breakpoint || *pc != (uintptr_t)breakpoint)
        _exit(1);
    delivered++;
    *pc = (uintptr_t)resume;
}

int main(void) {
    struct sigaction action = {.sa_sigaction = on_break, .sa_flags = SA_SIGINFO};
    if (sigaction(SIGTRAP, &action, NULL) != 0)
        return 2;
    __asm__ volatile(
        ".balign 4\n.globl breakpoint\nbreakpoint:\n"
#ifdef __loongarch__
        "break 0\n"
#else
        ".4byte 0x00100073\n"
#endif
        ".globl resume\nresume:" ::: "memory");
    if (delivered != 1)
        return 3;
    puts("breakpoint signal return regression passed");
    return 0;
}
