#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <ucontext.h>
#include <string.h>
#include <stdint.h>

void sig_handler(int signo, siginfo_t *si, void* arg)
{
    ucontext_t *context = (ucontext_t*)arg;
    mcontext_t *info_ctx = &context->uc_mcontext;
    void* fault_addr = si->si_addr;
    fault_addr = info_ctx->fault_address;
    void* pc = info_ctx->pc;

    printf("Received signal (%d, %d) @ %p, pc: %p\n", si->si_signo, si->si_code, fault_addr, pc);
    for (int i = 0; i < 32; i++) {
        printf("R%02d: %016x    ", i, info_ctx->regs[i]);
        if ((i % 4) == 3){
            puts("\n");
        }
    }
    // stacktrace();
    // struct backtrace_state *state = backtrace_create_state ("./main", 0, error_callback, NULL);
    // struct bt_ctx ctx = {state, 0};
    // backtrace_print(ctx.state, 0, stdout);
    // catch_segfault(signo, context);
    exit(1);
}

void install_signal_handler()
{
    struct sigaction act;
    // memset(&act, 0, sizeof(act));
    act.sa_sigaction = &sig_handler;
    act.sa_flags |= SA_SIGINFO;
    sigemptyset(&act.sa_mask);

    sigaction(SIGSEGV, &act, 0);
}

void vbar_el1_handler(uint64_t addr)
{
    printf("Handling vbar_el1_here, exception vector base is %p\n", addr);
}

void arch_cpu_init_handler()
{
    printf("Pretending to do arch_cpu_init here...\n");
}

extern void buggy(void* address);

int main() {
    install_signal_handler();
    printf("HAHA GOTTA CRASH FAST\n");
    buggy(0x2000010001d760);
    void (*foo)(void) = (void (*)())0x2000010001d760;
    foo();
}