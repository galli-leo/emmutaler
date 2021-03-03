#include "signals.h"
#include "signals_list.h"
#include "stacktrace.h"
#include <backtrace.h>
#include <backtrace-supported.h>

struct bt_ctx {
	struct backtrace_state *state;
	int error;
};


signal_info_t* find_signal(int signo)
{
    int num_signals = sizeof(sig_infos) / sizeof(sig_infos[0]);
    for (int i = 0; i < num_signals; i++) {
        signal_info_t info = sig_infos[i];
        if (info.code == signo) {
            return &sig_infos[i];
        }
    }

    return NULL;
}

static void error_callback(void *data, const char *msg, int errnum)
{
	struct bt_ctx *ctx = data;
	fprintf(stderr, "ERROR: %s (%d)", msg, errnum);
	ctx->error = 1;
}


void sig_handler(int signo, siginfo_t *si, void* arg)
{
    ucontext_t *context = (ucontext_t*)arg;
    mcontext_t *info_ctx = &context->uc_mcontext;
    signal_info_t* info = find_signal(signo);
    void* fault_addr = info_ctx->fault_address;
    void* pc = info_ctx->pc;

    printf("Received signal %s (%d) @ %p, pc: %p (lr: %p, x0: %p)\n", info->name, info->code, fault_addr, pc, info_ctx->regs[29], info_ctx->regs[0]);
    // stacktrace();
    struct backtrace_state *state = backtrace_create_state ("./main", 0, error_callback, NULL);
    struct bt_ctx ctx = {state, 0};
    backtrace_print(ctx.state, 0, stdout);
    catch_segfault(signo, context);
    exit(1);
}

void install_signal_handler()
{
#if DEBUG
    struct sigaction act;
    act.sa_sigaction = &sig_handler;
    act.sa_flags |= SA_SIGINFO;
    sigemptyset(&act.sa_mask);

    int num_signals = sizeof(sig_infos) / sizeof(sig_infos[0]);

    for (int i = 0; i < num_signals; i++) {
        signal_info_t info = sig_infos[i];
        sigaction(info.code, &act, 0);
    }

#endif
}