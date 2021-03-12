#include "signals.h"
#include "signals_list.h"
// #include "stacktrace.h"
// #include <backtrace.h>
// #include <backtrace-supported.h>
#include <execinfo.h>

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

void callback(void *data, uintptr_t pc, const char *filename, int lineno, const char *function)
{
    printf("%s:%d %s @ %016lx\n", filename, lineno, function, pc);
}

typedef struct frame_info {
    struct frame_info* prev_frame;
    void* prev_pc;
} frame_info_t;

#define BACKTRACE_SIZE 16
#define PTR_MASK 0xffffffffff
// #include <backtrace.h>
#include "symbols_list.h"

symbol_info_t* find_symbol(uint64_t addr)
{
    uint64_t num_symbols = sizeof(symbols) / sizeof(symbol_info_t);
    for (int i = 0; i < num_symbols; i++) {
        symbol_info_t* sym = &symbols[i];
        if (sym->start <= addr && addr < sym->end) {
            return sym;
        }
    }

    return NULL;
}

void sig_handler(int signo, siginfo_t *si, void* arg)
{
    ucontext_t *context = (ucontext_t*)arg;
    mcontext_t *info_ctx = &context->uc_mcontext;
    signal_info_t* info = find_signal(signo);
    void* fault_addr = si->si_addr;
    fault_addr = info_ctx->fault_address;
    void* pc = info_ctx->pc;
    void* lr = info_ctx->regs[30];

    printf("Received signal %s (%d, %d) @ %p, pc: %p, prev: %p\n", info->name, info->code, si->si_code, fault_addr, pc, lr);
    for (int i = 0; i < 32; i++) {
        printf("R%02d: %016lx    ", i, info_ctx->regs[i]);
        if (i % 4 == 3){
            puts("");
        }
    }
    // uint64_t* fp = info_ctx->regs[29];
    // for (int i = -4; i < 4; i++) {
    //     uint64_t* p = fp + i;
    //     printf("%016lx: %016lx\n", p, *p);
    // }
    printf("STACKTRACE:\n");
    void* prev_pc = (uint64_t)lr & PTR_MASK;
    print_stacktrace(prev_pc, info_ctx->regs[29]);

    // stacktrace();
    // struct bt_ctx ctx = {state, 0};

    // backtrace_print(ctx.state, 0, stdout);
    // catch_segfault(signo, context);
    exit(1);
}

void print_stacktrace(void* prev_pc, void* fp)
{
    frame_info_t* prev_frame = fp; // fp
    void* addr[BACKTRACE_SIZE];
    int i = 0;
    // struct backtrace_state *state = backtrace_create_state ("./main", 0, error_callback, NULL);
    for (; i < BACKTRACE_SIZE; i++) {
        addr[i] = prev_pc-4; // bc call!
        prev_frame = prev_frame->prev_frame;
        // backtrace_pcinfo (state, addr[i]-100, callback, error_callback, NULL);
        if ((uint64_t)prev_frame <= 0x400 || (uint64_t)prev_pc <= 0x400) {
            break;
        }
        prev_pc = (uint64_t)prev_frame->prev_pc & PTR_MASK;
    }
    int num_pcs = i+1;
    char** funcs = backtrace_symbols(addr, num_pcs);
    for (int i = 0; i < num_pcs; i++) {
        symbol_info_t* sym = find_symbol(addr[i]);
        symbol_info_t fake_sym = {0, 0, 0};
        if (sym == NULL) {
            sym = &fake_sym;
            char** funcs = backtrace_symbols(&addr[i], 1);
            if (funcs != NULL){
                // printf("WTF???? %p\n", funcs);
                fake_sym.name = funcs[0];
            } else {
                fake_sym.name = "unknown";
            }
        }
        printf("[0x%016lx] %s+0x%x\n", addr[i], sym->name, addr[i] - sym->start);
    }
}

void install_signal_handler()
{
#define DEBUG 1
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