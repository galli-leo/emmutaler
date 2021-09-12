#include "signals.h"
#include "signals_list.h"
// #include "stacktrace.h"
// #include <backtrace.h>
// #include <backtrace-supported.h>
#include <execinfo.h>
#include <stdio.h>
#include <unistd.h>
#include "log.h"

struct bt_ctx {
	struct backtrace_state *state;
	int error;
};

#define DEBUG 1

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

    log_error("Received signal %s (%d, %d) @ %p, pc: %p, prev: %p\n", info->name, info->code, si->si_code, fault_addr, pc, lr);
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
#if DEBUG
    // printf("STACKTRACE:\n");
    void* prev_pc = (uint64_t)lr & PTR_MASK;
    print_stacktrace(prev_pc, info_ctx->regs[29]);
    abort();
#endif

    // stacktrace();
    // struct bt_ctx ctx = {state, 0};

    // backtrace_print(ctx.state, 0, stdout);
    // catch_segfault(signo, context);
    exit(1);
}

#include <pthread.h>

pthread_mutex_t stack_trace_lock = PTHREAD_MUTEX_INITIALIZER;

void print_stacktrace(void* prev_pc, void* fp)
{
    pthread_mutex_lock(&stack_trace_lock);
#define LINE_PAD "               "

#ifdef LOG_USE_COLOR
  fprintf(stderr, LINE_PAD "\x1b[90mSTACKTRACE:\x1b[0m\n");
#else
  fprintf(stderr, LINE_PAD "STACKTRACE:\n");
#endif

    
    pthread_t self = pthread_self();
    
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
    /*FILE* addrout = NULL;
    char cmd[0x2000] = {};
    char exeName[0x101] = {};
    size_t res = readlink("/proc/self/exe", exeName, 0x100);*/
    // printf("num_pcs: %d\n", num_pcs);
    char** funcs = backtrace_symbols(addr, num_pcs);
    for (int i = 0; i < num_pcs; i++) {
        symbol_info_t* sym = find_symbol(addr[i]);
        symbol_info_t fake_sym = {0, 0, 0};
        char* finalName = NULL;
        if (sym == NULL) {
            sym = &fake_sym;
            char** funcs = backtrace_symbols(&addr[i], 1);
            if (funcs != NULL){
                fake_sym.name = funcs[0];
                /*
                sprintf(cmd, "addr2line -f -s -e %s 0x%lx", exeName, addr[i]);
                addrout = popen(cmd, "r");
                char* symbolName = NULL;
                size_t len = 0;
                size_t read = getline(&symbolName, &len, addrout);
                if (read == -1) {
                    fake_sym.name = funcs[0];
                    fclose(addrout);
                } else {
                    symbolName[read-1] = 0;
                
                    char* file = NULL;
                    read = getline(&file, &len, addrout);
                    fclose(addrout);

                    if (read == -1) {
                        fake_sym.name = funcs[0];
                        free(symbolName);
                    } else {
                        file[read -1] = 0;
                        finalName = malloc(0x100);

                        sprintf(finalName, "%s -> %s", file, symbolName);

                        free(file);
                        free(symbolName);
                        fake_sym.name = finalName;
                    }
                }*/
            } else {
                fake_sym.name = "unknown";
            }
        }
#ifdef LOG_USE_COLOR
  fprintf(stderr, LINE_PAD "\x1b[90m[0x%016lx]\x1b[0m %s+0x%x\n", addr[i], sym->name, addr[i] - sym->start);
#else
  fprintf(stderr, LINE_PAD "[0x%016lx] %s+0x%x\n", addr[i], sym->name, addr[i] - sym->start);
#endif
        //if (finalName != NULL) free(finalName);
    }
    fprintf(stderr, "\n");
    pthread_mutex_unlock(&stack_trace_lock);
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