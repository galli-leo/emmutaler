#ifndef __STACKTRACE_H
#define __STACKTRACE_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <execinfo.h>
#include <ucontext.h>
#include <signal.h>

#define TRACE_SIZE 16

void catch_segfault (int signal, void *ctx);

#endif /* __STACKTRACE_H */
