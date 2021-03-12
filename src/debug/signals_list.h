#ifndef __SIGNALS_LIST_H
#define __SIGNALS_LIST_H
#include "signals.h"

static signal_info_t sig_infos[] = {

SIG(SIGABRT, "Abort signal from abort(3)")
SIG(SIGALRM, "Timer signal from alarm(2)")
SIG(SIGBUS, "Bus error (bad memory access)")
SIG(SIGCHLD, "Child stopped or terminated")
// SIG(SIGCLD, "A synonym for SIGCHLD")
SIG(SIGCONT, "Continue if stopped")
SIG(SIGFPE, "Floating-point exception")
SIG(SIGHUP, "Hangup detected on controlling terminalor death of controlling processs")
SIG(SIGILL, "Illegal Instruction")
SIG(SIGINT, "Interrupt from keyboard")
SIG(SIGIO, "I/O now possible (4.2BSD)")
SIG(SIGIOT, "IOT trap. A synonym for SIGABRT")
SIG(SIGKILL, "Kill signal")
SIG(SIGPIPE, "Broken pipe: write to pipe with noreaders; see pipe(7))")
// SIG(SIGPOLL, "Pollable event (Sys V);synonym for SIGIOO")
SIG(SIGPROF, "Profiling timer expired")
// SIG(SIGPWR, "Power failure (System V)")
SIG(SIGQUIT, "Quit from keyboard")
SIG(SIGSEGV, "Invalid memory reference")
// SIG(SIGSTKFLT, "Stack fault on coprocessor (unused)")
SIG(SIGSTOP, "Stop process")
SIG(SIGTSTP, "Stop typed at terminal")
SIG(SIGSYS, "Bad system call (SVr4);see also seccomp(2))")
SIG(SIGTERM, "Termination signal")
SIG(SIGTRAP, "Trace/breakpoint trap")
SIG(SIGTTIN, "Terminal input for background process")
SIG(SIGTTOU, "Terminal output for background process")
SIG(SIGURG, "Urgent condition on socket (4.2BSD)")
SIG(SIGUSR1, "User-defined signal 1")
SIG(SIGUSR2, "User-defined signal 2")
SIG(SIGVTALRM, "Virtual alarm clock (4.2BSD)")
SIG(SIGXCPU, "CPU time limit exceeded (4.2BSD);see setrlimit(2))")
SIG(SIGXFSZ, "File size limit exceeded (4.2BSD);see setrlimit(2))")
SIG(SIGWINCH, "Window resize signal (4.3BSD, Sun)")

};

#endif /* __SIGNALS_LIST_H */
