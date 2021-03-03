#ifndef __SIGNALS_H
#define __SIGNALS_H

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <ucontext.h>
#include <stdlib.h>
#include <stdint.h>
#include "config.h"

// ^\s*(\w*)\s*[\w-]*\s*\w*\s*([\w ();:\/,.-]*)(\n\s*(([\w();:\/.-] ?)+))?$

typedef struct signal_info
{
    char* name;
    int code;
    char* description;
} signal_info_t;


#define SIG(name, desc) {#name, name, desc}, 

/**
 * 
 * @brief Installs a signal handler around all signals.
 * It will print a hopefully informative stack trace and information on the signal.
 * THIS IS A NOP IN RELEASE BUILDS.
 * 
 */
void install_signal_handler();

#endif /* __SIGNALS_H */