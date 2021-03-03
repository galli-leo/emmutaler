/* Catch segmentation faults and print backtrace.
   Copyright (C) 1998-2021 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1998.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include <alloca.h>
#include <ctype.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
// #include <_itoa.h>
// #include <ldsodefs.h>

/* This file defines macros to access the content of the sigcontext element
   passed up by the signal handler.  */
#include "sigcontextinfo.h"

#ifdef SA_SIGINFO
# define SIGCONTEXT siginfo_t *info, void *
#endif

/* Get code to possibly dump the content of all registers.  */
#include "register-dump.h"

/* We'll use this a lot.  */
#define WRITE_STRING(s) write (fd, s, strlen (s))

/* Name of the output file.  */
static const char *fname;


/* Print the signal number SIGNAL.  Either strerror or strsignal might
   call local internal functions and these in turn call far too many
   other functions and might even allocate memory which might fail.  */
static void
write_strsignal (int fd, int signal)
{
  char buf[30];
  char *ptr = _itoa_word (signal, &buf[sizeof (buf)], 10, 0);
  WRITE_STRING ("signal ");
  write (fd, ptr, &buf[sizeof (buf)] - ptr);
}


/* This function is called when a segmentation fault is caught.  The system
   is in an unstable state now.  This means especially that malloc() might
   not work anymore.  */
void
catch_segfault (int signal, void* ctx)
{
  int fd, cnt, i;
  void **arr;
  struct sigaction sa;
  uintptr_t pc;

  /* This is the name of the file we are writing to.  If none is given
     or we cannot write to this file write to stderr.  */
  fd = 2;
  if (fname != NULL)
    {
      fd = open (fname, O_TRUNC | O_WRONLY | O_CREAT, 0666);
      if (fd == -1)
	fd = 2;
    }

  WRITE_STRING ("*** ");
  write_strsignal (fd, signal);
  WRITE_STRING ("\n");

#ifdef REGISTER_DUMP
  REGISTER_DUMP;
#endif

  WRITE_STRING ("\nBacktrace:\n");

  /* Get the backtrace.  */
  arr = alloca (256 * sizeof (void *));
  cnt = backtrace (arr, 256);

  /* Now try to locate the PC from signal context in the backtrace.
     Normally it will be found at arr[2], but it might appear later
     if there were some signal handler wrappers.  Allow a few bytes
     difference to cope with as many arches as possible.  */
  pc = sigcontext_get_pc (ctx);
  for (i = 0; i < cnt; ++i)
    if ((uintptr_t) arr[i] >= pc - 16 && (uintptr_t) arr[i] <= pc + 16)
      break;

  /* If we haven't found it, better dump full backtrace even including
     the signal handler frames instead of not dumping anything.  */
  if (i == cnt)
    i = 0;

  /* Now generate nicely formatted output.  */
  backtrace_symbols_fd (arr + i, cnt - i, fd);

#ifdef HAVE_PROC_SELF
  /* Now the link map.  */
  int mapfd = open ("/proc/self/maps", O_RDONLY);
  if (mapfd != -1)
    {
      write (fd, "\nMemory map:\n\n", 14);

      char buf[256];
      ssize_t n;

      while ((n = TEMP_FAILURE_RETRY (read (mapfd, buf, sizeof (buf)))) > 0)
	TEMP_FAILURE_RETRY (write (fd, buf, n));

      close (mapfd);
    }
#endif
}