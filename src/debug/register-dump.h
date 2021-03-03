/* Dump registers.
   Copyright (C) 1998-2021 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Philip Blundell <pb@nexus.co.uk>, 1998.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library.  If not, see
   <https://www.gnu.org/licenses/>.  */

#include <sys/uio.h>
// #include <_itoa.h>
#include <sys/ucontext.h>

#ifndef _ITOA_WORD_TYPE
# define _ITOA_WORD_TYPE	unsigned long int
#endif

const char _itoa_upper_digits[36]
	= "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const char _itoa_lower_digits[36]
	= "0123456789abcdefghijklmnopqrstuvwxyz";

char *
_itoa_word (_ITOA_WORD_TYPE value, char *buflim,
	    unsigned int base, int upper_case)
{
  const char *digits = (upper_case
			? _itoa_upper_digits
			: _itoa_lower_digits);

  switch (base)
    {
#define SPECIAL(Base)							      \
    case Base:								      \
      do								      \
	*--buflim = digits[value % Base];				      \
      while ((value /= Base) != 0);					      \
      break

      SPECIAL (10);
      SPECIAL (16);
      SPECIAL (8);
    default:
      do
	*--buflim = digits[value % base];
      while ((value /= base) != 0);
    }
  return buflim;
}
#undef SPECIAL

/* We will print the register dump in this format:

 R0: XXXXXXXX   R1: XXXXXXXX   R2: XXXXXXXX   R3: XXXXXXXX
 R4: XXXXXXXX   R5: XXXXXXXX   R6: XXXXXXXX   R7: XXXXXXXX
 R8: XXXXXXXX   R9: XXXXXXXX   SL: XXXXXXXX   FP: XXXXXXXX
 IP: XXXXXXXX   SP: XXXXXXXX   LR: XXXXXXXX   PC: XXXXXXXX

 CPSR: XXXXXXXX

 Trap: XXXXXXXX   Error: XXXXXXXX   OldMask: XXXXXXXX
 Addr: XXXXXXXX

 */

static void
hexvalue (unsigned long int value, char *buf, size_t len)
{
  char *cp = _itoa_word (value, buf + len, 16, 0);
  while (cp > buf)
    *--cp = '0';
}

static void
register_dump (int fd, const ucontext_t *ctx)
{
  char regs[35][16];
  struct iovec iov[97];
  size_t nr = 0;

#define ADD_STRING(str) \
  iov[nr].iov_base = (char *) str;					      \
  iov[nr].iov_len = strlen (str);					      \
  ++nr
#define ADD_MEM(str, len) \
  iov[nr].iov_base = str;						      \
  iov[nr].iov_len = 16;						      \
  ++nr
#define GEN_REG(idx) hexvalue (ctx->uc_mcontext.regs[idx], regs[idx], 16)

  GEN_REG(0);
  GEN_REG(1);
  GEN_REG(2);
  GEN_REG(3);
  GEN_REG(4);
  GEN_REG(5);
  GEN_REG(6);
  GEN_REG(7);
  GEN_REG(8);
  GEN_REG(9);
  GEN_REG(10);
  GEN_REG(11);
  GEN_REG(12);
  GEN_REG(13);
  GEN_REG(14);
  GEN_REG(15);
  GEN_REG(16);
  GEN_REG(17);
  GEN_REG(18);
  GEN_REG(19);
  GEN_REG(20);
  GEN_REG(21);
  GEN_REG(22);
  GEN_REG(23);
  GEN_REG(24);
  GEN_REG(25);
  GEN_REG(26);
  GEN_REG(27);
  GEN_REG(28);
  GEN_REG(29);
  GEN_REG(30);
  hexvalue(ctx->uc_mcontext.sp, regs[31], 16);
  hexvalue(ctx->uc_mcontext.pc, regs[32], 16);
  hexvalue(ctx->uc_mcontext.pstate, regs[33], 16);
  hexvalue(ctx->uc_mcontext.fault_address, regs[34], 16);

#define ADD_REG(num) ADD_STRING("   R" #num ": "); \
  ADD_MEM (regs[num], 16)

  /* Generate the output.  */
  ADD_STRING ("Register dump:\n\n R0: ");
  ADD_MEM (regs[0], 16);
  ADD_REG(1);
  ADD_REG(2);
  ADD_REG(3);
  ADD_STRING("\n");
  ADD_REG(4);
  ADD_REG(5);
  ADD_REG(6);
  ADD_REG(7);
  ADD_STRING("\n");
  ADD_REG(8);
  ADD_REG(9);
  ADD_REG(10);
  ADD_REG(11);
  ADD_STRING("\n");
  ADD_REG(12);
  ADD_REG(13);
  ADD_REG(14);
  ADD_REG(15);
  ADD_STRING("\n");
  ADD_REG(16);
  ADD_REG(17);
  ADD_REG(18);
  ADD_REG(19);
  ADD_STRING("\n");
  ADD_REG(20);
  ADD_REG(21);
  ADD_REG(22);
  ADD_REG(23);
  ADD_STRING("\n");
  ADD_REG(24);
  ADD_REG(25);
  ADD_REG(26);
  ADD_REG(27);
  ADD_STRING("\n");
  ADD_REG(28);
  ADD_STRING ("   FP: ");
  ADD_MEM (regs[29], 16);
  ADD_STRING ("   LR: ");
  ADD_MEM (regs[30], 16);
  ADD_STRING ("   SP: ");
  ADD_MEM (regs[31], 16);
  ADD_STRING ("   PC: ");
  ADD_MEM (regs[32], 16);
  ADD_STRING ("\n Addr: ");
  ADD_MEM (regs[34], 16);

  ADD_STRING ("\n");

  /* Write the stuff out.  */
  writev (fd, iov, nr);
}


#define REGISTER_DUMP register_dump (fd, ctx)
