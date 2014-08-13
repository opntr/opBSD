/*-
 * Copyright (c) 2014, by Oliver Pinter <oliver.pntr at gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/linker.h>
#include <sys/linker_set.h>
#include <sys/selfpatch.h>

#include <machine/md_var.h>
#include <machine/specialreg.h>

const struct ksp_selector_entry ksp_selector_table[] = {
	/* feature_selector	feature pointer */
	{KSP_CPUID,		&cpu_feature},
	{KSP_CPUID2,		&cpu_feature2},
	{KSP_AMDID,		&amd_feature},
	{KSP_AMDID2,		&amd_feature2},
	{KSP_CPUID_STDEXT,	&cpu_stdext_feature},
	{KSP_VIA_CPUID,		&via_feature_rng},
	{KSP_VIA_CRYPT_CWLO,	&via_feature_xcrypt},
	{KSP_CPUID_EXTSTATE,	&cpu_extstate},

	KSP_SELECTOR_END
};

/*
 * assembly NOP store
 */
extern const char       nop1;
extern const char       nop2;
extern const char       nop3;
extern const char       nop4;
extern const char       nop5;
extern const char       nop6;
extern const char       nop7;
extern const char       nop8;
extern const char       nop9;

const char *selfpatch_nop_table[] = {
	[0] = (const char *)NULL,
	[1] = (const char *)&nop1,
	[2] = (const char *)&nop2,
	[3] = (const char *)&nop3,
	[4] = (const char *)&nop4,
	[5] = (const char *)&nop5,
	[6] = (const char *)&nop6,
	[7] = (const char *)&nop7,
	[8] = (const char *)&nop8,
	[9] = (const char *)&nop9
};

__asm(
"nop1:                          \n"
"      " KSP_INSTR_NOP1_C "	\n"
"nop2:                          \n"
"      " KSP_INSTR_NOP2_C "	\n"
"nop3:                          \n"
"      " KSP_INSTR_NOP3_C "	\n"
"nop4:                          \n"
"      " KSP_INSTR_NOP4_C "	\n"
"nop5:                          \n"
"      " KSP_INSTR_NOP5_C "	\n"
"nop6:                          \n"
"      " KSP_INSTR_NOP6_C "	\n"
"nop7:                          \n"
"      " KSP_INSTR_NOP7_C "	\n"
"nop8:                          \n"
"      " KSP_INSTR_NOP8_C "	\n"
"nop9:                          \n"
"      " KSP_INSTR_NOP9_C "	\n"
"	.p2align 4,0x90		\n"
);

