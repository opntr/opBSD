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


#ifndef	__X86_SELFPATCH_ASMACROS_H__
#define	__X86_SELFPATCH_ASMACROS_H__

#ifdef _KERNEL
#include "opt_cpu.h"
#endif

#define KSP_CPUID		1
#define KSP_CPUID2		2
#define KSP_AMDID		3
#define KSP_AMDID2		4
#define KSP_CPUID_STDEXT	5
#define KSP_VIA_CPUID		6
#define KSP_VIA_CRYPT_CWLO	7
#define KSP_CPUID_EXTSTATE	8

/*
 * Intel Instruction Set Reference M-Z
 * Table 4-12. recommended Multi-Byte Sequeance of NOP Instruction
 */
#define	KSP_INSTR_INTEL_NOP1	.byte 0x90
#define	KSP_INSTR_INTEL_NOP2	.byte 0x66,0x90
#define	KSP_INSTR_INTEL_NOP3	.byte 0x0f,0x1f,0x00
#define	KSP_INSTR_INTEL_NOP4	.byte 0x0f,0x1f,0x40,0x00
#define	KSP_INSTR_INTEL_NOP5	.byte 0x0f,0x1f,0x44,0x00,0x00
#define	KSP_INSTR_INTEL_NOP6	.byte 0x66,0x0f,0x1f,0x44,0x00,0x00
#define	KSP_INSTR_INTEL_NOP7	.byte 0x0f,0x1f,0x80,0x00,0x00,0x00,0x00
#define	KSP_INSTR_INTEL_NOP8	.byte 0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00
#define	KSP_INSTR_INTEL_NOP9	.byte 0x66,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00

#define	KSP_INSTR_NOP1	KSP_INSTR_INTEL_NOP1
#define	KSP_INSTR_NOP2	KSP_INSTR_INTEL_NOP2
#define	KSP_INSTR_NOP3	KSP_INSTR_INTEL_NOP3
#define	KSP_INSTR_NOP4	KSP_INSTR_INTEL_NOP4
#define	KSP_INSTR_NOP5	KSP_INSTR_INTEL_NOP5
#define	KSP_INSTR_NOP6	KSP_INSTR_INTEL_NOP6
#define	KSP_INSTR_NOP7	KSP_INSTR_INTEL_NOP7
#define	KSP_INSTR_NOP8	KSP_INSTR_INTEL_NOP8
#define	KSP_INSTR_NOP9	KSP_INSTR_INTEL_NOP9

/*
 * stringified version needed by C sources, because __STRING and __XSTRING failed
 */
#define	KSP_INSTR_INTEL_NOP1_C	".byte 0x90"
#define	KSP_INSTR_INTEL_NOP2_C	".byte 0x66,0x90"
#define	KSP_INSTR_INTEL_NOP3_C	".byte 0x0f,0x1f,0x00"
#define	KSP_INSTR_INTEL_NOP4_C	".byte 0x0f,0x1f,0x40,0x00"
#define	KSP_INSTR_INTEL_NOP5_C	".byte 0x0f,0x1f,0x44,0x00,0x00"
#define	KSP_INSTR_INTEL_NOP6_C	".byte 0x66,0x0f,0x1f,0x44,0x00,0x00"
#define	KSP_INSTR_INTEL_NOP7_C	".byte 0x0f,0x1f,0x80,0x00,0x00,0x00,0x00"
#define	KSP_INSTR_INTEL_NOP8_C	".byte 0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00"
#define	KSP_INSTR_INTEL_NOP9_C	".byte 0x66,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00"

#define	KSP_INSTR_NOP1_C	KSP_INSTR_INTEL_NOP1_C
#define	KSP_INSTR_NOP2_C	KSP_INSTR_INTEL_NOP2_C
#define	KSP_INSTR_NOP3_C	KSP_INSTR_INTEL_NOP3_C
#define	KSP_INSTR_NOP4_C	KSP_INSTR_INTEL_NOP4_C
#define	KSP_INSTR_NOP5_C	KSP_INSTR_INTEL_NOP5_C
#define	KSP_INSTR_NOP6_C	KSP_INSTR_INTEL_NOP6_C
#define	KSP_INSTR_NOP7_C	KSP_INSTR_INTEL_NOP7_C
#define	KSP_INSTR_NOP8_C	KSP_INSTR_INTEL_NOP8_C
#define	KSP_INSTR_NOP9_C	KSP_INSTR_INTEL_NOP9_C

#define	KSP_MAX_NOPLEN		9

#define KSP_INSTR_XSAVE_XSAVEOPT(_ARG)					\
	0723: 								\
		xsave ( _ARG ) ;					\
	0724: 								\
		.pushsection set_selfpatch_patch_set, "ax" ; 		\
	0725: 								\
		xsaveopt ( _ARG ) ;					\
	0726: 								\
		.popsection 						\
		.pushsection set_selfpatch_set, "a" ; 			\
			.quad   0723b ; 				\
			.quad   0725b ; 				\
			.int    0724b-0723b ; 				\
			.int    0726b-0725b ; 				\
			.int    KSP_CPUID_EXTSTATE ; 			\
			.int    CPUID_EXTSTATE_XSAVEOPT ; 		\
			.quad	0 ; 					\
		.popsection ;

#ifndef _xsave_xsaveopt
#define _xsave_xsaveopt(_ARG) KSP_INSTR_XSAVE_XSAVEOPT(_ARG)
#endif

#define KSP_INSTR_NOP3_CLAC						\
	0723: 								\
		KSP_INSTR_NOP3 ; 					\
	0724: 								\
		.pushsection set_selfpatch_patch_set, "ax" ; 		\
	0725: 								\
		clac ;							\
	0726: 								\
		.popsection 						\
		.pushsection set_selfpatch_set, "a" ; 			\
			.quad   0723b ; 				\
			.quad   0725b ; 				\
			.int    0724b-0723b ; 				\
			.int    0726b-0725b ; 				\
			.int    KSP_CPUID_STDEXT ; 			\
			.int    CPUID_STDEXT_SMAP ; 			\
			.quad	0 ; 					\
		.popsection ;

#ifdef INTEL_SMAP_SUPPORT
#ifndef	_clac
#define _clac	KSP_INSTR_NOP3_CLAC
#endif
#else
#ifndef _clac
#define _clac
#endif
#endif

#define KSP_INSTR_NOP3_STAC						\
	0723: 								\
		KSP_INSTR_NOP3 ; 					\
	0724: 								\
		.pushsection set_selfpatch_patch_set, "ax" ; 		\
	0725: 								\
		stac ; 							\
	0726: 								\
		.popsection 						\
		.pushsection set_selfpatch_set, "a" ; 			\
			.quad   0723b ; 				\
			.quad   0725b ; 				\
			.int    0724b-0723b ; 				\
			.int    0726b-0725b ; 				\
			.int    KSP_CPUID_STDEXT ;			\
			.int    CPUID_STDEXT_SMAP ; 			\
			.quad	0 ; 					\
		.popsection ;

#ifdef INTEL_SMAP_SUPPORT
#ifndef _stac
#define _stac	KSP_INSTR_NOP3_STAC
#endif
#else
#ifndef _stac
#define _stac
#endif
#endif

#endif /* __X86_SELFPATCH_ASMACROS_H__ */
