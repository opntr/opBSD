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

#ifndef __SELFPATH_H__
#define __SELFPATH_H__

#include <machine/selfpatch-asmacros.h>

#define KSP_SELFTEST		0
#define KSP_FEATURE_SELFTEST	1

#include <machine/selfpatch-machdep.h>

#define KSP_PRELOAD		1

struct linker_file_t;

typedef struct lf_selfpatch {
	char	*patchable;
	char	*patch;
	int	patchable_size;
	int	patch_size;
	int	feature_selector;
	int	feature;
	char	*comment;
} lf_selfpatch_t;

extern char *selfpatch_nop_table[];

void lf_selfpatch(linker_file_t lf, int preload);
void lf_selfpatch_apply(linker_file_t lf, struct lf_selfpatch *patch);
void lf_selfpatch_apply_preload(linker_file_t lf, struct lf_selfpatch *patch);

#endif /* __SELFPATH_H__ */
