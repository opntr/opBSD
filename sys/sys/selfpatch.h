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

#define KSP_NULL		0
#define KSP_SELFTEST		-1

struct ksp_selector_entry {
	const int	feature_selector;
	const int	*featurep;
};
#define KSP_SELECTOR_END	{KSP_NULL, NULL}

extern struct ksp_selector_entry ksp_selector_table[];

#define KSP_FEATURE_SELFTEST	1

#include <machine/selfpatch-machdep.h>

#define KSP_MODULE		1

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

int lf_selfpatch(linker_file_t lf, int mod);
int lf_selfpatch_apply(linker_file_t lf, struct lf_selfpatch *patch);
int lf_selfpatch_apply_module(linker_file_t lf, struct lf_selfpatch *patch);

#endif /* __SELFPATH_H__ */
