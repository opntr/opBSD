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

//#include "opt_selfpatch.h"

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

bool
lf_selfpatch_patch_needed(struct lf_selfpatch *p)
{

	if (p == NULL)
		return (false);

	switch (p->feature_selector) {
	case  KSP_CPU_FEATURE         :
		if ((cpu_feature & p->feature) != 0)
			return (true);
		break;
	case  KSP_CPU_FEATURE2        :
		if ((cpu_feature2 & p->feature) != 0)
			return (true);
		break;
	case  KSP_AMD_FEATURE         :
		if ((amd_feature & p->feature) != 0)
			return (true);
		break;
	case  KSP_AMD_FEATURE2        :
		if ((amd_feature2 & p->feature) != 0)
			return (true);
		break;
	case  KSP_VIA_FEATURE_RNG     :
		if ((via_feature_rng & p->feature) != 0)
			return (true);
		break;
	case  KSP_VIA_FEATURE_XCRYPT  :
		if ((via_feature_xcrypt & p->feature) != 0)
			return (true);
		break;
	case  KSP_CPU_STDEXT_FEATURE  :
		if ((cpu_stdext_feature & p->feature) != 0)
			return (true);
		break;

	default:
		return (false);
	}

	return (false);
}

void
lf_selfpatch(linker_file_t lf)
{

	printf("NOT IMPLEMENTED: %s\n", __func__);
}

void
lf_selfpatch_apply(linker_file_t lf, struct lf_selfpatch *patch)
{

	printf("NOT IMPLEMENTED: %s\n", __func__);
}
