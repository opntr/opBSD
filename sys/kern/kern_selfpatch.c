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
#include <sys/malloc.h>

#include <sys/linker.h>
#include <sys/linker_set.h>
#include <sys/selfpatch.h>
#include <sys/sysctl.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include <machine/md_var.h>
#include <machine/specialreg.h>

#define DBG(...)					\
	if (selfpatch_debug) {				\
		printf("%s: ", __func__);		\
		printf(__VA_ARGS__);			\
	}

extern struct lf_selfpatch __start_set_selfpatch_set[];
extern struct lf_selfpatch __stop_set_selfpatch_set[];

static int selfpatch_debug=1;
SYSCTL_INT(_debug, OID_AUTO, selfpatch_debug, CTLFLAG_RWTUN,
    &selfpatch_debug, 0, "Set various levels of selfpatch debug");

bool
lf_selfpatch_patch_needed(struct lf_selfpatch *p)
{
	if (p == NULL) {
		DBG("false\n");

		return (false);
	}

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
	struct lf_selfpatch *patch, *start, *stop;
	int count, ret;

	if (lf != NULL) {
		DBG("module: %s\n", lf->filename);
		ret = linker_file_lookup_set(lf, "selfpatch_set", &start, &stop, NULL);
		if (ret != 0) {
			DBG("failed to locate selfpatch_set\n");
			return;
		}
		DBG("start: %p stop: %p\n", start, stop);
	} else {
		DBG("kernel patching\n");
		DBG("start: %p stop: %p\n", __start_set_selfpatch_set, __stop_set_selfpatch_set);
		start = __stop_set_selfpatch_set;
		stop = __stop_set_selfpatch_set;
	}

	count = stop - start;
	DBG("count: %d\n", count);

	for (patch = start; patch != stop; patch++) {
		DBG("apply: %p\n", patch);
		lf_selfpatch_apply(lf, patch);
	}
}

void
lf_selfpatch_apply(linker_file_t lf, struct lf_selfpatch *p)
{
	vm_paddr_t *pages;
	vm_offset_t page_offset;
	int i, page_number;

	if (!lf_selfpatch_patch_needed(p))
		return;

	KASSERT(p->patch_size == p->patchable_size,
	    ("%s: patch_size != patchable_size", __func__));

	page_offset = (vm_offset_t)p->patchable & (vm_offset_t)PAGE_MASK;
	page_number = (p->patchable_size >> PAGE_SHIFT) +
	    ((page_offset + p->patchable_size) > PAGE_SIZE ? 2 : 1);

	pages = malloc(page_number, M_TEMP, M_WAITOK | M_ZERO);

	DBG("change mapping attribute from RX to RWX\n");
	for (i=0; i<page_number; i++) {
		vm_paddr_t kva;

		kva = trunc_page(p->patchable) + i * PAGE_SIZE;
		pages[i] = pmap_kextract(kva);
		pmap_kenter_attr(kva, pages[i], VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
	}
	DBG("done.\n");

	DBG("patchable: %p\n", p->patchable);
	DBG("patch: %p\n", p->patch);
	DBG("patch size: %d\n", p->patchable_size);

	memcpy(p->patchable, p->patch, p->patchable_size);

	DBG("patched.\n");

	DBG("change mapping attribute from RWX to RX:\n");
	for (i=0; i<page_number; i++) {
		vm_paddr_t kva;

		kva = trunc_page(p->patchable) + i * PAGE_SIZE;
		pmap_kenter_attr(kva, pages[i], VM_PROT_READ | VM_PROT_EXECUTE);
	}
	DBG("done.\n");

	free(pages, M_TEMP);
}

