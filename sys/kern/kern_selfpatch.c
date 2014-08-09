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

#include <sys/jail.h>
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

__noinline void lf_selfpatch_selftest(void);

bool
lf_selfpatch_patch_needed(struct lf_selfpatch *p)
{
	struct ksp_selector_entry	*e, *matched;

	if (p == NULL) {
		DBG("false\n");

		return (false);
	}

	matched = NULL;
	for (e = ksp_selector_table;
	    (e->feature_selector != KSP_NULL) && (e->featurep != NULL);
	    e++) {
		if (e->feature_selector == p->feature_selector) {
			matched = e;
			break;
		}
	}

	if (matched != NULL) {
		if ( (*(matched->featurep) & p->feature) != 0)
			return (true);

	}

	if (p->feature_selector == KSP_SELFTEST)
		if ((p->feature & KSP_FEATURE_SELFTEST) != 0)
			return (true);

	return (false);
}

int
lf_selfpatch(linker_file_t lf, int mod)
{
	struct lf_selfpatch *patch, *start, *stop;
	int count, ret;

	DBG("lf: %p %s\n", lf, mod ? "(module)" : "(kernel)");

	if (lf != NULL) {
		DBG("module: %s\n", lf->filename);
		ret = linker_file_lookup_set(lf, "selfpatch_set", &start, &stop, NULL);
		if (ret != 0) {
			DBG("failed to locate selfpatch_set\n");
			return (0);
		}
		DBG("start: %p stop: %p\n", start, stop);
	} else {
		DBG("kernel patching\n");
		DBG("start: %p stop: %p\n", __start_set_selfpatch_set, __stop_set_selfpatch_set);
		start = __start_set_selfpatch_set;
		stop = __stop_set_selfpatch_set;
	}

	count = stop - start;
	DBG("count: %d\n", count);

	for (patch = start; patch != stop; patch++) {
		DBG("apply: %p\n", patch);
		if (mod == KSP_MODULE) {
			ret = lf_selfpatch_apply_module(lf, patch);
			if (ret != 0)
				return (ret);
		} else {
			ret = lf_selfpatch_apply(lf, patch);
			if (ret != 0)
				return (ret);
		}
	}

	/*
	 * when selfpatch does not works, the system should crash
	 */
	lf_selfpatch_selftest();

	return (0);
}

int
lf_selfpatch_apply(linker_file_t lf, struct lf_selfpatch *p)
{
	vm_paddr_t pages[4];
	vm_offset_t page_offset;
	int i, page_number;

	/* Refuse to patch if securelevel raised */
	if (prison0.pr_securelevel > 0)
		return (EPERM);

	DBG("patchable: %p\n", p->patchable);
	DBG("patch: %p\n", p->patch);
	DBG("feature selector: %d\n", p->feature_selector);
	DBG("feature: %d\n", p->feature);
	DBG("patchable size: %d\n", p->patchable_size);
	DBG("patch size: %d\n", p->patch_size);
	DBG("comment: %s\n", p->comment);

	if (!lf_selfpatch_patch_needed(p)) {
		DBG("not needed.\n");

		return (0);
	}

	if (p->patch_size != p->patchable_size)
		panic("%s: patch_size != patchable_size", __func__);

	page_offset = (vm_offset_t)p->patchable & (vm_offset_t)PAGE_MASK;
	page_number = (p->patchable_size >> PAGE_SHIFT) +
	    ((page_offset + p->patchable_size) > PAGE_SIZE ? 2 : 1);

	DBG("page_number: %d\n", page_number);

	KASSERT(page_number < 4,
	    ("patch size longer than 3 page does not supported yet\n"));

	DBG("change mapping attribute from RX to RWX:\n");
	for (i=0; i<page_number; i++) {
		vm_paddr_t kva;

		kva = trunc_page(p->patchable) + i * PAGE_SIZE;
		pages[i] = pmap_kextract(kva);

		DBG("kva: %p page: %p\n", (void *)kva, (void *)pages[i]);
		pmap_kenter_attr(kva, pages[i], VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
	}
	DBG("done.\n");

	memcpy(p->patchable, p->patch, p->patchable_size);

	DBG("patched.\n");

	DBG("change mapping attribute from RWX to RX:\n");
	for (i=0; i<page_number; i++) {
		vm_paddr_t kva;

		kva = trunc_page(p->patchable) + i * PAGE_SIZE;
		pmap_kenter_attr(kva, pages[i], VM_PROT_READ | VM_PROT_EXECUTE);
	}
	DBG("done.\n");

	return (0);
}

int
lf_selfpatch_apply_module(linker_file_t lf, struct lf_selfpatch *p)
{

	/* Refuse to patch if securelevel raised */
	if (prison0.pr_securelevel > 0)
		return (EPERM);

	DBG("patchable: %p\n", p->patchable);
	DBG("patch: %p\n", p->patch);
	DBG("feature selector: %d\n", p->feature_selector);
	DBG("feature: %d\n", p->feature);
	DBG("patchable size: %d\n", p->patchable_size);
	DBG("patch size: %d\n", p->patch_size);
	DBG("comment: %s\n", p->comment);

	if (!lf_selfpatch_patch_needed(p)) {
		DBG("not needed.\n");

		return (0);
	}

	if (p->patch_size != p->patchable_size)
		panic("%s: patch_size != patchable_size", __func__);

	memcpy(p->patchable, p->patch, p->patchable_size);

	DBG("patched.\n");

	return (0);
}

__noinline void
lf_selfpatch_selftest(void)
{
	__asm __volatile(
	"1:"
	"	ud2; ud2; ; "
	"2:	"
	"	.pushsection set_selfpatch_patch_set, \"ax\" ;  "
	"3:	"
	"	.byte 0x90,0x90,0x90,0x90 ;"
	"4:	"
	"	.popsection "
	"	.pushsection set_selfpatch_set, \"a\" ; "
	"		.quad   1b ; "
	"		.quad   3b ; "
	"		.int    2b-1b ;	"
	"		.int    4b-3b ;	"
	"		.int    " __XSTRING(KSP_SELFTEST) " ; "
	"		.int    " __XSTRING(KSP_FEATURE_SELFTEST) " ; "
	"		.quad	0 ; "
	"	.popsection ; "
	);

	DBG("works.\n");
}

