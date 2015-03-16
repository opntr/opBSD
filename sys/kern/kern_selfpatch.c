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

#define	DBG(...)					\
	if (selfpatch_debug) {				\
		printf("%s: ", __func__);		\
		printf(__VA_ARGS__);			\
	}

#ifdef KSP_WxorX_KERNEL
#undef	KSP_WxorX_KERNEL
#endif /* KSP_WxorX_KERNEL */

extern struct lf_selfpatch __start_set_selfpatch_set[];
extern struct lf_selfpatch __stop_set_selfpatch_set[];

static int selfpatch_debug = 0;
SYSCTL_INT(_debug, OID_AUTO, selfpatch_debug, CTLFLAG_RWTUN,
    &selfpatch_debug, 0, "Set various levels of selfpatch debug");

#ifdef KSP_DEBUG
__noinline void lf_selfpatch_selftest(void);
#endif

static void lf_open_kernel_text(struct lf_selfpatch *p);
static void lf_close_kernel_text(struct lf_selfpatch *p);
static void lf_open_module_text(struct lf_selfpatch *p);
static void lf_close_module_text(struct lf_selfpatch *p);
static void lf_pad_with_nop(struct lf_selfpatch *p);

bool
lf_selfpatch_patch_needed(struct lf_selfpatch *p)
{
	struct ksp_selector_entry	*e, *matched;

	if (p == NULL) {
		DBG("false\n");

		return (false);
	}

	matched = NULL;
	for (e = __DECONST(struct ksp_selector_entry *, ksp_selector_table);
	    (e->feature_selector != KSP_NULL) && (e->featurep != NULL);
	    e++) {
		if (e->feature_selector == p->feature_selector) {
			matched = e;
			break;
		}
	}

	if (matched != NULL)
		if ((*(matched->featurep) & p->feature) != 0)
			return (true);

#ifdef KSP_DEBUG
	if (p->feature_selector == KSP_SELFTEST)
		if ((p->feature & KSP_FEATURE_SELFTEST) != 0)
			return (true);
#endif

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
		start = __start_set_selfpatch_set;
		stop = __stop_set_selfpatch_set;
		DBG("start: %p stop: %p\n", start, stop);
	}

	count = stop - start;
	DBG("count: %d\n", count);

	critical_enter();

	for (patch = start; patch != stop; patch++) {
		DBG("apply: %p\n", patch);
		ret = lf_selfpatch_apply(lf, patch, mod);
		if (ret != 0)
			return (ret);
	}

	critical_exit();

#ifdef KSP_DEBUG
	/*
	 * when selfpatch does not works, the system should crash
	 */
	lf_selfpatch_selftest();
#endif

	return (0);
}

int
lf_selfpatch_apply(linker_file_t lf, struct lf_selfpatch *p, int mod)
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

	if (p->patch_size > p->patchable_size)
		panic("%s: patch_size > patchable_size", __func__);

	/*
	 * open the kernel text
	 * currently this is a dummy function, because the kernel protection
	 * is RWX now.
	 */
	if (mod == KSP_MODULE)
		lf_open_module_text(p);
	else
		lf_open_kernel_text(p);

	/*
	 * replace the instructions
	 */
	memcpy(p->patchable, p->patch, p->patchable_size);
	lf_pad_with_nop(p);

	if (mod == KSP_MODULE)
		lf_close_module_text(p);
	else
		lf_close_kernel_text(p);

	DBG("patched.\n");

	return (0);
}

static void
lf_open_kernel_text(struct lf_selfpatch *p)
{
	/*
	 * dummy function, currently unused becasue the kernel
	 * protection is RWX
	 */
#ifdef KSP_WxorX_KERNEL
	vm_offset_t eva, sva;

	eva = (vm_offset_t)(p->patchable);
	sva = (vm_offset_t)(p->patchable + p->patchable_size);

	DBG("kernel: %p - %p RX -> RWX\n"
	    (void *)sva, (void *)eva);
	pmap_protect(kernel_pmap, sva, eva,
	    VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
#endif
}

static void
lf_close_kernel_text(struct lf_selfpatch *p)
{
	/*
	 * dummy function, currently unused becasue the kernel
	 * protection is RWX
	 *
	 * currently flushes the cache after modification
	 */
#ifdef KSP_WxorX_KERNEL
	vm_offset_t eva, sva;

	eva = (vm_offset_t)(p->patchable);
	sva = (vm_offset_t)(p->patchable + p->patchable_size);
	DBG("kernel: %p - %p RWX -> RX\n",
	    (void *)sva, (void *)eva);

	pmap_protect(kernel_pmap, sva, eva,
	    VM_PROT_READ | VM_PROT_EXECUTE);
#endif

	/* Flushes caches and TLBs. */
	wbinvd();
	invltlb();

	DBG("caches flushed.\n");
}

static void
lf_open_module_text(struct lf_selfpatch *p)
{
	/*
	 * dummy function, currently unused becasue the kernel
	 * protection is RWX
	 */
#ifdef KSP_WxorX_KERNEL
	vm_offset_t eva, sva;

	eva = (vm_offset_t)(p->patchable);
	sva = (vm_offset_t)(p->patchable + p->patchable_size);
	DBG("module: %p - %p RX -> RWX\n",
	    (void *)sva, (void *)eva);

	pmap_protect(module_pmap, sva, eva,
	    VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
#endif
}

static void
lf_close_module_text(struct lf_selfpatch *p)
{
	/*
	 * dummy function, currently unused becasue the kernel
	 * protection is RWX
	 *
	 * currently flushes the cache after modification
	 */
#ifdef KSP_WxorX_KERNEL
	vm_offset_t eva, sva;

	eva = (vm_offset_t)(p->patchable);
	sva = (vm_offset_t)(p->patchable + p->patchable_size);
	DBG("module: %p - %p RWX -> RX\n",
	    (void *)sva, (void *)eva);

	pmap_protect(module_pmap, sva, eva,
	    VM_PROT_READ | VM_PROT_EXECUTE);
#endif

	/* Flushes caches and TLBs. */
	wbinvd();
	invltlb();

	DBG("caches flushed.\n");
}


static void
lf_pad_with_nop(struct lf_selfpatch *p)
{
	int i, rem;
	char *patchable;

	if (p->patch_size == p->patchable_size)
		return;

	if (p->patch_size > p->patchable_size)
		panic("%s: patch_size > patchable_size", __func__);

	rem = p->patchable_size - p->patch_size;
	patchable = p->patchable + p->patch_size;

	DBG("rem: %d\n", rem);
	DBG("nop9: %d\n", rem / KSP_MAX_NOPLEN);

	for (i = rem / KSP_MAX_NOPLEN; i > 0; i -= KSP_MAX_NOPLEN) {
		memcpy(patchable,
		    selfpatch_nop_table[KSP_MAX_NOPLEN],
		    KSP_MAX_NOPLEN);
		patchable += KSP_MAX_NOPLEN;
	}

	rem %= KSP_MAX_NOPLEN;
	DBG("rem: %d -> nop%d\n", rem, rem);
	memcpy(patchable, selfpatch_nop_table[rem], rem);
}

#ifdef KSP_DEBUG
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
#endif
