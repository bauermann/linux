/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Ultravisor definitions
 *
 * Copyright 2019, IBM Corporation.
 *
 */
#ifndef _ASM_POWERPC_ULTRAVISOR_H
#define _ASM_POWERPC_ULTRAVISOR_H

#include <asm/asm-prototypes.h>
#include <asm/ultravisor-api.h>

static inline int uv_share_page(u64 pfn, u64 npages)
{
	return ucall_norets(UV_SHARE_PAGE, pfn, npages);
}

static inline int uv_unshare_page(u64 pfn, u64 npages)
{
	return ucall_norets(UV_UNSHARE_PAGE, pfn, npages);
}

static inline int uv_unshare_all_pages(void)
{
	return ucall_norets(UV_UNSHARE_ALL_PAGES);
}

#endif	/* _ASM_POWERPC_ULTRAVISOR_H */
