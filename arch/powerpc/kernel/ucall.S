/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Generic code to perform an ultravisor call.
 *
 * Copyright 2019, IBM Corporation.
 *
 */
#include <asm/ppc_asm.h>
#include <asm/export.h>

_GLOBAL(ucall_norets)
EXPORT_SYMBOL_GPL(ucall_norets)
	mfcr	r0
	stw	r0,8(r1)

	sc	2		/* Invoke the ultravisor */

	lwz	r0,8(r1)
	mtcrf	0xff,r0
	blr			/* Return r3 = status */
