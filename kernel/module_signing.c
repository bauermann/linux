/* Module signature checker
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/module_signature.h>
#include <linux/string.h>
#include <linux/verification.h>
#include <crypto/public_key.h>
#include "module-internal.h"

/**
 * validate_module_sig - validate that the given signature is sane
 *
 * @ms:		Signature to validate.
 * @file_len:	Size of the file to which @ms is appended.
 */
int validate_module_sig(const struct module_signature *ms, size_t file_len)
{
	if (be32_to_cpu(ms->sig_len) >= file_len - sizeof(*ms))
		return -EBADMSG;

	if (ms->id_type != PKEY_ID_PKCS7) {
		pr_err("Module is not signed with expected PKCS#7 message\n");
		return -ENOPKG;
	}

	if (ms->algo != 0 ||
	    ms->hash != 0 ||
	    ms->signer_len != 0 ||
	    ms->key_id_len != 0 ||
	    ms->__pad[0] != 0 ||
	    ms->__pad[1] != 0 ||
	    ms->__pad[2] != 0) {
		pr_err("PKCS#7 signature info has unexpected non-zero params\n");
		return -EBADMSG;
	}

	return 0;
}

/*
 * Verify the signature on a module.
 */
int mod_verify_sig(const void *mod, unsigned long *_modlen)
{
	struct module_signature ms;
	size_t modlen = *_modlen, sig_len;
	int ret;

	pr_devel("==>%s(,%zu)\n", __func__, modlen);

	if (modlen <= sizeof(ms))
		return -EBADMSG;

	memcpy(&ms, mod + (modlen - sizeof(ms)), sizeof(ms));

	ret = validate_module_sig(&ms, modlen);
	if (ret)
		return ret;

	sig_len = be32_to_cpu(ms.sig_len);
	modlen -= sig_len + sizeof(ms);
	*_modlen = modlen;

	return verify_pkcs7_signature(mod, modlen, mod + modlen, sig_len,
				      NULL, VERIFYING_MODULE_SIGNATURE,
				      NULL, NULL);
}
