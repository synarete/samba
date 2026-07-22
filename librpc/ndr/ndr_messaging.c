/*
   Unix SMB/CIFS implementation.

   Helper routines for messaging IDL-based messages

   Copyright (C) Shachar Sharon 2026 <ssharon@redhat.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "librpc/gen_ndr/ndr_messaging.h"
#include "librpc/ndr/ndr_messaging.h"

enum ndr_err_code messaging_debug_push(TALLOC_CTX *mem_ctx,
				       struct messaging_debug *msg,
				       DATA_BLOB *blob)
{
	msg->version = MESSAGING_DEBUG_VERSION_CURRENT;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_debug);
}

enum ndr_err_code messaging_debug_pull(TALLOC_CTX *mem_ctx,
				       const DATA_BLOB *blob,
				       struct messaging_debug *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_debug);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_DEBUG_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_profile_push(TALLOC_CTX *mem_ctx,
					 struct messaging_profile *msg,
					 DATA_BLOB *blob)
{
	msg->version = MESSAGING_PROFILE_VERSION_CURRENT;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_profile);
}

enum ndr_err_code messaging_profile_pull(TALLOC_CTX *mem_ctx,
					 const DATA_BLOB *blob,
					 struct messaging_profile *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_profile);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_PROFILE_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}
