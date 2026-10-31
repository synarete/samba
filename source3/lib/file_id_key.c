/*
   Unix SMB/CIFS implementation.

   The file_id key for locking.tdb and brlock.tdb

   Copyright (C) Stefan Metzmacher 2026

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

#include "replace.h"
#include "lib/util/debug.h"
#include "lib/util/fault.h"
#include "librpc/gen_ndr/ndr_file_id.h"
#include "lib/file_id_key.h"

/*
 * The key is the layout of the raw C structure in host byte order.
 */
void push_file_id_24(struct file_id_key_buf *buf, const struct file_id *id)
{
	struct file_id_key key = { .id = *id };
	DATA_BLOB blob = data_blob_const(buf->buf, sizeof(buf->buf));
	enum ndr_err_code ndr_err;

	ndr_err = ndr_push_struct_into_fixed_blob_flags(
		&blob,
		&key,
		LIBNDR_FLAG_HOST_BYTE_ORDER,
		(ndr_push_flags_fn_t)ndr_push_file_id_key);
	SMB_ASSERT(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
}

bool pull_file_id_24(const uint8_t *buf, size_t len, struct file_id *id)
{
	struct file_id_key key = { .id = { .devid = 0, }, };
	DATA_BLOB blob = data_blob_const(buf, len);
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob_all_noalloc_flags(
		&blob,
		&key,
		LIBNDR_FLAG_HOST_BYTE_ORDER,
		(ndr_pull_flags_fn_t)ndr_pull_file_id_key);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return false;
	}

	*id = key.id;
	return true;
}

/*
 * The 16 byte key is always little endian.
 */
void push_file_id_16(uint8_t *buf, const struct file_id *id)
{
	struct file_id_key_16 key = { .id = *id };
	DATA_BLOB blob = data_blob_const(buf, FILE_ID_KEY_16_LENGTH);
	enum ndr_err_code ndr_err;

	ndr_err = ndr_push_struct_into_fixed_blob(
		&blob,
		&key,
		(ndr_push_flags_fn_t)ndr_push_file_id_key_16);
	SMB_ASSERT(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
}

bool pull_file_id_16(const uint8_t *buf, size_t len, struct file_id *id)
{
	struct file_id_key_16 key = { .id = { .devid = 0, }, };
	DATA_BLOB blob = data_blob_const(buf, len);
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob_all_noalloc(
		&blob,
		&key,
		(ndr_pull_flags_fn_t)ndr_pull_file_id_key_16);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return false;
	}

	*id = key.id;
	return true;
}
