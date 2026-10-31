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

#ifndef __LIB_FILE_ID_KEY_H__
#define __LIB_FILE_ID_KEY_H__

#include "librpc/gen_ndr/file_id.h"

/*
 * The key for locking.tdb and brlock.tdb,
 * see file_id_key in file_id.idl.
 */
struct file_id_key_buf { uint8_t buf[FILE_ID_KEY_LENGTH]; };
void push_file_id_24(struct file_id_key_buf *buf, const struct file_id *id);
bool pull_file_id_24(const uint8_t *buf, size_t len, struct file_id *id);

/*
 * The key for xattr.tdb and acl.tdb, also used
 * for the directory names of vfs_streams_depot
 * and FSCTL_CREATE_OR_GET_OBJECT_ID,
 * see file_id_key_16 in file_id.idl.
 *
 * This ignores the extid.
 */
void push_file_id_16(uint8_t *buf, const struct file_id *id);
bool pull_file_id_16(const uint8_t *buf, size_t len, struct file_id *id);

#endif
