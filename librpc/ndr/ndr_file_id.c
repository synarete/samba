/*
   Unix SMB/CIFS implementation.

   Helper routines for the hand-written types of file_id.idl

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
#include "librpc/gen_ndr/ndr_file_id.h"

/*
 * A file_id_hyper is a struct file_id, but the members
 * are hyper instead of udlong, so with LIBNDR_FLAG_BIGENDIAN
 * the high 32 bits come first. This means with
 * LIBNDR_FLAG_HOST_BYTE_ORDER we get the layout of
 * the raw C structure on all platforms.
 */
enum ndr_err_code ndr_push_file_id_hyper(struct ndr_push *ndr,
					 ndr_flags_type ndr_flags,
					 const struct file_id *r)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 8));
		NDR_CHECK(ndr_push_hyper(ndr, NDR_SCALARS, r->devid));
		NDR_CHECK(ndr_push_hyper(ndr, NDR_SCALARS, r->inode));
		NDR_CHECK(ndr_push_hyper(ndr, NDR_SCALARS, r->extid));
		NDR_CHECK(ndr_push_trailer_align(ndr, 8));
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_file_id_hyper(struct ndr_pull *ndr,
					 ndr_flags_type ndr_flags,
					 struct file_id *r)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 8));
		NDR_CHECK(ndr_pull_hyper(ndr, NDR_SCALARS, &r->devid));
		NDR_CHECK(ndr_pull_hyper(ndr, NDR_SCALARS, &r->inode));
		NDR_CHECK(ndr_pull_hyper(ndr, NDR_SCALARS, &r->extid));
		NDR_CHECK(ndr_pull_trailer_align(ndr, 8));
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_file_id_hyper(struct ndr_print *ndr,
			     const char *name,
			     const struct file_id *r)
{
	ndr_print_file_id(ndr, name, r);
}

/*
 * A file_id_devino is a struct file_id, but only
 * devid and inode are on the wire, the extid is
 * ignored on push and zero after pull.
 */
enum ndr_err_code ndr_push_file_id_devino(struct ndr_push *ndr,
					  ndr_flags_type ndr_flags,
					  const struct file_id *r)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_udlong(ndr, NDR_SCALARS, r->devid));
		NDR_CHECK(ndr_push_udlong(ndr, NDR_SCALARS, r->inode));
		NDR_CHECK(ndr_push_trailer_align(ndr, 4));
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_file_id_devino(struct ndr_pull *ndr,
					  ndr_flags_type ndr_flags,
					  struct file_id *r)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_udlong(ndr, NDR_SCALARS, &r->devid));
		NDR_CHECK(ndr_pull_udlong(ndr, NDR_SCALARS, &r->inode));
		r->extid = 0;
		NDR_CHECK(ndr_pull_trailer_align(ndr, 4));
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_file_id_devino(struct ndr_print *ndr,
			      const char *name,
			      const struct file_id *r)
{
	ndr_print_struct(ndr, name, "file_id_devino");
	ndr->depth++;
	ndr_print_udlong(ndr, "devid", r->devid);
	ndr_print_udlong(ndr, "inode", r->inode);
	ndr->depth--;
}
