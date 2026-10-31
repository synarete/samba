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

#ifndef _LIBRPC_NDR_NDR_FILE_ID_H_
#define _LIBRPC_NDR_NDR_FILE_ID_H_

enum ndr_err_code ndr_push_file_id_hyper(struct ndr_push *ndr,
					 ndr_flags_type ndr_flags,
					 const struct file_id *r);
enum ndr_err_code ndr_pull_file_id_hyper(struct ndr_pull *ndr,
					 ndr_flags_type ndr_flags,
					 struct file_id *r);
void ndr_print_file_id_hyper(struct ndr_print *ndr,
			     const char *name,
			     const struct file_id *r);

enum ndr_err_code ndr_push_file_id_devino(struct ndr_push *ndr,
					  ndr_flags_type ndr_flags,
					  const struct file_id *r);
enum ndr_err_code ndr_pull_file_id_devino(struct ndr_pull *ndr,
					  ndr_flags_type ndr_flags,
					  struct file_id *r);
void ndr_print_file_id_devino(struct ndr_print *ndr,
			      const char *name,
			      const struct file_id *r);

#endif /* _LIBRPC_NDR_NDR_FILE_ID_H_ */
