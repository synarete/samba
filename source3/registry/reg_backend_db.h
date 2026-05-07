/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Gerald Carter                     2002-2005
 *  Copyright (C) Michael Adam                      2007-2009
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _REG_BACKEND_DB_H
#define _REG_BACKEND_DB_H

#include "registry.h"

WERROR init_registry_key(const char *add_path);
WERROR init_registry_data(void);
WERROR regdb_init(void);
WERROR regdb_open( void );
int regdb_close( void );
WERROR regdb_transaction_start(void);
WERROR regdb_transaction_commit(void);
WERROR regdb_transaction_cancel(void);
int regdb_get_seqnum(void);

/* Legacy format pack functions (V3) - for testing */
int regdb_pack_values_v3(struct regval_ctr *values, uint8_t *buf, int buflen);
int regdb_pack_keys_v3(struct regsubkey_ctr *ctr, uint8_t *buf, int buflen);

/* IDL format pack/unpack functions (V4) */
WERROR regdb_pack_values_v4(struct regval_ctr *values,
			    uint8_t **buf,
			    size_t *buflen,
			    TALLOC_CTX *mem_ctx);
WERROR regdb_unpack_values_v4(struct regval_ctr *values,
			      uint8_t *buf,
			      size_t buflen);
WERROR regdb_pack_keys_v4(struct regsubkey_ctr *ctr,
			  uint8_t **buf,
			  size_t *buflen,
			  TALLOC_CTX *mem_ctx);
WERROR regdb_unpack_keys_v4(struct regsubkey_ctr *ctr,
			    uint8_t *buf,
			    size_t buflen);

#endif /* _REG_BACKEND_DB_H */
