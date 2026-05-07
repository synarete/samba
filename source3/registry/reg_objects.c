/*
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Gerald Carter                     2002-2005
 *  Copyright (C) Michael Adam                      2007-2010
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

/* Implementation of registry frontend view functions. */

#include "includes.h"
#include "registry.h"
#include "reg_objects.h"
#include "util_tdb.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_rbt.h"
#include "../libcli/registry/util_reg.h"
#include "lib/util/string_wrappers.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_REGISTRY

/* low level structure to contain registry values */

struct regval_blob {
	fstring		valuename;
	uint32_t	type;
	/* this should be encapsulated in an RPC_DATA_BLOB */
	uint32_t	size;	/* in bytes */
	uint8_t		*data_p;
};

/* container for registry values */

struct regval_ctr {
	uint32_t num_values;
	struct regval_blob **values;
	int seqnum;
};

struct regsubkey_ctr {
	uint32_t        num_subkeys;
	char **subkeys;
	int seqnum;
};

/**********************************************************************

 Note that the struct regsubkey_ctr and struct regval_ctr objects *must* be
 talloc()'d since the methods use the object pointer as the talloc
 context for internal private data.

 There is no longer a regval_ctr_init() and regval_ctr_destroy()
 pair of functions.  Simply talloc_zero() and TALLOC_FREE() the
 object.

 **********************************************************************/

static int regsubkey_ctr_key_cmp(const char *a, const char *b)
{
	return strcmp(a, b);
}

static WERROR regsubkey_ctr_find_keyname(struct regsubkey_ctr *ctr,
					 const char *keyname,
					 uint32_t *idx,
					 bool *found)
{
	uint32_t low = 0, high;
	int cmp = 0;

	if ((ctr == NULL) || (keyname == NULL)) {
		return WERR_INVALID_PARAMETER;
	}

	high = ctr->num_subkeys;

	while (low < high) {
		uint32_t mid = low + (high - low) / 2;

		cmp = regsubkey_ctr_key_cmp(ctr->subkeys[mid], keyname);
		if (cmp < 0) {
			low = mid + 1;
			continue;
		}
		if (cmp > 0) {
			high = mid;
			continue;
		}

		if (idx != NULL) {
			*idx = mid;
		}
		if (found != NULL) {
			*found = true;
		}
		return WERR_OK;
	}

	if (idx != NULL) {
		*idx = low;
	}
	if (found != NULL) {
		*found = false;
	}
	return WERR_OK;
}

WERROR regsubkey_ctr_init(TALLOC_CTX *mem_ctx, struct regsubkey_ctr **ctr)
{
	if (ctr == NULL) {
		return WERR_INVALID_PARAMETER;
	}

	*ctr = talloc_zero(mem_ctx, struct regsubkey_ctr);
	if (*ctr == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	return WERR_OK;
}

/**
 * re-initialize the list of subkeys (to the empty list)
 * in an already allocated regsubkey_ctr
 */

WERROR regsubkey_ctr_reinit(struct regsubkey_ctr *ctr)
{
	if (ctr == NULL) {
		return WERR_INVALID_PARAMETER;
	}

	TALLOC_FREE(ctr->subkeys);

	ctr->num_subkeys = 0;
	ctr->seqnum = 0;

	return WERR_OK;
}

WERROR regsubkey_ctr_set_seqnum(struct regsubkey_ctr *ctr, int seqnum)
{
	if (ctr == NULL) {
		return WERR_INVALID_PARAMETER;
	}

	ctr->seqnum = seqnum;

	return WERR_OK;
}

int regsubkey_ctr_get_seqnum(struct regsubkey_ctr *ctr)
{
	if (ctr == NULL) {
		return -1;
	}

	return ctr->seqnum;
}

static WERROR regsubkey_ctr_index_for_keyname(struct regsubkey_ctr *ctr,
					      const char *keyname,
					      uint32_t *idx)
{
	bool found = false;
	WERROR werr;

	werr = regsubkey_ctr_find_keyname(ctr, keyname, idx, &found);
	W_ERROR_NOT_OK_RETURN(werr);

	if (!found) {
		return WERR_NOT_FOUND;
	}

	return WERR_OK;
}

/***********************************************************************
 Add a new key to the array
 **********************************************************************/

WERROR regsubkey_ctr_addkey( struct regsubkey_ctr *ctr, const char *keyname )
{
	char **newkeys;
	uint32_t idx;
	bool found = false;
	WERROR werr;

	if ( !keyname ) {
		return WERR_OK;
	}

	werr = regsubkey_ctr_find_keyname(ctr, keyname, &idx, &found);
	W_ERROR_NOT_OK_RETURN(werr);

	if (found) {
		return WERR_OK;
	}

	if (!(newkeys = talloc_realloc(ctr, ctr->subkeys, char *,
					     ctr->num_subkeys+1))) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	ctr->subkeys = newkeys;

	if (idx < ctr->num_subkeys) {
		memmove(&ctr->subkeys[idx + 1],
			&ctr->subkeys[idx],
			sizeof(char *) * (ctr->num_subkeys - idx));
	}

	ctr->subkeys[idx] = talloc_strdup(ctr->subkeys, keyname);
	if (ctr->subkeys[idx] == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	ctr->num_subkeys++;

	return WERR_OK;
}

 /***********************************************************************
 Delete a key from the array
 **********************************************************************/

WERROR regsubkey_ctr_delkey( struct regsubkey_ctr *ctr, const char *keyname )
{
	WERROR werr;
	uint32_t idx;

	if (keyname == NULL) {
		return WERR_INVALID_PARAMETER;
	}

	werr = regsubkey_ctr_index_for_keyname(ctr, keyname, &idx);
	W_ERROR_NOT_OK_RETURN(werr);

	ctr->num_subkeys--;
	if (idx < ctr->num_subkeys) {
		memmove(&ctr->subkeys[idx],
			&ctr->subkeys[idx + 1],
			sizeof(char *) * (ctr->num_subkeys - idx));
	}

	return WERR_OK;
}

/***********************************************************************
 Check for the existence of a key
 **********************************************************************/

bool regsubkey_ctr_key_exists( struct regsubkey_ctr *ctr, const char *keyname )
{
	WERROR werr;

	if (!ctr->subkeys) {
		return False;
	}

	werr = regsubkey_ctr_index_for_keyname(ctr, keyname, NULL);
	if (!W_ERROR_IS_OK(werr)) {
		return false;
	}

	return true;
}

/***********************************************************************
 How many keys does the container hold ?
 **********************************************************************/

uint32_t regsubkey_ctr_numkeys( struct regsubkey_ctr *ctr )
{
	return ctr->num_subkeys;
}

/***********************************************************************
 Retrieve a specific key string
 **********************************************************************/

char* regsubkey_ctr_specific_key( struct regsubkey_ctr *ctr, uint32_t key_index )
{
	if ( ! (key_index < ctr->num_subkeys) )
		return NULL;

	return ctr->subkeys[key_index];
}

/*
 * Utility functions for struct regval_ctr
 */

/**
 * allocate a regval_ctr structure.
 */
WERROR regval_ctr_init(TALLOC_CTX *mem_ctx, struct regval_ctr **ctr)
{
	if (ctr == NULL) {
		return WERR_INVALID_PARAMETER;
	}

	*ctr = talloc_zero(mem_ctx, struct regval_ctr);
	if (*ctr == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	return WERR_OK;
}

/***********************************************************************
 How many keys does the container hold ?
 **********************************************************************/

uint32_t regval_ctr_numvals(struct regval_ctr *ctr)
{
	return ctr->num_values;
}

/**********************************************************************
 *********************************************************************/

uint8_t* regval_data_p(struct regval_blob *val)
{
	return val->data_p;
}

/**********************************************************************
 *********************************************************************/

uint32_t regval_size(struct regval_blob *val)
{
	return val->size;
}

/**********************************************************************
 *********************************************************************/

char* regval_name(struct regval_blob *val)
{
	return val->valuename;
}

/**********************************************************************
 *********************************************************************/

uint32_t regval_type(struct regval_blob *val)
{
	return val->type;
}

/***********************************************************************
 Retrieve a pointer to a specific value. Caller should dup the structure
 since this memory will go away when the ctr is free()'d
 **********************************************************************/

struct regval_blob *regval_ctr_specific_value(struct regval_ctr *ctr,
					      uint32_t idx)
{
	if ( !(idx < ctr->num_values) )
		return NULL;

	return ctr->values[idx];
}

/***********************************************************************
 Check for the existence of a value
 **********************************************************************/

bool regval_ctr_value_exists(struct regval_ctr *ctr, const char *value)
{
	uint32_t i;

	for ( i=0; i<ctr->num_values; i++ ) {
		if ( strequal( ctr->values[i]->valuename, value) )
			return True;
	}

	return False;
}

/**
 * Get a value by its name
 */
struct regval_blob *regval_ctr_value_byname(struct regval_ctr *ctr,
					    const char *value)
{
	uint32_t i;

	for (i = 0; i < ctr->num_values; i++) {
		if (strequal(ctr->values[i]->valuename, value)) {
			return ctr->values[i];
		}
	}

	return NULL;
}


/***********************************************************************
 * compose a struct regval_blob from input data
 **********************************************************************/

struct regval_blob *regval_compose(TALLOC_CTX *ctx, const char *name,
				   uint32_t type,
				   const uint8_t *data_p, size_t size)
{
	struct regval_blob *regval = talloc(ctx, struct regval_blob);

	if (regval == NULL) {
		return NULL;
	}

	fstrcpy(regval->valuename, name);
	regval->type = type;
	if (size) {
		regval->data_p = (uint8_t *)talloc_memdup(regval, data_p, size);
		if (!regval->data_p) {
			TALLOC_FREE(regval);
			return NULL;
		}
	} else {
		regval->data_p = NULL;
	}
	regval->size = size;

	return regval;
}

/***********************************************************************
 Add a new registry value to the array
 **********************************************************************/

int regval_ctr_addvalue(struct regval_ctr *ctr, const char *name, uint32_t type,
                        const uint8_t *data_p, size_t size)
{
	if ( !name )
		return ctr->num_values;

	/* Delete the current value (if it exists) and add the new one */

	regval_ctr_delvalue( ctr, name );

	/* allocate a slot in the array of pointers */

	if (  ctr->num_values == 0 ) {
		ctr->values = talloc( ctr, struct regval_blob *);
	} else {
		ctr->values = talloc_realloc(ctr, ctr->values,
						   struct regval_blob *,
						   ctr->num_values+1);
	}

	if (!ctr->values) {
		ctr->num_values = 0;
		return 0;
	}

	/* allocate a new value and store the pointer in the array */

	ctr->values[ctr->num_values] = regval_compose(ctr, name, type, data_p,
						      size);
	if (ctr->values[ctr->num_values] == NULL) {
		ctr->num_values = 0;
		return 0;
	}
	ctr->num_values++;

	return ctr->num_values;
}

/***********************************************************************
 Add a new registry SZ value to the array
 **********************************************************************/

int regval_ctr_addvalue_sz(struct regval_ctr *ctr, const char *name, const char *data)
{
	DATA_BLOB blob;

	if (!push_reg_sz(ctr, &blob, data)) {
		return -1;
	}

	return regval_ctr_addvalue(ctr, name, REG_SZ,
				   (const uint8_t *)blob.data,
				   blob.length);
}

/***********************************************************************
 Add a new registry MULTI_SZ value to the array
 **********************************************************************/

int regval_ctr_addvalue_multi_sz(struct regval_ctr *ctr, const char *name, const char **data)
{
	DATA_BLOB blob;

	if (!push_reg_multi_sz(ctr, &blob, data)) {
		return -1;
	}

	return regval_ctr_addvalue(ctr, name, REG_MULTI_SZ,
				   (const uint8_t *)blob.data,
				   blob.length);
}

/***********************************************************************
 Add a new registry value to the array
 **********************************************************************/

int regval_ctr_copyvalue(struct regval_ctr *ctr, struct regval_blob *val)
{
	if ( val ) {
		regval_ctr_addvalue(ctr, val->valuename, val->type,
				    (uint8_t *)val->data_p, val->size);
	}

	return ctr->num_values;
}

/***********************************************************************
 Delete a single value from the registry container.
 No need to free memory since it is talloc'd.
 **********************************************************************/

int regval_ctr_delvalue(struct regval_ctr *ctr, const char *name)
{
	uint32_t i;

	for ( i=0; i<ctr->num_values; i++ ) {
		if ( strequal( ctr->values[i]->valuename, name ) )
			break;
	}

	/* just return if we don't find it */

	if ( i == ctr->num_values )
		return ctr->num_values;

	/* If 'i' was not the last element, just shift everything down one */
	ctr->num_values--;
	if ( i < ctr->num_values )
		memmove(&ctr->values[i], &ctr->values[i+1],
			sizeof(struct regval_blob*)*(ctr->num_values-i));

	return ctr->num_values;
}

/***********************************************************************
 Retrieve single value from the registry container.
 No need to free memory since it is talloc'd.
 **********************************************************************/

struct regval_blob* regval_ctr_getvalue(struct regval_ctr *ctr,
					const char *name)
{
	uint32_t i;

	/* search for the value */

	for ( i=0; i<ctr->num_values; i++ ) {
		if ( strequal( ctr->values[i]->valuename, name ) )
			return ctr->values[i];
	}

	return NULL;
}

int regval_ctr_get_seqnum(struct regval_ctr *ctr)
{
	if (ctr == NULL) {
		return -1;
	}

	return ctr->seqnum;
}

WERROR regval_ctr_set_seqnum(struct regval_ctr *ctr, int seqnum)
{
	if (ctr == NULL) {
		return WERR_INVALID_PARAMETER;
	}

	ctr->seqnum = seqnum;

	return WERR_OK;
}
