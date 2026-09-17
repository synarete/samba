/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2012

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
#include "smbd/globals.h"
#include "librpc/gen_ndr/ndr_smbXsrv.h"
#include "lib/cluster_support.h"

/*
 * This maps the active cluster functional level onto the record
 * version used for the file server internal states, that is the
 * struct smbXsrv_*_global records and the related messages.
 *
 * The cluster functional level is the single authority for this.
 * Every process verifies the active level against the level ranges
 * it was built with before it does anything else, see
 * cluster_level_db_check() and cluster_level_activate(), and exits
 * if the level is not supported. The level is only ever raised by
 * an explicit administrative step which requires all nodes to
 * support the new level. So any process that is running is
 * guaranteed to understand the active level.
 *
 * Note this is deliberately evaluated on every call instead of being
 * cached, because the active level can be raised while we are
 * running: the MSG_CLUSTER_LEVEL_UPGRADED handler installs the new
 * level and we use it for the records we write from then on. That is
 * the behaviour described in source3/librpc/idl/cluster_level.idl.
 */
uint32_t smbXsrv_version_global_current(void)
{
	const struct cluster_level_active *al = NULL;

	if (CLUSTER_LEVEL_ACTIVE(1, 0)) {
		return SMBXSRV_VERSION_1;
	}

	al = cluster_level_global_active();

	DBG_ERR("Unknown cluster functional level %" PRIu32 ".%" PRIu32,
		al->major, al->minor);
	smb_panic("No smbXsrv version for the active cluster functional level");
	return SMBXSRV_VERSION_CURRENT;
}
