/*
 * Unix SMB/CIFS implementation.
 *
 * Verify the key of netlogon_creds_cli records and g_locks.
 *
 * Copyright (C) Stefan Metzmacher 2026
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include "includes.h"
#include "libcli/auth/netlogon_creds_cli.c"

/*
 * netlogon_creds_cli.tdb is a local database, but the key is
 * also used for a g_lock in g_lock.tdb, which serializes the use
 * of the netlogon credentials of a machine account on all nodes
 * of a cluster, also between different versions.
 */

static void test_key_name(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct netlogon_creds_cli_context *context = NULL;
	NTSTATUS status;

	status = netlogon_creds_cli_context_common("client",
						   "client$",
						   SEC_CHAN_WKSTA,
						   DCERPC_AUTH_LEVEL_PRIVACY,
						   0,
						   0,
						   "dc1.example.com",
						   "example",
						   "example.com",
						   frame,
						   &context);
	assert_true(NT_STATUS_IS_OK(status));

	assert_string_equal(context->db.key_name,
			    "CLI[CLIENT/CLIENT$]/SRV[DC1/EXAMPLE]");
	assert_int_equal(context->db.key_data.dsize,
			 strlen(context->db.key_name) + 1);
	assert_memory_equal(context->db.key_data.dptr,
			    "CLI[CLIENT/CLIENT$]/SRV[DC1/EXAMPLE]",
			    context->db.key_data.dsize);

	/* the server name without a dot */
	status = netlogon_creds_cli_context_common("client",
						   "client$",
						   SEC_CHAN_WKSTA,
						   DCERPC_AUTH_LEVEL_PRIVACY,
						   0,
						   0,
						   "dc1",
						   "example",
						   "example.com",
						   frame,
						   &context);
	assert_true(NT_STATUS_IS_OK(status));

	assert_string_equal(context->db.key_name,
			    "CLI[CLIENT/CLIENT$]/SRV[DC1/EXAMPLE]");

	TALLOC_FREE(frame);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_key_name),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
