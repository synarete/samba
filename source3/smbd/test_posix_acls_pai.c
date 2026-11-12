/*
 * Unix SMB/CIFS implementation.
 *
 * Verify the format of the user.SAMBA_PAI xattr.
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

#include "posix_acls.c"
#include <setjmp.h>
#include <cmocka.h>

/*
 * With "map acl inherit = yes" the ACL inheritance flags are
 * stored in the user.SAMBA_PAI xattr, which is shared between
 * all nodes of a cluster, also between different versions.
 *
 * Samba only writes version 2 of the format, see
 * create_pai_buf_v2().
 */

/* the owner type is stored on disk */
BUILD_ASSERT(UID_ACE == 0);
BUILD_ASSERT(GID_ACE == 1);
BUILD_ASSERT(WORLD_ACE == 2);

static const uint8_t pai_v2[] = {
	0x02,			/* version */
	0x04, 0x94,		/* sd_type */
	0x03, 0x00,		/* num_entries */
	0x01, 0x00,		/* num_default_entries */
	/* entries */
	0x13, 0x00, 0xe8, 0x03, 0x00, 0x00,	/* uid 1000 */
	0x0b, 0x01, 0x64, 0x00, 0x00, 0x00,	/* gid 100 */
	0x10, 0x02, 0xff, 0xff, 0xff, 0xff,	/* world */
	/* default entries */
	0x1b, 0x00, 0xe9, 0x03, 0x00, 0x00,	/* uid 1001 */
};

static void test_create_pai_buf_v2(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	canon_ace file_aces[3] = {
		{
			.owner_type = UID_ACE,
			.unix_ug = { .type = ID_TYPE_UID, .id = 1000, },
			.ace_flags = 0x13,
		},
		{
			.owner_type = GID_ACE,
			.unix_ug = { .type = ID_TYPE_GID, .id = 100, },
			.ace_flags = 0x0b,
		},
		{
			.owner_type = WORLD_ACE,
			.unix_ug = { .type = ID_TYPE_NOT_SPECIFIED, .id = -1, },
			.ace_flags = 0x10,
		},
	};
	canon_ace dir_aces[1] = {
		{
			.owner_type = UID_ACE,
			.unix_ug = { .type = ID_TYPE_UID, .id = 1001, },
			.ace_flags = 0x1b,
		},
	};
	char *buf = NULL;
	size_t size = 0;

	file_aces[0].next = &file_aces[1];
	file_aces[1].next = &file_aces[2];

	buf = create_pai_buf_v2(file_aces, dir_aces, 0x9404, &size);
	assert_non_null(buf);
	assert_int_equal(size, sizeof(pai_v2));
	assert_memory_equal(buf, pai_v2, sizeof(pai_v2));

	TALLOC_FREE(frame);
}

static void assert_pai_entry(const struct pai_entry *e,
			     uint8_t ace_flags,
			     enum ace_owner owner_type,
			     enum id_type id_type,
			     uint32_t id)
{
	assert_non_null(e);
	assert_int_equal(e->ace_flags, ace_flags);
	assert_int_equal(e->owner_type, owner_type);
	assert_int_equal(e->unix_ug.type, id_type);
	assert_int_equal(e->unix_ug.id, id);
}

static void test_create_pai_val_v2(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct pai_val *paiv = NULL;
	const struct pai_entry *e = NULL;

	paiv = create_pai_val((const char *)pai_v2, sizeof(pai_v2));
	assert_non_null(paiv);

	assert_int_equal(paiv->sd_type, 0x9404);
	assert_int_equal(paiv->num_entries, 3);
	assert_int_equal(paiv->num_def_entries, 1);

	/* DLIST_ADD() adds the entries at the start */
	e = paiv->entry_list;
	assert_pai_entry(e, 0x10, WORLD_ACE, ID_TYPE_NOT_SPECIFIED, -1);
	e = e->next;
	assert_pai_entry(e, 0x0b, GID_ACE, ID_TYPE_GID, 100);
	e = e->next;
	assert_pai_entry(e, 0x13, UID_ACE, ID_TYPE_UID, 1000);
	assert_null(e->next);

	e = paiv->def_entry_list;
	assert_pai_entry(e, 0x1b, UID_ACE, ID_TYPE_UID, 1001);
	assert_null(e->next);

	/* the size needs to match the number of entries */
	paiv = create_pai_val((const char *)pai_v2, sizeof(pai_v2) - 1);
	assert_null(paiv);

	TALLOC_FREE(frame);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_create_pai_buf_v2),
		cmocka_unit_test(test_create_pai_val_v2),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
