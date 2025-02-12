#ifndef _VFS_IOSTAT_H_
#define _VFS_IOSTAT_H_
/*
 * Copyright (C) Shachar Sharon <ssharon@redhat.com> 2025
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include <stdint.h>

#define VFS_IOSTAT_TDB_FILE "iostat.tdb"

struct vfs_iostat_dbkey {
	uint64_t k[2];
};

struct vfs_iostat_entry {
	uint64_t count; /* number of events */
	uint64_t bytes; /* bytes */
	uint64_t time;	/* microseconds */
	uint64_t reserved;
};

struct vfs_iostat_record {
	uint64_t magic;
	uint64_t timestamp;
	uint64_t reserved[6];
	struct vfs_iostat_entry read;
	struct vfs_iostat_entry write;
	char service[]; /* service name (start) */
};

#endif
