/* Rate limiting protocol definitions for smbd ↔ ratelimitd communication */

#ifndef __RATELIMIT_PROTOCOL_H__
#define __RATELIMIT_PROTOCOL_H__

#include "lib/util/time.h"
#include "messages.h"
#include "librpc/gen_ndr/ndr_ratelimit.h"

#define RATELIMITD_SOCKET_NAME "ratelimitd.sock"

/*
 * Protocol versions of the activity reports
 * (struct ratelimit_activity_report):
 *
 * RATELIMIT_PROTOCOL_VERSION_2 uses host byte order
 * (LIBNDR_FLAG_HOST_BYTE_ORDER).
 *
 * RATELIMIT_PROTOCOL_VERSION_3 uses little endian on
 * all platforms, it's used once cluster level 2.0 is active.
 *
 * The receiver checks protocol_version (at offset
 * RATELIMIT_ACTIVITY_REPORT_PROTOCOL_VERSION_OFS)
 * in little endian first in order to find the format.
 */
#define RATELIMIT_PROTOCOL_VERSION_2 2
#define RATELIMIT_PROTOCOL_VERSION_3 3
#define RATELIMIT_ACTIVITY_REPORT_PROTOCOL_VERSION_OFS 16

static inline uint64_t time_now_usec(void)
{
	struct timespec ts;

	clock_gettime_mono(&ts);
	return (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

/* Operation types for rate limiting */
enum ratelimit_operation {
	RATELIMIT_OP_INVALID = 0,
	RATELIMIT_OP_READ = 1,
	RATELIMIT_OP_WRITE = 2,
};

/*
 * The activity reports (VFS process to local daemon via unix socket),
 * the node summaries (daemon to cluster) and the tdb records are
 * defined in source3/librpc/idl/ratelimit.idl. They used to be
 * packed C structures, the NDR representations have exactly
 * the same layout if marshalled with LIBNDR_FLAG_HOST_BYTE_ORDER.
 */

static inline uint32_t ratelimit_msg_type_summary(uint32_t operation)
{
	switch (operation) {
	case RATELIMIT_OP_READ:
		return MSG_VFS_AIO_RATELIMIT_READ_NODE_SUMMARY;
	case RATELIMIT_OP_WRITE:
		return MSG_VFS_AIO_RATELIMIT_WRITE_NODE_SUMMARY;
	default:
		return 0;
	}
}

/*
 * The node summaries in little endian on all platforms,
 * used once cluster level 2.0 is active.
 */
static inline uint32_t ratelimit_msg_type_summary_le(uint32_t operation)
{
	switch (operation) {
	case RATELIMIT_OP_READ:
		return MSG_VFS_AIO_RATELIMIT_READ_NODE_SUMMARY_LE;
	case RATELIMIT_OP_WRITE:
		return MSG_VFS_AIO_RATELIMIT_WRITE_NODE_SUMMARY_LE;
	default:
		return 0;
	}
}

static inline uint32_t ratelimit_op_from_string(const char *op_str)
{
	if (strcmp(op_str, "read") == 0) {
		return RATELIMIT_OP_READ;
	} else if (strcmp(op_str, "write") == 0) {
		return RATELIMIT_OP_WRITE;
	}
	return RATELIMIT_OP_INVALID;
}

static inline const char *ratelimit_op_to_string(uint32_t operation)
{
	switch (operation) {
	case RATELIMIT_OP_READ:
		return "read";
	case RATELIMIT_OP_WRITE:
		return "write";
	default:
		return "invalid";
	}
}

#endif /* __RATELIMIT_PROTOCOL_H__ */
