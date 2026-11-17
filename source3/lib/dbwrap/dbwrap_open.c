/*
   Unix SMB/CIFS implementation.
   Database interface wrapper

   Copyright (C) Volker Lendecke 2005-2007

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
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_private.h"
#include "dbwrap/dbwrap_open.h"
#include "dbwrap/dbwrap_tdb.h"
#include "dbwrap/dbwrap_ctdb.h"
#include "dbwrap/dbwrap_watch.h"
#include "lib/param/param.h"
#include "lib/cluster_support.h"
#include "lib/messages_ctdb.h"
#include "util_tdb.h"
#include "ctdbd_conn.h"
#include "global_contexts.h"

bool db_is_local(const char *name)
{
	const char *sockname = lp_ctdbd_socket();

	if (lp_clustering() && socket_exist(sockname)) {
		const char *partname;
		/* ctdb only wants the file part of the name */
		partname = strrchr(name, '/');
		if (partname) {
			partname++;
		} else {
			partname = name;
		}
		/* allow ctdb for individual databases to be disabled */
		if (lp_parm_bool(-1, "ctdb", partname, True)) {
			return false;
		}
	}

	return true;
}

static bool db_open_allowed;

/*
 * Called once the configuration is known, either by lp_load_ex()
 * or by code passing the paths explicitly, e.g. to
 * secrets_init_path().
 *
 * Note it stays set, also while a later lp_load_ex() loads the
 * configuration again, e.g. after lp_load_initial_only() skipped
 * the registry configuration, so db_open_registry_allowed
 * needs to be checked first.
 */
void db_open_allow(void)
{
	db_open_allowed = true;
}

static bool db_open_registry_allowed;

/*
 * Called by lp_smbconf_ctx() around opening registry.tdb,
 * which may happen while the configuration is loaded,
 * so the configuration is not known yet, even if
 * db_open_allowed is already set by an earlier load.
 */
void db_open_allow_registry(bool allow)
{
	db_open_registry_allowed = allow;
}

/*
 * Features of databases, which need to be the same for all users of
 * a database, with clustering also on all nodes, so they can only be
 * introduced for a database together with a cluster level and are
 * only used once that level is active:
 *
 * - DBWRAP_FLAG_WATCHED and DBWRAP_FLAG_G_LOCK, the layer on top of
 *   the backend, which db_open_ex() creates itself. It changes the
 *   format of the records, but the format can't be detected from the
 *   records. So a listed database can only be opened with its layer,
 *   e.g. not plain by a tool.
 *
 *   The layer of a busy database like locking.tdb can't simply change
 *   with a new cluster level, as processes which haven't noticed the
 *   new level yet still write records in the old format. In place
 *   upgrades of a layer need more care, e.g. a future
 *   DBWRAP_FLAG_WATCHED_V2 or DBWRAP_FLAG_G_LOCK_V2 could start the
 *   records with 0xFFFFFFFF, which is never a valid number of watchers,
 *   followed by a magic value, so that all versions can be told apart
 *   and read, while the new format is only written once the level is
 *   active.
 *
 * - DBWRAP_FLAG_PER_REC_PERSISTENT, which marks the records in the
 *   ctdb header and pushes them to the other nodes.
 *
 * - DBWRAP_FLAG_OPTIMIZE_READONLY_ACCESS, the read-only delegations
 *   of ctdb, which only work reliably if all nodes have the fixes for
 *   them. It's only an optimization, so it's silently not used for
 *   databases not listed or before the level is active, also if it's
 *   enabled with 'dbwrap_optimize_readonly:<name> = yes'.
 *
 * Properties of the local tdb file of a node, e.g. TDB_INCOMPATIBLE_HASH
 * or TDB_MUTEX_LOCKING, are not listed: tdb checks them when it opens an
 * existing file and with ctdb every node has its own local copy.
 */
struct db_open_feature {
	const char *name;
	uint64_t flags;
	struct cluster_level_active level;
};

#define DB_OPEN_FEATURE(__name, __flags, __major, __minor) { \
	.name = __name, \
	.flags = __flags, \
	.level = { \
		.major = CLUSTER_LEVEL_MAJOR_ ## __major, \
		.minor = CLUSTER_LEVEL_MAJOR_ ## __major ## _MINOR_ ## __minor, \
	}, \
}

static const struct db_open_feature db_open_features[] = {
	/*
	 * g_lock_ctx_init()
	 */
	DB_OPEN_FEATURE("g_lock.tdb",
			DBWRAP_FLAG_G_LOCK, LOWEST, MIN),
	/*
	 * share_mode_lock.c
	 */
	DB_OPEN_FEATURE("locking.tdb",
			DBWRAP_FLAG_G_LOCK, LOWEST, MIN),
	/*
	 * smbXsrv_client.c and smbXsrv_session.c
	 */
	DB_OPEN_FEATURE("smbXsrv_client_global.tdb",
			DBWRAP_FLAG_WATCHED, LOWEST, MIN),
	DB_OPEN_FEATURE("smbXsrv_session_global.tdb",
			DBWRAP_FLAG_WATCHED, LOWEST, MIN),
	/*
	 * Durable and persistent handles
	 */
	DB_OPEN_FEATURE("locking.tdb",
			DBWRAP_FLAG_PER_REC_PERSISTENT, LOWEST, MIN),
	DB_OPEN_FEATURE("brlock.tdb",
			DBWRAP_FLAG_PER_REC_PERSISTENT, LOWEST, MIN),
	DB_OPEN_FEATURE("smbXsrv_open_global.tdb",
			DBWRAP_FLAG_PER_REC_PERSISTENT, LOWEST, MIN),
	/*
	 * LOCAL-DBWRAP-PER-REC-PERSISTENCY
	 */
	DB_OPEN_FEATURE("test_per_rec_persistency.tdb",
			DBWRAP_FLAG_PER_REC_PERSISTENT, LOWEST, MIN),
	DB_OPEN_FEATURE("test_per_rec_persistency_watched.tdb",
			DBWRAP_FLAG_WATCHED, LOWEST, MIN),
	DB_OPEN_FEATURE("test_per_rec_persistency_watched.tdb",
			DBWRAP_FLAG_PER_REC_PERSISTENT, LOWEST, MIN),
	/*
	 * LOCAL-DBWRAP-DO-LOCKED1 and LOCAL-DBWRAP-WATCH*
	 */
	DB_OPEN_FEATURE("test_do_locked.tdb",
			DBWRAP_FLAG_WATCHED, LOWEST, MIN),
	DB_OPEN_FEATURE("test_watch.tdb",
			DBWRAP_FLAG_WATCHED, LOWEST, MIN),
	/*
	 * Read-only delegations
	 */
	DB_OPEN_FEATURE("netlogon_creds_cli.tdb",
			DBWRAP_FLAG_OPTIMIZE_READONLY_ACCESS, LOWEST, MIN),
	{ .name = NULL, },
};

static const struct db_open_feature *db_open_find_feature(const char *base,
							   uint64_t flags)
{
	const struct db_open_feature *f = NULL;

	for (f = db_open_features; f->name != NULL; f++) {
		if ((f->flags & flags) == 0) {
			continue;
		}
		if (strequal(f->name, base)) {
			return f;
		}
	}

	return NULL;
}

static bool db_open_feature_active(const struct db_open_feature *f)
{
	if (f->level.major == CLUSTER_LEVEL_MAJOR_LOWEST &&
	    f->level.minor == CLUSTER_LEVEL_MAJOR_LOWEST_MINOR_MIN)
	{
		/*
		 * Always allowed, even before the level is active,
		 * e.g. for databases opened by messaging_init().
		 */
		return true;
	}

	if (!cluster_level_global_is_valid()) {
		return false;
	}

	return _cluster_level_activated(f->level.major, f->level.minor);
}

/*
 * requested_flags are the flags of the caller of db_open_ex(),
 * dbwrap_flags may also contain DBWRAP_FLAG_OPTIMIZE_READONLY_ACCESS
 * enabled by 'dbwrap_optimize_readonly:<name> = yes'.
 */
static bool db_open_check_features(const char *base,
				   uint64_t requested_flags,
				   uint64_t *dbwrap_flags)
{
	uint64_t requested_layer = *dbwrap_flags & DBWRAP_FLAG_LAYERS;
	uint64_t listed_layer = 0;
	const struct db_open_feature *f = NULL;

	/*
	 * DBWRAP_FLAG_LAYERS are all flags for a layer, at most one
	 * of them can be used, so DBWRAP_FLAG_WATCHED and
	 * DBWRAP_FLAG_G_LOCK together are not allowed,
	 * DBWRAP_FLAG_G_LOCK already includes the watched layer.
	 */
	SMB_ASSERT((requested_layer & (requested_layer - 1)) == 0);

	f = db_open_find_feature(base, DBWRAP_FLAG_LAYERS);
	if (f != NULL) {
		listed_layer = f->flags & DBWRAP_FLAG_LAYERS;
	}

	if (f == NULL) {
		/*
		 * Every database using a layer
		 * needs to be listed in db_open_features[].
		 */
		SMB_ASSERT(requested_layer == 0);
	} else if (requested_layer != listed_layer) {
		DBG_ERR("%s needs to be opened with layer 0x%" PRIx64
			", not 0x%" PRIx64 "\n",
			base,
			listed_layer,
			requested_layer);
		errno = EINVAL;
		return false;
	} else if (!db_open_feature_active(f)) {
		DBG_ERR("%s can't use layer 0x%" PRIx64
			" before cluster level %" PRIu32 ".%" PRIu32 "\n",
			base,
			listed_layer,
			f->level.major,
			f->level.minor);
		errno = ENOTSUP;
		return false;
	}

	if (*dbwrap_flags & DBWRAP_FLAG_PER_REC_PERSISTENT) {
		f = db_open_find_feature(base, DBWRAP_FLAG_PER_REC_PERSISTENT);
		/*
		 * Every database using it
		 * needs to be listed in db_open_features[].
		 */
		SMB_ASSERT(f != NULL);
		if (!db_open_feature_active(f)) {
			DBG_ERR("%s can't use per record persistency "
				"before cluster level %" PRIu32 ".%" PRIu32
				"\n",
				base,
				f->level.major,
				f->level.minor);
			errno = ENOTSUP;
			return false;
		}
	}

	if (*dbwrap_flags & DBWRAP_FLAG_OPTIMIZE_READONLY_ACCESS) {
		f = db_open_find_feature(base,
					 DBWRAP_FLAG_OPTIMIZE_READONLY_ACCESS);
		if (f == NULL) {
			/*
			 * Every database requesting it
			 * needs to be listed in db_open_features[],
			 * it's only ignored if it's enabled by
			 * 'dbwrap_optimize_readonly:<name> = yes'.
			 */
			DBG_NOTICE("%s can't use read-only delegations\n",
				   base);
			SMB_ASSERT((requested_flags &
				    DBWRAP_FLAG_OPTIMIZE_READONLY_ACCESS) == 0);
			*dbwrap_flags &= ~DBWRAP_FLAG_OPTIMIZE_READONLY_ACCESS;
		} else if (!db_open_feature_active(f)) {
			DBG_NOTICE("%s can't use read-only delegations "
				   "before cluster level %" PRIu32 ".%" PRIu32
				   "\n",
				   base,
				   f->level.major,
				   f->level.minor);
			*dbwrap_flags &= ~DBWRAP_FLAG_OPTIMIZE_READONLY_ACCESS;
		}
	}

	return true;
}

/*
 * Put the layer requested by DBWRAP_FLAG_WATCHED or
 * DBWRAP_FLAG_G_LOCK on top of the backend, so that only
 * db_open_ex() creates the layers listed in db_open_features[].
 */
static struct db_context *db_open_ex_layer(TALLOC_CTX *mem_ctx,
					    struct db_context *backend,
					    struct messaging_context *msg_ctx,
					    uint64_t dbwrap_flags)
{
	uint64_t layer = dbwrap_flags & DBWRAP_FLAG_LAYERS;
	struct db_context *db = NULL;

	if (backend == NULL || layer == 0) {
		return backend;
	}

	if (msg_ctx == NULL) {
		/*
		 * As before db_open_ex() created the layer,
		 * this may still be NULL, which is fine for
		 * readers like smbstatus.
		 */
		msg_ctx = global_messaging_context();
	}

	db = db_open_watched_layer(mem_ctx, &backend, msg_ctx, layer);
	if (db == NULL) {
		TALLOC_FREE(backend);
		errno = ENOMEM;
		return NULL;
	}

	return db;
}

/**
 * open a database
 */
struct db_context *db_open_ex(TALLOC_CTX *mem_ctx,
			      struct tevent_context *ev_ctx_ex,
			      struct messaging_context *msg_ctx_ex,
			      struct ctdbd_connection *ctdb_conn_ex,
			      const char *name,
			      int hash_size,
			      int tdb_flags,
			      int open_flags,
			      mode_t mode,
			      enum dbwrap_lock_order lock_order,
			      uint64_t dbwrap_flags)
{
	struct db_context *result = NULL;
	const char *base;
	struct loadparm_context *lp_ctx = NULL;
	bool persistent = (tdb_flags & TDB_CLEAR_IF_FIRST) == 0;
	const uint64_t requested_flags = dbwrap_flags;

	if ((lock_order != DBWRAP_LOCK_ORDER_NONE) &&
	    !DBWRAP_LOCK_ORDER_VALID(lock_order)) {
		errno = EINVAL;
		return NULL;
	}

	base = strrchr_m(name, '/');
	if (base != NULL) {
		base++;
	} else {
		base = name;
	}

	hash_size = lp_parm_int(GLOBAL_SECTION_SNUM,
				"tdb_hash_size",
				base,
				hash_size);

	if (tdb_flags & TDB_CLEAR_IF_FIRST) {
		bool try_readonly = false;

		if (dbwrap_flags & DBWRAP_FLAG_OPTIMIZE_READONLY_ACCESS) {
			try_readonly = true;
		}

		try_readonly = lp_parm_bool(-1, "dbwrap_optimize_readonly", "*", try_readonly);
		try_readonly = lp_parm_bool(-1, "dbwrap_optimize_readonly", base, try_readonly);

		if (try_readonly) {
			dbwrap_flags |= DBWRAP_FLAG_OPTIMIZE_READONLY_ACCESS;
		} else {
			dbwrap_flags &= ~DBWRAP_FLAG_OPTIMIZE_READONLY_ACCESS;
		}
	}

	if (tdb_flags & TDB_CLEAR_IF_FIRST) {
		bool try_mutex = true;
		bool require_mutex = false;

		try_mutex = lp_parm_bool(-1, "dbwrap_tdb_mutexes", "*", try_mutex);
		try_mutex = lp_parm_bool(-1, "dbwrap_tdb_mutexes", base, try_mutex);

		if (!lp_use_mmap()) {
			/*
			 * Mutexes require mmap. "use mmap = no" can
			 * be a debugging tool, so let it override the
			 * mutex parameters
			 */
			try_mutex = false;
		}

		if (try_mutex) {
			if (tdb_runtime_check_for_robust_mutexes()) {
				tdb_flags |= TDB_MUTEX_LOCKING;
#ifdef HAVE_ROBUST_MUTEXES
			} else {
				DBG_ERR("mutexes requested but not "
					"available\n");
#endif
			}
		}

		require_mutex = lp_parm_bool(-1, "dbwrap_tdb_require_mutexes",
					   "*", require_mutex);
		require_mutex = lp_parm_bool(-1, "dbwrap_tdb_require_mutexes",
					   base, require_mutex);

		if (require_mutex) {
			tdb_flags |= TDB_MUTEX_LOCKING;
		}
	}

	if (lp_clustering()) {
		struct messaging_context *msg_ctx = NULL;
		const char *sockname;

		sockname = lp_ctdbd_socket();
		if (!socket_exist(sockname)) {
			DBG_WARNING("ctdb socket does %s not exist - "
				    "is ctdb not running?\n",
				    sockname);
			return NULL;
		}

		if (msg_ctx_ex != NULL) {
			msg_ctx = msg_ctx_ex;
		} else if ((db_open_allowed && !db_open_registry_allowed) ||
			   lp_parm_bool(-1, "ctdb", base, true))
		{
			/*
			 * Initialize messaging before getting the ctdb
			 * connection, as the ctdb connection requires messaging
			 * to be initialized.
			 *
			 * We also do this for databases not using ctdb,
			 * as messaging_init() activates the cluster level,
			 * which may be needed to choose the format
			 * of the records.
			 */
			msg_ctx = global_messaging_context();
			if (msg_ctx == NULL) {
				DBG_ERR("Failed to initialize messaging\n");
				return NULL;
			}
		} else if (db_open_registry_allowed &&
			   !cluster_level_global_is_valid())
		{
			/*
			 * But not before the configuration is known,
			 * see db_open_allow(), for registry.tdb not
			 * using ctdb, while lp_smbconf_ctx() opens it,
			 * as the private dir used by messaging may
			 * still change. It uses the oldest level until
			 * lp_smbconf_ctx() forgets it again.
			 */
			cluster_level_activate_oldest();
		}

		if (!db_open_check_features(base,
					    requested_flags,
					    &dbwrap_flags))
		{
			return NULL;
		}

		/* allow ctdb for individual databases to be disabled */
		if (lp_parm_bool(-1, "ctdb", base, true)) {
			struct ctdbd_connection *conn = NULL;
			struct tevent_context *ev_ctx = NULL;
			bool allow_transactions = persistent;

			if (ev_ctx_ex != NULL) {
				ev_ctx = ev_ctx_ex;
			} else {
				ev_ctx = global_event_context();
				if (ev_ctx == NULL) {
					DBG_ERR("global_event_context() failed\n");
					return NULL;
				}
			}

			if (ctdb_conn_ex != NULL) {
				conn = ctdb_conn_ex;
			} else {
				conn = messaging_ctdb_connection();
				if (conn == NULL) {
					DBG_WARNING("No ctdb connection\n");
					errno = EIO;
					return NULL;
				}
			}

			result = db_open_ctdb_ex(mem_ctx,
						 ev_ctx,
						 msg_ctx,
						 conn,
						 persistent,
						 allow_transactions,
						 base,
						 hash_size,
						 tdb_flags,
						 open_flags,
						 mode,
						 lock_order,
						 dbwrap_flags);
			if (result == NULL) {
				DBG_ERR("failed to attach to ctdb %s\n", base);
				if (errno == 0) {
					errno = EIO;
				}
				return NULL;
			}

			return db_open_ex_layer(mem_ctx,
						result,
						msg_ctx,
						dbwrap_flags);
		}
	} else if (!cluster_level_global_is_valid()) {
		/*
		 * Without clustering the latest level is
		 * always the correct one, but it's only
		 * activated by messaging_init(). Callers
		 * without a messaging context still need
		 * to know the level in order to choose the
		 * format of the records.
		 *
		 * But the latest level is only correct once the
		 * configuration is known, see db_open_allow().
		 * While lp_smbconf_ctx() opens registry.tdb,
		 * clustering may still be enabled by the
		 * configuration, so the oldest level is used
		 * until lp_smbconf_ctx() forgets it again.
		 */
		if (db_open_registry_allowed) {
			cluster_level_activate_oldest();
		} else if (db_open_allowed) {
			cluster_level_activate_latest();
		}
	}

	if (!lp_clustering() &&
	    !db_open_check_features(base, requested_flags, &dbwrap_flags))
	{
		return NULL;
	}

	lp_ctx = loadparm_init_s3(mem_ctx, loadparm_s3_helpers());

	if (hash_size == 0) {
		hash_size = lpcfg_tdb_hash_size(lp_ctx, name);
	}
	tdb_flags = lpcfg_tdb_flags(lp_ctx, tdb_flags);

	result = dbwrap_local_open(mem_ctx,
				   name,
				   hash_size,
				   tdb_flags,
				   open_flags,
				   mode,
				   lock_order,
				   dbwrap_flags);
	talloc_unlink(mem_ctx, lp_ctx);
	return db_open_ex_layer(mem_ctx, result, msg_ctx_ex, dbwrap_flags);
}

struct db_context *db_open(TALLOC_CTX *mem_ctx,
			   const char *name,
			   int hash_size,
			   int tdb_flags,
			   int open_flags,
			   mode_t mode,
			   enum dbwrap_lock_order lock_order,
			   uint64_t dbwrap_flags)
{
	struct db_context *db = NULL;
	const char *base = NULL;
	static bool busy;

	SMB_ASSERT(!busy);

	base = strrchr_m(name, '/');
	if (base != NULL) {
		base++;
	} else {
		base = name;
	}

	/*
	 * Only g_lock_ctx_init_db() uses DBWRAP_FLAG_G_LOCK
	 * via db_open_ex(), as it also creates the g_lock
	 * context on top of the database.
	 */
	SMB_ASSERT((dbwrap_flags & DBWRAP_FLAG_G_LOCK) == 0);

	/*
	 * The configuration is needed in order to open
	 * databases, only registry.tdb is opened while
	 * the configuration is loaded, see lp_smbconf_ctx().
	 */
	SMB_ASSERT(db_open_allowed ||
		   (db_open_registry_allowed &&
		    strequal(base, "registry.tdb")));

	busy = true;
	db = db_open_ex(mem_ctx,
			NULL, /* ev_ctx_ex */
			NULL, /* msg_ctx_ex */
			NULL, /* ctdb_conn_ex */
			name,
			hash_size,
			tdb_flags,
			open_flags,
			mode,
			lock_order,
			dbwrap_flags);
	busy = false;

	return db;
}
