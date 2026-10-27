# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher <metze@samba.org> 2026
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Formats gated on the cluster functional level, across an upgrade.

Cluster level 2.0 switches a number of formats from host byte order to
little endian.  Every build reads both, but which one it writes depends
on the active level, so that a node still on the stable build never sees
a format it does not know:

  brlock.tdb                    BRLOCK_DATA_VERSION_2 records
  secrets.tdb                   SECRETS/SID/<DOMAIN> and
                                SECRETS/DOMGUID/<DOMAIN>, converted as
                                a whole by the first writer, which
                                adds SECRETS/VERSION
  MSG_SMB_NOTIFY_REC_CHANGE     and its _LE variant, smbd -> notifyd
  MSG_SMB_NOTIFY_TRIGGER        and its _LE variant, smbd -> notifyd
  MSG_PVFS_NOTIFY               and its _LE variant, notifyd -> smbd,
                                also across nodes
  MSG_SMB_NOTIFY_DB             and its _LE variant, notifyd -> notifyd
                                across nodes, after a GET_DB

Every one of them crosses a node boundary, so in a mixed cluster an
encoder of one build meets a decoder of the other.  Getting it wrong
mostly looks like nothing at all: a lock which is not seen conflicts
with nothing and a notify event which cannot be parsed is dropped.  So
each step makes the other node do something which only works if it
understood what it was given.

The steps:

 1. Roll node 1 forward, the others stay on the stable build.
 2. Byte range locks at level 1.0, with each build creating the record
    and the other one joining it.
 3. Change notify at level 1.0, watched on one build and triggered on
    the other, in both directions.  And secrets.tdb written by one
    build and read by the other, staying unconverted.
 4. Leave a lock and a watch on node 1 behind and roll the other nodes
    forward underneath them.  The restarted notifyds have to learn
    about the watch from node 1 with MSG_SMB_NOTIFY_DB.
 5. Raise the level.
 6. The lock and the watch from step 4, still in the old format, have
    to be honoured at the new level, and new locks write the new one.
    The first write to secrets.tdb converts it, and every node reads
    the same SIDs afterwards.
 7. Restart a node at the new level, so that its notifyd learns about
    the watch with MSG_SMB_NOTIFY_DB_LE.
 8. Every smbd still answers.  In a DEVELOPER build sending a message
    type which does not match the level panics, see
    messaging_cfl_check() in source3/lib/messages.c.

Unlike the other cluster tests the SMB clients run in the test process,
using samba.samba3.libsmb, because neither smbclient nor smbtorture can
hold a byte range lock or a pending notify request on one node while
something else happens on another.  That is still only an SMB client:
it loads its configuration from /dev/null, never a node's smb.conf,
and never takes a messaging context, so it cannot register anything
with ctdbd, see the docstring of samba.tests.cluster_upgrade.  It does
mean the test process has to reach the nodes by node.name.
"""

import re
import time

from samba import credentials, ntstatus, NTSTATUSError
from samba.dcerpc import security
from samba.samba3 import libsmb_samba_internal as libsmb
from samba.samba3 import param as s3param
from samba.tests.cluster_driver import Cluster, ClusterError
from samba.tests.cluster_upgrade import ClusterUpgradeTest, critical

FILE_SHARE_ALL = (libsmb.FILE_SHARE_READ |
                  libsmb.FILE_SHARE_WRITE |
                  libsmb.FILE_SHARE_DELETE)

SHARED = libsmb.SMB2_LOCK_FLAG_SHARED | libsmb.SMB2_LOCK_FLAG_FAIL_IMMEDIATELY
EXCLUSIVE = (libsmb.SMB2_LOCK_FLAG_EXCLUSIVE |
             libsmb.SMB2_LOCK_FLAG_FAIL_IMMEDIATELY)
UNLOCK = libsmb.SMB2_LOCK_FLAG_UNLOCK


class ClusterLevelFormatsTests(ClusterUpgradeTest):

    # The node rolled forward first, and one left behind until step 4.
    NEW = 1
    OLD = 0

    # Where the lock and the watch of step 4 live.  It has to be the
    # node rolled forward first: its connections have to survive the
    # upgrade of every other node.
    HOLDER = NEW

    # A notifyd broadcasts its record log once a second, see
    # notifyd_broadcast_reclog_next(), and only a peer which has seen
    # a watch can deliver an event for it.
    NOTIFY_SETTLE = 3

    # How long an event may take to arrive.
    NOTIFY_TIMEOUT = 20

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.conns = {}
        cls.carry = {}

    #
    # SMB clients
    #

    def conn(self, idx):
        """An SMB2 connection to node idx, made once and kept."""
        conn = self.conns.get(idx)
        if conn is not None:
            return conn

        # /dev/null on purpose, see the module docstring.
        lp = s3param.get_context()
        lp.load("/dev/null")
        creds = credentials.Credentials()
        creds.guess(lp)
        creds.set_domain(self.cluster.domain)
        creds.set_username(self.cluster.username)
        creds.set_password(self.cluster.password)

        node = self.nodes[idx]
        try:
            conn = libsmb.Conn(node.name, self.cluster.share, lp, creds)
        except NTSTATUSError as e:
            self.fail("connecting to %s failed: %s" % (node, e.args[1]))
        type(self).conns[idx] = conn
        return conn

    def drop_conn(self, idx):
        """Forget the connection to a node which is about to go down."""
        type(self).conns.pop(idx, None)

    def open_file(self, idx, name):
        return self.conn(idx).create(
            name,
            DesiredAccess=(security.SEC_FILE_READ_DATA |
                           security.SEC_FILE_WRITE_DATA |
                           security.SEC_STD_DELETE),
            ShareAccess=FILE_SHARE_ALL,
            CreateDisposition=libsmb.FILE_OPEN_IF)

    def open_dir(self, idx, name):
        return self.conn(idx).create(
            name,
            DesiredAccess=(security.SEC_FILE_READ_DATA |
                           security.SEC_FILE_READ_ATTRIBUTE),
            ShareAccess=FILE_SHARE_ALL,
            CreateDisposition=libsmb.FILE_OPEN_IF,
            CreateOptions=libsmb.FILE_DIRECTORY_FILE)

    def close(self, idx, fnum):
        self.conn(idx).close(fnum)

    def lock(self, idx, fnum, offset, length, flags):
        """The NTSTATUS of a single element lock request."""
        try:
            self.conn(idx).lock(fnum, [(offset, length, flags)])
        except NTSTATUSError as e:
            return e.args[0]
        return ntstatus.NT_STATUS_OK

    def assertLock(self, idx, fnum, offset, length, flags, expected, why):
        status = self.lock(idx, fnum, offset, length, flags)
        self.assertEqual(status, expected,
                         "%s: lock(%d, %d, 0x%x) on %s returned 0x%08x, "
                         "expected 0x%08x" %
                         (why, offset, length, flags, self.nodes[idx],
                          status & 0xffffffff, expected & 0xffffffff))

    def watch(self, idx, dirname):
        """Open dirname on node idx and keep a notify request pending."""
        fnum = self.open_dir(idx, dirname)
        w = {"idx": idx, "fnum": fnum, "dirname": dirname}
        self.rearm(w)
        self.conn(idx).echo()
        self.assertIsNone(w["req"].get_changes(wait=False),
                          "a fresh watch on %s already has changes" %
                          dirname)
        return w

    def rearm(self, w):
        w["req"] = self.conn(w["idx"]).notify(
            fnum=w["fnum"],
            buffer_size=0xffff,
            completion_filter=libsmb.FILE_NOTIFY_CHANGE_ALL,
            recursive=False)

    def unwatch(self, w):
        self.close(w["idx"], w["fnum"])

    def wait_for_name(self, w, name, why):
        """Wait until the watch reports a change of name.

        Not get_changes(wait=True): a lost event is exactly the failure
        this looks for, and that would wait for it forever.  echo() is
        what drives the connection while we poll.

        Once a handle has had a notify request, smbd queues changes for
        it between requests, so whatever happened since the last one
        comes first, the removal of the previous test file for
        instance.  Keep collecting until name turns up.
        """
        idx = w["idx"]
        seen = []
        deadline = time.time() + self.NOTIFY_TIMEOUT
        while True:
            self.conn(idx).echo()
            changes = w["req"].get_changes(wait=False)
            if changes is not None:
                self.rearm(w)
                seen.extend(c["name"] for c in changes)
                if name in seen:
                    return
                continue
            if time.time() >= deadline:
                self.fail("%s: no notify event for %s on %s within %ds, "
                          "saw %s" % (why, name, self.nodes[idx],
                                      self.NOTIFY_TIMEOUT, seen))
            time.sleep(0.5)

    def assertNotified(self, w, trigger, why):
        """A file created on node trigger is seen by the watch."""
        name = "%s_%d" % (why.replace(" ", "_"), int(time.time() * 1000))
        path = "%s\\%s" % (w["dirname"], name)
        fnum = self.open_file(trigger, path)
        self.close(trigger, fnum)
        try:
            self.wait_for_name(w, name, why)
        finally:
            self.conn(trigger).unlink(path)

    #
    # Administrative tools
    #

    def smbstatus(self, idx, *args):
        node = self.nodes[idx]
        return self.assertRunOk(node, ["smbstatus"] + list(args))

    def assertBrlocks(self, idx, name, vnns, why):
        """smbstatus -B on node idx shows locks on name from every vnn.

        The Pid column is vnn:pid in a cluster.  A reader which cannot
        parse the record shows nothing at all for it.
        """
        out = self.smbstatus(idx, "-B")
        seen = set()
        for line in out.splitlines():
            if name not in line:
                continue
            seen.add(line.split()[0].split(":")[0])
        for vnn in vnns:
            self.assertIn(str(vnn), seen,
                          "%s: smbstatus -B on %s has no lock from node %d "
                          "on %s, nodes seen: %s\n%s" %
                          (why, self.nodes[idx], vnn, name,
                           sorted(seen) or "none", out))

    def assertNotifyWatch(self, idx, dirname, why):
        """smbstatus -N on node idx shows a watch on dirname.

        notify_walk() asks the local notifyd with MSG_SMB_NOTIFY_GET_DB
        and gets its database back with MSG_SMB_NOTIFY_DB or
        MSG_SMB_NOTIFY_DB_LE, depending on the level.  The lines are
        path\\vnn:pid\\filter\\subdir_filter.
        """
        out = self.smbstatus(idx, "-N")
        for line in out.splitlines():
            fields = line.split("\\")
            if len(fields) < 4:
                continue
            if not fields[-4].endswith(dirname):
                continue
            if fields[-3].split(":")[0] == str(idx):
                return
        self.fail("%s: smbstatus -N on %s shows no watch on %s:\n%s" %
                  (why, self.nodes[idx], dirname, out))

    SID_RE = r"(?m)^SID for %s %s is: (S-1-\S+)$"

    def sids(self, idx):
        """The local and the domain SID, as node idx reads them."""
        node = self.nodes[idx]
        out = self.assertRunOk(node, ["net", "getdomainsid"])
        local = re.search(self.SID_RE % ("local machine", r"\S+"), out)
        domain = re.search(self.SID_RE % ("domain", r"\S+"), out)
        self.assertIsNotNone(local, "no local SID from %s:\n%s" %
                             (node, out))
        self.assertIsNotNone(domain, "no domain SID from %s:\n%s" %
                             (node, out))
        return (local.group(1), domain.group(1))

    def assertSameSids(self, why):
        """Every node reads the SIDs node 0 read at the start."""
        for idx in range(len(self.nodes)):
            self.assertEqual(self.sids(idx), self.carry["sids"],
                             "%s: %s reads other SIDs" %
                             (why, self.nodes[idx]))

    def rewrite_local_sid(self, idx):
        """Store the local SID again, unchanged, from node idx.

        Any write goes through secrets_store_format_record(), which is
        where the database is converted once the level allows it.
        """
        self.assertRunOk(self.nodes[idx],
                         ["net", "setlocalsid", self.carry["sids"][0]])

    def secrets_version_exists(self, idx):
        """Whether secrets.tdb has SECRETS/VERSION, asked on node idx.

        It is a persistent ctdb database, so every node has to give
        the same answer.
        """
        node = self.nodes[idx]
        rc, out = node.run(["dbwrap_tool", "--persistent", "secrets.tdb",
                            "exists", "SECRETS/VERSION"])
        if "does not exist" in out:
            return False
        self.assertEqual(rc, 0, "%s: dbwrap_tool failed:\n%s" % (node, out))
        self.assertIn("exists", out)
        return True

    def restart_node(self, idx):
        """Restart a node on the build it already runs.

        install() takes the node down and brings it back, which is all
        a restart is; the build does not have to change for that.
        """
        self.drop_conn(idx)
        try:
            self.nodes[idx].install(Cluster.NEW)
        except ClusterError as e:
            self.fail(str(e))

    #
    # The scenarios
    #

    def cross_node_brlocks(self, first, second, tag):
        """Two nodes lock ranges of one file, first creating the record.

        second has to parse the record first wrote to see the conflict,
        and add its own lock to it; first then has to parse what second
        wrote back.
        """
        name = "cluster_level_brl_%s.dat" % tag
        a = self.open_file(first, name)
        b = self.open_file(second, name)
        try:
            self.assertLock(first, a, 0, 10, EXCLUSIVE,
                            ntstatus.NT_STATUS_OK, tag)
            self.assertLock(second, b, 0, 10, SHARED,
                            ntstatus.NT_STATUS_LOCK_NOT_GRANTED, tag)
            self.assertLock(second, b, 10, 10, EXCLUSIVE,
                            ntstatus.NT_STATUS_OK, tag)
            self.assertLock(first, a, 10, 10, SHARED,
                            ntstatus.NT_STATUS_LOCK_NOT_GRANTED, tag)

            # Both builds read the record holding both locks.
            for idx in (first, second):
                self.assertBrlocks(idx, name, (first, second), tag)

            self.assertLock(first, a, 0, 10, UNLOCK,
                            ntstatus.NT_STATUS_OK, tag)
            self.assertLock(second, b, 0, 10, SHARED,
                            ntstatus.NT_STATUS_OK, tag)
            self.assertLock(second, b, 0, 10, UNLOCK,
                            ntstatus.NT_STATUS_OK, tag)
            self.assertLock(second, b, 10, 10, UNLOCK,
                            ntstatus.NT_STATUS_OK, tag)
        finally:
            self.close(second, b)
            self.close(first, a)
            self.conn(first).unlink(name)

    def cross_node_notify(self, watcher, trigger, tag):
        """A watch on one node sees a change made on another.

        The watch reaches the local notifyd with
        MSG_SMB_NOTIFY_REC_CHANGE and the peer notifyds with the record
        log, the change reaches the trigger node's notifyd with
        MSG_SMB_NOTIFY_TRIGGER, and the event goes back across the
        cluster to the watching smbd with MSG_PVFS_NOTIFY.
        """
        dirname = "cluster_level_notify_%s" % tag
        w = self.watch(watcher, dirname)
        try:
            self.assertNotifyWatch(watcher, dirname, tag)
            time.sleep(self.NOTIFY_SETTLE)
            self.assertNotified(w, trigger, tag)
        finally:
            self.unwatch(w)
            self.conn(watcher).rmdir(dirname)

    #
    # Step 1 - make the cluster mixed
    #

    @critical
    def test_100_starting_level_is_1_0(self):
        self.assertClusterLevel(self.START_LEVEL)

    @critical
    def test_101_upgrade_the_new_node(self):
        self.upgrade_node(self.nodes[self.NEW])

    @critical
    def test_102_the_new_node_runs_the_build_under_test(self):
        self.assertNodeBuild(self.nodes[self.NEW], new=True)

    @critical
    def test_103_the_old_node_still_runs_the_stable_build(self):
        self.assertNodeBuild(self.nodes[self.OLD], new=False)

    #
    # Step 2 - byte range locks at level 1.0
    #

    def test_200_brlocks_new_first(self):
        self.cross_node_brlocks(self.NEW, self.OLD, "mixed_newfirst")

    def test_201_brlocks_old_first(self):
        self.cross_node_brlocks(self.OLD, self.NEW, "mixed_oldfirst")

    #
    # Step 3 - change notify at level 1.0
    #

    def test_300_notify_watched_on_new_triggered_on_old(self):
        self.cross_node_notify(self.NEW, self.OLD, "mixed_new_watches")

    def test_301_notify_watched_on_old_triggered_on_new(self):
        self.cross_node_notify(self.OLD, self.NEW, "mixed_old_watches")

    def test_310_secrets_both_builds_read_the_same_sids(self):
        type(self).carry["sids"] = self.sids(self.OLD)
        self.assertEqual(self.sids(self.NEW), self.carry["sids"])

    def test_311_secrets_written_by_the_new_build_at_level_1_0(self):
        self.rewrite_local_sid(self.NEW)
        self.assertFalse(self.secrets_version_exists(self.NEW),
                         "secrets.tdb converted at level 1.0")
        self.assertEqual(self.sids(self.OLD), self.carry["sids"])

    def test_312_secrets_written_by_the_stable_build(self):
        self.rewrite_local_sid(self.OLD)
        self.assertEqual(self.sids(self.NEW), self.carry["sids"])
        self.assertFalse(self.secrets_version_exists(self.NEW))

    #
    # Step 4 - a lock and a watch which outlive the rest of the upgrade
    #

    @critical
    def test_400_leave_a_lock_and_a_watch_on_the_holder(self):
        name = "cluster_level_carry.dat"

        fnum = self.open_file(self.HOLDER, name)
        self.assertLock(self.HOLDER, fnum, 0, 10, EXCLUSIVE,
                        ntstatus.NT_STATUS_OK, "carry")
        type(self).carry = {
            "name": name,
            "fnum": fnum,
            "watch": self.watch(self.HOLDER, "cluster_level_carry"),
        }

    @critical
    def test_401_upgrade_the_other_nodes(self):
        for idx, node in enumerate(self.nodes):
            if idx == self.HOLDER:
                continue
            self.drop_conn(idx)
            self.upgrade_node(node)
        for node in self.nodes:
            self.assertNodeBuild(node, new=True)

    def test_402_the_carried_lock_is_seen_by_the_upgraded_nodes(self):
        for idx in range(len(self.nodes)):
            if idx == self.HOLDER:
                continue
            fnum = self.open_file(idx, self.carry["name"])
            try:
                self.assertLock(idx, fnum, 0, 10, SHARED,
                                ntstatus.NT_STATUS_LOCK_NOT_GRANTED,
                                "carried lock at level 1.0")
            finally:
                self.close(idx, fnum)

    def test_403_the_restarted_notifyds_know_the_carried_watch(self):
        # Each of them asked node HOLDER for its database when they
        # first saw its record log, and got it as MSG_SMB_NOTIFY_DB.
        time.sleep(self.NOTIFY_SETTLE)
        self.assertNotified(self.carry["watch"], self.OLD,
                            "carried watch at level 1.0")

    #
    # Step 5 - raise the level
    #

    @critical
    def test_500_raise_the_level(self):
        self.cluster_level_upgrade()

    @critical
    def test_501_the_level_is_the_new_one(self):
        self.requireTwoLevels()
        self.waitForClusterLevel(self.new_level)
        self.assertClusterLevel(self.new_level)

    #
    # Step 6 - the old formats at the new level, and the new ones
    #

    def test_600_the_carried_lock_is_still_honoured(self):
        self.requireTwoLevels()
        fnum = self.open_file(self.OLD, self.carry["name"])
        try:
            self.assertLock(self.OLD, fnum, 0, 10, SHARED,
                            ntstatus.NT_STATUS_LOCK_NOT_GRANTED,
                            "carried lock at the new level")
            # Rewrites the record, in the new format now.
            self.assertLock(self.OLD, fnum, 10, 10, EXCLUSIVE,
                            ntstatus.NT_STATUS_OK,
                            "carried lock at the new level")
            for idx in range(len(self.nodes)):
                self.assertBrlocks(idx, self.carry["name"],
                                   (self.HOLDER, self.OLD),
                                   "carried lock at the new level")
            self.assertLock(self.HOLDER, self.carry["fnum"], 10, 10, SHARED,
                            ntstatus.NT_STATUS_LOCK_NOT_GRANTED,
                            "carried lock at the new level")
            self.assertLock(self.OLD, fnum, 10, 10, UNLOCK,
                            ntstatus.NT_STATUS_OK,
                            "carried lock at the new level")
        finally:
            self.close(self.OLD, fnum)

    def test_601_the_carried_lock_can_be_released(self):
        self.requireTwoLevels()
        self.assertLock(self.HOLDER, self.carry["fnum"], 0, 10, UNLOCK,
                        ntstatus.NT_STATUS_OK, "carried lock released")
        fnum = self.open_file(self.OLD, self.carry["name"])
        try:
            self.assertLock(self.OLD, fnum, 0, 10, EXCLUSIVE,
                            ntstatus.NT_STATUS_OK, "carried lock released")
            self.assertLock(self.OLD, fnum, 0, 10, UNLOCK,
                            ntstatus.NT_STATUS_OK, "carried lock released")
        finally:
            self.close(self.OLD, fnum)

    def test_602_the_carried_watch_still_fires(self):
        self.requireTwoLevels()
        self.assertNotified(self.carry["watch"], self.OLD,
                            "carried watch at the new level")

    def test_603_brlocks_at_the_new_level(self):
        self.requireTwoLevels()
        self.cross_node_brlocks(self.NEW, self.OLD, "new_level")

    def test_604_notify_at_the_new_level(self):
        self.requireTwoLevels()
        self.cross_node_notify(self.OLD, self.NEW, "new_level")

    def test_610_secrets_converted_by_the_first_write(self):
        self.requireTwoLevels()
        self.rewrite_local_sid(self.NEW)
        for idx in range(len(self.nodes)):
            self.assertTrue(self.secrets_version_exists(idx),
                            "secrets.tdb not converted, asked on %s" %
                            self.nodes[idx])
        self.assertSameSids("converted secrets.tdb")

    def test_611_secrets_written_after_the_conversion(self):
        self.requireTwoLevels()
        self.rewrite_local_sid(self.OLD)
        self.assertSameSids("secrets.tdb written after the conversion")

    #
    # Step 7 - a notifyd which learns the watch at the new level
    #

    @critical
    def test_700_restart_a_node_at_the_new_level(self):
        self.requireTwoLevels()
        self.restart_node(self.OLD)

    def test_701_the_restarted_notifyd_knows_the_carried_watch(self):
        self.requireTwoLevels()
        # It asked node HOLDER for its database again, and got it as
        # MSG_SMB_NOTIFY_DB_LE this time.
        time.sleep(self.NOTIFY_SETTLE)
        self.assertNotified(self.carry["watch"], self.OLD,
                            "carried watch after a restart")

    def test_702_smbstatus_shows_the_carried_watch(self):
        self.requireTwoLevels()
        self.assertNotifyWatch(self.HOLDER,
                               self.carry["watch"]["dirname"],
                               "carried watch after a restart")

    #
    # Step 8 - nothing panicked on the way
    #

    def test_800_release_the_carried_handles(self):
        self.unwatch(self.carry["watch"])
        self.close(self.HOLDER, self.carry["fnum"])
        self.conn(self.HOLDER).unlink(self.carry["name"])
        self.conn(self.HOLDER).rmdir(self.carry["watch"]["dirname"])

    def test_801_every_smbd_still_answers(self):
        for node in self.nodes:
            out = self.assertRunOk(node, ["smbcontrol", "smbd", "ping"])
            self.assertRegex(out, r"(?m)^PONG from pid ",
                             "%s did not answer" % node)
