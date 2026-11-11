# Unix SMB/CIFS implementation.
# Copyright (C) Ralph Boehme <slow@samba.org> 2026
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

"""Open the same file from two cluster nodes running different builds.

Whichever node opens first creates the locking.tdb record; the other one
has to parse it, add its own entry and write it back, and then both have
to read the result.  With the two nodes on different Samba builds those
are two different encoders, so this covers the on disk encoding from both
sides, which a single version cluster cannot.

The record has two parts: the share_mode_data blob, which the node that
creates the record encodes, and one share entry per open.  A node that
joins an existing record only adds its entry, and
share_mode_data_ltdb_store() stores the blob unchanged unless
d->modified is set.  So a build's encoding of the blob is only tested
when that build creates the record, and the test runs both orders.

The cfl_upgrade environment starts with every node on the latest stable
build, so the test makes the cluster mixed itself: it rolls node 1
forward and leaves nodes 0 and 2 behind.  That is a cluster part way
through a rolling upgrade, which is the only time a real cluster runs two
versions at once.
"""

from samba.dcerpc import security
from samba.samba3 import libsmb_samba_internal as libsmb
from samba.tests.cluster_upgrade import ClusterUpgradeTest, critical


class ClusterCrossNodeLockingTests(ClusterUpgradeTest):

    # The node rolled forward, and one of the two left behind.  The
    # record has to be written and read correctly by both.
    NEW = 1
    OLD = 0

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.locks = {}

    def open_from_both_nodes(self, first, second, tag):
        """Open one file from two nodes, first creating the record.

        Both opens are held while smbstatus on each node reads the record.
        """
        name = "cross_node_locking_%s.txt" % tag
        a = self.cluster.smb_conn(first)
        b = self.cluster.smb_conn(second)
        a.savefile(name, b"Hello World!\n")

        opened = []
        try:
            for conn in (a, b):
                # Read access is enough for an entry in the record.
                fnum = conn.create(
                    name,
                    DesiredAccess=security.SEC_FILE_READ_DATA,
                    ShareAccess=(libsmb.FILE_SHARE_READ |
                                 libsmb.FILE_SHARE_WRITE),
                    CreateDisposition=libsmb.FILE_OPEN)
                opened.append((conn, fnum))

            # Read the record with each node's own build: a reader which
            # cannot parse what the other build wrote shows neither node.
            locks = {}
            for which, idx in (("new", self.NEW), ("old", self.OLD)):
                rc, out = self.nodes[idx].run(["smbstatus", "--locks"])
                locks[which] = out
            type(self).locks[tag] = locks
        finally:
            for conn, fnum in opened:
                conn.close(fnum)
            a.unlink(name)

        self.assertTrue(locks["new"].strip(),
                        "no output from the build under test's smbstatus")
        self.assertTrue(locks["old"].strip(),
                        "no output from the stable build's smbstatus")

    def assertRecordReadable(self, tag, which):
        """Both nodes appear in the record, as read by one of the builds.

        What matters is that the record holds an open from each node and
        that both builds can read it, not the exact number of lines.  A
        reader which cannot parse the record shows neither node, and a
        writer which loses the other node's entry shows one, so both
        still fail here.
        """
        what = {"new": "build under test",
                "old": "stable build"}[which]
        name = "cross_node_locking_%s.txt" % tag
        out = self.locks[tag][which]

        self.assertIn("Locked files:", out,
                      "the %s smbstatus printed no locked files:\n%s" %
                      (what, out))

        # The Pid column is node:pid in a cluster.
        seen = set()
        for line in out.splitlines():
            if name not in line:
                continue
            pid = line.split()[0]
            seen.add(pid.split(":")[0])

        for want in (self.NEW, self.OLD):
            self.assertIn(str(want), seen,
                          "the %s smbstatus has no node %d entry for %s, "
                          "nodes seen: %s\n%s" %
                          (what, want, name, sorted(seen) or "none", out))

    #
    # Make the cluster mixed: node NEW forward, the others left behind.
    #

    @critical
    def test_100_upgrade_the_new_node(self):
        self.upgrade_node(self.nodes[self.NEW])

    @critical
    def test_101_the_new_node_runs_the_build_under_test(self):
        self.assertNodeBuild(self.nodes[self.NEW], new=True)

    @critical
    def test_102_the_old_node_still_runs_the_stable_build(self):
        self.assertNodeBuild(self.nodes[self.OLD], new=False)

    #
    # The build under test creates the record, the stable build joins it
    #

    @critical
    def test_200_the_new_node_creates_the_record(self):
        self.open_from_both_nodes(self.nodes[self.NEW], self.nodes[self.OLD],
                                  "newfirst")

    def test_201_the_build_under_test_reads_the_newfirst_record(self):
        self.assertRecordReadable("newfirst", "new")

    def test_202_the_stable_build_reads_the_newfirst_record(self):
        self.assertRecordReadable("newfirst", "old")

    #
    # The stable build creates the record, the build under test joins it
    #

    @critical
    def test_300_the_old_node_creates_the_record(self):
        self.open_from_both_nodes(self.nodes[self.OLD], self.nodes[self.NEW],
                                  "oldfirst")

    def test_301_the_build_under_test_reads_the_oldfirst_record(self):
        self.assertRecordReadable("oldfirst", "new")

    def test_302_the_stable_build_reads_the_oldfirst_record(self):
        self.assertRecordReadable("oldfirst", "old")
