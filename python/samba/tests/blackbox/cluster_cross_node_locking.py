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

Both orders are needed, and that is not obvious.  A writer which ignores
the record it is joining fails only the case where it created the record
itself: when it merely joins an existing one it does not regenerate the
data blob at all, because share_mode_data_ltdb_store() skips that unless
d->modified, so the stored version keeps the value it was parsed with.
With only the first order such a bug goes unnoticed.

The cfl_upgrade environment starts with every node on the latest stable
build, so the test makes the cluster mixed itself: it rolls node 1
forward and leaves nodes 0 and 2 behind.  That is a cluster part way
through a rolling upgrade, which is the only time a real cluster runs two
versions at once.
"""

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
        """Open one file from two nodes, $first creating the record.

        Both clients are kept running while smbstatus looks at the
        record, the way test_aio_outstanding.sh does.  Driving a second
        smbclient from inside the first one's command list, with "!", put
        the two of them on the same stdin and made what each of them read
        depend on timing.
        """
        name = "cross_node_locking_%s.txt" % tag
        src = self.workpath(name)
        self.cluster.client_write(first, src, "Hello World!\n")

        a = self.smbclient_interactive(first, "%s-a.log" % tag)
        b = self.smbclient_interactive(second, "%s-b.log" % tag)
        try:
            self.smbclient_send(a, "put %s %s" % (src, name))
            self.smbclient_send(a, "open %s" % name)
            self.smbclient_send(b, "open %s" % name)

            # Read the record back with each node's own build, which is
            # the point: a reader which cannot parse what the other
            # version wrote shows neither node.
            locks = {}
            for which, idx in (("new", self.NEW), ("old", self.OLD)):
                node = self.nodes[idx]
                rc, out = node.run(["smbstatus", "--locks"])
                locks[which] = out
            type(self).locks[tag] = locks
        finally:
            for client in (a, b):
                self.smbclient_send(client, "close 1", settle=0)
                self.smbclient_quit(client)

        self.assertTrue(locks["new"].strip(),
                        "no output from the build under test's smbstatus\n"
                        "%s\n%s" % (self.client_log(a), self.client_log(b)))
        self.assertTrue(locks["old"].strip(),
                        "no output from the stable build's smbstatus\n"
                        "%s\n%s" % (self.client_log(a), self.client_log(b)))

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
