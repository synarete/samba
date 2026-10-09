# Unix SMB/CIFS implementation.
# Copyright (C) Shachar Sharon <ssharon@redhat.com> 2026
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

"""A rolling upgrade of a cluster, under load and without an outage.

The cfl_upgrade environment starts with every node on the latest stable
build at cluster functional level 1.0, which is the only level both
builds serve.  That is a cluster before an upgrade, and this is the
upgrade:

 1. Baseline: all three nodes serve SMB and answer smbcontrol, every
    node runs the stable build, and the level cannot be raised because
    nothing offers more than 1.0.
 2. Put the cluster under load on node 0: an smbtorture open/close
    benchmark and a wbinfo loop.
 3. Roll nodes 1 and 2 forward to the build under test, under that load.
    In between, the level still cannot be raised, now because the nodes
    disagree about what they offer -- which is the case
    cluster_level_db_upgrade() exists for -- and smbcontrol is checked
    once more, this time from an upgraded node whose peers are still
    behind.
 4. Hand the load over to node 1: start there, then stop on node 0.
    Node 0 is next, and with no public addresses nothing fails over.
 5. Roll node 0 forward, the last one.  Now the level can be raised.
 6. Raise the level with the load still running.
 7. Check service at the new level, and that the load started in step 4
    came through the node 0 upgrade and the level change alive.

The order is the one a rolling upgrade has: binaries first, level last.
No level is named anywhere: the test asks the build what it offers, and
the steps which need something to upgrade to skip themselves on a build
which offers one level.

The steps run in name order and share the cluster, so they are numbered
by the step they belong to.
"""

from samba.tests.cluster_upgrade import ClusterUpgradeTest, critical


class ClusterRollingUpgradeTests(ClusterUpgradeTest):

    #
    # Step 1 - baseline on the all stable cluster at the old level
    #

    @critical
    def test_100_starting_level_is_1_0(self):
        # If the starting level is wrong the environment was not set up
        # correctly and every later step is meaningless.
        self.assertClusterLevel("1.0")

    @critical
    def test_101_every_node_runs_the_stable_build(self):
        for node in self.nodes:
            self.assertNodeBuild(node, new=False)

    def test_102_no_node_offers_more_than_1_0(self):
        self.assertSupportedRanges("stable")

    def test_103_upgrade_test_has_nothing_to_do(self):
        self.assertUpgradeTest("already")

    def test_104_every_node_serves_smb(self):
        for node in self.nodes:
            self.assertSmbService(node)

    def test_105_file_io_on_node0(self):
        self.assertFileIO(self.nodes[0])

    # Every node runs the stable build, so this is the behaviour the
    # upgraded cluster has to still have at the end.

    def test_110_ping_at_the_old_level(self):
        self.assertSmbcontrolPing()

    def test_111_debug_at_the_old_level(self):
        self.assertSmbcontrolDebug(3)

    def test_112_debuglevel_at_the_old_level(self):
        self.assertSmbcontrolDebuglevel()

    def test_113_profile_at_the_old_level(self):
        self.assertSmbcontrolProfile("off")

    def test_114_profilelevel_at_the_old_level(self):
        self.assertSmbcontrolProfilelevel()

    #
    # Step 2 - put the cluster under load, on node 0
    #

    @critical
    def test_200_start_load_on_node0(self):
        self.start_load("a", self.nodes[0])

    #
    # Step 3 - roll nodes 1 and 2 forward, under that load
    #

    @critical
    def test_300_upgrade_node1(self):
        self.upgrade_node(self.nodes[1])

    def test_301_node1_runs_the_build_under_test(self):
        self.assertNodeBuild(self.nodes[1], new=True)

    def test_302_node1_serves_smb(self):
        self.assertSmbService(self.nodes[1])

    def test_303_nodes_disagree_about_the_levels_they_offer(self):
        # Drive the rest from node 1.  "upgrade --test" works out the
        # level to go to from the ranges of the process running it, so
        # asked on a node which still offers only 1.0 it reports nothing
        # to do rather than the disagreement we are after.
        self.set_admin_node(1)
        self.assertSupportedRanges("mixed")

    def test_304_upgrade_test_refuses_a_mixed_cluster(self):
        self.assertUpgradeTest("mismatch")

    # Messaging from the build under test while its peers are still on
    # the stable one.  The checks in steps 1 and 7 are both ends of the
    # upgrade, where every node runs the same build and a message never
    # crosses a version boundary; here one does, and in the direction a
    # rolling upgrade spends its time in.  Node 1 is the only upgraded
    # node and, since test_303, the one the tools run on.

    def test_305_ping_on_a_mixed_cluster(self):
        self.assertSmbcontrolPing()

    def test_306_debug_on_a_mixed_cluster(self):
        self.assertSmbcontrolDebug(3)

    def test_307_debuglevel_on_a_mixed_cluster(self):
        self.assertSmbcontrolDebuglevel()

    def test_308_profile_on_a_mixed_cluster(self):
        self.assertSmbcontrolProfile("off")

    def test_309_profilelevel_on_a_mixed_cluster(self):
        self.assertSmbcontrolProfilelevel()

    @critical
    def test_310_upgrade_node2(self):
        self.upgrade_node(self.nodes[2])

    def test_311_node2_runs_the_build_under_test(self):
        self.assertNodeBuild(self.nodes[2], new=True)

    def test_312_node2_serves_smb(self):
        self.assertSmbService(self.nodes[2])

    def test_313_node0_still_offers_only_1_0(self):
        self.assertSupportedRanges("mixed")

    def test_314_upgrade_test_still_refuses_with_node0_behind(self):
        self.assertUpgradeTest("mismatch")

    #
    # Step 4 - hand the load over to an upgraded node
    #

    @critical
    def test_400_start_load_on_node1(self):
        # Start on node 1 before stopping on node 0, so the cluster stays
        # busy across the handover.
        self.start_load("b", self.nodes[1])

    def test_401_the_node0_load_survived_both_upgrades(self):
        # Node 0 is next and a connection to it would simply break, so
        # its clients come down now.
        self.stop_load("a")

    #
    # Step 5 - roll node 0 forward, the last one
    #

    @critical
    def test_500_upgrade_node0(self):
        self.upgrade_node(self.nodes[0])

    def test_501_node0_runs_the_build_under_test(self):
        self.assertNodeBuild(self.nodes[0], new=True)

    def test_502_node0_serves_smb(self):
        self.assertSmbService(self.nodes[0])

    def test_503_every_node_offers_the_new_level(self):
        self.assertSupportedRanges("uniform")

    def test_504_upgrade_test_accepts_a_uniform_cluster(self):
        self.assertUpgradeTest("possible")

    #
    # Step 6 - raise the level, with the load still running
    #

    @critical
    def test_600_raise_the_level(self):
        self.cluster_level_upgrade()

    @critical
    def test_601_the_level_is_the_new_one(self):
        self.requireTwoLevels()
        self.waitForClusterLevel(self.new_level)
        self.assertClusterLevel(self.new_level)

    #
    # Step 7 - messaging and continued service at the new level
    #

    # smbcontrol at the new level, which is where a format gated on a
    # level would be exercised once there is one.

    def test_710_ping_at_the_new_level(self):
        self.assertSmbcontrolPing()

    def test_711_debug_at_the_new_level(self):
        self.assertSmbcontrolDebug(3)

    def test_712_debuglevel_at_the_new_level(self):
        self.assertSmbcontrolDebuglevel()

    def test_713_profile_at_the_new_level(self):
        self.assertSmbcontrolProfile("off")

    def test_714_profilelevel_at_the_new_level(self):
        self.assertSmbcontrolProfilelevel()

    def test_720_the_node1_load_survived_the_level_change(self):
        # It has been running since step 4, so it spanned the node 0
        # upgrade and the level change.
        self.stop_load("b")

    def test_730_every_node_serves_smb(self):
        for node in self.nodes:
            self.assertSmbService(node)

    def test_731_file_io_on_every_node(self):
        for node in self.nodes:
            self.assertFileIO(node)
