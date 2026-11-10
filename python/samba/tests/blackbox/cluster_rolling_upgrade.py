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
build, at the highest cluster functional level that build offers.  That
is a cluster before an upgrade, and this is the upgrade:

 1. Baseline: all three nodes serve SMB and answer smbcontrol, every
    node runs the stable build, and the level cannot be raised because
    nothing offers more than the active level.
 2. Put the cluster under load on node 0: an smbtorture open/close
    benchmark and a wbinfo loop.
 3. Roll nodes 1 and 2 forward to the build under test, under that load.  In
    between, the level still cannot be raised, and smbcontrol is checked once
    more, with messages between every pair of nodes crossing between the
    two builds.
 4. Hand the load over to node 1: start there, then stop on node 0.
 5. Upgrade node 0, the last one.  Now the level can be raised.
 6. Raise the functional level with the load still running.
 7. Check service at the new level, and that the load started in step 4
    came through the node 0 upgrade and the level change alive.

The steps run in name order and share the cluster, so they are numbered
by the step they belong to.
"""

from samba.tests.cluster_upgrade import ClusterUpgradeTest, critical


class ClusterRollingUpgradeTests(ClusterUpgradeTest):

    #
    # Step 1 - baseline on the all stable cluster at the old level
    #

    @critical
    def test_100_starting_level_is_the_stable_builds_highest(self):
        # A fresh cluster starts at the highest level of the build its
        # first node runs; anything else means the setup is broken.
        self.assertClusterLevel(self.start_level)

    @critical
    def test_101_every_node_runs_the_stable_build(self):
        for node in self.nodes:
            self.assertNodeBuild(node, new=False)

    def test_102_every_node_offers_the_stable_ranges(self):
        self.assertSupportedRanges("stable")

    def test_103_upgrade_test_has_nothing_to_do(self):
        self.assertUpgradeTest("already")

    def test_104_every_node_serves_smb(self):
        for node in self.nodes:
            self.assertSmbService(node)

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
        # on a node still on the stable build it reports nothing to do
        # rather than the disagreement checked here.
        self.set_admin_node(1)
        self.assertSupportedRanges("mixed")

    def test_304_upgrade_test_refuses_a_mixed_cluster(self):
        self.assertUpgradeTest("mismatch")

    # smbcontrol from every node to every node's smbd while node 1 runs
    # the build under test and its peers the stable one, so messages
    # cross between the builds in both directions.  In steps 1 and 7
    # every node runs the same build.

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

    def test_313_node0_still_offers_the_stable_ranges(self):
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
        self.requireLevelBump()
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
