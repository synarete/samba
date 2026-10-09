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


"""Parsing of "net clusterlevel" output in samba.tests.cluster_driver."""

import samba.tests
from samba.tests.cluster_driver import (
    format_level,
    highest_level,
    parse_node_ranges,
    parse_ranges,
)

FEATURES = """Cluster support features:
   CLUSTER_SUPPORT
   Cluster Functional Levels:
%s"""


class ClusterLevelParseTests(samba.tests.TestCase):

    def test_features_one_range(self):
        ranges = parse_ranges(FEATURES % "      1.0 -> 1.0\n")
        self.assertEqual(ranges, [(1, 0, 0)])
        self.assertEqual(format_level(highest_level(ranges)), "1.0")

    def test_features_two_ranges(self):
        ranges = parse_ranges(FEATURES %
                              "      2.0 -> 2.0\n      1.0 -> 1.0\n")
        self.assertEqual(ranges, [(2, 0, 0), (1, 0, 0)])
        self.assertEqual(format_level(highest_level(ranges)), "2.0")

    def test_features_minor_bump(self):
        # A new minor level widens a range instead of adding one.
        ranges = parse_ranges(FEATURES %
                              "      2.0 -> 2.1\n      1.0 -> 1.0\n")
        self.assertEqual(ranges, [(2, 0, 1), (1, 0, 0)])
        self.assertEqual(format_level(highest_level(ranges)), "2.1")
        self.assertGreater(highest_level(ranges), (2, 0))

    def test_showall(self):
        out = ("Node[0] supported_ranges[1]\n"
               "    supported_range: 1.0 -> 1.0\n"
               "Node[1] supported_ranges[2]\n"
               "    supported_range: 2.0 -> 2.0\n"
               "    supported_range: 1.0 -> 1.0\n"
               "Node[2] supported_ranges[2]\n"
               "    supported_range: 2.0 -> 2.1\n"
               "    supported_range: 1.0 -> 1.0\n"
               "Active cluster functional level: 1.0\n"
               "Highest supported cluster functional level: 2.1\n")
        self.assertEqual(parse_node_ranges(out), {
            0: [(1, 0, 0)],
            1: [(2, 0, 0), (1, 0, 0)],
            2: [(2, 0, 1), (1, 0, 0)],
        })
