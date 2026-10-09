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

"""Base class for cluster rolling upgrade tests.

The tests get their cluster from samba.tests.cluster_driver and only use
its interfaces, so they run against the selftest cluster and, with
another driver, against a real cluster.

Each test class starts with every node on the stable build, at the highest
cluster functional level that build offers.  upgrade_node() moves one node
to the build under test, cluster_level_upgrade() raises the level once all
nodes support it.  Not every release adds a level, so the steps which need
one use requireLevelBump().

Test methods run in name order and share the cluster, so they are
numbered steps that build on each other.  State that spans steps, such
as the background load, is kept on the class.

The test process never opens a clustered database itself.  Opening one
goes through dbwrap_open() to global_messaging_context() and
cluster_level_db_check_or_update(), which would store the levels of the
build the test imports as those of the node it is attached to.  All Samba
operations therefore run as separate processes.
"""

import functools
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from unittest import SkipTest

import samba.tests
from samba import NTSTATUSError
from samba.tests.cluster_driver import (
    Cluster,
    ClusterError,
    format_level,
    highest_level,
    make_cluster,
    parse_node_ranges,
    parse_ranges,
)


def critical(func):
    """Mark a step that the later steps depend on.

    If the step fails, setUp() skips the remaining steps of the class, so
    a failed upgrade is reported once rather than by every later step.
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except SkipTest:
            raise
        except Exception:
            type(self).blocked = "%s failed" % func.__name__
            raise
    return wrapper


class Load:
    """Background SMB and winbind traffic against one node.

    Runs an smbtorture open/close benchmark, which exercises the
    clustered share mode and lock records, and a wbinfo loop against
    winbindd on the node.  Stop the load before the node goes down: the
    cluster has no public addresses and the clients use no persistent
    handles, so a dropped connection is not recovered.

    The benchmark gets a time limit longer than any test window and is
    killed by stop(); the test checks that it was still running then.
    """

    # Longer than the longest window a test opens.
    TIMELIMIT = 900

    # A node leaving or rejoining the cluster freezes the databases
    # during recovery, so wbinfo can fail briefly on a node that is not
    # being upgraded.  Only consecutive failures count.
    MAX_CONSECUTIVE_FAILURES = 5

    def __init__(self, cluster, node, logpath, basedir):
        self.cluster = cluster
        self.node = node
        self.logpath = logpath
        self.basedir = basedir
        self.rounds = 0
        self.wbinfo_error = None

        # A directory per load: stop() removes it, and loads overlap,
        # the node 1 load starts before the node 0 one is stopped.
        os.makedirs(basedir, exist_ok=True)

        self.bench_log = open(logpath, "w")
        self.bench = cluster.client_popen(
            # --basedir: without it smbtorture creates its output
            # directory in the current directory, see
            # torture_context_init(), which may not be writable:
            #
            #   torture_context_init() failed: Permission denied
            ["smbtorture", "--basedir=%s" % basedir, cluster.unc(node),
             cluster.creds(),
             "--option=torture:timelimit=%d" % self.TIMELIMIT,
             "smb2.bench.path-contention-shared"],
            stdout=self.bench_log, stderr=subprocess.STDOUT)

        self.stopping = threading.Event()
        self.wbinfo = threading.Thread(target=self._wbinfo_loop, daemon=True)
        self.wbinfo.start()

    def _wbinfo_loop(self):
        consecutive = 0
        while not self.stopping.is_set():
            for arg in ("-p", "-P", "-u"):
                rc, out = self.node.run(["wbinfo", arg])
                if rc != 0:
                    break
            if rc == 0:
                consecutive = 0
                self.rounds += 1
            else:
                consecutive += 1
                if consecutive >= self.MAX_CONSECUTIVE_FAILURES:
                    self.wbinfo_error = (
                        "wbinfo %s failed %d times in a row on %s:\n%s" %
                        (arg, consecutive, self.node, out))
                    return
            self.stopping.wait(1)

    def alive(self):
        """Why the load is not still running, or None if it is."""
        if self.bench.poll() is not None:
            return ("the smbtorture benchmark on %s exited early (%s):\n%s" %
                    (self.node, self.bench.returncode, self.tail()))
        if self.wbinfo_error is not None:
            return self.wbinfo_error
        if not self.wbinfo.is_alive():
            return "the wbinfo loop on %s stopped" % self.node
        # It must also have completed rounds.
        if self.rounds == 0:
            return "the wbinfo loop on %s completed no rounds" % self.node
        return None

    def stop(self):
        self.stopping.set()
        self.wbinfo.join(timeout=30)
        self.bench.terminate()
        try:
            self.bench.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.bench.kill()
            self.bench.wait()
        self.bench_log.close()

        # smbtorture removes its output directory when it finishes, see
        # torture_deltree_outputdir(), but it is killed here.
        shutil.rmtree(self.basedir, ignore_errors=True)

    def tail(self, lines=20):
        try:
            with open(self.logpath, errors="replace") as f:
                return "".join(f.readlines()[-lines:])
        except OSError:
            return ""


class ClusterUpgradeTest(samba.tests.TestCase):
    """A cluster in the state before an upgrade, and ways to drive it."""

    # Set by @critical when a step the rest depends on fails.
    blocked = None

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()

        cls.cluster = make_cluster()
        cls.cluster.reset()

        cls.nodes = cls.cluster.nodes
        cls.admin = cls.nodes[0]

        # The ranges each build offers.  Every node runs the stable build
        # now, so ask one of them.  A fresh cluster starts at the highest
        # level of the build its first node runs.
        cls.new_ranges = cls.cluster.new_ranges
        rc, out = cls.admin.run(["net", "clusterlevel", "features"])
        cls.stable_ranges = parse_ranges(out)
        if rc != 0 or not cls.stable_ranges:
            raise ClusterError("no cluster functional level from the "
                               "stable build on %s:\n%s" % (cls.admin, out))
        new = highest_level(cls.new_ranges)
        start = highest_level(cls.stable_ranges)
        cls.new_level = format_level(new)
        cls.start_level = format_level(start)
        # Whether the build under test adds a level to upgrade to.
        cls.level_bump = new > start
        cls.loads = {}
        # Files of the test, its clients and the processes it starts.
        # Kept after the test, for a look at the client logs.
        cls.workdir = tempfile.mkdtemp(prefix="%s-" % cls.__name__,
                                       dir=os.environ.get("SELFTEST_TMPDIR"))

    @classmethod
    def tearDownClass(cls):
        # Loads whose stop step was skipped after a failed @critical step
        for load in getattr(cls, "loads", {}).values():
            load.stop()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        if self.blocked is not None:
            self.skipTest(self.blocked)

    def workpath(self, name):
        """A file in the test's directory on this machine."""
        return os.path.join(self.workdir, name)

    #
    # Running things
    #

    def assertRunOk(self, node, argv, env=None, msg=None):
        """Run an administrative tool on a node, fail unless it succeeds."""
        rc, out = node.run(argv, env=env)
        text = "%s: %s\n%s" % (node, " ".join(argv), out)
        self.assertEqual(rc, 0, "%s\n%s" % (msg, text) if msg else text)
        return out

    #
    # Addressing the cluster
    #

    def set_admin_node(self, idx):
        """Run net and smbcontrol on this node from now on.

        They connect to the cluster, so they must come from the build the
        node runs, see the module docstring of samba.tests.cluster_driver.
        """
        type(self).admin = self.nodes[idx]
        print("driving the cluster from %s" % self.admin)

    def net(self, *args):
        return self.admin.run(["net"] + list(args))

    def smbcontrol(self, *args):
        return self.admin.run(["smbcontrol"] + list(args))

    #
    # Assertions about one node
    #

    def assertSmbService(self, node):
        """The node serves SMB: a file written to it reads back unchanged."""
        name = "cluster_upgrade_io_%d.tmp" % os.getpid()
        content = b"cluster upgrade I/O test\n"
        try:
            conn = self.cluster.smb_conn(node)
            conn.savefile(name, content)
            try:
                got = conn.loadfile(name)
            finally:
                conn.unlink(name)
        except NTSTATUSError as e:
            self.fail("%s does not serve SMB: %s" % (node, e))
        self.assertEqual(got, content, "%s read back something else" % node)

    def assertNodeBuild(self, node, new):
        """Check the node runs the build under test (new) or the stable one.

        Every daemon the driver reports on must agree.  ctdbd is checked
        as well as smbd, so a node with only smbd upgraded fails here
        instead of later, when raising the level fails.
        """
        versions = node.running_versions()

        why = ["%s should be running the %s build" %
               (node, "new" if new else "stable"),
               "build under test: %s" % self.cluster.new_version]
        for daemon, version in sorted(versions.items()):
            why.append("%s: %s" % (daemon, version or "<nothing reported>"))
        why = "\n".join(why)

        for version in versions.values():
            self.assertIsNotNone(version, why)
            self.assertEqual(version == self.cluster.new_version, new, why)

    #
    # Assertions about the cluster level
    #

    def assertClusterLevel(self, expected):
        rc, out = self.net("clusterlevel", "show")
        self.assertEqual(rc, 0, out)
        self.assertIn(expected, out)

    def waitForClusterLevel(self, expected, timeout=10):
        """Poll until "net clusterlevel show" reports the expected level.

        Raising the level sends MSG_CLUSTER_LEVEL_UPGRADED and each smbd
        updates its cached level when it arrives, so the old level can
        still be reported for a moment.
        """
        deadline = time.time() + timeout
        while True:
            rc, out = self.net("clusterlevel", "show")
            if rc == 0 and expected in out:
                return
            if time.time() >= deadline:
                self.fail("cluster level %s not reached within %ds:\n%s" %
                          (expected, timeout, out))
            time.sleep(1)

    def requireLevelBump(self):
        """Skip the test if the build under test adds no level.

        A release only adds a cluster functional level when a format
        shared between nodes changes.  Without one there is nothing to
        upgrade to; the rest of the rolling upgrade still runs.
        """
        if not self.level_bump:
            self.skipTest("the build under test offers no cluster "
                          "functional level above %s" % self.start_level)

    def upgradeTestExpectation(self, expect):
        """What "net clusterlevel upgrade --test" has to say, and when.

        "already": every node runs the stable build, which offers no level
        above the active one.  "mismatch": during the rolling upgrade
        cluster_level_db_upgrade() refuses, as it requires the stored
        ranges of all nodes to be identical, and reports the differing
        node in error_vnn.  "possible": every node runs this build.  The
        last two need a level bump.
        """
        return {
            "already": (False,
                        "Already at active cluster functional level: %s"
                        % self.start_level),
            "mismatch": (False, "NT_STATUS_REVISION_MISMATCH"),
            "possible": (True,
                         "Upgrade possible from cluster functional level "
                         "%s to %s" % (self.start_level, self.new_level)),
        }[expect]

    def assertUpgradeTest(self, expect):
        if expect != "already":
            self.requireLevelBump()
        want_ok, needle = self.upgradeTestExpectation(expect)
        rc, out = self.net("clusterlevel", "upgrade", "--test")
        why = "asked on %s\n%s" % (self.admin, out)
        self.assertEqual(rc == 0, want_ok, why)
        self.assertIn(needle, out, why)

    def assertSupportedRanges(self, expect):
        """Check what "net clusterlevel showall" reports for the nodes.

        Each node reports the ranges of the build it runs.  "stable":
        every node reports the stable build's ranges.  "mixed": some, but
        not all, report those of the build under test; that needs a level
        bump, without one the builds report the same ranges.  "uniform":
        every node reports those of the build under test.

        The summary only has an upgrade line when some node offers a
        level above the active one: "Highest supported" while not every
        node does, "Upgrade possible" once they all do.
        """
        if expect == "mixed":
            self.requireLevelBump()
        rc, out = self.net("clusterlevel", "showall")
        self.assertEqual(rc, 0, out)
        why = "asked on %s\n%s" % (self.admin, out)

        nodes = parse_node_ranges(out)
        self.assertEqual(len(nodes), len(self.nodes), why)
        on_new = len([r for r in nodes.values() if r == self.new_ranges])

        highest = ("Highest supported cluster functional level: %s"
                   % self.new_level)
        possible = ("Upgrade possible to cluster functional level: %s"
                    % self.new_level)

        if expect == "stable":
            for ranges in nodes.values():
                self.assertEqual(ranges, self.stable_ranges, why)
            self.assertNotIn("Highest supported", out, why)
            self.assertNotIn("Upgrade possible", out, why)
        elif expect == "mixed":
            self.assertGreater(on_new, 0, why)
            self.assertLess(on_new, len(nodes), why)
            self.assertIn(highest, out, why)
        elif expect == "uniform":
            self.assertEqual(on_new, len(nodes), why)
            if self.level_bump:
                self.assertIn(possible, out, why)
            else:
                self.assertNotIn("Upgrade possible", out, why)
        else:
            self.fail("unknown expectation %r" % expect)

    #
    # Driving the cluster forward
    #

    def upgrade_node(self, node):
        """Roll one node forward to the build under test."""
        try:
            node.install(Cluster.NEW)
        except ClusterError as e:
            self.fail(str(e))

    def cluster_level_upgrade(self):
        self.requireLevelBump()
        self.assertRunOk(self.admin,
                         ["net", "clusterlevel", "upgrade", "--apply"])

    #
    # Background load
    #

    def start_load(self, tag, node):
        load = Load(self.cluster, node, self.workpath("load-%s.bench" % tag),
                    self.workpath("load-%s" % tag))
        self.loads[tag] = load
        # Wait for the first wbinfo round, unless a client fails first.
        deadline = time.time() + 30
        while (load.rounds == 0 and load.bench.poll() is None and
               load.wbinfo.is_alive() and time.time() < deadline):
            time.sleep(1)
        why = load.alive()
        if why is not None:
            load.stop()
            del self.loads[tag]
            self.fail(why)

    def stop_load(self, tag):
        """Stop a load and fail unless both clients were still running.

        A load that is still running shows that the node kept serving
        for the whole window.
        """
        load = self.loads.pop(tag)
        why = load.alive()
        load.stop()
        if why is not None:
            self.fail("%s\nwbinfo rounds completed: %d\n"
                      "--- smbtorture ---\n%s" %
                      (why, load.rounds, load.tail()))

    #
    # smbcontrol, which is what the messaging formats are exercised with
    #

    def smbd_ids(self):
        """The server id of every node's smbd, as "vnn:pid"."""
        ids = []
        for node in self.nodes:
            rc, out = node.run(["smbcontrol", "smbd", "ping"])
            m = re.search(r"^PONG from pid (\S+)$", out, re.M)
            self.assertIsNotNone(m, "%s: no reply from its smbd:\n%s"
                                 % (node, out))
            ids.append(m.group(1))
        return ids

    def smbcontrol_everywhere(self, *args):
        """Run smbcontrol from every node against every node's smbd.

        Each node runs its own build, so in a mixed cluster the messages
        cross between the builds in both directions.  Yields (node, dest,
        output) for each pair.
        """
        ids = self.smbd_ids()
        for node in self.nodes:
            for dest in ids:
                rc, out = node.run(["smbcontrol", dest] + list(args))
                yield node, dest, out

    def assertSmbcontrolPing(self):
        for node, dest, out in self.smbcontrol_everywhere("ping"):
            self.assertIn("PONG from pid %s" % dest, out,
                          "%s pinging %s:\n%s" % (node, dest, out))

    def assertSmbcontrolDebug(self, level):
        rc, out = self.smbcontrol("smbd", "debug", str(level))
        self.assertEqual(rc, 0, out)

    def assertSmbcontrolDebuglevel(self):
        for node, dest, out in self.smbcontrol_everywhere("debuglevel"):
            self.assertIn("PID %s: " % dest, out,
                          "%s asking %s for its debug level:\n%s"
                          % (node, dest, out))

    def assertSmbcontrolProfile(self, command):
        rc, out = self.smbcontrol("smbd", "profile", command)
        self.assertEqual(rc, 0, out)

    def assertSmbcontrolProfilelevel(self):
        # Without --with-profiling-data nothing answers
        # MSG_REQ_PROFILELEVEL: profile_setup() is then profile_dummy.c.
        # Both builds in this environment have profiling, so no reply
        # is a failure, not a missing build option.
        for node, dest, out in self.smbcontrol_everywhere("profilelevel"):
            # The reply names the pid without the vnn.
            pid = dest.split(":")[1]
            self.assertIn("on pid %s" % pid, out,
                          "%s asking %s for its profile level:\n%s"
                          % (node, dest, out))
