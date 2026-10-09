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

"""Base class for tests which roll a cluster forward.

The cluster comes from samba.tests.cluster_driver, so these tests run
against the three node cluster selftest builds out of two trees and,
with SAMBA_CLUSTER_DRIVER set, against a real cluster of machines.
Nothing below knows which: it asks the cluster for a node and the node
for a tool.

A test gets a cluster in the state before an upgrade -- every node on the
stable build, cluster functional level 1.0 -- and drives it from there:
upgrade_node() replaces the build one node runs, and
cluster_level_upgrade() raises the level once every node offers it.

Test methods run in name order and share the cluster, so they are
numbered and each one picks up where the last left off.  State which
outlives a single step, the background load for instance, belongs on the
class.

Nothing here opens a database from the test process itself.  That is not
a style preference: a process which opens a clustered database ends up in
global_messaging_context(), see dbwrap_open(), and from there in
cluster_level_db_check_or_update(), which registers *its own* supported
levels as those of the node whose ctdbd it is attached to.  The test
process imports the bindings of the build under test, so anything which
reached a messaging context would do exactly that.  Shell out, always.
"""

import functools
import os
import subprocess
import threading
import time
from unittest import SkipTest

import samba.tests
from samba.tests.cluster_driver import Cluster, ClusterError, make_cluster


def critical(func):
    """Mark a step the rest of the test is meaningless without.

    The steps of an upgrade happen in one order and build on each other,
    so a failed upgrade turns every later check into noise.  Record it
    and let setUp() skip what follows, which reads far better in a CI
    report than a cascade of failures with one cause.
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
    """Background traffic against one node, for the length of a window.

    Two clients: an smbtorture open/close benchmark, which is what
    exercises the clustered share mode and lock records, and a wbinfo
    loop, which exercises winbindd on that node.  Both run against one
    node and have to be stopped before that node goes down: a cluster
    without public addresses fails nothing over, and without persistent
    handles a broken connection stays broken.

    The benchmark gets a time limit longer than any window and is killed
    at the end, so the window length does not have to be guessed.  Still
    being alive then is the thing worth checking.
    """

    # Longer than the longest window a test opens.
    TIMELIMIT = 900

    # A node leaving or rejoining the cluster freezes the databases for
    # the length of a recovery, so winbindd on this node can be slow or
    # briefly unhappy even though it is not the node being upgraded.
    # Give up only on sustained failure.
    MAX_CONSECUTIVE_FAILURES = 5

    def __init__(self, cluster, node, logpath, basedir):
        self.cluster = cluster
        self.node = node
        self.logpath = logpath
        self.basedir = basedir
        self.rounds = 0
        self.wbinfo_error = None

        # One directory per load, not one shared by all of them: stop()
        # takes it away again, and two windows overlap -- the node 1 load
        # is already running when the node 0 one is stopped.
        cluster.client_makedir(node, basedir)

        self.bench_log = open(logpath, "w")
        self.bench = cluster.client_popen(
            node,
            # --basedir because smbtorture puts its per run output
            # directory in the current directory otherwise, see
            # torture_context_init(), and nothing says the directory a
            # test happens to be started from is writable:
            #
            #   torture_context_init() failed: Permission denied
            #
            # A directory of this load's own under workdir(), which is
            # the one place a client is promised it can write, on
            # whichever host it runs on.
            ["smbtorture", "--basedir=%s" % basedir, cluster.unc(node),
             "-U%s/%s%%%s" % (cluster.domain, cluster.username,
                              cluster.password),
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
        # and it has to have got somewhere, not merely survived
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

        # smbtorture deletes its output directory on the way out, see
        # torture_deltree_outputdir(), but it is killed here rather than
        # left to finish, so it never gets there.
        self.cluster.client_rmtree(self.node, self.basedir)

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

        # The levels the build under test offers, highest first. The
        # tests name none of them: a level is added or a developer only
        # one is dropped without touching a test.
        cls.levels = cls.cluster.new_levels
        cls.new_level = cls.levels[0]

        cls.nodes = cls.cluster.nodes
        cls.admin = cls.nodes[0]
        cls.loads = {}
        # Where the clients read and write; not necessarily this machine.
        cls.workdir = cls.cluster.workdir(cls.__name__)
        # Where processes a test starts write their output; always here.
        cls.logdir = cls.cluster.logdir(cls.__name__)

    def setUp(self):
        super().setUp()
        if self.blocked is not None:
            self.skipTest(self.blocked)

    def workpath(self, name):
        """A file the clients can reach.  Use cluster.client_*() on it."""
        return os.path.join(self.workdir, name)

    def logpath(self, name):
        """A local file, for the output of a process the test starts."""
        return os.path.join(self.logdir, name)

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
        """Drive net and smbcontrol from this node from now on.

        Those two are not clients, they join the cluster, so they have to
        come from the build that node runs -- the way an admin would use
        the tools installed on the machine in front of them.  See the
        module docstring of samba.tests.cluster_driver.
        """
        type(self).admin = self.nodes[idx]
        print("driving the cluster from %s" % self.admin)

    def net(self, *args):
        return self.admin.run(["net"] + list(args))

    def smbcontrol(self, *args):
        return self.admin.run(["smbcontrol"] + list(args))

    #
    # Clients
    #

    def smbclient(self, node, command):
        """Run one smbclient command list against a node."""
        return self.cluster.client_run(
            node,
            ["smbclient", self.cluster.unc(node), self.cluster.creds(),
             "-c", command])

    def smbclient_interactive(self, node, logname):
        """Start an smbclient which stays up and takes commands on stdin.

        Returns the Popen.  stdout goes to a file in the work directory
        rather than a pipe, so that nobody has to drain it to keep the
        client from blocking on a full pipe buffer.

        Two such clients must not share a client GUID: connecting to a
        second node with the same one is what smbXsrv_client_cross_node
        tests, and it tears the first connection down.  Nothing to do for
        that: with libsmb:client_guid unset, cli_state_create() generates
        a random one per process.
        """
        log = open(self.logpath(logname), "w")
        p = self.cluster.client_popen(
            node,
            ["smbclient", self.cluster.unc(node), self.cluster.creds(),
             "--quiet"],
            env={"CLI_FORCE_INTERACTIVE": "1"},
            stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT,
            text=True)
        p.logname = logname
        p.logfile = log
        # Let it connect and reach its first prompt.  smbclient says
        # nothing when it is ready, so there is nothing to wait for.
        time.sleep(1)
        return p

    def smbclient_send(self, p, command, settle=1):
        """Send one command to an interactive smbclient.

        smbclient gives no reply to wait for, so the pause is how the
        next command is kept from overtaking this one.
        """
        p.stdin.write("%s\n" % command)
        p.stdin.flush()
        time.sleep(settle)

    def smbclient_quit(self, p):
        try:
            self.smbclient_send(p, "quit", settle=0)
            p.stdin.close()
            p.wait(timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            p.kill()
            p.wait()
        p.logfile.close()

    def client_log(self, p):
        try:
            with open(self.logpath(p.logname), errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    #
    # Assertions about one node
    #

    def assertSmbService(self, node):
        """The node serves SMB."""
        rc, out = self.smbclient(node, "ls")
        self.assertEqual(rc, 0, "%s does not serve SMB:\n%s" % (node, out))

    def assertFileIO(self, node):
        """A file written to the node reads back unchanged."""
        name = "cluster_upgrade_io_%d.tmp" % os.getpid()
        src = self.workpath(name)
        dst = self.workpath(name + ".got")
        content = "cluster upgrade I/O test\n"
        self.cluster.client_write(node, src, content)

        try:
            rc, out = self.smbclient(
                node, "put %s %s; get %s %s; rm %s" % (src, name,
                                                       name, dst, name))
            self.assertEqual(rc, 0, "I/O on %s failed:\n%s" % (node, out))
            self.assertEqual(self.cluster.client_read(node, dst), content,
                             "%s read back something else" % node)
        finally:
            for path in (src, dst):
                self.cluster.client_remove(node, path)

    def assertNodeBuild(self, node, new):
        """The node runs the build under test, or does not.

        Every daemon the driver reports on has to agree.  Checking ctdbd
        as well as smbd is the point: a node which came back with this
        build's smbd but the old ctdbd would look fine until the level
        could not be raised, much later and much harder to read.
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
        """Poll until every smbd has picked the new level up.

        Raising the level sends MSG_CLUSTER_LEVEL_UPGRADED and each smbd
        updates its cached level when it arrives, so "net clusterlevel
        show" can still report the old one for a moment.
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

    # The level the environment starts at, see setup_cfl_upgrade() in
    # selftest/target/Samba3.pm.
    START_LEVEL = "1.0"

    def requireTwoLevels(self):
        """Skip a test which has nothing to upgrade to.

        A build with one level cannot be asked about raising it. That is
        what a released build looks like until a format change earns a
        second level, see CFL_TEST_RANGES in
        source3/lib/cluster_support.c; the mixed version half of these
        tests is unaffected and keeps running.
        """
        if len(self.levels) < 2:
            self.skipTest("this build offers one cluster functional "
                          "level (%s), so there is nothing to upgrade to"
                          % self.levels[0])

    def upgradeTestExpectation(self, expect):
        """What "net clusterlevel upgrade --test" has to say, and when.

        On the all stable cluster nothing offers more than the active
        level, so there is nothing to do.  Part way through the rolling
        upgrade it has to refuse: cluster_level_db_upgrade() requires
        every node's stored range set to be identical, not merely to
        overlap, and names the node that disagrees in error_vnn.  Once
        every node runs this build it reports the upgrade as possible.
        """
        return {
            "already": (False,
                        "Already at active cluster functional level: %s"
                        % self.START_LEVEL),
            "mismatch": (False, "NT_STATUS_REVISION_MISMATCH"),
            "possible": (True,
                         "Upgrade possible from cluster functional level "
                         "%s to %s" % (self.START_LEVEL, self.new_level)),
        }[expect]

    def assertUpgradeTest(self, expect):
        self.requireTwoLevels()
        want_ok, needle = self.upgradeTestExpectation(expect)
        rc, out = self.net("clusterlevel", "upgrade", "--test")
        why = "asked on %s\n%s" % (self.admin, out)
        self.assertEqual(rc == 0, want_ok, why)
        self.assertIn(needle, out, why)

    def assertSupportedRanges(self, expect):
        if expect != "stable":
            self.requireTwoLevels()
        """What "net clusterlevel showall" says about the nodes.

        It prints one "Node[N] supported_ranges[M]" line per node.  The
        stable build offers one range, this build offers two, and the
        summary line only calls the upgrade possible once every node is
        at the highest level.
        """
        rc, out = self.net("clusterlevel", "showall")
        self.assertEqual(rc, 0, out)
        why = "asked on %s\n%s" % (self.admin, out)

        count = len(self.nodes)
        # A node on the build under test stores one range per level it
        # offers; the stable build offers fewer, so the count is what
        # tells the two apart.
        latest = len([line for line in out.splitlines()
                      if "supported_ranges[%d]" % len(self.levels) in line])

        if expect == "stable":
            # Nothing offers the new level, so there is no upgrade line.
            self.assertEqual(latest, 0, why)
            self.assertNotIn("cluster functional level: %s" % self.new_level,
                             out, why)
        elif expect == "mixed":
            self.assertGreater(latest, 0, why)
            self.assertLess(latest, count, why)
            self.assertIn("Highest supported cluster functional level: %s"
                          % self.new_level, out, why)
        elif expect == "uniform":
            self.assertEqual(latest, count, why)
            self.assertIn("Upgrade possible to cluster functional level: %s"
                          % self.new_level, out, why)
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
        self.requireTwoLevels()
        self.assertRunOk(self.admin,
                         ["net", "clusterlevel", "upgrade", "--apply"])

    #
    # Background load
    #

    def start_load(self, tag, node):
        load = Load(self.cluster, node, self.logpath("load-%s.bench" % tag),
                    self.workpath("load-%s" % tag))
        self.loads[tag] = load
        # Give both clients a moment to get going, so that starting the
        # window is itself a check that they can run at all.
        time.sleep(3)
        why = load.alive()
        if why is not None:
            load.stop()
            del self.loads[tag]
            self.fail(why)

    def stop_load(self, tag):
        """Both clients must still be running.

        That is what says the cluster kept serving this node throughout
        the window.
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

    def assertSmbcontrolPing(self):
        rc, out = self.smbcontrol("smbd", "ping")
        self.assertEqual(rc, 0, out)
        self.assertRegex(out, r"(?m)^PONG from pid ")

    def assertSmbcontrolDebug(self, level):
        rc, out = self.smbcontrol("smbd", "debug", str(level))
        self.assertEqual(rc, 0, out)

    def assertSmbcontrolDebuglevel(self):
        rc, out = self.smbcontrol("smbd", "debuglevel")
        self.assertEqual(rc, 0, out)
        self.assertTrue(out.strip(), "no reply to smbcontrol debuglevel")

    def assertSmbcontrolProfile(self, command):
        rc, out = self.smbcontrol("smbd", "profile", command)
        self.assertEqual(rc, 0, out)

    def assertSmbcontrolProfilelevel(self):
        # No skip for a build without profiling support, although that is
        # what "No replies received" here means: smbd registers the
        # handler for MSG_REQ_PROFILELEVEL in profile_setup(), which is
        # profile_dummy.c without --with-profiling-data, and nothing
        # answers.  Both builds in this environment are configured with
        # it, so a silent reply is a real failure and not a build option.
        rc, out = self.smbcontrol("smbd", "profilelevel")
        self.assertEqual(rc, 0, out)
        self.assertTrue(out.strip(), "no reply to smbcontrol profilelevel")
