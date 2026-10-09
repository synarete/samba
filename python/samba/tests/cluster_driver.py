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

"""Drivers that give the cluster tests access to a cluster.

The tests in samba.tests.blackbox.cluster_* only use the Cluster and
ClusterNode interfaces below, so the same tests run against the three
node cluster selftest builds from two trees and against a real cluster
with packages installed.

The environment selects the driver with SAMBA_CLUSTER_DRIVER: cfl_upgrade
sets "selftest", which selects SelftestCluster below.

A driver implements:

Cluster
    setup()                      read the configuration, build the nodes
    reset()                      back to the starting state: every node
                                 on the stable build, never upgraded
    nodes                        the ClusterNodes, in pnn order
    domain, username, password   an account which may connect
    new_version                  the version "new" means, as the
                                 daemons report it
    unc(node)                    what to connect to on that node
    client_conf()                the smb.conf of the SMB clients, if
                                 not selftest's client configuration

ClusterNode
    name                         what an SMB client connects to
    run(argv)                    an administrative tool, on this node,
                                 as root
    popen(argv)                  the same, left running
    install(build)               make this node run that build and come
                                 back serving
    running_versions()           what the daemons on it report now

run() is for net, smbcontrol, smbstatus and wbinfo.  These tools create a
messaging context and connect to ctdbd, and
cluster_level_db_check_or_update() then stores the cluster functional
levels they support as those of the node.  They must come from the build
the node runs, otherwise the node advertises levels its daemons do not
support.  On a real cluster run() executes the tool on the node over ssh;
the selftest driver uses the node's bindir and smb.conf.

The SMB clients run on this machine, the test driver, from the build
under test: smb_conn() connects the test process itself to a node with
the Python bindings, and client_run() and client_popen() run smbtorture.
Both use client_conf(), which does not enable clustering, so they do not
connect to ctdbd.

argv[0] is a bare tool name.  The driver adds the path and any
--configfile; tests never pass them.
"""

import abc
import os
import re
import subprocess

import samba.tests
from samba import credentials
from samba.samba3 import libsmb_samba_internal as libsmb
from samba.samba3 import param as s3param

class ClusterError(Exception):
    """Driving the cluster failed, as opposed to a test failing."""
    pass


def run_argv(argv, env=None, cwd=None, input=None):
    """Run argv, return (returncode, stdout and stderr together)."""
    p = subprocess.run(argv, env=env, cwd=cwd, input=input,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT,
                       text=True, errors="replace")
    return p.returncode, p.stdout


def last_version_in(lines, pattern):
    """The version in the last line of lines which matches pattern.

    Logs are appended to across restarts, so the last match is the
    version running now.
    """
    found = None
    for line in lines:
        match = re.search(pattern, line)
        if match is not None:
            found = match.group(1)
    return found


# One supported range, "major.minor_min -> major.minor_max".
RANGE = r"(\d+)\.(\d+)\s*->\s*\d+\.(\d+)"

def parse_ranges(out):
    """The ranges in "net clusterlevel features" output, highest first.

    It prints one "      2.0 -> 2.0" line per supported range under a
    "Cluster Functional Levels:" heading.  Each range is returned as a
    (major, minor_min, minor_max) tuple.
    """
    return [tuple(int(g) for g in m.groups())
            for m in re.finditer(r"^\s+%s\s*$" % RANGE, out, re.M)]


def parse_node_ranges(out):
    """The ranges of each node in "net clusterlevel showall" output.

    A dict from pnn to a list of ranges as returned by parse_ranges().
    Each node is printed as "Node[N] supported_ranges[M]", followed by
    one "    supported_range: 2.0 -> 2.0" line per range.
    """
    nodes = {}
    ranges = None
    for line in out.splitlines():
        m = re.match(r"^Node\[(\d+)\] supported_ranges\[\d+\]$", line)
        if m:
            ranges = nodes.setdefault(int(m.group(1)), [])
            continue
        m = re.match(r"^\s+supported_range: %s$" % RANGE, line)
        if m and ranges is not None:
            ranges.append(tuple(int(g) for g in m.groups()))
    return nodes


def highest_level(ranges):
    """The highest level in ranges, as a (major, minor) tuple.

    Ranges are listed highest first, and a range covers minor_min to
    minor_max of its major level.
    """
    major, _, minor_max = ranges[0]
    return (major, minor_max)


def format_level(level):
    """A (major, minor) level as "net clusterlevel" prints it."""
    return "%d.%d" % level


class ClusterNode(metaclass=abc.ABCMeta):
    """One node of the cluster under test."""

    def __init__(self, cluster, idx):
        self.cluster = cluster
        self.idx = idx

    def __str__(self):
        return "node%d" % self.idx

    @property
    @abc.abstractmethod
    def name(self):
        """What an SMB client connects to: a name or an address."""

    @abc.abstractmethod
    def run(self, argv, env=None):
        """Run an administrative Samba tool on this node, as root.

        argv[0] is a bare tool name.  Returns (returncode, output).
        """

    @abc.abstractmethod
    def popen(self, argv, env=None, **kwargs):
        """The same, left running.  Returns a subprocess.Popen."""

    @abc.abstractmethod
    def install(self, build):
        """Make this node run build, and come back serving SMB.

        build is Cluster.STABLE or Cluster.NEW.  The node is drained first
        and rejoins afterwards, so the other nodes keep serving.  Raises
        ClusterError if the node does not come back.
        """

    @abc.abstractmethod
    def running_versions(self):
        """What the daemons running on this node report, as a dict.

        Keys are daemon names, values the version of the running process,
        or None if it cannot be determined.  This reports the processes
        that are running, not the build the node is configured to run.
        Both ctdbd and smbd are included, so a node that came back with
        only one of them upgraded shows up.
        """


class Cluster(metaclass=abc.ABCMeta):
    """The cluster a test runs against."""

    # The two builds a rolling upgrade moves between.
    STABLE = "stable"
    NEW = "new"

    # Every test uses the same share, see cfl_node_conf() in
    # selftest/target/Samba3.pm.
    share = "cfl"

    def __init__(self):
        self.nodes = []
        self.domain = None
        self.username = None
        self.password = None
        self._new_ranges = None

    @abc.abstractmethod
    def setup(self):
        """Read the configuration and build the nodes."""

    @abc.abstractmethod
    def reset(self):
        """Put the cluster back to the state every test starts from.

        Every node on the stable build, at the highest level that build
        offers: the first node of a fresh cluster stores it.  Called once
        per test class: raising the level cannot be undone,
        cluster_level_activate() refuses to lower it, so each test class
        needs a cluster that was never upgraded.

        Raises ClusterError if it cannot get there.
        """

    @property
    @abc.abstractmethod
    def new_version(self):
        """The Samba version of the NEW build, as its daemons report it."""

    @property
    def new_ranges(self):
        """The cluster functional level ranges the build under test offers.

        Highest first, see parse_ranges(), from the build's own
        "net clusterlevel features".  Tests use these instead of naming
        levels, so they keep working whether or not a release adds a
        level.

        Taken from the tree the tests run from, for every driver, as the
        new build is built from that tree.
        """
        if self._new_ranges is None:
            #
            # --configfile=/dev/null: this asks the binary what it was
            # built with, whatever $SMB_CONF_PATH names.
            #
            rc, out = run_argv([os.path.join(samba.tests.BINDIR, "net"),
                                "--configfile=/dev/null",
                                "clusterlevel", "features"])
            self._new_ranges = parse_ranges(out)
            if not self._new_ranges:
                raise ClusterError("the build under test offers no cluster "
                                   "functional level:\n%s" % out)
        return self._new_ranges

    def client_conf(self):
        """The smb.conf of the SMB clients.

        selftest's client configuration, which $SMB_CONF_PATH names.
        """
        return os.environ["SMB_CONF_PATH"]

    def smb_conn(self, node):
        """An SMB connection from this process to the test share on node."""
        lp = s3param.get_context()
        lp.load(self.client_conf())
        creds = credentials.Credentials()
        creds.guess(lp)
        creds.set_domain(self.domain)
        creds.set_username(self.username)
        creds.set_password(self.password)
        return libsmb.Conn(node.name, self.share, lp, creds)

    def _client(self, argv, env):
        """argv and environment of an SMB client of the build under test."""
        client_env = dict(os.environ)
        client_env["SMB_CONF_PATH"] = self.client_conf()
        if env:
            client_env.update(env)
        argv = [os.path.join(samba.tests.BINDIR, argv[0])] + list(argv[1:])
        return argv, client_env

    def client_run(self, argv, env=None):
        """Run an SMB client of the build under test on this machine.

        Returns (returncode, output).
        """
        argv, env = self._client(argv, env)
        return run_argv(argv, env=env)

    def client_popen(self, argv, env=None, **kwargs):
        """The same, left running.  Returns a subprocess.Popen."""
        argv, env = self._client(argv, env)
        return subprocess.Popen(argv, env=env, **kwargs)

    def unc(self, node):
        return "//%s/%s" % (node.name, self.share)

    def creds(self):
        """The -U argument an SMB client takes."""
        return "-U%s/%s%%%s" % (self.domain, self.username, self.password)


class SelftestNode(ClusterNode):
    """A node of the cluster selftest builds in the cfl_upgrade prefix."""

    # Tools which take --configfile.  wbinfo does not: it answers
    # "Invalid option" and finds its node through the winbind socket
    # directory instead.
    CONFIGFILE_TOOLS = frozenset((
        "net", "smbcontrol", "smbstatus", "smbclient", "smbtorture",
        "smbd", "nmbd", "winbindd", "samba-dcerpcd",
    ))

    def __init__(self, cluster, idx):
        super().__init__(cluster, idx)
        self.base = os.environ["CTDB_BASE_NODE%d" % idx]
        self._name = os.environ["CTDB_SERVER_NAME_NODE%d" % idx]

    @property
    def name(self):
        return self._name

    @property
    def bindir(self):
        # Not cached: upgrade_node.sh rewrites this file to move the
        # node to another build.
        with open(os.path.join(self.base, "respawn", "bindir")) as f:
            return f.read().strip()

    def _argv(self, argv):
        tool = argv[0]
        resolved = [os.path.join(self.bindir, tool)]
        if tool in self.CONFIGFILE_TOOLS:
            # Always the node's own server.conf.  Without --configfile
            # these tools use $SMB_CONF_PATH, selftest's client
            # configuration, and would not find the node.
            resolved.append("--configfile=%s" %
                            os.path.join(self.base, "lib", "server.conf"))
        return resolved + list(argv[1:])

    def _env(self, extra=None):
        env = dict(os.environ)
        # Administrative tools run as root on a real cluster.
        env["UID_WRAPPER_INITIAL_RUID"] = "0"
        env["UID_WRAPPER_INITIAL_EUID"] = "0"
        # How wbinfo finds this node's winbindd.
        env["SELFTEST_WINBINDD_SOCKET_DIR"] = os.path.join(self.base, "wbsock")
        # Without the QUIC wrapper, like the node's daemons: it breaks the
        # stable build's binaries, see setup_clustered_samba().
        env["LD_PRELOAD"] = ":".join(
            p for p in env.get("LD_PRELOAD", "").split(":")
            if p and not p.endswith("/libquic-ko-wrapper.so"))
        env.pop("QUIC_KO_WRAPPER", None)
        if extra:
            env.update(extra)
        return env

    def run(self, argv, env=None):
        return run_argv(self._argv(argv), env=self._env(env))

    def popen(self, argv, env=None, **kwargs):
        return subprocess.Popen(self._argv(argv), env=self._env(env),
                                **kwargs)

    def install(self, build):
        if build != Cluster.NEW:
            # Nodes are never moved back to the stable build: selftest
            # provisions the environment again, see
            # SelftestCluster.reset().
            raise ClusterError(
                "the selftest driver can only move a node forward, "
                "not install %r" % build)

        # upgrade_node.sh stops the node's Samba daemons, shuts down its
        # ctdbd, which drains the node, switches the node to the other
        # build and starts everything again.  provision_ctdb() in
        # selftest/target/Samba3.pm generates it and respawn.sh.
        rc, out = run_argv(
            [os.path.join(self.cluster.prefix, "upgrade_node.sh"),
             str(self.idx)],
            env=self._env())
        if rc != 0:
            raise ClusterError("upgrading %s failed:\n%s" % (self, out))

    def _logged_version(self, logfile, pattern):
        try:
            with open(os.path.join(self.base, logfile),
                      errors="replace") as f:
                return last_version_in(f, pattern)
        except OSError:
            return None

    # Where the pid of the running smbd is recorded: smbd's own pidfile,
    # and the one respawn.sh writes for the process it started, which
    # also exists while smbd's pidfile is being rewritten.
    PIDFILES = ("pid/smbd.pid", "respawn/smbd.pid")

    def running_versions(self):
        return {
            #
            # ctdbd is not run under selftest's daemon wrappers, so its
            # startup line is always in the node's log.
            #
            "ctdbd": self._logged_version(
                "log.ctdb", r"Starting CTDBD \(Version ([^)]+)\)"),
            #
            # smbd's startup line is not: with SCREEN=1,
            # selftest/in_screen runs smbd in a screen or tmux window,
            # and its output goes there instead of to smbd_test.log.
            # Ask the running process which binary it executes instead,
            # which works in every mode.
            #
            "smbd": self._exe_version(self.PIDFILES),
        }

    def _exe_version(self, pidfiles):
        """The version of the binary a running daemon is executing."""
        for rel in pidfiles:
            exe = self._exe_of(os.path.join(self.base, rel))
            if exe is None:
                continue
            rc, out = run_argv([exe, "--version"], env=self._env())
            if rc != 0:
                continue
            return last_version_in(out.splitlines(), r"^Version (\S+)")
        return None

    @staticmethod
    def _exe_of(pidfile):
        """The binary a running process was started from, or None."""
        try:
            with open(pidfile) as f:
                exe = os.readlink("/proc/%d/exe" % int(f.read().strip()))
        except (OSError, ValueError):
            return None
        #
        # The binary was replaced on disk while the process runs, as
        # installing a package does.  The path then names the new file,
        # not the running one, so the version cannot be determined.
        #
        if exe.endswith(" (deleted)"):
            return None
        return exe


class SelftestCluster(Cluster):
    """The cfl_upgrade environment, as selftest sets it up.

    Three nodes in one prefix, every one of them started from the latest
    stable build.  See setup_cfl_upgrade() in selftest/target/Samba3.pm.
    """

    NODE_COUNT = 3

    def setup(self):
        self.prefix = os.environ["CTDB_PREFIX"]
        self.domain = os.environ["DOMAIN"]
        self.username = os.environ["DC_USERNAME"]
        self.password = os.environ["DC_PASSWORD"]
        self.nodes = [SelftestNode(self, i) for i in range(self.NODE_COUNT)]
        self._new_version = None

    def reset(self):
        # Nothing to undo: cfl_upgrade sets RESETUP_ENV, so
        # selftest has already torn it down and provisioned it again
        # from scratch before this testsuite started.
        pass

    @property
    def new_version(self):
        if self._new_version is None:
            rc, out = run_argv([os.path.join(samba.tests.BINDIR, "smbd"),
                                "--version"])
            if rc != 0:
                raise ClusterError("could not read the version of the "
                                   "build under test:\n%s" % out)
            self._new_version = last_version_in(out.splitlines(),
                                                r"^Version (\S+)")
        return self._new_version


def make_cluster():
    """The cluster SAMBA_CLUSTER_DRIVER names, ready to use."""
    name = os.environ.get("SAMBA_CLUSTER_DRIVER")
    if name == "selftest":
        cluster = SelftestCluster()
    else:
        raise ClusterError("SAMBA_CLUSTER_DRIVER should be \"selftest\", "
                           "not %r: run the tests in cfl_upgrade" % name)

    cluster.setup()
    return cluster
