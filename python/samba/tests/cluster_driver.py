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

"""How a cluster test reaches the cluster it tests.

The tests in samba.tests.blackbox.cluster_* say what a rolling upgrade
has to do; this says where the cluster is.  Between them sits one small
interface, so the same tests run against the three node cluster selftest
builds out of two trees and against a real cluster of machines with
packages installed on them.

Choose one with SAMBA_CLUSTER_DRIVER, which names a class as
"module:name":

  SAMBA_CLUSTER_DRIVER=samba.tests.cluster_driver_ssh:SshCluster

Unset, the selftest driver below is used, which is what "make test"
wants.

A driver implements two things.

Cluster
    setup()                      read the configuration, build the nodes
    reset()                      back to the starting state: every node
                                 on the stable build, level 1.0
    nodes                        the ClusterNodes, in pnn order
    domain, username, password   an account which may connect
    new_version                  the version "new" means, as the
                                 daemons report it
    unc(node)                    what to connect to on that node
    client_run(node, argv)       an SMB client aimed at a node
    client_popen(node, argv)     the same, left running
    workdir(name)                a directory the client can read and
                                 write, which is not necessarily here
    client_write/read/remove     files in it, from here, on the
                                 host a given node's clients run on
    client_makedir/rmtree        and directories in it
    logdir(name)                 a local directory for process output

ClusterNode
    name                         what an SMB client connects to
    run(argv)                    an administrative tool, on this node,
                                 as root
    popen(argv)                  the same, left running
    install(build)               make this node run that build and come
                                 back serving
    running_versions()           what the daemons on it report now

The split between run() and client_run() is the one thing to get right.
run() is for the tools which join the cluster -- net, smbcontrol,
smbstatus, wbinfo -- and they have to be *that node's* tools: they take a
messaging context, which means ctdbd, which means
cluster_level_db_check_or_update() writes the ranges they support into
the record of the node they attach to.  Run the wrong build's net against
a node and the cluster is told that node serves levels its daemons
cannot.  On a real cluster this falls out for free, because run() is an
ssh to the node; under selftest the driver has to arrange it.

client_run() is for smbclient and smbtorture, which only speak SMB, and
may run wherever the driver likes -- here, or on the node itself.  That
is why it takes the node it is aimed at even though the connection
already says so, and why the files a client puts and gets go through
client_write() and client_read() rather than open(): a test does not
know which filesystem a given node's clients see, only that workdir()
names a place in it.  Process output is different and always lands here,
under logdir(), because ssh brings it back anyway.

argv[0] is always a bare tool name.  The driver decides where that tool
lives and what it needs to find the node it belongs to; a test never
spells out a path or a --configfile.
"""

import abc
import importlib
import os
import re
import shutil
import subprocess

import samba.tests


class ClusterError(Exception):
    """The cluster could not be driven, which is not a test failure."""
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

    The logs are appended to across a restart, so the last match says
    what is running now rather than what ran first.
    """
    found = None
    for line in lines:
        match = re.search(pattern, line)
        if match is not None:
            found = match.group(1)
    return found


def parse_levels(out):
    """The levels in "net clusterlevel features" output, highest first.

    It prints one "      1.0 -> 1.0" line per supported range, newest
    first, under a "Cluster Functional Levels:" heading.
    """
    return [m.group(1) for m in
            re.finditer(r"^\s+(\d+\.\d+)\s*->\s*\d+\.\d+\s*$",
                        out, re.M)]


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

        build is Cluster.STABLE or Cluster.NEW.  Raises ClusterError if
        the node does not come back.  The node is drained first and
        rejoins afterwards, so the rest of the cluster keeps serving
        throughout.
        """

    @abc.abstractmethod
    def running_versions(self):
        """What the daemons running on this node report, as a dict.

        Keys are daemon names, values the version the running process
        reports, or None if it cannot be determined.  Both ctdbd and
        smbd matter: a node which came back with the new smbd and the old
        ctdbd is half upgraded.

        It has to be what is *running*, not what the node is configured
        to run, which is the whole point of the check.
        """


class Cluster(metaclass=abc.ABCMeta):
    """The cluster a test runs against."""

    # The two builds a rolling upgrade moves between.
    STABLE = "stable"
    NEW = "new"

    # Every test uses the same share.
    share = "tmp"

    # The same directory again, with vfs_aio_ratelimit on top, see
    # selftest/target/cfl_smb.conf.
    ratelimit_share = "aio_ratelimit"

    def __init__(self):
        self.nodes = []
        self.domain = None
        self.username = None
        self.password = None

    @abc.abstractmethod
    def setup(self):
        """Read the configuration and build the nodes."""

    @abc.abstractmethod
    def reset(self):
        """Put the cluster back to the state every test starts from.

        That is: every node on the stable build, cluster functional level
        1.0, nothing upgraded.  Called once per test class, because
        raising the level cannot be undone -- cluster_level_activate()
        refuses to move it back down -- so a test which has to start
        below the latest level needs a cluster which has never been
        upgraded.

        Raises ClusterError if it cannot get there.
        """

    @property
    @abc.abstractmethod
    def new_version(self):
        """The version string NEW means, as the daemons report it."""

    @property
    @abc.abstractmethod
    def new_levels(self):
        """The cluster functional levels the build under test offers.

        Highest first, as "major.minor", from the build's own
        "net clusterlevel features". A test asks for these rather than
        naming a level, so that it keeps working when the set changes --
        which it does whenever a level is added or a developer only one
        is dropped, see CFL_TEST_RANGES in source3/lib/cluster_support.c.
        """

    @abc.abstractmethod
    def workdir(self, name):
        """A directory for one test class's files, where clients run.

        Not necessarily on this machine: reach into it with
        client_write(), client_read() and client_remove().
        """

    @abc.abstractmethod
    def logdir(self, name):
        """A local directory for the output of processes a test starts."""

    @abc.abstractmethod
    def client_write(self, node, path, text):
        """Create a file under workdir() for that node's clients."""

    @abc.abstractmethod
    def client_read(self, node, path):
        """Read a file that node's clients wrote, or None."""

    @abc.abstractmethod
    def client_remove(self, node, path):
        """Remove such a file, if it is there."""

    @abc.abstractmethod
    def client_makedir(self, node, path):
        """Create a directory under workdir() for that node's clients."""

    @abc.abstractmethod
    def client_rmtree(self, node, path):
        """Remove such a directory and everything in it, if it is there."""

    @abc.abstractmethod
    def client_run(self, node, argv, env=None):
        """Run an SMB client aimed at node.  Returns (returncode, output)."""

    @abc.abstractmethod
    def client_popen(self, node, argv, env=None, **kwargs):
        """The same, left running.  Returns a subprocess.Popen."""

    def unc(self, node):
        return "//%s/%s" % (node.name, self.share)

    def creds(self):
        """The -U argument an SMB client takes."""
        return "-U%s%%%s" % (self.username, self.password)


class SelftestNode(ClusterNode):
    """A node of the cluster selftest builds in the cfl_upgrade prefix."""

    # Tools which take --configfile.  wbinfo does not: it answers
    # "Invalid option" and finds its node through the winbind socket
    # directory instead.
    CONFIGFILE_TOOLS = frozenset((
        "net", "smbcontrol", "smbstatus", "smbclient", "smbtorture",
        "dbwrap_tool",
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
        # Read every time rather than cached: upgrade_node.sh rewrites
        # this file, which is what moves the node to another build.
        with open(os.path.join(self.base, "respawn", "bindir")) as f:
            return f.read().strip()

    def _argv(self, argv):
        tool = argv[0]
        resolved = [os.path.join(self.bindir, tool)]
        if tool in self.CONFIGFILE_TOOLS:
            # Spelled out rather than kept in a variable of its own, so
            # that a missing node shows up as a missing directory.  These
            # tools accept an empty --configfile and fall back to
            # SMB_CONF_PATH, which selftest points at node 0, so they
            # would quietly act on a node we did not mean.
            resolved.append("--configfile=%s" %
                            os.path.join(self.base, "lib", "server.conf"))
        return resolved + list(argv[1:])

    def _env(self, extra=None):
        env = dict(os.environ)
        # Everything here would be root on a real cluster.
        env["UID_WRAPPER_INITIAL_RUID"] = "0"
        env["UID_WRAPPER_INITIAL_EUID"] = "0"
        # How wbinfo finds this node's winbindd.
        env["SELFTEST_WINBINDD_SOCKET_DIR"] = os.path.join(self.base, "wbsock")
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
            # Nothing puts the stable build back: selftest provisions the
            # whole environment again instead, see SelftestCluster.reset().
            raise ClusterError(
                "the selftest driver can only move a node forward, "
                "not install %r" % build)

        # upgrade_node.sh drains the node with "ctdb stop", takes its
        # daemons down, lets it rejoin and brings them back from the
        # other tree.  See provision_ctdb() in selftest/target/Samba3.pm
        # for how it and respawn.sh are generated.
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

    # Where a daemon records the pid of the process now running.  smbd
    # writes its own; respawn.sh records the one it started, which is
    # the same process and is there even between smbd's own pidfile
    # being removed and written again.
    PIDFILES = ("pid/smbd.pid", "respawn/smbd.pid")

    def running_versions(self):
        return {
            #
            # ctdbd is not wrapped by selftest's daemon wrappers, so its
            # startup line reaches the node's log whatever "make testenv"
            # was told to do.
            #
            "ctdbd": self._logged_version(
                "log.ctdb", r"Starting CTDBD \(Version ([^)]+)\)"),
            #
            # smbd's does not. SCREEN=1 wraps it in selftest/in_screen,
            # which runs it in a screen or tmux window, and its output
            # goes there instead of to smbd_test.log -- which then holds
            # only the wrapper's own stderr. Reading the log would make
            # every check here fail in the one mode people actually
            # debug in.
            #
            # So ask the running process which binary it is executing.
            # That is true in every mode, and a more direct answer than
            # the last matching line of a log which is appended to
            # across restarts.
            #
            "smbd": self._exe_version(self.PIDFILES),
        }

    def _exe_version(self, pidfiles):
        """The version of the binary a running daemon is executing."""
        for rel in pidfiles:
            exe = self._exe_of(os.path.join(self.base, rel))
            if exe is None:
                continue
            rc, out = run_argv([exe, "--version"])
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
        # A binary replaced on disk under a running process, which is
        # what installing a package does, reads back like this. The path
        # then names the new file rather than what is running, so it is
        # no answer at all; say nothing instead of saying something
        # false.
        #
        if exe.endswith(" (deleted)"):
            return None
        return exe


class SelftestCluster(Cluster):
    """The cfl_upgrade environment, as selftest sets it up.

    Three nodes in one prefix, every one of them started from the latest
    stable build with the cluster functional level pinned to 1.0.  See
    setup_cfl_upgrade() in selftest/target/Samba3.pm.
    """

    NODE_COUNT = 3

    def setup(self):
        self.prefix = os.environ["CTDB_PREFIX"]
        self.domain = os.environ["DOMAIN"]
        self.username = os.environ["DC_USERNAME"]
        self.password = os.environ["DC_PASSWORD"]
        self.nodes = [SelftestNode(self, i) for i in range(self.NODE_COUNT)]
        self._new_version = None
        self._new_levels = None
        self._dirs = {}

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

    @property
    def new_levels(self):
        if self._new_levels is None:
            #
            # --configfile=/dev/null on purpose: this asks the binary
            # what it was built with, not what a cluster is running.
            # $SMB_CONF_PATH points at node 0's config, which carries
            # "include = registry" and so needs root and a live ctdbd;
            # net exits before printing anything without them.
            #
            rc, out = run_argv([os.path.join(samba.tests.BINDIR, "net"),
                                "--configfile=/dev/null",
                                "clusterlevel", "features"])
            self._new_levels = parse_levels(out)
            if not self._new_levels:
                raise ClusterError("the build under test offers no cluster "
                                   "functional level:\n%s" % out)
        return self._new_levels

    def workdir(self, name):
        # $SELFTEST_TMPDIR is shared by every testsuite in the run and
        # nothing cleans it in between, unlike the environment itself.
        # Made once and remembered, so that asking again does not empty
        # it under a test which is already using it.
        path = self._dirs.get(name)
        if path is None:
            path = os.path.join(os.environ["SELFTEST_TMPDIR"], name)
            shutil.rmtree(path, ignore_errors=True)
            os.makedirs(path)
            self._dirs[name] = path
        return path

    # Everything is on this machine here, so the clients see the same
    # files the test does.
    logdir = workdir

    # The node makes no difference: one machine, one filesystem.

    def client_write(self, node, path, text):
        with open(path, "w") as f:
            f.write(text)

    def client_read(self, node, path):
        try:
            with open(path, errors="replace") as f:
                return f.read()
        except OSError:
            return None

    def client_remove(self, node, path):
        try:
            os.unlink(path)
        except OSError:
            pass

    def client_makedir(self, node, path):
        os.makedirs(path, exist_ok=True)

    def client_rmtree(self, node, path):
        shutil.rmtree(path, ignore_errors=True)

    #
    # The clients run on the same machine here, and have to use the
    # node's own build and config for the reason in the module docstring:
    # one smbclient from the wrong build is enough to make a node
    # advertise levels its daemons cannot serve.
    #

    def client_run(self, node, argv, env=None):
        return node.run(argv, env=env)

    def client_popen(self, node, argv, env=None, **kwargs):
        return node.popen(argv, env=env, **kwargs)


def make_cluster():
    """The cluster named by SAMBA_CLUSTER_DRIVER, ready to use."""
    spec = os.environ.get("SAMBA_CLUSTER_DRIVER")
    if not spec:
        cluster = SelftestCluster()
    else:
        modname, sep, clsname = spec.partition(":")
        if not sep:
            raise ClusterError(
                "SAMBA_CLUSTER_DRIVER should be 'module:name', not %r" % spec)
        try:
            module = importlib.import_module(modname)
            cluster = getattr(module, clsname)()
        except (ImportError, AttributeError) as e:
            raise ClusterError("no cluster driver %r: %s" % (spec, e))

    cluster.setup()
    return cluster
