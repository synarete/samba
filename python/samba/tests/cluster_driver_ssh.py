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

"""A cluster of real machines, reached over ssh, running real packages.

    !!! UNTESTED !!!

    This has never been run against a cluster.  It was written from the
    selftest driver it mirrors and from what the tests ask of a cluster,
    so treat it as a starting point with the shape already right, not as
    something known to work.  The interface it implements is exercised on
    every "make test" by SelftestCluster; this side is not.

What it is for: running the upstream cluster tests, unchanged, against
downstream packages on a downstream cluster.  Hand it two sets of RPMs
and three machines with ctdb already clustered, and the same
samba.tests.blackbox.cluster_* tests that gate upstream will drive a
rolling upgrade across them.

It provisions the cluster itself, the way setup_clusteredmember() does
for selftest: it writes smb.conf on every node, sets the ctdb tunable a
mixed version cluster needs, creates the share and joins the domain.
What it expects to find is a ctdb cluster that is already clustered and
healthy, a shared filesystem, and DNS for the realm -- not a configured
Samba.

    SAMBA_CLUSTER_DRIVER=samba.tests.cluster_driver_ssh:SshCluster \\
    SAMBA_CLUSTER_NODES=node1,node2,node3 \\
    SAMBA_CLUSTER_RPMS_STABLE=/srv/rpms/4.25 \\
    SAMBA_CLUSTER_RPMS_NEW=/srv/rpms/4.26 \\
    SAMBA_CLUSTER_DOMAIN=EXAMPLE \\
    SAMBA_CLUSTER_REALM=ad.example.com \\
    SAMBA_CLUSTER_NETBIOS_NAME=smbcluster \\
    SAMBA_CLUSTER_SHARE_PATH=/clusterfs/tmp \\
    SAMBA_CLUSTER_USERNAME=administrator \\
    SAMBA_CLUSTER_PASSWORD=... \\
    SAMBA_CLUSTER_JOIN_USER=Administrator \\
    SAMBA_CLUSTER_JOIN_PASSWORD=... \\
        python3 -m samba.subunit.run \\
            samba.tests.blackbox.cluster_rolling_upgrade

Nothing else is required.  The driver does the work: it copies the RPMs
to the node, installs them, stops and starts whatever services that node
actually runs, and waits for it to serve SMB again.  Everything it does
it does over ssh, clients included, so the machine running the tests
needs ssh and nothing else -- no Samba, no packages, no mounts.

The clients run on the node they are aimed at, from the packages
installed there.  That is the point of installing them on the nodes: the
smbclient and smbtorture which talk to a node are the ones that node's
RPMs provide, so a rolling upgrade moves the client as well as the
server, and there is no fixed client machine to be the odd one out when
its node is the one being upgraded.  SAMBA_CLUSTER_CLIENT_HOST pins them
somewhere else, a separate client VM or "local", for anyone who wants
the nodes left alone.

The defaults describe a stock RHEL-style ctdb cluster.  Everything that
varies between one cluster and the next can be overridden:

    SAMBA_CLUSTER_NODES           required, in pnn order
    SAMBA_CLUSTER_RPMS_STABLE     required, a directory of .rpm files
    SAMBA_CLUSTER_RPMS_NEW        required, a directory of .rpm files
    SAMBA_CLUSTER_DOMAIN          required, the short domain name
    SAMBA_CLUSTER_REALM           required
    SAMBA_CLUSTER_NETBIOS_NAME    required, the cluster's name, one
                                  machine account for all of it
    SAMBA_CLUSTER_SHARE_PATH      required, the directory to export, on
                                  the cluster filesystem: two nodes have
                                  to see the same file through it
    SAMBA_CLUSTER_USERNAME        required, an account which may connect
    SAMBA_CLUSTER_PASSWORD        required
    SAMBA_CLUSTER_JOIN_USER       required, may join a machine
    SAMBA_CLUSTER_JOIN_PASSWORD   required
    SAMBA_CLUSTER_NEW_VERSION     default: read out of the new RPMs
    SAMBA_CLUSTER_SHARE           default "tmp"
    SAMBA_CLUSTER_SSH             default "ssh -o BatchMode=yes"
    SAMBA_CLUSTER_SCP             default "scp -o BatchMode=yes"
    SAMBA_CLUSTER_SSH_USER        default "root"
    SAMBA_CLUSTER_CLIENT_HOST     default: each client runs on the
                                  node it is aimed at
    SAMBA_CLUSTER_SERVICES        default: ask the node, see
                                  SshNode.services()
    SAMBA_CLUSTER_RPM_COMMAND     default "rpm -Uvh --force --oldpackage"
    SAMBA_CLUSTER_LOG_CTDB        default "journalctl -u ctdb --no-pager -o cat"
    SAMBA_CLUSTER_LOG_SMBD        default "journalctl -u smb --no-pager -o cat"
    SAMBA_CLUSTER_WORKDIR         default "/var/tmp/samba-cluster-test-<pid>"

Which services a node runs is asked rather than assumed, because the two
common layouts differ: where ctdb starts Samba through its own event
scripts only the ctdb unit is enabled, and where systemd starts them
smb, nmb and winbind are enabled as well.  "systemctl is-enabled" answers
that per node, and the driver stops and starts exactly what it finds.

smbtorture usually ships in a package of its own, samba-test or
similar, so that package has to be in the RPM directories alongside the
rest for the benchmark the rolling upgrade test puts the cluster under.

    !!! This driver is destructive. !!!  It overwrites smb.conf on every
    node, joins the cluster to a domain, installs the old RPMs over
    whatever is there and deletes the persistent cluster_level.tdb.  The
    previous smb.conf is kept beside it as smb.conf.before-cluster-test,
    but nothing else is put back.  Point it only at a cluster you are
    willing to lose.
"""

import glob
import hashlib
import os
import re
import shlex
import subprocess
import tempfile
import time

from samba.tests.cluster_driver import (
    Cluster,
    ClusterError,
    ClusterNode,
    last_version_in,
    run_argv,
)


#
# Written by samba.tests.cluster_driver_ssh for the upstream cluster
# tests.  Whatever was here before is beside it, as
# smb.conf.before-cluster-test.
#
SMB_CONF_PATH = "/etc/samba/smb.conf"

# Where the packages keep Samba's own state, as opposed to its config.
STATE_DIR = "/var/lib/samba"

# Where the packages keep ctdb's configuration, and its persistent
# databases.
CTDB_BASE_PATH = "/etc/ctdb"
PERSISTENT_DIR = "/var/lib/ctdb/persistent"

# What a node runs. A node of the cluster selftest builds runs the same,
# see setup_clustered_samba() in selftest/target/Samba3.pm, plus its
# selftest plumbing: keep the two in step.
SMB_CONF = """\
[global]
\tworkgroup = %(workgroup)s
\trealm = %(realm)s
\tsecurity = ADS

\tclustering = yes

\t# One machine account for the whole cluster, and the name the join
\t# uses and every node authenticates to the DC with. It has to be the
\t# same everywhere, which is why it is here rather than per node.
\tnetbios name = %(netbios)s

\twinbind use default domain = no
\ttemplate shell = /bin/false
\tidmap config * : backend = tdb
\tidmap config * : range = 1000000-1999999
\tidmap config %(workgroup)s : backend = rid
\tidmap config %(workgroup)s : range = 2000000-2999999

\t# What the tests require, the same file the selftest backend
\t# includes. Inside [global], because it sets global parameters and
\t# an include is parsed where it stands.
\tinclude = %(fragment)s

[%(share)s]
\tpath = %(sharepath)s

[%(ratelimit_share)s]
\tpath = %(sharepath)s
\tvfs objects = aio_ratelimit

# Last, so a site can change anything above, shares included: a repeated
# section merges into the one before it and the later value wins. Put a
# [global] at the top of that file to reach the global section from
# here. It is per node, like smb.conf itself, so it has to be on every
# node. A file which is not there is not an error.
include = %(downstream)s
"""


def required(name):
    value = os.environ.get(name)
    if not value:
        raise ClusterError("%s must be set for the ssh cluster driver" % name)
    return value


def quote_argv(argv):
    return " ".join(shlex.quote(a) for a in argv)


class SshHost:
    """Somewhere to run commands over ssh, or here if host is "local"."""

    def __init__(self, cluster, host):
        self.cluster = cluster
        self.host = host

    @property
    def local(self):
        return self.host == "local"

    def _target(self):
        return "%s@%s" % (self.cluster.ssh_user, self.host)

    def argv_for(self, command, env=None):
        """The local argv which runs a shell command there."""
        if env:
            command = "env %s %s" % (
                " ".join("%s=%s" % (k, shlex.quote(v))
                         for k, v in sorted(env.items())),
                command)
        if self.local:
            return ["/bin/sh", "-c", command]
        return self.cluster.ssh + [self._target(), command]

    def shell(self, command, env=None, input=None):
        """Run a shell command there.  Returns (returncode, output)."""
        return run_argv(self.argv_for(command, env), input=input)

    def shell_popen(self, command, env=None, **kwargs):
        return subprocess.Popen(self.argv_for(command, env), **kwargs)

    def copy_to(self, paths, dest):
        """Copy local files there, into the directory dest."""
        if self.local:
            return run_argv(["cp", "--"] + list(paths) + [dest])
        return run_argv(self.cluster.scp + list(paths) +
                        ["%s:%s" % (self._target(), dest)])

    #
    # Files, for the host the clients run on
    #

    def write_file(self, path, text):
        rc, out = self.shell("cat > %s" % shlex.quote(path), input=text)
        if rc != 0:
            raise ClusterError("could not write %s on %s: %s"
                               % (path, self.host, out))

    def read_file(self, path):
        rc, out = self.shell("cat %s" % shlex.quote(path))
        return out if rc == 0 else None

    def remove_file(self, path):
        self.shell("rm -f %s" % shlex.quote(path))

    def make_dir(self, path):
        rc, out = self.shell("mkdir -p %s" % shlex.quote(path))
        if rc != 0:
            raise ClusterError("could not create %s on %s: %s"
                               % (path, self.host, out))


class SshNode(ClusterNode, SshHost):
    """One machine of the cluster, reached over ssh as root."""

    # Stopped in this order, started in the reverse.  Samba first,
    # because ctdb is what the rest of the cluster talks to.
    SERVICE_ORDER = ("smb", "nmb", "winbind", "ctdb")

    def __init__(self, cluster, idx, host):
        ClusterNode.__init__(self, cluster, idx)
        SshHost.__init__(self, cluster, host)
        self._services = None

    def __str__(self):
        return "node%d (%s)" % (self.idx, self.host)

    @property
    def name(self):
        # What an SMB client connects to.  The same name ssh uses, which
        # assumes the cluster is reachable by node name rather than only
        # through a public address.
        return self.host

    def run(self, argv, env=None):
        # argv[0] is a bare tool name and is left to the node's $PATH, so
        # that it is whichever build is installed there now -- which is
        # the whole point of run() living on the node.
        return self.shell(quote_argv(argv), env)

    def popen(self, argv, env=None, **kwargs):
        return self.shell_popen(quote_argv(argv), env, **kwargs)

    #
    # Services
    #

    def services(self):
        """The units this node actually runs, in stop order.

        Asked rather than assumed: where ctdb starts Samba through its
        event scripts only ctdb is enabled, and where systemd starts them
        smb, nmb and winbind are too.  Either way, what is enabled is
        what has to be stopped and started around an install.
        """
        if self._services is not None:
            return self._services
        if self.cluster.services is not None:
            self._services = self.cluster.services
            return self._services

        found = []
        for unit in self.SERVICE_ORDER:
            rc, _ = self.shell("systemctl is-enabled %s" % shlex.quote(unit))
            if rc == 0:
                found.append(unit)
        if "ctdb" not in found:
            raise ClusterError(
                "no enabled ctdb service on %s; set "
                "SAMBA_CLUSTER_SERVICES if it is called something else"
                % self)
        self._services = found
        return found

    def stop_services(self):
        for unit in self.services():
            rc, out = self.shell("systemctl stop %s" % shlex.quote(unit))
            if rc != 0:
                raise ClusterError("could not stop %s on %s: %s"
                                   % (unit, self, out))

    def start_services(self):
        for unit in reversed(self.services()):
            rc, out = self.shell("systemctl start %s" % shlex.quote(unit))
            if rc != 0:
                raise ClusterError("could not start %s on %s: %s"
                                   % (unit, self, out))

    #
    # Installing a build
    #

    def install_rpms(self, build):
        """Copy that build's RPMs here and install them.

        One rpm command for the whole set, so that packages which depend
        on each other go in together, and --oldpackage because reset()
        installs an older set over a newer one.
        """
        rpms = self.cluster.rpms(build)

        rc, out = self.shell("mktemp -d")
        if rc != 0:
            raise ClusterError("no staging directory on %s: %s" % (self, out))
        staging = out.strip()

        try:
            rc, out = self.copy_to(rpms, staging + "/")
            if rc != 0:
                raise ClusterError("could not copy the %s RPMs to %s:\n%s"
                                   % (build, self, out))

            rc, out = self.shell("%s %s/*.rpm"
                                 % (self.cluster.rpm_command,
                                    shlex.quote(staging)))
            if rc != 0:
                raise ClusterError("installing the %s RPMs on %s failed:\n%s"
                                   % (build, self, out))
        finally:
            self.shell("rm -rf %s" % shlex.quote(staging))

    def install(self, build):
        # Drain the node first, so the rest of the cluster rebalances
        # while this one is still up and keeps serving while it is down.
        rc, out = self.run(["ctdb", "stop"])
        if rc != 0:
            raise ClusterError("could not stop %s: %s" % (self, out))
        self.wait_for(lambda: self.ctdb_state() == "STOPPED",
                      "%s did not drain" % self)

        self.stop_services()
        self.install_rpms(build)
        self.start_services()

        self.wait_for(lambda: self.ctdb_state() is not None,
                      "ctdb on %s did not come back" % self)

        rc, out = self.run(["ctdb", "continue"])
        if rc != 0:
            raise ClusterError("could not continue %s: %s" % (self, out))

        self.wait_for(self.serves_smb,
                      "%s did not serve SMB again after installing the %s "
                      "build" % (self, build))

    def ctdb_state(self):
        rc, out = self.run(["ctdb", "nodestatus"])
        if rc != 0:
            return None
        # "pnn:0 10.0.0.1  OK (THIS NODE)"
        match = re.search(r"^pnn:\d+\s+\S+\s+(\S+)", out, re.M)
        return match.group(1) if match else None

    def serves_smb(self):
        rc, _ = self.run(["smbcontrol", "smbd", "ping"])
        return rc == 0

    def wait_for(self, predicate, what, timeout=300):
        deadline = time.time() + timeout
        while True:
            try:
                if predicate():
                    return
            except OSError:
                pass
            if time.time() >= deadline:
                raise ClusterError("%s within %ds" % (what, timeout))
            time.sleep(5)

    #
    # What is running now
    #

    def running_versions(self):
        return {
            "ctdbd": self._logged_version(
                self.cluster.log_ctdb,
                r"Starting CTDBD \(Version ([^)]+)\)"),
            "smbd": self._logged_version(
                self.cluster.log_smbd,
                r"smbd version (\S+) started"),
        }

    def _logged_version(self, log_command, pattern):
        # The same log lines the selftest driver reads, because they are
        # Samba's own and do not depend on where the log ends up.
        rc, out = self.shell(log_command)
        if rc != 0:
            return None
        return last_version_in(out.splitlines(), pattern)


class SshCluster(Cluster):
    """A real cluster, configured entirely from the environment."""

    def setup(self):
        self.share = os.environ.get("SAMBA_CLUSTER_SHARE", "tmp")
        self.domain = required("SAMBA_CLUSTER_DOMAIN")
        self.username = required("SAMBA_CLUSTER_USERNAME")
        self.password = required("SAMBA_CLUSTER_PASSWORD")

        self.ssh = shlex.split(os.environ.get("SAMBA_CLUSTER_SSH",
                                              "ssh -o BatchMode=yes"))
        self.scp = shlex.split(os.environ.get("SAMBA_CLUSTER_SCP",
                                              "scp -o BatchMode=yes"))
        self.ssh_user = os.environ.get("SAMBA_CLUSTER_SSH_USER", "root")
        self.rpm_command = os.environ.get("SAMBA_CLUSTER_RPM_COMMAND",
                                          "rpm -Uvh --force --oldpackage")
        self.log_ctdb = os.environ.get(
            "SAMBA_CLUSTER_LOG_CTDB", "journalctl -u ctdb --no-pager -o cat")
        self.log_smbd = os.environ.get(
            "SAMBA_CLUSTER_LOG_SMBD", "journalctl -u smb --no-pager -o cat")

        services = os.environ.get("SAMBA_CLUSTER_SERVICES")
        self.services = services.split() if services else None

        self._rpms = {
            Cluster.NEW: self._rpm_set("SAMBA_CLUSTER_RPMS_NEW"),
            Cluster.STABLE: self._rpm_set("SAMBA_CLUSTER_RPMS_STABLE"),
        }

        hosts = [h.strip()
                 for h in required("SAMBA_CLUSTER_NODES").split(",")
                 if h.strip()]
        if len(hosts) < 2:
            raise ClusterError("a cluster needs at least two nodes, got %r"
                               % hosts)
        self.nodes = [SshNode(self, i, host) for i, host in enumerate(hosts)]

        # Unset, each client runs on the node it is aimed at.
        pin = os.environ.get("SAMBA_CLUSTER_CLIENT_HOST")
        self.client_pin = SshHost(self, pin) if pin else None

        # One path, the same on every host, rather than a mktemp per
        # host: a test names a file once and whichever node's client
        # needs it finds it there.  Made on demand, and the files in it
        # are removed by the tests that create them.
        self.workroot = os.environ.get(
            "SAMBA_CLUSTER_WORKDIR",
            "/var/tmp/samba-cluster-test-%d" % os.getpid())

        self.realm = required("SAMBA_CLUSTER_REALM")
        self.netbios_name = required("SAMBA_CLUSTER_NETBIOS_NAME")
        self.share_dir = required("SAMBA_CLUSTER_SHARE_PATH")
        self.join_user = required("SAMBA_CLUSTER_JOIN_USER")
        self.join_password = required("SAMBA_CLUSTER_JOIN_PASSWORD")
        # Where the packages put it. cfl_smb.conf and smb.conf.downstream
        # go beside it, so there is one place to change if that ever
        # moves.
        self.smb_conf = SMB_CONF_PATH

        # The smb.conf both backends include. It is not installed, it
        # lives in the source tree next to the selftest target which
        # includes it; find it from this module, resolving the symlink
        # waf puts in bin/python first. Copying it to the nodes is this
        # driver's job, see write_config().
        self.fragment = os.path.normpath(
            os.path.join(os.path.dirname(os.path.realpath(__file__)),
                         "..", "..", "..", "selftest", "target",
                         "cfl_smb.conf"))
        if not os.path.isfile(self.fragment):
            raise ClusterError("no %s: run the tests from a Samba source "
                               "tree" % self.fragment)
        self.node_fragment = os.path.join(os.path.dirname(self.smb_conf),
                                          os.path.basename(self.fragment))
        # Where a site may change what this driver wrote: beside
        # smb.conf, so it is per node and belongs to the node rather
        # than to the cluster filesystem. Missing is fine; smb.conf
        # includes it unconditionally and loadparm does not mind an
        # include which is not there.
        self.downstream_conf = os.path.join(os.path.dirname(self.smb_conf),
                                            "smb.conf.downstream")

        self.share_path = self.share_dir
        # On node 0, where provision() runs: it records that this
        # cluster is done, and has no business on the exported
        # filesystem or among the config.
        self.marker = os.path.join(STATE_DIR, "cfl_provisioned")

        self._new_version = os.environ.get("SAMBA_CLUSTER_NEW_VERSION")
        self._made = set()
        self._workdirs = set()
        self._logdirs = {}

        self.provision()

    #
    # Provisioning: what setup_clusteredmember() does for selftest
    #

    def provision(self):
        """Configure the cluster for the tests, once per cluster.

        Writes smb.conf and the ctdb tunable on every node, creates the
        share, and joins the domain.  What it expects to find is a ctdb
        cluster which is already clustered and healthy, a shared
        filesystem at SAMBA_CLUSTER_SHARE_PATH, and DNS for the realm.

        Marked on node 0 when it is done, because make_cluster() runs
        once per testsuite and the join is the slow, heavy part.  The
        mark is a hash of everything this puts on the nodes, see
        stamp(), so changing any of it provisions again by itself.
        """
        stamp = self.stamp()
        if self.nodes[0].read_file(self.marker) == stamp:
            return

        for node in self.nodes:
            self.write_config(node)
        self.nodes[0].shell("mkdir -p %s" % shlex.quote(self.share_path))

        self.restart_all("a cluster to configure")
        self.join_domain()
        # So that winbindd and smbd come up holding the new machine
        # credentials rather than whatever they started with.
        self.restart_all("a cluster to serve the domain")

        # The package makes this directory, but say so rather than
        # finding out at the last step of provisioning.
        self.nodes[0].shell("mkdir -p %s"
                            % shlex.quote(os.path.dirname(self.marker)))
        self.nodes[0].write_file(self.marker, stamp)

    def stamp(self):
        """What this cluster is currently provisioned for.

        Everything provision() writes to the nodes goes into the hash:
        the identity, the smb.conf fragment's contents and which RPMs
        are to be installed.  A marker which still matches therefore
        means the cluster really is configured the way this run wants
        it, rather than the way some earlier run did -- the three
        fields it used to hold said nothing about the fragment or the
        packages, so editing either left the cluster as it was.

        To provision again regardless, remove the marker file.
        """
        h = hashlib.sha256()
        for part in (self.netbios_name, self.realm, self.domain,
                     self.share, self.share_path):
            h.update(part.encode("utf-8") + b"\0")
        with open(self.fragment, "rb") as f:
            h.update(f.read())
        for build in sorted(self._rpms):
            h.update(build.encode("utf-8") + b"\0")
            for rpm in sorted(os.path.basename(r)
                              for r in self._rpms[build]):
                h.update(rpm.encode("utf-8") + b"\0")
        return h.hexdigest() + "\n"

    def write_config(self, node):
        """smb.conf and ctdb.tunables on one node."""
        backup = self.smb_conf + ".before-cluster-test"
        rc, out = node.shell(
            "test ! -e %s || test -e %s || cp -p %s %s"
            % (shlex.quote(self.smb_conf), shlex.quote(backup),
               shlex.quote(self.smb_conf), shlex.quote(backup)))
        if rc != 0:
            raise ClusterError("could not back up %s on %s: %s"
                               % (self.smb_conf, node, out))

        with open(self.fragment) as f:
            node.write_file(self.node_fragment, f.read())

        node.write_file(self.smb_conf, SMB_CONF % {
            "netbios": self.netbios_name,
            "workgroup": self.domain,
            "realm": self.realm,
            "share": self.share,
            "ratelimit_share": self.ratelimit_share,
            "sharepath": self.share_path,
            "fragment": self.node_fragment,
            "downstream": self.downstream_conf,
        })

        # ctdb refuses a cluster whose nodes do not all run the same
        # version:
        #
        #   Keepalive version mismatch 0x0004001a != 0x00040019
        #   CTDB Cluster with mixed versions, cannot continue
        #
        # which is exactly what a node coming back on a new build is.
        # AllowMixedVersions turns that off, the way "allow unsafe
        # cluster upgrade" turns off smbd's version claim.  It goes in
        # the file rather than through "ctdb setvar" because install()
        # restarts ctdb and a runtime tunable would not survive it.
        node.write_file(os.path.join(CTDB_BASE_PATH, "ctdb.tunables"),
                        "AllowMixedVersions = 1\n")

    def restart_all(self, what):
        for node in self.nodes:
            node.stop_services()
        for node in self.nodes:
            node.start_services()
        for node in self.nodes:
            node.wait_for(node.serves_smb,
                          "%s did not come back for %s" % (node, what))

    def join_domain(self):
        """Join once, from node 0.

        Every node reads the same secrets.tdb out of the shared private
        directory, so one join is the whole cluster's.
        """
        node = self.nodes[0]

        # The password goes in a file rather than on the command line.
        # argv is world readable through ps, and this is an account
        # which may create machines in the domain; mktemp makes the file
        # 0600 and "cat >" keeps that.
        rc, out = node.shell("mktemp")
        if rc != 0:
            raise ClusterError("no credentials file on %s: %s" % (node, out))
        authfile = out.strip()

        try:
            node.write_file(authfile,
                            "username = %s\npassword = %s\ndomain = %s\n"
                            % (self.join_user, self.join_password,
                               self.domain))
            rc, out = node.run(["net", "ads", "join", "-A", authfile])
        finally:
            node.remove_file(authfile)

        if rc != 0:
            raise ClusterError("joining %s to %s failed:\n%s"
                               % (self.netbios_name, self.realm, out))

        rc, out = node.run(["net", "ads", "testjoin", "-P"])
        if rc != 0:
            raise ClusterError("the join to %s does not work:\n%s"
                               % (self.realm, out))

    @staticmethod
    def _rpm_set(var):
        directory = required(var)
        rpms = sorted(glob.glob(os.path.join(directory, "*.rpm")))
        if not rpms:
            raise ClusterError("no .rpm files in %s=%s" % (var, directory))
        return rpms

    def rpms(self, build):
        try:
            return self._rpms[build]
        except KeyError:
            raise ClusterError("no RPMs for build %r" % build)

    @property
    def new_version(self):
        """What the new RPMs call themselves.

        Read out of the packages, so that nobody has to keep a version
        string in step with a directory of RPMs by hand.  If they
        disagree among themselves, or rpm is not here to ask, say so and
        let SAMBA_CLUSTER_NEW_VERSION settle it.
        """
        if self._new_version is None:
            rc, out = run_argv(["rpm", "-qp", "--nosignature", "--nodigest",
                                "--queryformat", "%{VERSION}\n"]
                               + self.rpms(Cluster.NEW))
            if rc != 0:
                raise ClusterError(
                    "could not read the version of the new RPMs; set "
                    "SAMBA_CLUSTER_NEW_VERSION:\n%s" % out)
            versions = set(line.strip() for line in out.splitlines()
                           if line.strip())
            if len(versions) != 1:
                raise ClusterError(
                    "the new RPMs carry more than one version (%s); set "
                    "SAMBA_CLUSTER_NEW_VERSION" % ", ".join(sorted(versions)))
            self._new_version = versions.pop()
        return self._new_version

    #
    # Back to the state every test starts from
    #

    def reset(self):
        """Every node on the stable build, cluster functional level 1.0.

        Raising the level cannot be undone -- cluster_level_activate()
        panics on a downgrade -- so the record has to go.  Take the whole
        cluster down, install the old RPMs, delete the persistent
        cluster_level.tdb everywhere, and bring it back up: with nothing
        stored and only the old build running, the first daemon to start
        writes 1.0 and that is the active level again.

        This is why the driver is destructive, and why it has to be a
        cluster you are willing to lose.
        """
        for node in self.nodes:
            node.stop_services()

        for node in self.nodes:
            node.install_rpms(Cluster.STABLE)
            # The persistent databases are per node copies of the same
            # thing, so every one of them has to go, or whichever node
            # keeps its copy brings the old level back on recovery.
            rc, out = node.shell("rm -f %s/cluster_level.tdb.*"
                                 % shlex.quote(PERSISTENT_DIR))
            if rc != 0:
                raise ClusterError("could not clear the cluster level "
                                   "record on %s: %s" % (node, out))

        for node in self.nodes:
            node.start_services()

        for node in self.nodes:
            node.wait_for(node.serves_smb,
                          "%s did not serve SMB after the reset" % node)

    #
    # The clients, and the files they read and write
    #

    def client_host(self, node):
        """Where this node's clients run: the node itself, or the pin."""
        return self.client_pin if self.client_pin is not None else node

    def client_run(self, node, argv, env=None):
        host = self.client_host(node)
        self._ensure_workdirs(host)
        return host.shell(quote_argv(argv), env)

    def client_popen(self, node, argv, env=None, **kwargs):
        host = self.client_host(node)
        self._ensure_workdirs(host)
        return host.shell_popen(quote_argv(argv), env, **kwargs)

    def client_write(self, node, path, text):
        host = self.client_host(node)
        self._ensure_workdirs(host)
        host.write_file(path, text)

    def client_read(self, node, path):
        return self.client_host(node).read_file(path)

    def client_remove(self, node, path):
        self.client_host(node).remove_file(path)

    def client_makedir(self, node, path):
        host = self.client_host(node)
        self._ensure_workdirs(host)
        host.make_dir(self._under_workroot(path))

    def client_rmtree(self, node, path):
        self.client_host(node).shell("rm -rf %s"
                                     % shlex.quote(self._under_workroot(path)))

    def _under_workroot(self, path):
        """Refuse a path outside the work root.

        These run as root on somebody's cluster, and "rm -rf" with a
        path that came out wrong is the one mistake worth making
        impossible rather than unlikely.
        """
        full = os.path.normpath(path)
        root = os.path.normpath(self.workroot)
        if full != root and not full.startswith(root + os.sep):
            raise ClusterError("%s is outside the work root %s"
                               % (path, self.workroot))
        return full

    def _ensure_workdirs(self, host):
        """Make the test's directory on a host before a client needs it.

        smbtorture creates its output directory under --basedir before
        it does anything else, so the directory has to be there on
        whichever node the client runs on, not only on the ones a test
        has written a file to.
        """
        for path in self._workdirs:
            key = (host.host, path)
            if key not in self._made:
                host.make_dir(path)
                self._made.add(key)

    def workdir(self, name):
        """The path a test's files live at, on whichever host uses them.

        The same path everywhere, created on a host the first time a
        client of that host needs it.
        """
        path = os.path.join(self.workroot, name)
        self._workdirs.add(path)
        return path

    def logdir(self, name):
        """A local directory: ssh brings process output back here."""
        path = self._logdirs.get(name)
        if path is None:
            path = tempfile.mkdtemp(prefix="samba-cluster-%s-" % name)
            self._logdirs[name] = path
        return path
