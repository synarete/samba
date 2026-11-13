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

"""Request a persistent handle on every node of the cluster."""

import os
import struct

from samba.dcerpc import security
from samba.samba3 import libsmb_samba_internal as libsmb
from samba.tests import TestCase
from samba.tests.cluster_driver import make_cluster

# See libcli/smb/smb2_constants.h
SMB2_DHANDLE_FLAG_PERSISTENT = 0x00000002


def dh2q(flags):
    """A durable handle v2 request: timeout (0 for the server's default),
    flags, 8 reserved bytes and the CreateGuid."""
    return struct.pack("<II8x16s", 0, flags, os.urandom(16))


class ClusterPersistentHandleTests(TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.cluster = make_cluster()

    def test_persistent_handle(self):
        for node in self.cluster.nodes:
            with self.subTest(node=node):
                conn = self.cluster.smb_conn(node, self.cluster.ca_share)
                name = "persistent_handle_%s.txt" % node.name
                fnum, _, contexts = conn.create_ex(
                    name,
                    DesiredAccess=(security.SEC_FILE_READ_DATA |
                                   security.SEC_FILE_WRITE_DATA),
                    CreateDisposition=libsmb.FILE_OVERWRITE_IF,
                    CreateContexts=[
                        (libsmb.SMB2_CREATE_TAG_DH2Q,
                         dh2q(SMB2_DHANDLE_FLAG_PERSISTENT))])
                try:
                    responses = [data for tag, data in contexts
                                 if tag == libsmb.SMB2_CREATE_TAG_DH2Q]
                    self.assertEqual(len(responses), 1,
                                     "no durable handle granted: %r" %
                                     contexts)
                    _, flags = struct.unpack("<II", responses[0])
                    self.assertTrue(flags & SMB2_DHANDLE_FLAG_PERSISTENT,
                                    "durable, but not persistent: "
                                    "flags 0x%x" % flags)
                finally:
                    conn.close(fnum)
                    conn.unlink(name)
