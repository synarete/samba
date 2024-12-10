# Prometheus metrics exporter for Samba's internal counters.
#
# Copyright (C) Shachar Sharon <ssharon@redhat.com> 2025
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
# SPDX-License-Identifier: GPL-3.0

"""
Prometheus metrics exporter for Samba's internal counters and profile info.

Converts Samba's 'smbstatus' JSON output into Prometheus metrics format,
via HTTP port 9922. Uses the Prometheus Python library (https://prometheus.io/)
for the actual transformation of metrics information from 'smbstatus' JSON
output format into Prometheus metrics (mostly gauges). When Samba is compiled
and run with profiling enabled it is also possible to export this information
as metrics.
"""

import datetime
import json
import logging
import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List

import prometheus_client
from prometheus_client.core import (
    GaugeMetricFamily,
    InfoMetricFamily,
    Metric,
)
from prometheus_client.registry import CollectorRegistry

# Default Prometheus exporter port number for SMB. See:
# https://github.com/prometheus/prometheus/wiki/Default-port-allocations
DEFAULT_PORT: int = 9922

# Representation of 'smbstatus' output as Python dictionary.
_SMBStatusOutput = Dict[str, Any]


class _SMBStatusError(Exception):
    """An exception for failure upon execution of 'smbstatus' utility."""

    def __init__(self, msg: str, out: str = "", ret: int = 0) -> None:
        Exception.__init__(self, "smbstatus error: " + msg)
        self.out = out[-100:]
        self.ret = ret


class _SMBStatusUtility:
    """Wrapper over command-line execution of smbstatus utility."""

    def __init__(self) -> None:
        self.name = "smbstatus"
        self.xbin = self._locate_executable()

    def run(
        self,
        shares: bool = False,
        processes: bool = False,
        profile: bool = False,
    ) -> _SMBStatusOutput:
        """Run 'smbstatus' utility as sub-process.

        Converts the output of 'smbutility' from JSON format into Python
        dictionary with string-based keys.
        """
        args = ["--json"]
        if shares:
            args.append("--shares")
        elif processes:
            args.append("--processes")
        elif profile:
            args.append("--profile")
        try:
            json_output = self._execute_sub(args)
            return json.loads(json_output)
        except json.JSONDecodeError as ex:
            raise _SMBStatusError("bad json output: " + str(ex))

    def _execute_sub(self, args, timeout: float = 20.0) -> str:
        cmd = self._make_cmdline(args).strip()
        txt = ""
        exp = False
        with subprocess.Popen(
            shlex.split(cmd),
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/",
            shell=False,
            env=os.environ.copy(),
            universal_newlines=True,
        ) as proc:
            try:
                std_out, std_err = proc.communicate(timeout=timeout)
                out = std_out or std_err
                txt = out.strip()
            except subprocess.TimeoutExpired:
                proc.kill()
                exp = True
            ret = proc.returncode
            if exp:
                raise _SMBStatusError("timedout: " + cmd, txt, ret)
            if ret != 0:
                raise _SMBStatusError(cmd, txt, ret)
        return txt

    def _make_cmdline(self, args: Iterable[str]) -> str:
        return str(self.xbin) + " " + " ".join(args)

    def _locate_executable(self) -> Path:
        xbin = str(shutil.which(self.name) or "").strip()
        if not xbin:
            raise _SMBStatusError(f"unable to locate {self.name}")
        return Path(xbin).absolute()


class _BaseMetrics:
    def __init__(self) -> None:
        self.status_ok: bool = False
        self.version: str = ""

    def _parse_globals(self, data: _SMBStatusOutput) -> None:
        self.version = data.get("version", "")
        self.status_ok = len(self.version) > 0

    def _smb_metrics_status(self) -> Metric:
        return InfoMetricFamily(
            name="smb_metrics_status",
            documentation="Current metrics-collector status",
            value={
                "version": self.version,
                "status": "OK" if self.status_ok else "N/A",
            },
        )


class _TconsMetrics(_BaseMetrics):
    """Representation of Samba's tcons metrics for Prometheus exporter.

    Converts the json output of 'smbstatus --json --shares' utility into simple
    counter-values which are later converted into various Prometheus metrics
    (mostly gauges). Use this intermediate representation to avoid the memory
    overhead of large json objects, especially when used as caching object.
    """

    def __init__(self) -> None:
        _BaseMetrics.__init__(self)
        self.tcons_count: int = 0
        self.tcons_remotes: Dict[str, Dict[str, int]] = {}

    def parse(self, data: _SMBStatusOutput) -> None:
        self._parse_globals(data)
        self._parse_tcons_count(data)
        self._parse_tcons_remotes(data)

    def _parse_tcons_count(self, data: _SMBStatusOutput) -> None:
        tcons = data.get("tcons", {})
        self.tcons_count = len(tcons)

    def _parse_tcons_remotes(self, data: _SMBStatusOutput) -> None:
        self.tcons_remotes.clear()
        tcons = data.get("tcons", {})
        for tcon_id in tcons:
            tcon = tcons[tcon_id]
            service = tcon.get("service", "")
            machine = tcon.get("machine", "")
            if service and machine and service != "IPC$":
                rmap = self.tcons_remotes.get(machine, {})
                rmap[service] = rmap.get(service, 0) + 1
                self.tcons_remotes[machine] = rmap

    def as_prometheus_metrics(self) -> Iterable[Metric]:
        ret = [self._smb_metrics_status()]
        if self.status_ok:
            ret.append(self._smb_tcons_count())
            ret.extend(self._smb_tcons_remotes())
        return ret

    def _smb_tcons_count(self) -> Metric:
        return GaugeMetricFamily(
            name="smb_tcons_count",
            documentation="Number of active SMB tree-connections",
            value=self.tcons_count,
        )

    def _smb_tcons_remotes(self) -> Iterable[Metric]:
        ret = []
        for machine in self.tcons_remotes:
            rmap = self.tcons_remotes[machine]
            for service in rmap:
                count = rmap[service]
                gauge = GaugeMetricFamily(
                    name="smb_tcons_remotes",
                    documentation="Number of tree-connections from remote",
                    labels=["machine", "service"],
                )
                gauge.add_metric([machine, service], count)
                ret.append(gauge)
        return ret


class _SessionsMetrics(_BaseMetrics):
    """Representation of Samba's sessions metrics for Prometheus exporter.

    Converts the json output of 'smbstatus --json --processes' utility into
    counter-values which are later converted into various Prometheus metrics
    (mostly gauges). Use this intermediate representation to avoid the memory
    overhead of large json objects, especially when used as caching object.
    """

    def __init__(self) -> None:
        _BaseMetrics.__init__(self)
        self.sessions_count: int = 0
        self.users_count: int = 0

    def parse(self, data: _SMBStatusOutput) -> None:
        self._parse_globals(data)
        self._parse_sessions_count(data)
        self._parse_users_count(data)

    def _parse_sessions_count(self, data: _SMBStatusOutput) -> None:
        sessions = data.get("sessions", {})
        self.sessions_count = len(sessions)

    def _parse_users_count(self, data: _SMBStatusOutput) -> None:
        users = set()
        sessions = data.get("sessions", {})
        for se_num in sessions:
            se = sessions[se_num]
            username = se.get("username", "")
            if not username:
                continue
            users.add(username)
        self.users_count = len(users)

    def as_prometheus_metrics(self) -> Iterable[Metric]:
        ret = []
        if self.status_ok:
            ret.append(self._smb_sessions_count())
            ret.append(self._smb_users_count())
        return ret

    def _smb_sessions_count(self) -> Metric:
        return GaugeMetricFamily(
            name="smb_sessions_count",
            documentation="Number of active SMB sessions",
            value=self.sessions_count,
        )

    def _smb_users_count(self) -> Metric:
        return GaugeMetricFamily(
            name="smb_users_count",
            documentation="Number of currently connected users",
            value=self.users_count,
        )


class _ProfileLoopEntry:
    def __init__(
        self,
        name: str,
        count: int = 0,
        time: int = 0,
    ):
        self.name = name
        self.time = time
        self.count = count

    def as_metric(self) -> Metric:
        gauge = GaugeMetricFamily(
            name="smb_loop_operation_count",
            documentation="Number of smbd loop operations",
            labels=["operation", "microseconds"],
        )
        gauge.add_metric([self.name, str(self.time)], self.count)
        return gauge


class _ProfileVFSEntry:
    def __init__(
        self,
        name: str,
        count: int = 0,
        time: int = 0,
        idle: int = 0,
        nbytes: int = 0,
    ):
        self.name = name
        self.time = time
        self.count = count
        self.idle = idle
        self.nbytes = nbytes

    def as_metric(self) -> Metric:
        gauge = GaugeMetricFamily(
            name="smb_vfs_operation_count",
            documentation="Total number of calls to vfs operation",
            labels=["operation", "microseconds", "bytes"],
        )
        gauge.add_metric(
            [self.name, str(self.time), str(self.nbytes)], self.count
        )
        return gauge


class _ProfileSMB2Entry:
    def __init__(
        self,
        name: str,
        count: int = 0,
        time: int = 0,
        idle: int = 0,
        inbytes: int = 0,
        outbytes: int = 0,
    ):
        self.name = name
        self.time = time
        self.count = count
        self.idle = idle
        self.inbytes = inbytes
        self.outbytes = outbytes

    def as_metric(self) -> Metric:
        gauge = GaugeMetricFamily(
            name="smb_smb2_operation_count",
            documentation="Total number of calls to smb2 operation",
            labels=["operation", "microseconds", "inbytes", "outbytes"],
        )
        gauge.add_metric(
            [self.name, str(self.time), str(self.inbytes), str(self.outbytes)],
            self.count,
        )
        return gauge


class _ProfileMetrics:
    def __init__(self) -> None:
        self.profile_loop_entries: List[_ProfileLoopEntry] = []
        self.profile_vfs_entries: List[_ProfileVFSEntry] = []
        self.profile_smb2_entries: List[_ProfileSMB2Entry] = []

    def parse(self, data: _SMBStatusOutput) -> None:
        smbd_opers = data.get("SMBD loop", {})
        for oper_name in smbd_opers:
            if oper_name.startswith("cpu_"):
                continue
            oper = smbd_opers[oper_name]
            count = int(oper.get("count", 0))
            time = int(oper.get("time", 0))
            loop_entry = _ProfileLoopEntry(oper_name, count, time)
            self.profile_loop_entries.append(loop_entry)
        system_calls = data.get("System Calls", {})
        for syscall_name in system_calls:
            name = syscall_name.removeprefix("syscall_")
            sysc = system_calls[syscall_name]
            count = int(sysc.get("count", 0))
            time = int(sysc.get("time", 0))
            idle = int(sysc.get("idle", 0))
            nbytes = int(sysc.get("bytes", 0))
            vfs_entry = _ProfileVFSEntry(name, count, time, idle, nbytes)
            self.profile_vfs_entries.append(vfs_entry)
        smb2_calls = data.get("SMB2 Calls", {})
        for smb2_name in smb2_calls:
            name = smb2_name.removeprefix("smb2_")
            smbc = smb2_calls[smb2_name]
            count = int(smbc.get("count", 0))
            time = int(smbc.get("time", 0))
            idle = int(smbc.get("idle", 0))
            inbytes = int(smbc.get("inbytes", 0))
            outbytes = int(smbc.get("outbytes", 0))
            smb2_entry = _ProfileSMB2Entry(
                name, count, time, idle, inbytes, outbytes
            )
            self.profile_smb2_entries.append(smb2_entry)

    def as_prometheus_metrics(self) -> Iterable[Metric]:
        metrics: List[Metric] = []
        for loop_entry in self.profile_loop_entries:
            metrics.append(loop_entry.as_metric())
        for vfs_entry in self.profile_vfs_entries:
            metrics.append(vfs_entry.as_metric())
        for smb2_entry in self.profile_smb2_entries:
            metrics.append(smb2_entry.as_metric())
        return metrics


class _SambaPrometheusExporter(CollectorRegistry):
    """Prometheus exporter over HTTP for Samba metrics.

    Implements Prometheus collector: a bridge between in-memory metrics values
    and Prometheus metrics(mostly gauges) representation. Metrics are collected
    on-the-fly and cached internally for few seconds.
    """

    def __init__(
        self,
        portnum: int = DEFAULT_PORT,
        with_profile: bool = False,
    ) -> None:
        CollectorRegistry.__init__(self, auto_describe=True)
        self.logger = logging.getLogger(__name__)
        self.portnum = portnum if portnum > 0 else DEFAULT_PORT
        self.with_profile = with_profile
        self.smbstatus = _SMBStatusUtility()
        self.tcons_metrics = _TconsMetrics()
        self.sessions_metrics = _SessionsMetrics()
        self.profile_metrics = _ProfileMetrics()
        self.timestamp = datetime.datetime.now()

    def process_requests(self) -> None:
        """Execute exporter's logic as forever-loop.

        Register self as a collector and un-register internal metrics. Then use
        the 'prometheus_client' library to serve HTTP requests using most up to
        date cached metrics. In case there is no cached metrics (dropped after
        30 seconds), renew it by calling 'smbstatus' utility.
        """
        self.logger.info(f"Start processing requests: port={self.portnum}")
        self._register_collector()
        self._start_http()
        self._run_loop()

    def collect(self) -> Iterable[Metric]:
        """Export current smbstatus info as Prometheus metrics."""
        self._pre_collect()
        for metric in self.tcons_metrics.as_prometheus_metrics():
            yield metric
        for metric in self.sessions_metrics.as_prometheus_metrics():
            yield metric
        if self.with_profile:
            for metric in self.profile_metrics.as_prometheus_metrics():
                yield metric

    def _pre_collect(self) -> None:
        if self._need_refresh():
            try:
                self.tcons_metrics = self._fetch_tcons_metrics()
                self.sessions_metrics = self._fetch_sessions_metrics()
                if self.with_profile:
                    self.profile_metrics = self._fetch_profile_metrics()
                self.timestamp = datetime.datetime.now()
            except _SMBStatusError as ex:
                self.tcons_metrics = _TconsMetrics()
                self.sessions_metrics = _SessionsMetrics()
                self.profile_metrics = _ProfileMetrics()
                self.logger.warn(f"smbstatus error: {ex.ret} {ex.out}")

    def _need_refresh(self) -> bool:
        ret = True
        if self.tcons_metrics.status_ok:
            now = datetime.datetime.now()
            dif = now - self.timestamp
            ret = dif.total_seconds() > 10
        return ret

    def _fetch_tcons_metrics(self) -> _TconsMetrics:
        tcons_metrics = _TconsMetrics()
        tcons_metrics.parse(self.smbstatus.run(shares=True))
        return tcons_metrics

    def _fetch_sessions_metrics(self) -> _SessionsMetrics:
        sessions_metrics = _SessionsMetrics()
        sessions_metrics.parse(self.smbstatus.run(processes=True))
        return sessions_metrics

    def _fetch_profile_metrics(self) -> _ProfileMetrics:
        profile_metrics = _ProfileMetrics()
        profile_metrics.parse(self.smbstatus.run(profile=True))
        return profile_metrics

    def _register_collector(self) -> None:
        self.register(self)

    def _start_http(self) -> None:
        prometheus_client.start_http_server(port=self.portnum, registry=self)

    def _run_loop(self) -> None:
        while True:
            time.sleep(10)


def _prepare_prometheus_client_lib() -> None:
    if hasattr(prometheus_client, "disable_created_metrics"):
        prometheus_client.disable_created_metrics()


def run_metrics_exporter(portnum: int = 0, with_profile: bool = False):
    """Forever-execute Samba-to-Prometheus metrics exporter."""
    _prepare_prometheus_client_lib()
    exporter = _SambaPrometheusExporter(portnum, with_profile)
    exporter.process_requests()
