# SPDX-License-Identifier: GPL-3.0

"""
Prometheus metrics exporter for Samba's internal counters and profile counters.

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
from typing import Any, Dict, Iterable, List, Optional

import prometheus_client
from prometheus_client.core import (
    GaugeMetricFamily,
    InfoMetricFamily,
    Metric,
    REGISTRY,
)
from prometheus_client.registry import Collector

# Default Prometheus exporter port number for SMB. See:
# https://github.com/prometheus/prometheus/wiki/Default-port-allocations
DEFAULT_PORT: int = 9922

# Minimal refresh time (seconds) of internal stats caches
_REFRESH_TIME: int = 20

# Representation of 'smbstatus' output as Python dictionary.
_SMBStatusOutput = Dict[str, Any]


class _SMBStatusError(Exception):
    """An exception for failure upon execution of 'smbstatus' utility."""

    def __init__(self, msg: str, out: str = "", ret: int = 0) -> None:
        Exception.__init__(self, msg)
        self.out = out[-100:]
        self.ret = ret


class _SMBStatusUtility:
    """Wrapper over command-line execution of smbstatus utility."""

    def __init__(self) -> None:
        self.name = "smbstatus"
        self.cwd = "/"

    def execute(self, profile: bool = False) -> _SMBStatusOutput:
        """Run 'smbstatus' utility as sub-process.

        Converts the JSON output of 'smbutility' into Python dictionary with
        string-based keys.
        """
        args = ["--json"]
        if profile:
            args.append("--profile")
        json_dat = self._execute_sub(args)
        return json.loads(json_dat)

    def _execute_sub(self, args, timeout: float = 10.0) -> str:
        subcmd = self._make_cmdline(args)
        txt = ""
        exp = False
        with subprocess.Popen(
            shlex.split(subcmd),
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.cwd,
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
                raise _SMBStatusError("timedout: " + subcmd, txt, ret)
            if ret != 0:
                raise _SMBStatusError("failed: " + subcmd, txt, ret)
        return txt

    def _make_cmdline(self, args: Iterable[str]) -> str:
        cmdarg0 = str(self._locate_executable())
        cmdline = cmdarg0 + " " + " ".join(args)
        return cmdline.strip()

    def _locate_executable(self) -> Path:
        xbin = str(shutil.which(self.name) or "").strip()
        if not xbin:
            raise _SMBStatusError(f"unable to locate {self.name}")
        return Path(xbin).absolute()


class _SMBMetrics:
    """In-memory representation of metrics which are exported to Prometheus.

    Converts the json output of smbstatus utility into simple counter-values
    which are later converted into various Prometheus metrics (mostly gauges).
    Use this intermediate representation to avoid the memory overhead of large
    json objects, especially when used as caching object.
    """

    def __init__(self, data: Optional[_SMBStatusOutput] = None) -> None:
        self.status_ok: bool = False
        self.version: str = ""
        self.tcons_count: int = 0
        self.sessions_count: int = 0
        self.open_files_count: int = 0
        self.connected_users_count: int = 0
        self.tcons_remotes: Dict[str, Dict[str, int]] = {}
        if data is not None:
            self.parse(data)

    def parse(self, data: _SMBStatusOutput) -> None:
        self._parse_globals(data)
        self._parse_tcons(data)
        self._parse_sessions(data)
        self._parse_open_files(data)
        self._parse_tcons_remotes(data)

    def _parse_globals(self, data: _SMBStatusOutput) -> None:
        self.version = data.get("version", "")
        self.status_ok = len(self.version) > 0

    def _parse_tcons(self, data: _SMBStatusOutput) -> None:
        tcons = data.get("tcons", {})
        self.tcons_count = len(tcons)

    def _parse_sessions(self, data: _SMBStatusOutput) -> None:
        sessions = data.get("sessions", {})
        self.sessions_count = len(sessions)

        users = set()
        for se_num in sessions:
            se = sessions[se_num]
            username = se.get("username", "")
            if not username:
                continue
            users.add(username)
        self.connected_users_count = len(users)

    def _parse_open_files(self, data: _SMBStatusOutput) -> None:
        open_files = data.get("open_files", {})
        self.open_files_count = len(open_files)

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
            ret.append(self._smb_tcons_total())
            ret.append(self._smb_sessions_total())
            ret.append(self._smb_openfiles_total())
            ret.append(self._smb_users_total())
            ret.extend(self._smb_tcons_remotes())
        return ret

    def _smb_metrics_status(self) -> Metric:
        return InfoMetricFamily(
            name="smb_metrics_status",
            documentation="Current metrics-collector status",
            value={
                "version": self.version,
                "status": "OK" if self.status_ok else "N/A",
            },
        )

    def _smb_tcons_total(self) -> Metric:
        return GaugeMetricFamily(
            name="smb_tcons_total",
            documentation="Number of active SMB tree-connections",
            value=self.tcons_count,
        )

    def _smb_sessions_total(self) -> Metric:
        return GaugeMetricFamily(
            name="smb_sessions_total",
            documentation="Number of active SMB sessions",
            value=self.sessions_count,
        )

    def _smb_openfiles_total(self) -> Metric:
        return GaugeMetricFamily(
            name="smb_openfiles_total",
            documentation="Number of currently open files",
            value=self.open_files_count,
        )

    def _smb_users_total(self) -> Metric:
        return GaugeMetricFamily(
            name="smb_users_total",
            documentation="Number of currently connected users",
            value=self.connected_users_count,
        )

    def _smb_tcons_remotes(self) -> Iterable[Metric]:
        ret = []
        for machine in self.tcons_remotes:
            rmap = self.tcons_remotes[machine]
            for service in rmap:
                count = rmap[service]
                gauge = GaugeMetricFamily(
                    name="smb_tcon_remote",
                    documentation="Number of tree-connections from remote",
                    labels=["machine", "service"],
                )
                gauge.add_metric([machine, service], count)
                ret.append(gauge)
        return ret


class _SMBProfileLoopEntry:
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


class _SMBProfileVFSEntry:
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


class _SMBProfileSMB2Entry:
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


class _SMBProfileMetrics:
    def __init__(self, data: Optional[_SMBStatusOutput] = None) -> None:
        self.profile_loop_entries: List[_SMBProfileLoopEntry] = []
        self.profile_vfs_entries: List[_SMBProfileVFSEntry] = []
        self.profile_smb2_entries: List[_SMBProfileSMB2Entry] = []
        if data is not None:
            self.parse(data)

    def parse(self, data: _SMBStatusOutput) -> None:
        smbd_opers = data.get("SMBD loop", {})
        for oper_name in smbd_opers:
            if oper_name.startswith("cpu_"):
                continue
            oper = smbd_opers[oper_name]
            count = int(oper.get("count", 0))
            time = int(oper.get("time", 0))
            loop_entry = _SMBProfileLoopEntry(oper_name, count, time)
            self.profile_loop_entries.append(loop_entry)
        system_calls = data.get("System Calls", {})
        for syscall_name in system_calls:
            name = syscall_name.removeprefix("syscall_")
            sysc = system_calls[syscall_name]
            count = int(sysc.get("count", 0))
            time = int(sysc.get("time", 0))
            idle = int(sysc.get("idle", 0))
            nbytes = int(sysc.get("bytes", 0))
            vfs_entry = _SMBProfileVFSEntry(name, count, time, idle, nbytes)
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
            smb2_entry = _SMBProfileSMB2Entry(
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


class _SMBPrometheusExporter(Collector):
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
        self.logger = logging.getLogger(__name__)
        self.portnum = portnum if portnum > 0 else DEFAULT_PORT
        self.with_profile = with_profile
        self.registry = REGISTRY
        self.utility = _SMBStatusUtility()
        self.metrics = _SMBMetrics()
        self.profile_metrics = _SMBProfileMetrics()
        self.fetch_timestamp = datetime.datetime.now()

    def process_requests(self) -> None:
        """Execute exporter's logic as forever-loop.

        Register self as a collector and un-register internal metrics. Then use
        the 'prometheus_client' library to serve HTTP requests using most up to
        date cached metrics. In case there is no cached metrics (dropped after
        30 seconds), renew it by calling 'smbstatus' utility.
        """
        self.logger.info(f"Start processing requests: port={self.portnum}")
        self._register_collectors()
        self._disable_some_metrics()
        self._start_http()
        self._run_loop()

    def collect(self) -> Iterable[Metric]:
        """Export current smbstatus info as Prometheus metrics."""
        self._pre_collect()
        for metric in self.metrics.as_prometheus_metrics():
            yield metric
        for metric in self.profile_metrics.as_prometheus_metrics():
            yield metric

    def _pre_collect(self) -> None:
        if self._need_refresh():
            self.metrics = self._fetch_metrics()
            self.profile_metrics = self._fetch_profile_metrics()
            self.fetch_timestamp = datetime.datetime.now()

    def _need_refresh(self) -> bool:
        ret = True
        if self.metrics.status_ok:
            now = datetime.datetime.now()
            dif = now - self.fetch_timestamp
            ret = dif.total_seconds() > _REFRESH_TIME
        return ret

    def _fetch_metrics(self) -> _SMBMetrics:
        data: _SMBStatusOutput = dict()
        try:
            data = self.utility.execute()
        except _SMBStatusError as ser:
            self.logger.warn(
                f"Failed to execute 'smbstatus': {ser.ret} {ser.out}"
            )
        return _SMBMetrics(data=data)

    def _fetch_profile_metrics(self) -> _SMBProfileMetrics:
        if not self.with_profile:
            return _SMBProfileMetrics()
        data: _SMBStatusOutput = dict()
        try:
            data = self.utility.execute(profile=True)
        except _SMBStatusError as ser:
            self.logger.warn(
                f"Failed to execute 'smbstatus --profile': {ser.ret} {ser.out}"
            )
        return _SMBProfileMetrics(data=data)

    def _register_collectors(self) -> None:
        self.registry.register(self)

    def _disable_some_metrics(self) -> None:
        prometheus_client.disable_created_metrics()
        self.registry.unregister(prometheus_client.GC_COLLECTOR)
        self.registry.unregister(prometheus_client.PROCESS_COLLECTOR)
        self.registry.unregister(prometheus_client.PLATFORM_COLLECTOR)

    def _start_http(self) -> None:
        prometheus_client.start_http_server(self.portnum)

    def _run_loop(self) -> None:
        while True:
            time.sleep(10)


def run_metrics_exporter(portnum: int = 0, with_profile: bool = False):
    """Forever-execute Samba-to-Prometheus metrics exporter."""
    exporter = _SMBPrometheusExporter(portnum, with_profile)
    exporter.process_requests()
