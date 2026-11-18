#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vcf_diag.py - anonymized health/status collector for VMware Cloud Foundation 9.x

Collects read-only health and status information over SSH from ESXi, vCenter,
NSX, SDDC Manager and the Kubernetes-based control planes that host VCF
Operations / Automation, then writes a report in which hostnames, domains,
IP addresses, MACs, UUIDs, serials, object names and secrets are replaced by
consistent placeholders.

  * Python 3.9+ standard library only. Runs on macOS and Linux.
  * Terminal menus by default; "--gui" opens the same tool as a page in your
    browser, served only to this computer.
  * Uses the system OpenSSH client (ssh). Passwords are typed at a hidden
    prompt, kept in memory only and handed to ssh through a private askpass
    socket. They are never written to disk, argv or the environment.
  * Raw command output is held in memory only. Only anonymized text is written.
  * The placeholder <-> real-name mapping stays on this machine in a private
    directory (default ./vcf-diag-private). Never share that directory.

Run "python3 vcf_diag.py --help" for options, "--init" to create an inventory.
"""
from __future__ import annotations

import argparse
import atexit
import base64
import concurrent.futures
import configparser
import datetime
import fcntl
import getpass
import http.server
import ipaddress
import json
import os
import pty
import re
import secrets as pysecrets
import select
import shlex
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import termios
import textwrap
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

VERSION = "1.18.0"

# ----------------------------------------------------------------------------
# Diagnostic catalog
# ----------------------------------------------------------------------------
# mode: "sh"      POSIX shell command (bash / ESXi ash)
#       "nsxcli"  NSX CLI command (run directly as admin, or wrapped when root)
#       "kubectl" shell command using {K} as the kubectl binary
# harvest: (category, regex-with-one-group, split-regex-or-None). Captured
#          values are registered as names to anonymize everywhere in the report.


def cmd(label, command, timeout=30, mode="sh", harvest=(), max_lines=None, k8s=None, sudo=False, api=None,
        post=None, covered_by=None):
    # post: function(raw output) -> shorter output, applied to successful runs before anonymization
    # covered_by: an API check (its function name) that reports the same; when that API check
    #             succeeds on the same target, this result is left out of the report as redundant
    return {"label": label, "cmd": command, "timeout": timeout, "mode": mode,
            "harvest": tuple(harvest), "max_lines": max_lines, "k8s": k8s, "sudo": sudo, "api": api,
            "post": post, "covered_by": covered_by}


H_NAMESPACE = ("k8sns", r"(?m)^namespace: (\S+)", None)
H_SUPERVISOR = ("vcluster", r"(?m)^supervisor: (.+?) \(", None)
H_NSXNODE = ("host", r"(?m)(?:node|transport node|member): (\S+)", None)
H_EDGECL = ("edgecl", r"(?m)^edge cluster: (.+?)  ", None)


def apicmd(label, fn, shown, harvest=(), max_lines=600):
    """A check answered by the vCenter REST API from this computer (GET requests only)."""
    return cmd(label, shown, timeout=120, mode="vcapi", api=fn, harvest=harvest, max_lines=max_lines)


def is_api_group(key):
    """Checks answered by a REST API from this computer, not over SSH."""
    return key.startswith(("vc-api-", "nsx-api-", "sddc-api-"))


def plan_needs_ssh(item):
    """True when any check of a plan item runs over SSH. Follow-up plans keep their
    checks per host in host_groups, so those count too."""
    groups = list(item["groups"]) + [g for gs in (item.get("host_groups") or {}).values() for g in gs]
    return any(not is_api_group(g[0]) for g in groups)


def ncli(label, command, **kw):
    return cmd(label, command, mode="nsxcli", **kw)


def kctl(label, command, **kw):
    kw.setdefault("timeout", 45)
    return cmd(label, command, mode="kubectl", **kw)


# ----------------------------------------------------------------------------
# Output summarizers: turn long, repetitive raw output into a few lines an analyst
# (human or AI) can read. Each one returns its input unchanged when it cannot parse it.
# ----------------------------------------------------------------------------

RX_NSXCLI_STAMP = re.compile(r"(?m)^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (\w{3}) +(\d{1,2}) (\d{4}) UTC "
                             r"(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?[ \t]*\n?")


def nsxcli_stamp(out):
    """(epoch seconds of the first NSX CLI time stamp line or None, output without those lines)."""
    m = RX_NSXCLI_STAMP.search(out or "")
    if not m:
        return None, out
    try:
        dt = datetime.datetime.strptime("%s %s %s %s:%s:%s" % m.groups()[:6], "%b %d %Y %H:%M:%S")
        ts = dt.replace(tzinfo=datetime.timezone.utc).timestamp() + float("0." + (m.group(7) or "0"))
    except ValueError:
        ts = None
    return ts, RX_NSXCLI_STAMP.sub("", out)


def _gib(kb):
    return "%.1f GiB" % (kb / 1048576.0)


def post_nsx_version(out):
    """Drop the support URL and the copyright banner."""
    keep = []
    for ln in out.splitlines():
        if re.match(r"\s*(Technical Support:|Copyright)", ln):
            break
        keep.append(ln)
    return "\n".join(keep).strip() or out


def post_cpuinfo(out):
    """Summarize /proc/cpuinfo: one line per distinct CPU model instead of one block per vCPU."""
    blocks = [b for b in re.split(r"\n\s*\n", out) if re.search(r"(?m)^processor\s*:", b)]
    if not blocks:
        return out
    cpus = []
    for b in blocks:
        cpus.append({k.strip(): v.strip() for k, _, v in
                     (ln.partition(":") for ln in b.splitlines() if ":" in ln)})
    models = {}
    for c in cpus:
        try:
            mhz = "%d" % round(float(c.get("cpu MHz", "")))
        except ValueError:
            mhz = "?"
        key = (c.get("model name", "?"), mhz, c.get("cache size", "?"),
               c.get("microcode", "?"))
        models[key] = models.get(key, 0) + 1
    sockets = len({c.get("physical id") for c in cpus})
    flags = set(cpus[0].get("flags", "").split())
    lines = ["%d logical CPU(s) in %d socket(s)" % (len(cpus), sockets)]
    for (name, mhz, cache, mc), n in models.items():
        lines.append("  %d x %s, %s MHz, cache %s, microcode %s" % (n, name, mhz, cache, mc))
    lines.append("virtual machine: %s" % ("yes (hypervisor flag set)" if "hypervisor" in flags else "no"))
    key_flags = ["aes", "avx", "avx2", "avx512f", "sse4_2", "pdpe1gb", "x2apic", "rdrand", "pcid", "invpcid"]
    lines.append("key CPU flags present: %s" % (" ".join(f for f in key_flags if f in flags) or "none"))
    missing = [f for f in key_flags if f not in flags]
    if missing:
        lines.append("key CPU flags missing: %s" % " ".join(missing))
    if len({c.get("flags") for c in cpus}) > 1:
        lines.append("WARNING: the CPU flags differ between logical CPUs")
    if cpus[0].get("bugs"):
        lines.append("kernel-reported CPU vulnerabilities (mitigated where possible): %s" % cpus[0]["bugs"])
    return "\n".join(lines)


def post_meminfo(out):
    """Summarize /proc/meminfo into the values that matter for a health check."""
    kv = {}
    for ln in out.splitlines():
        m = re.match(r"\s*([\w()]+):\s+(\d+)(?:\s*kB)?\s*$", ln)
        if m:
            kv[m.group(1)] = int(m.group(2))
    if "MemTotal" not in kv:
        return out
    tot = kv["MemTotal"] or 1
    avail = kv.get("MemAvailable", kv.get("MemFree", 0))
    lines = ["total %s, available %s (%.0f%%), free %s" % (
        _gib(tot), _gib(avail), 100.0 * avail / tot, _gib(kv.get("MemFree", 0)))]
    if kv.get("SwapTotal"):
        lines.append("swap %s, free %s" % (_gib(kv["SwapTotal"]), _gib(kv.get("SwapFree", 0))))
    else:
        lines.append("swap: none configured")
    lines.append("process memory (AnonPages) %s, page cache %s, slab %s (unreclaimable %s)" % (
        _gib(kv.get("AnonPages", 0)), _gib(kv.get("Cached", 0) + kv.get("Buffers", 0)),
        _gib(kv.get("Slab", 0)), _gib(kv.get("SUnreclaim", 0))))
    if kv.get("CommitLimit"):
        lines.append("committed %s against commit limit %s (%.0f%%; only enforced with vm.overcommit_memory=2)" % (
            _gib(kv.get("Committed_AS", 0)), _gib(kv["CommitLimit"]),
            100.0 * kv.get("Committed_AS", 0) / kv["CommitLimit"]))
    if kv.get("HugePages_Total"):
        lines.append("huge pages %d, free %d" % (kv["HugePages_Total"], kv.get("HugePages_Free", 0)))
    if kv.get("HardwareCorrupted"):
        lines.append("WARNING: hardware-corrupted memory %d kB" % kv["HardwareCorrupted"])
    if 100.0 * avail / tot < 10:
        lines.append("NOTE: less than 10% of memory is available")
    return "\n".join(lines)


RX_NSX_MEMBER = re.compile(r"^\s*(\S{8,})\s+(\S+)\s+(not configured|\S+)\s+(UP|DOWN|UNKNOWN|\S+)\s+(\S+)\s*$")


def _nsx_member(ln):
    m = RX_NSX_MEMBER.match(ln)
    if not m or m.group(1) == "UUID":
        return None
    return m.group(5), m.group(2), m.group(4)          # fqdn, ipv4, status


def _member_lines(members, indent="  "):
    return ["%s%s  %s  %s" % (indent, f, ip, st) for f, ip, st in members]


def summarize_nsx_groups(head, groups, services=()):
    """head: lines to keep first; groups: [(name, status, [(fqdn, ip, status)])];
    services: [(name, [(fqdn, ip, status)])]."""
    lines = list(head)
    stable = [g for g in groups if g[1] == "STABLE" and all(m[2] == "UP" for m in g[2])]
    other = [g for g in groups if g not in stable]
    sets = {tuple(sorted(g[2])) for g in stable}
    if stable:
        lines.append("%d of %d groups STABLE with every member UP: %s" % (
            len(stable), len(groups), ", ".join(g[0] for g in stable)))
        if len(sets) == 1:
            lines.append("members (the same in each of these groups):")
            lines += _member_lines(sorted(stable[0][2]))
        else:
            for g in stable:
                lines.append("group %s members:" % g[0])
                lines += _member_lines(sorted(g[2]))
    for g in other:
        lines.append("group %s: %s" % (g[0], g[1]))
        lines += _member_lines(sorted(g[2]))
    if services:
        ok = [s_ for s_ in services if s_[1] and all(m[2] == "UP" for m in s_[1])]
        if ok:
            lines.append("node services with every node UP: %s" % ", ".join(
                "%s (%d)" % (s_[0], len(s_[1])) for s_ in ok))
        for s_ in services:
            if s_ not in ok:
                lines.append("node service %s:" % s_[0])
                lines += _member_lines(sorted(s_[1])) or ["  (no nodes listed)"]
    return lines


def post_nsx_cluster_status(out):
    """Fold 'get cluster status' (every group lists every member) into a few lines."""
    head, groups, services, cur = [], [], [], None
    for ln in out.splitlines():
        m = re.match(r"\s*(Cluster Id|Overall Status):\s*(.*)$", ln)
        if m:
            head.append("%s: %s" % m.groups())
            continue
        m = re.match(r"\s*Group Type:\s*(\S+)", ln)
        if m:
            cur = [m.group(1), "?", []]
            groups.append(cur)
            continue
        m = re.match(r"\s*Group Status:\s*(\S+)", ln)
        if m and cur is not None:
            cur[1] = m.group(1)
            continue
        m = re.match(r"\s*Service Name:\s*(\S+)", ln)
        if m:
            cur = [m.group(1), None, []]
            services.append(cur)
            continue
        mem = _nsx_member(ln)
        if mem and cur is not None:
            cur[2].append(mem)
    if not groups:
        return out
    return "\n".join(summarize_nsx_groups(
        head, [tuple(g) for g in groups], [(s_[0], s_[2]) for s_ in services]))


def post_nsx_cluster_config(out):
    """Fold 'get cluster config' into one line per node, plus the service ports."""
    head, nodes, cur = [], [], None
    for ln in out.splitlines():
        m = re.match(r"\s*(Cluster Id|Cluster Configuration Version|Number of nodes in the cluster):\s*(.*)$", ln)
        if m:
            head.append("%s: %s" % m.groups())
            continue
        m = re.match(r"\s*Node UUID:\s*(\S+)", ln)
        if m:
            cur = {"uuid": m.group(1), "status": "?", "ents": []}
            nodes.append(cur)
            continue
        m = re.match(r"\s*Node Status:\s*(\S+)", ln)
        if m and cur:
            cur["status"] = m.group(1)
            continue
        m = re.match(r"^\s*([A-Z][A-Z_-]+)\s+(\S{8,})\s+(\S+)\s+(not configured|\S+)\s+(\S+)\s+(\S+)\s*$", ln)
        if m and cur and m.group(1) != "ENTITY":
            cur["ents"].append((m.group(1), m.group(3), m.group(5), m.group(6)))
    if not nodes:
        return out
    lines = head + ["nodes (node UUID, status, address, name, entity count):"]
    for n in nodes:
        ips = sorted({e[1] for e in n["ents"]}) or ["?"]
        names = sorted({e[3] for e in n["ents"]}) or ["?"]
        lines.append("  %s  %s  %s  %s  %d entities" % (n["uuid"], n["status"], ",".join(ips), ",".join(names),
                                                       len(n["ents"])))
    kinds = [tuple(sorted(e[0] for e in n["ents"])) for n in nodes]
    if len(set(kinds)) == 1:
        lines.append("entities on every node: %s" % ", ".join(kinds[0]))
    else:
        for n, k in zip(nodes, kinds):
            lines.append("entities on %s: %s" % (n["uuid"], ", ".join(k)))
    ports = sorted({(e[0], e[2]) for n in nodes for e in n["ents"] if e[2] not in ("-", "")})
    if ports:
        lines.append("entity ports: %s" % ", ".join("%s %s" % p for p in ports))
    return "\n".join(lines)


def post_ntpq_peers(out):
    """ntpq cuts peer names to about 15 characters, so the anonymizer cannot recognize them as
    host names. Replace the remote (and a non-IP refid) column with peer-N before anonymizing."""
    lines, n = [], 0
    for ln in out.splitlines():
        m = re.match(r"^([ *+#ox.\-]?)(\S+)(\s+)(\S+)(\s+\d+\s+\w\s+.*)$", ln)
        if not m or m.group(2) == "remote" or ln.startswith("="):
            lines.append(ln)
            continue
        n += 1
        remote = m.group(2)
        if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", remote):
            remote = "peer-%d" % n
        refid = m.group(4)
        if not re.fullmatch(r"\.[A-Z0-9]{1,4}\.|\d{1,3}(?:\.\d{1,3}){3}", refid):
            refid = "peer-%d-ref" % n
        # keep the columns where ntpq put them: pad to the old width, eat padding on overflow
        rest = m.group(5)
        over = max(0, len(refid) - len(m.group(4)))
        gap = len(rest) - len(rest.lstrip())
        rest = rest[min(over, gap - 1):]
        lines.append("%s%s %s%s" % (m.group(1), remote.ljust(len(m.group(2) + m.group(3)) - 1),
                                    refid.ljust(len(m.group(4))), rest))
    while lines and not lines[-1].strip():
        lines.pop()
    if n:
        lines.append("(peer names are cut off by ntpq and cannot be anonymized reliably: shown as peer-N, "
                     "in the order ntpq listed them. The configured servers are under 'NTP servers'.)")
    return "\n".join(lines)


# NSX Manager services that are stopped unless the feature that uses them is in use
NSX_NORMALLY_STOPPED = {"migration-coordinator", "nsx-message-bus", "snmp"}


def post_nsx_services(out):
    """Fold 'get services' into the state counts, services that are not running, and settings."""
    svcs, cur = [], None
    for ln in out.splitlines():
        k, sep, val = ln.partition(":")
        if not sep:
            continue
        k, val = k.strip(), val.strip()
        if k == "Service name":
            cur = {"name": val, "state": "?", "attrs": []}
            svcs.append(cur)
        elif cur is None:
            continue
        elif k == "Service state":
            cur["state"] = val
        elif val and not (k == "Logging level" and val == "info"):
            cur["attrs"].append("%s %s" % (k.lower(), val))
    if not svcs:
        return out
    states = {}
    for sv in svcs:
        states[sv["state"]] = states.get(sv["state"], 0) + 1
    lines = ["%d services: %s" % (len(svcs), ", ".join("%d %s" % (n, st) for st, n in sorted(
        states.items(), key=lambda kv: (kv[0] != "running", kv[0]))))]
    down = [sv["name"] for sv in svcs if sv["state"] != "running"]
    usual = [n for n in down if n in NSX_NORMALLY_STOPPED]
    other = [n for n in down if n not in NSX_NORMALLY_STOPPED]
    if usual:
        lines.append("not running, usually stopped unless the feature is used: %s" % ", ".join(usual))
    if other:
        lines.append("NOT RUNNING (unexpected): %s" % ", ".join(
            "%s (%s)" % (sv["name"], sv["state"]) for sv in svcs if sv["name"] in other))
    settings = [sv for sv in svcs if sv["attrs"]]
    if settings:
        lines.append("settings:")
        lines += ["  %s: %s" % (sv["name"], "; ".join(sv["attrs"])) for sv in settings]
    return "\n".join(lines)


# ---- generic summarizers for Linux, Kubernetes and log output ----------------

# df lines of container and pod mounts: overlay roots, per-pod shm/tmpfs (secrets, tokens)
RX_POD_MOUNT = re.compile(r"(?:^overlay\s|^shm\s|^tmpfs\s.*\s/var/lib/kubelet/pods/|"
                          r"\s/run/containerd/|\s/var/lib/kubelet/pods/|\s/var/lib/containerd/.*/rootfs\s*$|"
                          r"\s/run/k3s/containerd/)")


def post_df(out):
    """df -hP / df -iP: leave out container and pod mounts (overlay, shm, per-pod tmpfs)."""
    lines = out.splitlines()
    keep = [ln for ln in lines if not RX_POD_MOUNT.search(ln)]
    n = len(lines) - len(keep)
    if not n:
        return out
    return "\n".join(keep + ["(%d container/pod mounts omitted: overlay, shm and tmpfs under "
                             "/var/lib/kubelet/pods and /run/containerd)" % n])


RX_LOG_TS = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"     # ISO 8601
    r"|(?<![\w])[IWEF]\d{4} \d{2}:\d{2}:\d{2}\.\d+"                                # klog E1118 10:00:00.123
    r"|(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)?,? ?(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d{1,2},? "
    r"(?:\d{4} )?\d{2}:\d{2}:\d{2}(?:\.\d+)?"                                       # syslog Nov 18 10:00:00
    r"|\b\d{10}(?:\.\d+)?\b")                                                       # epoch seconds
RX_LOG_VOLATILE = [
    (re.compile(r"(?i)\b(opID|op_id|operationID|reconcileID|requestID|request_id|traceID|spanID|sessionId|"
                r"correlationId|txnId|taskId|sub)\s*[=:]\s*\"?[^\s\",}\]]+"), r"\1=*"),
    (re.compile(r"(?i)\"(reconcileID|requestID|traceID|spanID)\"\s*:\s*\"[^\"]*\""), r'"\1":"*"'),
    (re.compile(r"(?i)\b(pid|tid|thread|thread-id|threadId)\s*[=: ]\s*\d+"), r"\1=*"),
    (re.compile(r"\[(?:\d+|[0-9a-fA-F]{4,})\]"), "[*]"),                            # kubelet[1234], [7f1a]
    (re.compile(r"(?<![\w-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![\w-])"),
     "<uuid>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "0x*"),
    (re.compile(r"(?<![\w-])(?=[0-9a-fA-F]*\d)(?=[0-9a-fA-F]*[a-fA-F])[0-9a-fA-F]{12,}(?![\w-])"), "<hex>"),
    (re.compile(r"(?<![\w.])\d+(?:\.\d+)?(?:ms|µs|us|ns|s)\b"), "<dur>"),
    (re.compile(r"(?<=[\s:=@])\d{4,}(?![\w.])"), "<n>"),                            # thread / process numbers
    (re.compile(r"[ \t]+"), " "),
]


def log_key(line):
    """A log line with time stamps, ids, process and thread numbers normalized: lines that
    differ only in those are the same message."""
    k = RX_LOG_TS.sub("<ts>", line)
    for rx, rep in RX_LOG_VOLATILE:
        k = rx.sub(rep, k)
    return k.strip()


def _ts_of(line):
    m = RX_LOG_TS.search(line)
    return m.group(0).strip() if m else ""


def dedup_lines(lines, sample_chars=400):
    """[(count, first_ts, last_ts, sample)] for lines grouped by log_key, in order of first appearance."""
    groups, order = {}, []
    for ln in lines:
        if not ln.strip():
            continue
        k = log_key(ln)
        g = groups.get(k)
        if g is None:
            g = groups[k] = [0, _ts_of(ln), "", ln]
            order.append(k)
        g[0] += 1
        g[2] = _ts_of(ln) or g[2]
        g[3] = ln                                   # keep the latest occurrence as the sample
    out = []
    for k in order:
        n, first, last, sample = groups[k]
        sample = sample.strip()
        if len(sample) > sample_chars:
            sample = sample[:sample_chars] + " ...[cut]"
        out.append((n, first, last, sample))
    return out


def _dedup_block(lines):
    rows = dedup_lines(lines)
    res = []
    for n, first, last, sample in rows:
        span = first if not last or first == last else "%s..%s" % (first, last)
        res.append("%4d x  %s%s" % (n, (span + "  ") if span and n > 1 else "", sample))
    return res, len(rows)


def post_log_dedup(out, drop=None, noise=None, noise_label="noise"):
    """Group repeated log lines: 'count x  first..last  latest sample line'. Time stamps, thread
    and process numbers, operation / reconcile ids, UUIDs and hex ids are ignored when comparing.
    Sections that start with '== name' (one per pod or file) are deduplicated separately.
    drop: function(line) -> True for lines that are not errors at all (counted, not shown);
    noise: function(line) -> True for low-value lines (counted, most frequent one shown)."""
    lines = out.splitlines()
    total = len([ln for ln in lines if ln.strip()])
    if not total:
        return out
    dropped, noisy, sections, cur = [], [], [], ["", []]
    sections.append(cur)
    for ln in lines:
        if ln.startswith("== "):
            cur = [ln, []]
            sections.append(cur)
        elif drop and drop(ln):
            dropped.append(ln)
        elif noise and noise(ln):
            noisy.append(ln)
        else:
            cur[1].append(ln)
    res, distinct = [], 0
    for head, body in sections:
        if head:
            res.append(head)
        if body or not head:
            block, n = _dedup_block(body)
            distinct += n
            res += block
        elif head:
            res.append("     (no matching lines)")
    shown = total - len(dropped) - len(noisy) - sum(1 for h, _ in sections if h)
    if distinct == shown and not dropped and not noisy:
        return out                                    # nothing repeated: keep the original
    head = ["%d line(s) -> %d distinct message(s) (count, first..last time stamp, latest example; time stamps, "
            "ids and thread numbers ignored when grouping):" % (shown, distinct)]
    if noisy:
        top = dedup_lines(noisy)
        top.sort(key=lambda r: -r[0])
        head.append("%d %s line(s) counted but not listed; most frequent (%dx): %s" % (
            len(noisy), noise_label, top[0][0], top[0][3]))
    if dropped:
        head.append("%d line(s) left out: they matched the search words but report no error" % len(dropped))
    return "\n".join(head + [ln for ln in res if ln.strip() or ln == ""]).rstrip()


def _is_notice(ln):
    """A line logged at NOTICE / INFO level (the level word stands alone near the start; an
    'SQLITE_ERROR' later in the message does not make it an error)."""
    head = ln[:100]
    return bool(re.search(r"\b(NOTICE|INFO|notice|info)\b", head)) and \
        not re.search(r"(?<![\w])(ERROR|SEVERE|FATAL|CRITICAL|error|severe|fatal)\b(?![_:\]])", head)


def post_sso_errors(out):
    """SSO / directory log errors: deduplicated; NOTICE-level lines (vmafdd SQLite notices that
    contain the word 'error') are counted as noise."""
    return post_log_dedup(out, noise=_is_notice, noise_label="NOTICE/INFO-level")


def _kubelet_not_error(ln):
    msg = re.sub(r"^.*?\]:\s*", "", ln) if "]:" in ln[:80] else ln
    return msg.lstrip().startswith("No ") or "No image pull failure found" in ln


def post_kubelet_errors(out):
    """kubelet journal errors: deduplicated; kubelet-watchdog 'No ... found' lines left out."""
    return post_log_dedup(out, drop=_kubelet_not_error)


def post_events(out):
    """Warning events: one line per (namespace, reason, message), with the count, the most recent
    age and the objects involved, most recent first."""
    groups, order, total, other = {}, [], 0, []
    for ln in out.splitlines():
        cols = ln.split(None, 5)
        if not cols or cols[0] == "NAMESPACE":
            continue
        if len(cols) < 6 or cols[2] not in ("Warning", "Normal", "Error"):
            other.append(ln)
            continue
        ns, age, typ, reason, obj, msg = cols
        total += 1
        key = (ns, typ, reason, log_key(msg))
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"n": 0, "age": age, "objs": [], "msg": msg}
            order.append(key)
        g["n"] += 1
        g["age"] = age                     # sorted by last time stamp: the later row is more recent
        g["msg"] = msg
        if obj not in g["objs"]:
            g["objs"].append(obj)
        order.remove(key)
        order.append(key)
    if not total:
        return out
    lines = ["%d event(s) -> %d distinct (namespace, reason, message), most recent first:" % (total, len(groups)),
             "count  last seen  namespace  type  reason  objects  message"]
    for key in reversed(order):
        g = groups[key]
        objs = g["objs"][:4]
        more = " +%d more" % (len(g["objs"]) - 4) if len(g["objs"]) > 4 else ""
        lines.append("%4dx  %s  %s  %s  %s  %s%s  %s" % (g["n"], g["age"], key[0], key[1], key[2],
                                                        ",".join(objs), more, g["msg"]))
    return "\n".join(lines + other)


def post_readyz(out):
    """/readyz?verbose: one line when every check is ok, otherwise the failing checks."""
    checks = re.findall(r"(?m)^\[([+-])\](\S+)\s*(.*)$", out)
    if not checks:
        return out
    bad = [c for c in checks if c[0] != "+"]
    verdict = re.search(r"(?m)^readyz check (passed|failed)", out)
    lines = ["readyz check %s (%d/%d ok)" % (verdict.group(1) if verdict else ("failed" if bad else "passed"),
                                            len(checks) - len(bad), len(checks))]
    lines += ["  [-]%s %s" % (c[1], c[2]) for c in bad]
    return "\n".join(lines)


def post_systemctl_status(out):
    """systemctl status: leave out the containerd-shim lines of the CGroup tree (one per pod)."""
    lines = out.splitlines()
    keep = [ln for ln in lines if "containerd-shim" not in ln]
    n = len(lines) - len(keep)
    return "\n".join(keep + ["(%d containerd-shim process line(s) omitted)" % n]) if n else out


def post_pv(out):
    """kubectl get pv: only volumes that are not Bound (Bound ones appear under the claims)."""
    lines = [ln for ln in out.splitlines() if ln.strip()]
    if not lines or not lines[0].startswith("NAME"):
        return out
    states = ("Bound", "Available", "Released", "Failed", "Pending")
    rows = [ln for ln in lines[1:] if any(s in ln.split() for s in states)]
    if len(rows) != len(lines) - 1:
        return out
    other = [ln for ln in rows if "Bound" not in ln.split()]
    res = ["%d persistent volume(s), %d Bound (see the claims), %d not Bound%s" % (
        len(rows), len(rows) - len(other), len(other), ":" if other else ".")]
    return "\n".join(res + ([lines[0]] + other if other else []))


RX_POD_SUFFIX = re.compile(r"(?:-[a-f0-9]{8,10})?-[a-z0-9]{5}$|-\d+$")


def post_all_pods(out):
    """kubectl get pods -A: one line per namespace (pod states, not ready, restarts, workloads).
    The full list is still read by the anonymizer, so every pod name is known."""
    per, order, total = {}, [], 0
    for ln in out.splitlines():
        cols = ln.split()
        if not cols or cols[0] == "NAMESPACE":
            continue
        if len(cols) < 5 or not re.fullmatch(r"\d+/\d+", cols[2]):
            return out
        total += 1
        ns = per.get(cols[0])
        if ns is None:
            ns = per[cols[0]] = {"n": 0, "st": {}, "nr": 0, "rs": 0, "wl": {}}
            order.append(cols[0])
        ns["n"] += 1
        ns["st"][cols[3]] = ns["st"].get(cols[3], 0) + 1
        a, b = cols[2].split("/")
        if a != b and cols[3] != "Completed":
            ns["nr"] += 1
        m = re.match(r"\d+", cols[4])
        ns["rs"] += int(m.group(0)) if m else 0
        wl = RX_POD_SUFFIX.sub("", cols[1]) or cols[1]
        ns["wl"][wl] = ns["wl"].get(wl, 0) + 1
    if not total:
        return out
    lines = ["%d pods in %d namespaces (per namespace: states, not ready, restarts, workloads = pod name "
             "without the generated suffix):" % (total, len(order))]
    for name in order:
        ns = per[name]
        st = ", ".join("%d %s" % (n, s) for s, n in sorted(ns["st"].items(), key=lambda kv: (kv[0] != "Running", kv[0])))
        wl = sorted(ns["wl"].items(), key=lambda kv: (-kv[1], kv[0]))
        wls = ", ".join("%s(%d)" % kv for kv in wl[:8]) + (" +%d more" % (len(wl) - 8) if len(wl) > 8 else "")
        lines.append("%s: %d pods (%s)%s%s; workloads: %s" % (
            name, ns["n"], st, ", %d not ready" % ns["nr"] if ns["nr"] else "",
            ", restarts %d" % ns["rs"] if ns["rs"] else "", wls))
    return "\n".join(lines)


def post_esxi_policy(out):
    """esxcli advanced settings for the password and lockout policy, one line per option."""
    vals, cur, errs = [], None, {}
    for ln in out.splitlines():
        m = re.match(r"^==\s+(\S+)", ln)
        if m:
            cur = [m.group(1), None]
            vals.append(cur)
            continue
        m = re.match(r"^\s*Path:\s*(\S+)", ln)
        if m and (cur is None or cur[1] is not None or cur[0] != m.group(1)):
            cur = [m.group(1), None]
            vals.append(cur)
            continue
        m = re.match(r"^\s*(Int Value|String Value):\s*(.*?)\s*$", ln)
        if m and cur is not None:
            if m.group(1) == "Int Value" or (m.group(2) and cur[1] is None):
                cur[1] = m.group(2)
            continue
        if cur is not None and ln.strip() and cur[1] is None and not re.match(r"^\s+\w[\w ]*:", ln):
            errs.setdefault(cur[0], ln.strip())
    if not vals:
        return out
    lines = []
    for path, val in vals:
        if val is not None:
            lines.append("%s = %s" % (path, val if val != "" else "(empty)"))
        else:
            lines.append("%s: not available on this host%s" % (path, (" (%s)" % errs[path][:120]) if path in errs else ""))
    return "\n".join(lines)


H_SEARCH = ("domain", r"(?m)^\s*(?:search|domain)\s+(.+)$", r"[\s,]+")


# Answers "is anything serving TLS on 443" without failing when nothing listens there.
CERT_443 = ("c=$(echo | timeout 10 openssl s_client -connect localhost:443 2>/dev/null | openssl x509 2>/dev/null); "
            "if [ -z \"$c\" ]; then echo 'nothing answered with a certificate on localhost:443'; "
            "else printf '%s\\n' \"$c\" | openssl x509 -noout -subject -issuer -dates 2>&1; fi")


def linux_groups(cert=True):
    """cert=False for Kubernetes nodes: nothing on the node itself listens on 443."""
    groups = [
        ("os", "OS, uptime, CPU, memory, disk", [
            cmd("OS release", "head -n 6 /etc/os-release 2>/dev/null"),
            cmd("Uptime and load", "uptime"),
            cmd("Memory", "free -m"),
            cmd("Disk usage", "df -hP", post=post_df),
            cmd("Inode usage", "df -iP", post=post_df),
            cmd("Top processes", "top -bn1 2>/dev/null | grep -v '^%Cpu[0-9]' | head -n 17"),
        ]),
        ("services", "systemd service state", [
            cmd("System state", "systemctl is-system-running 2>&1"),
            cmd("Failed units", "systemctl --failed --no-pager --no-legend 2>&1 | head -n 40"),
            cmd("Running services",
                "systemctl list-units --type=service --state=running --no-pager --no-legend 2>&1"
                " | awk '{print $1}' | head -n 150"),
        ]),
        ("time", "Time sync and DNS", [
            cmd("Time settings", "timedatectl 2>&1 | head -n 12"),
            cmd("NTP sources",
                "chronyc -n sources 2>/dev/null || ntpq -pn 2>/dev/null"
                " || systemctl status systemd-timesyncd --no-pager 2>&1 | head -n 8"),
            cmd("Resolver configuration", "grep -v '^#' /etc/resolv.conf 2>&1", harvest=[H_SEARCH]),
        ]),
        ("network", "Interfaces and routes", [
            cmd("Interfaces", "ip -br addr 2>/dev/null || ifconfig -a 2>&1"),
            cmd("Routes", "ip route 2>&1 | head -n 60"),
        ]),
        ("accounts", "Password expiry", [
            cmd("Password ageing",
                "for u in $(printf '%s\\n' root \"$(id -un)\" | sort -u); do echo \"== $u\";"
                " chage -l \"$u\" 2>&1 | head -n 4; done"),
        ]),
    ]
    if cert:
        groups.append(("cert", "Local HTTPS certificate", [cmd("Certificate on port 443", CERT_443)]))
    return groups


# Output templates for kubectl: one line per pod (with each container's state) and per node.
POD_JSONPATH = ('{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"  node="}{.spec.nodeName}'
                '{"  phase="}{.status.phase}{"  reason="}{.status.reason}{range .status.containerStatuses[*]}'
                '{"  ["}{.name}{" ready="}{.ready}{" restarts="}{.restartCount}{" waiting="}{.state.waiting.reason}'
                '{" last="}{.lastState.terminated.reason}{":"}{.lastState.terminated.exitCode}{"@"}'
                '{.lastState.terminated.finishedAt}{"]"}{end}{"\\n"}{end}')
NODE_COND_JSONPATH = ('{range .items[*]}{.metadata.name}{range .status.conditions[*]}{"  "}{.type}{"="}{.status}'
                      '{"("}{.reason}{")"}{end}{"\\n"}{end}')

K8S_GROUPS = [
    ("k8s-cluster", "Kubernetes API and nodes", [
        kctl("API server version", "{K} version 2>&1 | head -n 6"),
        kctl("API readiness checks", "{K} get --raw='/readyz?verbose' 2>&1 | tail -n 70", post=post_readyz),
        kctl("Nodes", "{K} get nodes -o wide 2>&1", k8s="nodes"),
        kctl("Node conditions and allocation",
             "{K} describe nodes 2>&1 | grep -E '^Name:|^Taints:|^  (MemoryPressure|DiskPressure|"
             "PIDPressure|Ready|NetworkUnavailable) |^  (cpu|memory|ephemeral-storage) .*%'",
             timeout=60),
        kctl("Node resource usage", "{K} top nodes 2>&1"),
    ]),
    ("k8s-workloads", "Pods and workloads", [
        kctl("Namespaces", "{K} get ns 2>&1", k8s="ns"),
        kctl("Pods not Running or not Ready",
             "{K} get pods -A -o wide --no-headers 2>&1 | awk '{split($3,a,\"/\");"
             " if ($4!=\"Completed\" && ($4!=\"Running\" || a[1]!=a[2])) print}'",
             k8s="nsrows", max_lines=300),
        kctl("Pods with most restarts",
             "{K} get pods -A --no-headers 2>&1 | awk '$5+0>0' | sort -k5 -n -r | head -n 30",
             k8s="nsrows"),
        # summarized per namespace; the anonymizer still learns every pod name from the full list
        kctl("All pods (per namespace)", "{K} get pods -A -o wide 2>&1", k8s="nsrows", max_lines=300,
             post=post_all_pods),
        kctl("Deployments, StatefulSets, DaemonSets", "{K} get deploy,sts,ds -A 2>&1",
             k8s="nsrows", max_lines=500),
    ]),
    ("k8s-storage", "Persistent storage", [
        kctl("Persistent volume claims", "{K} get pvc -A 2>&1", k8s="nsrows", max_lines=300),
        kctl("Persistent volumes not Bound", "{K} get pv 2>&1", max_lines=300, post=post_pv),
    ]),
    ("k8s-events", "Warning events", [
        kctl("Latest warning events",
             "{K} get events -A --field-selector type!=Normal --sort-by=.lastTimestamp 2>&1"
             " | tail -n 150", k8s="nsrows", post=post_events),
    ]),
    ("k8s-health", "Node and pod health in depth", [
        kctl("Node conditions with reasons",
             "{K} get nodes -o jsonpath=%s 2>&1" % shlex.quote(NODE_COND_JSONPATH), k8s="firstnode"),
        kctl("Cordoned or tainted nodes",
             "{K} get nodes -o custom-columns='NAME:.metadata.name,UNSCHEDULABLE:.spec.unschedulable,"
             "TAINTS:.spec.taints[*].key,EFFECT:.spec.taints[*].effect' 2>&1", k8s="firstnode"),
        kctl("Pod capacity and pods per node",
             "{K} get nodes -o custom-columns='NAME:.metadata.name,MAX_PODS:.status.allocatable.pods,"
             "CPU:.status.allocatable.cpu,MEMORY:.status.allocatable.memory' --no-headers 2>&1 | while read n m c r; do "
             "echo \"$n  allocatable pods=$m cpu=$c memory=$r  running pods=$({K} get pods -A --no-headers "
             "--field-selector spec.nodeName=$n 2>/dev/null | wc -l)\"; done", k8s="firstnode", timeout=90),
        kctl("Control-plane component pods",
             "{K} -n kube-system get pods -l tier=control-plane -o wide 2>&1", k8s="nsrows"),
        # the etcd image has no shell: etcdctl is run directly, the API version is a flag-free default (v3)
        kctl("etcd health and status (leader, database size)",
             "p=$({K} -n kube-system get pods -l component=etcd -o name 2>/dev/null | head -n 1); "
             "if [ -z \"$p\" ]; then echo 'no etcd pod found in kube-system'; else "
             "for c in 'endpoint health --cluster' 'endpoint status --cluster -w table'; do "
             "{K} -n kube-system exec \"$p\" -- etcdctl --endpoints=https://127.0.0.1:2379 "
             "--cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt "
             "--key=/etc/kubernetes/pki/etcd/server.key $c 2>&1; done; fi", timeout=90),
        kctl("Problem containers (not ready, waiting, restarted, last termination)",
             "{K} get pods -A -o jsonpath=%s 2>&1 | awk '/ready=false|waiting=[A-Za-z]|restarts=[1-9]|"
             "phase=(Pending|Failed|Unknown)/' | head -n 150" % shlex.quote(POD_JSONPATH), k8s="nsslash", max_lines=200),
        kctl("Containers killed for running out of memory (OOMKilled)",
             "{K} get pods -A -o jsonpath=%s 2>&1 | grep OOMKilled | head -n 50 || echo 'none'"
             % shlex.quote(POD_JSONPATH), k8s="nsslash"),
        kctl("Pending pods and why they cannot be scheduled",
             "{K} get pods -A --field-selector=status.phase=Pending -o wide 2>&1 | head -n 50; echo; "
             "{K} get events -A --field-selector reason=FailedScheduling --sort-by=.lastTimestamp 2>&1 | tail -n 30",
             k8s="nsrows"),
        kctl("Evicted and failed pods",
             "{K} get pods -A --field-selector=status.phase=Failed -o wide 2>&1 | head -n 60", k8s="nsrows"),
        kctl("Probe failures (liveness / readiness)",
             "{K} get events -A --field-selector reason=Unhealthy --sort-by=.lastTimestamp 2>&1 | tail -n 40",
             k8s="nsrows"),
        kctl("Deployments, StatefulSets and DaemonSets not fully available",
             "{K} get deploy,sts -A --no-headers 2>&1 | awk '{split($3,a,\"/\"); if (a[1]!=a[2]) print}'; "
             "{K} get ds -A --no-headers 2>&1 | awk '$3!=$5 || $3!=$7'", k8s="nsrows"),
        kctl("Volume claims not Bound", "{K} get pvc -A --no-headers 2>&1 | awk '$3!=\"Bound\"' | head -n 50",
             k8s="nsrows"),
        kctl("Top pods by memory", "{K} top pods -A --sort-by=memory 2>&1 | head -n 25", k8s="nsrows"),
        kctl("Previous logs of crashing containers (up to 5 pods)",
             "{K} get pods -A --no-headers 2>/dev/null | awk '$4 ~ /CrashLoopBackOff|Error|OOMKilled/ {print $1\" \"$2}' "
             "| head -n 5 | while read ns pod; do echo \"== $ns/$pod\"; {K} logs -n \"$ns\" \"$pod\" --all-containers "
             "--previous --tail=40 2>&1 | tail -n 40; done", k8s="nsslash", timeout=120, max_lines=250),
    ]),
    ("k8s-vcf", "VCF services runtime objects (best effort)", [
        kctl("Components", "{K} get components -A 2>&1 | head -n 200", k8s="nsrows"),
        kctl("Package installs", "{K} get packageinstalls -A 2>&1 | head -n 200", k8s="nsrows"),
    ]),
]

ESXI_GROUPS = [
    ("system", "Version, hardware, uptime", [
        cmd("ESXi version", "vmware -vl"),
        cmd("Host name", "esxcli system hostname get",
            harvest=[("host", r"(?m)^\s*Fully Qualified Domain Name:\s*(\S+)", None),
                     ("host", r"(?m)^\s*Host Name:\s*(\S+)", None),
                     ("domain", r"(?m)^\s*Domain Name:\s*(\S+)", None)]),
        cmd("Maintenance mode", "esxcli system maintenanceMode get"),
        cmd("Uptime and load", "uptime"),
        cmd("Hardware platform", "esxcli hardware platform get"),
        cmd("CPU summary", "esxcli hardware cpu global get"),
        cmd("Memory summary", "esxcli hardware memory get"),
        cmd("Image profile", "esxcli software profile get 2>&1 | head -n 12"),
        cmd("Core dump configuration",
            "esxcli system coredump file get 2>&1; esxcli system coredump partition get 2>&1"),
    ]),
    ("services", "Management agents and firewall", [
        cmd("hostd", "/etc/init.d/hostd status 2>&1"),
        cmd("vpxa", "/etc/init.d/vpxa status 2>&1"),
        cmd("Enabled services", "chkconfig --list 2>&1 | grep -w on | head -n 80"),
        cmd("Firewall state", "esxcli network firewall get"),
        cmd("Syslog configuration", "esxcli system syslog config get"),
        cmd("Host certificate",
            "openssl x509 -in /etc/vmware/ssl/rui.crt -noout -subject -issuer -dates 2>&1"),
    ]),
    ("time", "Time and NTP", [
        cmd("System time", "esxcli system time get"),
        cmd("NTP configuration", "esxcli system ntp get 2>&1"),
        cmd("NTP peers", "ntpq -pn 2>&1 | head -n 12"),
    ]),
    ("storage", "Datastores, adapters, paths", [
        cmd("Filesystems", "esxcli storage filesystem list",
            harvest=[("datastore",
                      r"(?m)^/vmfs/volumes/\S+\s+(.+?)\s+\S+\s+(?:true|false)\s+\S+\s+\d+\s+\d+\s*$",
                      None)]),
        cmd("Disk usage", "df -h 2>&1"),
        cmd("Ramdisk usage", "vdf -h 2>&1 | sed -n '/^Ramdisk/,$p'"),
        cmd("Storage adapters", "esxcli storage core adapter list"),
        cmd("Path state counts",
            "esxcli storage core path list 2>&1 | grep -E '^ +State:' | sort | uniq -c"),
        cmd("Device status counts",
            "esxcli storage core device list 2>&1 | grep -E '^ +(Status|Is Offline|Is SSD|Is Local):'"
            " | sort | uniq -c"),
    ]),
    ("network", "NICs, VMkernel, switches", [
        cmd("Physical NICs", "esxcli network nic list"),
        cmd("VMkernel interfaces", "esxcli network ip interface list",
            harvest=[("portgroup", r"(?m)^\s*Portgroup:\s*(.+?)\s*$", None),
                     ("dvs", r"(?m)^\s*VDS Name:\s*(.+?)\s*$", None)]),
        cmd("VMkernel IPv4", "esxcli network ip interface ipv4 get"),
        cmd("TCP/IP stacks", "esxcli network ip netstack list"),
        cmd("IPv4 routes", "esxcli network ip route ipv4 list"),
        cmd("DNS servers", "esxcli network ip dns server list"),
        cmd("DNS search domains", "esxcli network ip dns search list",
            harvest=[("domain", r"(?m)^\s*DNSSearch Domains:\s*(.+)$", r"[\s,]+")]),
        cmd("Standard switches", "esxcli network vswitch standard list 2>&1",
            harvest=[("portgroup", r"(?m)^\s*Portgroups:\s*(.+)$", r"\s*,\s*")]),
        cmd("Distributed switches",
            "esxcli network vswitch dvs vmware list 2>&1 | grep -vE '^ +(Port ID|In Use|Client|Port):'"
            " | head -n 120",
            harvest=[("dvs", r"(?m)^   Name:\s*(.+?)\s*$", None)]),
    ]),
    ("vsan", "vSAN", [
        cmd("vSAN cluster membership", "esxcli vsan cluster get 2>&1"),
        cmd("vSAN network", "esxcli vsan network list 2>&1"),
        cmd("vSAN health summary", "esxcli vsan health cluster list 2>&1", timeout=90),
        cmd("vSAN object health", "esxcli vsan debug object health summary get 2>&1", timeout=90),
        cmd("vSAN resync summary", "esxcli vsan debug resync summary get 2>&1", timeout=60),
    ]),
    ("nsx", "NSX transport node", [
        cmd("NSX VIBs", "esxcli software vib list 2>&1 | grep -i nsx | head -n 40"),
        cmd("NSX manager connections", "nsxcli -c 'get managers' 2>&1", timeout=45),
        cmd("NSX controller connections", "nsxcli -c 'get controllers' 2>&1", timeout=45),
    ]),
    ("vms", "Running VM count", [
        cmd("Running VMs (count only)", "esxcli vm process list 2>&1 | grep -c 'World ID'"),
    ]),
    ("passwords", "Local accounts, password age and lockout", [
        cmd("Local accounts", "esxcli system account list 2>&1"),
        # Only user name and dates are printed from /etc/shadow, never the password hash.
        cmd("Password age (days)",
            "today=$(( $(date +%s) / 86400 )); awk -F: -v t=$today '$2 !~ /^[*!]/ && $2 != \"\" "
            "{ age = ($3 == \"\" ? \"?\" : t - $3); printf \"%-20s changed %s days ago, max age %s days\\n\", "
            "$1, age, ($5 == \"\" ? \"none\" : $5) }' /etc/shadow 2>&1"),
        cmd("Password and lockout policy",
            "for o in PasswordMaxDays PasswordHistory PasswordQualityControl AccountLockFailures AccountUnlockTime; do "
            "echo \"== /Security/$o\"; esxcli system settings advanced list -o /Security/$o 2>&1; done",
            post=post_esxi_policy),
        cmd("Failed logins / locked root", "pam_tally2 --user root 2>&1 || faillock --user root 2>&1"),
    ]),
]

VCENTER_GROUPS = [
    ("vc-services", "vCenter version and services", [
        cmd("vCenter version", "vpxd -v 2>&1"),
        cmd("Service status", "service-control --status --all 2>&1", timeout=120),
        cmd("Primary network identifier",
            "/usr/lib/vmware-vmafd/bin/vmafd-cli get-pnid --server-name localhost 2>&1",
            harvest=[("host", r"(?m)^(\S+)\s*$", None)]),
        cmd("SSO domain",
            "/usr/lib/vmware-vmafd/bin/vmafd-cli get-domain-name --server-name localhost 2>&1",
            harvest=[("domain", r"(?m)^(\S+\.\S+)\s*$", None)]),
    ]),
    ("vc-certs", "Certificates in VECS", [
        cmd("VECS certificate validity",
            "for s in $(/usr/lib/vmware-vmafd/bin/vecs-cli store list 2>/dev/null"
            " | grep -v TRUSTED_ROOT_CRLS); do echo \"[store] $s\";"
            " /usr/lib/vmware-vmafd/bin/vecs-cli entry list --store \"$s\" --text 2>/dev/null"
            " | grep -E 'Alias|Not Before|Not After|Subject:|Issuer:'; done",
            timeout=120, max_lines=300),
    ]),
    ("vc-sso", "Embedded SSO: services, domain, Lookup Service, errors, passwords", [
        cmd("SSO and directory services",
            "for svc in vmdird vmware-stsd vmware-sts-idmd lookupsvc vmafdd vmcad vmware-vmon; do "
            "printf '%-18s ' \"$svc\"; service-control --status \"$svc\" 2>&1 | tr '\\n' ' '; echo; done", timeout=120),
        cmd("SSO domain, site and directory state",
            "A=/usr/lib/vmware-vmafd/bin/vmafd-cli; for q in get-domain-name get-site-name get-domain-state "
            "get-dc-name get-ls-location get-pnid; do printf '%-18s ' \"$q\"; $A $q --server-name localhost 2>&1 "
            "| tr '\\n' ' '; echo; done", harvest=[("domain", r"(?m)^get-domain-name\s+(\S+\.\S+)", None)]),
        cmd("Lookup Service registrations by host (all should point to this vCenter)",
            "echo \"PNID: $(/usr/lib/vmware-vmafd/bin/vmafd-cli get-pnid --server-name localhost 2>/dev/null)\"; "
            "PY=$(command -v python3 || command -v python); $PY /usr/lib/vmware-lookupsvc/tools/lstool.py list "
            "--url http://localhost:7090/lookupservice/sdk --no-check-cert 2>/dev/null | grep -oE '://[^/:\"]+' "
            "| sed 's#://##' | sort | uniq -c | sort -rn | head -n 25", timeout=120),
        cmd("Recent SSO and directory errors (24 h)",
            "find /var/log/vmware/sso /var/log/vmware/vmdird /var/log/vmware/vmafdd -name '*.log' -mmin -1440 "
            "2>/dev/null | head -n 40 | xargs -r grep -hiE 'error|exception|expired|locked|failed|invalid credential' "
            "2>/dev/null | tail -n 150", timeout=120, max_lines=200, post=post_sso_errors),
        cmd("Active Directory join (Integrated Windows Authentication)", "/opt/likewise/bin/domainjoin-cli query 2>&1"),
        cmd("vmdir database size", "du -sh /storage/db/vmware-vmdir 2>&1"),
        cmd("Local account password ageing",
            "for u in $(awk -F: '($3==0 || $3>=1000) && $7 !~ /nologin|false/ {print $1}' /etc/passwd); do "
            "echo \"== $u\"; chage -l \"$u\" 2>&1 | head -n 4; done"),
    ]),
    ("vc-supervisor", "Supervisor / Workload Management (wcp service)", [
        cmd("Workload Control Plane service", "vmon-cli -s wcp 2>&1 | head -n 12"),
        # The script also prints the Supervisor root password: only the cluster and IP lines are kept
        # (and a PWD line would be redacted anyway).
        cmd("Supervisor clusters and control-plane address",
            "/usr/lib/vmware-wcp/decryptK8Pwd.py 2>&1 | grep -iE '^ *(cluster|ip)\\b' || echo 'no Supervisor found'"),
        cmd("wcpsvc errors (last 150)",
            "grep -iE 'error|fail|x509' /var/log/vmware/wcp/wcpsvc.log 2>&1 | tail -n 150", max_lines=200,
            post=post_log_dedup),
        cmd("ESX Agent Manager errors (last 60)",
            "grep -iE ' error |exception' /var/log/vmware/eam/eam.log 2>&1 | tail -n 60", max_lines=80,
            post=post_log_dedup),
    ]),
    ("vc-api-namespaces", "Supervisor namespaces (vCenter API from this computer; needs a vCenter SSO login)", [
        apicmd("Supervisors", "supervisors", "GET /api/vcenter/namespace-management/clusters (+ details)",
               harvest=[H_SUPERVISOR]),
        apicmd("vSphere Namespaces", "namespaces", "GET /api/vcenter/namespaces/instances (+ details)",
               harvest=[H_NAMESPACE, H_SUPERVISOR], max_lines=1500),
        apicmd("Supervisor services", "services", "GET /api/vcenter/namespace-management/supervisor-services",
               harvest=[H_SUPERVISOR]),
    ]),
    ("vc-api-sso", "SSO certificates, identity sources and local passwords (vCenter API; needs an SSO login)", [
        apicmd("STS signing certificate (SSO token signing)", "vc_sts", "GET /api/vcenter/certificate-management/vcenter/signing-certificate"),
        apicmd("Machine SSL certificate", "vc_tls", "GET /api/vcenter/certificate-management/vcenter/tls"),
        apicmd("Identity sources", "vc_idp", "GET /api/vcenter/identity/providers"),
        apicmd("Appliance local accounts and password expiry", "vc_accounts", "GET /api/appliance/local-accounts (+ details)"),
    ]),
    ("vc-storage", "Appliance partitions and core dumps", [
        cmd("Key partitions", "df -hP /storage/log /storage/db /storage/seat /storage/core 2>&1", post=post_df),
        cmd("Core dumps", "ls -lh /storage/core 2>&1 | tail -n 15"),
    ]),
] + linux_groups()

NSX_NODE_CMDS = [
    ncli("Uptime", "get uptime"),
    ncli("CPU", "get cpu-stats", post=post_cpuinfo),
    ncli("Memory", "get memory-stats", post=post_meminfo),
    ncli("Filesystems", "get filesystem-stats"),
    ncli("Core dumps", "get core-dumps"),
    ncli("NTP servers", "get ntp-servers"),
    ncli("NTP associations", "get ntp-server associations", post=post_ntpq_peers),
    ncli("DNS servers", "get name-servers"),
    ncli("Password expiry: admin", "get user admin password-expiration", covered_by="nsx_users"),
    ncli("Password expiry: audit", "get user audit password-expiration", covered_by="nsx_users"),
]

NSX_GROUPS = [
    ("nsx-cluster", "Management cluster and services", [
        ncli("Version", "get version", post=post_nsx_version),
        ncli("Cluster status", "get cluster status", timeout=60, post=post_nsx_cluster_status),
        ncli("Cluster configuration", "get cluster config", timeout=60, max_lines=300,
             post=post_nsx_cluster_config),
        ncli("Managers", "get managers"),
        ncli("Services", "get services", timeout=60, max_lines=400, post=post_nsx_services),
    ]),
    ("nsx-node", "Node resources, time, DNS", NSX_NODE_CMDS),
    ("nsx-api-health", "NSX health from the NSX API (from this computer; needs an NSX API login)", [
        apicmd("Cluster status (API)", "nsx_cluster", "GET /api/v1/cluster/status", harvest=[H_NSXNODE]),
        apicmd("Open alarms", "nsx_alarms", "GET /api/v1/alarms?status=OPEN,ACKNOWLEDGED,SUPPRESSED",
               harvest=[H_NSXNODE], max_lines=800),
        apicmd("Transport nodes", "nsx_transport_nodes", "GET /api/v1/transport-nodes (+ state)",
               harvest=[H_NSXNODE], max_lines=800),
        apicmd("Edge clusters", "nsx_edge_clusters", "GET /api/v1/edge-clusters", harvest=[H_EDGECL]),
        apicmd("Backups", "nsx_backups", "GET /api/v1/cluster/backups/history (+ config)"),
        apicmd("Local users and password expiry", "nsx_users", "GET /api/v1/node/users (+ auth policy)"),
        apicmd("VM logical ports: orphaned, VM off, or down while the VM runs", "nsx_logical_ports",
               "GET /api/v1/logical-ports, /api/v1/fabric/vifs, /api/v1/fabric/virtual-machines (+ port status)",
               max_lines=600),
    ]),
    ("os", "OS level (root shell only)", [
        cmd("Disk usage", "df -hP", post=post_df),
        cmd("Failed units", "systemctl --failed --no-pager --no-legend 2>&1 | head -n 40"),
        cmd("Password ageing", "for u in root admin audit; do echo \"== $u\";"
                               " chage -l \"$u\" 2>&1 | head -n 4; done"),
    ]),
]

NSXEDGE_GROUPS = [
    ("edge-status", "Edge cluster and connectivity", [
        ncli("Version", "get version", post=post_nsx_version),
        ncli("Managers", "get managers"),
        ncli("Controllers", "get controllers"),
        ncli("Edge cluster status", "get edge-cluster status", timeout=60),
        ncli("Maintenance mode", "get maintenance-mode"),
        ncli("Logical routers", "get logical-routers",
             harvest=[("lrouter",
                       r"(?m)^[0-9a-fA-F-]{36}\s+\d+\s+\d+\s+(\S+)\s+[A-Z][A-Z0-9_]+", None)]),
        ncli("Services", "get services", timeout=60, max_lines=300),
    ]),
    ("edge-dataplane", "Datapath: interfaces, tunnels, BFD (best effort)", [
        ncli("Interfaces", "get interfaces", timeout=60, max_lines=300),
        ncli("Tunnel ports", "get tunnel-ports", timeout=60),
        ncli("BFD sessions", "get bfd-sessions", timeout=60, max_lines=300),
        ncli("Datapath CPU", "get dataplane cpu stats", timeout=60),
    ]),
    ("edge-node", "Node resources, time, DNS", NSX_NODE_CMDS),
]

SDDC_GROUPS = [
    ("sddc-services", "SDDC Manager services", [
        cmd("VCF service units",
            "systemctl list-units --type=service --all --no-pager --no-legend 2>&1 | grep -Ei"
            " 'vcf|sddc|lcm|domainmanager|operationsmanager|commonsvcs|nginx|postgres|sos'"),
        cmd("Service about endpoints",
            "for s in lcm domainmanager operationsmanager commonsvcs; do echo \"== $s\";"
            " curl -s -m 8 \"http://localhost/$s/about\" 2>&1; echo; done", timeout=60),
    ]),
    ("sddc-api-credentials", "Stored credentials and password rotations (SDDC Manager API; needs an SSO login)", [
        apicmd("Stored credentials and expiry", "sddc_credentials", "GET /v1/credentials", max_lines=800),
        apicmd("Recent password rotation / update tasks", "sddc_credential_tasks", "GET /v1/credentials/tasks"),
    ]),
] + linux_groups()

NODE_K8S_GROUPS = [
    ("node-certs", "Kubernetes certificates on this node", [
        cmd("kubelet certificates",
            "for f in /var/lib/kubelet/pki/kubelet-client-current.pem /var/lib/kubelet/pki/kubelet.crt; do "
            "[ -f \"$f\" ] && echo \"$f: $(openssl x509 -enddate -noout -in \"$f\" 2>&1)\"; done; true", sudo=True),
        cmd("Control-plane certificates (kubeadm)",
            "if [ ! -f /etc/kubernetes/pki/apiserver.crt ] && [ ! -f /etc/kubernetes/manifests/kube-apiserver.yaml ];"
            " then echo 'not a control-plane node (no /etc/kubernetes/pki/apiserver.crt): nothing to check';"
            " elif command -v kubeadm >/dev/null 2>&1; then kubeadm certs check-expiration 2>&1 | head -n 40; "
            "else for f in /etc/kubernetes/pki/*.crt /etc/kubernetes/pki/etcd/*.crt; do [ -f \"$f\" ] && "
            "echo \"$f: $(openssl x509 -enddate -noout -in \"$f\" 2>&1)\"; done; fi", sudo=True, timeout=60),
    ]),
]

MGMT_NODE_GROUPS = [
    ("node-runtime", "Kubernetes node agents (kubelet, containerd)", [
        cmd("kubelet and containerd", "systemctl status kubelet containerd --no-pager --lines=0 2>&1 | head -n 200",
            sudo=True, post=post_systemctl_status, max_lines=60),
        cmd("Containers not running",
            "crictl ps -a 2>/dev/null | awk 'NR==1 || $0 !~ /Running/' | head -n 60", sudo=True),
        cmd("Recent kubelet errors",
            "journalctl -u kubelet --since '-2h' --no-pager 2>/dev/null | grep -iE 'error|fail' | tail -n 150",
            sudo=True, post=post_kubelet_errors, max_lines=80),
    ]),
] + NODE_K8S_GROUPS + linux_groups(cert=False)

MGMT_CLUSTER_GROUPS = K8S_GROUPS + [
    ("k8s-nodes", "Control planes and workers (worker VMs are discovered, not listed)", [
        kctl("Pods per node",
             "{K} get pods -A -o wide --no-headers 2>&1 | awk '{n[$8]++; if ($4!=\"Running\" && $4!=\"Completed\")"
             " b[$8]++} END{for(k in n) printf \"%-50s pods %4d  not running %d\\n\", k, n[k], b[k]+0}' | sort"),
        kctl("Cluster API machines (worker VM lifecycle)",
             "{K} get clusters,machinedeployments,machinesets,machines -A -o wide 2>&1 | head -n 120",
             k8s="nsrows", max_lines=150),
        kctl("Machine health checks", "{K} get machinehealthchecks -A 2>&1 | head -n 40", k8s="nsrows"),
    ]),
]


SUPERVISOR_GROUPS = [
    ("k8s-supervisor", "Supervisor workloads: VKS clusters, Cluster API machines, VM Service", [
        kctl("VKS / Cluster API clusters",
             "{K} get clusters.cluster.x-k8s.io,tanzukubernetesclusters -A -o wide 2>&1 | head -n 120",
             k8s="nsrows", max_lines=150),
        kctl("Machines not Running",
             "{K} get machines.cluster.x-k8s.io -A -o wide --no-headers 2>&1 | grep -v ' Running ' | head -n 80",
             k8s="nsrows"),
        kctl("All machines", "{K} get machines.cluster.x-k8s.io -A -o wide 2>&1", k8s="nsrows", max_lines=400),
        kctl("Machine deployments and health checks",
             "{K} get machinedeployments,machinehealthchecks -A 2>&1 | head -n 80", k8s="nsrows"),
        kctl("VM Service virtual machines", "{K} get virtualmachines -A -o wide 2>&1", k8s="nsrows", max_lines=400),
        kctl("Supervisor services", "{K} get supervisorservices,packageinstalls -A 2>&1 | head -n 120", k8s="nsrows"),
        kctl("Cluster API and VM operator controller errors (best effort)",
             "for p in $({K} get pods -A --no-headers 2>/dev/null | awk '$2 ~ /(capi|capv|capw|vmop|vm-operator)"
             ".*controller-manager/ {print $1\"/\"$2}'); do echo \"== ${p#*/}\"; {K} logs -n \"${p%%/*}\" \"${p#*/}\" "
             "--all-containers --tail=300 2>/dev/null | grep -iE 'error|fail' | tail -n 100; done", timeout=90, max_lines=200,
             post=post_log_dedup),
    ]),
]


SUPERVISOR_GROUPS.append(("k8s-namespaces", "vSphere Namespaces as seen inside the Supervisor", [
    kctl("vSphere Namespaces", "{K} get ns -l vSphereClusterID -o wide 2>&1 || {K} get ns 2>&1", k8s="ns"),
    kctl("Resource quotas (CPU, memory, storage per policy)",
         "{K} describe resourcequota -A 2>&1 | grep -vE '^(Annotations|Labels):' | head -n 400",
         k8s="nsrows", max_lines=400),
    kctl("Limit ranges", "{K} get limitrange -A 2>&1", k8s="nsrows"),
    kctl("VM classes bound to namespaces",
         "{K} get virtualmachineclassbindings -A 2>/dev/null || {K} get virtualmachineclasses -A 2>&1",
         k8s="nsrows", max_lines=300),
    kctl("Namespace networks (best effort)",
         "{K} get networkinterfaces,virtualnetworks,subnetsets -A 2>&1 | head -n 200", k8s="nsrows"),
    kctl("Role bindings (namespace permissions)",
         "{K} get rolebindings -A -o wide 2>&1 | grep -vE ' system:|kube-system|vmware-system' | head -n 200",
         k8s="nsrows"),
    kctl("Pods not Running, per namespace",
         "{K} get pods -A --no-headers 2>&1 | awk '$4!=\"Running\" && $4!=\"Completed\"' | head -n 150",
         k8s="nsrows"),
]))


def endpoint_group(endpoints):
    """Checks for the VCF management service endpoints configured for a cluster."""
    if not endpoints:
        return []
    cmds = []
    for name, services in endpoints.items():
        q = shlex.quote(name)
        cmds.append(cmd(
            "Endpoint %s: %s" % (name, ", ".join(services)),
            "n=%s; echo '== DNS'; getent hosts \"$n\" || echo 'does not resolve'; "
            "echo '== HTTPS'; curl -sk -m 10 -o /dev/null -w 'HTTP %%{http_code} in %%{time_total}s\\n' "
            "\"https://$n/\" 2>&1 || echo 'no HTTPS response'; "
            "echo '== Certificate'; echo | timeout 10 openssl s_client -connect \"$n:443\" -servername \"$n\" "
            "2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>&1" % q,
            timeout=45, harvest=[("host", r"(?m)^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:]+)[ \t]+(\S.*)$",
                                 r"\s+")]))
    # Names are left unescaped (a dot matching any character is harmless here) so that the
    # anonymizer recognises them in the command line shown in the report.
    pattern = "|".join(n if re.fullmatch(r"[A-Za-z0-9.-]+", n) else re.escape(n) for n in endpoints)
    cmds.append(kctl(
        "Kubernetes objects that serve these endpoints",
        "{K} get ingress,httproutes.gateway.networking.k8s.io,gateways.gateway.networking.k8s.io,svc -A -o wide "
        "2>/dev/null | grep -iE -- %s || echo 'no ingress, route or service names these endpoints'"
        % shlex.quote("^NAMESPACE|" + pattern), k8s="nsrows", max_lines=150))
    return [("endpoints", "VCF management service endpoints", cmds)]


def is_cluster_group(key):
    """Groups of a VCF management cluster that describe the whole cluster: collected once."""
    return key.startswith("k8s-") or key == "endpoints"


# ----------------------------------------------------------------------------
# VCF Automation: its own Kubernetes cluster, nodes reached as vmware-system-user.
# The checks below look only at the Automation namespaces. {NSRX} is replaced at run
# time by the namespace pattern (inventory option "namespaces", or the default below).
# ----------------------------------------------------------------------------
AUTOMATION_NS_DEFAULT = (r"^(prelude|vmsp-.*|vcfa.*|.*automation.*|tenant-manager.*|cci-.*|"
                         r"provisioning.*|idem.*|abx.*)$")

_VCFA_NS = ("NS=$({K} get ns --no-headers -o custom-columns=:metadata.name 2>/dev/null | grep -E {NSRX}"
            " | tr '\\n' ' '); if [ -z \"$NS\" ]; then echo \"No VCF Automation namespaces found (pattern:"
            " {NSRX}). Set 'namespaces = ...' in this inventory section.\"; exit 0; fi; ")
# keep only rows whose first column (the namespace) is one of $NS
_VCFA_IN = "awk -v ns=\" $NS\" 'index(ns, \" \"$1\" \")"
_NONE = "out=$(%s); if [ -n \"$out\" ]; then echo \"$out\"; else echo none; fi"


def _vcfa(label, body, **kw):
    kw.setdefault("timeout", 90)
    return kctl(label, _VCFA_NS + body, **kw)


AUTOMATION_GROUPS = [
    ("vcfa-services", "VCF Automation services (pods in the Automation namespaces only)", [
        _vcfa("Automation namespaces and pod states",
              "{K} get pods -A --no-headers 2>&1 | " + _VCFA_IN + " {c[$1\" \"$4]++} END{for(k in c) print k, c[k]}'"
              " | sort", k8s="nsrows"),
        _vcfa("Automation pods not Running or not Ready", _NONE % (
              "{K} get pods -A -o wide --no-headers 2>&1 | " + _VCFA_IN +
              " {split($3,a,\"/\"); if ($4!=\"Completed\" && ($4!=\"Running\" || a[1]!=a[2])) print}'"),
              k8s="nsrows", max_lines=200),
        _vcfa("Automation workloads below desired replicas", _NONE % (
              "{K} get deploy,sts -A --no-headers 2>&1 | " + _VCFA_IN +
              " {split($3,a,\"/\"); if (a[1]!=a[2]) print}'"), k8s="nsrows"),
        _vcfa("Automation pods with restarts", _NONE % (
              "{K} get pods -A --no-headers 2>&1 | " + _VCFA_IN + " && $5+0>0' | sort -k5 -n -r | head -n 25"),
              k8s="nsrows"),
        _vcfa("Automation warning events (latest 60)", _NONE % (
              "{K} get events -A --field-selector type!=Normal --sort-by=.lastTimestamp --no-headers 2>&1 | "
              + _VCFA_IN + "' | tail -n 60"), k8s="nsrows", max_lines=120),
    ]),
    ("vcfa-detail", "VCF Automation versions, databases, logs and certificates", [
        _vcfa("Automation container images (versions)",
              "for ns in $NS; do {K} get pods -n \"$ns\" -o jsonpath='{range .items[*]}{range .spec.containers[*]}"
              "{.image}{\"\\n\"}{end}{end}' 2>/dev/null; done | sed 's#^.*/##; s#:\\([^:]*\\)$# version \\1#'"
              " | sort | uniq -c | sort -k1 -n -r"
              " | head -n 60", max_lines=80),
        _vcfa("Automation databases and volumes",
              "echo 'database pods:'; " + _NONE % (
                  "{K} get pods -A -o wide --no-headers 2>&1 | " + _VCFA_IN +
                  " && $2 ~ /postgres|pgsql|-db-|database/'") + "; echo; echo 'volume claims:'; " + _NONE % (
                  "{K} get pvc -A --no-headers 2>&1 | " + _VCFA_IN + "'"), k8s="nsrows", max_lines=150),
        _vcfa("Errors in Automation pod logs (last 30 min)", _NONE % (
              "for ns in $NS; do for p in $({K} get pods -n \"$ns\" --field-selector=status.phase=Running -o name"
              " 2>/dev/null); do e=$({K} logs -n \"$ns\" \"$p\" --all-containers --since=30m --tail=5000 2>/dev/null"
              " | grep -iE '(^|[^a-z])(error|fatal|severe)([^a-z]|$)|exception'); n=$(printf '%s\\n' \"$e\" | grep -c .);"
              " if [ \"$n\" -gt 0 ]; then echo \"== $ns/${p#pod/}: $n error line(s)\"; printf '%s\\n' \"$e\""
              " | tail -n 2 | cut -c1-300 | sed 's/^/   /'; fi; done; done"),
              k8s="nsslash", timeout=300, max_lines=300),
        _vcfa("Automation ingress hosts and certificates",
              "hosts=$(for ns in $NS; do {K} get ingress -n \"$ns\" -o jsonpath='{range .items[*]}"
              "{range .spec.rules[*]}{.host}{\"\\n\"}{end}{end}' 2>/dev/null; done | grep . | sort -u | head -n 5);"
              " if [ -z \"$hosts\" ]; then echo 'no ingress objects in the Automation namespaces'; exit 0; fi;"
              " for h in $hosts; do echo \"== $h\"; c=$(echo | timeout 10 openssl s_client -connect \"$h:443\""
              " -servername \"$h\" 2>/dev/null | openssl x509 2>/dev/null); if [ -z \"$c\" ]; then"
              " echo '   no TLS answer on port 443'; continue; fi; printf '%s\\n' \"$c\" | openssl x509 -noout"
              " -subject -issuer -enddate | sed 's/^/   /'; printf '%s\\n' \"$c\" | openssl x509 -noout"
              " -checkend 2592000 >/dev/null || echo '   WARNING: the certificate expires within 30 days'; done",
              timeout=120),
        cmd("vracli status (if installed)",
            "if command -v vracli >/dev/null 2>&1; then vracli version 2>&1 | head -n 5; vracli status 2>&1"
            " | head -n 120; else echo 'vracli is not installed on this node'; fi", timeout=90, sudo=True),
    ]),
]


def automation_ns_regex(value):
    """Inventory 'namespaces = prelude, vmsp-*' -> an anchored regex; empty -> the default."""
    names = [x for x in re.split(r"[\s,]+", value or "") if x]
    bad = [x for x in names if not re.fullmatch(r"[a-z0-9*][a-z0-9.*-]*", x)]
    if bad:
        raise ValueError("namespace '%s' may only contain a-z, 0-9, '-', '.' and '*'" % bad[0])
    if not names:
        return AUTOMATION_NS_DEFAULT
    return "^(%s)$" % "|".join(x.replace(".", r"\.").replace("*", ".*") for x in names)


OPSNET_GROUPS = [
    ("opsnet-cli", "Operations for networks CLI (works as consoleuser or support)", [
        ncli("Version", "show-version"),
        ncli("Service status", "show-service-status", timeout=90, max_lines=200),
        ncli("SSH service", "ssh-service status"),
    ]),
    ("opsnet-health", "Service health and application logs (support user)", [
        cmd("Service health check",
            "cd ~ 2>/dev/null; if [ -x ./check-service-health.sh ]; then ./check-service-health.sh -d -p 2>&1 "
            "| tail -n 250; else echo 'check-service-health.sh is not in the home directory of this user "
            "(log in as support)'; fi", timeout=300, max_lines=300),
        cmd("Appliance OS", "lsb_release -ds 2>/dev/null || head -n 4 /etc/os-release"),
        cmd("Recent errors in application logs (last 4 h)",
            "if [ -d /var/log/arkin ]; then find /var/log/arkin -name '*.log' -mmin -240 2>/dev/null | head -n 60 "
            "| xargs -r grep -hiE ' error |exception|fatal' 2>/dev/null | tail -n 150; "
            "else echo 'no /var/log/arkin on this node'; fi", timeout=120, max_lines=200, sudo=True,
            post=post_log_dedup),
        cmd("Largest log directories", "du -xsh /var/log/* 2>/dev/null | sort -h | tail -n 10", sudo=True),
    ]),
] + linux_groups()

# component types whose nodes run Kubernetes: kubectl is detected and {K} is available
K8S_TYPES = ("k8s", "vcfmgmt", "supervisor", "vcfa")

COMPONENTS = {
    "esxi": {"title": "ESXi hosts", "user": "root", "prefix": "esxi", "groups": ESXI_GROUPS},
    "vcenter": {"title": "vCenter Server", "user": "root", "prefix": "vcenter",
                "groups": VCENTER_GROUPS, "pty_escalate": "shell"},
    "nsx": {"title": "NSX Manager", "user": "admin", "prefix": "nsxmgr", "groups": NSX_GROUPS,
            "nsxcli": True, "nsxcli_wrap": "su admin -c {q}"},
    "nsxedge": {"title": "NSX Edge", "user": "admin", "prefix": "nsxedge",
                "groups": NSXEDGE_GROUPS, "nsxcli": True, "nsxcli_wrap": "nsxcli -c {q}"},
    "sddc": {"title": "SDDC Manager", "user": "vcf", "prefix": "sddcmgr", "groups": SDDC_GROUPS},
    "opsnet": {"title": "VCF Operations for networks (platform and collector nodes)", "user": "support",
               "prefix": "opsnet", "groups": OPSNET_GROUPS, "nsxcli": True, "nsxcli_wrap": "{c}"},
    "vcfa": {"title": "VCF Automation nodes", "user": "vmware-system-user", "prefix": "vcfa",
             "groups": AUTOMATION_GROUPS + K8S_GROUPS + MGMT_NODE_GROUPS, "sudo": "auto"},
    "k8s": {"title": "Kubernetes control plane (VCF services runtime, Operations, Automation)",
            "user": "vmware-system-user", "prefix": "k8snode",
            "groups": K8S_GROUPS + MGMT_NODE_GROUPS, "sudo": "auto"},
    "vcfmgmt": {"title": "VCF management cluster (services runtime: control planes and workers)",
                "user": "vmware-system-user", "prefix": "vcfmgmt", "sudo": "auto",
                "groups": MGMT_CLUSTER_GROUPS + MGMT_NODE_GROUPS, "host_label": "Control planes"},
    "supervisor": {"title": "vSphere Supervisor control plane", "user": "root", "prefix": "supervisor",
                   "groups": SUPERVISOR_GROUPS + K8S_GROUPS + MGMT_NODE_GROUPS, "host_label": "Control-plane address"},
    "linux": {"title": "Generic Linux appliance", "user": "root", "prefix": "linux",
              "groups": linux_groups()},
}

INVENTORY_TEMPLATE = """\
# vcf_diag inventory. This file contains real hostnames - keep it local.
# (inventory.ini is listed in .gitignore; do not commit it.)
#
# Section names are a component type, optionally followed by ":label" so you
# can keep several groups of the same type and pick between them at run time:
#     [esxi:mgmt]   [esxi:wld01]   [k8s:runtime]   [k8s:automation]
# The label is used in placeholders (esxi-mgmt-01), so it appears in the
# report. Choose labels that are fine to share.
#
# Component types:
#   esxi     ESXi hosts                      (default user: root)
#   vcenter  vCenter Server                  (root; bash or appliance shell)
#   nsx      NSX Manager nodes               (admin = NSX CLI, or root)
#   nsxedge  NSX Edge nodes                  (admin = NSX CLI, or root)
#   sddc     SDDC Manager                    (vcf)
#   k8s      Kubernetes control-plane nodes: VCF services runtime, Operations,
#            Automation, Supervisor          (vmware-system-user, or root)
#   vcfmgmt  VCF management cluster: control-plane IPs + service endpoints,
#            workers found automatically     (vmware-system-user)
#   supervisor  vSphere Supervisor control plane (root; the vCenter check
#            "Supervisor clusters" shows its address)
#   opsnet   VCF Operations for networks platform / collector nodes (support or consoleuser)
#   vcfa     VCF Automation nodes            (vmware-system-user; Automation-specific
#            checks plus the Kubernetes and node checks)
#   linux    Any other Linux appliance, e.g. Operations for logs
#
# Per-section options (all optional):
#   user       = default username offered at the prompt
#   port       = SSH port (default 22)
#   sudo       = auto | yes | no    run commands through sudo (k8s default: auto)
#   escalate   = su                 log in, then "su -" (asks for the root password)
#   kubeconfig = /path/admin.conf   k8s only; auto-detected when omitted
#   kubectl    = /path/to/kubectl   k8s only; default "kubectl"
#   namespaces = prelude, vmsp-*    vcfa only; Automation namespaces (default: found by name)

[settings]
# anonymize = no      keep real names and addresses in reports (secrets are still redacted)
# max_lines = 200     output lines kept per check
# Extra DNS domains to scrub (domains of inventory hosts are learned automatically).
extra_domains =
# Extra words to scrub everywhere: company name, site codes, project names ...
scrub_terms =
# Dotted values that are version numbers, not IP addresses (kept readable).
keep_literals = 9.1.1.0
# Extra Kubernetes namespaces that are product namespaces and can stay readable.
keep_namespaces =
# parallel = 4
# timeout = 30

[esxi]
hosts =
#    esx01.example.internal
#    esx02.example.internal

[vcenter]
hosts =
# Supervisor namespace checks use the vCenter API from this computer with an SSO login:
# sso_user   = administrator@vsphere.local
# ca_file    = ~/vcenter-ca.pem    trust vCenter's CA (download from https://<vcenter>/certs/download.zip)
# tls_verify = no                  or skip certificate checks (not recommended)

[nsx]
hosts =
# NSX API health checks (alarms, cluster, transport nodes, backups) run from this computer:
# sso_user = admin      ca_file = ~/nsx-ca.pem      tls_verify = no

[opsnet]
hosts =
# user = support        (consoleuser runs the CLI checks only)

[vcfa]
hosts =
# user = vmware-system-user        namespaces = prelude, vmsp-*

[nsxedge]
hosts =

[sddc]
hosts =

[k8s:runtime]
hosts =

[k8s:automation]
hosts =

[linux:opslogs]
hosts =

# VCF management cluster (VCF services runtime). List only the control-plane IPs:
# worker nodes have generated VM names and are found through Kubernetes.
#   ssh_workers = yes   also log in to each discovered worker (same credentials)
[vcfmgmt:mgmt]
control_planes =
#    10.0.0.11, 10.0.0.12, 10.0.0.13
# ssh_workers = no

# vSphere Supervisor control plane. Its address is shown by the vCenter check
# "Supervisor clusters and control-plane address". The root password comes from
# running /usr/lib/vmware-wcp/decryptK8Pwd.py on vCenter yourself; the tool never shows it.
[supervisor]
hosts =

# The management services that run on that cluster: service name = endpoint (FQDN,
# short name or IP). Several services may share one endpoint. The section label must
# match the [vcfmgmt:...] label above.
[endpoints:mgmt]
# VCF Operations          = ops.example.internal
# VCF Automation          = auto.example.internal
# Fleet lifecycle         = fleet.example.internal
# Salt RaaS               = fleet.example.internal

# AI for --investigate and the Investigate tab: any OpenAI-compatible chat endpoint.
# The API key is never stored here: set the environment variable VCF_DIAG_AI_KEY,
# or type it when asked.
[ai]
# base_url    = https://ai.example.internal/v1     (the tool adds /chat/completions)
# model       = your-model-name
# provider    = openai                 openai, asksage (CAPRA and other Ask Sage servers) or azure
# auth_header = bearer                 or api-key (Azure OpenAI style)
# ca_file     = ~/internal-ca.pem      trust an internal CA; tls_verify = no skips the check
# use_proxy   = yes                    use the system proxy settings to reach it
# max_rounds  = 10                     rounds of diagnostics before the AI must conclude
# max_report_chars  = 150000           longest report sent to the AI in one message
# max_context_chars = 400000           older reports are shortened above this total

# Add your own read-only commands to a component type:
# [commands:esxi]
# Advanced settings changed from default = esxcli system settings advanced list -d
"""

# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
_print_lock = threading.Lock()
_log_sinks = []          # the GUI adds a function here to mirror progress lines


class Fatal(Exception):
    """An error the user has to fix; shown as a plain message, not a traceback."""

    def __init__(self, msg, code=2):
        Exception.__init__(self, msg)
        self.code = code


def log(msg=""):
    with _print_lock:
        print(msg, flush=True)
        for sink in _log_sinks:
            sink(msg)


def die(msg, code=2):
    raise Fatal(msg, code)


def split_list(value):
    return [v for v in re.split(r"[\s,]+", value or "") if v]


def is_ipv4(s):
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def is_plain_ipv4(s):
    """True for an IPv4 address that the report hides (not loopback, mask, multicast ...)."""
    if not is_ipv4(s):
        return False
    o = [int(x) for x in s.split(".")]
    return not (o[0] in (0, 127, 255) or o[0] >= 224 or (o[0] == 169 and o[1] == 254))


def is_ip(s):
    try:
        ipaddress.ip_address(s.split("%")[0])
        return True
    except ValueError:
        return False


def write_private(path, text):
    """Write a file that only the current user can read."""
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


# ----------------------------------------------------------------------------
# Placeholder mapping (persistent, private)
# ----------------------------------------------------------------------------
class Mapping:
    def __init__(self, path=None):
        self.path = path
        self.maps = {}
        self.counters = {}
        self.env_domains = []
        self.lock = threading.RLock()
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            self.maps = data.get("maps", {})
            self.counters = data.get("counters", {})
            self.env_domains = data.get("env_domains", [])

    def lookup(self, cat, real):
        return self.maps.get(cat, {}).get(real.lower())

    def get(self, cat, real, prefix=None, width=4):
        key = real.lower()
        with self.lock:
            m = self.maps.setdefault(cat, {})
            if key in m:
                return m[key]
            prefix = prefix or cat
            n = self.counters.get(prefix, 0) + 1
            self.counters[prefix] = n
            m[key] = "%s-%0*d" % (prefix, width, n)
            return m[key]

    def alias(self, cat, real, placeholder):
        with self.lock:
            self.maps.setdefault(cat, {}).setdefault(real.lower(), placeholder)

    def ipv4(self, ip):
        with self.lock:
            m = self.maps.setdefault("ipv4", {})
            if ip in m:
                return m[ip]
            nets = self.maps.setdefault("ipv4net", {})
            net = ip.rsplit(".", 1)[0]
            if net not in nets:
                n = self.counters.get("ipv4net", 0) + 1
                self.counters["ipv4net"] = n
                nets[net] = str(n)
            nid = nets[net]
            h = self.counters.get("ipv4h:" + nid, 0) + 1
            self.counters["ipv4h:" + nid] = h
            m[ip] = "ip-n%s-h%d" % (nid, h)
            return m[ip]

    def save(self):
        if not self.path:
            return
        d = os.path.dirname(self.path)
        os.makedirs(d, mode=0o700, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        with self.lock:
            data = {"_warning": "PRIVATE - maps placeholders to real names. Never share this file.",
                    "version": 1, "env_domains": sorted(set(self.env_domains)),
                    "counters": self.counters, "maps": self.maps}
            write_private(self.path, json.dumps(data, indent=1, sort_keys=True))

    def counts(self):
        return {c: len(v) for c, v in self.maps.items() if v and c != "ipv4net"}


# ----------------------------------------------------------------------------
# Anonymizer
# ----------------------------------------------------------------------------
TOK_O, TOK_C = "", ""
TOK_RX = re.compile(TOK_O + r"\d+" + TOK_C)

LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
HOSTNAME_RX = re.compile(r"(?:%s)(?:\.(?:%s))*" % (LABEL, LABEL))

GENERIC_TLDS = ("com net org edu gov mil int local lan corp internal intranet intra lab home "
                "cloud priv private test example invalid").split()
CC_TLDS = ("us uk de fr nl ca au jp ch se es eu nz ie dk fi no it be at pl br mx kr cn sg za in "
           "ru cz pt gr hu ro tr il ae sa hk tw").split()
# Product / public names that are useful to the analyst and not identifying.
SAFE_DOMAINS = set("""vmware.com broadcom.com broadcom.net vsphere.local cluster.local
kubernetes.io k8s.io ntp.org github.com docker.com docker.io python.org apache.org openssl.org
gnu.org kernel.org ubuntu.com canonical.com debian.org redhat.com w3.org microsoft.com apple.com
oracle.com java.com eclipse.org freedesktop.org example.com example.org example.net
projectcalico.org localhost.localdomain photon.local""".split())
REVERSED_FIRST = set("com org net io java javax sun jdk".split())
# Hostnames that are too generic to replace when they stand alone (the FQDN is
# still replaced). Avoids turning every "nsx" or "api" in the output into a token.
GENERIC_NAMES = set("""localhost localdomain www api ntp dns mail smtp ldap proxy vip lb kubernetes
kube registry vcenter vc vcsa nsx nsxt esx esxi sddc vcf ops auto automation operations logs
master worker node admin root manager mgmt edge backup time pool default test prod dev lab
host server cluster vsan vmware photon linux local none null true false""".split())
DEFAULT_OBJECT_NAMES = set("""vm network|management network|vmotion|vsan|datastore1|vsandatastore|
n/a|none|default|true|false|unknown""".replace("\n", "").split("|"))
SAFE_DN_VALUES = set("""vmware|vmware, inc.|vmware inc.|vmware inc|vmware engineering|us|ca|
california|palo alto|kubernetes|kube-apiserver|kubernetes-ca|kube-ca|etcd-ca|front-proxy-ca|
system:masters|system:nodes|broadcom|broadcom inc|broadcom, inc.|vsphere|local""".replace("\n", "").split("|"))
EMPTY_VALUES = set(["", "none", "n/a", "na", "not specified", "unknown", "default string", "0",
                    "to be filled by o.e.m.", "not available", "null", "-"])
DEFAULT_KEEP_NS = (r"default|kube-.*|vmware-.*|vmsp-.*|vcf-.*|vsp-.*|prelude.*|tanzu-.*|tkg-.*|"
                   r"svc-.*|cert-manager.*|kapp-controller.*|secretgen-controller|carvel-.*|"
                   r"istio-.*|envoy-gateway.*|contour.*|projectcontour|ingress.*|"
                   r"local-path-storage|velero.*|antrea.*|calico.*|cilium.*|monitoring|"
                   r"observability|logging|ops.*|vrli.*|vrops.*|vrni.*|fleet.*|identity.*|"
                   r"vidb.*|salt.*|telemetry.*|postgres.*|rabbitmq.*|kafka.*|flux-system|"
                   r"cap[a-z]*-.*|vks.*|.*-system")

RX_PEM = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----", re.S)
RX_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
RX_URLCRED = re.compile(r"(://[^/\s:@]+:)([^/\s@]+)(@)")
RX_AUTHZ = re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer|basic|token)\s+)(\S+)")
RX_KV_SECRET = re.compile(
    r"(?i)((?<![A-Za-z])[\w.-]*(?:password|passwd|pwd|secret|token|apikey|api[_-]key|access[_-]key|"
    r"private[_-]key|credential)[\w.-]*[\"']?\s*[:=]\s*)(\"[^\"\n]*\"|'[^'\n]*'|[^\s\"',;\[\]{}]+)")
# Keys that name a password *setting* (length, history, age ...), not a secret. Their value is
# kept when it is a plain number, boolean or null, so password policies stay readable.
RX_KV_POLICY_KEY = re.compile(
    r"(?i)(?:length|len|chars|count|remembrance|history|frequency|expir\w*|change|changed|age|days|"
    r"period|attempts|failures|repeats|sequence|lockout\w*|status|enabled|required|policy|complexity)[\"']?$")
RX_KV_PLAIN_VALUE = re.compile(r"(?i)[\"']?(?:-?\d+(?:\.\d+)?|true|false|null|none)[\"']?")


def _kv_secret_is_setting(m):
    key = m.group(1).rstrip().rstrip(":=").rstrip()
    return bool(RX_KV_POLICY_KEY.search(key) and RX_KV_PLAIN_VALUE.fullmatch(m.group(2)))
RX_VMX_NAME = re.compile(r"(?<![\w.-])([A-Za-z0-9][A-Za-z0-9_.-]{1,80}?)\.vmx(?:@|\b)|\bvm=([^\s,;]+)")
RX_HASH = re.compile(r"\$(?:1|2[aby]?|5|6|y)\$[./A-Za-z0-9$]{20,}")
RX_SSHKEY = re.compile(r"AAAA[0-9A-Za-z+/]{60,}={0,2}")
RX_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{160,}={0,2}")
RX_SSHFP = re.compile(r"\b(SHA256|MD5):[A-Za-z0-9+/:]{22,}={0,2}")

RX_HEXSEQ = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{2}:){5,}[0-9A-Fa-f]{2}(?![\w:])")
RX_DASHMAC = re.compile(r"(?<![\w-])(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}(?![\w-])")
RX_UUID = re.compile(r"(?<![0-9A-Fa-f-])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
                     r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![0-9A-Fa-f-])")
RX_VMFS_UUID = re.compile(r"(?<![0-9A-Fa-f-])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-"
                          r"[0-9A-Fa-f]{12}(?![0-9A-Fa-f-])")
RX_SPACED_UUID = re.compile(r"(?:[0-9A-Fa-f]{2} ){7}[0-9A-Fa-f]{2}-(?:[0-9A-Fa-f]{2} ){7}[0-9A-Fa-f]{2}")
RX_0X_UUID = re.compile(r"(?:0x[0-9A-Fa-f]{1,2}\s+){15}0x[0-9A-Fa-f]{1,2}")
RX_DEVICE = re.compile(r"\b(naa|eui|vml)\.[0-9A-Fa-f]{8,}\b|\b(t10)\.[^\s,;:]+")
RX_IQN = re.compile(r"\biqn\.\d{4}-\d{2}\.[^\s,;]+")
RX_LICENSE = re.compile(r"(?<![A-Z0-9-])[A-Z0-9]{5}(?:-[A-Z0-9]{5}){4}(?![A-Z0-9-])")
RX_IPV4 = re.compile(r"(?<![\w.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\.?\d)(?!\w)")
RX_IPV6 = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
RX_VERSION_CTX = re.compile(r"(?i)(?<![A-Za-z])(?:version|ver|release|build|firmware|revision|rev)"
                            r"[ \t:=\"'(\[-]*\Z")
RX_SERIAL = re.compile(r"(?im)^([^\n]*?\b(?:serial\s*(?:number|no\.?|#)?|service\s*tag|asset\s*tag)\b"
                       r"[^\n:=]{0,20}[:=][ \t]*)([^\n]+?)[ \t]*$")
RX_DN_LINE = re.compile(r"(?i)\b(?:subject|issuer)\b|\bCN\s*=")
RX_DN_ATTR = re.compile(r"\b(CN|OU|O|L|ST|C|DC|emailAddress)(\s*=\s*)([^,/\n\"+;]+)")
RX_FQDN_ANY = re.compile(r"(?i)(?<![A-Za-z0-9_])((?:%s\.)+)(%s)(?![A-Za-z0-9_-])(?!\.[A-Za-z0-9_])"
                         % (LABEL, "|".join(GENERIC_TLDS + CC_TLDS)))
# Durations, ages and resource quantities that appear in kubectl / df tables (10m, 2d3h, 250m,
# 2236Mi, 15%, 1.5G). They are never names, and learning them would replace them everywhere.
RX_QUANTITY = re.compile(r"(?i)(?:\d+(?:\.\d+)?(?:ns|us|ms|s|m|h|d|w|y|ki|mi|gi|ti|pi|k|g|t|p|b|kb|mb|gb|tb|%)?"
                         r"|(?:\d+[smhdwy])+|<(?:unknown|none|invalid)>)")
# A dotted quad that starts a package version (VIB "4.2.1.0-9.1.24837353", "1.2.3.4-0.0.123")
RX_QUAD_VERSION_TAIL = re.compile(r"-\d+(?:\.\d+)*")
RX_DOTTED_QUAD = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?!\.?\d)(?!\w)")

OBJECT_CATS = {"edgecl": "edgecluster", "vcluster": "vcluster", "datastore": "datastore", "portgroup": "portgroup", "dvs": "dvs", "vm": "vm",
               "namespace": "ns", "k8sobj": "k8sobj", "lrouter": "lrouter", "term": "term"}


class Scrubber:
    def __init__(self, mapping, extra_domains=(), terms=(), keep_literals=(), keep_namespaces=(),
                 anonymize=True):
        self.m = mapping
        self.anonymize = anonymize      # False: only secrets are redacted
        self.env_domains = set()
        self.keep_literals = set(keep_literals)
        self.version_literals = set()
        self.kept_quads = {}
        keep_ns = "|".join([DEFAULT_KEEP_NS] + [re.escape(n) for n in keep_namespaces])
        self.keep_ns_rx = re.compile(r"(?i)^(?:%s)$" % keep_ns)
        self._env_rx = None
        self._env_rx_n = -1
        self._term_rx = []
        self._terms = {}
        self._toks = []
        for d in list(mapping.env_domains) + list(extra_domains):
            self.learn_domain(d)
        for t in terms:
            self.learn_term("term", t)

    # ---- learning ----------------------------------------------------------
    def learn_domain(self, d):
        d = d.strip().strip(".").lower()
        if not d or "." not in d or not HOSTNAME_RX.fullmatch(d) or is_ip(d):
            return None
        if not d.rsplit(".", 1)[1].isalpha() or self._safe(d):
            return None
        self.env_domains.add(d)
        return self.m.get("domain", d, width=2)

    def learn_host(self, name, prefix="host"):
        """Register a hostname (short or FQDN) that belongs to the environment."""
        name = name.strip().strip(".").lower()
        if not name or len(name) > 253 or not HOSTNAME_RX.fullmatch(name):
            return None
        if is_ip(name):
            return self.m.ipv4(name) if is_plain_ipv4(name) else None
        if self._safe(name):
            return None
        short, _, dom = name.partition(".")
        if dom:
            self.learn_domain(dom)
        if short.isdigit():
            return None
        return self.m.get("host", short, prefix=prefix, width=4 if prefix == "host" else 2)

    def learn_term(self, cat, value):
        v = value.strip()
        if len(v) < 3 or v.lower() in DEFAULT_OBJECT_NAMES or v.isdigit() or RX_QUANTITY.fullmatch(v):
            return None
        if re.fullmatch(r"(?i)(vSwitch|vmk|vmnic|vusb|eth|ens)\d+", v):
            return None
        if cat == "k8sobj" and self.m.lookup("host", v):
            return self.m.lookup("host", v)
        return self.m.get(cat, v, prefix=OBJECT_CATS.get(cat, cat), width=4)

    def learn(self, cat, value):
        if cat == "k8sns":
            v = value.strip()
            return None if self.keep_ns_rx.match(v) else self.learn_term("namespace", v)
        if cat == "host":
            return self.learn_host(value)
        if cat == "domain":
            return self.learn_domain(value)
        return self.learn_term(cat, value)

    def learn_k8s(self, kind, text, prefix="k8snode"):
        """Learn node names and organisation-specific namespaces from kubectl tables."""
        name_col = 1        # nsrows: column with the object name (1 for tables without a header)
        for line in text.splitlines():
            cols = line.split()
            if cols and cols[0] == "NAMESPACE":
                # a header: only tables with a NAME column right after NAMESPACE carry object
                # names there (events have LAST SEEN, top pods has NAME, quotas have none ...)
                name_col = 1 if len(cols) > 1 and cols[1] == "NAME" else None
                continue
            if not cols or cols[0] in ("NAME", "No", "Error", "error:"):
                continue
            if kind == "nodes":
                if len(cols) >= 3 and cols[1] in ("Ready", "NotReady") or (
                        len(cols) >= 3 and cols[1].startswith(("Ready,", "NotReady,"))):
                    role = ("-cp" if re.search(r"control-plane|master", cols[2]) else "-worker") \
                        if prefix != "k8snode" else ""
                    self.learn_host(cols[0], prefix=prefix + role)
            elif kind == "nsslash":
                m = re.match(r"(?:==\s+)?([a-z0-9]([a-z0-9-]*[a-z0-9])?)/([a-z0-9][a-z0-9.-]{2,})", line.strip())
                if m:
                    if not self.keep_ns_rx.match(m.group(1)):
                        self.learn_term("namespace", m.group(1))
                        self.learn_term("k8sobj", m.group(3))
                    nm = re.search(r"\snode=(\S+)", line)
                    if nm:
                        self.learn_host(nm.group(1), prefix=prefix if prefix == "k8snode" else prefix + "-worker")
            elif kind == "firstnode":
                if cols[0] not in ("NAME",) and len(cols) > 1 and re.fullmatch(r"[a-z0-9][a-z0-9.-]+", cols[0]):
                    if not self.m.lookup("host", cols[0].split(".")[0]):
                        self.learn_host(cols[0], prefix=prefix if prefix == "k8snode" else prefix + "-worker")
            elif kind in ("ns", "nsrows"):
                ns = cols[0]
                if not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", ns) or self.keep_ns_rx.match(ns):
                    continue
                if kind == "ns" and (len(cols) < 2 or cols[1] not in ("Active", "Terminating")):
                    continue
                self.learn_term("namespace", ns)
                if kind == "nsrows" and len(cols) > 1:
                    for i, c in enumerate(cols[1:], 1):
                        name = c.split("/", 1)[1] if "/" in c else (c if i == name_col else "")
                        if re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,}", name) and not name.isdigit() \
                                and not RX_QUANTITY.fullmatch(name):
                            self.learn_term("k8sobj", name)

    def prescan(self, text):
        """Discover IPs, version literals and FQDNs before scrubbing, so that every
        form of a name (short, dashed IP ...) is known when the report is written."""
        for m in RX_VMX_NAME.finditer(text):
            name = (m.group(1) or m.group(2) or "").strip()
            if len(name) >= 3 and not name.isdigit() and not RX_UUID.fullmatch(name) and \
                    not name.lower().startswith(("vm-", "uuid-", "none")):
                self.learn_term("vm", name)
        for m in RX_IPV4.finditer(text):
            if RX_VERSION_CTX.search(text[max(0, m.start() - 40):m.start()]):
                self.version_literals.add(m.group(0))
        for m in RX_IPV4.finditer(text):
            if self._ipv4_class(m, text) == "ip":
                self.m.ipv4(m.group(0))
        rx = self._get_env_rx()
        if rx:
            for m in rx.finditer(text):
                self._r_fqdn_env(m, learn_only=True)
        for m in RX_FQDN_ANY.finditer(text):
            self._r_fqdn_any(m, learn_only=True)

    def compile(self):
        loose, strict, digit = {}, {}, {}
        for short, ph in self.m.maps.get("host", {}).items():
            if short in GENERIC_NAMES or len(short) < 3:
                continue
            (strict if len(short) == 3 else loose)[short] = ph
        for cat in OBJECT_CATS:
            for real, ph in self.m.maps.get(cat, {}).items():
                loose.setdefault(real, ph)       # a host placeholder wins over an object one
        for ip, ph in self.m.maps.get("ipv4", {}).items():
            digit[ip.replace(".", "-")] = ph
        self._terms = {}
        self._term_rx = []
        for group, pre, post in ((loose, r"(?<![A-Za-z0-9])", r"(?![A-Za-z0-9])"),
                                 (strict, r"(?<![\w.-])", r"(?![\w-])(?!\.\w)"),
                                 (digit, r"(?<![\d.])", r"(?![\d])")):
            if not group:
                continue
            self._terms.update(group)
            alts = "|".join(re.escape(k) for k in sorted(group, key=len, reverse=True))
            self._term_rx.append(re.compile("(?i)%s(?:%s)%s" % (pre, alts, post)))
        self.m.env_domains = sorted(self.env_domains)

    # ---- helpers -----------------------------------------------------------
    @staticmethod
    def _safe(name):
        return any(name == s or name.endswith("." + s) for s in SAFE_DOMAINS)

    def _get_env_rx(self):
        if self._env_rx_n != len(self.env_domains):
            self._env_rx_n = len(self.env_domains)
            if self.env_domains:
                doms = "|".join(re.escape(d) for d in sorted(self.env_domains, key=len, reverse=True))
                self._env_rx = re.compile(
                    r"(?i)(?<![A-Za-z0-9_])((?:%s\.)*)(%s)(?![A-Za-z0-9_-])(?!\.[A-Za-z0-9_])"
                    % (LABEL, doms))
            else:
                self._env_rx = None
        return self._env_rx

    def _tok(self, value):
        self._toks.append(value)
        return "%s%d%s" % (TOK_O, len(self._toks) - 1, TOK_C)

    @staticmethod
    def _style(ph, orig):
        return ph.upper() if any(c.isalpha() for c in orig) and orig == orig.upper() else ph

    def _sub(self, rx, fn, text):
        """Apply rx to the parts of text that are not already replaced."""
        parts = TOK_RX.split(text)
        if len(parts) == 1:
            return rx.sub(fn, text)
        toks = TOK_RX.findall(text)
        out = []
        for i, part in enumerate(parts):
            out.append(rx.sub(fn, part) if part else part)
            if i < len(toks):
                out.append(toks[i])
        return "".join(out)

    # ---- replacement callbacks --------------------------------------------
    def _r_fqdn_env(self, m, learn_only=False):
        full = m.group(0)
        if self._safe(full.lower()):
            return full
        labels = m.group(1).rstrip(".")
        if not labels:
            ph = self.m.get("domain", m.group(2), width=2)
            return full if learn_only else self._tok(self._style(ph, full))
        short, _, mid = labels.partition(".")
        dom = (mid + "." if mid else "") + m.group(2)
        self.learn_domain(dom)
        dph = self.m.get("domain", dom, width=2)
        hph = self.m.get("host", short, prefix="host", width=4)
        return full if learn_only else self._tok(self._style(hph + "." + dph, full))

    def _r_fqdn_any(self, m, learn_only=False):
        full = m.group(0)
        low = full.lower()
        labels = low.split(".")
        if self._safe(low) or labels[0] in REVERSED_FIRST:
            return full
        if any(low == d or low.endswith("." + d) for d in self.env_domains):
            return full      # handled by the environment-domain pass
        if labels[-1] in CC_TLDS and len(labels) < 3:
            return full
        if len(labels) == 2:
            ph = self.m.get("domain", low, width=2)
        else:
            dph = self.m.get("domain", ".".join(labels[1:]), width=2)
            ph = self.m.get("exthost", labels[0], width=4) + "." + dph
        return full if learn_only else self._tok(self._style(ph, full))

    def _r_term(self, m):
        ph = self._terms.get(m.group(0).lower())
        return self._tok(self._style(ph, m.group(0))) if ph else m.group(0)

    def _r_hexseq(self, m):
        s = m.group(0).lower()
        n = s.count(":") + 1
        if s in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return m.group(0)
        cat = "mac" if n == 6 else "wwn" if n == 8 else "thumbprint" if n >= 16 else "hexid"
        return self._tok(self.m.get(cat, s))

    def _ipv4_class(self, m, text):
        s = m.group(0)
        o = [int(x) for x in m.groups()]
        if any(x > 255 for x in o) or not is_plain_ipv4(s):
            return "keep"
        if s in self.keep_literals or s in self.version_literals:
            return "version"
        if re.match(r"-\d*[A-Za-z]", text[m.end():m.end() + 6]):
            return "version"
        tail = RX_QUAD_VERSION_TAIL.match(text, m.end())
        if tail and "." in tail.group(0) and not is_ipv4(tail.group(0)[1:]):
            return "version"        # "4.2.1.0-9.1.24837353", but not a range "10.0.0.1-10.0.0.9"
        return "ip"

    def _r_ipv4(self, m):
        cls = self._ipv4_class(m, m.string)
        if cls == "ip":
            return self._tok(self.m.ipv4(m.group(0)))
        if cls == "version":
            self.kept_quads[m.group(0)] = self.kept_quads.get(m.group(0), 0) + 1
        return m.group(0)

    def _r_ipv6(self, m):
        s = m.group(0)
        if "::" not in s and s.count(":") != 7:
            return s
        try:
            ip = ipaddress.IPv6Address(s)
        except ValueError:
            return s
        if ip.is_unspecified or ip.is_loopback:
            return s
        return self._tok(self.m.get("ipv6", ip.compressed, prefix="ip6-ll" if ip.is_link_local else "ip6"))

    def _r_serial(self, m):
        v = m.group(2)
        if TOK_O in v or v.strip().lower() in EMPTY_VALUES:
            return m.group(0)
        return m.group(1) + self._tok(self.m.get("serial", v.strip()))

    def _r_dn(self, m):
        v = m.group(3).strip()
        if not v or v.lower() in SAFE_DN_VALUES or re.fullmatch("(?:%s\\d+%s|[.\\s*])+" % (TOK_O, TOK_C), v):
            return m.group(0)
        key = TOK_RX.sub(lambda t: self._toks[int(t.group(0)[1:-1])], v)
        return m.group(1) + m.group(2) + self._tok(self.m.get("dn", key))

    # ---- main entry --------------------------------------------------------
    def scrub(self, text):
        if not text:
            return text
        self._toks = []
        t = text.replace(TOK_O, "").replace(TOK_C, "")
        # 1. secrets
        t = RX_PEM.sub(lambda m: self._tok("[REDACTED-%s]" % m.group(1).strip().replace(" ", "-")), t)
        t = RX_JWT.sub(lambda m: self._tok("[REDACTED-JWT]"), t)
        t = RX_URLCRED.sub(lambda m: m.group(1) + self._tok("[REDACTED]") + m.group(3), t)
        t = RX_AUTHZ.sub(lambda m: m.group(1) + self._tok("[REDACTED]"), t)
        t = RX_KV_SECRET.sub(lambda m: m.group(0) if _kv_secret_is_setting(m)
                             else m.group(1) + self._tok("[REDACTED]"), t)
        t = RX_HASH.sub(lambda m: self._tok("[REDACTED-HASH]"), t)
        t = RX_SSHKEY.sub(lambda m: self._tok("[REDACTED-KEY]"), t)
        t = RX_BLOB.sub(lambda m: self._tok("[REDACTED-ENCODED-DATA]"), t)
        if not self.anonymize:
            toks = self._toks
            return TOK_RX.sub(lambda m: toks[int(m.group(0)[1:-1])], t)
        t = self._sub(RX_SSHFP, lambda m: self._tok(self.m.get("thumbprint", m.group(0))), t)
        # 2. identifiers that may contain a host name: replace them as a whole first
        t = self._sub(RX_IQN, lambda m: self._tok(self.m.get("iqn", m.group(0))), t)
        t = self._sub(RX_DEVICE, lambda m: self._tok(
            (m.group(1) or m.group(2)) + "." + self.m.get("device", m.group(0))), t)
        # 3. names known to belong to the environment
        rx = self._get_env_rx()
        if rx:
            t = self._sub(rx, self._r_fqdn_env, t)
        for rx in self._term_rx:
            t = self._sub(rx, self._r_term, t)
        # 4. structured identifiers
        t = self._sub(RX_HEXSEQ, self._r_hexseq, t)
        t = self._sub(RX_DASHMAC, lambda m: self._tok(self.m.get("mac", m.group(0).lower().replace("-", ":"))), t)
        for rx in (RX_UUID, RX_VMFS_UUID, RX_SPACED_UUID, RX_0X_UUID):
            t = self._sub(rx, lambda m: self._tok(self.m.get("uuid", m.group(0))), t)
        t = self._sub(RX_LICENSE, lambda m: self._tok(self.m.get("license", m.group(0))), t)
        # 5. addresses, then any remaining fully qualified names
        t = self._sub(RX_IPV4, self._r_ipv4, t)
        t = self._sub(RX_IPV6, self._r_ipv6, t)
        t = self._sub(RX_FQDN_ANY, self._r_fqdn_any, t)
        # 6. key based values
        t = RX_SERIAL.sub(self._r_serial, t)
        if RX_DN_LINE.search(t):
            t = "\n".join(RX_DN_ATTR.sub(self._r_dn, ln) if RX_DN_LINE.search(ln) else ln
                          for ln in t.split("\n"))
        toks = self._toks
        return TOK_RX.sub(lambda m: toks[int(m.group(0)[1:-1])], t)

    def leak_check(self, text):
        """Return {real_value: count} for known real values still present in text."""
        low = text.lower()
        hits = {}
        for cat, vals in self.m.maps.items():
            if cat in ("ipv4net", "target"):
                continue
            for real in vals:
                if len(real) < 4 or (cat in ("host", "exthost") and real in GENERIC_NAMES):
                    continue
                if cat == "exthost":
                    continue
                if real not in low or (cat == "ipv4" and not is_plain_ipv4(real)):
                    continue
                if cat == "ipv4":
                    n = len(re.findall(r"(?<![\d.])%s(?![\d])" % re.escape(real), low))
                else:
                    n = len(re.findall(r"(?<![a-z0-9])%s(?![a-z0-9])" % re.escape(real), low))
                if n:
                    hits[real] = n
        return hits


# ----------------------------------------------------------------------------
# SSH transport (system OpenSSH, password supplied through a private askpass socket)
# ----------------------------------------------------------------------------
def ssh_version():
    try:
        out = subprocess.run(["ssh", "-V"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             timeout=10).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return None, ""
    m = re.search(r"OpenSSH_(\d+)\.(\d+)", out)
    return ((int(m.group(1)), int(m.group(2))) if m else (0, 0)), out.strip()


def askpass_helper_main(prompt):
    """Runs as the SSH_ASKPASS program: fetch the answer from the parent process."""
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(20)
        s.connect(os.environ["VCFDIAG_SOCK"])
        s.sendall((json.dumps({"token": os.environ["VCFDIAG_TOKEN"], "prompt": prompt}) + "\n").encode())
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        reply = json.loads(data.decode())
    except Exception:
        return 1
    if reply.get("answer") is None:
        return 1
    sys.stdout.write(reply["answer"] + "\n")
    return 0


class AskpassServer:
    """Answers password prompts from ssh. Secrets travel only over a unix socket
    inside a 0700 directory, authorised by a one-time token."""

    def __init__(self, rundir):
        self.rundir = rundir
        self.sock_path = os.path.join(rundir, "ap")
        self.helper = os.path.join(rundir, "askpass")
        self.handlers = {}
        self.lock = threading.Lock()
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(self.sock_path)
        os.chmod(self.sock_path, 0o600)
        self.srv.listen(32)
        fd = os.open(self.helper, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o700)
        with os.fdopen(fd, "w") as fh:
            fh.write('#!/bin/sh\nexec "$VCFDIAG_PY" -I "$VCFDIAG_SELF" --askpass-helper "$1"\n')
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(10)
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            req = json.loads(data.decode())
            with self.lock:
                handler = self.handlers.get(req.get("token"))
            answer = handler(req.get("prompt", "")) if handler else None
            conn.sendall((json.dumps({"answer": answer}) + "\n").encode())
        except Exception:
            pass
        finally:
            conn.close()

    def register(self, handler):
        token = pysecrets.token_hex(16)
        with self.lock:
            self.handlers[token] = handler
        return token

    def unregister(self, token):
        with self.lock:
            self.handlers.pop(token, None)

    def env(self, token, old_ssh):
        e = dict(os.environ)
        e.update({"SSH_ASKPASS": self.helper, "SSH_ASKPASS_REQUIRE": "force",
                  "VCFDIAG_SOCK": self.sock_path, "VCFDIAG_TOKEN": token,
                  "VCFDIAG_PY": sys.executable, "VCFDIAG_SELF": os.path.abspath(__file__)})
        if old_ssh:
            e.setdefault("DISPLAY", "none:0")   # OpenSSH < 8.4 needs DISPLAY to use askpass
        return e


class Context:
    """Run-wide state: temp dir, askpass server, options."""

    def __init__(self, args):
        self.args = args
        self.ssh_ver, self.ssh_banner = ssh_version()
        if self.ssh_ver is None:
            die("the OpenSSH client 'ssh' was not found in PATH")
        base = "/tmp" if os.path.isdir("/tmp") else None
        self.rundir = tempfile.mkdtemp(prefix="vd", dir=base)
        os.chmod(self.rundir, 0o700)
        self.askpass = AskpassServer(self.rundir)
        self.targets = []
        self.cancel = threading.Event()
        self._n = 0
        self._lock = threading.Lock()
        atexit.register(self.cleanup)

    def next_ctl(self):
        with self._lock:
            self._n += 1
            return os.path.join(self.rundir, "c%d" % self._n)

    def cleanup(self):
        for t in self.targets:
            t.close()
        try:
            self.askpass.srv.close()
        except OSError:
            pass
        shutil.rmtree(self.rundir, ignore_errors=True)


class PtyShell:
    """Interactive remote shell for appliances whose login shell is not a POSIX
    shell (vCenter appliance shell) or that need "su -". Commands and output are
    base64 framed so terminal echo and line wrapping cannot corrupt them."""

    def __init__(self, argv):
        self.argv = argv
        self.p = None
        self.master = None
        self.buf = b""
        self.n = 0
        self.dead = False

    def _read(self, timeout):
        r, _, _ = select.select([self.p.stdout], [], [], timeout)
        if not r:
            return b""
        try:
            data = os.read(self.p.stdout.fileno(), 65536)
        except OSError:
            data = b""
        if not data:
            self.dead = True
            return None
        return data

    def _send(self, text):
        try:
            os.write(self.master, text.encode())
        except OSError:
            self.dead = True

    def _quiet(self, quiet, maxwait):
        end = time.time() + maxwait
        while time.time() < end and not self.dead:
            data = self._read(quiet)
            if data == b"":
                return
            if data:
                self.buf += data

    def _expect(self, pattern, timeout):
        rx = re.compile(pattern)
        end = time.time() + timeout
        while True:
            m = rx.search(self.buf)
            if m:
                return m
            left = end - time.time()
            if left <= 0 or self.dead:
                return None
            data = self._read(min(left, 1.0))
            if data:
                self.buf += data

    def open(self, escalate, secret=None):
        # Give ssh a local pseudo-terminal as stdin: it then asks the server for a
        # normal terminal (Ctrl-C, line editing) exactly as an interactive login would.
        self.master, slave = pty.openpty()
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 250, 0, 0))
        except OSError:
            pass
        try:
            self.p = subprocess.Popen(self.argv, stdin=slave, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, bufsize=0, start_new_session=True)
        finally:
            os.close(slave)
        self._quiet(1.5, 12)
        if escalate == "shell":
            self._send("shell\n")
            self._quiet(1.5, 8)
        elif escalate == "su":
            self.buf = b""
            self._send("su -\n")
            if not self._expect(rb"(?i)password[^\n]*:\s*$", 12):
                return False, "no password prompt after 'su -'"
            self._send((secret or "") + "\n")
            self._quiet(1.5, 8)
            if re.search(rb"(?i)authentication failure|incorrect password|su: ", self.buf[-300:]):
                return False, "su authentication failed"
        self.buf = b""
        # Make sure Ctrl-C can interrupt a hung command, and stop the echo.
        self._send('stty sane -echo 2>/dev/null; PS1=""; PS2=""; unset PROMPT_COMMAND; echo "__VD""RDY__"\n')
        if not self._expect(rb"__VDRDY__", 15):
            return False, "could not start a shell after '%s'" % escalate
        self.buf = b""
        return True, ""

    def run(self, command, timeout):
        if self.dead or self.p is None:
            return 255, "interactive session is not available", False
        self.n += 1
        n = self.n
        b64 = base64.b64encode(command.encode()).decode()
        if len(b64) > 3500:
            return 255, "command is too long for an interactive session", False
        self.buf = b""
        self._send('echo "__VD""B%d__"; echo %s | base64 -d | bash 2>&1 | base64 | tr -d "\\n"; '
                   'rc=${PIPESTATUS[2]}; echo; echo "__VD""E%d__:$rc:"\n' % (n, b64, n))
        m = self._expect(rb"__VDE%d__:(\d*):" % n, timeout)
        if not m:
            self._send("\x03")
            self._quiet(0.5, 2)
            self.buf = b""
            self._send('echo "__VD""SYNC__"\n')
            if not self._expect(rb"__VDSYNC__", 8):
                self.dead = True
            return 124, "", True
        body = self.buf[:m.start()]
        start = body.find(b"__VDB%d__" % n)
        payload = re.sub(rb"[^A-Za-z0-9+/=]", b"", body[start + len(b"__VDB%d__" % n):]) if start >= 0 else b""
        try:
            out = base64.b64decode(payload + b"=" * (-len(payload) % 4)).decode("utf-8", "replace")
        except Exception:
            out = "(could not decode command output)"
        return int(m.group(1) or 0), out, False

    def close(self):
        if self.p and self.p.poll() is None:
            try:
                self._send("exit\nexit\nexit\n")
                self.p.wait(timeout=3)
            except Exception:
                self.p.kill()
        if self.master is not None:
            try:
                os.close(self.master)
            except OSError:
                pass
            self.master = None


class Target:
    def __init__(self, ctx, section, address, placeholder, discovered=False):
        self.discovered = discovered      # a worker found through Kubernetes, not in the inventory
        self.sso = None                   # (user, password) for vCenter API checks
        self.ctx = ctx
        self.sec = section
        self.comp = COMPONENTS[section["type"]]
        self.address = address
        self.ph = placeholder
        self.user = None
        self.password = None
        self.su_password = None
        self.ctl = None
        self.connected = False
        self.errkind = None       # auth | unreachable | hostkey | error | skipped
        self.errmsg = ""
        self.mode = None          # sh | nsxcli | pty
        self.pty = None
        self.sudo = None          # None | nopass | pass
        self.remote_timeout = False   # remote has a usable "timeout" command
        self.kube = None          # dict(sudo=..., kubeconfig=...) or None
        self.kube_note = ""
        self.identity = []
        self.clock_offset = None
        self.results = []
        self.notes = []
        ctx.targets.append(self)      # so that cleanup always closes the connection

    # ---- connection --------------------------------------------------------
    def _base(self):
        extra = []
        if self.discovered and not self.ctx.args.strict_host_keys:
            extra = ["-o", "UserKnownHostsFile=" + os.path.join(self.ctx.rundir, "known_hosts_workers")]
        return ["-S", self.ctl, "-p", str(self.sec["port"]), "-l", self.user] + extra + self.sec["ssh_options"]

    def connect(self):
        self.errkind, self.errmsg = None, ""
        self.ctl = self.ctx.next_ctl()
        ver = self.ctx.ssh_ver
        state = {"sent": 0, "prompts": [], "refused": False}

        def handler(prompt):
            state["prompts"].append(prompt)
            p = prompt.lower()
            if "yes/no" in p or "continue connecting" in p:
                state["hostkey"] = True
                return "no"
            if state["sent"] >= 1:
                state["refused"] = True
                return None
            state["sent"] += 1
            return self.password

        token = self.ctx.askpass.register(handler)
        strict = "yes" if self.ctx.args.strict_host_keys else ("accept-new" if ver >= (7, 6) else "no")
        argv = ["ssh", "-M", "-N", "-f",
                "-o", "ControlPersist=600",
                "-o", "StrictHostKeyChecking=" + strict,
                "-o", "ConnectTimeout=%d" % self.ctx.args.connect_timeout,
                "-o", "NumberOfPasswordPrompts=1",
                "-o", "PreferredAuthentications=keyboard-interactive,password",
                "-o", "PubkeyAuthentication=no",
                "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
                "-o", "ForwardX11=no", "-o", "ForwardAgent=no",
                "-o", "LogLevel=ERROR"] + self._base() + [self.address]
        errfile = self.ctl + ".err"
        try:
            with open(errfile, "wb") as ef:
                p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=ef, stderr=ef,
                                   env=self.ctx.askpass.env(token, ver < (8, 4)),
                                   start_new_session=True,
                                   timeout=self.ctx.args.connect_timeout + 40)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            rc = -1
        finally:
            self.ctx.askpass.unregister(token)
        try:
            with open(errfile, "rb") as ef:
                err = ef.read().decode("utf-8", "replace").strip()
            os.unlink(errfile)
        except OSError:
            err = ""
        if rc == 0:
            self.connected = True
            return True
        low = err.lower()
        if "host key verification failed" in low or "identification has changed" in low or state.get("hostkey"):
            self.errkind = "hostkey"
            self.errmsg = ("the SSH host key of this host changed or is not trusted, on the computer running "
                           "vcf_diag (not on the target). If the host was rebuilt, remove the old key there "
                           "with: ssh-keygen -R %s" % self.address)
        elif any(k in " ".join(state["prompts"]).lower() for k in ("new password", "expired", "current")):
            self.errkind = "auth"
            self.errmsg = "the server asked for a password change - the password has probably expired"
        elif "permission denied" in low or "too many authentication failures" in low or state["refused"]:
            self.errkind = "auth"
            self.errmsg = "authentication failed (permission denied)"
        elif rc == -1 or any(k in low for k in ("timed out", "refused", "no route", "unreachable",
                                                 "could not resolve", "not known", "connection closed",
                                                 "connection reset")):
            self.errkind = "unreachable"
            self.errmsg = (err.splitlines() or ["connection timed out"])[-1]
        else:
            self.errkind = "error"
            self.errmsg = (err.splitlines() or ["ssh exited with status %s" % rc])[-1]
        return False

    def close(self):
        if self.pty:
            self.pty.close()
            self.pty = None
        if self.connected:
            self.connected = False
            try:
                subprocess.run(["ssh", "-O", "exit"] + self._base() + [self.address],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=10)
            except (OSError, subprocess.SubprocessError):
                pass

    # ---- execution ---------------------------------------------------------
    def exec(self, command, timeout, stdin_data=None):
        """Run one command through the multiplexed connection. Returns (rc, out, timed_out)."""
        argv = ["ssh", "-o", "ControlMaster=no", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
                "-T"] + self._base() + [self.address, "--", command]
        try:
            p = subprocess.run(argv, input=(stdin_data.encode() if stdin_data else None),
                               stdin=None if stdin_data else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
                               start_new_session=True)
            return p.returncode, p.stdout.decode("utf-8", "replace"), False
        except subprocess.TimeoutExpired as e:
            return 124, (e.stdout or b"").decode("utf-8", "replace"), True

    def sh(self, command, timeout, sudo=None):
        """Run a POSIX shell command, honouring pty mode and sudo."""
        if self.mode == "pty":
            return self.pty.run(command, timeout)
        # Let the remote side enforce the time limit too, so that a hung check
        # does not stay behind on the appliance after we give up locally.
        guard, local = "", timeout
        if self.remote_timeout:
            guard, local = "timeout -k 3 %d " % timeout, timeout + 8
        if sudo == "nopass":
            res = self.exec("sudo -n %ssh -c %s" % (guard, shlex.quote(command)), local)
        elif sudo == "pass":
            res = self.exec("sudo -S -p '' %ssh -c %s" % (guard, shlex.quote("exec 0</dev/null; " + command)),
                            local, stdin_data=self.password + "\n")
        elif guard:
            res = self.exec("%ssh -c %s" % (guard, shlex.quote(command)), local)
        else:
            res = self.exec(command, local)
        if guard and res[0] in (124, 137) and not res[2]:
            return 124, res[1], True
        return res

    # ---- discovery ---------------------------------------------------------
    def detect(self):
        """Work out what kind of shell we landed in and how to get privileges."""
        esc = self.sec.get("escalate")
        if esc == "su":
            return self._open_pty("su", self.su_password)
        rc, out, _ = self.exec("echo VDPROBE_$((6*7))", 20)
        if "VDPROBE_42" in out:
            self.mode = "sh"
        elif self.comp.get("nsxcli"):
            self.mode = "nsxcli"      # a restricted CLI login (NSX admin, Operations for networks consoleuser)
        elif self.comp.get("pty_escalate"):
            if not self._open_pty(self.comp["pty_escalate"], None):
                self.errmsg += (" - the login shell is not bash. Either enable the bash shell for this"
                                " user or check that the 'shell' command is allowed.")
                return False
        else:
            self.errkind, self.errmsg = "error", "login shell did not accept shell commands"
            return False
        if self.mode == "sh":
            rc, out, _ = self.exec("timeout -k 3 5 true 2>/dev/null && echo VDT_OK", 20)
            self.remote_timeout = "VDT_OK" in out
            want = self.sec.get("sudo") or self.comp.get("sudo") or "no"
            if want in ("auto", "yes"):
                self.sudo = self._detect_sudo()
                if want == "yes" and not self.sudo:
                    self.notes.append("sudo was requested but is not available for this user")
            if self.sec["type"] in K8S_TYPES:
                self._detect_kubectl()
        return True

    def _open_pty(self, escalate, secret):
        argv = ["ssh", "-o", "ControlMaster=no", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
                "-tt"] + self._base() + [self.address]
        self.pty = PtyShell(argv)
        ok, msg = self.pty.open(escalate, secret)
        if ok and escalate == "su" and self.pty.run("id -u", 15)[1].strip() != "0":
            ok, msg = False, "'su -' did not give a root shell (wrong root password?)"
        if not ok:
            self.pty.close()
            self.pty = None
            self.errkind, self.errmsg = "error", msg
            return False
        self.mode = "pty"
        self.notes.append("shell reached through '%s'" % ("su -" if escalate == "su" else escalate))
        return True

    def _detect_sudo(self):
        rc, _, _ = self.exec("sudo -n true 2>/dev/null", 15)
        if rc == 0:
            return "nopass"
        rc, _, _ = self.exec("sudo -S -p '' true 2>/dev/null", 20, stdin_data=self.password + "\n")
        return "pass" if rc == 0 else None

    def _detect_kubectl(self):
        kubectl = self.sec.get("kubectl") or "kubectl"
        confs = [self.sec["kubeconfig"]] if self.sec.get("kubeconfig") else \
            [None, "/etc/kubernetes/admin.conf", "/etc/kubernetes/super-admin.conf"]
        last = ""
        for sudo in ([None] if not self.sudo else [None, self.sudo]):
            for kc in confs:
                pre = "export KUBECONFIG=%s; " % shlex.quote(kc) if kc else ""
                rc, out, _ = self.sh(pre + kubectl + " get --raw /version 2>&1", 20, sudo=sudo)
                if rc == 0 and "gitVersion" in out:
                    self.kube = {"sudo": sudo, "kubeconfig": kc, "kubectl": kubectl}
                    self.notes.append("kubectl access: %s%s" % (
                        "sudo, " if sudo else "", "KUBECONFIG=" + kc if kc else "default kubeconfig"))
                    return
                last = out.strip().splitlines()[-1] if out.strip() else "exit status %d" % rc
        self.kube_note = "kubectl access could not be established (%s)" % last

    def probe_identity(self):
        t0 = time.time()
        if self.mode == "nsxcli" and self.sec["type"] == "opsnet":
            names = []
        elif self.mode == "nsxcli":
            rc, out, _ = self.exec("get hostname", 20)
            names = [ln.strip() for ln in out.splitlines() if ln.strip() and " " not in ln.strip()]
        else:
            rc, out, _ = self.sh("hostname -f 2>/dev/null; hostname 2>/dev/null; "
                                 "hostname -s 2>/dev/null; echo VDTIME=$(date -u +%s)", 20,
                                 sudo=None)
            names = [ln.strip() for ln in out.splitlines() if ln.strip() and "VDTIME=" not in ln]
            m = re.search(r"VDTIME=(\d+)", out)
            if m:
                self.clock_offset = int(m.group(1)) - (t0 + time.time()) / 2.0
        self.identity = [n for n in names if HOSTNAME_RX.fullmatch(n) and len(n) < 254]

    # ---- catalog -----------------------------------------------------------
    def run_catalog(self, group, c):
        res = {"group": group, "label": c["label"], "cmd": c["cmd"], "rc": None, "out": "",
               "dur": 0.0, "status": "ok", "note": "", "spec": c}
        t0 = time.time()
        command = c["cmd"]
        if c["mode"] == "sh":
            if self.mode == "nsxcli":
                res.update(status="skipped", note="needs the support user (logged in to the restricted CLI)"
                           if self.sec["type"] == "opsnet" else "needs a root shell (logged in to the NSX CLI)")
                return res
            sudo = self.sudo if (self.sec.get("sudo") == "yes" or c.get("sudo")) else None
            rc, out, to = self.sh(command, c["timeout"], sudo=sudo)
        elif c["mode"] == "nsxcli":
            if self.mode == "nsxcli":
                rc, out, to = self.exec(command, c["timeout"])
            else:
                rc, out, to = self.sh(self.comp["nsxcli_wrap"].format(q=shlex.quote(command), c=command) + " 2>&1",
                                      c["timeout"])
        else:  # kubectl
            if not self.kube:
                res.update(status="skipped", note=self.kube_note or "kubectl is not available")
                return res
            command = command.replace("{K}", self.kube["kubectl"])
            if "{NSRX}" in command:
                command = command.replace("{NSRX}", shlex.quote(self.sec.get("namespaces_rx") or AUTOMATION_NS_DEFAULT))
            res["cmd"] = command
            pre = "export KUBECONFIG=%s; " % shlex.quote(self.kube["kubeconfig"]) \
                if self.kube["kubeconfig"] else ""
            rc, out, to = self.sh(pre + command, c["timeout"], sudo=self.kube["sudo"])
        if c["mode"] == "sh" and c.get("sudo") and self.mode == "sh" and not self.sudo:
            res["note"] = "sudo not available for this user: ran without it"
        if c["mode"] == "nsxcli" and self.mode != "nsxcli" and self.sec["type"] == "opsnet" and rc == 127:
            res.update(status="skipped", note="a consoleuser CLI command: not available to this login", dur=time.time() - t0)
            return res
        t1 = time.time()
        if c["mode"] == "nsxcli":
            ts, out = nsxcli_stamp(out)
            if ts is not None and self.clock_offset is None and not to:
                self.clock_offset = ts - (t0 + t1) / 2.0
        if c.get("post") and rc == 0 and not to:
            try:
                short = c["post"](out)
                if short != out:
                    res["raw"] = out      # still read by the anonymizer, never printed
                out = short
            except Exception:  # noqa: BLE001 - a summarizer must never lose the raw output
                pass
        res.update(rc=rc, out=out, dur=t1 - t0)
        if to:
            res.update(status="timeout", note="timed out after %ds" % c["timeout"])
        elif rc != 0:
            res["status"] = "fail"
        return res


class VcApiError(Exception):
    pass


class VcApi:
    """Minimal vCenter REST client. Only GET requests are made, apart from opening and
    closing the session. The SSO password is used once, in memory, to open the session."""

    def __init__(self, host, user, password, verify=True, ca_file=None, base_url=None, timeout=30):
        self.base = base_url or "https://%s" % host
        self.user, self.password = user, password
        self.timeout = timeout
        self.token = None
        try:
            ctx = tls_context(verify, ca_file)
        except AiError as e:
            raise VcApiError(str(e))
        # vCenter is reached directly, never through a proxy from the environment.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                  urllib.request.HTTPSHandler(context=ctx))

    def _call(self, method, path, headers=None, data=None):
        req = urllib.request.Request(self.base + path, method=method, data=data,
                                     headers=dict({"User-Agent": "vcf_diag/%s" % VERSION}, **(headers or {})))
        if self.token and not getattr(self, "bearer", None):
            req.add_header("vmware-api-session-id", self.token)
        if getattr(self, "bearer", None):
            req.add_header("Authorization", "Bearer " + self.bearer)
            req.add_header("Accept", "application/json")
        if getattr(self, "basic", None):
            req.add_header("Authorization", self.basic)
            req.add_header("Accept", "application/json")
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                body = r.read().decode("utf-8", "replace")
                return r.status, body
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except urllib.error.URLError as e:
            reason = e.reason
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise VcApiError("the vCenter certificate is not trusted by this computer (%s). Set "
                                 "ca_file = <vCenter CA file> in the [vcenter] section, or tls_verify = no "
                                 "to skip the check" % reason.verify_message)
            raise VcApiError("cannot reach the vCenter API: %s" % reason)
        except (OSError, ValueError) as e:
            raise VcApiError("cannot reach the vCenter API: %s" % e)

    def login(self):
        cred = base64.b64encode(("%s:%s" % (self.user, self.password)).encode("utf-8")).decode()
        code, body = self._call("POST", "/api/session", {"Authorization": "Basic " + cred})
        self.password = None
        if code == 401:
            raise VcApiError("vCenter SSO login failed for %s (wrong user or password)" % self.user)
        if code not in (200, 201):
            raise VcApiError("vCenter refused the session (HTTP %d)" % code)
        self.token = json.loads(body)

    def logout(self):
        if self.token:
            try:
                self._call("DELETE", "/api/session")
            except VcApiError:
                pass
            self.token = None

    def get(self, path):
        """Returns parsed JSON, or None when the endpoint does not exist on this version."""
        code, body = self._call("GET", path)
        if code == 404:
            return None
        if code in (401, 403):
            raise VcApiError("HTTP %d for %s: the SSO user lacks permission" % (code, path))
        if code >= 400:
            raise VcApiError("HTTP %d for %s: %s" % (code, path, body[:300]))
        return json.loads(body) if body.strip() else None


def _messages(msgs, indent="  "):
    out = []
    for m in msgs or []:
        d = m.get("details") or m
        text = d.get("default_message") or d.get("id") or json.dumps(d)
        out.append("%s%s: %s" % (indent, m.get("severity", "INFO"), text))
    return out


def _detail_json(obj):
    return json.dumps(obj, indent=1, sort_keys=True)


def api_supervisors(api):
    out, attention = [], []
    clusters = api.get("/api/vcenter/namespace-management/clusters") or []
    summaries = api.get("/api/vcenter/namespace-management/supervisors/summaries")
    if not clusters and not summaries:
        return "No Supervisor is enabled on this vCenter."
    out.append("Supervisors")
    for c in clusters:
        out.append("supervisor: %s (%s)  config=%s  kubernetes=%s" % (
            c.get("cluster_name"), c.get("cluster"), c.get("config_status"), c.get("kubernetes_status")))
        if c.get("config_status") != "RUNNING" or c.get("kubernetes_status") not in (None, "READY"):
            attention.append("  %s: config=%s kubernetes=%s" % (
                c.get("cluster_name"), c.get("config_status"), c.get("kubernetes_status")))
    for item in (summaries or {}).get("items", []) if isinstance(summaries, dict) else []:
        info = item.get("info") or {}
        out.append("supervisor: %s (%s)  config=%s  kubernetes=%s" % (
            info.get("name"), item.get("supervisor"), info.get("config_status"), info.get("kubernetes_status")))
    if attention:
        out[:0] = ["Supervisors needing attention:"] + attention + [""]
    for c in clusters:
        d = api.get("/api/vcenter/namespace-management/clusters/" + urllib.parse.quote(c.get("cluster", ""))) or {}
        out += ["", "== supervisor %s (%s)" % (c.get("cluster_name"), c.get("cluster")),
                "config_status: %s   kubernetes_status: %s   size: %s   network: %s" % (
                    d.get("config_status"), d.get("kubernetes_status"), d.get("size_hint"),
                    d.get("network_provider"))]
        out += ["messages:"] + (_messages(d.get("messages")) or ["  none"])
        out += ["kubernetes messages:"] + (_messages(d.get("kubernetes_status_messages")) or ["  none"])
        stats = d.get("stat_summary") or {}
        if stats:
            out.append("capacity: CPU %s/%s MHz, memory %s/%s MiB, storage %s/%s MiB" % (
                stats.get("cpu_used"), stats.get("cpu_capacity"), stats.get("memory_used"),
                stats.get("memory_capacity"), stats.get("storage_used"), stats.get("storage_capacity")))
        out += ["--- full detail", _detail_json(d)]
    return "\n".join(out)


def api_namespaces(api):
    items = api.get("/api/vcenter/namespaces/instances")
    if items is None:
        return "The namespaces API is not available on this vCenter (no Supervisor?)."
    if not items:
        return "No vSphere Namespaces exist."
    names = {c.get("cluster"): c.get("cluster_name")
             for c in (api.get("/api/vcenter/namespace-management/clusters") or [])}
    head, attention, details = [], [], []
    for n in items:
        st = n.get("stats") or {}
        sup = n.get("supervisor") or n.get("cluster")
        head.append("namespace: %s  supervisor=%s  status=%s  CPU=%s MHz  memory=%s MiB  storage=%s MiB" % (
            n.get("namespace"), names.get(sup, sup), n.get("config_status"), st.get("cpu_used"),
            st.get("memory_used"), st.get("storage_used")))
        name = urllib.parse.quote(n.get("namespace", ""))
        d = api.get("/api/vcenter/namespaces/instances/" + name) or \
            api.get("/api/vcenter/namespaces/instances/v2/" + name) or {}
        msgs = _messages(d.get("messages"))
        if n.get("config_status") != "RUNNING" or any(m.lstrip().startswith(("ERROR", "WARNING")) for m in msgs):
            attention.append("  %s: status=%s%s" % (n.get("namespace"), n.get("config_status"),
                                                   (" - " + msgs[0].strip()) if msgs else ""))
        details += ["", "== namespace %s" % n.get("namespace"), "status: %s" % d.get("config_status"),
                    "messages:"] + (msgs or ["  none"])
        acc = d.get("access_list") or []
        details.append("access: " + (", ".join("%s %s@%s %s" % (a.get("subject_type"), a.get("subject"),
                                                              a.get("domain"), a.get("role")) for a in acc) or "none"))
        stor = d.get("storage_specs") or []
        details.append("storage policies: " + (", ".join("%s (limit %s MiB)" % (x.get("policy"), x.get("limit", "none"))
                                                         for x in stor) or "none"))
        vm = d.get("vm_service_spec") or {}
        details.append("VM classes: %s   content libraries: %d" % (
            ", ".join(vm.get("vm_classes") or []) or "none", len(vm.get("content_libraries") or [])))
        if d.get("resource_spec"):
            details.append("resource limits: %s" % json.dumps(d["resource_spec"], sort_keys=True))
        details += ["--- full detail", _detail_json(d)]
    out = (["Namespaces needing attention:"] + attention + [""] if attention else
           ["All namespaces report RUNNING without errors or warnings.", ""])
    return "\n".join(out + head + details)


def api_services(api):
    svcs = api.get("/api/vcenter/namespace-management/supervisor-services")
    if svcs is None:
        return "The Supervisor services API is not available on this vCenter."
    out = ["Registered Supervisor services:"]
    out += ["  %s  (%s)  state=%s" % (x.get("display_name"), x.get("supervisor_service"), x.get("state"))
            for x in svcs] or ["  none"]
    for c in api.get("/api/vcenter/namespace-management/clusters") or []:
        inst = api.get("/api/vcenter/namespace-management/clusters/%s/supervisor-services"
                       % urllib.parse.quote(c.get("cluster", ""))) or []
        out += ["", "supervisor: %s (%s) installed services:" % (c.get("cluster_name"), c.get("cluster"))]
        for x in inst:
            out.append("  %s %s  config=%s" % (x.get("supervisor_service"), x.get("version"), x.get("config_status")))
            out += _messages(x.get("messages"), indent="    ")
        if not inst:
            out.append("  none")
    return "\n".join(out)


class NsxApi(VcApi):
    """NSX Manager REST API: basic authentication on every GET (no session)."""

    def login(self):
        self.basic = "Basic " + base64.b64encode(("%s:%s" % (self.user, self.password)).encode("utf-8")).decode()
        self.password = None
        code, body = self._call("GET", "/api/v1/cluster/status")
        if code in (401, 403):
            raise VcApiError("NSX API login failed for %s (wrong user or password, or the account is locked)"
                             % self.user)
        if code >= 400:
            raise VcApiError("NSX API answered HTTP %d: %s" % (code, body[:200]))

    def logout(self):
        self.basic = None

    def paged(self, path, limit=10):
        items, cursor = [], None
        for _ in range(limit):
            sep = "&" if "?" in path else "?"
            page = self.get(path + (sep + "cursor=" + urllib.parse.quote(cursor) if cursor else "")) or {}
            items += page.get("results") or []
            cursor = page.get("cursor")
            if not cursor:
                break
        return items


def _ms(ts):
    try:
        return datetime.datetime.fromtimestamp(int(ts) / 1000.0, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OverflowError, OSError):
        return "?"


def nsx_cluster(api):
    st = api.get("/api/v1/cluster/status") or {}
    det = st.get("detailed_cluster_status") or {}
    out = ["overall: %s   management cluster: %s   control cluster: %s" % (
        det.get("overall_status"), (st.get("mgmt_cluster_status") or {}).get("status"),
        (st.get("control_cluster_status") or {}).get("status"))]
    groups = [(g.get("group_type"), g.get("group_status"),
               [(m.get("member_fqdn") or m.get("member_uuid"), m.get("member_ip"), m.get("member_status"))
                for m in g.get("members") or []]) for g in det.get("groups") or []]
    # "member: <name>" lines are kept: the H_NSXNODE harvest learns the peer names from them
    lines = summarize_nsx_groups([], groups)
    out += [re.sub(r"^  (?=\S)", "  member: ", ln) for ln in lines]
    return "\n".join(out)


def nsx_alarms(api):
    alarms = api.paged("/api/v1/alarms?status=OPEN,ACKNOWLEDGED,SUPPRESSED&page_size=500")
    if not alarms:
        return "No open, acknowledged or suppressed alarms."
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    alarms.sort(key=lambda a: (order.get(a.get("severity"), 9), -(a.get("last_reported_time") or 0)))
    counts = {}
    for a in alarms:
        counts[(a.get("severity"), a.get("status"))] = counts.get((a.get("severity"), a.get("status")), 0) + 1
    out = ["%d alarm(s): %s" % (len(alarms), ", ".join("%s %s %d" % (k[0], k[1], v) for k, v in sorted(
        counts.items(), key=lambda kv: (order.get(kv[0][0], 9), kv[0][1] or ""))))]
    for a in alarms[:200]:
        out.append("")
        out.append("%s %s  %s / %s  last %s  (node: %s)" % (
            a.get("severity"), a.get("status"), a.get("feature_name"), a.get("event_type"),
            _ms(a.get("last_reported_time")), a.get("node_display_name") or a.get("node_id") or "-"))
        for k in ("summary", "description", "recommended_action"):
            if a.get(k):
                out.append("  %s: %s" % (k.replace("_", " "), re.sub(r"\s+", " ", str(a[k]))[:600]))
    if len(alarms) > 200:
        out.append("\n... %d more alarms not listed" % (len(alarms) - 200))
    return "\n".join(out)


def nsx_transport_nodes(api):
    nodes = {n.get("id"): n for n in api.paged("/api/v1/transport-nodes?page_size=500")}
    # The state list takes no page_size: NSX 9.x refuses it with HTTP 400 (error 268).
    states = api.paged("/api/v1/transport-nodes/state")
    counts, bad = {}, []
    for s_ in states:
        n = nodes.get(s_.get("transport_node_id")) or {}
        kind = (n.get("node_deployment_info") or {}).get("resource_type") or "node"
        state = s_.get("state")
        counts[(kind, state)] = counts.get((kind, state), 0) + 1
        dep = (s_.get("node_deployment_state") or {}).get("state")
        if state != "success" or (dep and dep not in ("NODE_READY", "success")):
            details = "; ".join(str(d.get("failure_message") or d.get("state") or d)
                                for d in (s_.get("details") or []) if isinstance(d, dict))[:400]
            bad.append("transport node: %s  type=%s  state=%s  deployment=%s  %s" % (
                n.get("display_name") or s_.get("transport_node_id"), kind, state, dep,
                (s_.get("failure_message") or details or "").strip()))
    out = ["%d transport node(s)." % len(nodes), "Configuration state by type:"]
    out += ["  %s %s: %d" % (k[0], k[1], v) for k, v in sorted(counts.items(), key=lambda kv: str(kv[0]))]
    out += ["", "Nodes not in a good state:"] + (bad or ["  none"])
    tz = api.get("/api/v1/transport-zones/transport-node-status") or {}
    rows = tz.get("results") if isinstance(tz, dict) else None
    if rows:
        st = {}
        for r in rows:
            st[r.get("status")] = st.get(r.get("status"), 0) + 1
        out += ["", "Tunnel / connection status: " + ", ".join("%s %d" % kv for kv in sorted(st.items(), key=str))]
        down = [r for r in rows if r.get("status") not in ("UP", None)]
        for r in down[:100]:
            out.append("  transport node: %s  status=%s" % (r.get("node_display_name") or r.get("node_uuid"),
                                                           r.get("status")))
    return "\n".join(out)


def nsx_edge_clusters(api):
    clusters = api.paged("/api/v1/edge-clusters?page_size=200")
    if not clusters:
        return "No edge clusters."
    out = []
    for c in clusters:
        out.append("edge cluster: %s  members=%d  deployment=%s" % (
            c.get("display_name"), len(c.get("members") or []), c.get("deployment_type")))
    return "\n".join(out)


def nsx_backups(api):
    cfg = api.get("/api/v1/cluster/backups/config") or {}
    hist = api.get("/api/v1/cluster/backups/history") or {}
    out = ["automatic backups: %s" % ("enabled" if cfg.get("backup_enabled") else "NOT enabled")]
    sched = cfg.get("backup_schedule") or {}
    if sched:
        out.append("schedule: %s" % json.dumps(sched, sort_keys=True))
    for kind in ("cluster_backup_statuses", "node_backup_statuses", "inventory_backup_statuses"):
        rows = sorted(hist.get(kind) or [], key=lambda r: r.get("start_time") or 0)[-3:]
        out.append("%s:" % kind.replace("_statuses", "").replace("_", " "))
        for r in rows:
            out.append("  %s  %s%s" % (_ms(r.get("start_time")), "succeeded" if r.get("success") else "FAILED",
                                       ("  " + str(r.get("error_message") or r.get("error_code"))) if not r.get("success") else ""))
        if not rows:
            out.append("  no backups recorded")
    return "\n".join(out)


class SddcApi(VcApi):
    """SDDC Manager public API: token from POST /v1/tokens, then Bearer."""

    def login(self):
        body = json.dumps({"username": self.user, "password": self.password}).encode("utf-8")
        code, text = self._call("POST", "/v1/tokens", {"Content-Type": "application/json"}, data=body)
        self.password = None
        if code in (401, 403):
            raise VcApiError("SDDC Manager login failed for %s (wrong user or password, or no permission)" % self.user)
        if code >= 400:
            raise VcApiError("SDDC Manager refused the login (HTTP %d): %s" % (code, text[:200]))
        try:
            self.bearer = json.loads(text)["accessToken"]
        except (ValueError, KeyError, TypeError):
            raise VcApiError("unexpected answer to the SDDC Manager login: %s" % text[:200])

    def logout(self):
        self.bearer = None


def _cert_dates(pem):
    """(subject CN, notAfter as datetime) for one PEM certificate, without third-party libraries."""
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(pem if pem.endswith("\n") else pem + "\n")
        info = ssl._ssl._test_decode_cert(path)
    except Exception:
        return None, None
    finally:
        os.unlink(path)
    cn = dict(x[0] for x in info.get("subject", ())).get("commonName", "?")
    try:
        when = datetime.datetime.strptime(info["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
    except (KeyError, ValueError):
        when = None
    return cn, when


def _expiry_line(label, when):
    if not when:
        return "%s: expiry date unknown" % label
    days = (when - datetime.datetime.now(datetime.timezone.utc)).days
    flag = "EXPIRED" if days < 0 else "EXPIRES SOON" if days <= 30 else "ok"
    return "%s: valid until %s (%d days) %s" % (label, when.strftime("%Y-%m-%d"), days, flag)


def _pems(obj):
    """Every PEM certificate found anywhere in an API answer."""
    text = json.dumps(obj)
    return [m.replace("\\n", "\n") for m in re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text)]


def vc_sts(api):
    d = api.get("/api/vcenter/certificate-management/vcenter/signing-certificate")
    if d is None:
        return "This vCenter does not offer the signing-certificate API (vSphere 7.0 Update 3 or later is needed)."
    out = ["The STS signing certificate signs every SSO token. When it expires, nobody can log in to vCenter."]
    active = _pems((d or {}).get("active_cert_chain") or {})
    for i, pem in enumerate(active[:1]):
        cn, when = _cert_dates(pem)
        out.append(_expiry_line("active signing certificate (%s)" % cn, when))
    others = [p for p in _pems((d or {}).get("signing_cert_chains") or []) if p not in active[:1]]
    for pem in others[:10]:
        cn, when = _cert_dates(pem)
        out.append(_expiry_line("  other certificate in the signing chains (%s)" % cn, when))
    if len(out) == 1:
        out.append("no certificate found in the answer")
    return "\n".join(out)


def vc_tls(api):
    d = api.get("/api/vcenter/certificate-management/vcenter/tls") or {}
    when = None
    try:
        when = datetime.datetime.strptime(str(d.get("valid_to"))[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        pass
    return "\n".join([_expiry_line("machine SSL certificate", when),
                      "subject: %s" % d.get("subject_dn"), "issuer: %s" % d.get("issuer_dn")])


def vc_idp(api):
    d = api.get("/api/vcenter/identity/providers")
    if d is None:
        return "This vCenter does not offer the identity providers API."
    rows = d if isinstance(d, list) else (d.get("providers") or d.get("items") or [])
    if not rows:
        return "No external identity providers configured (only the vsphere.local SSO domain, and AD sources managed in SSO)."
    out = []
    for r in rows:
        out.append("provider: %s  type=%s  default=%s  domains=%s" % (
            r.get("name") or r.get("provider"), r.get("config_tag") or r.get("type"), r.get("is_default"),
            ",".join(r.get("domain_names") or []) or "-"))
    return "\n".join(out)


def vc_accounts(api):
    names = api.get("/api/appliance/local-accounts")
    if names is None:
        return "This vCenter does not offer the local accounts API."
    out = ["%-16s %-8s %-12s %-22s %s" % ("account", "enabled", "last change", "password expires", "status")]
    for n in names or []:
        a = api.get("/api/appliance/local-accounts/" + urllib.parse.quote(str(n))) or {}
        exp, status = a.get("password_expires_at"), "ok"
        if exp:
            try:
                when = datetime.datetime.strptime(str(exp)[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
                days = (when - datetime.datetime.now(datetime.timezone.utc)).days
                status = "EXPIRED" if days < 0 else ("EXPIRES IN %d DAYS" % days if days <= 14 else "%d days left" % days)
            except ValueError:
                status = "?"
        else:
            status = "never expires"
        out.append("%-16s %-8s %-12s %-22s %s" % (n, a.get("enabled"), str(a.get("last_password_change") or "-")[:10],
                                                  str(exp or "-")[:19], status))
    pol = api.get("/api/appliance/local-accounts/global-policy")
    if pol:
        out.append("global policy: %s" % json.dumps(pol, sort_keys=True))
    return "\n".join(out)


def nsx_logical_ports(api, status_limit=300):
    """Explain logical ports of VMs (named <vm>.vmx@<id>) by what is behind them: no VM interface
    (orphaned, typically after the VM was deleted or redeployed), a powered-off VM (down is
    expected), or a running VM (down is a real problem)."""
    ports = api.paged("/api/v1/logical-ports?attachment_type=VIF&page_size=1000", limit=50)
    if not ports:
        return "No VM logical ports returned."
    vifs = {}
    for f in api.paged("/api/v1/fabric/vifs?page_size=1000", limit=50):
        if f.get("lport_attachment_id"):
            vifs[f["lport_attachment_id"]] = f
    vms = {m.get("external_id"): m for m in api.paged("/api/v1/fabric/virtual-machines?page_size=1000", limit=50)}
    switches = {sw.get("id"): sw.get("display_name") for sw in api.paged("/api/v1/logical-switches?page_size=1000", limit=20)}
    orphaned, off, running = [], [], []
    for p in ports:
        att = (p.get("attachment") or {}).get("id")
        vif = vifs.get(att)
        row = {"name": p.get("display_name") or p.get("id"), "id": p.get("id"),
               "switch": switches.get(p.get("logical_switch_id"), p.get("logical_switch_id")),
               "created": _ms(p.get("_create_time")), "host": (vif or {}).get("host_id")}
        if not vif:
            orphaned.append(row)
            continue
        vm = vms.get(vif.get("owner_vm_id")) or {}
        row["vm"] = vm.get("display_name") or vif.get("owner_vm_id")
        row["power"] = vm.get("power_state")
        (off if str(vm.get("power_state", "")).upper() not in ("VM_RUNNING", "POWEREDON", "RUNNING") else running).append(row)
    down, checked = [], 0
    for row in running[:status_limit]:
        st = api.get("/api/v1/logical-ports/%s/status" % urllib.parse.quote(str(row["id"]))) or {}
        checked += 1
        if str(st.get("status", "")).upper() != "UP":
            row["status"] = st.get("status") or "?"
            down.append(row)
    out = ["%d VM logical port(s): %d orphaned, %d on powered-off VMs, %d on running VMs (%d of those checked, "
           "%d down)." % (len(ports), len(orphaned), len(off), len(running), checked, len(down)),
           "A port named <vm>.vmx@<number> is one network adapter of one VM.", ""]
    out.append("Down while the VM is running (a real problem: adapter disconnected in vCenter, host transport node "
               "not ready, or a datapath issue):")
    out += ["  port %s  vm=%s  segment=%s  status=%s  host=%s" % (r["name"], r["vm"], r["switch"], r["status"], r["host"])
            for r in down] or ["  none"]
    out += ["", "Orphaned: no VM network interface is attached any more (the VM was deleted, redeployed or "
            "re-registered; the port stays Down and raises alerts until it is removed):"]
    out += ["  port %s  segment=%s  created %s  id=%s" % (r["name"], r["switch"], r["created"], r["id"])
            for r in orphaned[:200]] or ["  none"]
    if len(orphaned) > 200:
        out.append("  ... %d more" % (len(orphaned) - 200))
    out += ["", "On powered-off VMs (Down is expected while the VM is off):"]
    out += ["  port %s  vm=%s  power=%s" % (r["name"], r["vm"], r["power"]) for r in off[:100]] or ["  none"]
    if len(running) > status_limit:
        out.append("\n(only the first %d ports of running VMs were checked for status)" % status_limit)
    return "\n".join(out)


def nsx_users(api):
    users = api.paged("/api/v1/node/users")
    out = ["%-12s %-20s %-18s %s" % ("user", "status", "change every (days)", "last change (days ago)")]
    today = int(time.time() // 86400)
    for u in users:
        last = u.get("last_password_change")
        ago = (today - int(last)) if isinstance(last, int) and last > 1000 else last
        out.append("%-12s %-20s %-18s %s" % (u.get("username"), u.get("status"), u.get("password_change_frequency"), ago))
    pol = api.get("/api/v1/node/aaa/auth-policy")
    if pol:
        keep = {k: v_ for k, v_ in pol.items() if not k.startswith("_")}
        out.append("authentication and lockout policy: %s" % json.dumps(keep, sort_keys=True))
    return "\n".join(out) if users or pol else "No user information returned."


def _flat(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v_ in obj.items():
            yield from _flat(v_, "%s%s." % (prefix, k))
    elif isinstance(obj, list):
        for i, v_ in enumerate(obj[:5]):
            yield from _flat(v_, "%s%d." % (prefix, i))
    else:
        yield prefix[:-1], obj


def sddc_credentials(api):
    page, rows = 0, []
    while page < 20:
        d = api.get("/v1/credentials?pageSize=500&pageNumber=%d" % page) or {}
        rows += d.get("elements") or []
        if (d.get("pageMetadata") or {}).get("totalPages", 1) <= page + 1:
            break
        page += 1
    if not rows:
        return "No stored credentials returned."
    out = ["%d stored credential(s). Expiry and status as SDDC Manager knows them:" % len(rows)]
    for c in rows:
        res = c.get("resource") or {}
        extra = ["%s=%s" % (k, v_) for k, v_ in _flat(c) if re.search(r"(?i)expir|status|lock|valid", k)]
        out.append("- %s %s  user=%s  type=%s/%s  %s" % (
            res.get("resourceType"), res.get("resourceName") or res.get("resourceIp"), c.get("username"),
            c.get("credentialType"), c.get("accountType"), " ".join(extra) or ""))
    return "\n".join(out)


def sddc_credential_tasks(api):
    d = api.get("/v1/credentials/tasks") or {}
    rows = d.get("elements") or (d if isinstance(d, list) else [])
    if not rows:
        return "No credential tasks recorded."
    rows = sorted(rows, key=lambda r: str(r.get("creationTimestamp") or ""), reverse=True)[:20]
    out = ["Failed rotations or updates leave the stored password out of sync with the system (a stale password)."]
    for r in rows:
        out.append("%s  %s  %s  %s" % (str(r.get("creationTimestamp") or "")[:19], r.get("status"),
                                       r.get("name") or r.get("type") or r.get("operationType"),
                                       "; ".join(str((e or {}).get("message") or e) for e in (r.get("errors") or []))[:300]))
    return "\n".join(out)


VCAPI_FUNCS = {"supervisors": api_supervisors, "namespaces": api_namespaces, "services": api_services,
               "nsx_cluster": nsx_cluster, "nsx_alarms": nsx_alarms, "nsx_transport_nodes": nsx_transport_nodes,
               "nsx_edge_clusters": nsx_edge_clusters, "nsx_backups": nsx_backups, "nsx_users": nsx_users, "nsx_logical_ports": nsx_logical_ports,
               "vc_sts": vc_sts, "vc_tls": vc_tls, "vc_idp": vc_idp, "vc_accounts": vc_accounts,
               "sddc_credentials": sddc_credentials, "sddc_credential_tasks": sddc_credential_tasks}


TOOL_ERROR_NOTE = ("tool error: the API refused the request itself (HTTP 400). This points to a problem "
                   "in vcf_diag for this product version, not to a fault in the environment.")


def collect_api(t, groups):
    """Run vCenter API checks for one vCenter target, from this computer."""
    todo = [(g, c) for g in groups for c in g[2]]
    user, password = t.sso or (None, None)
    if not password:
        for g, c in todo:
            t.results.append({"group": g, "label": c["label"], "cmd": c["cmd"], "rc": None, "out": "", "dur": 0.0,
                              "status": "skipped", "note": "no API login was entered", "spec": c})
        return
    sec = t.sec
    api = {"nsx": NsxApi, "sddc": SddcApi}.get(sec["type"], VcApi)(
        t.address, user, password, verify=sec.get("tls_verify", True), ca_file=sec.get("ca_file"),
        base_url=sec.get("api_base"))
    try:
        api.login()
    except VcApiError as e:
        for g, c in todo:
            t.results.append({"group": g, "label": c["label"], "cmd": c["cmd"], "rc": 1, "out": str(e), "dur": 0.0,
                              "status": "fail", "note": "", "spec": c})
        return
    try:
        for g, c in todo:
            if t.ctx.cancel.is_set():
                break
            t0 = time.time()
            res = {"group": g, "label": c["label"], "cmd": c["cmd"], "rc": 0, "out": "", "dur": 0.0,
                   "status": "ok", "note": "", "spec": c}
            try:
                res["out"] = VCAPI_FUNCS[c["api"]](api)
            except (VcApiError, ValueError, KeyError, TypeError, AttributeError) as e:
                res.update(rc=1, status="fail", out="%s" % e)
                if isinstance(e, VcApiError) and str(e).startswith("HTTP 400 "):
                    res["note"] = TOOL_ERROR_NOTE
            res["dur"] = time.time() - t0
            t.results.append(res)
    finally:
        api.logout()


def drop_covered_results(t):
    """Leave out SSH results that a successful API check on the same target already covers."""
    ok_api = {r["spec"].get("api"): r["label"] for r in t.results
              if r["status"] == "ok" and r["spec"].get("api")}
    covered = [r for r in t.results if r["status"] == "ok" and r["spec"].get("covered_by") in ok_api]
    if covered:
        t.results = [r for r in t.results if r not in covered]
        t.notes.append("left out because the API check '%s' reports the same: %s" % (
            ok_api[covered[0]["spec"]["covered_by"]], ", ".join(r["label"] for r in covered)))


def collect_target(t, groups, progress):
    """Connect (if needed), detect, and run every selected command on one target.
    vCenter API checks run from this computer, also when SSH to the target fails."""
    ssh_groups = [g for g in groups if not is_api_group(g[0])]
    api_groups = [g for g in groups if is_api_group(g[0])]
    try:
        if ssh_groups:
            ok = t.connected or t.connect()
            if ok and not t.detect():
                t.errkind = t.errkind or "error"
                ok = False
            if not ok:
                progress(t, "FAILED: " + t.errmsg + (" (vCenter API checks still run)" if api_groups else ""))
            else:
                t.probe_identity()
                for g in ssh_groups:
                    for c in g[2]:
                        if t.ctx.cancel.is_set():
                            break
                        t.results.append(t.run_catalog(g, c))
        if api_groups and not t.ctx.cancel.is_set():
            collect_api(t, api_groups)
        drop_covered_results(t)
        if t.results or not t.errkind:
            bad = sum(1 for r in t.results if r["status"] in ("fail", "timeout"))
            skipped = sum(1 for r in t.results if r["status"] == "skipped")
            progress(t, "done: %d commands, %d failed, %d skipped (%s)" % (
                len(t.results), bad, skipped, t.mode or "api"))
    except Exception as e:  # never let one host break the run
        t.errkind, t.errmsg = "error", "collector error: %r" % (e,)
        progress(t, "FAILED: " + t.errmsg)
    finally:
        t.close()


# ----------------------------------------------------------------------------
# Inventory
# ----------------------------------------------------------------------------
def load_inventory(path):
    cp = configparser.ConfigParser(interpolation=None, delimiters=("=",), comment_prefixes=("#", ";"))
    cp.optionxform = str
    try:
        with open(path, encoding="utf-8") as fh:
            cp.read_file(fh)
    except (OSError, configparser.Error) as e:
        die("cannot read inventory %s: %s" % (path, e))
    settings = dict(cp["settings"]) if cp.has_section("settings") else {}
    sections, custom, endpoints = [], {}, {}
    if cp.has_section("ai"):
        settings["_ai"] = dict(cp["ai"])
    for name in cp.sections():
        if name in ("settings", "ai"):
            continue
        typ, _, label = name.partition(":")
        typ, label = typ.strip().lower(), label.strip()
        if typ == "endpoints":
            eps = endpoints.setdefault(label, {})
            for service, names in cp[name].items():
                for host in split_list(names):
                    eps.setdefault(host, []).append(service.strip())
            continue
        if typ == "commands":
            if label not in COMPONENTS:
                die("inventory: [%s] refers to unknown component type '%s'" % (name, label))
            custom[label] = [(k, v) for k, v in cp[name].items()]
            continue
        if typ not in COMPONENTS:
            die("inventory: unknown component type in section [%s]. Valid types: %s"
                % (name, ", ".join(COMPONENTS)))
        s = cp[name]
        hosts = list(dict.fromkeys(split_list(s.get("hosts", "") + " " + s.get("control_planes", ""))))
        if not hosts:
            continue
        slug = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")
        prefix = COMPONENTS[typ]["prefix"] + ("-" + slug if slug else "")
        sudo = (s.get("sudo") or "").strip().lower() or None
        if sudo not in (None, "auto", "yes", "no"):
            die("inventory: [%s] sudo must be auto, yes or no" % name)
        esc = (s.get("escalate") or "").strip().lower() or None
        if esc not in (None, "su"):
            die("inventory: [%s] escalate must be 'su' or omitted" % name)
        try:
            nsrx = automation_ns_regex(s.get("namespaces")) if s.get("namespaces", "").strip() else None
        except ValueError as e:
            die("inventory: [%s] %s" % (name, e))
        sections.append({
            "name": name, "type": typ, "label": label, "prefix": prefix, "hosts": hosts,
            "user": (s.get("user") or COMPONENTS[typ]["user"]).strip(),
            "port": int(s.get("port", "22")), "sudo": sudo, "escalate": esc,
            "kubeconfig": (s.get("kubeconfig") or "").strip() or None,
            "kubectl": (s.get("kubectl") or "").strip() or None,
            "namespaces_rx": nsrx,
            "ssh_options": shlex.split(s.get("ssh_options", "")),
            "ssh_workers": (s.get("ssh_workers") or "no").strip().lower() in ("yes", "true", "1"),
            "sso_user": (s.get("sso_user") or ("admin" if typ == "nsx" else "administrator@vsphere.local")).strip(),
            "tls_verify": (s.get("tls_verify") or "yes").strip().lower() not in ("no", "false", "0", "off"),
            "ca_file": os.path.expanduser((s.get("ca_file") or "").strip()) or None,
            "api_base": (s.get("api_base") or "").strip() or None,
            "endpoints": {},
        })
    mgmt = [x for x in sections if x["type"] == "vcfmgmt"]
    for label, eps in endpoints.items():
        if not eps:
            continue
        owners = [x for x in mgmt if x["label"] == label] or ([x for x in mgmt if not x["endpoints"]]
                                                              if label == "" else [])
        if not owners:
            die("inventory: [endpoints%s] has no matching [vcfmgmt%s] section with control planes"
                % ((":" + label) if label else "", (":" + label) if label else ""))
        for x in owners:
            x["endpoints"] = eps
    return settings, sections, custom


SETTINGS_FIELDS = [("anonymize", "yes"), ("max_lines", "200"), ("parallel", "4"), ("timeout", "30"),
                   ("connect_timeout", "15"), ("strict_host_keys", "no"), ("scrub_terms", ""),
                   ("extra_domains", ""), ("keep_literals", "9.1.1.0"), ("keep_namespaces", "")]
AI_FIELDS = [("profile", ""), ("genai_model", ""), ("capra_model", ""),
             ("provider", "openai"), ("base_url", ""), ("model", ""), ("auth_header", "bearer"), ("max_rounds", "10"), ("max_tokens", ""),
             ("timeout", "600"), ("max_report_chars", "150000"), ("max_context_chars", "400000"), ("ca_file", ""),
             ("tls_verify", "yes"), ("use_proxy", "yes"), ("proxy", ""), ("key_env", "")]
GROUP_FIELDS = ["user", "port", "sudo", "escalate", "kubeconfig", "kubectl", "ssh_workers", "sso_user", "ca_file",
                "tls_verify", "api_base", "ssh_options", "namespaces"]
STANDARD_MGMT_SERVICES = ["VCF Operations", "VCF Operations for networks", "VCF Automation", "VCF services runtime",
                          "Fleet lifecycle", "Log management", "Salt RaaS", "Software depot", "Real-time metrics",
                          "Real-time metrics store", "Salt master", "SDDC lifecycle", "Telemetry"]


def _ini_parser():
    cp = configparser.ConfigParser(interpolation=None, delimiters=("=",), comment_prefixes=("#", ";"))
    cp.optionxform = str
    return cp


def read_settings_model(text):
    """Inventory text -> the structured form the Settings tab edits (keeps empty groups)."""
    cp = _ini_parser()
    try:
        cp.read_string(text)
    except configparser.Error as e:
        raise Fatal("the inventory file cannot be read: %s" % e)
    model = {"settings": {k: cp.get("settings", k, fallback=d) for k, d in SETTINGS_FIELDS},
             "ai": {k: cp.get("ai", k, fallback=d) for k, d in AI_FIELDS}, "groups": [], "commands": []}
    endpoints = {}
    for name in cp.sections():
        typ, _, label = (x.strip() for x in name.partition(":"))
        typ = typ.lower()
        if typ == "endpoints":
            endpoints[label] = [{"service": k, "endpoint": v} for k, v in cp[name].items()]
        elif typ == "commands":
            model["commands"] += [{"type": label, "label": k, "command": v} for k, v in cp[name].items()]
        elif typ in COMPONENTS:
            sec = cp[name]
            g = {"type": typ, "label": label,
                 "hosts": list(dict.fromkeys(split_list(sec.get("hosts", "") + " " + sec.get("control_planes", "")))),
                 "endpoints": []}
            for k in GROUP_FIELDS:
                g[k] = sec.get(k, "")
            model["groups"].append(g)
    for g in model["groups"]:
        if g["type"] == "vcfmgmt":
            g["endpoints"] = endpoints.pop(g["label"], [])
    return model


def _clean(v):
    return re.sub(r"[\r\n]+", " ", str(v if v is not None else "")).strip()


def render_settings_model(model):
    """The structured form -> inventory text. Only values that are set are written."""
    out = ["# vcf_diag settings, written by the Settings tab of the window.",
           "# Contains real host names: keep it on this computer. You do not need to edit it by hand.", ""]

    def block(header, pairs):
        pairs = [(k, _clean(v)) for k, v in pairs if _clean(v) != ""]
        out.append("[%s]" % header)
        out.extend("%s = %s" % (k, v) for k, v in pairs)
        out.append("")

    st = model.get("settings") or {}
    block("settings", [(k, st.get(k, "")) for k, _ in SETTINGS_FIELDS])
    ai = model.get("ai") or {}
    block("ai", [(k, ai.get(k, "")) for k, _ in AI_FIELDS])
    for g in model.get("groups") or []:
        typ = _clean(g.get("type")).lower()
        if typ not in COMPONENTS:
            raise Fatal("unknown component type '%s'" % typ)
        label = _clean(g.get("label"))
        if label and not re.fullmatch(r"[A-Za-z0-9_.-]+", label):
            raise Fatal("group label '%s' may only contain letters, digits, '-', '_' and '.'" % label)
        name = typ + (":" + label if label else "")
        hosts = [h for h in (_clean(x) for x in (g.get("hosts") or [])) if h]
        bad = [h for h in hosts if not re.fullmatch(r"[A-Za-z0-9_.:\[\]-]+", h)]
        if bad:
            raise Fatal("[%s]: '%s' is not a host name or IP address" % (name, bad[0]))
        block(name, [("control_planes" if typ == "vcfmgmt" else "hosts", ", ".join(hosts))] +
              [(k, g.get(k, "")) for k in GROUP_FIELDS])
        eps = [(_clean(e.get("service")), _clean(e.get("endpoint"))) for e in (g.get("endpoints") or [])]
        eps = [(k, v) for k, v in eps if k]
        if typ == "vcfmgmt" and eps:
            seen = set()
            for k, _ in eps:
                if not re.fullmatch(r"[^=\[\]#;]+", k):
                    raise Fatal("service name '%s' may not contain = [ ] # or ;" % k)
                if k.lower() in seen:
                    raise Fatal("[%s]: the service '%s' is listed twice" % (name, k))
                seen.add(k.lower())
            # rows without an endpoint yet are kept (written empty, ignored when collecting)
            out.append("[endpoints%s]" % (":" + label if label else ""))
            out.extend(("%s = %s" % (k, v)).rstrip() for k, v in eps)
            out.append("")
    cmds, seen_cmds = {}, set()
    for c in model.get("commands") or []:
        typ, lab, cm = _clean(c.get("type")).lower(), _clean(c.get("label")), _clean(c.get("command"))
        if lab and cm:
            if (typ, lab.lower()) in seen_cmds:
                raise Fatal("custom command '%s' is listed twice for %s" % (lab, typ))
            seen_cmds.add((typ, lab.lower()))
            if typ not in COMPONENTS:
                raise Fatal("custom command '%s': choose a component type" % lab)
            if not re.fullmatch(r"[^=\[\]#;]+", lab):
                raise Fatal("custom command name '%s' may not contain = [ ] # or ;" % lab)
            cmds.setdefault(typ, []).append((lab, cm))
    for typ, pairs in cmds.items():
        block("commands:" + typ, pairs)
    return "\n".join(out)


def groups_for(sec, custom):
    """Check groups for a component type, or for an inventory section (which may add endpoints)."""
    typ = sec["type"] if isinstance(sec, dict) else sec
    groups = list(COMPONENTS[typ]["groups"])
    if isinstance(sec, dict) and sec.get("endpoints"):
        groups = groups[:len(MGMT_CLUSTER_GROUPS)] + endpoint_group(sec["endpoints"]) + \
            groups[len(MGMT_CLUSTER_GROUPS):]
    extra = custom.get(typ)
    if extra:
        cmds = []
        for label, command in extra:
            mode = "kubectl" if "{K}" in command else (
                "nsxcli" if COMPONENTS[typ].get("nsxcli") and re.match(r"(get|show|list) ", command) else "sh")
            cmds.append(cmd(label, command, timeout=60, mode=mode))
        groups.append(("custom", "Custom commands from the inventory file", cmds))
    return groups


# ----------------------------------------------------------------------------
# Interactive selection
# ----------------------------------------------------------------------------
def parse_selection(answer, n):
    a = answer.strip().lower()
    if a in ("", "a", "all", "*"):
        return list(range(n))
    if a in ("n", "none", "0"):
        return []
    picked = set()
    for part in re.split(r"[,\s]+", a):
        if not part:
            continue
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if not m:
            return None
        lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
        if lo < 1 or hi > n or lo > hi:
            return None
        picked.update(range(lo - 1, hi))
    return sorted(picked)


def choose(title, items, auto_all=False):
    if auto_all or len(items) == 1:
        return list(range(len(items)))
    print("\n" + title)
    for i, it in enumerate(items, 1):
        print("  %2d) %s" % (i, it))
    while True:
        sel = parse_selection(input("Select [all] (e.g. 1,3-5 / all / none): "), len(items))
        if sel is not None:
            return sel
        print("  Not understood. Use numbers, ranges, 'all' or 'none'.")


def ask_yes(question, default=True):
    a = input("%s [%s]: " % (question, "Y/n" if default else "y/N")).strip().lower()
    return default if not a else a.startswith("y")


def prompt_credentials(sec, what=None):
    what = what or "[%s] %s" % (sec["name"], COMPONENTS[sec["type"]]["title"])
    print("\nCredentials for %s" % what)
    user = input("  SSH username [%s]: " % sec["user"]).strip() or sec["user"]
    password = getpass.getpass("  SSH password for %s: " % user)
    su_password = None
    if sec.get("escalate") == "su":
        su_password = getpass.getpass("  root password for 'su -': ")
    return user, password, su_password


class ConsoleUI:
    """How the collector asks the person at the terminal for credentials."""

    def initial_credentials(self, sec):
        return prompt_credentials(sec)

    def sso_credentials(self, sec):
        print("\n%s for the API checks of [%s] (Return to skip)" % (
            "NSX API login" if sec["type"] == "nsx" else "SSO login for the SDDC Manager API" if sec["type"] == "sddc"
            else "vCenter SSO login", sec["name"]))
        user = input("  SSO username [%s]: " % sec["sso_user"]).strip() or sec["sso_user"]
        return user, getpass.getpass("  SSO password for %s: " % user)

    def retry_credentials(self, sec, what, message, default=True):
        if not ask_yes("  %s Enter different credentials for %s?" % (message, what), default):
            return None
        return prompt_credentials(sec, what=what)


def build_plan(sections, custom, auto_all):
    usable = [s for s in sections if s["hosts"]]
    if not usable:
        die("the inventory has no hosts. Edit it and add hosts under at least one section.")
    idx = choose("Components found in the inventory:",
                 ["[%s]  %s  (%d host%s)" % (s["name"], COMPONENTS[s["type"]]["title"], len(s["hosts"]),
                                             "" if len(s["hosts"]) == 1 else "s") for s in usable],
                 auto_all)
    plan = []
    for i in idx:
        s = usable[i]
        hsel = choose("Hosts in [%s]:" % s["name"], s["hosts"], auto_all)
        groups = groups_for(s, custom)
        gsel = choose("Diagnostics for [%s]:" % s["name"],
                      ["%-14s %s (%d checks)" % (g[0], g[1], len(g[2])) for g in groups], auto_all)
        if hsel and gsel:
            plan.append({"sec": s, "hosts": [s["hosts"][j] for j in hsel],
                         "groups": [groups[j] for j in gsel]})
    return plan


# ----------------------------------------------------------------------------
# Collection driver
# ----------------------------------------------------------------------------
def run_plan(ctx, plan, scrubber, ui=None):
    """Run the plan. Returns a list of (section, [Target])."""
    ui = ui or ConsoleUI()
    done = []
    creds = {}
    sso = {}
    for item in plan:
        needs_ssh = plan_needs_ssh(item)
        creds[item["sec"]["name"]] = ui.initial_credentials(item["sec"]) if needs_ssh else (None, None, None)
        if any(is_api_group(g[0]) for g in item["groups"]):
            sso[item["sec"]["name"]] = ui.sso_credentials(item["sec"])
    log()

    def progress(t, msg):
        log("  [%s] %-40s %s" % (t.sec["name"], t.address, msg))

    for item in plan:
        if ctx.cancel.is_set():
            break
        sec = item["sec"]
        targets = []
        for addr in item["hosts"]:
            if not scrubber.anonymize:
                ph = addr
            elif is_ip(addr):
                ph = scrubber.m.get("target", addr, prefix=sec["prefix"], width=2)
                if is_plain_ipv4(addr):
                    scrubber.m.ipv4(addr)
            else:
                ph = scrubber.learn_host(addr, prefix=sec["prefix"]) or \
                    scrubber.m.get("target", addr, prefix=sec["prefix"], width=2)
            t = Target(ctx, sec, addr, ph)
            targets.append(t)

        def apply(ts, c):
            for t in ts:
                t.user, t.password, t.su_password = c

        host_groups = item.setdefault("host_groups", {})
        cluster_groups = []
        if sec["type"] == "vcfmgmt" and not host_groups:
            # Whole-cluster checks run on one control plane only; node checks on every node.
            cluster_groups = [g for g in item["groups"] if is_cluster_group(g[0])]
            node_groups = [g for g in item["groups"] if not is_cluster_group(g[0])]
            for i, t in enumerate(targets):
                host_groups[t.address] = (cluster_groups if i == 0 else []) + node_groups

        if sec["type"] in ("nsx", "vcenter", "sddc") and not host_groups and len(targets) > 1:
            api_g = [g for g in item["groups"] if is_api_group(g[0])]
            if api_g:
                rest_g = [g for g in item["groups"] if not is_api_group(g[0])]
                for i, t in enumerate(targets):
                    host_groups[t.address] = item["groups"] if i == 0 else rest_g

        def groups_of(t):
            return host_groups.get(t.address, item["groups"])

        apply(targets, creds[sec["name"]])
        for t in targets:
            t.sso = sso.get(sec["name"])
        if plan_needs_ssh(item) and not creds[sec["name"]][1]:
            for t in targets:
                t.errkind, t.errmsg = "skipped", "no password was entered for this group"
            log("[%s] skipped: no password was entered" % sec["name"])
            done.append((item, targets))
            continue
        log("[%s] %d host(s), %d check(s) in total" % (
            sec["name"], len(targets), sum(len(g[2]) for t in targets for g in groups_of(t))))
        # Canary: try the first host alone, so a mistyped password costs one failed
        # login on one host instead of one on every host (account lockout protection).
        first, rest = targets[0], targets[1:]
        tries = 0
        needs_ssh = plan_needs_ssh(item)
        while needs_ssh and not first.connect() and first.errkind == "auth" and tries < 2:
            tries += 1
            log("  [%s] %s: %s" % (sec["name"], first.address, first.errmsg))
            new = ui.retry_credentials(sec, "[%s]" % sec["name"],
                                       "%s rejected the credentials (%s)." % (first.address, first.errmsg))
            if not new:
                break
            creds[sec["name"]] = new
            apply(targets, new)
        if first.errkind == "auth":
            for t in rest:
                t.errkind = "skipped"
                t.errmsg = "not attempted: credentials were rejected by the first host of this group"
            progress(first, "FAILED: " + first.errmsg)
            api_only = [g for g in item["groups"] if is_api_group(g[0])]
            for t in targets if api_only else []:
                collect_api(t, api_only)
            done.append((item, targets))
            continue
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, ctx.args.parallel)) as pool:
            list(pool.map(lambda t: collect_target(t, groups_of(t), progress), targets))
        # Offer a retry for individual hosts that rejected the shared credentials.
        for t in targets:
            if t.errkind == "auth" and t is not first and not ctx.cancel.is_set():
                new = ui.retry_credentials(sec, "host %s" % t.address,
                                           "%s rejected the credentials used for its group." % t.address,
                                           default=False)
                if new:
                    apply([t], new)
                    t.results = []
                    collect_target(t, groups_of(t), progress)
        if cluster_groups and not ctx.cancel.is_set():
            mgmt_followup(ctx, item, targets, cluster_groups, creds[sec["name"]], scrubber, progress)
        done.append((item, targets))
    return done


def mgmt_followup(ctx, item, targets, cluster_groups, cred, scrubber, progress):
    """VCF management cluster: make sure the cluster checks ran somewhere, then reach
    the worker nodes, whose VM names are generated and therefore not in the inventory."""
    sec = item["sec"]
    keys = set(g[0] for g in cluster_groups)
    have = [t for t in targets if any(r["group"][0] in keys and r["status"] != "skipped" for r in t.results)]
    if not have:
        for t in targets[1:]:
            if t.errkind:
                continue
            log("  [%s] %s: collecting the cluster-wide checks here instead" % (sec["name"], t.address))
            collect_target(t, cluster_groups, progress)
            if any(r["group"][0] in keys and r["status"] != "skipped" for r in t.results):
                have = [t]
                break
    if not have:
        log("  [%s] cluster-wide checks could not be collected from any control plane" % sec["name"])
        return
    node_groups = [g for g in item["groups"] if not is_cluster_group(g[0])]
    if not sec.get("ssh_workers") or not node_groups:
        return
    table = next((r["out"] for r in have[0].results if r["label"] == "Nodes"), "")
    known = set(t.address for t in targets)
    workers = []
    for line in table.splitlines():
        cols = line.split()
        if len(cols) < 6 or cols[0] == "NAME" or re.search(r"control-plane|master", cols[2]):
            continue
        ip = next((c for c in cols[5:7] if is_ipv4(c)), None)
        if ip and ip not in known:
            known.add(ip)
            scrubber.m.ipv4(ip) if is_plain_ipv4(ip) else None
            ph = (scrubber.learn_host(cols[0], prefix=sec["prefix"] + "-worker") if scrubber.anonymize
                  else "%s (%s)" % (cols[0], ip)) or ip
            w = Target(ctx, sec, ip, ph, discovered=True)
            w.user, w.password, w.su_password = cred
            workers.append(w)
    if not workers:
        return
    log("[%s] %d worker node(s) found through Kubernetes" % (sec["name"], len(workers)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, ctx.args.parallel)) as pool:
        list(pool.map(lambda w: collect_target(w, node_groups, progress), workers))
    targets.extend(workers)


def learn_from_results(done, scrubber):
    """Feed everything we collected into the scrubber before any text is written."""
    texts = []
    # Every host's own name first, so that a node seen in another host's output
    # gets the same placeholder as the host itself.
    for item, targets in done:
        for t in targets:
            for name in t.identity:
                short = name.split(".")[0].lower()
                if "." in name:
                    scrubber.learn_domain(name.split(".", 1)[1])
                if short not in GENERIC_NAMES and not short.isdigit():
                    scrubber.m.alias("host", short, t.ph)
    for item, targets in done:
        nodeprefix = item["sec"]["prefix"] if item["sec"]["type"] == "vcfmgmt" else "k8snode"
        for t in targets:
            if t.errmsg:
                texts.append(t.errmsg)
            for r in t.results:
                spec = r["spec"]
                # a summarized result keeps its full output: names are learned from all of it
                full = r.get("raw") or r["out"]
                for cat, rx, split in spec["harvest"]:
                    for m in re.finditer(rx, full):
                        for v in (re.split(split, m.group(1)) if split else [m.group(1)]):
                            scrubber.learn(cat, v)
                if spec["k8s"]:
                    scrubber.learn_k8s(spec["k8s"], full, prefix=nodeprefix)
                texts.append(full)
                if full is not r["out"]:
                    texts.append(r["out"])
    for tx in texts:
        scrubber.prescan(tx)
    scrubber.compile()


# ----------------------------------------------------------------------------
# Report
# ----------------------------------------------------------------------------
def clip(text, max_lines):
    lines = text.rstrip("\n").split("\n")
    lines = [ln if len(ln) <= 2000 else ln[:2000] + " ...[line truncated]" for ln in lines]
    if len(lines) > max_lines:
        head = int(max_lines * 0.7)
        tail = max_lines - head
        lines = lines[:head] + ["... [%d lines omitted] ..." % (len(lines) - max_lines)] + lines[-tail:]
    return "\n".join(lines)


def fence(text):
    n = 3
    for m in re.finditer(r"`{3,}", text):
        n = max(n, len(m.group(0)) + 1)
    return "`" * n


LEGEND = """\
All identifying values were replaced on the collecting machine before this file was written.
The same real value always maps to the same placeholder, in this and in later reports.

| Placeholder | Stands for |
|---|---|
| `esxi-01`, `vcenter-01`, `nsxmgr-01`, `k8snode-...-01` ... | a host listed in the inventory (prefix = component type and group label) |
| `host-0001` | another host in the environment's own DNS domains |
| `exthost-0001` | a host in some other DNS domain |
| `domain-01` | a DNS domain. `esxi-01.domain-01` is a fully qualified name |
| `ip-n3-h7` | an IPv4 address: `n3` = the third distinct /24 network seen, `h7` = the seventh address in it |
| `ip6-0001`, `ip6-ll-0001` | IPv6 address / link-local IPv6 address |
| `mac-`, `wwn-`, `uuid-`, `serial-`, `thumbprint-`, `license-`, `naa.device-`, `iqn-` | hardware and software identifiers |
| `datastore-`, `portgroup-`, `dvs-`, `lrouter-`, `ns-`, `k8sobj-`, `dn-`, `term-` | named objects, certificate name parts, custom terms |
| `[REDACTED...]` | a secret (password, token, key, certificate body) |

An UPPERCASE placeholder means the original was written in upper case. Loopback, link-local,
multicast addresses and netmasks are left as they are."""


LEGEND_PLAIN = """\
This report is **not anonymized**: host names, domains and addresses are real. Only secrets
(passwords, tokens, keys, certificate bodies) are replaced by `[REDACTED...]`. Keep it inside
the organisation."""


# ----------------------------------------------------------------------------
# Key facts: a short, machine-readable digest of each target, derived from the
# (summarized) check output. Keyed by check label; each returns [(key, value)].
# ----------------------------------------------------------------------------

def _fact_df(out):
    worst = None
    for ln in out.splitlines():
        m = re.match(r"^(\S+)\s+\S+\s+\S+\s+\S+\s+(\d+)%\s+(/\S*)\s*$", ln)
        if m and not m.group(1).startswith(("tmpfs", "devtmpfs", "none", "overlay")):
            if worst is None or int(m.group(2)) > worst[0]:
                worst = (int(m.group(2)), m.group(3))
    return [("fs_fullest", "%d%% %s" % worst)] if worst else []


def _fact_uptime(out):
    f = []
    m = re.search(r"up\s+(\d+)\s+day", out)
    f.append(("uptime_days", int(m.group(1)) if m else 0))
    m = re.search(r"load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)", out)
    if m:
        f.append(("load_avg_1_5_15", "%s %s %s" % m.groups()))
    return f


def _fact_cluster(out):
    f = []
    m = re.search(r"(?i)overall(?: status)?:\s*(\S+)", out)
    if m:
        f.append(("cluster_overall", m.group(1)))
    m = re.search(r"(\d+) of (\d+) groups STABLE", out)
    if m:
        f.append(("cluster_groups_stable", "%s/%s" % m.groups()))
    ups = re.findall(r"(?m)^\s+(?:member: )?\S+\s+\S+\s+(UP|DOWN|\S+)$", out)
    if ups:
        f.append(("cluster_members_up", "%d/%d" % (ups.count("UP"), len(ups))))
    return f


def _fact_alarms(out):
    if out.startswith("No open"):
        return [("alarms_open", 0)]
    m = re.match(r"(\d+) alarm\(s\):\s*(.*)", out)
    return [("alarms_open", int(m.group(1))), ("alarms_by_severity", m.group(2).strip())] if m else []


def _fact_tn(out):
    f = []
    m = re.match(r"(\d+) transport node", out)
    if m:
        f.append(("transport_nodes", int(m.group(1))))
    bad = re.search(r"Nodes not in a good state:\n((?:  .*\n?)*)", out)
    if bad:
        rows = [ln for ln in bad.group(1).splitlines() if ln.strip() and ln.strip() != "none"]
        f.append(("transport_nodes_not_good", len(rows)))
    m = re.search(r"Tunnel / connection status: (.*)", out)
    if m:
        f.append(("transport_node_status", m.group(1).strip()))
    return f


def _fact_mem(out):
    f = []
    m = re.search(r"available [\d.]+ GiB \((\d+)%\)", out)
    if m:
        f.append(("mem_available_pct", int(m.group(1))))
    if "swap: none" in out:
        f.append(("swap", "none"))
    return f


def _fact_ntp(out):
    m = re.search(r"(?m)^\*\S+\s+\S+\s+(\d+)\s+\w\s+\S+\s+\d+\s+\d+\s+[\d.]+\s+(-?[\d.]+)", out)
    if m:
        return [("ntp_synced", "yes, stratum %s" % m.group(1)), ("ntp_offset_ms", float(m.group(2)))]
    return [("ntp_synced", "no peer selected")] if re.search(r"(?m)^=+$", out) else []


def _fact_backups(out):
    f = []
    m = re.search(r"automatic backups: (.*)", out)
    if m:
        f.append(("backup_automatic", m.group(1).strip()))
    for kind, last in re.findall(r"(?m)^(\w+) backup:\n\s+(.+)$", out):
        f.append(("backup_last_%s" % kind, last.strip()))
    return f


def _fact_services(out):
    m = re.match(r"(\d+) services: (.*)", out)
    if not m:                                   # not summarized (e.g. NSX Edge): no digest
        return []
    f = [("services", m.group(2))]
    m = re.search(r"NOT RUNNING \(unexpected\): (.*)", out)
    f.append(("services_down_unexpected", m.group(1) if m else "none"))
    m = re.search(r"(?m)^  ssh: .*root login (\w+)", out)
    if m:
        f.append(("ssh_root_login", m.group(1)))
    return f


def _fact_nsx_users(out):
    due = []
    for ln in out.splitlines():
        m = re.match(r"^(\S+)\s+ACTIVE\s+(\d+)\s+(\d+)\s*$", ln)
        if m:
            due.append((int(m.group(2)) - int(m.group(3)), m.group(1)))
    return [("account_expiry_soonest", "%s in %d days" % (min(due)[1], min(due)[0]))] if due else []


def _vcfa_fact(key, count):
    """Key fact from an Automation check; reports a missing namespace once, as its own fact."""
    def fn(out):
        if out.startswith("No VCF Automation namespaces found"):
            return [("automation_namespaces", "none found")]
        return [(key, count(out))]
    return fn


def _rows(out):
    return 0 if out.strip() == "none" else len([ln for ln in out.splitlines() if ln.strip()])


def _fact_vcfa_certs(out):
    if out.startswith("No VCF Automation namespaces found"):
        return [("automation_namespaces", "none found")]
    ends = re.findall(r"notAfter=(.+)", out)
    f = [("automation_certs_checked", len(ends))] if ends else []
    if ends:
        dates = []
        for e in ends:
            try:
                dates.append(datetime.datetime.strptime(e.strip().replace("  ", " "), "%b %d %H:%M:%S %Y %Z"))
            except ValueError:
                pass
        if dates:
            f.append(("automation_cert_expires_first", min(dates).strftime("%Y-%m-%d")))
    if "expires within 30 days" in out:
        f.append(("automation_cert_expiring_30d", out.count("expires within 30 days")))
    if "no TLS answer" in out:
        f.append(("automation_hosts_without_tls", out.count("no TLS answer")))
    return f


KEY_FACTS = {
    "Automation pods not Running or not Ready": _vcfa_fact("automation_pods_not_ready", _rows),
    "Automation workloads below desired replicas": _vcfa_fact("automation_workloads_below_desired", _rows),
    "Errors in Automation pod logs (last 30 min)": _vcfa_fact(
        "automation_pods_with_log_errors", lambda o: len(re.findall(r"(?m)^== ", o))),
    "Automation ingress hosts and certificates": _fact_vcfa_certs,
    "Version": lambda o: [("version", m.group(1)) for m in [re.search(r"Version (\S+)", o)] if m],
    "Uptime": _fact_uptime,
    "CPU": lambda o: [("cpus", int(m.group(1))) for m in [re.match(r"(\d+) logical CPU", o)] if m],
    "Memory": _fact_mem,
    "Filesystems": _fact_df,
    "Disk usage": _fact_df,
    "Core dumps": lambda o: [("core_dumps", 0)] if o.startswith("No core dumps") else [],
    "NTP associations": _fact_ntp,
    "DNS servers": lambda o: [("dns_servers", n) for n in [len(set(re.findall(
        r"(?<![\w.:])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![\w.:])", o)))] if n],
    "Cluster status": _fact_cluster,
    "Cluster status (API)": _fact_cluster,
    "Open alarms": _fact_alarms,
    "Transport nodes": _fact_tn,
    "Edge clusters": lambda o: [("edge_clusters", len(re.findall(r"(?m)^edge cluster: ", o)))],
    "Backups": _fact_backups,
    "Services": _fact_services,
    "Local users and password expiry": _fact_nsx_users,
}


def key_facts(t):
    """[(key, value)] for one target; later checks do not overwrite a key already set."""
    facts, seen = [], set()
    if t.clock_offset is not None:
        facts.append(("clock_offset_s", round(t.clock_offset)))
        seen.add("clock_offset_s")
    for r in t.results:
        fn = KEY_FACTS.get(r["label"])
        if not fn or r["status"] != "ok":
            continue
        try:
            got = fn(r["out"] or "")
        except Exception:  # noqa: BLE001 - a digest must never break the report
            continue
        for k, val in got:
            if k not in seen:
                seen.add(k)
                facts.append((k, val))
    failed = [r["label"] for r in t.results if r["status"] in ("fail", "timeout")]
    if failed:
        facts.append(("checks_failed", "; ".join(failed)))
    return facts


def build_report(ctx, done, scrubber, started, max_lines, kind="health", title=""):
    S = scrubber.scrub
    out = []
    w = out.append
    w("# VCF %s%s report" % ("anonymized " if scrubber.anonymize else "",
                            "follow-up" if kind == "followup" else "diagnostic"))
    w("")
    w("- Generated: %s UTC" % started.strftime("%Y-%m-%d %H:%M:%S"))
    w("- Tool: vcf_diag %s, Python %s, %s" % (VERSION, sys.version.split()[0], ctx.ssh_banner))
    if kind == "followup":
        w("- Scope: read-only diagnostics requested in an analyst plan%s" % (": " + S(title) if title else ""))
    else:
        w("- Scope: health and status checks only, read-only commands over SSH")
    w("")
    w("## How to read this report")
    w("")
    w(LEGEND if scrubber.anonymize else LEGEND_PLAIN)
    w("")
    w("## How to reply (for the analyst)")
    w("")
    w(ANALYST_GUIDE if scrubber.anonymize else ANALYST_GUIDE.replace(ANALYST_INTRO, ANALYST_INTRO_PLAIN))
    w("")
    w("## Summary")
    w("")
    w("| Target | Group | Result | Shell | Checks | Failed | Timed out | Skipped | Clock offset (s) |")
    w("|---|---|---|---|---|---|---|---|---|")
    attention = []
    for item, targets in done:
        for t in targets:
            n = len(t.results)
            f = sum(1 for r in t.results if r["status"] == "fail")
            to = sum(1 for r in t.results if r["status"] == "timeout")
            sk = sum(1 for r in t.results if r["status"] == "skipped")
            result = "collected" if not t.errkind else t.errkind
            off = "%+d" % round(t.clock_offset) if t.clock_offset is not None else "-"
            off = "0" if off in ("+0", "-0") else off
            w("| %s | %s | %s | %s | %d | %d | %d | %d | %s |" % (
                t.ph, item["sec"]["name"], result, t.mode or "-", n, f, to, sk, off))
            if t.errkind:
                attention.append("- **%s**: %s - %s" % (t.ph, t.errkind, S(t.errmsg)))
            if t.clock_offset is not None and abs(t.clock_offset) > 5:
                attention.append("- **%s**: clock differs from the collector by %+.0f s" % (t.ph, t.clock_offset))
            timed = [S(r["label"]) for r in t.results if r["status"] == "timeout"]
            failed = [S(r["label"]) for r in t.results
                      if r["status"] == "fail" and r.get("note") != TOOL_ERROR_NOTE]
            tool_err = [S(r["label"]) for r in t.results
                        if r["status"] == "fail" and r.get("note") == TOOL_ERROR_NOTE]
            if timed:
                attention.append("- %s: timed out: %s" % (t.ph, "; ".join(timed)))
            if failed:
                attention.append("- %s: non-zero exit status: %s" % (t.ph, "; ".join(failed)))
            if tool_err:
                attention.append("- %s: tool error (request refused by the API, not an environment fault): %s"
                                 % (t.ph, "; ".join(tool_err)))
    w("")
    w("### Items needing attention (collection level)")
    w("")
    out.extend(attention or ["- none"])
    w("")
    w("A non-zero exit status is not always a fault: a check for a feature that is not in use")
    w("(vSAN, NSX, a missing tool) also ends that way. Read the output before concluding.")
    digest = [(t, key_facts(t)) for _, targets in done for t in targets]
    if any(f for _, f in digest):
        w("")
        w("### Key facts")
        w("")
        w("Derived by the tool from the checks below (YAML, one entry per target). It is a digest,")
        w("not a verdict: read the check output for detail.")
        w("")
        body = []
        for t, facts in digest:
            if facts:
                body.append("%s:" % t.ph)
                body += ["  %s: %s" % (k, json.dumps(val) if isinstance(val, str) else val) for k, val in facts]
        body = S("\n".join(body))
        f = fence(body)
        w(f + "yaml")
        w(body)
        w(f)
    for item, targets in done:
        sec = item["sec"]
        w("")
        w("## [%s] %s" % (sec["name"], COMPONENTS[sec["type"]]["title"]))
        for t in targets:
            w("")
            w("### %s" % t.ph)
            w("")
            if t.errkind:
                w("Not collected over SSH: %s - %s" % (t.errkind, S(t.errmsg)))
                if not t.results:
                    continue
                w("")
            info = ["user `%s`" % S(t.user), "shell mode `%s`" % t.mode]
            if t.identity:
                short, _, dom = t.identity[0].lower().partition(".")
                name = scrubber.m.lookup("host", short) or t.ph
                if dom:
                    name += "." + (scrubber.m.lookup("domain", dom) or "domain-unknown")
                if not scrubber.anonymize:
                    name = t.identity[0]
                info.append("reports its own name as `%s`" % name)
            w("Connection: " + ", ".join(info) + ".")
            for note in t.notes:
                w("Note: " + S(note))
            gkey = None
            for r in t.results:
                if r["group"][0] != gkey:
                    gkey = r["group"][0]
                    w("")
                    w("#### %s - %s" % (gkey, r["group"][1]))
                w("")
                if r["status"] == "skipped":
                    w("**%s** - skipped: %s" % (S(r["label"]), S(r["note"])))
                    continue
                status = "ok" if r["status"] == "ok" else (
                    "TIMEOUT" if r["status"] == "timeout" else "exit %s" % r["rc"])
                w("**%s** (%s, %.1fs)" % (S(r["label"]), status, r["dur"]))
                w("")
                if r["note"]:
                    w("Note: " + S(r["note"]))
                    w("")
                w("`$ %s`" % S(r["cmd"]).replace("`", "'"))
                body = S(clip(r["out"], max(r["spec"]["max_lines"] or max_lines, max_lines)))
                body = "\n".join(ln.rstrip() for ln in body.split("\n")).strip("\n")
                if not body.strip():
                    body = "(no output)"
                f = fence(body)
                w(f + "text")
                w(body)
                w(f)
    w("")
    w("## Anonymization statistics")
    w("")
    counts = scrubber.m.counts()
    w("Distinct values replaced so far (all runs): " + (", ".join(
        "%s %d" % (k, v) for k, v in sorted(counts.items()) if k != "target") or "none"))
    w("")
    return "\n".join(out)


def review_data(scrubber, text):
    """Local privacy check of finished text. The result contains real values:
    show it to the person running the tool, never put it in a report."""
    if not scrubber.anonymize:
        return {"hits": [], "quads": [], "known": 0, "anonymized": False}
    quads = {}
    for m in RX_DOTTED_QUAD.finditer(text):
        if is_plain_ipv4(m.group(0)):
            quads[m.group(0)] = quads.get(m.group(0), 0) + 1
    return {"anonymized": True, "hits": sorted(scrubber.leak_check(text).items(), key=lambda kv: -kv[1]),
            "quads": sorted(quads.items()),
            "known": sum(len(v) for c, v in scrubber.m.maps.items() if c != "ipv4net")}


def print_review(data):
    if not data.get("anonymized", True):
        print("\nNot anonymized: the report contains real host names and addresses (secrets are redacted).")
        print("  Keep it inside the organisation.")
        return
    print("\nPrivacy check of the written report")
    if data["hits"]:
        print("  WARNING: %d known real value(s) are still present. Review before sharing:" % len(data["hits"]))
        for real, n in data["hits"][:40]:
            print("    %-40s %d occurrence(s)" % (real, n))
        print("  Add them to scrub_terms / extra_domains in the inventory and run again.")
    else:
        print("  OK - none of the %d known real names or addresses appear in the report." % data["known"])
    if data["quads"]:
        print("  Dotted values left readable because they look like version numbers:")
        print("    " + ", ".join("%s (x%d)" % tuple(kv) for kv in data["quads"]))
        print("  If any of these is really an IP address, remove it from keep_literals and tell me.")


def review(scrubber, text):
    """Run the privacy check and print it on the console."""
    data = review_data(scrubber, text)
    print_review(data)
    return data


# ----------------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------------
def anonymize_enabled(args, settings):
    if getattr(args, "no_anonymize", False):
        return False
    return (settings.get("anonymize") or "yes").strip().lower() not in ("no", "false", "off", "0")


def max_lines_for(args, settings):
    return args.max_lines or _clamp(settings.get("max_lines"), 200, 20, 100000)


def make_scrubber(args, settings):
    if not anonymize_enabled(args, settings):
        return Scrubber(Mapping(None), anonymize=False)     # no mapping is kept either
    os.makedirs(args.private_dir, mode=0o700, exist_ok=True)
    mapping = Mapping(os.path.join(args.private_dir, "mapping.json"))
    return Scrubber(mapping,
                    extra_domains=split_list(settings.get("extra_domains", "")),
                    terms=[t.strip() for t in re.split(r"[,\n]+", settings.get("scrub_terms", "")) if t.strip()],
                    keep_literals=split_list(settings.get("keep_literals", "")),
                    keep_namespaces=split_list(settings.get("keep_namespaces", "")))


def find_inventory(args):
    if args.inventory:
        return args.inventory
    for cand in ("inventory.ini", os.path.join(os.path.dirname(os.path.abspath(__file__)), "inventory.ini")):
        if os.path.exists(cand):
            return cand
    return None


def cmd_init(args):
    path = args.inventory or "inventory.ini"
    if os.path.exists(path):
        die("%s already exists - not overwriting it" % path)
    write_private(path, INVENTORY_TEMPLATE)
    print("Wrote %s. Add your hosts to it, then run:  python3 %s" % (path, os.path.basename(__file__)))


def cmd_list(args):
    custom = {}
    inv = find_inventory(args)
    if inv:
        _, _, custom = load_inventory(inv)
    for typ, comp in COMPONENTS.items():
        print("\n[%s] %s  (default user: %s)" % (typ, comp["title"], comp["user"]))
        for key, title, cmds in groups_for(typ, custom):
            print("  %s - %s" % (key, title))
            for c in cmds:
                print("      %-34s %s" % (c["label"], c["cmd"]))


def learn_inventory(scrubber, sections):
    for s in sections:
        for name in s.get("endpoints") or {}:
            if is_ip(name):
                if is_plain_ipv4(name):
                    scrubber.m.ipv4(name)
            else:
                scrubber.learn_host(name, prefix="endpoint")
        for addr in s["hosts"]:
            if is_ip(addr):
                scrubber.m.get("target", addr, prefix=s["prefix"], width=2)
                if is_plain_ipv4(addr):
                    scrubber.m.ipv4(addr)
            else:
                scrubber.learn_host(addr, prefix=s["prefix"])


def scrub_texts(args, texts):
    """Anonymize arbitrary texts with the inventory settings and the saved mapping."""
    settings, sections = {}, []
    inv = find_inventory(args)
    if inv:
        settings, sections, _ = load_inventory(inv)
    scrubber = make_scrubber(args, settings)
    learn_inventory(scrubber, sections)
    for tx in texts:
        scrubber.prescan(tx)
    scrubber.compile()
    results = [scrubber.scrub(tx) for tx in texts]
    scrubber.m.save()
    return scrubber, results


def decode_text(args, text):
    """Translate placeholders back to real names using the private mapping."""
    dec = Decoder(Mapping(os.path.join(args.private_dir, "mapping.json")))
    if not dec.rev:
        die("no mapping found in %s - run a collection first" % args.private_dir)
    return dec(text)


def cmd_scrub_files(args):
    texts = []
    for path in args.scrub_file:
        with open(path, encoding="utf-8", errors="replace") as fh:
            texts.append(fh.read())
    scrubber, results = scrub_texts(args, texts)
    os.makedirs(args.output_dir, exist_ok=True)
    for path, result in zip(args.scrub_file, results):
        dest = os.path.join(args.output_dir, "anon-%s-%s.txt" % (
            datetime.datetime.now().strftime("%Y%m%d-%H%M%S"),
            scrubber.m.get("file", os.path.abspath(path), width=3)))
        write_private(dest, result)
        print("Anonymized %s -> %s" % (path, dest))
        review(scrubber, result)
    scrubber.m.save()


def cmd_decode(args):
    with open(args.decode, encoding="utf-8", errors="replace") as fh:
        sys.stdout.write(decode_text(args, fh.read()))


def collect_and_report(args, settings, sections, plan, ui, on_context=None, kind="health", title=""):
    """Run a plan and write the anonymized report. Shared by the terminal and the GUI.
    Returns None when the run was cancelled."""
    args.connect_timeout = getattr(args, "connect_timeout", None) or _clamp(settings.get("connect_timeout"), 15, 3, 300)
    args.strict_host_keys = getattr(args, "strict_host_keys", False) or \
        (settings.get("strict_host_keys") or "no").strip().lower() in ("yes", "true", "1", "on")
    ctx = Context(args)
    if on_context:
        on_context(ctx)
    try:
        scrubber = make_scrubber(args, settings)
        learn_inventory(scrubber, sections)
        started = datetime.datetime.now(datetime.timezone.utc)
        done = run_plan(ctx, plan, scrubber, ui)
        if ctx.cancel.is_set():
            return None
        learn_from_results(done, scrubber)
        report = build_report(ctx, done, scrubber, started, max_lines_for(args, settings), kind=kind, title=title)
        scrubber.m.save()
        os.makedirs(args.output_dir, exist_ok=True)
        path = os.path.join(args.output_dir, "vcf-%s-%s.md" % (
            "followup" if kind == "followup" else "report", started.strftime("%Y%m%d-%H%M%S")))
        write_private(path, report)
    finally:
        ctx.cleanup()
    targets = [t for _, ts in done for t in ts]
    return {"path": os.path.abspath(path), "report": report, "review": review_data(scrubber, report),
            "total": len(targets), "failed": sum(1 for t in targets if t.errkind),
            "targets": [{"section": t.sec["name"], "address": t.address, "placeholder": t.ph,
                         "result": t.errkind or "collected", "detail": t.errmsg,
                         "checks": len(t.results),
                         "problems": sum(1 for r in t.results if r["status"] in ("fail", "timeout"))}
                        for t in targets]}


def scale_timeouts(plan, factor):
    if factor != 1.0:
        for item in plan:
            item["groups"] = [(k, t, [dict(c, timeout=max(5, int(c["timeout"] * factor))) for c in cs])
                              for k, t, cs in item["groups"]]


def cmd_collect(args):
    inv = find_inventory(args)
    if not inv:
        die("no inventory file found. Create one with:  python3 %s --init" % os.path.basename(__file__))
    settings, sections, custom = load_inventory(inv)
    if args.parallel is None:
        args.parallel = int(settings.get("parallel", 4))
    if args.timeout_scale is None:
        args.timeout_scale = float(settings.get("timeout", 30)) / 30.0
    print("vcf_diag %s - anonymized VCF health collector" % VERSION)
    print("Inventory: %s   Private mapping: %s" % (inv, args.private_dir))
    plan = build_plan(sections, custom, args.all)
    if not plan:
        die("nothing selected", 0)
    scale_timeouts(plan, args.timeout_scale)
    print("\nPlan")
    for item in plan:
        n = sum(len(g[2]) for g in item["groups"])
        print("  [%s] %d host(s) x %d checks: %s" % (item["sec"]["name"], len(item["hosts"]), n,
                                                    ", ".join(g[0] for g in item["groups"])))
    if args.dry_run:
        print("\nDry run - nothing was contacted.")
        return
    if not args.all and not ask_yes("\nProceed? Only read-only commands are run."):
        return
    for sig in (signal.SIGTERM, signal.SIGHUP):      # close connections if we are killed
        signal.signal(sig, lambda *_: sys.exit(143))
    try:
        res = collect_and_report(args, settings, sections, plan, ConsoleUI())
    except KeyboardInterrupt:
        print("\nInterrupted - connections closed. No report written.")
        sys.exit(130)
    print_result(args, res)


def print_result(args, res):
    print_review(res["review"])
    report = res["report"]
    print("\nReport:  %s" % res["path"])
    print("Size:    %.0f KB, roughly %d thousand tokens" % (len(report) / 1024.0, len(report) // 3500))
    print("Hosts:   %d collected, %d not collected" % (res["total"] - res["failed"], res["failed"]))
    if len(report) > 1500000:
        print("Note:    this is a large report. Consider collecting one component group at a time.")
    if res["review"].get("anonymized", True):
        print("Mapping: %s  (PRIVATE - never share)" % os.path.join(args.private_dir, "mapping.json"))
    print("\nOpen the report and skim it before sharing. Use --decode to translate an analysis back.")


# ----------------------------------------------------------------------------
# Analyst replies: follow-up diagnostics (run, read-only) and fixes (translated
# for the person to apply by hand - this tool never runs a fix)
# ----------------------------------------------------------------------------
ANALYST_INTRO = """\
The person who sent this report works in an isolated environment. Their tool translates your
reply back to real names, so always refer to hosts, addresses, domains and objects by the
placeholders exactly as they appear here."""
ANALYST_INTRO_PLAIN = """\
The person who sent this report works in an isolated environment. Refer to hosts by the names
used in the section headings of this report (the names in the inventory)."""
ANALYST_GUIDE = ANALYST_INTRO + """ Write your analysis as normal prose. When you need
more data, or want to propose changes, add one fenced block like this to your reply:

````text
```vcf-plan
plan: short title of what this plan is for

[collect] target=vcenter-01
label: vpxd errors, last 200 lines
run: grep -iE 'error|fail' /var/log/vmware/vpxd/vpxd.log | tail -n 200

[collect] target=@esxi:mgmt
label: vmkernel warnings
run: grep -i warn /var/log/vmkernel.log | tail -n 100
timeout: 60

[fix] target=vcenter-01
label: Restart the vpxd service
run: service-control --restart vmware-vpxd
note: vCenter is unavailable for about two minutes. No rollback needed.
```
````

Rules for the block:

- `target=` takes one or more hosts from this report, comma separated, or
  `@group` for every host of a group (the group names are the `[...]` section headings below).
- `[collect]` steps must only read. The tool shows them to the person, runs them after they
  confirm, and returns the anonymized output as a follow-up report. A step that looks as if it
  changes anything is refused, as is one that would print secrets.
- `[fix]` steps are never run by the tool. The person reads them with real names and applies
  them by hand. Make each one a complete command, put them in the order they must be applied,
  and state impact and rollback in `note:`.
- One command per `run:`; continue a long command on indented lines. On Kubernetes nodes write
  `{K}` for kubectl. On NSX nodes NSX CLI commands (`get ...`) can be given directly.
- Optional per step: `timeout:` seconds (default 60) and `lines:` output lines to keep (default 400).
- Commands run on the target as the login user shown in each host's "Connection:" line, through
  sudo where the tool has it. Do not add sudo yourself. Use `journalctl` and log files freely.
- Connection problems in a report (host key, authentication, unreachable) happen on the person's
  own computer, not on the targets. Do not ask to inspect them on a target; propose a [fix] for
  the person to run locally instead (for a changed host key: `ssh-keygen -R <host>`).
- Ask only for what you need: every line of output costs the person review time."""

PLAN_FENCE = re.compile(r"`{3,}[ \t]*vcf-plan[^\n]*\n(.*?)`{3,}", re.S)
PLAN_STEP = re.compile(r"(?i)^\[(collect|fix)\][ \t]*(.*)$")
PLAN_KEY = re.compile(r"(?i)^(targets?|label|run|note|mode|timeout|lines)[ \t]*[:=][ \t]?(.*)$")
FOLLOWUP_GROUP = ("followup", "Follow-up diagnostics requested by the analyst")


def parse_plan(text):
    """Extract the steps of a vcf-plan block from an analyst reply."""
    text = text.replace("\r\n", "\n")
    blocks = PLAN_FENCE.findall(text)
    body = "\n".join(textwrap.dedent(b) for b in blocks) if blocks else text
    title, steps, cur, last = "", [], None, None
    for raw in body.split("\n"):
        line = raw.rstrip()
        indented = raw[:1] in (" ", "\t")
        m = None if indented else PLAN_STEP.match(line)
        if m:
            cur = {"kind": m.group(1).lower(), "targets": [], "label": "", "run": "", "note": "",
                   "mode": "", "timeout": "", "lines": ""}
            tm = re.match(r"(?i)targets?[ \t]*[:=][ \t]*(.*)$", m.group(2).strip())
            if tm:
                cur["targets"] = split_list(tm.group(1))
            steps.append(cur)
            last = None
            continue
        if cur is None:
            tm = re.match(r"(?i)^#*[ \t]*plan[ \t]*:[ \t]*(.+)$", line.strip())
            if tm and not title:
                title = tm.group(1).strip()
            continue
        if indented and last and line.strip():
            cur[last] += ("\n" if last == "run" else " ") + line.strip()
            continue
        km = None if indented else PLAN_KEY.match(line)
        if km:
            key = km.group(1).lower()
            if key.startswith("target"):
                cur["targets"] += split_list(km.group(2))
                last = None
            else:
                cur[key] = km.group(2).strip()
                last = key
            continue
        last = None
    return {"title": title, "steps": steps}


# A safety net, not a proof: a [collect] step that matches any of these is not run.
_CMDPOS = r"(?:^|[|;&(`{\n]|\$\(|\b(?:xargs|exec|then|do|else|time|nohup|watch|env|timeout)\s[^|;&]*?|-exec\s|-ok\s)\s*(?:[\w./-]*/)?"
_KUBE_READ = set("get describe logs top version api-resources api-versions cluster-info explain events".split())
_KUBE_WRITE = set("""delete apply create replace patch edit scale drain cordon uncordon taint label annotate exec cp
run expose set autoscale debug attach port-forward proxy certificate approve deny""".split())
READONLY_RULES = [(re.compile(rx, re.I), why) for rx, why in [
    (_CMDPOS + r"(?:rm|rmdir|mv|cp|dd|truncate|shred|chmod|chown|chgrp|chattr|ln|touch|mkdir|mktemp|tee|install|"
               r"unlink|mkfs\S*|mount|umount|fsck\S*|gunzip|unzip|patch|vi|vim|nano|ed)(?![\w.-])",
     "it can create, change or delete files"),
    (r"\bfind\b[^|;&]*\s-(?:delete|fprint\S*|fls)\b", "it can delete or write files"),
    (r"\bsed\b[^|;&]*\s-[a-z]*i|\bsed\b[^|;&]*--in-place|\bperl\b[^|;&]*\s-[a-z]*i", "it can edit a file in place"),
    (_CMDPOS + r"(?:reboot|shutdown|halt|poweroff|init|telinit|kill|pkill|killall|kexec)(?![\w.-])",
     "it can stop processes or the system"),
    (r"\bsystemctl\b[^|;&]*\b(?:start|stop|restart|try-restart|reload\S*|enable|disable|mask|unmask|"
     r"daemon-reload|daemon-reexec|kill|reset-failed|isolate|set-property|set-default|edit|revert|preset\S*)\b",
     "it can change a service"),
    (r"\bservice-control\b[^|;&]*--(?:start|stop|restart)|\bservice\s+\S+\s+(?:start|stop|restart|reload)\b|"
     r"/etc/init\.d/\S+\s+(?:start|stop|restart|reload)\b|\bvmon-cli\b[^|;&]*\s(?:-[ikr]\b|--(?:start|stop|restart))",
     "it can start or stop a service"),
    (r"\bvim-cmd\b[^|;&]*(?:power\.(?!getstate)|destroy|unregister|reload|maintenance_mode_(?:enter|exit)|"
     r"snapshot\.(?:create|remove|revert)|/(?:set|add|remove|delete|start|stop|restart|enable|disable)\w*)",
     "it can change the host or a VM"),
    (r"\bvsish\b[^|;&]*-e\s+set\b", "it can change a kernel setting"),
    (r"\bnsxcli\s+-c\s+(?![\"']?\s*get\b)", "only NSX CLI 'get' commands are read-only"),
    (r"\bcurl\b[^|;&]*(?:-X\s*(?:POST|PUT|PATCH|DELETE)|--request[ =](?:POST|PUT|PATCH|DELETE)|\s-d\b|--data|"
     r"(?-i:\s-T\b|\s-F\b|\s-O\b)|--upload-file|--form|(?:(?-i:\s-o)|--output)(?![ =]*/dev/null))", "it can send data or write a file"),
    (_CMDPOS + r"(?:wget|scp|sftp|rsync|ssh|telnet|ftp|tftp|socat)(?![\w.-])", "it can copy data or open a session elsewhere"),
    (_CMDPOS + r"(?:nc|ncat|netcat)(?![\w.-])(?![^|;&]*\s-[a-z]*z)", "it can send data to another system"),
    (r"\b(?:psql|mysql|sqlite3)\b[^|]*\b(?:update|delete|insert|drop|alter|truncate|create|vacuum|reindex|grant|revoke)\b",
     "it can change a database"),
    (_CMDPOS + r"(?:tdnf|yum|dnf|apt|apt-get|dpkg|pip[0-9.]*|esxupdate)(?![\w.-])|\brpm\s+-(?![a-z]*q)[a-z]*[ieUF]",
     "it can install or remove software"),
    (_CMDPOS + r"(?:passwd|chpasswd|useradd|userdel|usermod|groupadd|groupdel|visudo)(?![\w.-])|\bchage\s+(?!-l\b)|"
     r"\b(?:pam_tally2|faillock)\b[^|;&]*(?:--reset|-r\b)", "it can change accounts"),
    (_CMDPOS + r"(?:sudo|su|doas)(?![\w.-])", "privilege is handled by the tool (sudo / escalate in the inventory)"),
    (_CMDPOS + r"(?:eval|source|\.)\s|\b(?:bash|sh|zsh|ash|python[0-9.]*|perl|ruby|node)\s+-[ce]\b|"
     r"\bbase64\s+(?:-d|--decode)\b|\|\s*(?:bash|sh|zsh|ash|python[0-9.]*)\b", "it runs code that cannot be checked"),
    (r"\b(?:crictl|docker|ctr|nerdctl)\b[^|;&]*\s(?:rm|rmi|stop|kill|exec|pull|push|run|runp|create|start|restart|prune)\b",
     "it can change containers"),
    (r"\betcdctl\b[^|;&]*\s(?:put|del|defrag|compact|move-leader|snapshot\s+(?:save|restore)|member\s+(?:add|remove|update))\b",
     "it can change etcd"),
    (r"\bkubeadm\b[^|;&]*\s(?:reset|init|join|upgrade\s+apply|certs\s+renew|token\s+(?:create|delete))\b|"
     r"\bhelm\b[^|;&]*\s(?:install|upgrade|uninstall|rollback|delete)\b", "it can change the cluster"),
    (r"(?:/etc/shadow|/etc/gshadow|id_rsa|id_ed25519|id_ecdsa|\.pgpass|\.kube/config|/etc/kubernetes/\S*\.conf|"
     r"/etc/kubernetes/pki/\S*\.key|\S+\.key\b|\S+\.pfx\b|\S+\.p12\b|\S+\.jks\b)", "it would read secrets or private keys"),
    (r"(?:kubectl|\{K\})[^|;&]*\bget\b[^|;&]*\bsecrets?\b[^|;&]*(?:-o|--output)", "it would print secret values"),
]]
_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")
_REDIRECT = re.compile(r"(?<![0-9&<>])[0-9]?>{1,2}(?!\s*(?:&[0-9]|/dev/null))")
_SEGMENT = re.compile(r"[^|;&\n]+")


def readonly_problem(command, mode):
    """Return why a command may not be read-only, or None when nothing suspicious was found."""
    if mode == "nsxcli":
        if not re.match(r"\s*(?:get|ping|traceroute|nslookup|help)\b", command) or re.search(r"[|;&`\n]|\$\(", command):
            return "only single NSX CLI 'get' commands are read-only"
        return None
    for rx, why in READONLY_RULES:
        if rx.search(command):
            return why
    if _REDIRECT.search(_QUOTED.sub("''", command)):
        return "it writes its output to a file"
    for seg in _SEGMENT.findall(_QUOTED.sub("''", command)):
        words = seg.split()
        for i, word in enumerate(words):
            base = word.rsplit("/", 1)[-1]
            if base in ("esxcli", "localcli"):
                named = []
                for x in words[i + 1:]:
                    if x.startswith("-"):
                        break
                    named.append(x)
                if not named or named[-1] not in ("get", "list", "ping"):
                    return "only esxcli 'get' and 'list' commands are read-only"
            if base == "kubectl" or word == "{K}":
                verbs = [x for x in words[i + 1:] if x in _KUBE_READ or x in _KUBE_WRITE or
                         x in ("rollout", "config", "auth")]
                if not verbs:
                    return "the kubectl action could not be recognised"
                verb, rest = verbs[0], words[words.index(verbs[0]) + 1:]
                if verb in _KUBE_WRITE:
                    return "kubectl %s changes the cluster or opens a session" % verb
                sub = next((x for x in rest if not x.startswith("-")), "")
                if (verb == "rollout" and sub not in ("status", "history")) or \
                        (verb == "config" and sub not in ("view", "current-context", "get-contexts")) or \
                        (verb == "auth" and sub not in ("can-i", "whoami")):
                    return "kubectl %s %s is not read-only" % (verb, sub)
    return None


class Decoder:
    """Translates placeholders back to real names with the private mapping."""

    def __init__(self, mapping):
        self.rev = {}
        for cat, vals in mapping.maps.items():
            if cat in ("ipv4net", "file"):
                continue
            for real, ph in vals.items():
                self.rev.setdefault(ph.lower(), real)
        self.rx = re.compile(r"(?i)(?<![\w-])(?:%s)(?![\w-])" % "|".join(
            re.escape(k) for k in sorted(self.rev, key=len, reverse=True))) if self.rev else None

    def __call__(self, text):
        return self.rx.sub(lambda m: self.rev[m.group(0).lower()], text) if self.rx else text


def _clamp(value, default, lo, hi):
    try:
        return min(hi, max(lo, int(value)))
    except (TypeError, ValueError):
        return default


def prepare_plan(args, text, require_mapping=True):
    """Translate an analyst reply and sort its steps into: read-only diagnostics the tool
    may run, and everything else, which is only shown for the person to apply by hand."""
    inv = find_inventory(args)
    if not inv:
        die("no inventory file found - the reply refers to hosts in your inventory")
    settings, sections, _ = load_inventory(inv)
    plain = not anonymize_enabled(args, settings)
    # Even with anonymization off, a mapping from earlier anonymized reports is used when it
    # exists, so that a reply written against those placeholders still finds its hosts.
    mapping = Mapping(os.path.join(args.private_dir, "mapping.json"))
    dec = Decoder(mapping)
    if require_mapping and not plain and not dec.rev:
        die("no mapping found in %s - run a collection first" % args.private_dir)
    known, by_addr = {}, {}
    for s in sections:
        for addr in s["hosts"]:
            if plain:
                by_addr[(s["name"], addr)] = addr
                keys = [addr.lower()] + ([] if is_ip(addr) else [addr.lower().split(".")[0]])
                old = mapping.lookup("target", addr) or (None if is_ip(addr) else
                                                         mapping.lookup("host", addr.split(".")[0]))
                for k in keys + ([old.lower()] if old else []):
                    known.setdefault(k, (s, addr, addr))
                continue
            ph = mapping.lookup("target", addr) or (None if is_ip(addr) else mapping.lookup("host", addr.split(".")[0]))
            by_addr[(s["name"], addr)] = ph or "not in a report yet"
            if ph:
                known.setdefault(ph.lower(), (s, addr, ph))
    parsed = parse_plan(text)
    out = {"title": parsed["title"], "translated": dec(text), "collect": [], "manual": [], "problems": [],
           "settings": settings, "sections": sections, "plan": []}
    per_host = {}
    for n, st in enumerate(parsed["steps"], 1):
        label = st["label"] or "Step %d" % n
        if not st["run"].strip():
            out["problems"].append("Step %d (%s) has no run: line and was ignored." % (n, label))
            continue
        resolved, unknown = [], []
        for tok in st["targets"]:
            if tok.startswith("@"):
                sec = next((s for s in sections if s["name"].lower() == tok[1:].lower()), None)
                if sec:
                    resolved += [(sec, a, by_addr[(sec["name"], a)]) for a in sec["hosts"]]
                else:
                    unknown.append(tok)
            elif tok.lower() in known or (not is_ip(tok) and tok.lower().split(".")[0] in known):
                resolved.append(known.get(tok.lower()) or known[tok.lower().split(".")[0]])
            else:
                unknown.append(tok)
        resolved = list({(s["name"], a): (s, a, ph) for s, a, ph in resolved}.values())
        if unknown:
            out["problems"].append("Step %d (%s): %s is not a host or group in your inventory."
                                   % (n, label, ", ".join(unknown)))
        entry = {"kind": st["kind"], "label": dec(label), "note": dec(st["note"]), "command": dec(st["run"]),
                 "reason": "", "targets": [{"section": s["name"], "address": a, "placeholder": ph}
                                           for s, a, ph in resolved]}
        if st["kind"] == "fix":
            out["manual"].append(entry)
            continue
        if not resolved:
            continue
        if re.search(r"(?:^|[|;&(`]\s*|\$\(\s*)kubectl\s", st["run"]) and \
                any(s["type"] in K8S_TYPES for s, a, ph in resolved):
            st["run"] = re.sub(r"(^|[|;&(`]\s*|\$\(\s*)kubectl(?=\s)", r"\1{K}", st["run"])
            entry["command"] = dec(st["run"])
        modes = {}
        for s, a, ph in resolved:
            mode = st["mode"].lower() if st["mode"].lower() in ("sh", "nsxcli", "kubectl") else (
                "kubectl" if "{K}" in st["run"] else
                "nsxcli" if COMPONENTS[s["type"]].get("nsxcli") and re.match(r"\s*get\s", st["run"]) else "sh")
            modes[(s["name"], a)] = mode
        reason = next((r for r in (readonly_problem(st["run"], m) for m in set(modes.values())) if r), None)
        if reason:
            entry.update(kind="blocked", reason=reason)
            out["manual"].append(entry)
            continue
        out["collect"].append(entry)
        for s, a, ph in resolved:
            per_host.setdefault(s["name"], {}).setdefault(a, []).append(
                cmd(label, entry["command"], timeout=_clamp(st["timeout"], 60, 5, 900), mode=modes[(s["name"], a)],
                    max_lines=_clamp(st["lines"], 400, 20, 5000), sudo=s.get("sudo") != "no"))
    for s in sections:
        if s["name"] in per_host:
            out["plan"].append({"sec": s, "hosts": list(per_host[s["name"]]), "groups": [],
                                "host_groups": {a: [FOLLOWUP_GROUP + (cs,)] for a, cs in per_host[s["name"]].items()}})
    return out


def plan_public(prep):
    """The part of a prepared plan that is shown to the person (contains real names)."""
    logins = [{"name": i["sec"]["name"], "title": COMPONENTS[i["sec"]["type"]]["title"], "user": i["sec"]["user"],
               "escalate": i["sec"]["escalate"]} for i in prep["plan"]]
    return {"title": prep["title"], "translated": prep["translated"], "collect": prep["collect"],
            "manual": prep["manual"], "problems": prep["problems"], "logins": logins}


def cmd_plan(args):
    with open(args.plan, encoding="utf-8", errors="replace") as fh:
        prep = prepare_plan(args, fh.read())

    def show(e):
        print("  - %s" % e["label"])
        print("      on:  %s" % (", ".join("%s (%s)" % (t["address"], t["placeholder"]) for t in e["targets"]) or "?"))
        for i, ln in enumerate(e["command"].split("\n")):
            print("      %s %s" % ("run:" if i == 0 else "    ", ln))
        if e["note"]:
            print("      note: %s" % e["note"])
        if e["reason"]:
            print("      NOT RUN by this tool: %s" % e["reason"])

    if prep["title"]:
        print("Plan: %s" % prep["title"])
    for p in prep["problems"]:
        print("warning: %s" % p)
    if prep["manual"]:
        print("\nTo apply by hand (this tool never runs these):")
        for e in prep["manual"]:
            show(e)
    if not prep["collect"]:
        print("\nNo read-only diagnostics to run." if prep["manual"] else "\nNo plan steps were found in that file.")
        return 0
    print("\nRead-only diagnostics requested:")
    for e in prep["collect"]:
        show(e)
    if not ask_yes("\nRun these %d read-only diagnostic(s) now?" % len(prep["collect"]), default=False):
        return 0
    if args.parallel is None:
        args.parallel = int(prep["settings"].get("parallel", 4))
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: sys.exit(143))
    try:
        res = collect_and_report(args, prep["settings"], prep["sections"], prep["plan"], ConsoleUI(),
                                 kind="followup", title=prep["title"])
    except KeyboardInterrupt:
        print("\nInterrupted - connections closed. No report written.")
        return 130
    print_result(args, res)
    return 0


# ----------------------------------------------------------------------------
# AI-driven investigation: an OpenAI-compatible chat endpoint reads the reports,
# asks for read-only diagnostics (approved by the admin round by round) and ends
# with a root cause and fix steps. Fix steps are only shown, never run.
# ----------------------------------------------------------------------------
class AiError(Exception):
    pass


THINK_RX = re.compile(r"<think(?:ing)?>.*?</think(?:ing)?>\s*", re.S | re.I)


def strip_think(text):
    """Remove the reasoning section some models put in their reply."""
    return THINK_RX.sub("", text or "").strip()


_MAC_TRUST = {}


def mac_trusted_pem():
    """Certificates this Mac trusts (system roots, System and login keychains), as PEM text.
    Python does not use the macOS trust store by itself, so certificates an organisation
    installed (for example DoD roots) would otherwise be unknown to it."""
    if "pem" in _MAC_TRUST:
        return _MAC_TRUST["pem"]
    pem = ""
    if sys.platform == "darwin" and shutil.which("security"):
        for args in (["/System/Library/Keychains/SystemRootCertificates.keychain"],
                     ["/Library/Keychains/System.keychain"], []):
            try:
                p = subprocess.run(["security", "find-certificate", "-a", "-p"] + args, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
                pem += p.stdout.decode("ascii", "ignore")
            except (OSError, subprocess.SubprocessError):
                pass
    _MAC_TRUST["pem"] = pem
    return pem


def tls_context(verify=True, ca_file=None):
    """TLS settings shared by the AI, vCenter and NSX clients."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    pem = mac_trusted_pem()
    if pem:
        try:
            ctx.load_verify_locations(cadata=pem)
        except (ssl.SSLError, ValueError):
            pass
    if ca_file:
        try:
            ctx.load_verify_locations(cafile=ca_file)
        except (OSError, ssl.SSLError) as e:
            raise AiError("cannot use the CA file %s: %s" % (ca_file, e))
    return ctx


CLIENT_CERT_MSG = ("the server at %s asks for a client certificate during the connection (for example a CAC / DoD "
                   "PKI certificate). An API key alone is not accepted there. Ask the service's administrators "
                   "whether API access works with a key only (and at which address), or whether it needs a "
                   "certificate-based login")


def client_cert_required(err):
    text = str(err).upper()
    return any(k in text for k in ("CERTIFICATE_REQUIRED", "ALERT_HANDSHAKE_FAILURE", "PEER DID NOT RETURN A CERTIFICATE",
                                   "BAD_CERTIFICATE", "CERTIFICATE_UNKNOWN"))


AI_PROVIDERS = {
    "openai": "OpenAI-compatible endpoint (most AI gateways, vLLM, Ollama, LM Studio)",
    "asksage": "Ask Sage (including CAPRA and other government Ask Sage servers)",
    "azure": "Azure OpenAI",
}


def normalize_ai_url(base_url, provider="openai"):
    """Turn what a person types (a host name, a URL with or without a path) into the API base URL."""
    u = (base_url or "").strip().rstrip("/")
    if not u:
        return ""
    if "://" not in u:
        u = "https://" + u
    parts = urllib.parse.urlsplit(u)
    host = parts.hostname or ""
    if parts.scheme not in ("http", "https") or not host or host in ("http", "https") or \
            not re.fullmatch(r"[A-Za-z0-9._-]+|[0-9A-Fa-f:.]+", host):
        raise AiError("'%s' is not a valid endpoint address. Enter a host name such as ai.example.mil, "
                      "or a URL such as https://ai.example.mil/v1" % base_url)
    path = parts.path.rstrip("/")
    for suffix in ("/chat/completions", "/models"):
        if path.endswith(suffix):
            path = path[:-len(suffix)]
    if provider == "asksage" and path in ("", "/server", "/server/openai"):
        path = "/server/openai/v1"
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


class AiClient:
    """Minimal chat client (stdlib only) for OpenAI-compatible endpoints, Azure OpenAI and
    Ask Sage. For Ask Sage the OpenAI-compatible API is tried first and the native Ask Sage
    API is used when that is not offered. The API key is held in memory only."""

    def __init__(self, base_url, model, key, auth_header="bearer", verify=True, ca_file=None,
                 timeout=600, max_tokens=None, use_proxy=True, provider="openai", proxy=""):
        self.provider = provider if provider in AI_PROVIDERS else "openai"
        self.base = normalize_ai_url(base_url, self.provider)
        if not self.base:
            raise AiError("enter the AI endpoint address on the Settings tab")
        self.url = self.base + "/chat/completions"
        parts = urllib.parse.urlsplit(self.base)
        self.native = "%s://%s/server" % (parts.scheme, parts.netloc)     # Ask Sage native API
        self.flavor = "native" if (self.provider == "asksage" and not parts.path.endswith("/v1")) else "openai"
        # Ask Sage serves its web page on chat.<domain> and its API on api.<domain>: when only the
        # server name was given, the api. variant is tried too.
        self.roots = [(self.base, self.native)]
        host = parts.hostname or ""
        if self.provider == "asksage" and parts.path == "/server/openai/v1" and not host.startswith("api."):
            alt = "api." + (host[5:] if host.startswith("chat.") else host)
            netloc = alt + (":%d" % parts.port if parts.port else "")
            self.roots.append(("%s://%s/server/openai/v1" % (parts.scheme, netloc), "%s://%s/server" % (parts.scheme, netloc)))
        if self.provider == "openai" and parts.path == "" and not parts.query:
            # Only a server name was given: almost every OpenAI-compatible service lives under /v1.
            self.roots = [(self.base + "/v1", self.native), (self.base, self.native)]
            self._use_root(0)
        self.root_i = 0
        self.model, self.key = model, clean_key(key)
        self.auth = "api-key" if self.provider == "azure" else (auth_header or "bearer").lower()
        # With the default header, other common key headers are tried once if the key is refused.
        self.auth_auto = self.provider == "openai" and self.auth == "bearer"
        self.auth_tried = [self.auth]
        self.first_refusal = None
        self.refusals = []
        self.locked = False
        self.timeout, self.max_tokens = timeout, max_tokens
        tls = [urllib.request.HTTPSHandler(context=tls_context(verify, ca_file))] if self.base.startswith("https:") else []
        self.direct = urllib.request.build_opener(urllib.request.ProxyHandler({}), *tls)
        proxy = (proxy or "").strip()
        if proxy and "://" not in proxy:
            proxy = "http://" + proxy
        self.proxy = proxy
        if proxy:          # a proxy named in the settings, e.g. the one a PAC file picks for this server
            self.opener = urllib.request.build_opener(_AlwaysProxy({"http": proxy, "https": proxy}), *tls)
        else:
            self.opener = urllib.request.build_opener(*tls) if use_proxy else self.direct
        self.note = ""          # set when the tool had to go around the proxy

    # ---- transport ---------------------------------------------------------
    def _headers(self, native=False):
        h = {"Content-Type": "application/json", "Accept": "application/json",
             # some gateways refuse the default "Python-urllib" client name
             "User-Agent": "vcf_diag/%s" % VERSION}
        if self.key:
            if native:
                h["x-access-tokens"] = self.key
            elif self.auth == "api-key":
                h["api-key"] = self.key
            elif self.auth == "x-api-key":
                h["x-api-key"] = self.key
            elif self.auth == "token":
                h["Authorization"] = "Token " + self.key
            else:
                h["Authorization"] = "Bearer " + self.key
        return h

    def _request(self, method, url, body=None, native=False, retries=0, timeout=None):
        if self.locked:
            raise AiError("this API key was reported as locked; unlock it in the service's web portal, then restart "
                          "the test")
        data = json.dumps(body).encode("utf-8") if body is not None else None
        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(url, data=data, method=method, headers=self._headers(native))
            except ValueError:
                raise AiError("'%s' is not a valid endpoint address" % url)
            try:
                with self.opener.open(req, timeout=timeout or self.timeout) as r:
                    text = r.read().decode("utf-8", "replace")
                try:
                    return json.loads(text)
                except ValueError:
                    raise AiError("the endpoint at %s did not answer with JSON (is the address right?): %s"
                                  % (url, text[:200]))
            except urllib.error.HTTPError as e:
                detail = e.read().decode("utf-8", "replace")[:500]
                if e.code in (407, 502, 503, 504) and self._proxy_applies(url) and \
                        self._go_direct("the proxy answered HTTP %d" % e.code):
                    return self._request(method, url, body, native, retries, timeout)
                if e.code in (429, 500, 502, 503, 504) and attempt < retries:
                    time.sleep(5 * (attempt + 1))
                    continue
                if e.code in (401, 403):
                    if self.first_refusal is None:
                        self.first_refusal = (self.auth, detail)
                    self.refusals.append(detail)
                    lock = re.search(r"(?i)\block(ed|out)\b|too many (failed|attempts)|disabled|suspended", detail)
                    if lock:
                        self.locked = True
                        m = re.search(r'https?://[^\s"\'<>]+', detail)
                        raise AiError("the AI service has LOCKED this API key (%s). The tool will not send it again "
                                      "in this session. %s" % (
                                          re.sub(r"\s+", " ", _json_message(detail))[:200],
                                          ("Unlock it here, in your browser: " + m.group(0)) if m else
                                          "Unlock or regenerate it in the service's web portal."))
                    names_bearer = re.search(r"(?i)authorization:?\s*bearer", detail)
                    # Other headers are tried only when the server says the key header was missing or not
                    # recognised; never after "invalid", "expired" or "locked", so failed attempts do not pile up.
                    header_missing = re.search(r"(?i)missing|no (api )?key|not provided|required|unrecognized|"
                                               r"unsupported (auth|scheme)", detail)
                    if not native and self.key and self.auth_auto and header_missing and not names_bearer \
                            and self._next_auth():
                        return self._request(method, url, body, native, retries, timeout)
                    if names_bearer and self.auth != "bearer":
                        # the server asks for Bearer: report what it said to the Bearer attempt
                        detail = self.first_refusal[1] if self.first_refusal[0] == "bearer" else detail
                        self.auth = "bearer"
                    why = re.sub(r"\s+", " ", detail).strip()[:300]
                    m = re.search(r"Bearer\s+([A-Za-z]{2,10}_)", " ".join(self.refusals))
                    prefix = ""
                    if m and not self.key.startswith(m.group(1)):
                        prefix = (" The server expects keys that start with '%s', but this key %s - check that you "
                                  "pasted the key for this service." % (m.group(1), key_shape(self.key)))
                    tried = (" Tried the key as: %s." % ", ".join(self.auth_tried)) if len(self.auth_tried) > 1 else ""
                    raise AiError("the AI endpoint rejected the API key (HTTP %d).%s%s%s Check that the key is "
                                  "current and was created for API use on this service" % (
                                      e.code, tried, (" The server said: " + why + ".") if why else "", prefix))
                if e.code in (404, 405):
                    raise _NotHere(url, e.code)
                if e.code == 400 and re.search(r"(?i)context|too long|maximum|token limit", detail):
                    raise AiError("the AI rejected the request as too long (HTTP 400). Lower the report and "
                                  "conversation sizes under More AI options. Detail: %s" % detail)
                if e.code == 400 and re.search(r"(?i)model", detail):
                    raise AiError("the AI does not accept the model name '%s' (HTTP 400). Use Find models to "
                                  "pick one. Detail: %s" % (self.model, detail))
                raise AiError("the AI endpoint returned HTTP %d: %s" % (e.code, detail))
            except urllib.error.URLError as e:
                if "tunnel connection failed" in str(e.reason).lower() and self._go_direct(str(e.reason)):
                    return self._request(method, url, body, native, retries, timeout)
                if isinstance(e.reason, ssl.SSLCertVerificationError):
                    raise AiError("the AI server's certificate is not trusted (%s). Give its CA file under More "
                                  "AI options, or turn off the certificate check" % e.reason.verify_message)
                if client_cert_required(e.reason):
                    raise AiError(CLIENT_CERT_MSG % url)
                if "WRONG_VERSION_NUMBER" in str(e.reason):
                    raise AiError("the server at %s does not speak HTTPS on that port; if it really is plain HTTP, "
                                  "write http:// in front of the address" % url)
                if attempt < retries:
                    time.sleep(5 * (attempt + 1))
                    continue
                if self.note:
                    raise AiError("cannot reach the AI endpoint at %s. This Mac's proxy refused it (%s), and a direct "
                                  "connection failed too (%s). Check that this Mac can reach the AI server (network, "
                                  "VPN), or ask for the proxy to allow it" % (url, self.proxy_why, e.reason))
                if isinstance(e.reason, socket.gaierror):
                    raise AiError("this computer cannot look up the server name in %s (%s). Check the spelling; if your "
                                  "browser opens it, it probably goes through a proxy: enter that proxy under More AI "
                                  "options, Proxy to use. Check connection step by step shows more" % (url, e.reason))
                if isinstance(e.reason, ConnectionResetError):
                    raise AiError("the AI server at %s ended the connection (%s). A server that requires a client "
                                  "certificate (CAC / PKI) can end connections this way; Check connection step by "
                                  "step tells whether it asks for one" % (url, e.reason))
                raise AiError("cannot reach the AI endpoint at %s: %s" % (url, e.reason))
            except (OSError, ValueError) as e:
                if client_cert_required(e):
                    raise AiError(CLIENT_CERT_MSG % url)
                raise AiError("bad answer from the AI endpoint: %s" % e)

    def _next_auth(self):
        for style in ("x-api-key", "api-key", "token"):
            if style not in self.auth_tried:
                self.auth_tried.append(style)
                self.auth = style
                base_note = re.sub(r"(; )?the key was accepted in the \S+ header", "", self.note)
                self.note = (base_note + "; " if base_note else "") + "the key was accepted in the %s header" % style
                return True
        self.auth = self.auth_tried[0]
        self.note = re.sub(r"(; )?the key was accepted in the \S+ header", "", self.note)
        return False

    def _proxy_applies(self, url):
        if self.opener is self.direct:
            return False
        if self.proxy:
            return True
        parts = urllib.parse.urlsplit(url)
        return bool(urllib.request.getproxies().get(parts.scheme)) and not urllib.request.proxy_bypass(parts.hostname or "")

    def _go_direct(self, why):
        """The Mac's proxy cannot (or may not) reach this server: use a direct connection from now on."""
        if self.opener is self.direct:
            return False
        self.opener = self.direct
        self.proxy_why = why
        self.note = "the proxy refused (%s), so the tool connected directly" % why
        return True

    # ---- chat --------------------------------------------------------------
    def _use_root(self, i):
        self.root_i = i
        self.base, self.native = self.roots[i]
        self.url = self.base + "/chat/completions"

    def _each_root(self, attempt):
        """Run attempt() on the current API address, then on the alternatives (Ask Sage api. host).
        The first address that answers is kept for the rest of the session."""
        tried = []
        for i in range(self.root_i, len(self.roots)):
            self._use_root(i)
            try:
                return attempt(tried)
            except _NotHere as e:
                tried.append("%s (HTTP %d)" % (e.url, e.code))
            except AiError as e:
                if self.locked or i == len(self.roots) - 1 or not re.search(r"cannot look up|cannot reach", str(e)):
                    if tried and i > 0:
                        raise AiError("%s. Also tried: %s" % (e, ", ".join(tried)))
                    raise
                tried.append("%s (%s)" % (self.base, "name not found" if "look up" in str(e) else "no connection"))
        self._use_root(0)
        raise _Exhausted(tried)

    def chat(self, messages, retries=2):
        if self.provider != "asksage":
            try:
                return self._each_root(lambda tried: self._chat_openai(messages, retries))
            except _Exhausted as e:
                raise AiError("the AI endpoint was not found at %s - check the address; it usually ends in /v1 or "
                              "/v1/chat/completions" % " or ".join(e.tried))

        def attempt(tried):
            if self.flavor == "openai":
                try:
                    return self._chat_openai(messages, retries)
                except _NotHere as e:
                    tried.append("%s (HTTP %d)" % (e.url, e.code))
                    self.flavor = "native"
            try:
                return self._chat_native(messages, retries)
            except _NotHere:
                self.flavor = "openai"       # try both kinds again on the next address
                raise
        try:
            return self._each_root(attempt)
        except _Exhausted as e:
            raise AiError("no Ask Sage API answered. Tried: %s. Ask your Ask Sage administrators for the API address "
                          "(it often starts with api.) and enter it as https://<api address>/server/openai/v1"
                          % ", ".join(e.tried))

    def _chat_openai(self, messages, retries):
        body = {"model": self.model, "messages": messages}
        if self.max_tokens:
            body["max_tokens"] = self.max_tokens
        reply = self._request("POST", self.url, body, retries=retries)
        try:
            choice = reply["choices"][0]
            content = choice["message"].get("content") or ""
        except (KeyError, IndexError, TypeError, AttributeError):
            raise AiError("unexpected answer from the AI endpoint: %s" % json.dumps(reply)[:300])
        if isinstance(content, list):          # some gateways return content parts
            content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
        if choice.get("finish_reason") == "length":
            content += "\n\n[The AI's reply was cut off at its output limit.]"
        return strip_think(content)

    def _chat_native(self, messages, retries):
        """Ask Sage /server/query: the conversation is sent as one message text."""
        system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        turns = []
        for m in messages:
            if m["role"] != "system":
                turns.append("%s:\n%s" % ("ADMINISTRATOR AND COLLECTOR" if m["role"] == "user" else "YOU (EARLIER REPLY)",
                                          m["content"]))
        text = (system + "\n\n" if system else "") + "CONVERSATION SO FAR:\n\n" + "\n\n".join(turns) + \
            "\n\nWrite your next reply now."
        body = {"message": text, "model": self.model, "temperature": 0}
        reply = self._request("POST", self.native + "/query", body, native=True, retries=retries)
        for k in ("message", "answer", "text", "response"):
            v = reply.get(k) if isinstance(reply, dict) else None
            if isinstance(v, str) and v.strip() and v.strip().upper() != "OK":
                return strip_think(v)
        raise AiError("unexpected answer from Ask Sage: %s" % json.dumps(reply)[:300])

    # ---- models ------------------------------------------------------------
    def list_models(self):
        """Model names the endpoint offers (OpenAI /models, or Ask Sage /server/get-models)."""
        if self.provider != "asksage":
            if len(self.roots) == 1:
                return self._list_models_here()

            def attempt_plain(tried):
                return self._list_models_here(strict=True)
            try:
                return self._each_root(attempt_plain)
            except _Exhausted as e:
                raise AiError("no model list at %s - check the address, or type the model name" % " or ".join(e.tried))

        def attempt(tried):
            try:
                return self._list_models_here(strict=True)
            except _NotHere:
                raise
        try:
            return self._each_root(attempt)
        except _Exhausted as e:
            raise AiError("no Ask Sage API answered. Tried: %s. Ask your Ask Sage administrators for the API address "
                          "(it often starts with api.), or type the model name" % ", ".join(e.tried))

    def _list_models_here(self, strict=False):
        names, errors, missing = [], [], None
        if self.flavor == "openai" or self.provider != "asksage":
            try:
                r = self._request("GET", self.base + "/models", timeout=60)
                data = r.get("data") if isinstance(r, dict) else r
                names = [m.get("id") if isinstance(m, dict) else m for m in (data or [])]
            except _NotHere as e:
                errors.append(str(e))
                missing = e
                if strict and self.provider != "asksage":
                    raise
            except AiError as e:
                errors.append(str(e))
        if not names and self.provider == "asksage":
            try:
                r = self._request("POST", self.native + "/get-models", {}, native=True, timeout=60)
                data = r.get("response") or r.get("models") or r.get("data") if isinstance(r, dict) else r
                if isinstance(data, dict):
                    data = data.get("models") or data.get("data") or list(data)
                names = [m.get("id") or m.get("name") if isinstance(m, dict) else m for m in (data or [])]
            except _NotHere as e:
                errors.append(str(e))
                if strict and missing is not None:
                    raise e                     # neither kind of API exists at this address
            except AiError as e:
                errors.append(str(e))
                if strict and re.search(r"cannot look up|cannot reach", str(e)):
                    raise
        names = sorted({str(n) for n in names if n})
        if not names:
            raise AiError("the endpoint did not return a model list" + (": " + errors[-1] if errors else "") +
                          ". Type the model name your AI provider gives you")
        return names


def _json_message(text):
    try:
        d = json.loads(text)
        e = d.get("error") if isinstance(d, dict) else None
        return (e.get("message") if isinstance(e, dict) else None) or d.get("message") or text
    except (ValueError, AttributeError):
        return text


class _Exhausted(Exception):
    def __init__(self, tried):
        Exception.__init__(self, ", ".join(tried))
        self.tried = tried


class _AlwaysProxy(urllib.request.ProxyHandler):
    """A proxy the person named explicitly: used for every request, ignoring the system's and
    NO_PROXY's exception lists (which would otherwise silently bypass it)."""

    def proxy_open(self, req, proxy, type):
        orig_type = req.type
        proxy_type, user, password, hostport = urllib.request._parse_proxy(proxy)
        if proxy_type is None:
            proxy_type = orig_type
        if user and password:
            creds = base64.b64encode(("%s:%s" % (urllib.parse.unquote(user),
                                                 urllib.parse.unquote(password))).encode()).decode("ascii")
            req.add_header("Proxy-authorization", "Basic " + creds)
        req.set_proxy(urllib.parse.unquote(hostport), proxy_type)
        if orig_type == proxy_type or orig_type == "https":
            return None
        return self.parent.open(req, timeout=req.timeout)


class _NotHere(Exception):
    def __init__(self, url, code):
        Exception.__init__(self, "HTTP %d at %s" % (code, url))
        self.url, self.code = url, code


AI_PRESETS = {
    "genai": {"title": "GenAI.mil", "provider": "openai", "base_url": "https://api.genai.mil/v1/chat/completions",
              "model": "gemini-3.5-flash-lite-withtools", "auth_header": "bearer",
              "key_hint": "the API key from the GenAI.mil portal (starts with STARK_)"},
    "capra": {"title": "CAPRA (Ask Sage)", "provider": "asksage", "base_url": "chat.capra.flankspeed.us.navy.mil",
              "model": "", "auth_header": "bearer",
              "key_hint": "the API key you created in CAPRA / Ask Sage (Settings, Account, API)"},
}


def ai_profile(ai):
    """Which AI service the settings use: a preset ("genai", "capra") or "custom"."""
    p = (ai.get("profile") or "").strip().lower()
    if p in AI_PRESETS or p == "custom":
        return p
    url = (ai.get("base_url") or "").strip()
    if not url:
        return "genai"                       # a fresh installation starts with GenAI.mil
    for name, pre in AI_PRESETS.items():
        try:
            if normalize_ai_url(url, pre["provider"]).lower() == normalize_ai_url(pre["base_url"], pre["provider"]).lower():
                return name
        except AiError:
            pass
    return "custom"


def ai_settings(settings):
    ai = settings.get("_ai") or {}
    profile = ai_profile(ai)
    pre = AI_PRESETS.get(profile)
    if pre:
        model = (ai.get(profile + "_model") or "").strip() or (
            (ai.get("model") or "").strip() if not (ai.get("profile") or "").strip() else "") or pre["model"]
    return {
        "profile": profile,
        "base_url": pre["base_url"] if pre else (ai.get("base_url") or "").strip(),
        "model": model if pre else (ai.get("model") or "").strip(),
        "auth_header": pre["auth_header"] if pre else (ai.get("auth_header") or "bearer").strip(),
        "provider": pre["provider"] if pre else (ai.get("provider") or "openai").strip().lower(),
        "proxy": (ai.get("proxy") or "").strip(),
        "tls_verify": (ai.get("tls_verify") or "yes").strip().lower() not in ("no", "false", "0", "off"),
        "ca_file": os.path.expanduser((ai.get("ca_file") or "").strip()) or None,
        "use_proxy": (ai.get("use_proxy") or "yes").strip().lower() not in ("no", "false", "0", "off"),
        "max_rounds": _clamp(ai.get("max_rounds"), 10, 1, 50),
        "max_tokens": _clamp(ai.get("max_tokens"), 0, 0, 1000000) or None,
        "timeout": _clamp(ai.get("timeout"), 600, 30, 3600),
        "max_report_chars": _clamp(ai.get("max_report_chars"), 150000, 5000, 5000000),
        "max_context_chars": _clamp(ai.get("max_context_chars"), 400000, 20000, 20000000),
        "key_env": (ai.get("key_env") or "VCF_DIAG_AI_KEY").strip(),
    }


KEYCHAIN_SERVICE = "vcf_diag AI key"


def keychain_available():
    return (sys.platform == "darwin" or bool(os.environ.get("VCFDIAG_FAKE_KEYCHAIN"))) and bool(shutil.which("security"))


def keychain_get(account):
    if not keychain_available() or not account:
        return ""
    try:
        p = subprocess.run(["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account, "-w"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return ""
    return p.stdout.decode("utf-8", "replace").rstrip("\n") if p.returncode == 0 else ""


def keychain_set(account, key):
    if not keychain_available():
        raise Fatal("the macOS Keychain is not available on this computer")
    p = subprocess.run(["security", "add-generic-password", "-U", "-s", KEYCHAIN_SERVICE, "-a", account, "-w", key],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=15)
    if p.returncode != 0:
        raise Fatal("the Keychain refused to save the key: %s" % p.stderr.decode("utf-8", "replace").strip())


def keychain_delete(account):
    if keychain_available() and account:
        subprocess.run(["security", "delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)


def endpoint_id(cfg):
    """One name per AI endpoint, so that a key entered for one service is never sent to another."""
    try:
        return normalize_ai_url(cfg.get("base_url", ""), cfg.get("provider", "openai")).lower()
    except AiError:
        return (cfg.get("base_url") or "").strip().lower()


def resolve_ai_key(cfg, typed="", session=None):
    """Typed key, then the key entered earlier in this window for this endpoint, then the environment,
    then the Keychain entry for this endpoint."""
    return key_with_source(cfg, typed, session)[0]


def key_with_source(cfg, typed="", session=None):
    if typed:
        return typed, "typed in the key field"
    if isinstance(session, dict) and session.get(endpoint_id(cfg)):
        return session[endpoint_id(cfg)], "set for this session"
    if isinstance(session, str) and session:
        return session, "set for this session"
    if os.environ.get(cfg["key_env"]):
        return os.environ[cfg["key_env"]], "environment variable %s" % cfg["key_env"]
    k = keychain_get(cfg["base_url"])
    return (k, "macOS Keychain") if k else ("", "none")


def clean_key(key):
    """Remove what often sneaks into a pasted key: spaces, line breaks, quotes, a leading 'Bearer '."""
    k = (key or "").strip().strip("'\"").strip()
    k = re.sub(r"(?i)^bearer\s+", "", k)
    return re.sub(r"\s+", "", k)


def key_shape(key):
    """A description of a key that does not reveal it."""
    if not key:
        return "no key"
    m = re.match(r"([A-Za-z]{2,10}[_-])", key)
    return "starts with '%s', %d characters" % (m.group(1), len(key)) if m else "%d characters" % len(key)


def mac_pac_url():
    """The automatic proxy configuration (PAC) URL of this Mac, if one is set."""
    if sys.platform != "darwin" or not shutil.which("scutil"):
        return ""
    try:
        out = subprocess.run(["scutil", "--proxy"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=10).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return ""
    if re.search(r"ProxyAutoConfigEnable\s*:\s*1", out):
        m = re.search(r"ProxyAutoConfigURLString\s*:\s*(\S+)", out)
        return m.group(1) if m else "a PAC file"
    if re.search(r"ProxyAutoDiscoveryEnable\s*:\s*1", out):
        return "automatic proxy discovery (WPAD)"
    return ""


def _mask_proxy(url):
    return re.sub(r"//[^/@]+@", "//***@", url or "")


def ai_connection_check(cfg, key, source=""):
    """Step-by-step connection check for the AI endpoint. Returns text a person can copy into a
    support message: no key is included."""
    lines = ["vcf_diag %s, Python %s, %s" % (VERSION, sys.version.split()[0], sys.platform)]

    def step(name, ok, detail):
        lines.append("[%s] %s: %s" % ("ok" if ok else "FAIL" if ok is False else "info", name, detail))

    try:
        base = normalize_ai_url(cfg["base_url"], cfg["provider"])
    except AiError as e:
        step("address", False, str(e))
        return "\n".join(lines)
    parts = urllib.parse.urlsplit(base)
    host, port = parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)
    step("settings used", None, "service=%s, address=%s, model=%s, key header=%s, use the Mac's proxy=%s, "
         "check certificate=%s, CA file=%s, key entered=%s" % (cfg["provider"], base, cfg["model"] or "(none)",
                                         "x-access-tokens / Bearer" if cfg["provider"] == "asksage" else
                                         "api-key" if cfg["provider"] == "azure" else cfg["auth_header"],
                                         "yes" if cfg["use_proxy"] else "no", "yes" if cfg["tls_verify"] else "no",
                                         cfg["ca_file"] or "(none)", "yes" if key else "no"))
    step("key", None, "%s%s" % (key_shape(clean_key(key)), (", " + source) if source else ""))
    proxies = urllib.request.getproxies()
    shown = {k: _mask_proxy(v_) for k, v_ in proxies.items() if k in ("http", "https", "all")}
    step("proxy settings Python sees", None, ", ".join("%s=%s" % kv for kv in shown.items()) or "none")
    pac = mac_pac_url()
    if pac:
        step("automatic proxy configuration (PAC)", None, "this Mac uses %s. Python cannot read PAC files, so it may "
             "use a different proxy for this server than your browser does. Ask your IT department (or look in the "
             "PAC file) which proxy serves %s, and enter it under More AI options, Proxy to use" % (pac, host))
    applies = bool(proxies.get(parts.scheme)) and not urllib.request.proxy_bypass(host)
    if cfg.get("proxy"):
        route = "through the proxy named in the settings: %s" % _mask_proxy(cfg["proxy"])
    elif cfg["use_proxy"] and applies:
        route = "through the Mac's proxy %s" % _mask_proxy(proxies.get(parts.scheme))
    else:
        route = "direct (no proxy)"
    step("route the tool will use", None, route)
    try:
        addrs = sorted({a[4][0] for a in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)})
        step("name lookup", True, "%s -> %s" % (host, ", ".join(addrs)))
    except OSError as e:
        step("name lookup", False, "%s does not resolve on this Mac (%s). Check the spelling against the address "
             "bar of your browser. If the browser can open it, the name probably only works through a proxy: "
             "enter that proxy under Proxy to use%s" % (host, e, " (see the PAC line above)" if pac else ""))
        addrs = []
    if addrs:
        try:
            sock = socket.create_connection((host, port), timeout=10)
            step("direct network connection", True, "port %d on %s answers" % (port, host))
            if parts.scheme == "https":
                asked = []
                try:
                    ctx = tls_context(cfg["tls_verify"], cfg["ca_file"])
                    try:      # watch the handshake for a request for a client certificate (debug hook)
                        ctx._msg_callback = lambda conn, direction, ver, ctype, mtype, data: asked.append(1) if (
                            direction == "read" and getattr(mtype, "name", str(mtype)) == "CERTIFICATE_REQUEST") else None
                    except (AttributeError, TypeError):
                        pass
                    with ctx.wrap_socket(sock, server_hostname=host) as tls:
                        cert = tls.getpeercert() or {}
                        # With TLS 1.3 a demand for a client certificate only shows on the first read.
                        tls.settimeout(10)
                        tls.sendall(("HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % host).encode())
                        try:
                            tls.recv(1)
                        except socket.timeout:
                            pass
                        subj = dict(x[0] for x in cert.get("subject", ())).get("commonName", "?")
                        iss = dict(x[0] for x in cert.get("issuer", ())).get("commonName", "?")
                        step("certificate", True, "trusted; issued to %s by %s" % (subj, iss) if cert
                             else "not checked (certificate check is off)")
                    if asked:
                        step("client certificate", False, CLIENT_CERT_MSG % base)
                except (ssl.SSLError, AiError, OSError) as e:
                    if client_cert_required(e) or asked:
                        step("certificate", False, CLIENT_CERT_MSG % base)
                    else:
                        step("certificate", False, "%s. Give the server's CA file under More AI options, or turn "
                             "off the certificate check" % (getattr(e, "verify_message", None) or e))
            else:
                sock.close()
        except OSError as e:
            step("direct network connection", False, "port %d on %s does not answer directly (%s)%s" % (
                port, host, e, "; only the proxy may be able to reach it" if applies else ""))
    try:
        client = make_ai_client(dict(cfg, model=cfg["model"] or "-"), key)
        client.timeout = 60
        models = client.list_models()
        step("API request (model list)", True, "%d model(s): %s%s" % (len(models), ", ".join(models[:8]),
                                                                       " (%s)" % client.note if client.note else ""))
    except AiError as e:
        step("API request (model list)", False, str(e))
        if re.search(r"rejected the API key|LOCKED", str(e)):
            step("API request (chat)", None, "skipped: the key was refused, and repeated failed attempts can lock it")
            return "\n".join(lines)
    if cfg["model"]:
        try:
            client = make_ai_client(cfg, key)
            client.timeout = 120
            reply = client.chat([{"role": "user", "content": "Reply with the single word OK."}], retries=0)
            step("API request (chat with %s)" % cfg["model"], True, "%s via %s%s" % (
                reply[:60].replace("\n", " "), client.url if client.flavor == "openai" else client.native + "/query",
                " (%s)" % client.note if client.note else ""))
        except AiError as e:
            step("API request (chat with %s)" % cfg["model"], False, str(e))
    return "\n".join(lines)


def make_ai_client(cfg, key):
    return AiClient(cfg["base_url"], cfg["model"], key, auth_header=cfg["auth_header"], verify=cfg["tls_verify"],
                    ca_file=cfg["ca_file"], timeout=cfg["timeout"], max_tokens=cfg["max_tokens"],
                    use_proxy=cfg["use_proxy"], provider=cfg["provider"], proxy=cfg.get("proxy", ""))


def investigator_prompt(max_rounds, anonymized):
    names = ("Hosts, domains and addresses are anonymized placeholders; use them exactly as written."
             if anonymized else "Hosts are named as in the inventory; use those names exactly.")
    return """You are an expert VMware Cloud Foundation 9.x troubleshooter (ESXi, vCenter, vSAN, NSX,
SDDC Manager, the VCF management services and services runtime, vSphere Supervisor, VKS and
Kubernetes). An administrator describes a problem; your job is to find its exact cause.

You cannot reach the environment yourself. A collector tool runs read-only commands for you on
the hosts in the inventory and returns their output as a report. %s

Work in rounds. In every reply, either:
1. ask for more data: explain briefly what you suspect and why, then add one vcf-plan block with
   only [collect] steps (at most 8 per round, each focused on a hypothesis), or
2. conclude: start with a line "ROOT CAUSE: <one sentence>" (or "NO ROOT CAUSE FOUND: <why>" when
   read-only data cannot settle it), give the evidence by quoting the report lines that prove it,
   then add one vcf-plan block with the [fix] steps in the order they must be applied, each with
   impact and rollback in note:, and a "Verify ..." step after each fix, or
3. ask the administrator: when you need something only a person knows or can do (a UI setting, a
   change window, a password policy), end with "QUESTION FOR THE ADMINISTRATOR: <question>".

Fix steps must be exact, complete commands or scripts for the named hosts that the administrator
can paste into a terminal, with real values filled in from the reports: service names, file paths,
object names, IDs. Never write general advice such as "check the logs", "verify the configuration"
or "restart the affected service" instead of commands. A longer fix may be a multi-line script
(indent the continuation lines under run:). Where a fix can only be done in a web UI, give the exact
menu path, and the equivalent CLI or API command when one exists. After each fix add a step that
verifies it (as a [fix] step labelled "Verify ...").

The administrator may also run your commands in a terminal and paste the output back, or tell you
what happened after applying a fix. Continue from there.

Rules:
- Base conclusions on evidence in the reports, not on assumptions. Do not conclude early when one
  more targeted check would confirm or rule out the cause; do not ask again for data you have.
- The administrator approves every round, and you have at most %d rounds before you must
  conclude. Each message from the tool says which round it is.
- A [collect] step that looks as if it changes something, or that would print secrets, is refused
  by the tool; you will be told which and why. Never put sudo in a command.
- Prefer commands that print a bounded amount of output (tail, grep, head).

Format of the plan block (the same as described in the reports):

```vcf-plan
plan: short title
[collect] target=<host or @group>
label: what this shows
run: <one read-only shell command; {K} stands for kubectl on Kubernetes hosts>
timeout: 60
lines: 400

[fix] target=<host or @group>
label: what this does
run: <command the administrator runs by hand>
note: impact, rollback
```""" % (names, max_rounds)


def report_for_ai(report, limit):
    """The part of a report the AI needs, shortened if it exceeds the limit (with a visible note)."""
    report = re.sub(r"(?s)## How to reply \(for the analyst\)\n.*?(?=\n## )", "", report)
    if len(report) <= limit:
        return report, False
    head = int(limit * 0.6)
    tail = limit - head
    return (report[:head] + "\n\n[... %d characters of this report were left out by the collector because it is "
            "longer than max_report_chars. Ask for narrower checks if you need what is missing ...]\n\n"
            % (len(report) - limit) + report[-tail:]), True


def inventory_overview(args):
    """The hosts and groups the AI may target, named as the AI will see them."""
    settings, sections, _ = load_inventory(find_inventory(args))
    plain = not anonymize_enabled(args, settings)
    mapping = Mapping(None if plain else os.path.join(args.private_dir, "mapping.json"))
    lines = ["Inventory (targets for vcf-plan steps; @<group> means every host of that group):"]
    for s in sections:
        names = []
        for addr in s["hosts"]:
            if plain:
                names.append(addr)
            else:
                ph = mapping.lookup("target", addr) or (None if is_ip(addr) else
                                                        mapping.lookup("host", addr.split(".")[0]))
                names.append(ph or "(unnamed host)")
        lines.append("- @%s  %s  (login user: %s): %s" % (
            s["name"], COMPONENTS[s["type"]]["title"], s["user"], ", ".join(names)))
        if s.get("endpoints"):
            for name, svcs in s["endpoints"].items():
                shown = name if plain else (mapping.lookup("host", name.split(".")[0]) or
                                            (mapping.lookup("ipv4", name) if is_ip(name) else None) or "(endpoint)")
                lines.append("    endpoint %s: %s" % (shown, ", ".join(svcs)))
    return "\n".join(lines)


class CachedUI:
    """Asks for each group's login once per investigation, then reuses it."""

    def __init__(self, ui):
        self.ui = ui
        self.creds, self.sso = {}, {}

    def initial_credentials(self, sec):
        if sec["name"] not in self.creds:
            self.creds[sec["name"]] = self.ui.initial_credentials(sec)
        return self.creds[sec["name"]]

    def sso_credentials(self, sec):
        if sec["name"] not in self.sso:
            self.sso[sec["name"]] = self.ui.sso_credentials(sec)
        return self.sso[sec["name"]]

    def retry_credentials(self, sec, what, message, default=True):
        new = self.ui.retry_credentials(sec, what, message, default)
        if new and what.startswith("["):
            self.creds[sec["name"]] = new
        return new


def latest_report(args):
    try:
        names = sorted(n for n in os.listdir(args.output_dir) if re.match(r"vcf-(report|followup)-.*\.md$", n))
    except OSError:
        return None
    return os.path.join(args.output_dir, names[-1]) if names else None


class Investigation:
    """The investigation loop, independent of terminal or window.
    emit(kind, text) reports progress; approve(prep) decides on each round of diagnostics;
    stopped() is checked between steps; collect runs a prepared plan."""

    def __init__(self, args, ai, cfg, problem, ui, emit, approve, stopped=lambda: False,
                 start_report=None, collect=None):
        self.args, self.ai, self.cfg = args, ai, cfg
        self.problem, self.ui, self.emit, self.approve, self.stopped = problem, ui, emit, approve, stopped
        self.start_report = start_report
        self.collect = collect or collect_and_report
        self.messages = []
        self.final = None
        self.path = None
        self.anonymized = True

    def _trim_context(self):
        """Keep the conversation under max_context_chars by shortening the oldest tool reports."""
        limit = self.cfg["max_context_chars"]
        total = sum(len(m["content"]) for m in self.messages)
        for m in self.messages[1:-1]:
            if total <= limit:
                break
            if m["role"] == "user" and m.get("_report") and not m.get("_trimmed"):
                short = m["content"][:1500] + "\n\n[... the rest of this earlier report was removed to stay " \
                    "within max_context_chars; your reply to it above summarizes what mattered ...]"
                total -= len(m["content"]) - len(short)
                m["content"], m["_trimmed"] = short, True
        if total > limit:
            self.emit("warn", "The conversation is still larger than max_context_chars after shortening "
                              "earlier reports.")

    def _ask_ai(self):
        self._trim_context()
        self.emit("status", "Waiting for the AI ...")
        reply = self.ai.chat([{"role": m["role"], "content": m["content"]} for m in self.messages])
        self.messages.append({"role": "assistant", "content": reply})
        return reply

    def run(self):
        settings, sections, _ = load_inventory(find_inventory(self.args))
        self.anonymized = anonymize_enabled(self.args, settings)
        scrubber = make_scrubber(self.args, settings)
        learn_inventory(scrubber, sections)        # so that every inventory host has its placeholder
        scrubber.m.save()
        problem = scrub_texts(self.args, [self.problem])[1][0]
        first = ["Problem reported by the administrator:", problem.strip() or "(no description given)", "",
                 inventory_overview(self.args)]
        if self.start_report:
            text, cut = report_for_ai(self.start_report, self.cfg["max_report_chars"])
            if cut:
                self.emit("warn", "The starting report was shortened to max_report_chars for the AI.")
            first += ["", "Current diagnostic report:", "", text]
        else:
            first += ["", "No report has been collected yet. Ask for the diagnostics you need."]
        first += ["", "Round 1 of %d." % self.cfg["max_rounds"]]
        self.messages = [{"role": "system", "content": investigator_prompt(self.cfg["max_rounds"], self.anonymized)},
                         {"role": "user", "content": "\n".join(first), "_report": bool(self.start_report)}]
        return self._loop()

    def continue_with(self, text, kind="message"):
        """The administrator answers: pasted command output, a question, or anything else.
        The text follows the anonymize setting like everything else sent to the AI."""
        text = scrub_texts(self.args, [text])[1][0].strip()
        head = {"output": "Output of the commands you asked for, run by the administrator in a terminal:",
                "fix-output": "The administrator applied fix steps and reports the result:"}.get(
            kind, "Message from the administrator:")
        self.messages.append({"role": "user", "content": "%s\n\n%s\n\nRound 1 of %d." % (
            head, text or "(empty)", self.cfg["max_rounds"]), "_report": kind == "output"})
        self.emit("you", text)
        return self._loop()

    def _format_problem(self, reply):
        """What is wrong with a reply that does not follow the required format, or None."""
        has_plan = bool(PLAN_FENCE.search(reply))
        if re.search(r"(?i)QUESTION FOR THE ADMINISTRATOR\s*:", reply):
            return None
        if re.search(r"(?im)^\W*NO ROOT CAUSE FOUND\s*:", reply):
            return None
        if re.search(r"(?im)^\W*ROOT CAUSE\s*:", reply):
            steps = parse_plan(reply)["steps"] if has_plan else []
            if any(st["kind"] == "fix" and st["run"].strip() for st in steps):
                return None
            return ("You gave a root cause but no fix steps. Add a vcf-plan block with [fix] steps: exact, "
                    "complete commands or scripts for the named hosts that the administrator can paste into a "
                    "terminal, with impact and rollback in note:, followed by a verification command. If no change "
                    "is needed, say so explicitly.")
        if has_plan:
            if parse_plan(reply)["steps"]:
                return None
            return "Your vcf-plan block contains no steps in the required format ([collect] or [fix] with run:)."
        return ("Your reply does not follow the required format. Reply again, either with a vcf-plan block of "
                "[collect] steps to get more data, or starting with 'ROOT CAUSE:' and a vcf-plan block of [fix] "
                "steps that are exact commands, not general advice. If you need information only the administrator "
                "has, end with 'QUESTION FOR THE ADMINISTRATOR: <question>'.")

    def _ask_ai_checked(self):
        reply = self._ask_ai()
        for _ in range(2):
            problem = self._format_problem(reply)
            if not problem:
                break
            self.emit("status", "The AI's answer did not follow the format; asking it again ...")
            self.messages.append({"role": "user", "content": problem})
            reply = self._ask_ai()
        return reply

    def _loop(self):
        max_rounds = self.cfg["max_rounds"]
        prep = None
        for rnd in range(1, max_rounds + 1):
            if self.stopped():
                return self._finish("stopped", prep)
            reply = self._ask_ai_checked()
            prep = prepare_plan(self.args, reply, require_mapping=False)
            self.emit("ai", prep["translated"])
            if not prep["collect"]:
                if prep["problems"] and not prep["manual"] and rnd < max_rounds:
                    self.messages.append({"role": "user", "content": "The tool could not use your plan: %s "
                                          "Round %d of %d." % (" ".join(prep["problems"]), rnd + 1, max_rounds)})
                    continue
                question = re.search(r"(?is)QUESTION FOR THE ADMINISTRATOR\s*:\s*(.+)$", prep["translated"])
                return self._finish("question" if question else "concluded", prep,
                                    question=question.group(1).strip() if question else "")
            if rnd == max_rounds:
                break
            if self.stopped():
                return self._finish("stopped", prep)
            decision = self.approve(prep)
            decision = {True: "run", False: "stop", None: "stop"}.get(decision, decision)
            if decision == "manual":
                return self._finish("manual", prep)       # the administrator runs them and pastes the output
            if decision != "run":
                return self._finish("declined", prep)
            self.emit("status", "Running %d read-only diagnostic(s) ..." % len(prep["collect"]))
            res = self.collect(self.args, prep["settings"], prep["sections"], prep["plan"], self.ui,
                               kind="followup", title=prep["title"])
            if res is None:
                return self._finish("stopped", prep)
            self.emit("report", res["path"])
            text, cut = report_for_ai(res["report"], self.cfg["max_report_chars"])
            if cut:
                self.emit("warn", "The round %d report was shortened to max_report_chars for the AI." % rnd)
            notes = []
            for e in prep["manual"]:
                if e["kind"] == "blocked":
                    notes.append("- Refused [collect] step '%s': %s." % (e["label"], e["reason"]))
            notes += ["- %s" % p for p in prep["problems"]]
            msg = ["Results of round %d." % rnd]
            if notes:
                msg += ["Steps the tool could not run:"] + notes
            msg += ["", text, "", "Round %d of %d.%s" % (rnd + 1, max_rounds,
                                                        " This is the last round: conclude now."
                                                        if rnd + 1 == max_rounds else "")]
            self.messages.append({"role": "user", "content": "\n".join(msg), "_report": True})
        self.messages.append({"role": "user", "content": "The round limit is reached. Conclude now with the "
                              "evidence you have, in the conclusion format."})
        reply = self._ask_ai_checked()
        prep = prepare_plan(self.args, reply, require_mapping=False)
        self.emit("ai", prep["translated"])
        return self._finish("concluded", prep)

    def _finish(self, how, prep, question=""):
        if not self.path:
            stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            os.makedirs(self.args.output_dir, exist_ok=True)
            self.path = os.path.abspath(os.path.join(self.args.output_dir, "vcf-investigation-%s.md" % stamp))
        out = ["# VCF investigation (%s)" % how, "", "- Tool: vcf_diag %s" % VERSION,
               "- AI model: %s" % self.cfg["model"], ""]
        for m in self.messages[1:]:
            out += ["## %s" % ("Collector / administrator" if m["role"] == "user" else "AI"), "", m["content"], ""]
        write_private(self.path, "\n".join(out))
        self.final = {"how": how, "path": self.path, "question": question,
                      "conclusion": prep["translated"] if prep else "",
                      "collect": prep["collect"] if prep else [],
                      "manual": prep["manual"] if prep else [], "problems": prep["problems"] if prep else []}
        return self.final


def plan_as_script(entries, title="Steps"):
    """Steps as one shell script to copy: each command with its hosts and notes as comments."""
    out = ["# %s - generated by vcf_diag %s. Run each block on the host named above it." % (title, VERSION), ""]
    for i, e in enumerate(entries, 1):
        hosts = ", ".join(t["address"] for t in e["targets"]) or "?"
        out.append("# %d. %s" % (i, e["label"]))
        out.append("#    on: %s" % hosts)
        if e.get("note"):
            out.append("#    note: %s" % e["note"])
        out.append(e["command"].rstrip())
        out.append("")
    return "\n".join(out)


def print_plan_steps(prep, include_collect=True):
    def show(e):
        print("  - %s" % e["label"])
        print("      on:  %s" % (", ".join("%s (%s)" % (t["address"], t["placeholder"]) for t in e["targets"]) or "?"))
        for i, ln in enumerate(e["command"].split("\n")):
            print("      %s %s" % ("run:" if i == 0 else "    ", ln))
        if e["note"]:
            print("      note: %s" % e["note"])
        if e["reason"]:
            print("      NOT RUN by this tool: %s" % e["reason"])

    for p in prep["problems"]:
        print("warning: %s" % p)
    if prep["manual"]:
        print("\nTo apply by hand (this tool never runs these):")
        for e in prep["manual"]:
            show(e)
    if include_collect and prep["collect"]:
        print("\nRead-only diagnostics requested:")
        for e in prep["collect"]:
            show(e)


def cmd_investigate(args):
    inv = find_inventory(args)
    if not inv:
        die("no inventory file found. Create one with:  python3 %s --init" % os.path.basename(__file__))
    settings, sections, custom = load_inventory(inv)
    cfg = ai_settings(settings)
    if not cfg["base_url"] or not cfg["model"]:
        die("add an [ai] section with base_url and model to the inventory (see inventory.example.ini)")
    if args.parallel is None:
        args.parallel = int(settings.get("parallel", 4))
    problem = args.investigate.strip()
    if not problem:
        print("Describe the problem (finish with an empty line):")
        lines = []
        while True:
            ln = input()
            if not ln.strip():
                break
            lines.append(ln)
        problem = "\n".join(lines)
    key = resolve_ai_key(cfg) or getpass.getpass("API key for %s (hidden; Return for none): "
                                                             % cfg["base_url"])
    start_text = None
    start = args.start or ("latest" if latest_report(args) else "none")
    if args.report:
        with open(args.report, encoding="utf-8", errors="replace") as fh:
            start_text = fh.read()
        print("Starting from %s" % args.report)
    elif start == "latest":
        path = latest_report(args)
        if path:
            with open(path, encoding="utf-8", errors="replace") as fh:
                start_text = fh.read()
            print("Starting from the latest report: %s" % path)
        else:
            print("No earlier report found; the AI starts from the description only.")
    elif start == "collect":
        plan = build_plan(sections, custom, args.all)
        if not plan:
            die("nothing selected", 0)
        res = collect_and_report(args, settings, sections, plan, ConsoleUI())
        print_result(args, res)
        start_text = res["report"]
    ui = CachedUI(ConsoleUI())

    def emit(kind, text):
        if kind == "ai":
            print("\n" + "=" * 78 + "\nAI\n" + "=" * 78 + "\n" + text + "\n")
        elif kind == "report":
            print("Follow-up report: %s" % text)
        elif kind == "warn":
            print("note: %s" % text)
        else:
            print(text)

    def approve(prep):
        print_plan_steps(prep, include_collect=True)
        while True:
            a = input("\n[r] run these %d read-only diagnostic(s) for me, [m] I will run them myself and paste "
                      "the output, [s] stop: " % len(prep["collect"])).strip().lower()[:1]
            if a in ("r", "m", "s"):
                return {"r": "run", "m": "manual", "s": "stop"}[a]
            print("Please answer r, m or s.")

    def read_reply():
        print("\nType or paste your reply for the AI (command output, results, questions).")
        print("Finish with a line containing only a dot (.). Press Return on an empty first line to end.")
        lines = []
        while True:
            try:
                ln = input()
            except EOFError:
                break
            if ln.strip() == "." or (not lines and not ln.strip()):
                break
            lines.append(ln)
        return "\n".join(lines).strip()

    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: sys.exit(143))
    inv = Investigation(args, make_ai_client(cfg, key), cfg, problem, ui, emit, approve, start_report=start_text)
    try:
        result = inv.run()
        while True:
            print("\n" + "=" * 78)
            print({"concluded": "The AI has concluded.", "declined": "Stopped: you declined a round.",
                   "stopped": "Investigation stopped.", "question": "The AI has a question for you:",
                   "manual": "Run these commands yourself, then paste their output below."}[result["how"]])
            if result["how"] == "question":
                print(result["question"])
            if result["how"] == "manual":
                print("\n" + plan_as_script(result["collect"], "Read-only diagnostics requested by the AI"))
            fixes = [e for e in result["manual"] if e["kind"] == "fix"]
            if fixes:
                print("\nFixes as one script (the tool never runs these):\n")
                print(plan_as_script(fixes, "Fix steps"))
            print("Transcript (as sent to the AI): %s" % result["path"])
            text = read_reply()
            if not text:
                break
            kind = "output" if result["how"] == "manual" else (
                "fix-output" if any(e["kind"] == "fix" for e in result["manual"]) else "message")
            result = inv.continue_with(text, kind)
    except AiError as e:
        die(str(e))
    except KeyboardInterrupt:
        print("\nInvestigation interrupted.")
        return 130
    return 0


# ----------------------------------------------------------------------------
# Browser GUI (python3 vcf_diag.py --gui). Served to this machine only.
# ----------------------------------------------------------------------------
GUI_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VCF Diagnostics</title>
<style>
:root {
  --bg: #f4f5f7; --panel: #ffffff; --ink: #1c2330; --muted: #5d6778; --line: #d9dee6;
  --accent: #1f6feb; --accent-ink: #ffffff; --good: #1a7f4b; --warn: #9a5b00; --bad: #b3261e;
  --good-bg: #e6f4ec; --warn-bg: #fff4e0; --bad-bg: #fdecea; --code: #f0f2f5;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14181f; --panel: #1c222c; --ink: #e6e9ef; --muted: #9aa5b5; --line: #323b49;
    --accent: #5b9bff; --accent-ink: #0b1220; --good: #5fd08f; --warn: #f0b955; --bad: #ff8a80;
    --good-bg: #173426; --warn-bg: #3a2c10; --bad-bg: #40201d; --code: #232b37;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink);
  font: 15px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }
header { background: var(--panel); border-bottom: 1px solid var(--line); }
.bar { max-width: 980px; margin: 0 auto; padding: 14px 20px 0; }
.title { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
h1 { font-size: 20px; margin: 0; }
.ver { color: var(--muted); font-size: 13px; }
.spacer { flex: 1; }
nav { display: flex; gap: 4px; margin-top: 12px; }
nav button { border: 0; background: none; color: var(--muted); font: inherit; padding: 8px 14px;
  border-bottom: 3px solid transparent; cursor: pointer; }
nav button[aria-selected="true"] { color: var(--ink); border-bottom-color: var(--accent); font-weight: 600; }
main { max-width: 980px; margin: 0 auto; padding: 20px; }
h2 { font-size: 16px; margin: 22px 0 8px; }
p { margin: 6px 0; }
.muted { color: var(--muted); }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  padding: 14px 16px; margin: 10px 0; }
.card.on { border-color: var(--accent); }
.row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.pick { display: flex; align-items: center; gap: 10px; cursor: pointer; flex: 1; min-width: 240px; }
.pick b { font-family: ui-monospace, Menlo, monospace; font-size: 14px; }
input[type=checkbox] { width: 17px; height: 17px; flex: none; accent-color: var(--accent); }
.fields { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; margin-top: 12px; }
label.f { display: block; font-size: 13px; color: var(--muted); }
input[type=text], input[type=password], input[type=number], textarea {
  width: 100%; margin-top: 4px; padding: 8px 10px; border: 1px solid var(--line); border-radius: 7px;
  background: var(--bg); color: var(--ink); font: inherit; }
input:focus, textarea:focus, button:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
input.missing { border-color: var(--bad); }
textarea { font: 13px/1.45 ui-monospace, Menlo, Consolas, monospace; min-height: 220px; resize: vertical; }
details { margin-top: 12px; }
summary { cursor: pointer; color: var(--accent); font-size: 14px; }
.cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-top: 10px; }
.list { border: 1px solid var(--line); border-radius: 8px; padding: 8px 10px; max-height: 240px; overflow: auto; }
.list label { display: flex; gap: 8px; align-items: flex-start; padding: 3px 0; font-size: 14px; }
.list label span { overflow-wrap: anywhere; }
.listhead { display: flex; justify-content: space-between; font-size: 13px; color: var(--muted); margin-bottom: 4px; }
.link { background: none; border: 0; color: var(--accent); cursor: pointer; font: inherit; padding: 0 2px; }
button.btn { border: 1px solid var(--line); background: var(--panel); color: var(--ink); font: inherit;
  padding: 8px 14px; border-radius: 8px; cursor: pointer; }
button.btn:hover { border-color: var(--accent); }
button.primary { background: var(--accent); border-color: var(--accent); color: var(--accent-ink); font-weight: 600; }
button:disabled { opacity: .5; cursor: default; }
.actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-top: 16px; }
.note { border-radius: 8px; padding: 10px 14px; margin: 10px 0; border: 1px solid var(--line); }
.note.good { background: var(--good-bg); border-color: var(--good); }
.note.warn { background: var(--warn-bg); border-color: var(--warn); }
.note.bad { background: var(--bad-bg); border-color: var(--bad); }
pre { background: var(--code); border: 1px solid var(--line); border-radius: 8px; padding: 12px;
  font: 12.5px/1.5 ui-monospace, Menlo, Consolas, monospace; overflow: auto; max-height: 340px;
  white-space: pre-wrap; overflow-wrap: anywhere; margin: 8px 0; }
#report { max-height: 520px; }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: 13px; }
td.mono { font-family: ui-monospace, Menlo, monospace; font-size: 13px; overflow-wrap: anywhere; }
.tablewrap { overflow-x: auto; }
.pill { display: inline-block; padding: 1px 9px; border-radius: 999px; font-size: 12.5px; border: 1px solid; }
.pill.good { color: var(--good); } .pill.bad { color: var(--bad); } .pill.warn { color: var(--warn); }
.overlay { position: fixed; inset: 0; background: rgba(0,0,0,.45); display: flex; align-items: center;
  justify-content: center; padding: 20px; z-index: 10; }
.modal { background: var(--panel); border-radius: 12px; padding: 20px; width: 100%; max-width: 760px;
  max-height: 92vh; overflow: auto; border: 1px solid var(--line); }
.modal.small { max-width: 460px; }
.modal h2 { margin-top: 0; }
[hidden] { display: none !important; }
label.chk { display: flex; gap: 8px; align-items: flex-start; margin: 10px 0 0; font-size: 14px; }
select { margin-top: 4px; padding: 8px 10px; border: 1px solid var(--line); border-radius: 7px;
  background: var(--bg); color: var(--ink); font: inherit; max-width: 100%; }
.eprow, .cmdrow { display: grid; grid-template-columns: 1fr 1fr auto; gap: 8px; margin: 6px 0; align-items: center; }
.cmdrow { grid-template-columns: 160px 1fr 2fr auto; }
@media (max-width: 640px) { .eprow, .cmdrow { grid-template-columns: 1fr; } }
.grouphead { display: flex; gap: 10px; align-items: end; flex-wrap: wrap; }
.grouphead label.f { flex: 1; min-width: 160px; }
.spin { display: inline-block; width: 14px; height: 14px; border: 2px solid var(--line);
  border-top-color: var(--accent); border-radius: 50%; animation: sp 0.9s linear infinite; vertical-align: -2px; }
@keyframes sp { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .spin { animation: none; } }
</style>
</head>
<body>
<header><div class="bar">
  <div class="title">
    <h1>VCF Diagnostics</h1><span class="ver" id="ver"></span><span class="spacer"></span>
    <button class="btn" id="editInv">Settings</button>
    <button class="btn" id="quit">Quit</button>
  </div>
  <nav role="tablist">
    <button role="tab" data-tab="collect" aria-selected="true">Collect</button>
    <button role="tab" data-tab="investigate" aria-selected="false">Investigate with AI</button>
    <button role="tab" data-tab="reply" aria-selected="false">Analyst reply</button>
    <button role="tab" data-tab="scrub" aria-selected="false">Anonymize text</button>
    <button role="tab" data-tab="settings" aria-selected="false">Settings</button>
  </nav>
</div></header>

<main>
<div id="stopped" class="note" hidden>The tool has stopped. You can close this tab.</div>

<section id="tab-collect">
  <div id="problem" class="note bad" hidden></div>
  <div id="plainMode" class="note warn" hidden>Anonymization is off (Settings, Reports and privacy): reports keep
    real host names and addresses. Only secrets are redacted.</div>
  <div id="empty" class="note warn" hidden>
    No systems are set up yet. On the <b>Settings</b> tab, click <b>Add group</b>, enter the hosts and save.
  </div>
  <div id="setup">
    <p class="muted">Tick the groups to check, enter the SSH login for each, then run. Only read-only
      health checks are executed. Passwords stay in memory on this Mac and are never saved.</p>
    <div id="groups"></div>
    <details id="opts">
      <summary>Options</summary>
      <div class="fields">
        <label class="f">Hosts contacted at the same time
          <input type="number" id="optParallel" min="1" max="16" value="4"></label>
        <label class="f">Output lines kept per check
          <input type="number" id="optLines" min="20" max="100000" value="200"></label>
        <label class="f" style="display:flex;gap:8px;align-items:center;margin-top:22px;color:var(--ink)">
          <input type="checkbox" id="optStrict"> Only connect to hosts already in known_hosts</label>
      </div>
    </details>
    <div class="actions">
      <button class="btn primary" id="run">Run diagnostics</button>
      <span class="muted" id="runHint"></span>
    </div>
  </div>

  <div id="progress" hidden>
    <h2><span class="spin" id="spin"></span> <span id="progTitle">Collecting…</span></h2>
    <pre id="log" aria-live="polite"></pre>
    <div class="actions">
      <button class="btn" id="cancel">Cancel</button>
      <button class="btn" id="again" hidden>Back to selection</button>
    </div>
  </div>

  <div id="result" hidden>
    <h2>Report ready</h2>
    <p id="resSummary"></p>
    <p class="muted">Send the saved file for analysis, then paste the answer into the <b>Analyst reply</b> tab.</p>
    <div id="resPrivacy"></div>
    <div id="resQuads" class="note warn" hidden></div>
    <div class="actions">
      <button class="btn primary" id="copy">Copy report</button>
      <button class="btn" id="save">Save a copy…</button>
      <button class="btn" id="reveal">Show file</button>
      <button class="btn" id="toInvestigate">Investigate this with AI</button>
      <span class="muted" id="copied"></span>
    </div>
    <p class="muted" id="resPath"></p>
    <h2>Hosts in this run</h2>
    <p class="muted">This table shows real names and is only displayed here. It is not part of the report.</p>
    <div class="tablewrap"><table><thead><tr><th>Real name</th><th>Shown in report as</th><th>Group</th>
      <th>Result</th><th>Checks</th></tr></thead><tbody id="resHosts"></tbody></table></div>
    <h2>Report preview</h2>
    <p class="muted">Skim this before you share it. Add anything identifying that is still readable to
      <code>scrub_terms</code> in the inventory.</p>
    <pre id="report"></pre>
  </div>
</section>

<section id="tab-scrub" hidden>
  <p class="muted">Paste any text (a log excerpt, an error message). It is anonymized with the same
    placeholders as your reports.</p>
  <textarea id="scrubIn" placeholder="Paste text here" aria-label="Text to anonymize"></textarea>
  <div class="actions"><button class="btn primary" id="scrubGo">Anonymize</button>
    <button class="btn" id="scrubCopy" hidden>Copy result</button><span class="muted" id="scrubMsg"></span></div>
  <div id="scrubPrivacy"></div>
  <pre id="scrubOut" hidden></pre>
</section>

<section id="tab-investigate" hidden>
  <div id="aiMissing" class="note warn" hidden>No AI is set up yet. On the <b>Settings</b> tab, fill in the
    endpoint URL and model name under <b>AI for investigations</b>, then click <b>Save settings</b>.</div>
  <div id="invSetup">
    <p class="muted">Describe the problem. The AI reads the diagnostics, asks for the read-only checks it needs
      (you approve every round), and ends with the root cause and the fix steps. Fixes are only shown, never run.
      <span id="aiWho"></span></p>
    <label class="f">Problem description
      <textarea id="invProblem" style="min-height:120px;font-family:inherit"
        placeholder="For example: VCF Automation login fails since this morning with error ..."></textarea></label>
    <div class="fields">
      <fieldset style="border:1px solid var(--line);border-radius:8px;padding:8px 12px">
        <legend class="muted" style="font-size:13px">Start from</legend>
        <label style="display:block"><input type="radio" name="invStart" value="latest" checked>
          the latest report <span class="muted" id="invLatest"></span></label>
        <label style="display:block"><input type="radio" name="invStart" value="collect">
          a new collection of what is selected on the Collect tab</label>
        <label style="display:block"><input type="radio" name="invStart" value="none">
          only the description</label>
      </fieldset>
      <div class="f">
        <span class="muted" style="font-size:13px">AI service</span>
        <div class="row" role="radiogroup" aria-label="AI service" id="invProfiles"></div>
        <label class="f" style="margin-top:8px">API key <input type="password" id="aiKey" autocomplete="off"></label>
        <label class="chk" id="aiRememberRow"><input type="checkbox" id="aiRemember"> Remember the key in the macOS
          Keychain</label>
        <span class="muted" id="aiKeyState"></span>
      </div>
    </div>
    <details id="invLogins"><summary>Logins for the hosts the AI may ask about</summary>
      <p class="muted">Fill in the groups you expect to be involved. If the AI asks about another group, you are
        asked for its login then. Passwords stay in memory on this Mac.</p>
      <div id="invCreds"></div></details>
    <div class="actions"><button class="btn primary" id="invGo">Start investigation</button>
      <span class="muted" id="invMsg"></span></div>
  </div>
  <div id="invView" hidden>
    <h2><span class="spin" id="invSpin"></span> <span id="invTitle">Investigating ...</span></h2>
    <div id="invEntries"></div>
    <pre id="invLog" hidden></pre>
    <div id="invApprove" class="card on" hidden>
      <b>The AI asks for these read-only diagnostics</b>
      <p class="muted">Check the commands and hosts. They run only if you click Run.</p>
      <div class="tablewrap"><table><thead><tr><th>Host</th><th>What</th><th>Command</th></tr></thead>
        <tbody id="invApproveRows"></tbody></table></div>
      <div id="invRefused"></div>
      <div class="actions"><button class="btn primary" id="invRun">Run these diagnostics for me</button>
        <button class="btn" id="invManual">I'll run them myself and paste the output</button>
        <button class="btn" id="invDecline">Stop</button></div>
    </div>
    <div id="invFinal" hidden>
      <div id="invQuestion" class="note warn" hidden></div>
      <div id="invManualBox" hidden>
        <h2>Run these commands yourself</h2>
        <p class="muted">Run each block on the host named above it, then paste all the output below and send it.</p>
        <pre id="invManualScript"></pre>
        <div class="actions"><button class="btn" id="invCopyCollect">Copy the commands</button>
          <span class="muted" id="invCopyCollectMsg"></span></div>
      </div>
      <h2 id="invFinalTitle"></h2>
      <div id="invFixes"></div>
      <div class="actions" id="invFixScriptRow" hidden><button class="btn" id="invCopyFixes">Copy all fixes as one script</button>
        <span class="muted" id="invCopyFixesMsg"></span></div>
      <p class="muted" id="invPath"></p>
      <div class="card on" id="invReplyBox">
        <b>Continue the conversation</b>
        <p class="muted" id="invReplyHint">Paste the output of commands you ran, tell the AI what happened after a fix,
          or ask a follow-up question.</p>
        <textarea id="invReply" spellcheck="false" placeholder="Paste output or type your reply"></textarea>
        <div class="actions">
          <select id="invReplyKind" aria-label="What you are sending">
            <option value="output">Output of the commands the AI asked for</option>
            <option value="fix-output">Result of the fixes I applied</option>
            <option value="message">A message or question</option></select>
          <button class="btn primary" id="invSend">Send to the AI</button>
          <span class="muted" id="invSendMsg"></span></div>
      </div>
    </div>
    <div class="actions"><button class="btn" id="invStop">Stop</button>
      <button class="btn" id="invAgain" hidden>New investigation</button></div>
  </div>
</section>

<section id="tab-settings" hidden>
  <p class="muted">Everything the tool needs is set here. Changes take effect when you click <b>Save settings</b>.
    Passwords for the hosts are never stored: you type them when you run.</p>
  <div id="setErr" class="note bad" hidden></div>
  <div class="actions" style="margin-top:0">
    <button class="btn primary setSave">Save settings</button>
    <button class="btn" id="setReload">Discard changes</button>
    <span class="muted setMsg"></span></div>

  <h2>AI for investigations</h2>
  <div class="card on">
    <div class="row" role="radiogroup" aria-label="AI service" id="setProfiles">
      <label class="chk" style="margin:0"><input type="radio" name="setProfile" value="genai"> <b>GenAI.mil</b></label>
      <label class="chk" style="margin:0"><input type="radio" name="setProfile" value="capra"> <b>CAPRA (Ask Sage)</b></label>
      <label class="chk" style="margin:0"><input type="radio" name="setProfile" value="custom"> Other AI service</label>
    </div>
    <p class="muted" id="setPresetInfo"></p>
    <div id="setCustomAi">
    <p class="muted">Any OpenAI-compatible chat endpoint: most internal AI gateways, Azure OpenAI, vLLM, Ollama,
      LM Studio and others.</p>
    <div class="fields">
      <label class="f">AI service
        <select data-ai="provider" id="setProvider">
          <option value="openai">OpenAI-compatible (most AI gateways, vLLM, Ollama, LM Studio)</option>
          <option value="asksage">Ask Sage (CAPRA and other Ask Sage servers)</option>
          <option value="azure">Azure OpenAI</option></select></label>
      <label class="f"><span id="setUrlLabel">Endpoint address</span>
        <input type="text" data-ai="base_url" id="setUrl" placeholder="https://ai.example.internal/v1"></label>
    </div>
    <p class="muted" id="setUrlHint"></p>
    </div>
    <div class="fields">
      <label class="f">Model
        <input type="text" data-ai="model" id="setModel" list="setModelList" placeholder="click Find models, or type the name">
        <datalist id="setModelList"></datalist></label>
      <div class="f" style="align-self:end"><button class="btn" id="setFindModels" type="button">Find models</button>
        <span class="muted" id="setModelsMsg"></span></div>
      <label class="f">Rounds before the AI must conclude<input type="number" min="1" max="50" data-ai="max_rounds"></label>
    </div>
    <div class="fields">
      <label class="f">API key<input type="password" id="setKey" autocomplete="off"></label>
      <div class="f" style="align-self:end"><span class="muted" id="setKeyState"></span></div>
    </div>
    <div class="actions">
      <button class="btn" id="setKeySession">Use for this session</button>
      <button class="btn" id="setKeySave">Save in the macOS Keychain</button>
      <button class="btn" id="setKeyForget">Forget the key</button>
      <button class="btn primary" id="setAiTest">Test connection</button>
      <button class="btn" id="setAiCheck">Check connection step by step</button>
      <span class="muted" id="setAiMsg"></span></div>
    <div id="setAiCheckOut" hidden>
      <pre id="setAiCheckText"></pre>
      <div class="actions"><button class="btn" id="setAiCheckCopy">Copy the result</button>
        <span class="muted" id="setAiCheckMsg">No key or password is included; you can send it for help.</span></div>
    </div>
    <details><summary>More AI options</summary>
      <div class="fields">
        <label class="f">Longest report sent at once (characters)<input type="number" min="5000" data-ai="max_report_chars"></label>
        <label class="f">Largest conversation (characters)<input type="number" min="20000" data-ai="max_context_chars"></label>
        <label class="f">Reply length limit (tokens, empty = endpoint default)<input type="number" min="0" data-ai="max_tokens"></label>
        <label class="f">Wait for a reply (seconds)<input type="number" min="30" data-ai="timeout"></label>
        <label class="f">Trust this CA file (path)<input type="text" data-ai="ca_file" placeholder="~/internal-ca.pem"></label>
        <label class="f">Proxy to use (optional, overrides the Mac's)<input type="text" data-ai="proxy"
          placeholder="proxy.example.mil:8080"></label>
        <label class="f">Key goes in (OpenAI-compatible only)
          <select data-ai="auth_header"><option value="bearer">Authorization: Bearer (most endpoints)</option>
            <option value="api-key">api-key header (Azure style)</option>
            <option value="x-api-key">x-api-key header</option>
            <option value="token">Authorization: Token</option></select></label>
      </div>
      <p class="muted">Certificates this Mac trusts (for example ones your organisation installed) are trusted
        automatically.</p>
      <label class="chk"><input type="checkbox" data-ai-bool="tls_verify"> Check the endpoint's certificate</label>
      <label class="chk"><input type="checkbox" data-ai-bool="use_proxy"> Use this Mac's proxy settings to reach it
        (ignored when a proxy is entered above)</label>
    </details>
  </div>

  <h2>Systems to check</h2>
  <p class="muted">One entry per group of systems. The group name (type and label) is used in placeholders such as
    <code>esxi-mgmt-01</code>; changing it later gives those hosts new placeholders.</p>
  <div id="setGroups"></div>
  <div class="actions">
    <select id="setNewType" aria-label="Type of the new group"></select>
    <button class="btn" id="setAddGroup">Add group</button></div>

  <h2>Reports and privacy</h2>
  <div class="card">
    <label class="chk"><input type="checkbox" data-set-bool="anonymize"> Anonymize reports (replace host names,
      addresses and identifiers with placeholders). Turn off when reports stay inside the organisation.</label>
    <div class="fields">
      <label class="f">Output lines kept per check<input type="number" min="20" data-set="max_lines"></label>
      <label class="f">Words to hide everywhere (comma separated: company, site codes ...)<input type="text" data-set="scrub_terms"></label>
      <label class="f">Extra DNS domains to hide<input type="text" data-set="extra_domains"></label>
      <label class="f">Version numbers that look like IPs (keep readable)<input type="text" data-set="keep_literals"></label>
      <label class="f">Kubernetes namespaces to keep readable<input type="text" data-set="keep_namespaces"></label>
    </div>
  </div>

  <h2>Connections</h2>
  <div class="card">
    <div class="fields">
      <label class="f">Hosts contacted at the same time<input type="number" min="1" max="16" data-set="parallel"></label>
      <label class="f">SSH connect timeout (seconds)<input type="number" min="3" max="300" data-set="connect_timeout"></label>
      <label class="f">Command time limit (seconds, default 30)<input type="number" min="5" max="600" data-set="timeout"></label>
    </div>
    <label class="chk"><input type="checkbox" data-set-bool="strict_host_keys"> Only connect to hosts whose SSH key
      this Mac already knows (otherwise new hosts are trusted on first use)</label>
  </div>

  <h2>Your own read-only commands</h2>
  <div class="card">
    <p class="muted">Added as an extra check group for that type of system. Use <code>{K}</code> for kubectl.</p>
    <div id="setCmds"></div>
    <div class="actions"><button class="btn" id="setAddCmd">Add command</button></div>
  </div>

  <h2>Files</h2>
  <div class="card">
    <p class="muted" id="setPaths"></p>
    <div class="actions">
      <button class="btn" data-folder="output">Open the reports folder</button>
      <button class="btn" data-folder="private">Open the private folder</button>
      <button class="btn" id="editRaw">Edit the settings file as text (advanced)</button></div>
  </div>

  <div class="actions">
    <button class="btn primary setSave">Save settings</button>
    <span class="muted setMsg"></span></div>
</section>

<section id="tab-reply" hidden>
  <p class="muted">Paste the analyst's whole reply. Placeholders are translated back to your real names.
    Fixes are only shown, for you to apply by hand: this tool never runs them. Read-only follow-up
    diagnostics can be run from here.</p>
  <textarea id="replyIn" placeholder="Paste the reply here" aria-label="Analyst reply"></textarea>
  <div class="actions"><button class="btn primary" id="replyGo">Translate and read plan</button>
    <span class="muted" id="replyMsg"></span></div>
  <div id="replyOut" hidden>
    <div id="planProblems" class="note warn" hidden></div>
    <div id="planManualWrap" hidden>
      <h2>To apply by hand</h2>
      <p class="muted">The tool does not run these. Read each one, make sure you agree, then run it yourself
        on the host shown, in this order.</p>
      <div id="planManual"></div>
    </div>
    <div id="planCollectWrap" hidden>
      <h2>Read-only diagnostics requested</h2>
      <p class="muted">These only read information. Check the commands, enter the logins and run them. The
        output is anonymized into a follow-up report to send back.</p>
      <div class="tablewrap"><table><thead><tr><th>Host</th><th>What</th><th>Command</th></tr></thead>
        <tbody id="planCollect"></tbody></table></div>
      <div id="planCreds"></div>
      <div class="actions"><button class="btn primary" id="planRun">Run these diagnostics</button>
        <span class="muted" id="planRunMsg"></span></div>
    </div>
    <h2>Translated reply</h2>
    <p class="muted">Shown here only. It contains your real names, so do not send this version anywhere.</p>
    <pre id="replyText"></pre>
  </div>
</section>
</main>

<div class="overlay" id="invModal" hidden><div class="modal" role="dialog" aria-modal="true" aria-labelledby="invTitle">
  <h2 id="invTitle">Inventory</h2>
  <p class="muted" id="invPath"></p>
  <textarea id="invText" style="min-height:420px" spellcheck="false" aria-label="Inventory file"></textarea>
  <div id="invErr" class="note bad" hidden></div>
  <div class="actions"><button class="btn primary" id="invSave">Save</button>
    <button class="btn" id="invCancel">Cancel</button></div>
</div></div>

<div class="overlay" id="credModal" hidden><div class="modal small" role="dialog" aria-modal="true" aria-labelledby="credTitle">
  <h2 id="credTitle">Login was rejected</h2>
  <p id="credMsg"></p>
  <p class="muted">Only one login is tried per host, so nothing else has been contacted with these credentials.</p>
  <div class="fields" style="grid-template-columns:1fr">
    <label class="f">Username<input type="text" id="credUser" autocomplete="off" autocapitalize="off" spellcheck="false"></label>
    <label class="f">Password<input type="password" id="credPass" autocomplete="off"></label>
    <label class="f" id="credSuWrap">Root password for su<input type="password" id="credSu" autocomplete="off"></label>
  </div>
  <div class="actions"><button class="btn primary" id="credOk">Try again</button>
    <button class="btn" id="credSkip">Skip</button></div>
</div></div>

<script>
"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
function el(tag, props, ...kids) {
  const e = document.createElement(tag);
  Object.assign(e, props || {});
  for (const k of kids) e.append(k);
  return e;
}
async function api(path, body) {
  const opt = body === undefined ? {} :
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const r = await fetch("api/" + path, opt);
  const j = await r.json();
  if (!r.ok || j.error) throw new Error(j.error || r.statusText);
  return j;
}
let sections = [], lastReport = "", logNext = 0, timer = null;

// ---- tabs ----
$$("nav button").forEach(b => b.onclick = () => {
  $$("nav button").forEach(x => x.setAttribute("aria-selected", x === b));
  ["collect", "investigate", "reply", "scrub", "settings"].forEach(t => $("#tab-" + t).hidden = t !== b.dataset.tab);
  if (b.dataset.tab === "settings" && !settingsLoaded) loadSettings();
});

// ---- selection ----
function checklist(title, items, cls) {
  const box = el("div", { className: "list" });
  for (const it of items) {
    box.append(el("label", {}, el("input", { type: "checkbox", checked: true, className: cls, value: it.value }),
      el("span", { textContent: it.text })));
  }
  const set = v => $$("input", box).forEach(i => { i.checked = v; i.dispatchEvent(new Event("change", { bubbles: true })); });
  const head = el("div", { className: "listhead" }, el("span", { textContent: title }),
    el("span", {}, el("button", { className: "link", type: "button", textContent: "all", onclick: () => set(true) }), " / ",
      el("button", { className: "link", type: "button", textContent: "none", onclick: () => set(false) })));
  return el("div", {}, head, box);
}
function renderGroups() {
  const root = $("#groups");
  root.textContent = "";
  for (const s of sections) {
    const pick = el("input", { type: "checkbox", className: "sec" });
    const count = el("span", { className: "muted" });
    const body = el("div", { hidden: true });
    const card = el("div", { className: "card" },
      el("div", { className: "row" },
        el("label", { className: "pick" }, pick, el("b", { textContent: s.name }), el("span", { textContent: s.title })),
        count), body);
    card.dataset.name = s.name;
    const user = el("input", { type: "text", className: "user", value: s.user, autocomplete: "off", spellcheck: false });
    user.setAttribute("autocapitalize", "off");
    const fields = el("div", { className: "fields" },
      el("label", { className: "f" }, "SSH username", user),
      el("label", { className: "f" }, "SSH password", el("input", { type: "password", className: "pass", autocomplete: "off" })));
    if (s.escalate === "su")
      fields.append(el("label", { className: "f" }, "Root password for su",
        el("input", { type: "password", className: "su", autocomplete: "off" })));
    if (s.type === "vcenter" || s.type === "nsx" || s.type === "sddc") {
      const su = el("input", { type: "text", className: "ssouser", value: s.sso_user, autocomplete: "off", spellcheck: false });
      su.setAttribute("autocapitalize", "off");
      const what = s.type === "nsx" ? "NSX API" : s.type === "sddc" ? "SDDC Manager API (SSO)" : "vCenter SSO";
      fields.append(el("label", { className: "f" }, what + " user (" + (s.type === "vcenter" ? "SSO and namespace checks" : "API checks") + ")", su),
        el("label", { className: "f" }, what + " password",
          el("input", { type: "password", className: "ssopass", autocomplete: "off" })));
    }
    const det = el("details", {}, el("summary", { textContent: "Choose hosts and checks" }),
      el("div", { className: "cols" },
        checklist(s.host_label || "Hosts", s.hosts.map(h => ({ value: h, text: h })), "host"),
        checklist("Checks", s.groups.map(g => ({ value: g.key, text: g.title + " (" + g.checks.length + ")" })), "grp")));
    body.append(fields, det);
    const update = () => {
      const h = $$(".host:checked", card).length, g = $$(".grp:checked", card).length;
      count.textContent = h + " of " + s.hosts.length + " host" + (s.hosts.length === 1 ? "" : "s") +
        " · " + g + " of " + s.groups.length + " check groups";
      body.hidden = !pick.checked;
      card.classList.toggle("on", pick.checked);
      updateHint();
    };
    card.addEventListener("change", update);
    root.append(card);
    update();
  }
}
function updateHint() {
  const n = $$(".sec:checked").length;
  $("#runHint").textContent = n ? n + " group" + (n === 1 ? "" : "s") + " selected" : "Select at least one group";
  $("#run").disabled = !n;
}
async function loadState() {
  const st = await api("state");
  $("#ver").textContent = "v" + st.version;
  sections = st.sections;
  $("#problem").hidden = !st.error;
  $("#problem").textContent = st.error;
  $("#empty").hidden = !!st.error || sections.length > 0;
  $("#optParallel").value = st.parallel;
  $("#optLines").value = st.max_lines;
  $("#plainMode").hidden = st.anonymize !== false;
  renderInvestigateSetup(st);
  renderGroups();
  updateHint();
  if (st.busy && st.busy_kind === "investigate") { $('nav button[data-tab="investigate"]').click(); startInvPolling(); }
  else if (st.busy) startPolling();
}

// ---- run ----
$("#run").onclick = async () => {
  const req = { sections: {}, options: { parallel: +$("#optParallel").value, max_lines: +$("#optLines").value,
    strict: $("#optStrict").checked } };
  let bad = null;
  for (const card of $$("#groups .card")) {
    if (!$(".sec", card).checked) continue;
    const hosts = $$(".host:checked", card).map(i => i.value), groups = $$(".grp:checked", card).map(i => i.value);
    const isApi = g => /^(vc|nsx|sddc)-api-/.test(g);
    const apiOnly = groups.length > 0 && groups.every(isApi);
    const need = (apiOnly ? [] : [$(".pass", card)].concat($(".su", card) ? [$(".su", card)] : []))
      .concat(groups.some(isApi) && $(".ssopass", card) ? [$(".ssopass", card)] : []);
    $$("input[type=password]", card).forEach(i => i.classList.remove("missing"));
    for (const i of need) { i.classList.toggle("missing", !i.value); if (!i.value && !bad) bad = i; }
    if (!hosts.length || !groups.length) {
      $("#runHint").textContent = "Group " + card.dataset.name + " has no hosts or no checks selected";
      $("details", card).open = true;
      return;
    }
    req.sections[card.dataset.name] = { hosts, groups, user: $(".user", card).value.trim(),
      password: $(".pass", card).value, su_password: $(".su", card) ? $(".su", card).value : null,
      sso_user: $(".ssouser", card) ? $(".ssouser", card).value.trim() : null,
      sso_password: $(".ssopass", card) ? $(".ssopass", card).value : null };
  }
  if (bad) { bad.focus(); $("#runHint").textContent = "Enter the password for each selected group"; return; }
  try {
    await api("run", req);
  } catch (e) { $("#runHint").textContent = e.message; return; }
  $$("#groups input[type=password]").forEach(i => i.value = "");
  startPolling();
};
function startPolling() {
  logNext = 0;
  $("#log").textContent = "";
  $("#setup").hidden = true; $("#result").hidden = true; $("#progress").hidden = false;
  $("#spin").hidden = false; $("#cancel").hidden = false; $("#again").hidden = true;
  $("#progTitle").textContent = "Collecting…";
  clearInterval(timer);
  timer = setInterval(poll, 700);
  poll();
}
async function poll() {
  let st;
  try { st = await api("status?since=" + logNext); } catch (e) { return; }
  if (st.lines.length) {
    const log = $("#log");
    log.append(st.lines.join("\n") + "\n");
    log.scrollTop = log.scrollHeight;
    logNext = st.next;
  }
  if (st.prompt && st.prompt.kind !== "approve" && $("#credModal").hidden) showCred(st.prompt);
  if (!st.prompt || st.prompt.kind === "approve") $("#credModal").hidden = true;
  if (st.state === "running") return;
  clearInterval(timer);
  $("#spin").hidden = true; $("#cancel").hidden = true; $("#again").hidden = false;
  if (st.state === "done") { $("#progTitle").textContent = "Finished"; showResult(st.result); }
  else if (st.state === "cancelled") $("#progTitle").textContent = "Cancelled. No report was written.";
  else if (st.state === "error") $("#progTitle").textContent = "Stopped: " + st.error;
}
$("#cancel").onclick = () => { $("#progTitle").textContent = "Cancelling…"; api("cancel", {}).catch(() => {}); };
$("#again").onclick = () => { $("#progress").hidden = true; $("#result").hidden = true; $("#setup").hidden = false; };

function showCred(p) {
  $("#credMsg").textContent = p.message + " Enter different credentials for " + p.what + ", or skip.";
  $("#credUser").value = p.user; $("#credPass").value = ""; $("#credSu").value = "";
  $("#credSuWrap").hidden = !p.needs_su;
  $("#credModal").hidden = false;
  $("#credPass").focus();
}
$("#credOk").onclick = () => {
  if (!$("#credPass").value) { $("#credPass").focus(); return; }
  api("answer", { user: $("#credUser").value.trim(), password: $("#credPass").value,
    su_password: $("#credSu").value || null }).catch(() => {});
  $("#credPass").value = ""; $("#credSu").value = ""; $("#credModal").hidden = true;
};
$("#credSkip").onclick = () => { api("answer", { skip: true }).catch(() => {}); $("#credModal").hidden = true; };

function privacyNote(box, rv) {
  box.textContent = "";
  if (rv.anonymized === false) {
    box.append(el("div", { className: "note warn", textContent: "Not anonymized: this text contains real host " +
      "names and addresses. Only secrets were redacted. Keep it inside the organisation." }));
  } else if (rv.hits.length) {
    const n = el("div", { className: "note bad" },
      el("b", { textContent: rv.hits.length + " known real value" + (rv.hits.length === 1 ? " is" : "s are") +
        " still readable. Do not share yet." }),
      el("p", { textContent: "Add them to scrub_terms or extra_domains in the inventory and run again:" }));
    n.append(el("p", { className: "mono", textContent: rv.hits.slice(0, 40).map(h => h[0] + " (×" + h[1] + ")").join(", ") }));
    box.append(n);
  } else {
    box.append(el("div", { className: "note good", textContent:
      "Privacy check passed: none of the " + rv.known + " known real names or addresses appear in the text." }));
  }
}
async function showResult(res) {
  $("#result").hidden = false;
  $("#resSummary").textContent = (res.total - res.failed) + " host" + (res.total - res.failed === 1 ? "" : "s") +
    " collected, " + res.failed + " not collected. Report size " + res.size_kb + " KB (about " + res.tokens_k +
    " thousand tokens).";
  privacyNote($("#resPrivacy"), res.review);
  const q = $("#resQuads");
  q.hidden = !res.review.quads.length;
  q.textContent = "Left readable because they look like version numbers: " +
    res.review.quads.map(x => x[0] + " (×" + x[1] + ")").join(", ") +
    ". If one of these is really an IP address, remove it from keep_literals in the inventory.";
  $("#resPath").textContent = "Saved as " + res.path;
  const tb = $("#resHosts");
  tb.textContent = "";
  for (const t of res.targets) {
    const ok = t.result === "collected";
    const pill = el("span", { className: "pill " + (ok ? "good" : t.result === "skipped" ? "warn" : "bad"),
      textContent: ok ? "collected" : t.result });
    const cell = el("td", {}, pill);
    if (t.detail) cell.append(el("div", { className: "muted", textContent: t.detail }));
    tb.append(el("tr", {}, el("td", { className: "mono", textContent: t.address }),
      el("td", { className: "mono", textContent: t.placeholder }), el("td", { className: "mono", textContent: t.section }),
      cell, el("td", { textContent: ok ? t.checks + (t.problems ? " (" + t.problems + " non-zero)" : "") : "–" })));
  }
  lastReport = (await api("report")).text;
  $("#report").textContent = lastReport;
  $("#result").scrollIntoView({ behavior: "smooth" });
}
async function copyText(text, msg) {
  try { await navigator.clipboard.writeText(text); msg.textContent = "Copied"; }
  catch (e) { msg.textContent = "Copy failed. Select the text in the preview instead."; }
  setTimeout(() => msg.textContent = "", 2500);
}
$("#copy").onclick = () => copyText(lastReport, $("#copied"));
$("#save").onclick = () => {
  const a = el("a", { href: URL.createObjectURL(new Blob([lastReport], { type: "text/markdown" })),
    download: ($("#resPath").textContent.split("/").pop() || "vcf-report.md") });
  a.click();
  URL.revokeObjectURL(a.href);
};
$("#reveal").onclick = () => api("reveal", {}).catch(e => $("#copied").textContent = e.message);
$("#toInvestigate").onclick = async () => {
  await loadState();
  $('nav button[data-tab="investigate"]').click();
  $("#invView").hidden = true; $("#invSetup").hidden = false;
  const latest = $('input[name="invStart"][value="latest"]'); if (latest) latest.checked = true;
  $("#invProblem").focus();
};

// ---- settings ----
let settingsLoaded = false, setModel = null, setMeta = null;
const typeInfo = t => setMeta.types.find(x => x.type === t) || { title: t, default_user: "", host_label: "Hosts" };
function inp(type, value, extra) {
  const i = el("input", Object.assign({ type, value: value == null ? "" : value, autocomplete: "off", spellcheck: false }, extra || {}));
  i.setAttribute("autocapitalize", "off");
  return i;
}
function sel(options, value) {
  const s = el("select", {});
  for (const [v, t] of options) s.append(el("option", { value: v, textContent: t, selected: v === value }));
  return s;
}
const yes = v => !/^(no|false|0|off)$/i.test(String(v || "").trim());
function endpointRow(e) {
  const row = el("div", { className: "eprow" }, inp("text", e.service, { placeholder: "Service, e.g. VCF Operations", className: "epsvc" }),
    inp("text", e.endpoint, { placeholder: "FQDN, short name or IP", className: "epname" }),
    el("button", { className: "btn", type: "button", textContent: "Remove", onclick: () => row.remove() }));
  return row;
}
function groupCard(g) {
  const info = typeInfo(g.type);
  const card = el("div", { className: "card" });
  card.dataset.type = g.type;
  card._extra = { api_base: g.api_base || "", ssh_options: g.ssh_options || "" };
  const label = inp("text", g.label, { placeholder: "optional, e.g. mgmt", className: "glabel" });
  card.append(el("div", { className: "grouphead" },
    el("div", {}, el("b", { textContent: info.title }), el("div", { className: "muted", textContent: "type: " + g.type })),
    el("label", { className: "f" }, "Label", label),
    el("button", { className: "btn", type: "button", textContent: "Remove group",
      onclick: () => { if (confirm("Remove this group from the settings?")) card.remove(); } })));
  const hosts = el("textarea", { className: "ghosts", value: (g.hosts || []).join("\n"), spellcheck: false,
    placeholder: "one per line: FQDN, short name or IP" });
  hosts.style.minHeight = "80px";
  card.append(el("label", { className: "f" }, info.host_label + (g.type === "vcfmgmt" ? " (workers are found automatically)" : "") +
    " - one per line", hosts));
  const f = el("div", { className: "fields" },
    el("label", { className: "f" }, "Default SSH user", inp("text", g.user, { placeholder: info.default_user, className: "guser" })),
    el("label", { className: "f" }, "SSH port", inp("number", g.port, { placeholder: "22", className: "gport", min: 1, max: 65535 })),
    el("label", { className: "f" }, "Use sudo", Object.assign(sel([["", "default for this type"], ["auto", "when available"],
      ["yes", "always"], ["no", "never"]], g.sudo || ""), { className: "gsudo" })),
    el("label", { className: "f" }, "After login", Object.assign(sel([["", "use the login as is"],
      ["su", "switch to root with su (asks for the root password)"]], g.escalate || ""), { className: "gesc" })));
  card.append(f);
  if (g.type === "k8s" || g.type === "vcfmgmt" || g.type === "supervisor" || g.type === "vcfa")
    card.append(el("div", { className: "fields" },
      el("label", { className: "f" }, "kubeconfig path (empty = find automatically)", inp("text", g.kubeconfig, { className: "gkcfg" })),
      el("label", { className: "f" }, "kubectl command", inp("text", g.kubectl, { placeholder: "kubectl", className: "gkctl" }))));
  if (g.type === "vcfa")
    card.append(el("div", { className: "fields" },
      el("label", { className: "f" }, "Automation namespaces (empty = find automatically; * allowed)",
        inp("text", g.namespaces, { placeholder: "prelude, vmsp-*", className: "gns" }))),
      el("p", { className: "muted", textContent: "Log in as vmware-system-user (sudo is used for kubectl when needed)." }));
  if (g.type === "vcenter" || g.type === "nsx" || g.type === "sddc") {
    const nsx = g.type !== "vcenter";
    card.append(el("div", { className: "fields" },
      el("label", { className: "f" }, g.type === "nsx" ? "NSX API user (API health checks)" : g.type === "sddc" ?
        "SDDC Manager API user (SSO, credential checks)" : "vCenter SSO user (SSO and namespace checks)",
        inp("text", g.sso_user, { placeholder: g.type === "nsx" ? "admin" : "administrator@vsphere.local", className: "gsso" })),
      el("label", { className: "f" }, "Trust this " + (nsx ? "NSX" : "vCenter") + " CA file (path)",
        inp("text", g.ca_file, { placeholder: nsx ? "~/nsx-ca.pem" : "~/vcenter-ca.pem", className: "gca" }))));
    card.append(el("label", { className: "chk" }, el("input", { type: "checkbox", className: "gtls", checked: yes(g.tls_verify || "yes") }),
      "Check the " + (nsx ? "NSX Manager" : "vCenter") + " certificate"));
  }
  if (g.type === "opsnet")
    card.append(el("p", { className: "muted", textContent: "Log in as support for the full health check; consoleuser runs the CLI checks only." }));
  if (g.type === "vcfmgmt") {
    card.append(el("label", { className: "chk" }, el("input", { type: "checkbox", className: "gworkers", checked: yes(g.ssh_workers || "no") }),
      "Also log in to the worker nodes (same login as the control planes)"));
    const eps = el("div", { className: "geps" });
    (g.endpoints || []).forEach(e => eps.append(endpointRow(e)));
    card.append(el("p", { innerHTML: "<b>Management service endpoints</b>" }),
      el("p", { className: "muted", textContent: "Each service and the name or IP it answers on. Services that share an endpoint are checked once." }),
      eps, el("div", { className: "actions" },
        el("button", { className: "btn", type: "button", textContent: "Add endpoint", onclick: () => eps.append(endpointRow({})) }),
        el("button", { className: "btn", type: "button", textContent: "Add the standard VCF management services",
          onclick: () => { const have = $$(".epsvc", eps).map(i => i.value);
            setMeta.standard_services.filter(n => !have.includes(n)).forEach(n => eps.append(endpointRow({ service: n }))); } })));
  }
  return card;
}
function cmdRow(c) {
  const types = setMeta.types.map(t => [t.type, t.type]);
  const row = el("div", { className: "cmdrow" }, Object.assign(sel(types, c.type || "esxi"), { className: "ctype" }),
    inp("text", c.label, { placeholder: "Name of the check", className: "clabel" }),
    inp("text", c.command, { placeholder: "read-only command", className: "ccmd" }),
    el("button", { className: "btn", type: "button", textContent: "Remove", onclick: () => row.remove() }));
  return row;
}
function renderSettings() {
  const m = setModel;
  $$("[data-set]").forEach(i => i.value = m.settings[i.dataset.set] || "");
  $$("[data-set-bool]").forEach(i => i.checked = yes(m.settings[i.dataset.setBool]));
  $$("[data-ai]").forEach(i => i.value = m.ai[i.dataset.ai] || (i.tagName === "SELECT" ? "bearer" : ""));
  $$("[data-ai-bool]").forEach(i => i.checked = yes(m.ai[i.dataset.aiBool] || "yes"));
  if (!m.ai.provider) $("#setProvider").value = "openai";
  providerHints();
  const prof = setMeta.profile || "genai";
  $$('input[name="setProfile"]').forEach(r => r.checked = r.value === prof);
  showProfile(); $("#setModel").dataset.profile = prof;
  const gs = $("#setGroups");
  gs.textContent = "";
  m.groups.forEach(g => gs.append(groupCard(g)));
  if (!m.groups.length) gs.append(el("p", { className: "muted", textContent: "No groups yet. Add one below." }));
  const nt = $("#setNewType");
  nt.textContent = "";
  setMeta.types.forEach(t => nt.append(el("option", { value: t.type, textContent: t.title })));
  const cs = $("#setCmds");
  cs.textContent = "";
  m.commands.forEach(c => cs.append(cmdRow(c)));
  $("#setKeySave").hidden = !setMeta.keychain;
  const k = setMeta.key;
  $("#setKeyState").textContent = keyStateText(k);
  $("#setPaths").textContent = "Settings file: " + setMeta.paths.inventory + ". Reports: " + setMeta.paths.output +
    ". Private folder (placeholder mapping, never share): " + setMeta.paths.private + ".";
}
function keyStateText(k) {
  return k.keychain ? "A key is saved in the Keychain for this endpoint." : k.session ? "A key is set until you quit the tool." :
    k.env ? "Using " + k.env_name + " from the environment." : "No key set (fine if the endpoint needs none).";
}
function collectSettings() {
  const m = { settings: {}, ai: Object.assign({}, setModel.ai), groups: [], commands: [] };
  $$("[data-set]").forEach(i => m.settings[i.dataset.set] = i.value.trim());
  $$("[data-set-bool]").forEach(i => m.settings[i.dataset.setBool] = i.checked ? "yes" : "no");
  $$("[data-ai]").forEach(i => m.ai[i.dataset.ai] = i.value.trim());
  const prof = currentProfile();
  m.ai.profile = prof;
  if (PRESETS[prof]) { m.ai[prof + "_model"] = $("#setModel").value.trim(); m.ai.model = setModel.ai.model || ""; }
  $$("[data-ai-bool]").forEach(i => m.ai[i.dataset.aiBool] = i.checked ? "yes" : "no");
  for (const card of $$("#setGroups > .card")) {
    const v = c => { const i = $(c, card); return i ? i.value.trim() : ""; };
    const g = Object.assign({ type: card.dataset.type, label: v(".glabel"),
      hosts: $(".ghosts", card).value.split(/[\s,]+/).map(x => x.trim()).filter(Boolean),
      user: v(".guser"), port: v(".gport"), sudo: v(".gsudo"), escalate: v(".gesc"), kubeconfig: v(".gkcfg"),
      kubectl: v(".gkctl"), namespaces: v(".gns"), sso_user: v(".gsso"), ca_file: v(".gca"), endpoints: [] }, card._extra);
    if ($(".gtls", card)) g.tls_verify = $(".gtls", card).checked ? "yes" : "no";
    if ($(".gworkers", card)) g.ssh_workers = $(".gworkers", card).checked ? "yes" : "no";
    for (const r of $$(".eprow", card)) g.endpoints.push({ service: $(".epsvc", r).value.trim(), endpoint: $(".epname", r).value.trim() });
    m.groups.push(g);
  }
  for (const r of $$("#setCmds .cmdrow"))
    m.commands.push({ type: $(".ctype", r).value, label: $(".clabel", r).value.trim(), command: $(".ccmd", r).value.trim() });
  return m;
}
async function loadSettings() {
  $("#setErr").hidden = true;
  try {
    const r = await api("settings");
    setModel = r.model; setMeta = r.meta; settingsLoaded = true;
    renderSettings();
  } catch (e) { $("#setErr").textContent = e.message; $("#setErr").hidden = false; }
}
function setMsg(t) { $$(".setMsg").forEach(x => x.textContent = t); if (t) setTimeout(() => $$(".setMsg").forEach(x => x.textContent = ""), 4000); }
$$(".setSave").forEach(b => b.onclick = async () => {
  $("#setErr").hidden = true;
  try {
    const m = collectSettings();
    await api("settings", { model: m });
    setModel = m;
    setMsg("Saved.");
    await loadSettings();
    await loadState();
  } catch (e) { $("#setErr").textContent = e.message; $("#setErr").hidden = false; $("#setErr").scrollIntoView({ block: "center" }); }
});
$("#setReload").onclick = () => loadSettings();
$("#setAddGroup").onclick = () => {
  const gs = $("#setGroups");
  if (!$$(".card", gs).length) gs.textContent = "";
  const card = groupCard({ type: $("#setNewType").value, label: "", hosts: [] });
  gs.append(card);
  card.scrollIntoView({ block: "center" });
  $(".ghosts", card).focus();
};
$("#setAddCmd").onclick = () => $("#setCmds").append(cmdRow({}));
const aiForm = () => collectSettings().ai;
const PRESETS = {
  genai: { title: "GenAI.mil", url: "https://api.genai.mil/v1/chat/completions", model: "gemini-3.5-flash-lite-withtools",
    key: "Paste the API key from the GenAI.mil portal (it starts with STARK_)." },
  capra: { title: "CAPRA (Ask Sage)", url: "chat.capra.flankspeed.us.navy.mil", model: "",
    key: "Paste the API key you created in CAPRA / Ask Sage, then click Find models and pick one." } };
function currentProfile() { const r = $('input[name="setProfile"]:checked'); return r ? r.value : "genai"; }
function showProfile() {
  const p = currentProfile(), pre = PRESETS[p];
  $("#setCustomAi").hidden = !!pre;
  $("#setPresetInfo").textContent = pre ? "Address: " + pre.url + " (filled in for you). " + pre.key : "";
  const model = pre ? (setModel.ai[p + "_model"] || pre.model) : (setModel.ai.model || "");
  $("#setModel").value = model;
  $("#setModelList").textContent = "";
  $("#setAiMsg").textContent = ""; $("#setModelsMsg").textContent = "";
}
$$('input[name="setProfile"]').forEach(r => r.addEventListener("change", () => {
  // keep what was typed for the profile being left
  const was = $("#setModel").dataset.profile;
  if (was) { if (PRESETS[was]) setModel.ai[was + "_model"] = $("#setModel").value.trim(); else setModel.ai.model = $("#setModel").value.trim(); }
  showProfile(); $("#setModel").dataset.profile = currentProfile();
}));
function providerHints() {
  const p = $("#setProvider").value;
  $("#setUrlLabel").textContent = p === "asksage" ? "Ask Sage server address" : p === "azure" ? "Azure OpenAI endpoint URL" : "Endpoint address";
  $("#setUrl").placeholder = p === "asksage" ? "capra1.example.mil" : p === "azure" ?
    "https://NAME.openai.azure.com/openai/deployments/DEPLOYMENT?api-version=2024-06-01" : "https://ai.example.internal/v1";
  $("#setUrlHint").textContent = p === "asksage" ?
    "Enter just the server name, the same one you use in the browser. The tool finds the right API on that server; the key is the API key you created in Ask Sage (Settings, Account, API)." :
    p === "azure" ? "Use the deployment URL from the Azure portal; the key goes in the api-key header." :
    "https:// is added if you leave it out. Most gateways end in /v1.";
}
$("#setProvider").addEventListener("change", providerHints);
function linkify(box, text) {
  box.textContent = "";
  const parts = String(text).split(/(https?:\/\/[^\s"'<>]+)/);
  parts.forEach((p, i) => box.append(i % 2 ? el("a", { href: p, textContent: p, target: "_blank", rel: "noopener noreferrer" }) : p));
}
$("#setAiCheck").onclick = async () => {
  $("#setAiMsg").textContent = "Checking step by step ...";
  try {
    const r = await api("ai_check", { ai: aiForm(), key: $("#setKey").value });
    linkify($("#setAiCheckText"), r.text); $("#setAiCheckOut").hidden = false; $("#setAiMsg").textContent = "";
  } catch (e) { $("#setAiMsg").textContent = e.message; }
};
$("#setAiCheckCopy").onclick = () => copyText($("#setAiCheckText").textContent, $("#setAiCheckMsg"));
$("#setFindModels").onclick = async () => {
  $("#setModelsMsg").textContent = "Asking the endpoint ...";
  try {
    const r = await api("ai_models", { ai: aiForm(), key: $("#setKey").value });
    const dl = $("#setModelList"); dl.textContent = "";
    r.models.forEach(m => dl.append(el("option", { value: m })));
    if (!$("#setModel").value && r.models.length) $("#setModel").value = r.models[0];
    $("#setModelsMsg").textContent = r.models.length + " model(s) found: click the Model field to choose.";
    $("#setModel").focus();
  } catch (e) { linkify($("#setModelsMsg"), e.message); }
};
$("#setAiTest").onclick = async () => {
  $("#setAiMsg").textContent = "Testing ...";
  try {
    const r = await api("ai_test", { ai: aiForm(), key: $("#setKey").value });
    $("#setAiMsg").textContent = "Connected through the " + r.flavor + ": the AI answered in " + r.seconds + " s (" +
      (r.reply || "empty reply").slice(0, 60) + ")." + (r.used_key ? "" : " No key was sent.") +
      (r.note ? " Note: " + r.note + "; you can untick the proxy option under More AI options." : "") + " Click Save settings to keep it.";
  } catch (e) { linkify($("#setAiMsg"), e.message); }
};
async function keyAction(action) {
  try {
    const r = await api("ai_key", { action, key: $("#setKey").value, base_url: aiForm().base_url, provider: aiForm().provider });
    $("#setKey").value = "";
    $("#setAiMsg").textContent = { session: "The key is used until you quit the tool.", save: "The key is saved in the Keychain for this endpoint.",
      forget: "The key is forgotten." }[action];
    setMeta.key = r.key;
    $("#setKeyState").textContent = keyStateText(r.key);
  } catch (e) { $("#setAiMsg").textContent = e.message; }
}
$("#setKeySession").onclick = () => keyAction("session");
$("#setKeySave").onclick = () => keyAction("save");
$("#setKeyForget").onclick = () => keyAction("forget");
$$("[data-folder]").forEach(b => b.onclick = () => api("open_folder", { which: b.dataset.folder }).catch(e => setMsg(e.message)));
$("#editInv").onclick = () => $('nav button[data-tab="settings"]').click();

// ---- inventory editor (advanced: the settings file as text) ----
$("#editRaw").onclick = async () => {
  const inv = await api("inventory");
  $("#invText").value = inv.text;
  $("#invPath").textContent = inv.path + (inv.exists ? "" : " (not created yet — this is the template)") +
    ". Contains real hostnames; it stays on this Mac.";
  $("#invErr").hidden = true;
  $("#invModal").hidden = false;
  $("#invText").focus();
};
$("#invCancel").onclick = () => $("#invModal").hidden = true;
$("#invSave").onclick = async () => {
  try {
    await api("inventory", { text: $("#invText").value });
    $("#invModal").hidden = true;
    await loadState();
    if (settingsLoaded) await loadSettings();
  } catch (e) { $("#invErr").textContent = e.message; $("#invErr").hidden = false; }
};

// ---- anonymize / translate back ----
$("#scrubGo").onclick = async () => {
  $("#scrubMsg").textContent = "";
  try {
    const r = await api("scrub", { text: $("#scrubIn").value });
    $("#scrubOut").textContent = r.text; $("#scrubOut").hidden = false; $("#scrubCopy").hidden = false;
    privacyNote($("#scrubPrivacy"), r.review);
  } catch (e) { $("#scrubMsg").textContent = e.message; }
};
$("#scrubCopy").onclick = () => copyText($("#scrubOut").textContent, $("#scrubMsg"));

// ---- analyst reply: translate, show fixes, run read-only follow-ups ----
let planText = "";
const hostNames = ts => ts.length ? ts.map(t => t.address + " (" + t.placeholder + ")").join(", ") : "no known host";
function credFields(l) {
  const user = el("input", { type: "text", className: "user", value: l.user, autocomplete: "off", spellcheck: false });
  user.setAttribute("autocapitalize", "off");
  const f = el("div", { className: "fields" },
    el("label", { className: "f" }, "SSH username", user),
    el("label", { className: "f" }, "SSH password", el("input", { type: "password", className: "pass", autocomplete: "off" })));
  if (l.escalate === "su")
    f.append(el("label", { className: "f" }, "Root password for su",
      el("input", { type: "password", className: "su", autocomplete: "off" })));
  const card = el("div", { className: "card on" },
    el("div", { className: "row" }, el("b", { textContent: l.name }), el("span", { textContent: l.title })), f);
  card.dataset.name = l.name;
  return card;
}
function renderPlan(r) {
  $("#replyOut").hidden = false;
  $("#replyText").textContent = r.translated;
  const pr = $("#planProblems");
  pr.hidden = !r.problems.length;
  pr.textContent = r.problems.join(" ");
  const man = $("#planManual");
  man.textContent = "";
  $("#planManualWrap").hidden = !r.manual.length;
  r.manual.forEach((e, i) => {
    const msg = el("span", { className: "muted" });
    const card = el("div", { className: "card" },
      el("div", { className: "row" }, el("b", { textContent: (i + 1) + ". " + e.label }),
        el("span", { className: "pill " + (e.kind === "fix" ? "warn" : "bad"),
          textContent: e.kind === "fix" ? "changes the system" : "not run by the tool" })),
      el("p", { textContent: "On: " + hostNames(e.targets) }));
    if (e.reason) card.append(el("p", { className: "muted", textContent:
      "It was requested as a read-only check, but " + e.reason + ". Run it yourself only if you agree with it." }));
    if (e.note) card.append(el("p", { textContent: e.note }));
    card.append(el("pre", { textContent: e.command }),
      el("div", { className: "actions" }, el("button", { className: "btn", textContent: "Copy command",
        onclick: () => copyText(e.command, msg) }), msg));
    man.append(card);
  });
  const tb = $("#planCollect");
  tb.textContent = "";
  $("#planCollectWrap").hidden = !r.collect.length;
  for (const e of r.collect)
    tb.append(el("tr", {}, el("td", { className: "mono", textContent: e.targets.map(t => t.address).join("\n") }),
      el("td", { textContent: e.label }), el("td", { className: "mono", textContent: e.command })));
  const creds = $("#planCreds");
  creds.textContent = "";
  r.logins.forEach(l => creds.append(credFields(l)));
  if (!r.manual.length && !r.collect.length && !r.problems.length)
    $("#replyMsg").textContent = "No plan block was found in this reply. The translation is below.";
}
$("#replyGo").onclick = async () => {
  $("#replyMsg").textContent = ""; $("#planRunMsg").textContent = "";
  try {
    const r = await api("plan", { text: $("#replyIn").value });
    planText = $("#replyIn").value;
    renderPlan(r);
  } catch (e) { $("#replyOut").hidden = true; $("#replyMsg").textContent = e.message; }
};
$("#planRun").onclick = async () => {
  const req = { text: planText, sections: {}, options: { parallel: +$("#optParallel").value, strict: $("#optStrict").checked } };
  let bad = null;
  for (const card of $$("#planCreds .card")) {
    const need = [$(".pass", card)].concat($(".su", card) ? [$(".su", card)] : []);
    for (const i of need) { i.classList.toggle("missing", !i.value); if (!i.value && !bad) bad = i; }
    req.sections[card.dataset.name] = { user: $(".user", card).value.trim(), password: $(".pass", card).value,
      su_password: $(".su", card) ? $(".su", card).value : null };
  }
  if (bad) { bad.focus(); $("#planRunMsg").textContent = "Enter the password for each group"; return; }
  try { await api("plan_run", req); } catch (e) { $("#planRunMsg").textContent = e.message; return; }
  $$("#planCreds input[type=password]").forEach(i => i.value = "");
  $('nav button[data-tab="collect"]').click();
  startPolling();
};

// ---- investigate with AI ----
let invTimer = null, invShown = 0, invLogNext = 0;
function renderInvestigateSetup(st) {
  const ai = st.ai || {};
  $("#aiMissing").hidden = !!ai.configured;
  $("#invGo").disabled = !ai.configured;
  $("#aiWho").textContent = ai.configured ? "AI: " + ai.model + " at " + ai.base_url + ", up to " + ai.max_rounds + " rounds." : "";
  $("#invLatest").textContent = ai.latest_report ? "(" + ai.latest_report + ")" : "(none yet)";
  $("#aiKey").placeholder = ai.key_ready ? "a key is already saved for this service" : "paste the API key";
  $("#aiKeyState").textContent = ai.key_ready ? "A key is saved for " + (ai.profile === "custom" ? "this service" :
    (ai.presets.find(x => x.id === ai.profile) || {}).title) + "; leave the field empty to use it." :
    (ai.presets.find(x => x.id === ai.profile) || {}).key_hint ? "Use " + ai.presets.find(x => x.id === ai.profile).key_hint + "." : "";
  $("#aiRememberRow").hidden = !ai.keychain;
  const pr = $("#invProfiles");
  pr.textContent = "";
  const opts = (ai.presets || []).map(x => [x.id, x.title]).concat([["custom", "Other" + (ai.custom_name ? " (" + ai.custom_name + ")" : "")]]);
  for (const [id, title] of opts) {
    const r = el("input", { type: "radio", name: "invProfile", value: id, checked: id === ai.profile });
    r.onchange = async () => {
      try { await api("ai_profile", { profile: id }); } catch (e) { $("#invMsg").textContent = e.message; }
      loadState();
    };
    pr.append(el("label", { className: "chk", style: "margin:0 12px 0 0" }, r, " " + title));
  }
  const box = $("#invCreds");
  if (!box.children.length || box.dataset.n !== String(sections.length)) {
    box.textContent = "";
    sections.forEach(s => box.append(credFields({ name: s.name, title: s.title, user: s.user, escalate: s.escalate })));
    box.dataset.n = String(sections.length);
  }
}
function invCreds() {
  const out = {};
  for (const card of $$("#invCreds .card"))
    out[card.dataset.name] = { user: $(".user", card).value.trim(), password: $(".pass", card).value,
      su_password: $(".su", card) ? $(".su", card).value : null };
  return out;
}
$("#invGo").onclick = async () => {
  const start = $('input[name="invStart"]:checked').value;
  const req = { problem: $("#invProblem").value, start, key: $("#aiKey").value, remember: $("#aiRemember").checked, creds: invCreds(),
    options: { parallel: +$("#optParallel").value, max_lines: +$("#optLines").value, strict: $("#optStrict").checked } };
  if (start === "collect") {
    req.collect = {};
    for (const card of $$("#groups .card")) {
      if (!$(".sec", card).checked) continue;
      req.collect[card.dataset.name] = { hosts: $$(".host:checked", card).map(i => i.value),
        groups: $$(".grp:checked", card).map(i => i.value), user: $(".user", card).value.trim(),
        password: $(".pass", card).value || (req.creds[card.dataset.name] || {}).password || "",
        su_password: $(".su", card) ? $(".su", card).value : null,
        sso_user: $(".ssouser", card) ? $(".ssouser", card).value.trim() : null,
        sso_password: $(".ssopass", card) ? $(".ssopass", card).value : null };
    }
    if (!Object.keys(req.collect).length) { $("#invMsg").textContent = "Select groups on the Collect tab first"; return; }
  }
  try { await api("investigate", req); } catch (e) { $("#invMsg").textContent = e.message; return; }
  $("#invMsg").textContent = "";
  $$("#invCreds input[type=password], #aiKey").forEach(i => i.value = "");
  startInvPolling();
};
function startInvPolling() {
  invShown = 0; invLogNext = 0;
  $("#invEntries").textContent = ""; $("#invLog").textContent = ""; $("#invLog").hidden = true;
  $("#invSetup").hidden = true; $("#invView").hidden = false; $("#invFinal").hidden = true;
  $("#invApprove").hidden = true; $("#invSpin").hidden = false; $("#invStop").hidden = false; $("#invAgain").hidden = true;
  $("#invTitle").textContent = "Investigating ...";
  clearInterval(invTimer);
  invTimer = setInterval(invPoll, 800);
  invPoll();
}
function invEntry(e) {
  if (e.kind === "ai") {
    const card = el("div", { className: "card" }, el("b", { textContent: "AI" }), el("pre", { textContent: e.text }));
    return card;
  }
  if (e.kind === "warn") return el("div", { className: "note warn", textContent: e.text });
  if (e.kind === "report") return el("p", { className: "muted", textContent: "Report saved: " + e.text });
  if (e.kind === "you") return el("div", { className: "card" }, el("b", { textContent: "You" }), el("pre", { textContent: e.text }));
  return el("p", { className: "muted", textContent: e.text });
}
function renderApprove(plan) {
  const tb = $("#invApproveRows");
  tb.textContent = "";
  for (const e of plan.collect)
    tb.append(el("tr", {}, el("td", { className: "mono", textContent: e.targets.map(t => t.address).join("\n") }),
      el("td", { textContent: e.label }), el("td", { className: "mono", textContent: e.command })));
  const ref = $("#invRefused");
  ref.textContent = "";
  const blocked = plan.manual.filter(e => e.kind === "blocked");
  if (blocked.length)
    ref.append(el("div", { className: "note warn", textContent: "Refused by the read-only check (not run; the AI is told): " +
      blocked.map(e => e.label + " (" + e.reason + ")").join("; ") }));
  if (plan.problems.length) ref.append(el("div", { className: "note warn", textContent: plan.problems.join(" ") }));
  $("#invApprove").hidden = false;
  $("#invApprove").scrollIntoView({ behavior: "smooth", block: "center" });
}
async function invPoll() {
  let st;
  try { st = await api("status?since=" + invLogNext); } catch (e) { return; }
  if (st.lines.length) {
    const log = $("#invLog");
    log.hidden = false;
    log.append(st.lines.join("\n") + "\n");
    log.scrollTop = log.scrollHeight;
    invLogNext = st.next;
  }
  const inv = st.inv;
  if (!inv) return;
  const box = $("#invEntries");
  for (; invShown < inv.entries.length; invShown++) box.append(invEntry(inv.entries[invShown]));
  const ap = st.prompt && st.prompt.kind === "approve";
  if (ap && $("#invApprove").hidden) renderApprove(st.prompt.plan);
  if (!ap) $("#invApprove").hidden = true;
  if (st.prompt && !ap && $("#credModal").hidden) showCred(st.prompt);
  if (inv.state === "running") return;
  clearInterval(invTimer);
  $("#invSpin").hidden = true; $("#invStop").hidden = true; $("#invAgain").hidden = false; $("#credModal").hidden = true;
  if (inv.state === "error") { $("#invTitle").textContent = "Stopped: " + inv.error; return; }
  const f = inv.final;
  $("#invTitle").textContent = { concluded: "The AI has concluded", declined: "Stopped by you", stopped: "Investigation stopped",
    question: "The AI has a question for you", manual: "Waiting for the output of the commands" }[f.how] || "Finished";
  $("#invFinal").hidden = false;
  $("#invQuestion").hidden = f.how !== "question";
  $("#invQuestion").textContent = f.question || "";
  $("#invManualBox").hidden = f.how !== "manual";
  $("#invManualScript").textContent = f.collect_script || "";
  $("#invFixScriptRow").hidden = !f.fix_script;
  $("#invReplyKind").value = f.how === "manual" ? "output" : (f.manual.some(e => e.kind === "fix") ? "fix-output" : "message");
  $("#invReply").value = "";
  if (f.how === "manual") $("#invReply").focus();
  lastFinal = f;
  const fixes = f.manual.filter(e => e.kind === "fix");
  $("#invFinalTitle").textContent = fixes.length ? "Fixes to apply by hand, in this order" : "";
  const fx = $("#invFixes");
  fx.textContent = "";
  fixes.forEach((e, i) => {
    const msg = el("span", { className: "muted" });
    const card = el("div", { className: "card" },
      el("div", { className: "row" }, el("b", { textContent: (i + 1) + ". " + e.label }),
        /^verify|^check/i.test(e.label) ? el("span", { className: "pill good", textContent: "verification" })
          : el("span", { className: "pill warn", textContent: "changes the system" })),
      el("p", { textContent: "On: " + hostNames(e.targets) }));
    if (e.note) card.append(el("p", { textContent: e.note }));
    card.append(el("pre", { textContent: e.command }), el("div", { className: "actions" },
      el("button", { className: "btn", textContent: "Copy command", onclick: () => copyText(e.command, msg) }), msg));
    fx.append(card);
  });
  $("#invPath").textContent = "Transcript (as sent to the AI): " + f.path;
}
$("#invRun").onclick = () => { $("#invApprove").hidden = true; api("answer", { decision: "run" }).catch(() => {}); };
$("#invManual").onclick = () => { $("#invApprove").hidden = true; api("answer", { decision: "manual" }).catch(() => {}); };
$("#invDecline").onclick = () => { $("#invApprove").hidden = true; api("answer", { decision: "stop" }).catch(() => {}); };
let lastFinal = null;
$("#invCopyCollect").onclick = () => copyText($("#invManualScript").textContent, $("#invCopyCollectMsg"));
$("#invCopyFixes").onclick = () => copyText(lastFinal ? lastFinal.fix_script : "", $("#invCopyFixesMsg"));
$("#invSend").onclick = async () => {
  try {
    await api("inv_reply", { text: $("#invReply").value, kind: $("#invReplyKind").value });
  } catch (e) { $("#invSendMsg").textContent = e.message; return; }
  $("#invSendMsg").textContent = "";
  $("#invFinal").hidden = true; $("#invSpin").hidden = false; $("#invStop").hidden = false; $("#invAgain").hidden = true;
  $("#invTitle").textContent = "Investigating ...";
  clearInterval(invTimer); invLogNext = 0; $("#invLog").textContent = ""; $("#invLog").hidden = true;
  invTimer = setInterval(invPoll, 800); invPoll();
};
$("#invStop").onclick = () => { $("#invTitle").textContent = "Stopping ..."; api("cancel", {}).catch(() => {}); };
$("#invAgain").onclick = () => { $("#invView").hidden = true; $("#invSetup").hidden = false; loadState(); };

$("#quit").onclick = async () => {
  if (!confirm("Stop the tool? A collection that is still running will be cancelled.")) return;
  await api("quit", {}).catch(() => {});
  clearInterval(timer);
  $$("section").forEach(s => s.hidden = true);
  $("#stopped").hidden = false;
};
document.addEventListener("keydown", e => {
  if (e.key === "Escape" && !$("#invModal").hidden) $("#invModal").hidden = true;
  if (e.key === "Enter" && !$("#credModal").hidden) $("#credOk").click();
});
loadState().catch(e => { $("#problem").hidden = false; $("#problem").textContent = e.message; });
</script>
</body>
</html>
"""


class GuiUI:
    """Credential source for a run started from the browser."""

    def __init__(self, gui, creds):
        self.gui = gui
        self.creds = creds

    def initial_credentials(self, sec):
        c = self.creds.get(sec["name"], {})
        if not c.get("password") and self.gui.inv and self.gui.inv["state"] == "running":
            new = self.gui.ask({"kind": "creds", "section": sec["name"], "what": "[%s]" % sec["name"],
                                "message": "The AI asked for diagnostics on [%s] %s, and no login was entered "
                                           "for it." % (sec["name"], COMPONENTS[sec["type"]]["title"]),
                                "user": c.get("user") or sec["user"], "needs_su": sec.get("escalate") == "su"})
            if new:
                return new
        return (c.get("user") or sec["user"], c.get("password") or "", c.get("su_password") or None)

    def sso_credentials(self, sec):
        c = self.creds.get(sec["name"], {})
        return (c.get("sso_user") or sec["sso_user"], c.get("sso_password") or "")

    def retry_credentials(self, sec, what, message, default=True):
        return self.gui.ask({"section": sec["name"], "what": what, "message": message,
                             "user": sec["user"], "needs_su": sec.get("escalate") == "su"})


class Gui:
    """State behind the browser page. One collection can run at a time."""

    def __init__(self, args):
        self.args = args
        self.token = pysecrets.token_urlsafe(18)
        self.lock = threading.Lock()
        self.state = "idle"            # idle | running | done | cancelled | error
        self.lines = []
        self.prompt = None
        self.answer = None
        self.answered = threading.Event()
        self.result = None
        self.error = ""
        self.ctx = None
        self.httpd = None
        self.inv = None                    # state of the current or last investigation
        self.ai_keys = {}                  # AI keys entered in this window, per endpoint address (memory only)
        self.inv_stop = threading.Event()
        self.inv_obj = None                # the investigation conversation, kept so it can continue
        _log_sinks.append(lambda msg: self.lines.append(msg) if msg.strip() else None)

    # ---- helpers -----------------------------------------------------------
    def inventory_path(self):
        return find_inventory(self.args) or "inventory.ini"

    def ask(self, prompt):
        with self.lock:
            self.prompt, self.answer = prompt, None
            self.answered.clear()
        while not self.answered.wait(0.5):
            if (self.ctx is not None and self.ctx.cancel.is_set()) or self.inv_stop.is_set():
                break
        with self.lock:
            self.prompt = None
            return self.answer

    def cancel(self):
        self.inv_stop.set()
        self.answered.set()
        ctx = self.ctx
        if ctx is not None:
            ctx.cancel.set()
            self.answered.set()
            for t in list(ctx.targets):      # drop the connections so running checks stop now
                t.close()

    # ---- API ---------------------------------------------------------------
    def api_state(self):
        out = {"version": VERSION, "sections": [], "error": "", "busy": self.state == "running",
               "busy_kind": "investigate" if (self.inv and self.inv["state"] == "running") else "collect",
               "ai": {"configured": False},
               "parallel": self.args.parallel or 4, "max_lines": self.args.max_lines or 200,
               "anonymize": True}
        if ssh_version()[0] is None:
            out["error"] = "The OpenSSH client 'ssh' was not found on this machine."
            return out
        inv = find_inventory(self.args)
        if not inv:
            return out
        try:
            settings, sections, custom = load_inventory(inv)
        except Fatal as e:
            out["error"] = "%s (fix it on the Settings tab)" % e
            return out
        if not self.args.parallel:
            out["parallel"] = int(settings.get("parallel", 4))
        out["max_lines"] = max_lines_for(self.args, settings)
        cfg = ai_settings(settings)
        latest = latest_report(self.args)
        out["ai"] = {"configured": bool(cfg["base_url"] and cfg["model"]), "model": cfg["model"],
                     "profile": cfg["profile"], "keychain": keychain_available(),
                     "presets": [{"id": k, "title": v_["title"], "key_hint": v_["key_hint"]} for k, v_ in AI_PRESETS.items()],
                     "custom_name": (settings.get("_ai") or {}).get("base_url", ""),
                     "base_url": cfg["base_url"], "key_env": cfg["key_env"],
                     "key_from_env": bool(os.environ.get(cfg["key_env"])), "max_rounds": cfg["max_rounds"],
                     "key_ready": bool(resolve_ai_key(cfg, "", self.ai_keys)),
                     "latest_report": os.path.basename(latest) if latest else None}
        out["anonymize"] = anonymize_enabled(self.args, settings)
        for s in sections:
            out["sections"].append({
                "name": s["name"], "title": COMPONENTS[s["type"]]["title"], "user": s["user"],
                "type": s["type"], "sso_user": s["sso_user"],
                "host_label": COMPONENTS[s["type"]].get("host_label", "Hosts"),
                "hosts": s["hosts"], "escalate": s["escalate"],
                "groups": [{"key": k, "title": t, "checks": [c["label"] for c in cs]}
                           for k, t, cs in groups_for(s, custom)]})
        return out

    def api_inventory_get(self):
        path = self.inventory_path()
        exists = os.path.exists(path)
        text = INVENTORY_TEMPLATE
        if exists:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        return {"path": os.path.abspath(path), "exists": exists, "text": text}

    def api_inventory_set(self, body):
        text = str(body.get("text", "")).replace("\r\n", "\n")
        fd, tmp = tempfile.mkstemp(prefix="vdinv")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
            try:
                load_inventory(tmp)              # validate before replacing the real file
            except Fatal as e:
                raise Fatal(str(e).replace(tmp, "the inventory"))
        finally:
            os.unlink(tmp)
        write_private(self.inventory_path(), text)
        return {"ok": True}

    def api_run(self, body):
        with self.lock:
            if self.state == "running":
                raise Fatal("a collection is already running")
            self.state = "running"
        try:
            settings, sections, custom = load_inventory(self.inventory_path())
            plan, creds = self._plan_from_selection(body.get("sections") or {}, sections, custom)
            args = self._run_args(body, settings)
            scale = self.args.timeout_scale
            scale_timeouts(plan, scale if scale is not None else float(settings.get("timeout", 30)) / 30.0)
        except Exception:
            with self.lock:
                self.state = "idle"
            raise
        return self._start(args, settings, sections, plan, creds, "health", "")

    def _plan_from_selection(self, selection, sections, custom):
        if True:
            byname = {s["name"]: s for s in sections}
            plan, creds = [], {}
            for name, sel in selection.items():
                sec = byname.get(name)
                if not sec:
                    raise Fatal("unknown inventory section [%s]" % name)
                hosts = [h for h in sec["hosts"] if h in set(sel.get("hosts") or [])]
                groups = [g for g in groups_for(sec, custom) if g[0] in set(sel.get("groups") or [])]
                if not hosts or not groups:
                    raise Fatal("nothing selected in [%s]" % name)
                api = [g for g in groups if is_api_group(g[0])]
                if len(api) < len(groups) and not sel.get("password"):
                    raise Fatal("no password given for [%s]" % name)
                if api and not sel.get("sso_password"):
                    raise Fatal("no vCenter SSO password given for the namespace checks of [%s]" % name)
                plan.append({"sec": sec, "hosts": hosts, "groups": groups})
                creds[name] = {"user": str(sel.get("user") or "").strip(), "password": str(sel.get("password") or ""),
                               "su_password": sel.get("su_password"),
                               "sso_user": str(sel.get("sso_user") or "").strip(),
                               "sso_password": str(sel.get("sso_password") or "")}
            if not plan:
                raise Fatal("nothing selected")
            return plan, creds

    def _run_args(self, body, settings):
        opt = body.get("options") or {}
        args = argparse.Namespace(**vars(self.args))
        args.parallel = _clamp(opt.get("parallel") or settings.get("parallel", 4), 4, 1, 16)
        args.max_lines = _clamp(opt.get("max_lines") or max_lines_for(self.args, settings), 200, 20, 100000)
        args.strict_host_keys = bool(opt.get("strict")) or self.args.strict_host_keys
        return args

    def _start(self, args, settings, sections, plan, creds, kind, title):
        with self.lock:
            del self.lines[:]
            self.result, self.error, self.prompt = None, "", None
        threading.Thread(target=self._run, args=(args, settings, sections, plan, creds, kind, title),
                         daemon=True).start()
        return {"ok": True}

    def api_settings_get(self):
        path = self.inventory_path()
        text = INVENTORY_TEMPLATE
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        model = read_settings_model(text)
        cfg = ai_settings({"_ai": model["ai"]})
        types = [{"type": t, "title": c["title"], "default_user": c["user"],
                  "host_label": c.get("host_label", "Hosts")} for t, c in COMPONENTS.items()]
        return {"model": model, "meta": {
            "profile": ai_profile(model["ai"]),
            "types": types, "standard_services": STANDARD_MGMT_SERVICES, "keychain": keychain_available(),
            "key": {"session": bool(self.ai_keys.get(endpoint_id(cfg))), "env": bool(os.environ.get(cfg["key_env"])),
                    "env_name": cfg["key_env"], "keychain": bool(keychain_get(cfg["base_url"]))},
            "paths": {"inventory": os.path.abspath(path), "output": os.path.abspath(self.args.output_dir),
                      "private": os.path.abspath(self.args.private_dir)},
            "exists": os.path.exists(path)}}

    def api_settings_set(self, body):
        text = render_settings_model(body.get("model") or {})
        self.api_inventory_set({"text": text})      # validates, then writes with owner-only permissions
        return {"ok": True}

    def api_ai_test(self, body):
        cfg = ai_settings({"_ai": body.get("ai") or {}})
        key = resolve_ai_key(cfg, str(body.get("key") or ""), self.ai_keys)
        try:
            client = make_ai_client(cfg, key)          # checks the address first
            if not cfg["model"]:
                raise AiError("choose a model first (Find models lists the ones this endpoint offers)")
            client.timeout = min(client.timeout, 120)
            t0 = time.time()
            reply = client.chat([{"role": "user", "content": "Reply with the single word OK."}], retries=0)
        except AiError as e:
            raise Fatal(str(e))
        return {"ok": True, "seconds": round(time.time() - t0, 1), "reply": reply[:200], "used_key": bool(key),
                "note": client.note,
                "url": client.url if client.flavor == "openai" else client.native + "/query",
                "flavor": "OpenAI-compatible API" if client.flavor == "openai" else "native Ask Sage API"}

    def api_ai_profile(self, body):
        """Switch the AI service (and optionally remember a key) from the Investigate tab."""
        profile = str(body.get("profile") or "")
        if profile not in AI_PRESETS and profile != "custom":
            raise Fatal("unknown AI service '%s'" % profile)
        path = self.inventory_path()
        text = INVENTORY_TEMPLATE
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        model = read_settings_model(text)
        model["ai"]["profile"] = profile
        self.api_inventory_set({"text": render_settings_model(model)})
        cfg = ai_settings({"_ai": model["ai"]})
        if profile == "custom" and not cfg["base_url"]:
            raise Fatal("set up the other AI service on the Settings tab first")
        return {"ok": True, "key": self._key_state(cfg), "model": cfg["model"]}

    def api_ai_check(self, body):
        cfg = ai_settings({"_ai": body.get("ai") or {}})
        key, source = key_with_source(cfg, str(body.get("key") or ""), self.ai_keys)
        return {"text": ai_connection_check(cfg, key, source)}

    def api_ai_models(self, body):
        cfg = ai_settings({"_ai": dict(body.get("ai") or {}, model=(body.get("ai") or {}).get("model") or "-")})
        key = resolve_ai_key(cfg, str(body.get("key") or ""), self.ai_keys)
        try:
            client = make_ai_client(cfg, key)
            return {"models": client.list_models(), "base": client.base}
        except AiError as e:
            raise Fatal(str(e))

    def api_ai_key(self, body):
        action, key = body.get("action"), str(body.get("key") or "")
        cfg = ai_settings({"_ai": {"base_url": body.get("base_url") or "", "provider": body.get("provider") or "openai"}})
        if action == "forget":
            self.ai_keys.pop(endpoint_id(cfg), None)
            keychain_delete(cfg["base_url"])
            return {"ok": True, "key": self._key_state(cfg)}
        if not key:
            raise Fatal("enter the key first")
        self.ai_keys[endpoint_id(cfg)] = clean_key(key)
        if action == "save":
            if not cfg["base_url"]:
                raise Fatal("enter the endpoint URL first: the key is saved for that address")
            keychain_set(cfg["base_url"], clean_key(key))
        return {"ok": True, "key": self._key_state(cfg)}

    def _key_state(self, cfg):
        return {"session": bool(self.ai_keys.get(endpoint_id(cfg))), "env": bool(os.environ.get(cfg["key_env"])),
                "env_name": cfg["key_env"],
                "keychain": bool(keychain_get(cfg["base_url"]))}

    def api_open_folder(self, body):
        path = os.path.abspath(self.args.private_dir if body.get("which") == "private" else self.args.output_dir)
        os.makedirs(path, exist_ok=True)
        argv = ["open", path] if sys.platform == "darwin" else ["xdg-open", path]
        try:
            subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            raise Fatal("could not open the folder; it is %s" % path)
        return {"ok": True, "path": path}

    def api_investigate(self, body):
        """Start an AI investigation in the background."""
        with self.lock:
            if self.state == "running":
                raise Fatal("a collection or investigation is already running")
            self.state = "running"
        try:
            settings, sections, custom = load_inventory(self.inventory_path())
            cfg = ai_settings(settings)
            if not (cfg["base_url"] and cfg["model"]):
                raise Fatal("add an [ai] section with base_url and model to the inventory first")
            key = resolve_ai_key(cfg, str(body.get("key") or ""), self.ai_keys)
            if body.get("key"):
                self.ai_keys[endpoint_id(cfg)] = clean_key(str(body["key"]))
                if body.get("remember") and keychain_available():
                    keychain_set(cfg["base_url"], clean_key(str(body["key"])))
            problem = str(body.get("problem") or "").strip()
            if not problem:
                raise Fatal("describe the problem first")
            start = body.get("start") or "latest"
            creds = {}
            for name, c in (body.get("creds") or {}).items():
                creds[name] = {"user": str(c.get("user") or "").strip(), "password": str(c.get("password") or ""),
                               "su_password": c.get("su_password"), "sso_user": str(c.get("sso_user") or "").strip(),
                               "sso_password": str(c.get("sso_password") or "")}
            collect_plan = None
            if start == "collect":
                collect_plan, ccreds = self._plan_from_selection(body.get("collect") or {}, sections, custom)
                for name, c in ccreds.items():
                    if not (creds.get(name) or {}).get("password"):
                        creds[name] = c
            args = self._run_args(body, settings)
            ai = make_ai_client(cfg, key)
        except Exception:
            with self.lock:
                self.state = "idle"
            raise
        with self.lock:
            del self.lines[:]
            self.result, self.error, self.prompt = None, "", None
            self.inv = {"state": "running", "entries": [], "final": None, "error": "", "model": cfg["model"]}
            self.inv_stop.clear()
        threading.Thread(target=self._investigate, args=(args, settings, sections, cfg, ai, problem, start,
                                                         collect_plan, creds), daemon=True).start()
        return {"ok": True}

    def _final_public(self, f):
        if not f:
            return f
        f = dict(f)
        fixes = [e for e in f["manual"] if e["kind"] == "fix"]
        f["fix_script"] = plan_as_script(fixes, "Fix steps") if fixes else ""
        f["collect_script"] = plan_as_script(f["collect"], "Read-only diagnostics requested by the AI") \
            if f.get("collect") else ""
        return f

    def _inv_emit(self, kind, text):
        with self.lock:
            self.inv["entries"].append({"kind": kind, "text": text})

    def _inv_approve(self, prep):
        answer = self.ask({"kind": "approve", "plan": plan_public(prep)})
        return answer if answer in ("run", "manual") else "stop"

    def api_inv_reply(self, body):
        """The administrator continues the conversation: pasted output, a result or a question."""
        text = str(body.get("text") or "").strip()
        if not text:
            raise Fatal("type or paste your reply first")
        with self.lock:
            if self.state == "running":
                raise Fatal("the investigation is still working")
            if not self.inv_obj:
                raise Fatal("there is no investigation to continue - start one first")
            self.state = "running"
            del self.lines[:]
            self.prompt = None
            self.inv.update(state="running", final=None, error="")
            self.inv_stop.clear()
        kind = body.get("kind") if body.get("kind") in ("output", "fix-output", "message") else "message"
        threading.Thread(target=self._inv_continue, args=(text, kind), daemon=True).start()
        return {"ok": True}

    def _inv_continue(self, text, kind):
        state, error, final = "finished", "", None
        inv = self.inv_obj
        inv.ui = CachedUI(GuiUI(self, {}))        # logins are asked for again when needed
        try:
            final = inv.continue_with(text, kind)
        except (AiError, Fatal) as e:
            state, error = "error", str(e)
        except Exception as e:
            state, error = "error", "unexpected error: %r" % (e,)
        finally:
            inv.ui.creds.clear()
            with self.lock:
                self.ctx, self.prompt = None, None
                self.inv.update(state=state, error=error, final=final)
                self.state = "idle"

    def _investigate(self, args, settings, sections, cfg, ai, problem, start, collect_plan, creds):
        state, error, final = "finished", "", None
        ui = CachedUI(GuiUI(self, creds))
        try:
            start_text = None
            if start == "latest":
                path = latest_report(args)
                if path:
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        start_text = fh.read()
                    self._inv_emit("status", "Starting from the latest report: %s" % os.path.basename(path))
                else:
                    self._inv_emit("warn", "No earlier report found; the AI starts from the description only.")
            elif start == "collect":
                self._inv_emit("status", "Collecting the selected health checks first ...")
                res = collect_and_report(args, settings, sections, collect_plan, ui,
                                         on_context=lambda ctx: setattr(self, "ctx", ctx))
                if res is None:
                    raise Fatal("the starting collection was cancelled")
                start_text = res["report"]
                self._inv_emit("report", res["path"])

            def collect(a, st, secs, plan, u, kind, title):
                return collect_and_report(a, st, secs, plan, u, kind=kind, title=title,
                                          on_context=lambda ctx: setattr(self, "ctx", ctx))

            self.inv_obj = Investigation(args, ai, cfg, problem, ui, self._inv_emit, self._inv_approve,
                                         stopped=self.inv_stop.is_set, start_report=start_text, collect=collect)
            final = self.inv_obj.run()
        except (AiError, Fatal) as e:
            state, error = "error", str(e)
        except Exception as e:
            state, error = "error", "unexpected error: %r" % (e,)
        finally:
            creds.clear()
            ui.creds.clear()
            with self.lock:
                self.ctx, self.prompt = None, None
                self.inv.update(state=state, error=error, final=final)
                self.state = "idle"

    def api_plan(self, body):
        text = str(body.get("text", ""))
        if not text.strip():
            raise Fatal("paste the reply first")
        return plan_public(prepare_plan(self.args, text))

    def api_plan_run(self, body):
        """Run the read-only diagnostics of a pasted reply. Fix steps are never run."""
        with self.lock:
            if self.state == "running":
                raise Fatal("a collection is already running")
            self.state = "running"
        try:
            prep = prepare_plan(self.args, str(body.get("text", "")))
            if not prep["plan"]:
                raise Fatal("this reply contains no read-only diagnostics to run")
            creds = {}
            for item in prep["plan"]:
                name = item["sec"]["name"]
                sel = (body.get("sections") or {}).get(name) or {}
                if not sel.get("password"):
                    raise Fatal("no password given for [%s]" % name)
                creds[name] = {"user": str(sel.get("user") or "").strip(), "password": str(sel["password"]),
                               "su_password": sel.get("su_password")}
            args = self._run_args(body, prep["settings"])
        except Exception:
            with self.lock:
                self.state = "idle"
            raise
        return self._start(args, prep["settings"], prep["sections"], prep["plan"], creds, "followup", prep["title"])

    def _run(self, args, settings, sections, plan, creds, kind="health", title=""):
        state, result, error = "error", None, ""
        try:
            result = collect_and_report(args, settings, sections, plan, GuiUI(self, creds),
                                        on_context=lambda ctx: setattr(self, "ctx", ctx),
                                        kind=kind, title=title)
            state = "done" if result else "cancelled"
        except Fatal as e:
            error = str(e)
        except Exception as e:
            error = "unexpected error: %r" % (e,)
        finally:
            creds.clear()
            with self.lock:
                self.ctx, self.prompt = None, None
                self.result, self.error, self.state = result, error, state

    def api_status(self, since):
        with self.lock:
            out = {"state": self.state, "lines": self.lines[since:], "next": len(self.lines),
                   "prompt": self.prompt, "error": self.error, "result": None,
                   "inv": dict(self.inv, entries=list(self.inv["entries"]),
                               final=self._final_public(self.inv.get("final"))) if self.inv else None}
            r = self.result
            if self.state == "done" and r:
                out["result"] = {k: r[k] for k in ("path", "total", "failed", "review", "targets")}
                out["result"]["size_kb"] = int(round(len(r["report"]) / 1024.0))
                out["result"]["tokens_k"] = max(1, len(r["report"]) // 3500)
        return out

    def api_answer(self, body):
        with self.lock:
            if not self.prompt:
                return {"ok": False}
            if self.prompt.get("kind") == "approve":
                d = body.get("decision")
                self.answer = d if d in ("run", "manual", "stop") else ("run" if body.get("approve") else "stop")
                self.answered.set()
                return {"ok": True}
            self.answer = None if body.get("skip") or not body.get("password") else (
                str(body.get("user") or self.prompt["user"]).strip(), str(body["password"]),
                body.get("su_password") or None)
        self.answered.set()
        return {"ok": True}

    def api_reveal(self):
        if not self.result:
            raise Fatal("there is no report yet")
        path = self.result["path"]
        argv = ["open", "-R", path] if sys.platform == "darwin" else ["xdg-open", os.path.dirname(path)]
        try:
            subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            raise Fatal("could not open the file manager; the report is at %s" % path)
        return {"ok": True}

    def api_scrub(self, body):
        text = str(body.get("text", ""))
        if not text.strip():
            raise Fatal("paste some text first")
        scrubber, results = scrub_texts(self.args, [text])
        return {"text": results[0], "review": review_data(scrubber, results[0])}

    def api_decode(self, body):
        text = str(body.get("text", ""))
        if not text.strip():
            raise Fatal("paste some text first")
        return {"text": decode_text(self.args, text)}

    def handle(self, method, route, query, body):
        if method == "GET":
            if route == "state":
                return self.api_state()
            if route == "status":
                return self.api_status(max(0, int((query.get("since") or ["0"])[0])))
            if route == "inventory":
                return self.api_inventory_get()
            if route == "report":
                return {"text": self.result["report"] if self.result else ""}
            if route == "settings":
                return self.api_settings_get()
        elif method == "POST":
            if route == "inventory":
                return self.api_inventory_set(body)
            if route == "run":
                return self.api_run(body)
            if route == "plan":
                return self.api_plan(body)
            if route == "plan_run":
                return self.api_plan_run(body)
            if route == "investigate":
                return self.api_investigate(body)
            if route == "inv_reply":
                return self.api_inv_reply(body)
            if route == "settings":
                return self.api_settings_set(body)
            if route == "ai_test":
                return self.api_ai_test(body)
            if route == "ai_models":
                return self.api_ai_models(body)
            if route == "ai_check":
                return self.api_ai_check(body)
            if route == "ai_profile":
                return self.api_ai_profile(body)
            if route == "ai_key":
                return self.api_ai_key(body)
            if route == "open_folder":
                return self.api_open_folder(body)
            if route == "answer":
                return self.api_answer(body)
            if route == "cancel":
                self.cancel()
                return {"ok": True}
            if route == "reveal":
                return self.api_reveal()
            if route == "scrub":
                return self.api_scrub(body)
            if route == "decode":
                return self.api_decode(body)
            if route == "quit":
                self.cancel()
                threading.Thread(target=self.httpd.shutdown, daemon=True).start()
                return {"ok": True}
        return None


class GuiHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "vcf_diag"
    sys_version = ""

    def log_message(self, *a):          # keep the terminal for progress lines only
        pass

    def _reply(self, code, payload, ctype="application/json"):
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                         "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)

    def _route(self):
        """Return (route, query) for an authorised request, else None.
        The page is only for the browser on this machine that was given the secret URL."""
        gui = self.server.gui
        port = self.server.server_address[1]
        if self.headers.get("Host", "") not in ("127.0.0.1:%d" % port, "localhost:%d" % port):
            return None
        origin = self.headers.get("Origin")
        if origin and origin not in ("http://127.0.0.1:%d" % port, "http://localhost:%d" % port):
            return None
        parsed = urllib.parse.urlsplit(self.path)
        parts = parsed.path.split("/", 2)
        if len(parts) < 3 or not pysecrets.compare_digest(parts[1], gui.token):
            return None
        return parts[2], urllib.parse.parse_qs(parsed.query)

    def _serve(self, method):
        r = self._route()
        if r is None:
            return self._reply(403, {"error": "forbidden"})
        route, query = r
        if method == "GET" and route == "":
            return self._reply(200, GUI_HTML.encode("utf-8"), "text/html")
        if not route.startswith("api/"):
            return self._reply(404, {"error": "not found"})
        body = {}
        if method == "POST":
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if n > 16 * 1024 * 1024:
                    return self._reply(413, {"error": "that text is too large (16 MB limit)"})
                body = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._reply(400, {"error": "bad request"})
        try:
            out = self.server.gui.handle(method, route[4:], query, body)
        except Fatal as e:
            return self._reply(400, {"error": str(e)})
        except Exception as e:
            return self._reply(500, {"error": "unexpected error: %r" % (e,)})
        if out is None:
            return self._reply(404, {"error": "not found"})
        return self._reply(200, out)

    def do_GET(self):
        self._serve("GET")

    def do_POST(self):
        self._serve("POST")


def cmd_gui(args):
    gui = Gui(args)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), GuiHandler)
    httpd.daemon_threads = True
    httpd.gui = gui
    gui.httpd = httpd
    url = "http://127.0.0.1:%d/%s/" % (httpd.server_address[1], gui.token)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: sys.exit(143))
    print("vcf_diag %s - the window opens in your browser. If it does not, open this address:" % VERSION)
    print("  " + url)
    print("Only this computer can reach it. Leave this terminal open; press Ctrl-C here to stop.\n")
    if not args.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        gui.cancel()
        httpd.server_close()
    print("\nStopped.")
    return 0


SELF_TEST = """\
Fully Qualified Domain Name: esx01.corp.acme-widgets.com
vmk0 10.20.30.41 netmask 255.255.255.0 mac 00:50:56:ab:cd:ef gw 10.20.30.1 mtu 9000
vmk1 10.20.31.41 ESX01 is also esx01-vmk1 and ip-10-20-30-41
NTP server ntp1.corp.acme-widgets.com and 0.vmware.pool.ntp.org, peer VC01.CORP.ACME-WIDGETS.COM
Version: 9.1.1.0 build-24812345   "version":"9.0.2.0"   VCF 9.1.1.0
Serial Number: 7XK2P93
UUID: 4c4c4544-0038-4b10-8032-b7c04f503933 volume 5f3c2a1b-8d7e6f5a-4b3c-2a1b0c9d8e7f
Device naa.600508b1001c5e3a9f2d4b7c8e1f0a2b on vmhba0, fe80::250:56ff:feab:cdef and ::1
subject= /C=US/O=Acme Widgets Inc/CN=vc01.corp.acme-widgets.com
SHA1 Fingerprint=AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01
password = "Sup3rS3cret!"   api_token: abcdef123456   Password expires : never
-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBa
-----END CERTIFICATE-----
/vmfs/volumes/5f3c2a1b-8d7e6f5a-4b3c-2a1b0c9d8e7f  ACME-PROD-DS01  5f3c2a1b-8d7e6f5a-4b3c-2a1b0c9d8e7f  true  VMFS-6  1099511627776  549755813888
mail admin@acme-widgets.com, mirror at files.partner-example.net, svc kubernetes.default.svc.cluster.local
Project Zephyr rollout on LICENSE AB1CD-EF2GH-IJ3KL-MN4OP-QR5ST
"""


def cmd_self_test():
    sc = Scrubber(Mapping(None), terms=["Zephyr"], keep_literals=["9.1.1.0"])
    sc.learn_host("esx01.corp.acme-widgets.com", prefix="esxi")
    sc.learn_host("vc01.corp.acme-widgets.com", prefix="vcenter")
    sc.learn("datastore", "ACME-PROD-DS01")
    sc.prescan(SELF_TEST)
    sc.compile()
    out = sc.scrub(SELF_TEST)
    must_go = ["esx01", "vc01", "acme", "10.20.30", "10.20.31", "00:50:56", "7XK2P93", "4c4c4544",
               "5f3c2a1b", "600508b1", "fe80::250", "Sup3rS3cret", "abcdef123456", "MIIDdz",
               "AB:CD:EF", "Zephyr", "partner-example", "AB1CD", "10-20-30-41", "ACME"]
    must_stay = ["255.255.255.0", "9.1.1.0", "9.0.2.0", "0.vmware.pool.ntp.org", "::1", "mtu 9000",
                 "Password expires : never", "svc.cluster.local", "esxi-01.domain-01",
                 "VCENTER-01.DOMAIN-01", "ip-n1-h1", "vmhba0", "build-24812345"]
    bad = [s for s in must_go if s.lower() in out.lower()] + \
          ["(missing) " + s for s in must_stay if s not in out]
    print(out)
    if bad or sc.leak_check(out):
        print("SELF-TEST FAILED:", bad, sc.leak_check(out))
        return 1
    print("SELF-TEST PASSED")
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) >= 1 and argv[0] == "--askpass-helper":
        return askpass_helper_main(argv[1] if len(argv) > 1 else "")
    ap = argparse.ArgumentParser(
        description="Collect anonymized health and status diagnostics from a VCF 9.x environment.",
        epilog="With no options the tool reads inventory.ini and asks what to collect and where.")
    ap.add_argument("-i", "--inventory", help="inventory file (default: ./inventory.ini)")
    ap.add_argument("-o", "--output-dir", default="vcf-diag-output", help="where reports are written")
    ap.add_argument("--private-dir", default="vcf-diag-private",
                    help="where the private placeholder mapping is kept (never share)")
    ap.add_argument("--gui", action="store_true",
                    help="open the graphical interface in your browser (served to this computer only)")
    ap.add_argument("--no-browser", action="store_true", help="with --gui: print the address, do not open it")
    ap.add_argument("--init", action="store_true", help="write a template inventory file and exit")
    ap.add_argument("--list", action="store_true", help="list every check the tool can run and exit")
    ap.add_argument("--all", action="store_true",
                    help="select every component, host and check without menus (passwords are still asked)")
    ap.add_argument("--dry-run", action="store_true", help="show the plan, contact nothing")
    ap.add_argument("--parallel", type=int, help="hosts contacted at the same time (default 4)")
    ap.add_argument("--connect-timeout", type=int, help="SSH connect timeout in seconds (default 15)")
    ap.add_argument("--timeout-scale", type=float, help="multiply every command timeout by this factor")
    ap.add_argument("--max-lines", type=int,
                    help="output lines kept per check (default: max_lines in the inventory, else 200)")
    ap.add_argument("--no-anonymize", action="store_true",
                    help="keep real names and addresses in the report (secrets are still redacted)")
    ap.add_argument("--strict-host-keys", action="store_true",
                    help="only connect to hosts already in known_hosts (default: trust on first use)")
    ap.add_argument("--scrub-file", nargs="+", metavar="FILE",
                    help="anonymize existing text files with the same mapping, then exit")
    ap.add_argument("--investigate", nargs="?", const="", metavar="PROBLEM",
                    help="let the AI in the [ai] section investigate a problem: it asks for read-only diagnostics, "
                         "you approve each round, and it ends with the root cause and fix steps (never run)")
    ap.add_argument("--ai-check", action="store_true",
                    help="check the connection to the AI in the [ai] section step by step, then exit")
    ap.add_argument("--start", choices=("latest", "collect", "none"),
                    help="with --investigate: start from the latest report (default), a new collection, or nothing")
    ap.add_argument("--report", metavar="FILE", help="with --investigate: start from this report")
    ap.add_argument("--plan", metavar="FILE",
                    help="read an analyst reply: show its fixes translated to real names (never run) and "
                         "offer to run the read-only diagnostics it asks for")
    ap.add_argument("--decode", metavar="FILE",
                    help="print FILE with placeholders translated back to real names (local use only)")
    ap.add_argument("--self-test", action="store_true", help="test the anonymizer and exit")
    ap.add_argument("--version", action="version", version="vcf_diag " + VERSION)
    args = ap.parse_args(argv)
    try:
        return dispatch(args)
    except Fatal as e:
        print("error: %s" % e, file=sys.stderr)
        return e.code


def dispatch(args):
    if args.self_test:
        return cmd_self_test()
    if args.init:
        return cmd_init(args)
    if args.list:
        return cmd_list(args)
    if args.decode:
        return cmd_decode(args)
    if args.scrub_file:
        return cmd_scrub_files(args)
    if args.ai_check:
        cfg = ai_settings(load_inventory(find_inventory(args) or "inventory.ini")[0])
        key, source = key_with_source(cfg)
        if not key:
            key, source = getpass.getpass("API key (hidden; Return for none): "), "typed at the prompt"
        print(ai_connection_check(cfg, key, source))
        return 0
    if args.investigate is not None:
        return cmd_investigate(args)
    if args.plan:
        return cmd_plan(args)
    if args.gui:
        return cmd_gui(args)
    try:
        return cmd_collect(args)
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        return 130


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except BrokenPipeError:      # e.g. output piped into "head"
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
