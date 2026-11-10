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
import struct
import subprocess
import sys
import tempfile
import termios
import textwrap
import threading
import time
import urllib.parse
import webbrowser

VERSION = "1.2.0"

# ----------------------------------------------------------------------------
# Diagnostic catalog
# ----------------------------------------------------------------------------
# mode: "sh"      POSIX shell command (bash / ESXi ash)
#       "nsxcli"  NSX CLI command (run directly as admin, or wrapped when root)
#       "kubectl" shell command using {K} as the kubectl binary
# harvest: (category, regex-with-one-group, split-regex-or-None). Captured
#          values are registered as names to anonymize everywhere in the report.


def cmd(label, command, timeout=30, mode="sh", harvest=(), max_lines=None, k8s=None):
    return {"label": label, "cmd": command, "timeout": timeout, "mode": mode,
            "harvest": tuple(harvest), "max_lines": max_lines, "k8s": k8s}


def ncli(label, command, **kw):
    return cmd(label, command, mode="nsxcli", **kw)


def kctl(label, command, **kw):
    kw.setdefault("timeout", 45)
    return cmd(label, command, mode="kubectl", **kw)


H_SEARCH = ("domain", r"(?m)^\s*(?:search|domain)\s+(.+)$", r"[\s,]+")


def linux_groups():
    return [
        ("os", "OS, uptime, CPU, memory, disk", [
            cmd("OS release", "head -n 6 /etc/os-release 2>/dev/null"),
            cmd("Uptime and load", "uptime"),
            cmd("Memory", "free -m"),
            cmd("Disk usage", "df -hP"),
            cmd("Inode usage", "df -iP"),
            cmd("Top processes", "top -bn1 2>/dev/null | head -n 17"),
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
        ("cert", "Local HTTPS certificate", [
            cmd("Certificate on port 443",
                "echo | timeout 10 openssl s_client -connect localhost:443 2>/dev/null"
                " | openssl x509 -noout -subject -issuer -dates 2>&1"),
        ]),
    ]


K8S_GROUPS = [
    ("k8s-cluster", "Kubernetes API and nodes", [
        kctl("API server version", "{K} version 2>&1 | head -n 6"),
        kctl("API readiness checks", "{K} get --raw='/readyz?verbose' 2>&1 | tail -n 70"),
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
        kctl("Pod status counts per namespace",
             "{K} get pods -A --no-headers 2>&1 | awk '{c[$1\" \"$4]++} END{for(k in c) print k, c[k]}'"
             " | sort", k8s="nsrows", max_lines=300),
        kctl("Pods with most restarts",
             "{K} get pods -A --no-headers 2>&1 | awk '$5+0>0' | sort -k5 -n -r | head -n 30",
             k8s="nsrows"),
        kctl("All pods", "{K} get pods -A -o wide 2>&1", k8s="nsrows", max_lines=900),
        kctl("Deployments, StatefulSets, DaemonSets", "{K} get deploy,sts,ds -A 2>&1",
             k8s="nsrows", max_lines=500),
    ]),
    ("k8s-storage", "Persistent storage", [
        kctl("Persistent volume claims", "{K} get pvc -A 2>&1", k8s="nsrows", max_lines=300),
        kctl("Persistent volumes", "{K} get pv 2>&1", max_lines=300),
    ]),
    ("k8s-events", "Warning events", [
        kctl("Latest warning events",
             "{K} get events -A --field-selector type!=Normal --sort-by=.lastTimestamp 2>&1"
             " | tail -n 80", k8s="nsrows"),
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
    ("vc-storage", "Appliance partitions and core dumps", [
        cmd("Key partitions", "df -hP /storage/log /storage/db /storage/seat /storage/core 2>&1"),
        cmd("Core dumps", "ls -lh /storage/core 2>&1 | tail -n 15"),
    ]),
] + linux_groups()

NSX_NODE_CMDS = [
    ncli("Uptime", "get uptime"),
    ncli("CPU", "get cpu-stats"),
    ncli("Memory", "get memory-stats"),
    ncli("Filesystems", "get filesystem-stats"),
    ncli("Core dumps", "get core-dumps"),
    ncli("NTP servers", "get ntp-servers"),
    ncli("NTP associations", "get ntp-server associations"),
    ncli("DNS servers", "get name-servers"),
]

NSX_GROUPS = [
    ("nsx-cluster", "Management cluster and services", [
        ncli("Version", "get version"),
        ncli("Cluster status", "get cluster status", timeout=60),
        ncli("Cluster configuration", "get cluster config", timeout=60, max_lines=300),
        ncli("Managers", "get managers"),
        ncli("Services", "get services", timeout=60, max_lines=400),
    ]),
    ("nsx-node", "Node resources, time, DNS", NSX_NODE_CMDS),
    ("os", "OS level (root shell only)", [
        cmd("Disk usage", "df -hP"),
        cmd("Failed units", "systemctl --failed --no-pager --no-legend 2>&1 | head -n 40"),
        cmd("Password ageing", "for u in root admin audit; do echo \"== $u\";"
                               " chage -l \"$u\" 2>&1 | head -n 4; done"),
    ]),
]

NSXEDGE_GROUPS = [
    ("edge-status", "Edge cluster and connectivity", [
        ncli("Version", "get version"),
        ncli("Managers", "get managers"),
        ncli("Controllers", "get controllers"),
        ncli("Edge cluster status", "get edge-cluster status", timeout=60),
        ncli("Maintenance mode", "get maintenance-mode"),
        ncli("Logical routers", "get logical-routers",
             harvest=[("lrouter",
                       r"(?m)^[0-9a-fA-F-]{36}\s+\d+\s+\d+\s+(\S+)\s+[A-Z][A-Z0-9_]+", None)]),
        ncli("Services", "get services", timeout=60, max_lines=300),
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
] + linux_groups()

COMPONENTS = {
    "esxi": {"title": "ESXi hosts", "user": "root", "prefix": "esxi", "groups": ESXI_GROUPS},
    "vcenter": {"title": "vCenter Server", "user": "root", "prefix": "vcenter",
                "groups": VCENTER_GROUPS, "pty_escalate": "shell"},
    "nsx": {"title": "NSX Manager", "user": "admin", "prefix": "nsxmgr", "groups": NSX_GROUPS,
            "nsxcli": True, "nsxcli_wrap": "su admin -c {q}"},
    "nsxedge": {"title": "NSX Edge", "user": "admin", "prefix": "nsxedge",
                "groups": NSXEDGE_GROUPS, "nsxcli": True, "nsxcli_wrap": "nsxcli -c {q}"},
    "sddc": {"title": "SDDC Manager", "user": "vcf", "prefix": "sddcmgr", "groups": SDDC_GROUPS},
    "k8s": {"title": "Kubernetes control plane (VCF services runtime, Operations, Automation)",
            "user": "vmware-system-user", "prefix": "k8snode",
            "groups": K8S_GROUPS + linux_groups(), "sudo": "auto"},
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
#   linux    Any other Linux appliance, e.g. Operations for logs / networks
#
# Per-section options (all optional):
#   user       = default username offered at the prompt
#   port       = SSH port (default 22)
#   sudo       = auto | yes | no    run commands through sudo (k8s default: auto)
#   escalate   = su                 log in, then "su -" (asks for the root password)
#   kubeconfig = /path/admin.conf   k8s only; auto-detected when omitted
#   kubectl    = /path/to/kubectl   k8s only; default "kubectl"

[settings]
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

[nsx]
hosts =

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
    r"private[_-]key|credential)[\w.-]*[\"']?\s*[:=]\s*)(\"[^\"\n]*\"|'[^'\n]*'|[^\s\"',;]+)")
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
RX_DOTTED_QUAD = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?!\.?\d)(?!\w)")

OBJECT_CATS = {"datastore": "datastore", "portgroup": "portgroup", "dvs": "dvs", "vm": "vm",
               "namespace": "ns", "k8sobj": "k8sobj", "lrouter": "lrouter", "term": "term"}


class Scrubber:
    def __init__(self, mapping, extra_domains=(), terms=(), keep_literals=(), keep_namespaces=()):
        self.m = mapping
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
        if len(v) < 3 or v.lower() in DEFAULT_OBJECT_NAMES or v.isdigit():
            return None
        if re.fullmatch(r"(?i)(vSwitch|vmk|vmnic|vusb|eth|ens)\d+", v):
            return None
        return self.m.get(cat, v, prefix=OBJECT_CATS.get(cat, cat), width=4)

    def learn(self, cat, value):
        if cat == "host":
            return self.learn_host(value)
        if cat == "domain":
            return self.learn_domain(value)
        return self.learn_term(cat, value)

    def learn_k8s(self, kind, text):
        """Learn node names and organisation-specific namespaces from kubectl tables."""
        for line in text.splitlines():
            cols = line.split()
            if not cols or cols[0] in ("NAMESPACE", "NAME", "No", "Error", "error:"):
                continue
            if kind == "nodes":
                if len(cols) >= 3 and cols[1] in ("Ready", "NotReady") or (
                        len(cols) >= 3 and cols[1].startswith(("Ready,", "NotReady,"))):
                    self.learn_host(cols[0], prefix="k8snode")
            elif kind in ("ns", "nsrows"):
                ns = cols[0]
                if not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", ns) or self.keep_ns_rx.match(ns):
                    continue
                if kind == "ns" and (len(cols) < 2 or cols[1] not in ("Active", "Terminating")):
                    continue
                self.learn_term("namespace", ns)
                if kind == "nsrows" and len(cols) > 1:
                    for c in cols[1:]:
                        name = c.split("/", 1)[1] if "/" in c else (c if c is cols[1] else "")
                        if re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,}", name) and not name.isdigit():
                            self.learn_term("k8sobj", name)

    def prescan(self, text):
        """Discover IPs, version literals and FQDNs before scrubbing, so that every
        form of a name (short, dashed IP ...) is known when the report is written."""
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
                loose[real] = ph
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
        t = RX_KV_SECRET.sub(lambda m: m.group(1) + self._tok("[REDACTED]"), t)
        t = RX_HASH.sub(lambda m: self._tok("[REDACTED-HASH]"), t)
        t = RX_SSHKEY.sub(lambda m: self._tok("[REDACTED-KEY]"), t)
        t = RX_BLOB.sub(lambda m: self._tok("[REDACTED-ENCODED-DATA]"), t)
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
    def __init__(self, ctx, section, address, placeholder):
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
        return ["-S", self.ctl, "-p", str(self.sec["port"]), "-l", self.user] + self.sec["ssh_options"]

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
            self.errmsg = "SSH host key not trusted or changed (check ~/.ssh/known_hosts)"
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
            self.mode = "nsxcli"
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
            if self.sec["type"] == "k8s":
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
        if self.mode == "nsxcli":
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
                res.update(status="skipped", note="needs a root shell (logged in to the NSX CLI)")
                return res
            sudo = self.sudo if (self.sec.get("sudo") == "yes") else None
            rc, out, to = self.sh(command, c["timeout"], sudo=sudo)
        elif c["mode"] == "nsxcli":
            if self.mode == "nsxcli":
                rc, out, to = self.exec(command, c["timeout"])
            else:
                rc, out, to = self.sh(self.comp["nsxcli_wrap"].format(q=shlex.quote(command)) + " 2>&1",
                                      c["timeout"])
        else:  # kubectl
            if not self.kube:
                res.update(status="skipped", note=self.kube_note or "kubectl is not available")
                return res
            command = command.replace("{K}", self.kube["kubectl"])
            res["cmd"] = command
            pre = "export KUBECONFIG=%s; " % shlex.quote(self.kube["kubeconfig"]) \
                if self.kube["kubeconfig"] else ""
            rc, out, to = self.sh(pre + command, c["timeout"], sudo=self.kube["sudo"])
        res.update(rc=rc, out=out, dur=time.time() - t0)
        if to:
            res.update(status="timeout", note="timed out after %ds" % c["timeout"])
        elif rc != 0:
            res["status"] = "fail"
        return res


def collect_target(t, groups, progress):
    """Connect (if needed), detect, and run every selected command on one target."""
    try:
        if not t.connected and not t.connect():
            progress(t, "FAILED: " + t.errmsg)
            return
        if not t.detect():
            t.errkind = t.errkind or "error"
            progress(t, "FAILED: " + t.errmsg)
            return
        t.probe_identity()
        todo = [(g, c) for g in groups for c in g[2]]
        for g, c in todo:
            if t.ctx.cancel.is_set():
                break
            t.results.append(t.run_catalog(g, c))
        bad = sum(1 for r in t.results if r["status"] in ("fail", "timeout"))
        skipped = sum(1 for r in t.results if r["status"] == "skipped")
        progress(t, "done: %d commands, %d failed, %d skipped (%s)" % (len(t.results), bad, skipped, t.mode))
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
    sections, custom = [], {}
    for name in cp.sections():
        if name == "settings":
            continue
        typ, _, label = name.partition(":")
        typ, label = typ.strip().lower(), label.strip()
        if typ == "commands":
            if label not in COMPONENTS:
                die("inventory: [%s] refers to unknown component type '%s'" % (name, label))
            custom[label] = [(k, v) for k, v in cp[name].items()]
            continue
        if typ not in COMPONENTS:
            die("inventory: unknown component type in section [%s]. Valid types: %s"
                % (name, ", ".join(COMPONENTS)))
        s = cp[name]
        hosts = list(dict.fromkeys(split_list(s.get("hosts", ""))))
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
        sections.append({
            "name": name, "type": typ, "label": label, "prefix": prefix, "hosts": hosts,
            "user": (s.get("user") or COMPONENTS[typ]["user"]).strip(),
            "port": int(s.get("port", "22")), "sudo": sudo, "escalate": esc,
            "kubeconfig": (s.get("kubeconfig") or "").strip() or None,
            "kubectl": (s.get("kubectl") or "").strip() or None,
            "ssh_options": shlex.split(s.get("ssh_options", "")),
        })
    return settings, sections, custom


def groups_for(typ, custom):
    groups = list(COMPONENTS[typ]["groups"])
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
        groups = groups_for(s["type"], custom)
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
    for item in plan:
        creds[item["sec"]["name"]] = ui.initial_credentials(item["sec"])
    log()

    def progress(t, msg):
        log("  [%s] %-40s %s" % (t.sec["name"], t.address, msg))

    for item in plan:
        if ctx.cancel.is_set():
            break
        sec = item["sec"]
        targets = []
        for addr in item["hosts"]:
            if is_ip(addr):
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

        def groups_of(t):
            return item.get("host_groups", {}).get(t.address, item["groups"])

        apply(targets, creds[sec["name"]])
        log("[%s] %d host(s), %d check(s) in total" % (
            sec["name"], len(targets), sum(len(g[2]) for t in targets for g in groups_of(t))))
        # Canary: try the first host alone, so a mistyped password costs one failed
        # login on one host instead of one on every host (account lockout protection).
        first, rest = targets[0], targets[1:]
        tries = 0
        while not first.connect() and first.errkind == "auth" and tries < 2:
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
        done.append((item, targets))
    return done


def learn_from_results(done, scrubber):
    """Feed everything we collected into the scrubber before any text is written."""
    texts = []
    for item, targets in done:
        for t in targets:
            for name in t.identity:
                short = name.split(".")[0].lower()
                if "." in name:
                    scrubber.learn_domain(name.split(".", 1)[1])
                if short not in GENERIC_NAMES and not short.isdigit():
                    scrubber.m.alias("host", short, t.ph)
            if t.errmsg:
                texts.append(t.errmsg)
            for r in t.results:
                spec = r["spec"]
                for cat, rx, split in spec["harvest"]:
                    for m in re.finditer(rx, r["out"]):
                        for v in (re.split(split, m.group(1)) if split else [m.group(1)]):
                            scrubber.learn(cat, v)
                if spec["k8s"]:
                    scrubber.learn_k8s(spec["k8s"], r["out"])
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


def build_report(ctx, done, scrubber, started, max_lines, kind="health", title=""):
    S = scrubber.scrub
    out = []
    w = out.append
    w("# VCF anonymized %s report" % ("follow-up" if kind == "followup" else "diagnostic"))
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
    w(LEGEND)
    w("")
    w("## How to reply (for the analyst)")
    w("")
    w(ANALYST_GUIDE)
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
            failed = [S(r["label"]) for r in t.results if r["status"] == "fail"]
            if timed:
                attention.append("- %s: timed out: %s" % (t.ph, "; ".join(timed)))
            if failed:
                attention.append("- %s: non-zero exit status: %s" % (t.ph, "; ".join(failed)))
    w("")
    w("### Items needing attention (collection level)")
    w("")
    out.extend(attention or ["- none"])
    w("")
    w("A non-zero exit status is not always a fault: a check for a feature that is not in use")
    w("(vSAN, NSX, a missing tool) also ends that way. Read the output before concluding.")
    for item, targets in done:
        sec = item["sec"]
        w("")
        w("## [%s] %s" % (sec["name"], COMPONENTS[sec["type"]]["title"]))
        for t in targets:
            w("")
            w("### %s" % t.ph)
            w("")
            if t.errkind:
                w("Not collected: %s - %s" % (t.errkind, S(t.errmsg)))
                continue
            info = ["user `%s`" % S(t.user), "shell mode `%s`" % t.mode]
            if t.identity:
                short, _, dom = t.identity[0].lower().partition(".")
                name = scrubber.m.lookup("host", short) or t.ph
                if dom:
                    name += "." + (scrubber.m.lookup("domain", dom) or "domain-unknown")
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
                w("`$ %s`" % S(r["cmd"]).replace("`", "'"))
                body = S(clip(r["out"], r["spec"]["max_lines"] or max_lines)).strip("\n")
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
    quads = {}
    for m in RX_DOTTED_QUAD.finditer(text):
        if is_plain_ipv4(m.group(0)):
            quads[m.group(0)] = quads.get(m.group(0), 0) + 1
    return {"hits": sorted(scrubber.leak_check(text).items(), key=lambda kv: -kv[1]),
            "quads": sorted(quads.items()),
            "known": sum(len(v) for c, v in scrubber.m.maps.items() if c != "ipv4net")}


def print_review(data):
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
def make_scrubber(args, settings):
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
        report = build_report(ctx, done, scrubber, started, args.max_lines, kind=kind, title=title)
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
    print("Mapping: %s  (PRIVATE - never share)" % os.path.join(args.private_dir, "mapping.json"))
    print("\nOpen the report and skim it before sharing. Use --decode to translate an analysis back.")


# ----------------------------------------------------------------------------
# Analyst replies: follow-up diagnostics (run, read-only) and fixes (translated
# for the person to apply by hand - this tool never runs a fix)
# ----------------------------------------------------------------------------
ANALYST_GUIDE = """\
The person who sent this report works in an isolated environment. Their tool translates your
reply back to real names, so always refer to hosts, addresses, domains and objects by the
placeholders exactly as they appear here. Write your analysis as normal prose. When you need
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

- `target=` takes one or more host placeholders from this report, comma separated, or
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


def prepare_plan(args, text):
    """Translate an analyst reply and sort its steps into: read-only diagnostics the tool
    may run, and everything else, which is only shown for the person to apply by hand."""
    inv = find_inventory(args)
    if not inv:
        die("no inventory file found - the reply refers to hosts in your inventory")
    settings, sections, _ = load_inventory(inv)
    mapping = Mapping(os.path.join(args.private_dir, "mapping.json"))
    dec = Decoder(mapping)
    if not dec.rev:
        die("no mapping found in %s - run a collection first" % args.private_dir)
    known, by_addr = {}, {}
    for s in sections:
        for addr in s["hosts"]:
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
            elif tok.lower().split(".")[0] in known:
                resolved.append(known[tok.lower().split(".")[0]])
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
                    max_lines=_clamp(st["lines"], 400, 20, 5000)))
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
    <button class="btn" id="editInv">Edit inventory</button>
    <button class="btn" id="quit">Quit</button>
  </div>
  <nav role="tablist">
    <button role="tab" data-tab="collect" aria-selected="true">Collect</button>
    <button role="tab" data-tab="reply" aria-selected="false">Analyst reply</button>
    <button role="tab" data-tab="scrub" aria-selected="false">Anonymize text</button>
  </nav>
</div></header>

<main>
<div id="stopped" class="note" hidden>The tool has stopped. You can close this tab.</div>

<section id="tab-collect">
  <div id="problem" class="note bad" hidden></div>
  <div id="empty" class="note warn" hidden>
    The inventory has no hosts yet. Click <b>Edit inventory</b> and list your hosts under the matching sections.
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
          <input type="number" id="optLines" min="20" max="5000" value="200"></label>
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
  ["collect", "reply", "scrub"].forEach(t => $("#tab-" + t).hidden = t !== b.dataset.tab);
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
    const det = el("details", {}, el("summary", { textContent: "Choose hosts and checks" }),
      el("div", { className: "cols" },
        checklist("Hosts", s.hosts.map(h => ({ value: h, text: h })), "host"),
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
  renderGroups();
  updateHint();
  if (st.busy) startPolling();
}

// ---- run ----
$("#run").onclick = async () => {
  const req = { sections: {}, options: { parallel: +$("#optParallel").value, max_lines: +$("#optLines").value,
    strict: $("#optStrict").checked } };
  let bad = null;
  for (const card of $$("#groups .card")) {
    if (!$(".sec", card).checked) continue;
    const need = [$(".pass", card)].concat($(".su", card) ? [$(".su", card)] : []);
    for (const i of need) { i.classList.toggle("missing", !i.value); if (!i.value && !bad) bad = i; }
    const hosts = $$(".host:checked", card).map(i => i.value), groups = $$(".grp:checked", card).map(i => i.value);
    if (!hosts.length || !groups.length) {
      $("#runHint").textContent = "Group " + card.dataset.name + " has no hosts or no checks selected";
      $("details", card).open = true;
      return;
    }
    req.sections[card.dataset.name] = { hosts, groups, user: $(".user", card).value.trim(),
      password: $(".pass", card).value, su_password: $(".su", card) ? $(".su", card).value : null };
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
  if (st.prompt && $("#credModal").hidden) showCred(st.prompt);
  if (!st.prompt) $("#credModal").hidden = true;
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
  if (rv.hits.length) {
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

// ---- inventory editor ----
$("#editInv").onclick = async () => {
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
        return (c.get("user") or sec["user"], c.get("password") or "", c.get("su_password") or None)

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
        _log_sinks.append(lambda msg: self.lines.append(msg) if msg.strip() else None)

    # ---- helpers -----------------------------------------------------------
    def inventory_path(self):
        return find_inventory(self.args) or "inventory.ini"

    def ask(self, prompt):
        with self.lock:
            self.prompt, self.answer = prompt, None
            self.answered.clear()
        while not self.answered.wait(0.5):
            if self.ctx is not None and self.ctx.cancel.is_set():
                break
        with self.lock:
            self.prompt = None
            return self.answer

    def cancel(self):
        ctx = self.ctx
        if ctx is not None:
            ctx.cancel.set()
            self.answered.set()
            for t in list(ctx.targets):      # drop the connections so running checks stop now
                t.close()

    # ---- API ---------------------------------------------------------------
    def api_state(self):
        out = {"version": VERSION, "sections": [], "error": "", "busy": self.state == "running",
               "parallel": self.args.parallel or 4, "max_lines": self.args.max_lines}
        if ssh_version()[0] is None:
            out["error"] = "The OpenSSH client 'ssh' was not found on this machine."
            return out
        inv = find_inventory(self.args)
        if not inv:
            return out
        try:
            settings, sections, custom = load_inventory(inv)
        except Fatal as e:
            out["error"] = "%s (click Edit inventory to fix it)" % e
            return out
        if not self.args.parallel:
            out["parallel"] = int(settings.get("parallel", 4))
        for s in sections:
            out["sections"].append({
                "name": s["name"], "title": COMPONENTS[s["type"]]["title"], "user": s["user"],
                "hosts": s["hosts"], "escalate": s["escalate"],
                "groups": [{"key": k, "title": t, "checks": [c["label"] for c in cs]}
                           for k, t, cs in groups_for(s["type"], custom)]})
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
            byname = {s["name"]: s for s in sections}
            plan, creds = [], {}
            for name, sel in (body.get("sections") or {}).items():
                sec = byname.get(name)
                if not sec:
                    raise Fatal("unknown inventory section [%s]" % name)
                hosts = [h for h in sec["hosts"] if h in set(sel.get("hosts") or [])]
                groups = [g for g in groups_for(sec["type"], custom) if g[0] in set(sel.get("groups") or [])]
                if not hosts or not groups:
                    raise Fatal("nothing selected in [%s]" % name)
                if not sel.get("password"):
                    raise Fatal("no password given for [%s]" % name)
                plan.append({"sec": sec, "hosts": hosts, "groups": groups})
                creds[name] = {"user": str(sel.get("user") or "").strip(), "password": str(sel["password"]),
                               "su_password": sel.get("su_password")}
            if not plan:
                raise Fatal("nothing selected")
            args = self._run_args(body, settings)
            scale = self.args.timeout_scale
            scale_timeouts(plan, scale if scale is not None else float(settings.get("timeout", 30)) / 30.0)
        except Exception:
            with self.lock:
                self.state = "idle"
            raise
        return self._start(args, settings, sections, plan, creds, "health", "")

    def _run_args(self, body, settings):
        opt = body.get("options") or {}
        args = argparse.Namespace(**vars(self.args))
        args.parallel = _clamp(opt.get("parallel") or settings.get("parallel", 4), 4, 1, 16)
        args.max_lines = _clamp(opt.get("max_lines") or self.args.max_lines, 200, 20, 5000)
        args.strict_host_keys = bool(opt.get("strict")) or self.args.strict_host_keys
        return args

    def _start(self, args, settings, sections, plan, creds, kind, title):
        with self.lock:
            del self.lines[:]
            self.result, self.error, self.prompt = None, "", None
        threading.Thread(target=self._run, args=(args, settings, sections, plan, creds, kind, title),
                         daemon=True).start()
        return {"ok": True}

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
                   "prompt": self.prompt, "error": self.error, "result": None}
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
        elif method == "POST":
            if route == "inventory":
                return self.api_inventory_set(body)
            if route == "run":
                return self.api_run(body)
            if route == "plan":
                return self.api_plan(body)
            if route == "plan_run":
                return self.api_plan_run(body)
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
    ap.add_argument("--connect-timeout", type=int, default=15, help="SSH connect timeout in seconds")
    ap.add_argument("--timeout-scale", type=float, help="multiply every command timeout by this factor")
    ap.add_argument("--max-lines", type=int, default=200, help="output lines kept per check (default 200)")
    ap.add_argument("--strict-host-keys", action="store_true",
                    help="only connect to hosts already in known_hosts (default: trust on first use)")
    ap.add_argument("--scrub-file", nargs="+", metavar="FILE",
                    help="anonymize existing text files with the same mapping, then exit")
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
