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
import threading
import time

VERSION = "1.0.0"

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


def log(msg=""):
    with _print_lock:
        print(msg, flush=True)


def die(msg, code=2):
    print("error: " + msg, file=sys.stderr)
    sys.exit(code)


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
        for i, (g, c) in enumerate(todo, 1):
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
def run_plan(ctx, plan, scrubber, creds_fn=prompt_credentials, interactive=True):
    """Run the plan. Returns a list of (section, [Target])."""
    done = []
    creds = {}
    for item in plan:
        creds[item["sec"]["name"]] = creds_fn(item["sec"])
    print()

    def progress(t, msg):
        log("  [%s] %-40s %s" % (t.sec["name"], t.address, msg))

    for item in plan:
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

        apply(targets, creds[sec["name"]])
        log("[%s] %d host(s), %d check group(s)" % (sec["name"], len(targets), len(item["groups"])))
        # Canary: try the first host alone, so a mistyped password costs one failed
        # login on one host instead of one on every host (account lockout protection).
        first, rest = targets[0], targets[1:]
        tries = 0
        while not first.connect() and first.errkind == "auth" and interactive and tries < 2:
            tries += 1
            log("  [%s] %s: %s" % (sec["name"], first.address, first.errmsg))
            if not ask_yes("  Re-enter credentials for [%s]?" % sec["name"]):
                break
            creds[sec["name"]] = creds_fn(sec)
            apply(targets, creds[sec["name"]])
        if first.errkind == "auth":
            for t in rest:
                t.errkind = "skipped"
                t.errmsg = "not attempted: credentials were rejected by the first host of this group"
            progress(first, "FAILED: " + first.errmsg)
            done.append((item, targets))
            continue
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, ctx.args.parallel)) as pool:
            list(pool.map(lambda t: collect_target(t, item["groups"], progress), targets))
        # Offer a retry for individual hosts that rejected the shared credentials.
        for t in targets:
            if t.errkind == "auth" and interactive and t is not first:
                if ask_yes("  %s rejected the credentials. Enter different ones for this host?"
                           % t.address, default=False):
                    apply([t], creds_fn(sec, what="host %s" % t.address))
                    t.results = []
                    collect_target(t, item["groups"], progress)
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


def build_report(ctx, done, scrubber, started, max_lines):
    S = scrubber.scrub
    out = []
    w = out.append
    w("# VCF anonymized diagnostic report")
    w("")
    w("- Generated: %s UTC" % started.strftime("%Y-%m-%d %H:%M:%S"))
    w("- Tool: vcf_diag %s, Python %s, %s" % (VERSION, sys.version.split()[0], ctx.ssh_banner))
    w("- Scope: health and status checks only, read-only commands over SSH")
    w("")
    w("## How to read this report")
    w("")
    w(LEGEND)
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
            timed = [r["label"] for r in t.results if r["status"] == "timeout"]
            failed = [r["label"] for r in t.results if r["status"] == "fail"]
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
                    w("**%s** - skipped: %s" % (r["label"], S(r["note"])))
                    continue
                status = "ok" if r["status"] == "ok" else (
                    "TIMEOUT" if r["status"] == "timeout" else "exit %s" % r["rc"])
                w("**%s** (%s, %.1fs)" % (r["label"], status, r["dur"]))
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


def review(scrubber, text):
    """Print the local, human review hints. Shows real values - console only."""
    hits = scrubber.leak_check(text)
    print("\nPrivacy check of the written report")
    if hits:
        print("  WARNING: %d known real value(s) are still present. Review before sharing:" % len(hits))
        for real, n in sorted(hits.items(), key=lambda kv: -kv[1])[:40]:
            print("    %-40s %d occurrence(s)" % (real, n))
        print("  Add them to scrub_terms / extra_domains in the inventory and run again.")
    else:
        print("  OK - none of the %d known real names or addresses appear in the report."
              % sum(len(v) for v in scrubber.m.maps.values()))
    quads = {}
    for m in RX_DOTTED_QUAD.finditer(text):
        if not is_plain_ipv4(m.group(0)):
            continue
        quads[m.group(0)] = quads.get(m.group(0), 0) + 1
    if quads:
        print("  Dotted values left readable because they look like version numbers:")
        print("    " + ", ".join("%s (x%d)" % kv for kv in sorted(quads.items())))
        print("  If any of these is really an IP address, remove it from keep_literals and tell me.")
    return hits


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


def cmd_scrub_files(args):
    settings, sections = {}, []
    inv = find_inventory(args)
    if inv:
        settings, sections, _ = load_inventory(inv)
    scrubber = make_scrubber(args, settings)
    learn_inventory(scrubber, sections)
    texts = []
    for path in args.scrub_file:
        with open(path, encoding="utf-8", errors="replace") as fh:
            texts.append(fh.read())
    for tx in texts:
        scrubber.prescan(tx)
    scrubber.compile()
    os.makedirs(args.output_dir, exist_ok=True)
    for path, tx in zip(args.scrub_file, texts):
        dest = os.path.join(args.output_dir, "anon-%s-%s.txt" % (
            datetime.datetime.now().strftime("%Y%m%d-%H%M%S"),
            scrubber.m.get("file", os.path.abspath(path), width=3)))
        result = scrubber.scrub(tx)
        write_private(dest, result)
        print("Anonymized %s -> %s" % (path, dest))
        review(scrubber, result)
    scrubber.m.save()


def cmd_decode(args):
    mapping = Mapping(os.path.join(args.private_dir, "mapping.json"))
    rev = {}
    for cat, vals in mapping.maps.items():
        if cat in ("ipv4net", "file"):
            continue
        for real, ph in vals.items():
            rev.setdefault(ph.lower(), real)
    if not rev:
        die("no mapping found in %s" % args.private_dir)
    with open(args.decode, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    rx = re.compile(r"(?i)(?<![\w-])(?:%s)(?![\w-])" % "|".join(
        re.escape(k) for k in sorted(rev, key=len, reverse=True)))
    sys.stdout.write(rx.sub(lambda m: rev[m.group(0).lower()], text))


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
    if args.timeout_scale != 1.0:
        for item in plan:
            item["groups"] = [(k, t, [dict(c, timeout=int(c["timeout"] * args.timeout_scale)) for c in cs])
                              for k, t, cs in item["groups"]]
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
    ctx = Context(args)
    for sig in (signal.SIGTERM, signal.SIGHUP):      # close connections if we are killed
        signal.signal(sig, lambda *_: sys.exit(143))
    scrubber = make_scrubber(args, settings)
    learn_inventory(scrubber, sections)
    started = datetime.datetime.now(datetime.timezone.utc)
    try:
        done = run_plan(ctx, plan, scrubber)
    except KeyboardInterrupt:
        print("\nInterrupted - closing connections. No report written.")
        ctx.cleanup()
        sys.exit(130)
    learn_from_results(done, scrubber)
    report = build_report(ctx, done, scrubber, started, args.max_lines)
    scrubber.m.save()
    os.makedirs(args.output_dir, exist_ok=True)
    path = os.path.join(args.output_dir, "vcf-report-%s.md" % started.strftime("%Y%m%d-%H%M%S"))
    write_private(path, report)
    ctx.cleanup()
    review(scrubber, report)
    total = sum(len(ts) for _, ts in done)
    failed = sum(1 for _, ts in done for t in ts if t.errkind)
    print("\nReport:  %s" % path)
    print("Size:    %.0f KB, roughly %d thousand tokens" % (len(report) / 1024.0, len(report) // 3500))
    print("Hosts:   %d collected, %d not collected" % (total - failed, failed))
    if len(report) > 1500000:
        print("Note:    this is a large report. Consider collecting one component group at a time.")
    print("Mapping: %s  (PRIVATE - never share)" % os.path.join(args.private_dir, "mapping.json"))
    print("\nOpen the report and skim it before sharing. Use --decode to translate an analysis back.")


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
    ap.add_argument("--decode", metavar="FILE",
                    help="print FILE with placeholders translated back to real names (local use only)")
    ap.add_argument("--self-test", action="store_true", help="test the anonymizer and exit")
    ap.add_argument("--version", action="version", version="vcf_diag " + VERSION)
    args = ap.parse_args(argv)
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
