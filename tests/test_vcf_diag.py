"""Unit tests for the anonymizer and the non-network parts of vcf_diag.

Run from the repository root:  python3 -m unittest discover -s tests -v
All names and addresses below are invented.
"""
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import vcf_diag as v  # noqa: E402


def make(terms=(), keep=("9.1.1.0",), domains=(), mapping=None):
    sc = v.Scrubber(mapping or v.Mapping(None), extra_domains=domains, terms=terms, keep_literals=keep)
    sc.learn_host("esx01.corp.example-widgets.com", prefix="esxi")
    sc.learn_host("vc01.corp.example-widgets.com", prefix="vcenter")
    return sc


def run(sc, text):
    sc.prescan(text)
    sc.compile()
    return sc.scrub(text)


def harvest(sc, spec, text):
    for cat, rx, split in spec["harvest"]:
        for m in re.finditer(rx, text):
            for val in (re.split(split, m.group(1)) if split else [m.group(1)]):
                sc.learn(cat, val)


def find(typ, label):
    for _, _, cmds in v.COMPONENTS[typ]["groups"]:
        for c in cmds:
            if c["label"] == label:
                return c
    raise KeyError(label)


class HostAndDomain(unittest.TestCase):
    def test_fqdn_short_and_case(self):
        out = run(make(), "esx01.corp.example-widgets.com ESX01 esx01 VC01.CORP.EXAMPLE-WIDGETS.COM")
        self.assertEqual(out, "esxi-01.domain-01 ESXI-01 esxi-01 VCENTER-01.DOMAIN-01")

    def test_unknown_host_in_known_domain(self):
        out = run(make(), "ntp1.corp.example-widgets.com then ntp1 alone, bare corp.example-widgets.com")
        self.assertNotIn("example-widgets", out)
        self.assertIn("host-0001.domain-01", out)
        self.assertIn("bare domain-01", out)

    def test_short_name_inside_other_names(self):
        out = run(make(), "esx01-vmk1 esx01_local /vmfs/volumes/esx01-ds notesx01x")
        self.assertEqual(out, "esxi-01-vmk1 esxi-01_local /vmfs/volumes/esxi-01-ds notesx01x")

    def test_generic_short_names_are_not_replaced_alone(self):
        sc = make()
        sc.learn_host("nsx.corp.example-widgets.com", prefix="nsxmgr")
        out = run(sc, "nsx-proxy is running; nsx.corp.example-widgets.com")
        self.assertIn("nsx-proxy is running", out)
        self.assertNotIn("example-widgets", out)

    def test_other_domains_and_safe_names(self):
        out = run(make(), "mirror.partner-site.net pool.ntp.org kubernetes.default.svc.cluster.local "
                          "administrator@vsphere.local com.vmware.vsan java.net.ConnectException "
                          "vmware-vpostgres.service packages.broadcom.com")
        self.assertNotIn("partner-site", out)
        for keep in ("pool.ntp.org", "svc.cluster.local", "administrator@vsphere.local", "com.vmware.vsan",
                     "java.net.ConnectException", "vmware-vpostgres.service", "packages.broadcom.com"):
            self.assertIn(keep, out)

    def test_email_domain(self):
        out = run(make(), "alerts@corp.example-widgets.com")
        self.assertEqual(out, "alerts@domain-01")


class Addresses(unittest.TestCase):
    def test_ipv4_networks_are_grouped(self):
        out = run(make(), "10.1.1.5 10.1.1.6 10.1.2.5 10.1.1.5/24 10.1.1.5:443")
        self.assertEqual(out, "ip-n1-h1 ip-n1-h2 ip-n2-h1 ip-n1-h1/24 ip-n1-h1:443")

    def test_special_addresses_kept(self):
        text = "127.0.0.1 0.0.0.0 255.255.252.0 169.254.1.1 224.1.2.3 ::1"
        self.assertEqual(run(make(), text), text)

    def test_versions_kept_addresses_hidden(self):
        out = run(make(), 'Version: 8.0.3.0 "version":"9.0.2.0" VCF 9.1.1.0 build 9.0.0.0.24755229 '
                          'i40en 2.9.2.0-1OEM.800 nameserver 10.9.8.7 NTP Server 10.9.8.8 Driver: 10.9.8.9')
        for keep in ("8.0.3.0", "9.0.2.0", "9.1.1.0", "9.0.0.0.24755229", "2.9.2.0-1OEM"):
            self.assertIn(keep, out)
        self.assertNotIn("10.9.8.", out)

    def test_version_word_on_previous_line_does_not_protect_an_address(self):
        out = run(make(), "NAME VERSION\n10.2.2.2 Ready\nrelease\n\n10.3.3.3")
        self.assertNotIn("10.2.2.2", out)
        self.assertNotIn("10.3.3.3", out)

    def test_dashed_and_reverse_forms(self):
        out = run(make(), "10.20.30.41 ip-10-20-30-41.internal-zone 41.30.20.10.in-addr.arpa")
        self.assertNotIn("10-20-30-41", out)
        self.assertNotIn("41.30.20.10", out)

    def test_ipv6_and_times(self):
        out = run(make(), "fe80::250:56ff:feab:cdef 2001:db8:10::15 at 12:34:56 std::string")
        self.assertIn("ip6-ll-0001", out)
        self.assertIn("ip6-0001", out)
        self.assertIn("12:34:56", out)
        self.assertIn("std::string", out)

    def test_mac_wwn_thumbprint(self):
        out = run(make(), "00:50:56:ab:cd:ef 00-50-56-AB-CD-EF 20:00:00:25:b5:aa:bb:cc "
                          "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01 ff:ff:ff:ff:ff:ff")
        self.assertEqual(out, "mac-0001 mac-0001 wwn-0001 thumbprint-0001 ff:ff:ff:ff:ff:ff")


class Identifiers(unittest.TestCase):
    def test_uuid_forms(self):
        out = run(make(), "4c4c4544-0038-4b10-8032-b7c04f503933 5f3c2a1b-8d7e6f5a-4b3c-2a1b0c9d8e7f "
                          "50 0e 3c 1a 2b 4d 5e 6f-70 81 92 a3 b4 c5 d6 e7")
        self.assertEqual(out, "uuid-0001 uuid-0002 uuid-0003")

    def test_devices_serials_license(self):
        out = run(make(), "naa.600508b1001c5e3a9f2d4b7c8e1f0a2b t10.NVMe____Dell_Ent_NVMe_AGN_MU_U.2_1.6TB_____0123456789AB "
                          "iqn.1998-01.com.vmware:esx01-4f3a2b1c\n   Serial Number: 7XK2P93\n   Asset Tag: unknown\n"
                          "key AB1CD-EF2GH-IJ3KL-MN4OP-QR5ST")
        for gone in ("600508b1", "0123456789AB", "4f3a2b1c", "7XK2P93", "AB1CD"):
            self.assertNotIn(gone, out)
        self.assertIn("naa.device-0001", out)
        self.assertIn("Asset Tag: unknown", out)

    def test_certificate_names(self):
        out = run(make(), "subject=C = US, O = Example Widgets Inc, CN = vc01.corp.example-widgets.com\n"
                          "issuer=CN = CA, DC = vsphere, DC = local, O = VMware")
        self.assertNotIn("Example Widgets", out)
        self.assertIn("CN = vcenter-01.domain-01", out)
        self.assertIn("O = VMware", out)

    def test_secrets(self):
        out = run(make(), 'password = "Sup3r S3cret"\napi_token: abc123\nPassword expires : never\n'
                          "Last password change : Nov 01, 2026\nhttps://svc:hunter2@10.1.1.1/x\n"
                          "Authorization: Bearer abc.def.ghi\nroot:$6$abcdefgh$" + "x" * 40 + ":19000\n"
                          "-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----\n")
        for gone in ("Sup3r", "abc123", "hunter2", "abc.def.ghi", "MIIabc", "$6$"):
            self.assertNotIn(gone, out)
        self.assertIn("Password expires : never", out)
        self.assertIn("Last password change : Nov 01, 2026", out)
        self.assertIn("[REDACTED-PRIVATE-KEY]", out)


class Harvest(unittest.TestCase):
    def test_esxi_datastores_and_switches(self):
        sc = make()
        fs = ("Mount Point                                        Volume Name       UUID                                 Mounted  Type            Size          Free\n"
              "/vmfs/volumes/5f3c2a1b-8d7e6f5a-4b3c-2a1b0c9d8e7f  WIDGETS-PROD-DS1  5f3c2a1b-8d7e6f5a-4b3c-2a1b0c9d8e7f     true  VMFS-6  1099511627776  549755813888\n"
              "/vmfs/volumes/vsan:52a1b2c3d4e5f607-8899aabbccddeeff  vsanDatastore     vsan:52a1b2c3d4e5f607-8899aabbccddeeff  true  vsan   9999999999999  1111111111111\n")
        vsw = "vSwitch0\n   Name: vSwitch0\n   Portgroups: Widgets-Backup, VM Network, Management Network\n"
        vmk = "vmk0\n   Name: vmk0\n   Portgroup: N/A\n   VDS Name: Widgets-DSwitch-01\n   MTU: 9000\n"
        harvest(sc, find("esxi", "Filesystems"), fs)
        harvest(sc, find("esxi", "Standard switches"), vsw)
        harvest(sc, find("esxi", "VMkernel interfaces"), vmk)
        out = run(sc, fs + vsw + vmk + "df: /vmfs/volumes/WIDGETS-PROD-DS1 50%\n")
        self.assertNotIn("widgets", out.lower())
        for keep in ("vsanDatastore", "VM Network", "Management Network", "vSwitch0", "MTU: 9000", "Portgroup: N/A"):
            self.assertIn(keep, out)
        self.assertIn("/vmfs/volumes/DATASTORE-0001 50%", out)

    def test_search_domains(self):
        sc = v.Scrubber(v.Mapping(None))
        harvest(sc, find("linux", "Resolver configuration"), "nameserver 10.1.1.53\nsearch eng.widgets-internal.io ops.widgets-internal.io\n")
        out = run(sc, "db01.eng.widgets-internal.io and search eng.widgets-internal.io")
        self.assertNotIn("widgets", out)

    def test_kubernetes_tables(self):
        sc = make()
        nodes = ("NAME        STATUS   ROLES           AGE   VERSION\n"
                 "vsr-cp-a1   Ready    control-plane   40d   v1.31.4+vmware.1\n"
                 "vsr-cp-a2   NotReady,SchedulingDisabled control-plane 40d v1.31.4+vmware.1\n")
        ns = "NAME STATUS AGE\nkube-system Active 40d\nprelude Active 40d\nwidgets-finance Active 3d\n"
        pods = ("NAMESPACE NAME READY STATUS RESTARTS AGE IP NODE\n"
                "prelude provisioning-service-app-5d9c7b6f4-x2x9z 0/1 CrashLoopBackOff 37 2d 198.18.3.14 vsr-cp-a2\n"
                "widgets-finance ledger-api-7f6d5c4b3-abcde 1/1 Running 2 3d 198.18.3.15 vsr-cp-a1\n")
        sc.learn_k8s("nodes", nodes)
        sc.learn_k8s("ns", ns)
        sc.learn_k8s("nsrows", pods)
        out = run(sc, nodes + ns + pods)
        for gone in ("vsr-cp-a", "widgets", "ledger-api", "198.18"):
            self.assertNotIn(gone, out)
        for keep in ("kube-system", "prelude provisioning-service-app-5d9c7b6f4-x2x9z", "CrashLoopBackOff 37",
                     "v1.31.4+vmware.1", "NotReady,SchedulingDisabled"):
            self.assertIn(keep, out)


class MappingAndTools(unittest.TestCase):
    def test_mapping_is_stable_across_runs_and_private(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "private", "mapping.json")
            first = run(make(mapping=v.Mapping(path)), "esx01 10.1.1.5 corp.example-widgets.com")
            v.Mapping(path)  # nothing saved yet
            m = v.Mapping(path)
            sc = make(mapping=m)
            run(sc, "10.7.7.7 esx01 10.1.1.5")
            m.save()
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            again = run(make(mapping=v.Mapping(path)), "10.1.1.5 esx01 10.7.7.7")
            self.assertEqual(again, "ip-n2-h1 esxi-01 ip-n1-h1")
            self.assertIn("esxi-01", first)

    def test_leak_check_finds_known_values(self):
        sc = make()
        run(sc, "10.1.1.5")
        self.assertEqual(sc.leak_check("all clean esxi-01 ip-n1-h1"), {})
        self.assertEqual(sc.leak_check("oops esx01 and 10.1.1.5"), {"esx01": 1, "10.1.1.5": 1})

    def test_selection_parser(self):
        self.assertEqual(v.parse_selection("", 4), [0, 1, 2, 3])
        self.assertEqual(v.parse_selection("1,3-4", 4), [0, 2, 3])
        self.assertEqual(v.parse_selection("none", 4), [])
        self.assertIsNone(v.parse_selection("5", 4))
        self.assertIsNone(v.parse_selection("x", 4))

    def test_inventory_and_custom_commands(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "inv.ini")
            with open(path, "w") as fh:
                fh.write("[settings]\nscrub_terms = Widgets, Site 7\n[esxi:mgmt]\nhosts =\n  a.example.internal\n"
                         "  b.example.internal, 10.0.0.9\nuser = root\n[vcenter]\nhosts =\n"
                         "[commands:esxi]\nAdvanced = esxcli system settings advanced list -d\n")
            settings, sections, custom = v.load_inventory(path)
            self.assertEqual(len(sections), 1)
            self.assertEqual(sections[0]["hosts"], ["a.example.internal", "b.example.internal", "10.0.0.9"])
            self.assertEqual(sections[0]["prefix"], "esxi-mgmt")
            self.assertEqual(v.groups_for("esxi", custom)[-1][0], "custom")
            self.assertIn("scrub_terms", settings)

    def test_template_parses_and_clip(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "inv.ini")
            with open(path, "w") as fh:
                fh.write(v.INVENTORY_TEMPLATE)
            _, sections, _ = v.load_inventory(path)
            self.assertEqual(sections, [])
        clipped = v.clip("\n".join(str(i) for i in range(1000)), 100)
        self.assertEqual(len(clipped.split("\n")), 101)
        self.assertIn("900 lines omitted", clipped)
        self.assertEqual(v.fence("a ``` b"), "````")

    def test_self_test(self):
        self.assertEqual(v.cmd_self_test(), 0)


READ_ONLY_OK = r"""
grep -iE 'error|fail' /var/log/vmware/vpxd/vpxd.log | tail -n 200
tail -n 100 /var/log/vmkernel.log
esxcli network nic stats get -n vmnic0
esxcli vsan debug object health summary get
esxcli software vib list | grep -i nsx
esxcli network diag ping -H ip-n1-h2 -I vmk1 -s 8972 -d
vmkping -I vmk1 -s 8972 -d ip-n1-h2
{K} logs -n prelude provisioning-service-app-5d9c7b6f4-x2x9z --tail=200 --previous 2>&1
{K} get pods -n prelude -o wide | awk '$4!="Running" && $5>3'
{K} describe pod -n prelude identity-service-app-0 | tail -n 40
{K} rollout status deploy/foo -n prelude
{K} get secret -n prelude
journalctl -u vmware-vpxd --since '2 hours ago' --no-pager | grep -i error | tail -n 100
systemctl status vmware-vpxd --no-pager 2>&1 | head -n 20
service-control --status vmware-vpxd
df -h; free -m; uptime
openssl x509 -in /etc/vmware-vpx/ssl/rui.crt -noout -dates
curl -sk https://localhost/lcm/about
curl -s -m 5 -o /dev/null -w '%{http_code}' https://vcenter-01.domain-01/ 2>/dev/null
nc -vz ip-n1-h5 443 2>&1
rpm -qa | grep -i vmware | head
vim-cmd hostsvc/hostsummary | grep -i maintenance
vim-cmd vmsvc/getallvms | wc -l
zcat /var/log/vmware/vpxd/vpxd-1.log.gz | grep -c ERROR
find /var/log -name '*.log' -mmin -60 -size +100M
chage -l root
nsxcli -c 'get managers'
for f in /var/log/vmware/*/*.log; do echo "$f $(grep -c ERROR "$f")"; done | sort -k2 -n | tail
"""

NOT_READ_ONLY = r"""
rm -f /var/log/x.log
service-control --restart vmware-vpxd
systemctl restart vmware-vpxd
echo 1 > /proc/sys/vm/drop_caches
grep x /var/log/a | tee /tmp/out
esxcli system maintenanceMode set -e true
esxcli storage core adapter rescan --all
{K} delete pod -n prelude foo
{K} -n prelude delete pod foo
{K} exec -n prelude foo -- cat /etc/passwd
{K} rollout restart deploy/foo -n prelude
{K} get secret -n prelude db-creds -o yaml
sed -i 's/a/b/' /etc/hosts
cat /etc/shadow
cat /root/.ssh/id_rsa
cat /etc/kubernetes/admin.conf
curl -X POST https://localhost/api/restart
curl -sk https://localhost/x -d '{"a":1}'
find /tmp -name '*.core' -delete
find /var/core -type f -exec rm {} \;
kill -9 1234
sudo cat /var/log/messages
bash -c 'echo hi'
echo cm0gLXJmIC8K | base64 -d | sh
python3 -c 'import os; os.remove("/x")'
vim-cmd vmsvc/power.off 12
vim-cmd hostsvc/maintenance_mode_enter
nsxcli -c 'set service ntp restart'
psql -U postgres -d VCDB -c 'delete from vpx_event'
tdnf install -y foo
chage -M 90 root
ls /tmp && rm -rf /tmp/x
uptime; shutdown -r now
scp /etc/hosts other:/tmp
date >> /var/log/custom.log
/usr/bin/rm /tmp/x
timeout 5 rm /tmp/x
nc ip-n1-h5 443 < /etc/passwd
"""

REPLY = """The vpxd service on vcenter-01.domain-01 cannot reach esxi-01 (ip-n1-h1).

```vcf-plan
plan: look at vpxd and restart it

[collect] target=vcenter-01
label: vpxd errors
run: grep -i error /var/log/vmware/vpxd/vpxd.log |
  grep esxi-01.domain-01 | tail -n 50
timeout: 90
lines: 80

[collect] target=@esxi
label: clean up
run: rm -rf /var/core/*

[collect] target=nosuchhost-09
label: unknown host
run: uptime

[fix] target=vcenter-01
label: Restart vpxd
run: service-control --restart vmware-vpxd
note: vCenter API is down for two minutes; esxi-01 reconnects by itself.
```
"""


class Plans(unittest.TestCase):
    def test_read_only_check(self):
        mode = lambda c: "kubectl" if "{K}" in c else "sh"   # noqa: E731
        refused = [c for c in READ_ONLY_OK.strip().split("\n") if v.readonly_problem(c, mode(c))]
        allowed = [c for c in NOT_READ_ONLY.strip().split("\n") if not v.readonly_problem(c, mode(c))]
        self.assertEqual(refused, [], "read-only commands wrongly refused")
        self.assertEqual(allowed, [], "changing commands wrongly allowed")
        self.assertIsNone(v.readonly_problem("get cluster status", "nsxcli"))
        self.assertIsNotNone(v.readonly_problem("set service ntp", "nsxcli"))
        self.assertIsNotNone(v.readonly_problem("get managers | tee x", "nsxcli"))

    def test_parse_plan(self):
        p = v.parse_plan(REPLY)
        self.assertEqual(p["title"], "look at vpxd and restart it")
        self.assertEqual([s["kind"] for s in p["steps"]], ["collect", "collect", "collect", "fix"])
        self.assertEqual(p["steps"][0]["targets"], ["vcenter-01"])
        self.assertIn("\ngrep esxi-01.domain-01 | tail -n 50", p["steps"][0]["run"])
        self.assertEqual((p["steps"][0]["timeout"], p["steps"][0]["lines"]), ("90", "80"))
        self.assertTrue(p["steps"][3]["note"].startswith("vCenter API is down"))
        self.assertEqual(v.parse_plan("just prose, no plan")["steps"], [])

    def test_prepare_plan_sorts_steps_and_translates(self):
        import argparse
        with tempfile.TemporaryDirectory() as d:
            inv = os.path.join(d, "inventory.ini")
            with open(inv, "w") as fh:
                fh.write("[esxi]\nhosts = esx01.corp.example-widgets.com\n"
                         "[vcenter]\nhosts = vc01.corp.example-widgets.com\n")
            args = argparse.Namespace(inventory=inv, private_dir=os.path.join(d, "private"))
            with self.assertRaises(v.Fatal):
                v.prepare_plan(args, REPLY)                 # no mapping yet
            m = v.Mapping(os.path.join(d, "private", "mapping.json"))
            sc = make(mapping=m)
            run(sc, "10.1.1.5")
            m.save()
            prep = v.prepare_plan(args, REPLY)
            self.assertIn("vc01.corp.example-widgets.com cannot reach esx01 (10.1.1.5)", prep["translated"])
            self.assertEqual([e["label"] for e in prep["collect"]], ["vpxd errors"])
            self.assertIn("grep esx01.corp.example-widgets.com", prep["collect"][0]["command"])
            self.assertEqual(prep["collect"][0]["targets"][0]["address"], "vc01.corp.example-widgets.com")
            kinds = {e["label"]: e["kind"] for e in prep["manual"]}
            self.assertEqual(kinds, {"clean up": "blocked", "Restart vpxd": "fix"})
            self.assertTrue(any("nosuchhost-09" in p for p in prep["problems"]))
            # only the read-only step is in the plan the tool would run
            self.assertEqual(len(prep["plan"]), 1)
            item = prep["plan"][0]
            self.assertEqual(item["sec"]["name"], "vcenter")
            cmds = item["host_groups"]["vc01.corp.example-widgets.com"][0][2]
            self.assertEqual([(c["label"], c["timeout"], c["max_lines"]) for c in cmds], [("vpxd errors", 90, 80)])
            self.assertNotIn("service-control", str(prep["plan"]))
            self.assertNotIn("rm -rf", str(prep["plan"]))

    def test_encoded_blobs_are_redacted(self):
        out = run(make(), "client-key-data: " + "QUJD" * 60 + "\nok: short QUJDQUJD")
        self.assertIn("[REDACTED-ENCODED-DATA]", out)
        self.assertIn("short QUJDQUJD", out)


MGMT_INVENTORY = """
[vcfmgmt:mgmt]
control_planes = 10.9.0.11, 10.9.0.12, 10.9.0.13
ssh_workers = yes
[endpoints:mgmt]
VCF Operations = ops-x01.corp.example-widgets.com
Fleet lifecycle = fleet-x01
Salt RaaS = fleet-x01
VCF Operations for networks = 10.9.5.50
"""


class ManagementCluster(unittest.TestCase):
    def load(self, text):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "inv.ini")
            with open(path, "w") as fh:
                fh.write(text)
            return v.load_inventory(path)

    def test_inventory_control_planes_and_endpoints(self):
        _, sections, custom = self.load(MGMT_INVENTORY)
        sec = sections[0]
        self.assertEqual((sec["type"], sec["prefix"], sec["user"]), ("vcfmgmt", "vcfmgmt-mgmt", "vmware-system-user"))
        self.assertEqual(sec["hosts"], ["10.9.0.11", "10.9.0.12", "10.9.0.13"])
        self.assertTrue(sec["ssh_workers"])
        self.assertEqual(sec["endpoints"]["fleet-x01"], ["Fleet lifecycle", "Salt RaaS"])
        groups = v.groups_for(sec, custom)
        keys = [g[0] for g in groups]
        self.assertIn("endpoints", keys)
        self.assertLess(keys.index("endpoints"), keys.index("node-runtime"))
        labels = [c["label"] for c in groups[keys.index("endpoints")][2]]
        self.assertIn("Endpoint fleet-x01: Fleet lifecycle, Salt RaaS", labels)
        self.assertEqual(len(labels), 4)     # three endpoints + the Kubernetes lookup
        self.assertNotIn("endpoints", [g[0] for g in v.groups_for("vcfmgmt", custom)])
        self.assertEqual({k for k in keys if v.is_cluster_group(k)},
                         {"k8s-cluster", "k8s-workloads", "k8s-storage", "k8s-events", "k8s-vcf", "k8s-nodes", "endpoints"})

    def test_endpoints_need_a_cluster(self):
        with self.assertRaises(v.Fatal):
            self.load("[endpoints:other]\nVCF Operations = ops\n")
        self.assertEqual(self.load("[endpoints:other]\n")[1], [])

    def test_endpoint_and_node_names_are_anonymized(self):
        _, sections, custom = self.load(MGMT_INVENTORY)
        sc = v.Scrubber(v.Mapping(None))
        v.learn_inventory(sc, sections)
        nodes = ("NAME STATUS ROLES AGE VERSION INTERNAL-IP\n"
                 "wid-run-cp-8f2kq Ready control-plane 40d v1.31.4 10.9.0.11\n"
                 "wid-run-md-0-7xk2p-9zq4t NotReady <none> 40d v1.31.4 10.9.0.21\n")
        sc.learn_k8s("nodes", nodes, prefix="vcfmgmt-mgmt")
        endpoint_cmds = [g for g in v.groups_for(sections[0], custom) if g[0] == "endpoints"][0][2]
        text = nodes + "\n".join(c["cmd"] for c in endpoint_cmds) + "\n10.9.6.1 fleet-x01.corp.example-widgets.com fleet-x01"
        out = run(sc, text)
        for gone in ("8f2kq", "7xk2p", "ops-x01", "fleet-x01", "example-widgets", "10.9."):
            self.assertNotIn(gone, out)
        for keep in ("vcfmgmt-mgmt-cp-01", "vcfmgmt-mgmt-worker-01", "endpoint-01.domain-01", "endpoint-02"):
            self.assertIn(keep, out)


class NotAnonymized(unittest.TestCase):
    def test_only_secrets_are_redacted(self):
        sc = v.Scrubber(v.Mapping(None), anonymize=False)
        sc.learn_host("esx01.corp.example-widgets.com", prefix="esxi")
        text = "esx01.corp.example-widgets.com 10.1.1.5 00:50:56:ab:cd:ef password=hunter2 token: abc123\n"
        sc.prescan(text)
        sc.compile()
        out = sc.scrub(text)
        self.assertEqual(out, "esx01.corp.example-widgets.com 10.1.1.5 00:50:56:ab:cd:ef "
                              "password=[REDACTED] token: [REDACTED]\n")
        self.assertFalse(v.review_data(sc, out)["anonymized"])

    def test_switch_and_line_limit_from_settings(self):
        import argparse
        args = argparse.Namespace(no_anonymize=False, max_lines=None, private_dir="unused")
        self.assertTrue(v.anonymize_enabled(args, {}))
        self.assertFalse(v.anonymize_enabled(args, {"anonymize": "no"}))
        self.assertFalse(v.make_scrubber(args, {"anonymize": "no"}).anonymize)
        self.assertEqual(v.max_lines_for(args, {"max_lines": "5000"}), 5000)
        self.assertEqual(v.max_lines_for(args, {}), 200)
        args.no_anonymize, args.max_lines = True, 300
        self.assertFalse(v.anonymize_enabled(args, {}))
        self.assertEqual(v.max_lines_for(args, {"max_lines": "5000"}), 300)

    def test_plan_uses_real_names_without_a_mapping(self):
        import argparse
        with tempfile.TemporaryDirectory() as d:
            inv = os.path.join(d, "inventory.ini")
            with open(inv, "w") as fh:
                fh.write("[settings]\nanonymize = no\n[vcenter]\nhosts = vc01.corp.example-widgets.com\n"
                         "[esxi]\nhosts = 10.1.1.5, 10.1.1.6\n")
            args = argparse.Namespace(inventory=inv, private_dir=os.path.join(d, "none"))
            reply = ("```vcf-plan\n[collect] target=vc01\nrun: uptime\n[collect] target=10.1.1.6\nrun: uptime\n"
                     "[fix] target=@esxi\nrun: /etc/init.d/hostd restart\n```")
            prep = v.prepare_plan(args, reply)
            self.assertEqual(prep["problems"], [])
            self.assertEqual([e["targets"][0]["address"] for e in prep["collect"]],
                             ["vc01.corp.example-widgets.com", "10.1.1.6"])
            self.assertEqual([t["address"] for t in prep["manual"][0]["targets"]], ["10.1.1.5", "10.1.1.6"])


class FollowUps(unittest.TestCase):
    def test_workers_get_a_per_run_known_hosts_file(self):
        import argparse
        import types
        ctx = types.SimpleNamespace(rundir="/run/x", targets=[], args=argparse.Namespace(strict_host_keys=False))
        sec = {"type": "vcfmgmt", "port": 22, "ssh_options": []}
        worker = v.Target(ctx, sec, "10.9.0.21", "w", discovered=True)
        cp = v.Target(ctx, sec, "10.9.0.11", "c")
        worker.user = cp.user = "u"
        worker.ctl = cp.ctl = "/run/x/c1"
        self.assertIn("UserKnownHostsFile=/run/x/known_hosts_workers", worker._base())
        self.assertFalse(any("UserKnownHostsFile" in a for a in cp._base()))
        ctx.args.strict_host_keys = True
        self.assertFalse(any("UserKnownHostsFile" in a for a in worker._base()))

    def test_follow_up_steps_use_sudo_and_old_placeholders_still_work(self):
        import argparse
        with tempfile.TemporaryDirectory() as d:
            inv = os.path.join(d, "inventory.ini")
            with open(inv, "w") as fh:
                fh.write("[settings]\nanonymize = no\n[vcfmgmt:mgmt]\ncontrol_planes = 10.9.0.11\n")
            m = v.Mapping(os.path.join(d, "private", "mapping.json"))
            m.get("target", "10.9.0.11", prefix="vcfmgmt-mgmt", width=2)
            m.save()
            args = argparse.Namespace(inventory=inv, private_dir=os.path.join(d, "private"))
            prep = v.prepare_plan(args, "```vcf-plan\n[collect] target=vcfmgmt-mgmt-01\n"
                                        "run: journalctl -u kubelet --no-pager | tail -n 20\n```")
            self.assertEqual(prep["problems"], [])
            step = prep["plan"][0]["host_groups"]["10.9.0.11"][0][2][0]
            self.assertTrue(step["sudo"])
            self.assertEqual(step["mode"], "sh")


class Supervisor(unittest.TestCase):
    def test_component_and_vcenter_checks(self):
        keys = [g[0] for g in v.COMPONENTS["supervisor"]["groups"]]
        self.assertEqual(keys[0], "k8s-supervisor")
        self.assertIn("k8s-cluster", keys)
        vc = [g for g in v.COMPONENTS["vcenter"]["groups"] if g[0] == "vc-supervisor"][0]
        decrypt = [c for c in vc[2] if "decryptK8Pwd" in c["cmd"]][0]["cmd"]
        self.assertIn("grep -iE", decrypt)          # only cluster and IP lines are kept

    def test_password_line_is_redacted_even_if_printed(self):
        out = run(make(), "Cluster: domain-c8:1234\nIP: 10.7.7.2\nPWD: Sup3rSecret!\n")
        self.assertNotIn("Sup3rSecret", out)

    def test_worker_seen_as_machine_keeps_its_node_placeholder(self):
        sc = make()
        sc.learn_k8s("nodes", "NAME STATUS ROLES\nwid-run-md-0-7xk2p-9zq4t Ready <none>\n", prefix="vcfmgmt-mgmt")
        sc.learn_k8s("nsrows", "NAMESPACE NAME CLUSTER\nsvc-mgmt-ns wid-run-md-0-7xk2p-9zq4t wid-run\n")
        out = run(sc, "node wid-run-md-0-7xk2p-9zq4t / machine wid-run-md-0-7xk2p-9zq4t")
        self.assertEqual(out, "node vcfmgmt-mgmt-worker-01 / machine vcfmgmt-mgmt-worker-01")


FAKE_VC = {
    "/api/vcenter/namespace-management/clusters": [
        {"cluster": "domain-c8", "cluster_name": "WIDGETS-MGMT-CL01", "config_status": "RUNNING",
         "kubernetes_status": "READY"}],
    "/api/vcenter/namespace-management/clusters/domain-c8": {
        "config_status": "RUNNING", "kubernetes_status": "WARNING", "size_hint": "SMALL",
        "network_provider": "NSXT_CONTAINER_PLUGIN", "api_server_management_endpoint": "10.20.30.41",
        "messages": [], "kubernetes_status_messages": [
            {"severity": "WARNING", "details": {"default_message": "Control plane VM 10.20.30.42 is degraded."}}],
        "stat_summary": {"cpu_used": 9000, "cpu_capacity": 100000, "memory_used": 64000,
                         "memory_capacity": 512000, "storage_used": 1000, "storage_capacity": 9000}},
    "/api/vcenter/namespaces/instances": [
        {"namespace": "widgets-finance", "cluster": "domain-c8", "config_status": "RUNNING",
         "stats": {"cpu_used": 1200, "memory_used": 4096, "storage_used": 20480}},
        {"namespace": "svc-velero-domain-c8", "cluster": "domain-c8", "config_status": "ERROR",
         "stats": {"cpu_used": 0, "memory_used": 0, "storage_used": 0}}],
    "/api/vcenter/namespaces/instances/widgets-finance": {
        "config_status": "RUNNING", "messages": [],
        "access_list": [{"subject_type": "USER", "subject": "devops", "domain": "vsphere.local", "role": "EDIT"}],
        "storage_specs": [{"policy": "4c4c4544-0038-4b10-8032-b7c04f503933", "limit": 102400}],
        "vm_service_spec": {"vm_classes": ["best-effort-small"], "content_libraries": ["lib-1"]},
        "resource_spec": {"cpu_limit": 20000}},
    "/api/vcenter/namespaces/instances/svc-velero-domain-c8": {
        "config_status": "ERROR",
        "messages": [{"severity": "ERROR", "details": {"default_message": "Failed to create network for namespace."}}]},
    "/api/vcenter/namespace-management/supervisor-services": [
        {"supervisor_service": "velero.vsphere.vmware.com", "display_name": "Velero", "state": "ACTIVATED"}],
    "/api/vcenter/namespace-management/clusters/domain-c8/supervisor-services": [
        {"supervisor_service": "velero.vsphere.vmware.com", "version": "1.5.1", "config_status": "ERROR",
         "messages": [{"severity": "ERROR", "details": {"default_message": "Reconcile failed."}}]}],
}


def fake_vcenter():
    """A local stand-in for the vCenter REST API (GET only, plus the session)."""
    import http.server
    import json as _json
    import threading
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def send(self, code, obj):
            data = _json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            seen.append(("POST", self.path))
            import base64 as b64
            auth = self.headers.get("Authorization", "")
            ok = auth == "Basic " + b64.b64encode(b"administrator@vsphere.local:Secr3t!").decode()
            self.send(201 if ok else 401, "token-123" if ok else {"error": "unauthorized"})

        def do_DELETE(self):
            seen.append(("DELETE", self.path))
            self.send(204, "")

        def do_GET(self):
            seen.append(("GET", self.path))
            if self.headers.get("vmware-api-session-id") != "token-123":
                return self.send(401, {})
            if self.path in FAKE_VC:
                return self.send(200, FAKE_VC[self.path])
            self.send(404, {"error": "not found"})

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1], seen


class VCenterNamespaces(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.seen = fake_vcenter()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_namespace_report_and_only_reads(self):
        api = v.VcApi("vc", "administrator@vsphere.local", "Secr3t!", base_url=self.base)
        api.login()
        self.assertIsNone(api.password)                      # not kept after login
        sup, ns, svc = v.api_supervisors(api), v.api_namespaces(api), v.api_services(api)
        api.logout()
        self.assertIn("supervisor: WIDGETS-MGMT-CL01 (domain-c8)  config=RUNNING  kubernetes=READY", sup)
        self.assertIn("WARNING: Control plane VM 10.20.30.42 is degraded.", sup)
        self.assertTrue(ns.startswith("Namespaces needing attention:\n  svc-velero-domain-c8: status=ERROR - ERROR: "
                                      "Failed to create network"))
        self.assertIn("namespace: widgets-finance  supervisor=WIDGETS-MGMT-CL01  status=RUNNING", ns)
        self.assertIn("access: USER devops@vsphere.local EDIT", ns)
        self.assertIn("VM classes: best-effort-small   content libraries: 1", ns)
        self.assertIn("velero.vsphere.vmware.com 1.5.1  config=ERROR", svc)
        self.assertEqual({m for m, _ in self.seen}, {"POST", "GET", "DELETE"})
        self.assertEqual([p for m, p in self.seen if m != "GET"], ["/api/session", "/api/session"])

    def test_wrong_password(self):
        api = v.VcApi("vc", "administrator@vsphere.local", "nope", base_url=self.base)
        with self.assertRaises(v.VcApiError) as e:
            api.login()
        self.assertIn("SSO login failed", str(e.exception))

    def test_names_are_anonymized(self):
        api = v.VcApi("vc", "administrator@vsphere.local", "Secr3t!", base_url=self.base)
        api.login()
        text = v.api_namespaces(api) + "\n" + v.api_supervisors(api)
        api.logout()
        sc = make()
        group = [g for g in v.COMPONENTS["vcenter"]["groups"] if g[0] == "vc-api-namespaces"][0]
        harvest(sc, group[2][1], text)
        out = run(sc, text)
        for gone in ("widgets", "WIDGETS", "10.20.30", "4c4c4544"):
            self.assertNotIn(gone, out)
        self.assertIn("svc-velero-domain-c8", out)           # product namespace stays readable
        self.assertRegex(out, r"namespace: ns-0001  supervisor=VCLUSTER-0001")


class FollowUpRegression(unittest.TestCase):
    """1.6.0 skipped the SSH login for follow-up plans (their checks live in host_groups)."""

    def prep(self, run_line, typ="supervisor"):
        import argparse
        with tempfile.TemporaryDirectory() as d:
            inv = os.path.join(d, "inventory.ini")
            with open(inv, "w") as fh:
                fh.write("[settings]\nanonymize = no\n[%s]\nhosts = 10.9.0.5\n" % typ)
            args = argparse.Namespace(inventory=inv, private_dir=os.path.join(d, "none"))
            return v.prepare_plan(args, "```vcf-plan\n[collect] target=10.9.0.5\nrun: %s\n```" % run_line)

    def test_follow_up_plans_ask_for_the_ssh_login(self):
        prep = self.prep("kubectl get kubeadmcontrolplane -n ns-a cl-b -o yaml")
        item = prep["plan"][0]
        self.assertEqual(item["groups"], [])
        self.assertTrue(v.plan_needs_ssh(item))

        class UI:
            asked = []

            def initial_credentials(self, sec):
                UI.asked.append(sec["name"])
                return ("root", "pw", None)

        import argparse
        import threading
        ctx = argparse.Namespace(cancel=threading.Event(), args=argparse.Namespace(parallel=1, strict_host_keys=False))
        ctx.cancel.set()               # stop right after the credentials are collected
        v.run_plan(ctx, prep["plan"], v.Scrubber(v.Mapping(None), anonymize=False), UI())
        self.assertEqual(UI.asked, ["supervisor"])

    def test_plain_kubectl_uses_the_detected_kubectl(self):
        step = self.prep("kubectl get kubeadmcontrolplane -A")["plan"][0]["host_groups"]["10.9.0.5"][0][2][0]
        self.assertEqual((step["mode"], step["cmd"]), ("kubectl", "{K} get kubeadmcontrolplane -A"))
        step = self.prep("journalctl -u kubelet | tail -n 5")["plan"][0]["host_groups"]["10.9.0.5"][0][2][0]
        self.assertEqual(step["mode"], "sh")
        step = self.prep("kubectl version", typ="linux")["plan"][0]["host_groups"]["10.9.0.5"][0][2][0]
        self.assertEqual(step["mode"], "sh")      # not a Kubernetes section: left as written


def fake_ai(target):
    """A local stand-in for an OpenAI-compatible chat endpoint: asks for one diagnostic,
    then concludes once it has seen the results."""
    import http.server
    import json as _json
    import threading
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = _json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
            last = body["messages"][-1]["content"]
            if "Results of round 1" in last:
                text = ("<think>private reasoning</think>ROOT CAUSE: kubelet on %s cannot reach the API server.\n"
                        "Evidence: the report shows the error.\n\n```vcf-plan\n[fix] target=%s\n"
                        "label: Restart kubelet\nrun: systemctl restart kubelet\nnote: brief node blip\n```" % (target, target))
            else:
                text = ("I suspect kubelet.\n\n```vcf-plan\nplan: kubelet check\n[collect] target=%s\n"
                        "label: kubelet log\nrun: journalctl -u kubelet -n 20\n[collect] target=%s\n"
                        "label: bad step\nrun: rm -rf /var/lib/kubelet\n```" % (target, target))
            data = _json.dumps({"choices": [{"message": {"role": "assistant", "content": text},
                                             "finish_reason": "stop"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d/v1" % srv.server_address[1], seen


class Investigations(unittest.TestCase):
    def run_case(self, anonymize):
        import argparse
        with tempfile.TemporaryDirectory() as d:
            inv = os.path.join(d, "inventory.ini")
            with open(inv, "w") as fh:
                fh.write("[settings]\nanonymize = %s\n[vcfmgmt:mgmt]\ncontrol_planes = 10.9.0.11\n"
                         "[ai]\nbase_url = placeholder\nmodel = test-model\n" % ("yes" if anonymize else "no"))
            target = "vcfmgmt-mgmt-01" if anonymize else "10.9.0.11"
            srv, base, seen = fake_ai(target)
            try:
                args = argparse.Namespace(inventory=inv, private_dir=os.path.join(d, "private"),
                                          output_dir=os.path.join(d, "out"), no_anonymize=False, max_lines=None)
                settings, _, _ = v.load_inventory(inv)
                cfg = v.ai_settings(settings)
                cfg["base_url"] = base
                events, approvals, collected = [], [], []

                def collect(a, st, secs, plan, ui, kind, title):
                    collected.append(plan)
                    return {"path": "/x/followup.md", "report": "kubelet: dial tcp 10.9.0.11:6443: connection refused"}

                def approve(prep):
                    approvals.append([e["command"] for e in prep["collect"]])
                    return True

                inv_run = v.Investigation(args, v.make_ai_client(cfg, "sk-test"), cfg,
                                          "Pods on 10.9.0.11 keep restarting", None,
                                          lambda k, t: events.append((k, t)), approve, collect=collect)
                result = inv_run.run()
                return result, seen, events, approvals, collected
            finally:
                srv.shutdown()
                srv.server_close()

    def test_loop_plain(self):
        result, seen, events, approvals, collected = self.run_case(False)
        self.assertEqual(result["how"], "concluded")
        self.assertEqual(len(seen), 2)
        self.assertTrue(seen[0]["path"].endswith("/v1/chat/completions"))
        self.assertEqual(seen[0]["auth"], "Bearer sk-test")
        self.assertEqual(seen[0]["body"]["model"], "test-model")
        self.assertEqual(seen[0]["body"]["messages"][0]["role"], "system")
        self.assertIn("Pods on 10.9.0.11 keep restarting", seen[0]["body"]["messages"][1]["content"])
        self.assertIn("@vcfmgmt:mgmt", seen[0]["body"]["messages"][1]["content"])
        # only the read-only step was approved and run; the destructive one was refused and reported
        self.assertEqual(approvals, [["journalctl -u kubelet -n 20"]])
        self.assertNotIn("rm -rf", str(collected))
        round2 = seen[1]["body"]["messages"][-1]["content"]
        self.assertIn("Refused [collect] step 'bad step'", round2)
        self.assertIn("connection refused", round2)
        self.assertTrue(result["conclusion"].startswith("ROOT CAUSE: kubelet on 10.9.0.11"))
        self.assertNotIn("private reasoning", result["conclusion"])
        self.assertEqual([e["command"] for e in result["manual"] if e["kind"] == "fix"], ["systemctl restart kubelet"])
        self.assertTrue(os.path.basename(result["path"]).startswith("vcf-investigation-"))

    def test_loop_anonymized(self):
        result, seen, events, approvals, collected = self.run_case(True)
        first = seen[0]["body"]["messages"][1]["content"]
        self.assertNotIn("10.9.0.11", first)                   # the admin's text is anonymized too
        self.assertIn("vcfmgmt-mgmt-01", first)
        self.assertEqual(list(collected[0][0]["host_groups"]), ["10.9.0.11"])   # translated back to run
        self.assertIn("ROOT CAUSE: kubelet on 10.9.0.11", result["conclusion"])  # shown with real names

    def test_round_limit_forces_a_conclusion(self):
        import argparse
        srv, base, seen = fake_ai("10.9.0.11")
        try:
            with tempfile.TemporaryDirectory() as d:
                inv = os.path.join(d, "inventory.ini")
                with open(inv, "w") as fh:
                    fh.write("[settings]\nanonymize = no\n[vcfmgmt:mgmt]\ncontrol_planes = 10.9.0.11\n"
                             "[ai]\nbase_url = x\nmodel = m\nmax_rounds = 1\n")
                args = argparse.Namespace(inventory=inv, private_dir=os.path.join(d, "p"),
                                          output_dir=os.path.join(d, "o"), no_anonymize=False, max_lines=None)
                cfg = v.ai_settings(v.load_inventory(inv)[0])
                cfg["base_url"] = base
                ran = []
                v.Investigation(args, v.make_ai_client(cfg, ""), cfg, "x", None, lambda k, t: None,
                                lambda p: ran.append(p) or True, collect=lambda *a, **k: None).run()
                self.assertEqual(ran, [])                      # no diagnostics beyond the limit
                self.assertIn("round limit is reached", seen[-1]["body"]["messages"][-1]["content"])
                self.assertIsNone(seen[0]["auth"])             # no key, no header
        finally:
            srv.shutdown()
            srv.server_close()

    def test_errors_are_explained(self):
        with self.assertRaises(v.AiError):
            v.AiClient("", "m", "k")
        c = v.AiClient("http://127.0.0.1:9/v1", "m", "k", timeout=2)
        with self.assertRaises(v.AiError) as e:
            c.chat([{"role": "user", "content": "x"}], retries=0)
        self.assertIn("cannot reach", str(e.exception))

    def test_long_reports_are_shortened_visibly(self):
        text, cut = v.report_for_ai("## How to reply (for the analyst)\nguide\n## Summary\n" + "x" * 20000, 6000)
        self.assertTrue(cut)
        self.assertNotIn("guide", text)
        self.assertIn("left out by the collector", text)


class SettingsModel(unittest.TestCase):
    def test_round_trip_and_inventory_compatibility(self):
        model = v.read_settings_model(v.INVENTORY_TEMPLATE)
        self.assertEqual(model["settings"]["anonymize"], "yes")
        self.assertTrue(any(g["type"] == "vcfmgmt" for g in model["groups"]))
        model["settings"]["anonymize"] = "no"
        model["ai"].update(base_url="https://ai.example.internal/v1", model="m1")
        model["groups"] = [{"type": "vcfmgmt", "label": "mgmt", "hosts": ["10.9.0.11", "10.9.0.12"], "ssh_workers": "yes",
                            "endpoints": [{"service": "VCF Operations", "endpoint": "ops01"},
                                          {"service": "Telemetry", "endpoint": ""}]},
                           {"type": "vcenter", "label": "", "hosts": ["vc01.example.internal"], "sso_user": "a@vsphere.local",
                            "tls_verify": "no"}]
        model["commands"] = [{"type": "esxi", "label": "Advanced", "command": "esxcli system settings advanced list -d"}]
        text = v.render_settings_model(model)
        again = v.read_settings_model(text)
        self.assertEqual(again["groups"][0]["endpoints"][1], {"service": "Telemetry", "endpoint": ""})  # kept, not dropped
        self.assertEqual(v.render_settings_model(again), text)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "i.ini")
            with open(path, "w") as fh:
                fh.write(text)
            settings, sections, custom = v.load_inventory(path)
        self.assertEqual(settings["anonymize"], "no")
        self.assertEqual(v.ai_settings(settings)["model"], "m1")
        self.assertEqual(sections[0]["hosts"], ["10.9.0.11", "10.9.0.12"])
        self.assertEqual(sections[0]["endpoints"], {"ops01": ["VCF Operations"]})   # empty row ignored
        self.assertFalse(sections[1]["tls_verify"])
        self.assertIn("esxi", custom)

    def test_bad_input_is_refused_with_a_message(self):
        base = {"settings": {}, "ai": {}, "commands": []}
        for groups, msg in (([{"type": "esxi", "label": "bad label!", "hosts": []}], "may only contain"),
                            ([{"type": "esxi", "label": "", "hosts": ["host one"]}], "not a host name"),
                            ([{"type": "nope", "label": "", "hosts": []}], "unknown component type"),
                            ([{"type": "vcfmgmt", "label": "", "hosts": [], "endpoints": [
                                {"service": "A", "endpoint": "x"}, {"service": "a", "endpoint": "y"}]}], "listed twice")):
            with self.assertRaises(v.Fatal) as e:
                v.render_settings_model(dict(base, groups=groups))
            self.assertIn(msg, str(e.exception))

    def test_keychain_through_the_security_command(self):
        import stat
        with tempfile.TemporaryDirectory() as d:
            store = os.path.join(d, "kc")
            script = os.path.join(d, "security")
            with open(script, "w") as fh:
                fh.write("#!/bin/sh\ncmd=$1; shift; a=; w=\nwhile [ $# -gt 0 ]; do case $1 in -a) a=$2; shift;; "
                         "-w) if [ $# -ge 2 ]; then w=$2; shift; fi;; esac; shift; done\n"
                         "case $cmd in find-generic-password) grep -F \"$a|\" %s 2>/dev/null | cut -d'|' -f2 | grep . || exit 44;;\n"
                         "add-generic-password) printf '%%s|%%s\\n' \"$a\" \"$w\" > %s;;\n"
                         "delete-generic-password) : > %s;; esac\n" % (store, store, store))
            os.chmod(script, stat.S_IRWXU)
            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = d + os.pathsep + old_path
            os.environ["VCFDIAG_FAKE_KEYCHAIN"] = "1"
            try:
                self.assertTrue(v.keychain_available())
                self.assertEqual(v.keychain_get("https://ai/v1"), "")
                v.keychain_set("https://ai/v1", "sk-123")
                self.assertEqual(v.keychain_get("https://ai/v1"), "sk-123")
                cfg = v.ai_settings({"_ai": {"base_url": "https://ai/v1"}})
                self.assertEqual(v.resolve_ai_key(cfg), "sk-123")
                self.assertEqual(v.resolve_ai_key(cfg, session="sk-session"), "sk-session")
                self.assertEqual(v.resolve_ai_key(cfg, typed="sk-typed", session="sk-session"), "sk-typed")
                v.keychain_delete("https://ai/v1")
                self.assertEqual(v.keychain_get("https://ai/v1"), "")
            finally:
                os.environ["PATH"] = old_path
                del os.environ["VCFDIAG_FAKE_KEYCHAIN"]


FAKE_NSX = {
    "/api/v1/cluster/status": {
        "mgmt_cluster_status": {"status": "STABLE"}, "control_cluster_status": {"status": "STABLE"},
        "detailed_cluster_status": {"overall_status": "DEGRADED", "groups": [
            {"group_type": "MANAGER", "group_status": "DEGRADED", "members": [
                {"member_fqdn": "nsx01.corp.example-widgets.com", "member_ip": "10.20.30.11", "member_status": "UP"},
                {"member_fqdn": "nsx02.corp.example-widgets.com", "member_ip": "10.20.30.12", "member_status": "DOWN"}]}]}},
    "/api/v1/alarms?status=OPEN,ACKNOWLEDGED,SUPPRESSED&page_size=500": {"results": [
        {"severity": "MEDIUM", "status": "OPEN", "feature_name": "certificates", "event_type": "certificate_expiration_approaching",
         "last_reported_time": 1763380000000, "node_display_name": "nsx01", "summary": "Certificate expires in 20 days."}],
        "cursor": "p2"},
    "/api/v1/alarms?status=OPEN,ACKNOWLEDGED,SUPPRESSED&page_size=500&cursor=p2": {"results": [
        {"severity": "CRITICAL", "status": "OPEN", "feature_name": "manager_health", "event_type": "manager_cpu_usage_very_high",
         "last_reported_time": 1763390000000, "node_display_name": "nsx02", "description": "CPU above 95%.",
         "recommended_action": "Check the node."}]},
    "/api/v1/transport-nodes?page_size=500": {"results": [
        {"id": "tn1", "display_name": "esx01.corp.example-widgets.com", "node_deployment_info": {"resource_type": "HostNode"}},
        {"id": "tn2", "display_name": "edge01", "node_deployment_info": {"resource_type": "EdgeNode"}}]},
    "/api/v1/transport-nodes/state?page_size=500": {"results": [
        {"transport_node_id": "tn1", "state": "success"},
        {"transport_node_id": "tn2", "state": "failed", "failure_message": "Host config failed: MTU mismatch",
         "node_deployment_state": {"state": "NODE_READY"}}]},
    "/api/v1/edge-clusters?page_size=200": {"results": [{"display_name": "WIDGETS-EC01", "members": [{}, {}],
                                                         "deployment_type": "VIRTUAL_MACHINE"}]},
    "/api/v1/cluster/backups/config": {"backup_enabled": False},
    "/api/v1/cluster/backups/history": {"cluster_backup_statuses": [
        {"start_time": 1763300000000, "success": False, "error_message": "SFTP server unreachable"}]},
}


def fake_nsx():
    import base64 as b64
    import http.server
    import json as _json
    import threading
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            seen.append((self.command, self.path))
            ok = self.headers.get("Authorization") == "Basic " + b64.b64encode(b"admin:Nsx-Pass1!").decode()
            code, body = (200, FAKE_NSX[self.path]) if ok and self.path in FAKE_NSX else ((401, {}) if not ok else (404, {}))
            data = _json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1], seen


class NsxAndOpsNet(unittest.TestCase):
    def setUp(self):
        self.srv, self.base, self.seen = fake_nsx()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_nsx_api_checks(self):
        api = v.NsxApi("nsx", "admin", "Nsx-Pass1!", base_url=self.base)
        api.login()
        self.assertIsNone(api.password)
        cl, al, tn, ec, bk = (f(api) for f in (v.nsx_cluster, v.nsx_alarms, v.nsx_transport_nodes,
                                                 v.nsx_edge_clusters, v.nsx_backups))
        self.assertIn("overall: DEGRADED", cl)
        self.assertIn("member: nsx02.corp.example-widgets.com  10.20.30.12  DOWN", cl)
        self.assertTrue(al.startswith("2 alarm(s): CRITICAL OPEN 1, MEDIUM OPEN 1"))
        self.assertLess(al.index("manager_cpu_usage_very_high"), al.index("certificate_expiration"))   # worst first
        self.assertIn("recommended action: Check the node.", al)
        self.assertIn("transport node: edge01  type=EdgeNode  state=failed", tn)
        self.assertIn("MTU mismatch", tn)
        self.assertIn("edge cluster: WIDGETS-EC01  members=2", ec)
        self.assertIn("automatic backups: NOT enabled", bk)
        self.assertIn("FAILED  SFTP server unreachable", bk)
        self.assertTrue(all(m == "GET" for m, _ in self.seen))

    def test_nsx_wrong_password_and_anonymization(self):
        with self.assertRaises(v.VcApiError) as e:
            v.NsxApi("nsx", "admin", "wrong", base_url=self.base).login()
        self.assertIn("NSX API login failed", str(e.exception))
        api = v.NsxApi("nsx", "admin", "Nsx-Pass1!", base_url=self.base)
        api.login()
        text = "\n".join(f(api) for f in (v.nsx_cluster, v.nsx_alarms, v.nsx_transport_nodes, v.nsx_edge_clusters))
        sc = make()
        group = [g for g in v.COMPONENTS["nsx"]["groups"] if g[0] == "nsx-api-health"][0]
        for c in group[2]:
            harvest(sc, c, text)
        out = run(sc, text)
        for gone in ("example-widgets", "WIDGETS", "10.20.30", "nsx02", "edge01"):
            self.assertNotIn(gone, out)

    def test_component_wiring(self):
        self.assertTrue(v.is_api_group("nsx-api-health"))
        self.assertFalse(v.is_api_group("nsx-cluster"))
        op = v.COMPONENTS["opsnet"]
        self.assertEqual(op["user"], "support")
        self.assertEqual([g[0] for g in op["groups"]][:2], ["opsnet-cli", "opsnet-health"])
        self.assertEqual(op["nsxcli_wrap"].format(q="'x y'", c="ssh-service status"), "ssh-service status")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "i.ini")
            with open(path, "w") as fh:
                fh.write("[nsx]\nhosts = 10.1.1.1, 10.1.1.2\n[opsnet]\nhosts = 192.168.0.50\n")
            _, sections, _ = v.load_inventory(path)
        self.assertEqual(sections[0]["sso_user"], "admin")
        self.assertEqual(sections[1]["user"], "support")


def fake_asksage(openai_compatible):
    """Stand-in Ask Sage server: native API always, OpenAI-compatible API optionally."""
    import http.server
    import json as _json
    import threading
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def send(self, code, obj):
            data = _json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def handle_any(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = _json.loads(self.rfile.read(n)) if n else None
            seen.append((self.command, self.path, dict(self.headers), body))
            if self.path.startswith("/server/openai/v1"):
                if not openai_compatible:
                    return self.send(404, {"error": "not found"})
                if self.headers.get("Authorization") != "Bearer sk-sage":
                    return self.send(401, {})
                if self.path.endswith("/models"):
                    return self.send(200, {"data": [{"id": "gpt-4o"}, {"id": "claude-3-5-sonnet"}]})
                return self.send(200, {"choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}]})
            if not self.path.startswith("/server/"):
                return self.send(404, {"error": "not found"})
            if self.headers.get("x-access-tokens") != "sk-sage":
                return self.send(401, {})
            if self.path == "/server/get-models":
                return self.send(200, {"response": ["gpt-4o-gov", "aws-bedrock-claude-35-sonnet-gov"], "status": 200})
            if self.path == "/server/query":
                return self.send(200, {"message": "OK from native", "response": "OK", "status": 200})
            self.send(404, {})

        do_GET = do_POST = handle_any

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1], seen


class AiEndpoints(unittest.TestCase):
    def test_addresses_people_type(self):
        n = v.normalize_ai_url
        self.assertEqual(n("capra1.flankspeed.us.local.mil", "asksage"),
                         "https://capra1.flankspeed.us.local.mil/server/openai/v1")
        self.assertEqual(n("https://capra1.example.mil/", "asksage"), "https://capra1.example.mil/server/openai/v1")
        self.assertEqual(n("ai.example.internal/v1/chat/completions"), "https://ai.example.internal/v1")
        self.assertEqual(n("http://10.1.1.5:8000/v1"), "http://10.1.1.5:8000/v1")
        self.assertEqual(n("https://x.openai.azure.com/openai/deployments/d?api-version=2024-06-01", "azure"),
                         "https://x.openai.azure.com/openai/deployments/d?api-version=2024-06-01")
        for bad in ("ftp://x", "https://", "::"):
            with self.assertRaises(v.AiError):
                n(bad)
        self.assertEqual(v.AiClient("capra1.example.mil", "m", "k", provider="asksage").url,
                         "https://capra1.example.mil/server/openai/v1/chat/completions")

    def test_asksage_native_only(self):
        srv, base, seen = fake_asksage(openai_compatible=False)
        try:
            host = base.replace("http://", "http://")
            c = v.AiClient(host, "gpt-4o-gov", "sk-sage", provider="asksage")
            self.assertEqual(c.list_models(), ["aws-bedrock-claude-35-sonnet-gov", "gpt-4o-gov"])
            reply = c.chat([{"role": "system", "content": "SYSTEM RULES"}, {"role": "user", "content": "the problem"}],
                           retries=0)
            self.assertEqual(reply, "OK from native")
            self.assertEqual(c.flavor, "native")              # remembered for the rest of the investigation
            q = [x for x in seen if x[1] == "/server/query"][-1]
            self.assertEqual({k.lower(): v_ for k, v_ in q[2].items()}.get("x-access-tokens"), "sk-sage")
            self.assertEqual(q[3]["model"], "gpt-4o-gov")
            self.assertIn("SYSTEM RULES", q[3]["message"])
            self.assertIn("the problem", q[3]["message"])
            with self.assertRaises(v.AiError) as e:
                v.AiClient(host, "m", "wrong", provider="asksage").chat([{"role": "user", "content": "x"}], retries=0)
            self.assertIn("rejected the API key", str(e.exception))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_asksage_openai_compatible(self):
        srv, base, seen = fake_asksage(openai_compatible=True)
        try:
            c = v.AiClient(base, "gpt-4o", "sk-sage", provider="asksage")
            self.assertEqual(c.list_models(), ["claude-3-5-sonnet", "gpt-4o"])
            self.assertEqual(c.chat([{"role": "user", "content": "x"}], retries=0), "OK")
            self.assertEqual(c.flavor, "openai")
            self.assertFalse(any(p == "/server/query" for _, p, _, _ in seen))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_plain_openai_404_is_explained(self):
        srv, base, seen = fake_asksage(openai_compatible=False)
        try:
            with self.assertRaises(v.AiError) as e:
                v.AiClient(base + "/v1", "m", "k").chat([{"role": "user", "content": "x"}], retries=0)
            self.assertIn("not found (HTTP 404)", str(e.exception))
        finally:
            srv.shutdown()
            srv.server_close()


class ProxyFallback(unittest.TestCase):
    def test_refusing_proxy_is_bypassed(self):
        """A proxy that answers CONNECT with 503 (like a corporate proxy that cannot reach an
        internal server): the client must retry directly and say so."""
        import http.server
        import socketserver
        import threading

        class Proxy(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_CONNECT(self):
                self.send_response(503, "Service Unavailable")
                self.end_headers()

            do_POST = do_GET = do_CONNECT

        proxy = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Proxy)
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        srv, base, seen = fake_asksage(openai_compatible=True)
        saved = {k: os.environ.get(k) for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "no_proxy", "NO_PROXY")}
        try:
            for k in saved:
                os.environ.pop(k, None)
            os.environ["http_proxy"] = os.environ["HTTP_PROXY"] = "http://127.0.0.1:%d" % proxy.server_address[1]
            c = v.AiClient(base, "gpt-4o", "sk-sage", provider="asksage")
            self.assertEqual(c.chat([{"role": "user", "content": "x"}], retries=0), "OK")
            self.assertIn("proxy refused", c.note)
            c2 = v.AiClient(base, "gpt-4o", "sk-sage", provider="asksage", use_proxy=False)
            self.assertEqual(c2.chat([{"role": "user", "content": "x"}], retries=0), "OK")
            self.assertEqual(c2.note, "")
        finally:
            for k, val in saved.items():
                if val is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = val
            srv.shutdown()
            srv.server_close()
            proxy.shutdown()
            proxy.server_close()


class GuiApi(unittest.TestCase):
    """The browser GUI's local web API, without contacting any host."""

    def setUp(self):
        import argparse
        import http.client
        import http.server
        import threading
        self.dir = tempfile.TemporaryDirectory()
        d = self.dir.name
        self.inv = os.path.join(d, "inventory.ini")
        args = argparse.Namespace(inventory=self.inv, private_dir=os.path.join(d, "private"),
                                  output_dir=os.path.join(d, "out"), parallel=None, max_lines=200,
                                  strict_host_keys=False, timeout_scale=None, connect_timeout=5,
                                  no_browser=True)
        self.gui = v.Gui(args)
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), v.GuiHandler)
        self.httpd.gui = self.gui
        self.gui.httpd = self.httpd
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.http = http.client

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.dir.cleanup()

    def call(self, route, body=None, token=None, headers=None):
        import json
        c = self.http.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        c.request("POST" if body is not None else "GET", "/%s/%s" % (token or self.gui.token, route),
                  body=json.dumps(body) if body is not None else None, headers=h)
        r = c.getresponse()
        data = r.read().decode()
        c.close()
        return r.status, (json.loads(data) if route.startswith("api/") else data)

    def test_access_is_limited_to_the_secret_local_url(self):
        self.assertEqual(self.call("api/state", token="wrong")[0], 403)
        self.assertEqual(self.call("api/state", headers={"Host": "evil.example"})[0], 403)
        self.assertEqual(self.call("api/state", headers={"Origin": "http://evil.example"})[0], 403)
        code, page = self.call("")
        self.assertEqual(code, 200)
        self.assertIn("VCF Diagnostics", page)
        self.assertNotIn("http://", page.replace("http://www.w3.org", ""))   # no outside resources

    def test_inventory_round_trip_and_validation(self):
        code, inv = self.call("api/inventory")
        self.assertFalse(inv["exists"])
        self.assertEqual(inv["text"], v.INVENTORY_TEMPLATE)
        code, out = self.call("api/inventory", {"text": "[bogus]\nhosts = a\n"})
        self.assertEqual(code, 400)
        self.assertIn("unknown component type", out["error"])
        self.assertFalse(os.path.exists(self.inv))
        good = "[esxi:mgmt]\nhosts = esx01.corp.example-widgets.com\n[sddc]\nhosts = 10.1.1.9\nescalate = su\n"
        self.assertEqual(self.call("api/inventory", {"text": good})[0], 200)
        self.assertEqual(os.stat(self.inv).st_mode & 0o777, 0o600)
        code, st = self.call("api/state")
        self.assertEqual([s["name"] for s in st["sections"]], ["esxi:mgmt", "sddc"])
        self.assertEqual(st["sections"][1]["escalate"], "su")
        self.assertTrue(st["sections"][0]["groups"][0]["checks"])

    def test_run_requires_a_valid_selection(self):
        self.call("api/inventory", {"text": "[esxi]\nhosts = esx01.corp.example-widgets.com\n"})
        code, out = self.call("api/run", {"sections": {}})
        self.assertEqual((code, out["error"]), (400, "nothing selected"))
        code, out = self.call("api/run", {"sections": {"esxi": {"hosts": ["esx01.corp.example-widgets.com"],
                                                               "groups": ["system"], "password": ""}}})
        self.assertEqual(code, 400)
        self.assertIn("no password", out["error"])
        self.assertEqual(self.call("api/status?since=0")[1]["state"], "idle")

    def test_reply_is_translated_and_fixes_are_never_runnable(self):
        self.call("api/inventory", {"text": "[esxi]\nhosts = esx01.corp.example-widgets.com\n"
                                            "[vcenter]\nhosts = vc01.corp.example-widgets.com\n"})
        self.call("api/scrub", {"text": "seed the mapping 10.1.1.5"})
        code, plan = self.call("api/plan", {"text": REPLY})
        self.assertEqual(code, 200)
        self.assertEqual([e["label"] for e in plan["collect"]], ["vpxd errors"])
        self.assertEqual({e["kind"] for e in plan["manual"]}, {"fix", "blocked"})
        self.assertEqual([lg["name"] for lg in plan["logins"]], ["vcenter"])
        self.assertIn("vc01.corp.example-widgets.com", plan["translated"])
        # a reply that only contains fixes offers nothing to run
        only_fix = "```vcf-plan\n[fix] target=vcenter-01\nrun: service-control --restart vmware-vpxd\n```"
        code, out = self.call("api/plan_run", {"text": only_fix, "sections": {"vcenter": {"password": "x"}}})
        self.assertEqual(code, 400)
        self.assertIn("no read-only diagnostics", out["error"])
        self.assertEqual(self.call("api/status?since=0")[1]["state"], "idle")

    def test_investigate_needs_an_ai_and_a_problem(self):
        self.call("api/inventory", {"text": "[esxi]\nhosts = esx01.corp.example-widgets.com\n"})
        code, st = self.call("api/state")
        self.assertFalse(st["ai"]["configured"])
        code, out = self.call("api/investigate", {"problem": "x"})
        self.assertEqual(code, 400)
        self.assertIn("[ai] section", out["error"])
        self.call("api/inventory", {"text": "[esxi]\nhosts = esx01.corp.example-widgets.com\n"
                                            "[ai]\nbase_url = http://127.0.0.1:9/v1\nmodel = m\n"})
        code, st = self.call("api/state")
        self.assertTrue(st["ai"]["configured"])
        code, out = self.call("api/investigate", {"problem": "  "})
        self.assertEqual((code, out["error"]), (400, "describe the problem first"))
        self.assertEqual(self.call("api/status?since=0")[1]["state"], "idle")

    def test_settings_api_and_ai_test(self):
        code, r = self.call("api/settings")
        self.assertEqual(code, 200)
        self.assertFalse(r["meta"]["exists"])
        self.assertIn("vcfmgmt", [t["type"] for t in r["meta"]["types"]])
        model = r["model"]
        model["groups"] = [{"type": "esxi", "label": "mgmt", "hosts": ["esx01.corp.example-widgets.com"]}]
        srv, base, seen = fake_ai("esxi-mgmt-01")
        try:
            model["ai"].update(base_url=base, model="m")
            code, out = self.call("api/ai_test", {"ai": model["ai"], "key": "sk-1"})
            self.assertEqual(code, 200)
            self.assertTrue(out["used_key"])
            self.assertEqual(seen[-1]["auth"], "Bearer sk-1")
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(self.call("api/settings", {"model": model})[0], 200)
        self.assertEqual(os.stat(self.inv).st_mode & 0o777, 0o600)
        code, st = self.call("api/state")
        self.assertEqual([s["name"] for s in st["sections"]], ["esxi:mgmt"])
        self.assertTrue(st["ai"]["configured"])
        model["groups"][0]["label"] = "bad label"
        code, out = self.call("api/settings", {"model": model})
        self.assertEqual(code, 400)
        self.assertIn("may only contain", out["error"])
        code, out = self.call("api/ai_key", {"action": "session", "key": "sk-2", "base_url": base})
        self.assertTrue(out["key"]["session"])

    def test_ai_models_and_bad_address_in_the_window(self):
        srv, base, seen = fake_asksage(openai_compatible=False)
        try:
            code, out = self.call("api/ai_models", {"ai": {"provider": "asksage", "base_url": base}, "key": "sk-sage"})
            self.assertEqual(code, 200)
            self.assertIn("gpt-4o-gov", out["models"])
            code, out = self.call("api/ai_test", {"ai": {"provider": "asksage", "base_url": base, "model": "gpt-4o-gov"},
                                                  "key": "sk-sage"})
            self.assertEqual((code, out["flavor"]), (200, "native Ask Sage API"))
        finally:
            srv.shutdown()
            srv.server_close()
        code, out = self.call("api/ai_test", {"ai": {"base_url": "ftp://nope", "model": "m"}})
        self.assertEqual(code, 400)
        self.assertIn("not a valid endpoint address", out["error"])
        code, out = self.call("api/ai_test", {"ai": {"base_url": "capra1.example.mil", "provider": "asksage"}})
        self.assertIn("choose a model first", out["error"])

    def test_anonymize_and_translate_back(self):
        self.call("api/inventory", {"text": "[esxi]\nhosts = esx01.corp.example-widgets.com\n"})
        code, out = self.call("api/scrub", {"text": "esx01.corp.example-widgets.com at 10.4.4.4 password=hunter2"})
        self.assertEqual(code, 200)
        self.assertEqual(out["text"], "esxi-01.domain-01 at ip-n1-h1 password=[REDACTED]")
        self.assertEqual(out["review"]["hits"], [])
        code, back = self.call("api/decode", {"text": "check esxi-01.domain-01 and ip-n1-h1"})
        self.assertEqual(back["text"], "check esx01.corp.example-widgets.com and 10.4.4.4")


if __name__ == "__main__":
    unittest.main()
