"""Unit tests for the anonymizer and the non-network parts of vcf_diag.

Run from the repository root:  python3 -m unittest discover -s tests -v
All names and addresses below are invented.
"""
import os
import re
import sys
import tempfile
import types
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

    def test_event_ages_and_quantities_are_never_learned_as_names(self):
        # Regression: cols[1] of "kubectl get events -A" is LAST SEEN (10m, 11m ...); these were
        # learned as k8s object names and then replaced everywhere (df sizes, top pods CPU ...).
        sc = make()
        events = ("NAMESPACE   LAST SEEN   TYPE      REASON      OBJECT                     MESSAGE\n"
                  "widgets-ns  10m         Warning   Unhealthy   pod/ledger-api-7f6d5c4b3   Readiness probe failed\n"
                  "widgets-ns  11m         Warning   BackOff     pod/ledger-db-0            Back-off restarting\n"
                  "widgets-ns  2d3h        Warning   Failed      pod/ledger-db-1            failed\n")
        noheader = "widgets-ns   14m   Warning   Unhealthy   pod/ledger-api-7f6d5c4b3   probe failed\n"
        top = ("NAMESPACE NAME CPU(cores) MEMORY(bytes)\n"
               "widgets-ns pgdatabase-0 250m 2236Mi\n")
        sc.learn_k8s("nsrows", events)
        sc.learn_k8s("nsrows", noheader)
        sc.learn_k8s("nsrows", top)
        for q in ("10m", "11m", "14m", "2d3h", "250m", "2236Mi", "10M", "15%"):
            self.assertIsNone(sc.learn_term("k8sobj", q), q)
        df = ("Filesystem Size Used Avail Use% Mounted on\n"
              "/dev/sda2 10M 2.0M 8.0M 20% /boot/efi\ntmpfs 3.9G 11M 3.9G 1% /run\n")
        out = run(sc, events + noheader + top + df)
        self.assertNotIn("K8SOBJ", out)
        self.assertEqual(len(sc.m.maps.get("k8sobj", {})), 5)      # four pod names + pgdatabase, nothing else
        for keep in (" 10m ", " 11m ", " 2d3h ", "250m 2236Mi", "/dev/sda2 10M 2.0M", "tmpfs 3.9G 11M"):
            self.assertIn(keep, out)
        for gone in ("ledger-api", "ledger-db", "pgdatabase-0", "widgets-ns"):
            self.assertNotIn(gone, out)

    def test_nsrows_learns_the_name_column_only_where_the_header_has_one(self):
        sc = make()
        sc.learn_k8s("nsrows", "NAMESPACE   LAST SEEN   TYPE   REASON   OBJECT   MESSAGE\n"
                               "widgets-ns  33s   Warning   FailedMount   widgetsvol   nope\n")
        self.assertIsNone(sc.m.lookup("k8sobj", "33s"))
        self.assertIsNone(sc.m.lookup("k8sobj", "warning"))
        sc.learn_k8s("nsrows", "NAMESPACE NAME READY STATUS\nwidgets-ns ledger-api-1 1/1 Running\n")
        self.assertTrue(sc.m.lookup("k8sobj", "ledger-api-1"))

    def test_vib_versions_are_not_ip_addresses(self):
        sc = make()
        vibs = ("nsx-python-protobuf   4.2.1.0-9.1.24837353   VMware  VMwareCertified  2025-03-01\n"
                "nsx-esx-datapath      9.1.0.0-0.0.24837353   VMware  VMwareCertified  2025-03-01\n"
                "range 10.40.1.10-10.40.1.20 host 10.40.1.5\n")
        out = run(sc, vibs)
        self.assertIn("4.2.1.0-9.1.24837353", out)
        self.assertIn("9.1.0.0-0.0.24837353", out)
        for gone in ("10.40.1.10", "10.40.1.20", "10.40.1.5"):
            self.assertNotIn(gone, out)



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
                         {"k8s-cluster", "k8s-workloads", "k8s-storage", "k8s-events", "k8s-health", "k8s-vcf", "k8s-nodes",
                          "endpoints"})

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
        # full API detail only for objects that are not healthy
        self.assertEqual(ns.count("--- full detail"), 1)
        self.assertLess(ns.index("== namespace svc-velero-domain-c8"), ns.index("--- full detail"))
        self.assertIn("--- full detail", sup)                # kubernetes=WARNING with messages
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
    "/api/v1/transport-nodes/state": {"results": [
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
            self.assertIn("not found at", str(e.exception))
            self.assertIn("(HTTP 404)", str(e.exception))
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


class NamedProxy(unittest.TestCase):
    def test_proxy_named_in_settings_is_used(self):
        """A working forward proxy given in the settings carries the request (like the proxy a PAC
        file would choose), even when the Mac has no proxy configured."""
        import http.server
        import socketserver
        import threading
        used = []

        class Forward(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def relay(self):
                used.append(self.path)
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else None
                req = urllib.request.Request(self.path, data=body, method=self.command,
                                             headers={k: v_ for k, v_ in self.headers.items() if k.lower() != "host"})
                direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with direct.open(req) as r:
                    data = r.read()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = relay

        import urllib.request
        proxy = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Forward)
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        srv, base, seen = fake_asksage(openai_compatible=True)
        try:
            c = v.AiClient(base, "gpt-4o", "sk-sage", provider="asksage", use_proxy=False,
                           proxy="127.0.0.1:%d" % proxy.server_address[1])
            self.assertEqual(c.chat([{"role": "user", "content": "x"}], retries=0), "OK")
            self.assertTrue(used and used[0].startswith(base))
            self.assertEqual(c.note, "")
        finally:
            srv.shutdown()
            srv.server_close()
            proxy.shutdown()
            proxy.server_close()

    def test_name_lookup_failure_is_explained(self):
        with self.assertRaises(v.AiError) as e:
            v.AiClient("capra1.example.invalid", "m", "k", provider="asksage", use_proxy=False).chat(
                [{"role": "user", "content": "x"}], retries=0)
        self.assertIn("cannot look up the server name", str(e.exception))
        cfg = v.ai_settings({"_ai": {"provider": "asksage", "base_url": "capra1.example.invalid", "model": "m",
                                     "use_proxy": "no"}})
        text = v.ai_connection_check(cfg, "")
        self.assertIn("[FAIL] name lookup", text)
        self.assertIn("route the tool will use: direct (no proxy)", text)
        self.assertNotIn("sk-", text)


class AskSageApiHost(unittest.TestCase):
    def test_api_host_is_derived_from_the_chat_host(self):
        c = v.AiClient("chat.capra.example.mil", "m", "k", provider="asksage")
        self.assertEqual([r[0] for r in c.roots], ["https://chat.capra.example.mil/server/openai/v1",
                                                   "https://api.capra.example.mil/server/openai/v1"])
        self.assertEqual(c.roots[1][1], "https://api.capra.example.mil/server")
        self.assertEqual(len(v.AiClient("api.capra.example.mil", "m", "k", provider="asksage").roots), 1)
        self.assertEqual(len(v.AiClient("https://x.example.mil/custom/v1", "m", "k", provider="asksage").roots), 1)
        self.assertFalse(any("api." in r[0] for r in v.AiClient("chat.example.mil", "m", "k").roots))  # Ask Sage only

    def test_falls_through_to_the_api_host(self):
        import http.server
        import threading

        class Nothing(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def nope(self):
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = do_POST = nope

        chat = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Nothing)
        threading.Thread(target=chat.serve_forever, daemon=True).start()
        api, api_base, seen = fake_asksage(openai_compatible=False)
        chat_base = "http://127.0.0.1:%d" % chat.server_address[1]
        try:
            c = v.AiClient(chat_base, "gpt-4o-gov", "sk-sage", provider="asksage")
            c.roots = [(chat_base + "/server/openai/v1", chat_base + "/server"),
                       (api_base + "/server/openai/v1", api_base + "/server")]
            self.assertIn("gpt-4o-gov", c.list_models())
            self.assertEqual(c.root_i, 1)                  # remembered
            self.assertEqual(c.chat([{"role": "user", "content": "x"}], retries=0), "OK from native")
            c2 = v.AiClient(chat_base, "m", "sk-sage", provider="asksage")
            c2.roots = [(chat_base + "/server/openai/v1", chat_base + "/server")]
            with self.assertRaises(v.AiError) as e:
                c2.chat([{"role": "user", "content": "x"}], retries=0)
            self.assertIn("no Ask Sage API answered. Tried:", str(e.exception))
            self.assertIn("/server/query (HTTP 404)", str(e.exception))
            with self.assertRaises(v.AiError) as e:
                c2.list_models()
            self.assertIn("no Ask Sage API answered", str(e.exception))
        finally:
            chat.shutdown()
            chat.server_close()
            api.shutdown()
            api.server_close()


def scripted_ai(answer):
    """Stand-in OpenAI-compatible endpoint whose reply is computed by answer(messages)."""
    import http.server
    import json as _json
    import threading
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = _json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append(body["messages"])
            data = _json.dumps({"choices": [{"message": {"content": answer(body["messages"])},
                                             "finish_reason": "stop"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d/v1" % srv.server_address[1], seen


PLAN_COLLECT = "Need data.\n```vcf-plan\n[collect] target=10.9.0.11\nlabel: kubelet log\nrun: journalctl -u kubelet -n 20\n```"
PLAN_FIX = ("ROOT CAUSE: expired kubelet certificate on 10.9.0.11.\nEvidence: x509 expired.\n```vcf-plan\n"
            "[fix] target=10.9.0.11\nlabel: Renew kubelet certificate\nrun: kubeadm certs renew all &&\n"
            "  systemctl restart kubelet\nnote: node restarts kubelet\n[fix] target=10.9.0.11\n"
            "label: Verify kubelet\nrun: systemctl is-active kubelet\n```")


class Conversation(unittest.TestCase):
    def setUp(self):
        import argparse
        self.dir = tempfile.TemporaryDirectory()
        d = self.dir.name
        self.inv = os.path.join(d, "inventory.ini")
        with open(self.inv, "w") as fh:
            fh.write("[settings]\nanonymize = no\n[vcfmgmt:mgmt]\ncontrol_planes = 10.9.0.11\n[ai]\nbase_url = x\nmodel = m\n")
        self.args = argparse.Namespace(inventory=self.inv, private_dir=os.path.join(d, "p"),
                                       output_dir=os.path.join(d, "o"), no_anonymize=False, max_lines=None)

    def tearDown(self):
        self.dir.cleanup()

    def investigation(self, base, approve):
        cfg = v.ai_settings(v.load_inventory(self.inv)[0])
        cfg["base_url"] = base
        events = []
        inv = v.Investigation(self.args, v.make_ai_client(cfg, ""), cfg, "kubelet keeps failing", None,
                              lambda k, t_: events.append((k, t_)), approve,
                              collect=lambda *a, **k: {"path": "/x", "report": "x509: certificate has expired"})
        return inv, events

    def test_general_advice_is_sent_back(self):
        def answer(msgs):
            last = msgs[-1]["content"]
            if "does not follow the required format" in last:
                return PLAN_FIX
            return "You should check the kubelet logs and verify the certificates, then restart the service."
        srv, base, seen = scripted_ai(answer)
        try:
            inv, events = self.investigation(base, lambda p: "run")
            res = inv.run()
            self.assertEqual(res["how"], "concluded")
            self.assertEqual(len(seen), 2)                     # one correction round trip
            self.assertEqual([e["label"] for e in res["manual"]], ["Renew kubelet certificate", "Verify kubelet"])
            script = v.plan_as_script([e for e in res["manual"] if e["kind"] == "fix"], "Fix steps")
            self.assertIn("# 1. Renew kubelet certificate\n#    on: 10.9.0.11\n#    note: node restarts kubelet\n"
                          "kubeadm certs renew all &&\nsystemctl restart kubelet", script)
            self.assertIn("# 2. Verify kubelet", script)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_root_cause_without_fix_commands_is_sent_back(self):
        def answer(msgs):
            if "no fix steps" in msgs[-1]["content"]:
                return PLAN_FIX
            return "ROOT CAUSE: expired certificate. Renew it and restart kubelet."
        srv, base, seen = scripted_ai(answer)
        try:
            res = self.investigation(base, lambda p: "run")[0].run()
            self.assertEqual(len(seen), 2)
            self.assertTrue(any(e["kind"] == "fix" for e in res["manual"]))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_question_asking_for_a_secret_is_sent_back(self):
        ask = ("QUESTION FOR THE ADMINISTRATOR: Could you please provide the administrator@vsphere.local password "
               "or perform a password rotation in SDDC Manager?")

        def answer(msgs):
            if "Do not ask the administrator for passwords" in msgs[-1]["content"]:
                return "QUESTION FOR THE ADMINISTRATOR: did a password rotation fail in SDDC Manager this week?"
            return ask
        srv, base, seen = scripted_ai(answer)
        try:
            inv, events = self.investigation(base, lambda p: "run")
            res = inv.run()
            self.assertEqual(len(seen), 2)
            self.assertIn("Never ask the administrator for a password", seen[0][0]["content"])
            self.assertEqual(res["how"], "question")
            self.assertEqual(res["question"], "did a password rotation fail in SDDC Manager this week?")
            self.assertFalse(any(k == "warn" and "secret" in str(t) for k, t in events))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_persistent_secret_request_warns_the_administrator(self):
        srv, base, seen = scripted_ai(lambda msgs: "QUESTION FOR THE ADMINISTRATOR: please share the NSX admin password.")
        try:
            inv, events = self.investigation(base, lambda p: "run")
            inv.run()
            self.assertEqual(len(seen), 3)                    # first answer + two corrections
            self.assertTrue(any(k == "warn" and "Do not type it here" in str(t) for k, t in events))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_secret_request_detection(self):
        q = "QUESTION FOR THE ADMINISTRATOR: "
        for text in ("Could you please provide the administrator@vsphere.local password?",
                     "What is the root password of esxi-01?", "Please paste the API token.",
                     "Can you share the credentials for vcenter-01?"):
            self.assertTrue(v.asks_for_secret(q + text), text)
        for text in ("Did the password rotation in SDDC Manager succeed?",
                     "Was the transport zone deleted in the NSX UI?",
                     "Is there a change window for restarting vpxd?"):
            self.assertFalse(v.asks_for_secret(q + text), text)
        self.assertFalse(v.asks_for_secret("Please provide the password.\n```vcf-plan\n```"))

    def test_run_it_myself_then_paste_output(self):
        def answer(msgs):
            last = msgs[-1]["content"]
            if last.startswith("Output of the commands you asked for"):
                return PLAN_FIX
            if last.startswith("The administrator applied fix steps"):
                return "QUESTION FOR THE ADMINISTRATOR: did the node rejoin the cluster in the UI?"
            return PLAN_COLLECT
        srv, base, seen = scripted_ai(answer)
        try:
            ran = []
            inv, events = self.investigation(base, lambda p: "manual")
            inv.collect = lambda *a, **k: ran.append(1)
            res = inv.run()
            self.assertEqual(res["how"], "manual")
            self.assertEqual(ran, [])                         # nothing was run by the tool
            self.assertEqual([e["command"] for e in res["collect"]], ["journalctl -u kubelet -n 20"])
            self.assertIn("journalctl -u kubelet -n 20", v.plan_as_script(res["collect"]))
            res = inv.continue_with("Nov 17 kubelet: x509: certificate has expired on 10.9.0.11", "output")
            self.assertEqual(res["how"], "concluded")
            self.assertIn("x509: certificate has expired", seen[-1][-1]["content"])
            self.assertIn(("you", "Nov 17 kubelet: x509: certificate has expired on 10.9.0.11"), events)
            res = inv.continue_with("Renewed, kubelet active", "fix-output")
            self.assertEqual(res["how"], "question")
            self.assertEqual(res["question"], "did the node rejoin the cluster in the UI?")
            self.assertEqual(res["path"], inv.path)            # one transcript for the whole conversation
            with open(res["path"]) as fh:
                self.assertIn("Renewed, kubelet active", fh.read())
        finally:
            srv.shutdown()
            srv.server_close()

    def test_pasted_output_follows_the_anonymize_setting(self):
        with open(self.inv, "w") as fh:
            fh.write("[settings]\nanonymize = yes\n[vcfmgmt:mgmt]\ncontrol_planes = 10.9.0.11\n[ai]\nbase_url = x\nmodel = m\n")
        srv, base, seen = scripted_ai(lambda msgs: "QUESTION FOR THE ADMINISTRATOR: anything else?")
        try:
            inv, _ = self.investigation(base, lambda p: "run")
            inv.run()
            inv.continue_with("error on 10.9.0.11 password=hunter2", "output")
            sent = seen[-1][-1]["content"]
            self.assertNotIn("10.9.0.11", sent)
            self.assertNotIn("hunter2", sent)
        finally:
            srv.shutdown()
            srv.server_close()


class KeyHeaders(unittest.TestCase):
    def test_header_styles(self):
        for style, header, value in (("bearer", "Authorization", "Bearer k1"), ("api-key", "api-key", "k1"),
                                     ("x-api-key", "x-api-key", "k1"), ("token", "Authorization", "Token k1")):
            h = v.AiClient("https://api.example.mil/v1", "m", "k1", auth_header=style)._headers()
            self.assertEqual(h.get(header), value, style)
        self.assertEqual(v.AiClient("https://api.example.mil/v1/chat/completions", "m", "k").url,
                         "https://api.example.mil/v1/chat/completions")

    def test_client_certificate_demand_is_recognised(self):
        self.assertTrue(v.client_cert_required(ssl_error("[SSL: TLSV13_ALERT_CERTIFICATE_REQUIRED] tlsv13 alert certificate required")))
        self.assertTrue(v.client_cert_required(ssl_error("[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure")))
        self.assertFalse(v.client_cert_required(ssl_error("[SSL: CERTIFICATE_VERIFY_FAILED] self signed certificate")))
        self.assertIn("client certificate", v.CLIENT_CERT_MSG % "https://api.example.mil")


def ssl_error(text):
    import ssl
    return ssl.SSLError(text)


class ServerNameOnly(unittest.TestCase):
    def test_v1_is_tried_when_only_a_server_name_is_given(self):
        c = v.AiClient("api.genai.example.mil", "m", "k")
        self.assertEqual([r[0] for r in c.roots], ["https://api.genai.example.mil/v1", "https://api.genai.example.mil"])
        self.assertEqual(c.url, "https://api.genai.example.mil/v1/chat/completions")
        self.assertEqual(len(v.AiClient("https://api.genai.example.mil/v1/chat/completions", "m", "k").roots), 1)

    def test_falls_back_and_explains(self):
        srv, base, seen = fake_ai("x")            # serves POST on any path, so /v1 answers first
        try:
            c = v.AiClient(base.rsplit("/v1", 1)[0], "m", "")
            c.chat([{"role": "user", "content": "hello"}], retries=0)
            self.assertTrue(seen[-1]["path"].endswith("/v1/chat/completions"))
        finally:
            srv.shutdown()
            srv.server_close()
        import http.server
        import threading

        class Nothing(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def nope(self):
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = do_POST = nope

        nothing = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Nothing)
        threading.Thread(target=nothing.serve_forever, daemon=True).start()
        try:
            c = v.AiClient("http://127.0.0.1:%d" % nothing.server_address[1], "m", "")
            with self.assertRaises(v.AiError) as e:
                c.chat([{"role": "user", "content": "x"}], retries=0)
            self.assertIn("/v1/chat/completions (HTTP 404) or", str(e.exception))
            self.assertIn("usually ends in /v1", str(e.exception))
            with self.assertRaises(v.AiError):
                c.list_models()
        finally:
            nothing.shutdown()
            nothing.server_close()


class KeyHeaderDiscovery(unittest.TestCase):
    def serve(self, wants, refusal="Invalid API key: key expired on 2026-10-01"):
        import http.server
        import json as _json
        import threading
        seen = []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                seen.append(dict(self.headers))
                ok = self.headers.get(wants[0]) == wants[1]
                data = _json.dumps({"choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}]} if ok
                                   else {"error": {"message": refusal}}).encode()
                self.send_response(200 if ok else 401)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, "http://127.0.0.1:%d/v1" % srv.server_address[1], seen

    def test_other_header_is_found_and_reported(self):
        srv, base, seen = self.serve(("api-key", "k1"), refusal="Missing API key header")
        try:
            c = v.AiClient(base, "m", "k1")
            self.assertEqual(c.chat([{"role": "user", "content": "x"}], retries=0), "OK")
            self.assertEqual(c.auth, "api-key")
            self.assertEqual(c.note, "the key was accepted in the api-key header")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_refusal_shows_what_the_server_said(self):
        srv, base, seen = self.serve(("x-api-key", "something-else"))
        try:
            with self.assertRaises(v.AiError) as e:
                v.AiClient(base, "m", "k1").chat([{"role": "user", "content": "x"}], retries=0)
            msg = str(e.exception)
            self.assertNotIn("Tried the key as", msg)          # no guessing after "invalid / expired"
            self.assertIn("key expired on 2026-10-01", msg)
            self.assertEqual(len(seen), 1)                     # one failed attempt only
            with self.assertRaises(v.AiError):     # an explicitly chosen header is not changed
                v.AiClient(base, "m", "k1", auth_header="api-key").chat([{"role": "user", "content": "x"}], retries=0)
            self.assertEqual(len(seen), 2)
        finally:
            srv.shutdown()
            srv.server_close()


def genai_like():
    """Answers like GenAI.mil: only 'Authorization: Bearer STARK_...' is accepted."""
    import http.server
    import json as _json
    import threading
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            auth = self.headers.get("Authorization") or ""
            seen.append(auth)
            if auth == "Bearer STARK_good123":
                code, body = 200, {"choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}]}
            elif auth.startswith("Bearer "):
                code, body = 401, {"error": {"type": "unauthorized", "message": "Invalid API key."}}
            else:
                code, body = 401, {"error": {"type": "unauthorized", "message": "Missing authorization. Provide an API "
                                             "key via the Authorization header: 'Authorization: Bearer STARK_...'"}}
            data = _json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d/v1/chat/completions" % srv.server_address[1], seen


class GenAiLikeKeys(unittest.TestCase):
    def setUp(self):
        self.srv, self.url, self.seen = genai_like()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def chat(self, key):
        return v.AiClient(self.url, "m", key).chat([{"role": "user", "content": "x"}], retries=0)

    def test_client_name_is_not_python_urllib(self):
        self.assertEqual(v.AiClient(self.url, "m", "k")._headers()["User-Agent"], "vcf_diag/%s" % v.VERSION)

    def test_pasted_key_is_cleaned(self):
        self.assertEqual(self.chat("  Bearer STARK_good123\n"), "OK")
        self.assertEqual(self.chat('"STARK_good123"'), "OK")

    def test_wrong_key_reports_the_bearer_answer_and_the_prefix(self):
        with self.assertRaises(v.AiError) as e:
            self.chat("capra-key-0123456789")
        msg = str(e.exception)
        self.assertIn("Invalid API key", msg)                       # what the server said to Bearer
        self.assertEqual(self.seen, ["Bearer capra-key-0123456789"])   # one attempt, nothing else tried
        self.assertNotIn("capra-key-0123456789", msg)               # the key itself is never shown
        # when the refusal itself names the expected prefix, the message points it out
        del self.seen[:]
        with self.assertRaises(v.AiError) as e:
            self.chat("")
        c = v.AiClient(self.url, "m", "capra-key-0123456789")
        c.refusals.append("Provide 'Authorization: Bearer STARK_...'")
        with self.assertRaises(v.AiError) as e:
            c.chat([{"role": "user", "content": "x"}], retries=0)
        self.assertIn("expects keys that start with 'STARK_'", str(e.exception))
        self.assertIn("20 characters", str(e.exception))
        with self.assertRaises(v.AiError) as e:
            self.chat("STARK_expired999")
        self.assertNotIn("expects keys that start", str(e.exception))

    def test_key_shape_and_session_keys_per_endpoint(self):
        self.assertEqual(v.key_shape("STARK_abcdef"), "starts with 'STARK_', 12 characters")
        self.assertEqual(v.key_shape("abcdef"), "6 characters")
        capra = v.ai_settings({"_ai": {"provider": "asksage", "base_url": "chat.capra.example.mil"}})
        genai = v.ai_settings({"_ai": {"base_url": "https://api.genai.example.mil/v1/chat/completions"}})
        session = {v.endpoint_id(capra): "capra-key"}
        self.assertEqual(v.resolve_ai_key(capra, "", session), "capra-key")
        self.assertEqual(v.key_with_source(genai, "", session), ("", "none"))   # never another service's key
        text = v.ai_connection_check(dict(genai, base_url=self.url, use_proxy=False, model="m"), "STARK_good123",
                                     "typed in the key field")
        self.assertIn("[info] key: starts with 'STARK_', 13 characters, typed in the key field", text)
        self.assertNotIn("good123", text)


class LockedKey(unittest.TestCase):
    def test_locked_key_stops_everything(self):
        import http.server
        import json as _json
        import threading
        hits = []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def answer(self):
                n = int(self.headers.get("Content-Length") or 0)
                if n:
                    self.rfile.read(n)
                hits.append(self.path)
                data = _json.dumps({"error": {"type": "unauthorized", "message": "API key locked - visit the unlock URL "
                                              "to re-enable your key", "unlock_url": "https://genai.example.mil/unlock/abc"}}).encode()
                self.send_response(401)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = answer

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = "http://127.0.0.1:%d/v1" % srv.server_address[1]
        try:
            c = v.AiClient(base, "m", "STARK_x")
            with self.assertRaises(v.AiError) as e:
                c.chat([{"role": "user", "content": "x"}], retries=2)
            self.assertIn("LOCKED", str(e.exception))
            self.assertIn("https://genai.example.mil/unlock/abc", str(e.exception))
            self.assertEqual(len(hits), 1)                     # no retries, no other headers
            with self.assertRaises(v.AiError):
                c.chat([{"role": "user", "content": "x"}])
            self.assertEqual(len(hits), 1)                     # never sent again by this client
            cfg = v.ai_settings({"_ai": {"base_url": base, "model": "m", "use_proxy": "no"}})
            text = v.ai_connection_check(cfg, "STARK_x")
            self.assertIn("skipped: the key was refused", text)
            self.assertEqual(len(hits), 2)                     # the check made one attempt, not two
        finally:
            srv.shutdown()
            srv.server_close()


class AiPresets(unittest.TestCase):
    def test_presets_and_existing_settings(self):
        genai = v.ai_settings({})
        self.assertEqual((genai["profile"], genai["provider"], genai["base_url"], genai["model"]),
                         ("genai", "openai", "https://api.genai.mil/v1/chat/completions", "gemini-3.5-flash-lite-withtools"))
        capra = v.ai_settings({"_ai": {"profile": "capra", "capra_model": "gpt-4o-gov"}})
        self.assertEqual((capra["provider"], capra["base_url"], capra["model"]),
                         ("asksage", "chat.capra.flankspeed.us.navy.mil", "gpt-4o-gov"))
        # settings written before presets existed are recognised, and their model kept
        old = v.ai_settings({"_ai": {"base_url": "https://api.genai.mil/v1/chat/completions", "model": "gemini-x"}})
        self.assertEqual((old["profile"], old["model"]), ("genai", "gemini-x"))
        old = v.ai_settings({"_ai": {"provider": "asksage", "base_url": "https://chat.capra.flankspeed.us.navy.mil"}})
        self.assertEqual(old["profile"], "capra")
        custom = v.ai_settings({"_ai": {"base_url": "https://ai.example.internal/v1", "model": "m"}})
        self.assertEqual((custom["profile"], custom["base_url"]), ("custom", "https://ai.example.internal/v1"))
        # each preset keeps its own model; the custom one is untouched
        both = {"_ai": {"profile": "genai", "genai_model": "g", "capra_model": "c", "base_url": "https://x/v1", "model": "x"}}
        self.assertEqual(v.ai_settings(both)["model"], "g")
        both["_ai"]["profile"] = "capra"
        self.assertEqual(v.ai_settings(both)["model"], "c")
        both["_ai"]["profile"] = "custom"
        self.assertEqual((v.ai_settings(both)["model"], v.ai_settings(both)["base_url"]), ("x", "https://x/v1"))
        # keys are kept per service: a key for one is never used for the other
        session = {v.endpoint_id(v.ai_settings({"_ai": {"profile": "capra"}})): "capra-key"}
        self.assertEqual(v.resolve_ai_key(v.ai_settings({}), "", session), "")


STS_PEM = """-----BEGIN CERTIFICATE-----
MIIDETCCAfmgAwIBAgIUWoc5iTiKGCOQdkYQ1SLSQGuWGbYwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNc3Nvc2VydmVyU2lnbjAeFw0yNjExMTgxMzU5MzRaFw0y
NjExMjgxMzU5MzRaMBgxFjAUBgNVBAMMDXNzb3NlcnZlclNpZ24wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCgEN0eoT27yHILQksHZhSUXpA5eJGcgNbC
DJHJ7c4h0oSTffJ5OGUpAF9itWBuvWQoDat05YvWP+ZMPratuI/7wIhM/U1jCof8
3UhGMh8r7l0qgnU0kv84Upi68pdxPzMZL9DB01ZOeoFqUjskykG+BENqdgSzpIv4
YGml1gzEIGb3Fircro4h2gioiphJiV3oHan7srYmBzKcuEcz83ZJCHf9q03bae7G
2/VUWZ0ydfyA0w30+Iife1mhnjcDwAPknoUPusLYmUMV/lQooXya+HtHziPSjoRA
CTdOD319ibkzOdTLDs6a/b9bwuk52JahmY/VYfvKHFOW5XW9qSudAgMBAAGjUzBR
MB0GA1UdDgQWBBRNV/dWYUsAEO7zSQTV/cXyoU9KzTAfBgNVHSMEGDAWgBRNV/dW
YUsAEO7zSQTV/cXyoU9KzTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQA4EqIuh2jitwsGa6rQq/JtSOD7HcWGXMYggK5Ax6OSjYrlBsKcT+dq4S4R
v4mS2jP4jNO688xBwt1E+WoHaKWTwPVjalT67Fx9mBtgVQixjnp8Hrp3KvE1gYs9
2ch+eulRUT0qBwwr4xKoVancGCFWOynK9REXfzh74Qy76+o4peRhPRRTxZXDEZGW
FpC3VairIq83hQALYiH2WsvAI97oKl2TV3RFCB8mmjdYuUP3ZP/OdOprXOquhZQl
/Q+RsrnXhuDpcZcKZzksB+g/pYtOFkFqAAav9euIwZsTth25SvOUjwdfotPnYAyE
nkyoXBBsXffFtjo0rJQq7lcLs8mY
-----END CERTIFICATE-----"""


class SsoAndPasswords(unittest.TestCase):
    def test_vcenter_sso_checks(self):
        FAKE_VC["/api/vcenter/certificate-management/vcenter/signing-certificate"] = {
            "active_cert_chain": {"cert_chain": [STS_PEM]}, "signing_cert_chains": [{"cert_chain": [STS_PEM]}]}
        FAKE_VC["/api/vcenter/certificate-management/vcenter/tls"] = {
            "valid_to": "2020-01-01T00:00:00.000Z", "subject_dn": "CN=vc01", "issuer_dn": "CN=CA"}
        FAKE_VC["/api/appliance/local-accounts"] = ["root", "monitor"]
        FAKE_VC["/api/appliance/local-accounts/root"] = {"enabled": True, "last_password_change": "2026-01-01T00:00:00.000Z",
                                                         "password_expires_at": "2026-01-02T00:00:00.000Z"}
        FAKE_VC["/api/appliance/local-accounts/monitor"] = {"enabled": True}
        FAKE_VC["/api/vcenter/identity/providers"] = [{"name": "ADFS", "config_tag": "Oidc", "is_default": True,
                                                       "domain_names": ["corp.example"]}]
        srv, base, seen = fake_vcenter()
        try:
            api = v.VcApi("vc", "administrator@vsphere.local", "Secr3t!", base_url=base)
            api.login()
            sts, tls, idp, acc = v.vc_sts(api), v.vc_tls(api), v.vc_idp(api), v.vc_accounts(api)
            api.logout()
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertIn("active signing certificate (ssoserverSign): valid until", sts)
        self.assertTrue("EXPIRES SOON" in sts or "EXPIRED" in sts)
        self.assertNotIn("BEGIN CERTIFICATE", sts)
        self.assertIn("machine SSL certificate: valid until 2020-01-01", tls)
        self.assertIn("EXPIRED", tls)
        self.assertIn("provider: ADFS  type=Oidc  default=True", idp)
        self.assertRegex(acc, r"root\s+True\s+2026-01-01\s+2026-01-02T00:00:00\s+EXPIRED")
        self.assertRegex(acc, r"monitor .* never expires")
        self.assertTrue(all(m == "GET" for m, p in seen if p != "/api/session"))

    def test_nsx_users(self):
        FAKE_NSX["/api/v1/node/users"] = {"results": [
            {"username": "admin", "status": "ACTIVE", "password_change_frequency": 90, "last_password_change": 3},
            {"username": "audit", "status": "PASSWORD_EXPIRED", "password_change_frequency": 90, "last_password_change": 120}]}
        FAKE_NSX["/api/v1/node/aaa/auth-policy"] = {"api_failed_auth_lockout_period": 900, "_revision": 1}
        srv, base, seen = fake_nsx()
        try:
            api = v.NsxApi("nsx", "admin", "Nsx-Pass1!", base_url=base)
            api.login()
            out = v.nsx_users(api)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertRegex(out, r"audit\s+PASSWORD_EXPIRED\s+90\s+120")
        self.assertIn('"api_failed_auth_lockout_period": 900', out)
        self.assertNotIn("_revision", out)

    def test_sddc_stored_credentials(self):
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
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                body = _json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen.append(("POST", self.path))
                ok = body == {"username": "administrator@vsphere.local", "password": "Pw1!"}
                self.send(200 if ok else 401, {"accessToken": "tok"} if ok else {})

            def do_GET(self):
                seen.append(("GET", self.path))
                if self.headers.get("Authorization") != "Bearer tok":
                    return self.send(401, {})
                if self.path.startswith("/v1/credentials/tasks"):
                    return self.send(200, {"elements": [{"creationTimestamp": "2026-11-17T10:00:00Z", "status": "FAILED",
                                                         "name": "Rotate passwords",
                                                         "errors": [{"message": "Password for esx02 root is out of sync"}]}]})
                if self.path.startswith("/v1/credentials"):
                    return self.send(200, {"elements": [
                        {"username": "root", "credentialType": "SSH", "accountType": "USER",
                         "resource": {"resourceType": "ESXI", "resourceName": "esx02.corp.example"},
                         "expiry": {"expiryDate": "2026-11-20", "status": "EXPIRING"}}], "pageMetadata": {"totalPages": 1}})
                self.send(404, {})

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        try:
            api = v.SddcApi("sddc", "administrator@vsphere.local", "Pw1!", base_url=base)
            api.login()
            self.assertIsNone(api.password)
            creds, tasks = v.sddc_credentials(api), v.sddc_credential_tasks(api)
            with self.assertRaises(v.VcApiError):
                v.SddcApi("sddc", "administrator@vsphere.local", "bad", base_url=base).login()
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertIn("- ESXI esx02.corp.example  user=root  type=SSH/USER", creds)
        self.assertIn("expiry.status=EXPIRING", creds)
        self.assertIn("FAILED  Rotate passwords  Password for esx02 root is out of sync", tasks)

    def test_esxi_password_age_never_prints_hashes(self):
        import subprocess
        import time
        c = [c for g in v.COMPONENTS["esxi"]["groups"] if g[0] == "passwords" for c in g[2]
             if c["label"] == "Password age (days)"][0]
        with tempfile.TemporaryDirectory() as d:
            shadow = os.path.join(d, "shadow")
            today = int(time.time() // 86400)
            with open(shadow, "w") as fh:
                fh.write("root:$6$salt$HASHVALUE:%d:0:90:7:::\ndcui:*:%d:0:99999:7:::\nvpxuser:$6$x$OTHERHASH:%d::::::\n"
                         % (today - 100, today, today - 5))
            out = subprocess.run(["sh", "-c", c["cmd"].replace("/etc/shadow", shadow)], stdout=subprocess.PIPE).stdout.decode()
        self.assertIn("root                 changed 100 days ago, max age 90 days", out)
        self.assertIn("vpxuser              changed 5 days ago, max age none days", out)
        self.assertNotIn("HASH", out)
        self.assertNotIn("dcui", out)                        # locked accounts are skipped

    def test_new_shell_checks_parse(self):
        import subprocess
        for typ in ("vcenter", "esxi"):
            for key, title, cmds in v.COMPONENTS[typ]["groups"]:
                for c in cmds:
                    if c["mode"] == "sh" and key in ("vc-sso", "passwords"):
                        r = subprocess.run(["bash", "-n", "-c", c["cmd"]], stderr=subprocess.PIPE)
                        self.assertEqual(r.returncode, 0, (c["label"], r.stderr))
        self.assertTrue(v.is_api_group("sddc-api-credentials"))


class NodeAndPodHealth(unittest.TestCase):
    def health(self, label):
        return [c for g in v.K8S_GROUPS if g[0] == "k8s-health" for c in g[2] if c["label"].startswith(label)][0]

    def test_problem_container_filter(self):
        import stat
        import subprocess
        lines = [
            "prelude/provisioning-app-5d9c-x2x9z  node=wkr-1  phase=Running  reason=  [app ready=false restarts=37 waiting=CrashLoopBackOff last=Error:1@2026-11-18T09:00:00Z]",
            "prelude/identity-app-0  node=wkr-1  phase=Running  reason=  [app ready=true restarts=0 waiting= last=:@]",
            "widgets-fin/ledger-7f6d-abcde  node=wkr-2  phase=Running  reason=  [api ready=true restarts=3 waiting= last=OOMKilled:137@2026-11-18T08:00:00Z]",
            "kube-system/etcd-cp-1  node=cp-1  phase=Running  reason=  [etcd ready=true restarts=0 waiting= last=:@]",
            "widgets-fin/batch-9  node=  phase=Pending  reason=  ",
            "prelude/old-job-1  node=wkr-2  phase=Failed  reason=Evicted  [job ready=false restarts=0 waiting= last=:@]",
        ]
        with tempfile.TemporaryDirectory() as d:
            fake = os.path.join(d, "kubectl")
            with open(fake, "w") as fh:
                fh.write("#!/bin/sh\ncat <<'EOF'\n%s\nEOF\n" % "\n".join(lines))
            os.chmod(fake, stat.S_IRWXU)
            out = subprocess.run(["bash", "-c", self.health("Problem containers")["cmd"].replace("{K}", fake)],
                                 stdout=subprocess.PIPE).stdout.decode()
            oom = subprocess.run(["bash", "-c", self.health("Containers killed")["cmd"].replace("{K}", fake)],
                                 stdout=subprocess.PIPE).stdout.decode()
        picked = [ln.split()[0] for ln in out.splitlines()]
        self.assertEqual(picked, ["prelude/provisioning-app-5d9c-x2x9z", "widgets-fin/ledger-7f6d-abcde",
                                  "widgets-fin/batch-9", "prelude/old-job-1"])
        self.assertEqual([ln.split()[0] for ln in oom.splitlines()], ["widgets-fin/ledger-7f6d-abcde"])

    def test_names_in_new_outputs_are_anonymized(self):
        sc = make()
        text = ("widgets-fin/ledger-7f6d-abcde  node=wkr-xk2p  phase=Running  [api ready=true restarts=3 waiting= "
                "last=OOMKilled:137@2026-11-18T08:00:00Z]\n== widgets-fin/ledger-7f6d-abcde\nNAME UNSCHEDULABLE TAINTS\n"
                "wkr-xk2p true node.kubernetes.io/unschedulable\nprelude/provisioning-app-1 node=wkr-xk2p phase=Running\n")
        sc.learn_k8s("nsslash", text, prefix="vcfmgmt-mgmt")
        sc.learn_k8s("firstnode", text, prefix="vcfmgmt-mgmt")
        out = run(sc, text)
        for gone in ("widgets", "ledger", "wkr-xk2p"):
            self.assertNotIn(gone, out)
        self.assertIn("prelude/provisioning-app-1", out)      # product namespaces stay readable
        self.assertIn("vcfmgmt-mgmt-worker-01", out)
        self.assertIn("OOMKilled:137", out)

    def test_commands_parse_and_groups_are_wired(self):
        import subprocess
        groups = [g for g in v.K8S_GROUPS if g[0] == "k8s-health"] + v.NODE_K8S_GROUPS
        for key, title, cmds in groups:
            for c in cmds:
                r = subprocess.run(["bash", "-n", "-c", c["cmd"].replace("{K}", "kubectl")], stderr=subprocess.PIPE)
                self.assertEqual(r.returncode, 0, (c["label"], r.stderr))
        for typ in ("k8s", "vcfmgmt", "supervisor"):
            keys = [g[0] for g in v.COMPONENTS[typ]["groups"]]
            self.assertIn("k8s-health", keys)
            self.assertIn("node-certs", keys)
            self.assertIn("node-runtime", keys)
        self.assertFalse(v.is_cluster_group("node-certs"))       # runs on every node
        self.assertTrue(v.is_cluster_group("k8s-health"))        # runs once per cluster


class NsxLogicalPorts(unittest.TestCase):
    def test_ports_are_explained_by_what_is_behind_them(self):
        FAKE_NSX.update({
            "/api/v1/logical-ports?attachment_type=VIF&page_size=1000": {"results": [
                {"id": "p1", "display_name": "widgets-auto01.vmx@552418466", "logical_switch_id": "ls1",
                 "attachment": {"attachment_type": "VIF", "id": "att-gone"}, "_create_time": 1759000000000},
                {"id": "p2", "display_name": "widgets-db02.vmx@1", "logical_switch_id": "ls1",
                 "attachment": {"attachment_type": "VIF", "id": "att-off"}},
                {"id": "p3", "display_name": "widgets-web03.vmx@2", "logical_switch_id": "ls1",
                 "attachment": {"attachment_type": "VIF", "id": "att-down"}},
                {"id": "p4", "display_name": "widgets-app04.vmx@3", "logical_switch_id": "ls1",
                 "attachment": {"attachment_type": "VIF", "id": "att-up"}}]},
            "/api/v1/fabric/vifs?page_size=1000": {"results": [
                {"lport_attachment_id": "att-off", "owner_vm_id": "vm-off", "host_id": "h1"},
                {"lport_attachment_id": "att-down", "owner_vm_id": "vm-down", "host_id": "h2"},
                {"lport_attachment_id": "att-up", "owner_vm_id": "vm-up", "host_id": "h2"}]},
            "/api/v1/fabric/virtual-machines?page_size=1000": {"results": [
                {"external_id": "vm-off", "display_name": "widgets-db02", "power_state": "VM_STOPPED"},
                {"external_id": "vm-down", "display_name": "widgets-web03", "power_state": "VM_RUNNING"},
                {"external_id": "vm-up", "display_name": "widgets-app04", "power_state": "VM_RUNNING"}]},
            "/api/v1/logical-switches?page_size=1000": {"results": [{"id": "ls1", "display_name": "WIDGETS-SEG-APP"}]},
            "/api/v1/logical-ports/p3/status": {"status": "DOWN"},
            "/api/v1/logical-ports/p4/status": {"status": "UP"},
        })
        srv, base, seen = fake_nsx()
        try:
            api = v.NsxApi("nsx", "admin", "Nsx-Pass1!", base_url=base)
            api.login()
            out = v.nsx_logical_ports(api)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertTrue(out.startswith("4 VM logical port(s): 1 orphaned, 1 on powered-off VMs, 2 on running VMs "
                                       "(2 of those checked, 1 down)."))
        down = out.split("Down while the VM is running")[1].split("Orphaned:")[0]
        self.assertIn("port widgets-web03.vmx@2  vm=widgets-web03  segment=WIDGETS-SEG-APP  status=DOWN", down)
        self.assertNotIn("widgets-app04", down)
        orphaned = out.split("Orphaned:")[1].split("On powered-off VMs")[0]
        self.assertIn("port widgets-auto01.vmx@552418466  segment=WIDGETS-SEG-APP  created 2025-", orphaned)
        self.assertIn("vm=widgets-db02  power=VM_STOPPED", out.split("On powered-off VMs")[1])
        self.assertTrue(all(m == "GET" for m, _ in seen))
        # VM names in port names are anonymized
        sc = make(terms=[])
        group = [g for g in v.COMPONENTS["nsx"]["groups"] if g[0] == "nsx-api-health"][0]
        harvest(sc, [c for c in group[2] if c["api"] == "nsx_logical_ports"][0], out)
        scrubbed = run(sc, out)
        for gone in ("widgets-auto01", "widgets-web03", "widgets-db02"):
            self.assertNotIn(gone, scrubbed)
        self.assertIn(".vmx@552418466", scrubbed)


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
        self.assertTrue(st["ai"]["configured"])                # a fresh installation starts with GenAI.mil
        self.assertEqual(st["ai"]["profile"], "genai")
        self.call("api/inventory", {"text": "[esxi]\nhosts = esx01.corp.example-widgets.com\n[ai]\nprofile = custom\n"})
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

    def test_switching_the_ai_service(self):
        self.call("api/inventory", {"text": "[esxi]\nhosts = esx01.corp.example-widgets.com\n"})
        code, out = self.call("api/ai_profile", {"profile": "capra"})
        self.assertEqual(code, 200)
        code, st = self.call("api/state")
        self.assertEqual(st["ai"]["profile"], "capra")
        self.assertIn("chat.capra", st["ai"]["base_url"])
        self.assertEqual([p["id"] for p in st["ai"]["presets"]], ["genai", "capra"])
        code, r = self.call("api/settings")
        self.assertEqual((r["meta"]["profile"], r["model"]["ai"]["profile"]), ("capra", "capra"))
        self.assertEqual([g["type"] for g in r["model"]["groups"]], ["esxi"])     # nothing else changed
        code, out = self.call("api/ai_profile", {"profile": "custom"})
        self.assertEqual(code, 400)
        self.assertIn("set up the other AI service", out["error"])
        self.assertEqual(self.call("api/ai_profile", {"profile": "nope"})[0], 400)

    def test_anonymize_and_translate_back(self):
        self.call("api/inventory", {"text": "[esxi]\nhosts = esx01.corp.example-widgets.com\n"})
        code, out = self.call("api/scrub", {"text": "esx01.corp.example-widgets.com at 10.4.4.4 password=hunter2"})
        self.assertEqual(code, 200)
        self.assertEqual(out["text"], "esxi-01.domain-01 at ip-n1-h1 password=[REDACTED]")
        self.assertEqual(out["review"]["hits"], [])
        code, back = self.call("api/decode", {"text": "check esxi-01.domain-01 and ip-n1-h1"})
        self.assertEqual(back["text"], "check esx01.corp.example-widgets.com and 10.4.4.4")


class ReportReadability(unittest.TestCase):
    """Summarizers and redaction fixes that keep reports short and correct for an analyst."""

    HDR = "    UUID                                       IPV4             IPV6          STATUS    FQDN   "

    @staticmethod
    def row(uuid, ip, fqdn, status="UP"):
        return "    %s   %s   not configured   %s   %s      " % (uuid, ip, status, fqdn)

    def cluster_status(self, down=None):
        u = "aaaaaaaa-1111-2222-3333-%012d"
        nodes = [("10.20.30.11", "nsx01.corp.example-widgets.com"), ("10.20.30.12", "nsx02.corp.example-widgets.com")]
        out = ["Wed Nov 18 2026 UTC 14:17:30.899", "Cluster Id: " + u % 0, "Overall Status: STABLE", ""]
        for g in ("DATASTORE", "CONTROLLER", "MANAGER"):
            bad = g == down
            out += ["Group Type: " + g, "Group Status: " + ("DEGRADED" if bad else "STABLE"), "", "Members:", self.HDR]
            out += [self.row(u % (i + 1), ip, f, "DOWN" if bad and i else "UP") for i, (ip, f) in enumerate(nodes)]
            out.append("")
        out += ["Wed Nov 18 2026 UTC 14:17:32.743", "Node Services:", "", "Service Name: SEARCH", "", "Nodes:",
                self.HDR, self.row(u % 1, *nodes[0]), "", self.row(u % 2, *nodes[1])]
        return "\n".join(out)

    def test_nsxcli_time_stamp_is_removed_and_parsed(self):
        ts, out = v.nsxcli_stamp(self.cluster_status())
        self.assertAlmostEqual(ts, 1795011450.899, places=2)
        self.assertNotIn("UTC 14:17", out)
        self.assertEqual(v.nsxcli_stamp("no stamp"), (None, "no stamp"))

    def test_cluster_status_is_folded(self):
        out = v.post_nsx_cluster_status(v.nsxcli_stamp(self.cluster_status())[1])
        self.assertIn("Overall Status: STABLE", out)
        self.assertIn("3 of 3 groups STABLE with every member UP: DATASTORE, CONTROLLER, MANAGER", out)
        self.assertEqual(out.count("nsx01.corp.example-widgets.com"), 1)
        self.assertIn("node services with every node UP: SEARCH (2)", out)
        self.assertNotIn("aaaaaaaa-1111-2222-3333-000000000001", out)     # per-group member UUIDs dropped

    def test_cluster_status_shows_unhealthy_groups(self):
        out = v.post_nsx_cluster_status(self.cluster_status(down="CONTROLLER"))
        self.assertIn("2 of 3 groups STABLE", out)
        self.assertIn("group CONTROLLER: DEGRADED", out)
        self.assertIn("nsx02.corp.example-widgets.com  10.20.30.12  DOWN", out)

    def test_cluster_config_is_folded(self):
        hdr = "    ENTITY      UUID       IPV4 ADDRESS      IPV6 ADDRESS      PORT     FQDN"
        out = ["Cluster Id: c1", "Cluster Configuration Version: 3", "Number of nodes in the cluster: 2"]
        for n, ip, f in (("1", "10.20.30.11", "nsx01.corp.example-widgets.com"),
                         ("2", "10.20.30.12", "nsx02.corp.example-widgets.com")):
            out += ["", "Node UUID: node-uuid-%s" % n, "Node Status: JOINED", hdr]
            for i, (ent, port) in enumerate((("CONTROLLER", "-"), ("DATASTORE", "9000"), ("HTTPS", "443"))):
                out.append("    %-12s ent-uuid-%s%d   %s   not configured   %s   %s   " % (ent, n, i, ip, port, f))
        res = v.post_nsx_cluster_config("\n".join(out))
        self.assertIn("node-uuid-1  JOINED  10.20.30.11  nsx01.corp.example-widgets.com  3 entities", res)
        self.assertIn("entities on every node: CONTROLLER, DATASTORE, HTTPS", res)
        self.assertIn("entity ports: DATASTORE 9000, HTTPS 443", res)
        self.assertNotIn("ent-uuid", res)

    def test_cpu_and_memory_summaries(self):
        cpu = "\n\n".join("processor\t: %d\nmodel name\t: Example CPU 9000\ncpu MHz\t\t: 2499.999\n"
                          "cache size\t: 61440 KB\nphysical id\t: %d\nmicrocode\t: 0x1\n"
                          "flags\t\t: fpu aes avx2 hypervisor\nbugs\t\t: spectre_v1" % (i, i) for i in range(4))
        out = v.post_cpuinfo(cpu)
        self.assertIn("4 logical CPU(s) in 4 socket(s)", out)
        self.assertIn("4 x Example CPU 9000, 2500 MHz", out)
        self.assertIn("virtual machine: yes", out)
        self.assertEqual(out.count("Example CPU"), 1)
        mem = v.post_meminfo("MemTotal: 24599336 kB\nMemFree: 806016 kB\nMemAvailable: 1181560 kB\n"
                             "SwapTotal: 0 kB\nAnonPages: 20528248 kB\nCommitLimit: 12299668 kB\n"
                             "Committed_AS: 28908164 kB\nHugePages_Total: 0\n")
        self.assertIn("total 23.5 GiB, available 1.1 GiB (5%)", mem)
        self.assertIn("swap: none configured", mem)
        self.assertIn("committed 27.6 GiB against commit limit 11.7 GiB", mem)
        self.assertIn("NOTE: less than 10% of memory is available", mem)
        for f in (v.post_cpuinfo, v.post_meminfo, v.post_nsx_cluster_status, v.post_nsx_cluster_config):
            self.assertEqual(f("something unexpected"), "something unexpected")

    def test_version_banner_dropped(self):
        out = v.post_nsx_version("VMware NSX Software, Version 9.1.1.0.1\nProduct Version 9.1.1.0.2\n"
                                 "Technical Support: https://support.example.com/\n\nCopyright (c) 2026 Example.\n")
        self.assertEqual(out, "VMware NSX Software, Version 9.1.1.0.1\nProduct Version 9.1.1.0.2")

    def test_truncated_ntp_peer_names_do_not_leak(self):
        raw = ("     remote           refid      st t when poll reach   delay   offset  jitter\n"
               "==============================================================================\n"
               "*timesrv1.widge .GPS.            1 u  299 1024  377    0.396   -1.069   0.140\n"
               "+timesrv2.wid   .GPS.            1 u  535 1024  377    0.489   -0.967   0.162\n"
               "-10.1.2.3       timesrv1.wid     2 u  535 1024  377    0.489   -0.967   0.162\n")
        out = v.post_ntpq_peers(raw)
        self.assertNotIn("timesrv", out)
        self.assertNotIn("wid", out)
        self.assertIn("*peer-1         .GPS.            1 u  299", out)
        self.assertIn("-10.1.2.3       peer-3-ref       2 u", out)

    def test_password_policy_values_are_not_redacted(self):
        text = ('policy: {"invalid_password_chars": ["\\u0000", ":"], "minimum_password_length": 12, '
                '"password_remembrance": 5, "password": "Sup3r", "password_change": "S3cret", "api_token": 42}')
        out = run(make(), text)
        self.assertIn('"invalid_password_chars": ["\\u0000", ":"]', out)
        self.assertIn('"minimum_password_length": 12', out)
        self.assertIn('"password_remembrance": 5', out)
        for gone in ("Sup3r", "S3cret", ": 42"):
            self.assertNotIn(gone, out)

    def test_run_catalog_strips_stamp_sets_clock_and_summarizes(self):
        t = v.Target.__new__(v.Target)
        t.mode, t.sec, t.clock_offset = "nsxcli", {"type": "nsx"}, None
        reply = {}
        t.exec = lambda command, timeout: (reply["rc"], reply["out"], False)

        def boom(_):
            raise RuntimeError("parser bug")
        stamp = v.time.strftime("%a %b %d %Y UTC %H:%M:%S.000", v.time.gmtime())
        reply.update(rc=0, out=stamp + "\nVMware NSX Software, Version 9.1\nCopyright (c) 2026 Example.\n")
        res = t.run_catalog(("g", "G"), v.ncli("Version", "get version", post=v.post_nsx_version))
        self.assertEqual(res["out"], "VMware NSX Software, Version 9.1")
        self.assertLess(abs(t.clock_offset), 3)
        reply.update(rc=0, out="raw text\n")
        self.assertEqual(t.run_catalog(("g", "G"), v.ncli("X", "get x", post=boom))["out"], "raw text\n")
        reply.update(rc=1, out="% Command not found\n")
        res = t.run_catalog(("g", "G"), v.ncli("X", "get x", post=lambda o: "summary"))
        self.assertEqual((res["status"], res["out"]), ("fail", "% Command not found\n"))


class ReportDigest(unittest.TestCase):
    """Services summary, redundant CLI checks left out, and the Key facts block."""

    SERVICES = ("Service name:      http\nService state:     running\nLogging level:     info\n"
                "Session timeout:   1800\n\nService name:      snmp\nService state:     stopped\n"
                "Start on boot:     False\n\nService name:      manager\nService state:     stopped\n\n"
                "Service name:      ssh\nService state:     running\nRoot login:        enabled\n\n"
                "Service name:      controller\nService state:     running\nListen address:\n")

    def test_services_summary(self):
        out = v.post_nsx_services(self.SERVICES)
        self.assertIn("5 services: 3 running, 2 stopped", out)
        self.assertIn("usually stopped unless the feature is used: snmp", out)
        self.assertIn("NOT RUNNING (unexpected): manager (stopped)", out)
        self.assertIn("  http: session timeout 1800", out)
        self.assertNotIn("logging level", out)
        self.assertNotIn("controller", out)                       # empty attribute dropped
        self.assertEqual(v.post_nsx_services("nothing"), "nothing")

    def test_ntp_note_has_no_blank_line_before_it(self):
        out = v.post_ntpq_peers("     remote   refid  st t when poll reach delay offset jitter\n=====\n"
                                "*timesrv1.wid .GPS.  1 u  1 64 377 0.4 -0.8 0.2\n\n")
        self.assertIn("0.2\n(peer names", out)

    @staticmethod
    def res(label, out, status="ok", **spec):
        return {"group": ("nsx-x", "X"), "label": label, "cmd": "c", "rc": 0 if status == "ok" else 1,
                "out": out, "dur": 0.1, "status": status, "note": "", "spec": dict({"max_lines": None}, **spec)}

    def target(self):
        t = types.SimpleNamespace(ph="nsxmgr-01", mode="nsxcli", errkind=None, errmsg="", identity=[],
                                  user="admin", notes=[], clock_offset=0.4)
        users = ("user   status   change every (days) last change (days ago)\n"
                 "root   ACTIVE   90   2\nadmin   ACTIVE   90   10\nguest   NOT_ACTIVATED   90   300\n")
        t.results = [
            self.res("Services", v.post_nsx_services(self.SERVICES)),
            self.res("Memory", "total 23.5 GiB, available 3.0 GiB (13%), free 0.7 GiB\nswap: none configured"),
            self.res("Core dumps", "No core dumps generated in system"),
            self.res("Password expiry: admin", "Password expires 90 days after last change", covered_by="nsx_users"),
            self.res("Transport nodes", "HTTP 500 for /x", status="fail"),
            self.res("Local users and password expiry", users, api="nsx_users"),
        ]
        return t

    def test_covered_cli_checks_are_left_out_with_a_note(self):
        t = self.target()
        v.drop_covered_results(t)
        self.assertNotIn("Password expiry: admin", [r["label"] for r in t.results])
        self.assertIn("Local users and password expiry", t.notes[0])
        self.assertIn("Password expiry: admin", t.notes[0])
        t = self.target()
        t.results[-1]["status"] = "fail"                         # API failed: keep the CLI check
        v.drop_covered_results(t)
        self.assertIn("Password expiry: admin", [r["label"] for r in t.results])

    def test_key_facts(self):
        facts = dict(v.key_facts(self.target()))
        self.assertEqual(facts["clock_offset_s"], 0)
        self.assertEqual(facts["mem_available_pct"], 13)
        self.assertEqual(facts["services_down_unexpected"], "manager (stopped)")
        self.assertEqual(facts["ssh_root_login"], "enabled")
        self.assertEqual(facts["core_dumps"], 0)
        self.assertEqual(facts["account_expiry_soonest"], "admin in 80 days")
        self.assertNotIn("checks_failed", facts)            # listed once, under failed checks
        self.assertEqual(v.KEY_FACTS["Core dumps"]("total 0"), [("core_dumps", 0)])     # vCenter ls output
        self.assertEqual(v.KEY_FACTS["DNS servers"]("   DNSServers: 10.1.1.1, 10.1.1.2"), [("dns_servers", 2)])

    def test_report_has_anonymized_key_facts_block(self):
        t = self.target()
        v.drop_covered_results(t)
        ctx = types.SimpleNamespace(ssh_banner="OpenSSH_test")
        item = {"sec": {"name": "nsx", "type": "nsx"}}
        rep = v.build_report(ctx, [(item, [t])], make(), v.datetime.datetime(2026, 11, 18), 400)
        block = rep.split("### Key facts", 1)[1].split("```yaml\n", 1)[1].split("\n```", 1)[0]
        self.assertTrue(block.startswith("nsxmgr-01:\n  clock_offset_s: 0\n"))
        self.assertIn('  account_expiry_soonest: "admin in 80 days"', block)   # not redacted
        self.assertNotIn("checks_failed", block)
        failed = rep.split("### Collection problems and failed checks", 1)[1].split("###", 1)[0]
        self.assertIn("- environment (look at these):\n  - nsxmgr-01: Transport nodes (HTTP 500 for /x)", failed)
        self.assertIn("**Services** (ok)\n", rep)                 # no duration for quick checks
        self.assertIn("Note: left out because the API check", rep)
        self.assertNotIn("**Password expiry: admin**", rep)


FAKE_KUBECTL = r"""#!/bin/sh
a="$*"
case "$a" in
  "get ns --no-headers -o custom-columns=:metadata.name") printf 'default\nkube-system\nprelude\nvmsp-platform\nwidgets-team\n';;
  "get pods -A --no-headers"|"get pods -A -o wide --no-headers") printf '%s\n' \
    'kube-system coredns-1 1/1 Running 0 5d 10.0.0.1 node1' \
    'prelude provisioning-service-app-7f 1/1 Running 3 5d 10.0.0.2 node1' \
    'prelude ebs-app-5c 0/1 CrashLoopBackOff 42 5d 10.0.0.3 node2' \
    'prelude postgres-0 1/1 Running 0 5d 10.0.0.4 node2' \
    'widgets-team web-1 0/1 Pending 0 1d 10.0.0.6 node1';;
  "get deploy,sts -A --no-headers") printf 'prelude deployment.apps/ebs-app 0/1 1 0 5d\nkube-system deployment.apps/coredns 1/2 2 1 5d\n';;
  "get pvc -A --no-headers") printf 'prelude data-postgres-0 Bound pvc-1 20Gi RWO sc 5d\n';;
  get\ events*) printf 'prelude 2m Warning BackOff pod/ebs-app-5c Back-off\n';;
  get\ pods\ -n\ *jsonpath*) printf 'registry.example/vmware/ebs:9.0.1.0-123\n';;
  get\ pods\ -n\ prelude\ --field-selector*) printf 'pod/ebs-app-5c\npod/provisioning-service-app-7f\n';;
  get\ pods\ -n\ *) ;;
  logs\ -n\ prelude\ pod/ebs-app-5c*) printf 'INFO ok\nERROR db connection refused\njava.lang.IllegalStateException: x\n';;
  logs*) printf 'INFO fine\nterror-free line\n';;
  get\ ingress*) ;;
  *) echo "unhandled: $a" >&2; exit 1;;
esac
"""


class Automation(unittest.TestCase):
    """VCF Automation component: wiring, namespace option and the shell checks themselves."""

    def test_pasted_inventory_lines_and_skipped_groups_are_reported(self):
        text = ("[supervisor]\nhosts = 10.1.1.70\n```\n[vcfa]\n```\n`hosts = 10.1.1.30`\n"
                "[esxi]\nhosts =\n[k8s:automation]\nhost = 10.1.1.31\n")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "inventory.ini")
            with open(path, "w") as fh:
                fh.write(text)
            settings, sections, _ = v.load_inventory(path)
        self.assertEqual([(x["name"], x["hosts"]) for x in sections],
                         [("supervisor", ["10.1.1.70"]), ("vcfa", ["10.1.1.30"])])
        self.assertEqual(settings["_empty_groups"], ["esxi", "k8s:automation"])
        warns = settings["_warnings"]
        self.assertTrue(any("unknown setting 'host'" in w for w in warns), warns)
        self.assertTrue(any(w.startswith("[k8s:automation]") and "lists no hosts" in w for w in warns), warns)
        self.assertFalse(any(w.startswith("[esxi]") for w in warns), warns)   # untouched template group: no noise
        model = v.read_settings_model(text)
        self.assertIn(("vcfa", ["10.1.1.30"]), [(g["type"], g["hosts"]) for g in model["groups"]])

    def test_component_and_inventory(self):
        c = v.COMPONENTS["vcfa"]
        self.assertEqual((c["user"], c["prefix"], c["sudo"]), ("vmware-system-user", "vcfa", "auto"))
        self.assertEqual([g[0] for g in c["groups"]][:2], ["vcfa-services", "vcfa-detail"])
        self.assertIn("k8s-cluster", [g[0] for g in c["groups"]])
        self.assertIn("vcfa", v.K8S_TYPES)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "i.ini")
            with open(path, "w") as fh:
                fh.write("[vcfa]\nhosts = 10.1.1.5\nnamespaces = prelude, vmsp-*\n[vcfa:b]\nhosts = 10.1.1.6\n")
            _, sections, _ = v.load_inventory(path)
            self.assertEqual(sections[0]["user"], "vmware-system-user")
            self.assertEqual(sections[0]["namespaces_rx"], "^(prelude|vmsp-.*)$")
            self.assertIsNone(sections[1]["namespaces_rx"])
            with open(path, "w") as fh:
                fh.write("[vcfa]\nhosts = 10.1.1.5\nnamespaces = a;rm\n")
            with self.assertRaises(BaseException):
                v.load_inventory(path)

    def test_settings_round_trip_keeps_namespaces(self):
        text = v.INVENTORY_TEMPLATE.replace("[vcfa]\nhosts =\n", "[vcfa]\nhosts = 10.1.1.5\nnamespaces = prelude\n")
        model = v.read_settings_model(text)
        g = [x for x in model["groups"] if x["type"] == "vcfa"][0]
        self.assertEqual(g["namespaces"], "prelude")
        self.assertIn("namespaces = prelude", v.render_settings_model(model))

    def run_checks(self, nsrx=None):
        out = {}
        with tempfile.TemporaryDirectory() as d:
            k = os.path.join(d, "kubectl")
            with open(k, "w") as fh:
                fh.write(FAKE_KUBECTL)
            os.chmod(k, 0o755)
            for g in v.AUTOMATION_GROUPS:
                for c in g[2]:
                    if c["mode"] != "kubectl":
                        continue
                    cmd = c["cmd"].replace("{K}", k).replace(
                        "{NSRX}", v.shlex.quote(nsrx or v.AUTOMATION_NS_DEFAULT))
                    r = v.subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, timeout=60)
                    self.assertEqual((r.returncode, r.stderr), (0, ""), c["label"])
                    out[c["label"]] = r.stdout
        return out

    def test_checks_look_only_at_automation_namespaces(self):
        out = self.run_checks()
        self.assertIn("prelude CrashLoopBackOff 1", out["Automation namespaces and pod states"])
        self.assertNotIn("widgets-team", "".join(out.values()))
        self.assertNotIn("coredns", "".join(out.values()))
        self.assertEqual(out["Automation pods not Running or not Ready"].split()[1], "ebs-app-5c")
        self.assertIn("deployment.apps/ebs-app", out["Automation workloads below desired replicas"])
        images = out["Automation container images (versions)"]
        self.assertIn("2 ebs version 9.0.1.0-123", images)             # one per Automation namespace
        self.assertIn("ebs version 9.0.1.0-123", run(make(keep=()), images))   # kept as a version, not an IP
        self.assertNotIn("registry.example", images)                    # registry host dropped
        self.assertIn("prelude postgres-0", out["Automation databases and volumes"])
        logs = out["Errors in Automation pod logs (last 30 min)"]
        self.assertIn("== prelude/ebs-app-5c: 2 error line(s)", logs)
        self.assertIn("IllegalStateException", logs)
        self.assertNotIn("provisioning-service", logs)                  # "terror-free" is not an error
        self.assertIn("no ingress objects", out["Automation ingress hosts and certificates"])

    def test_missing_namespaces_are_explained(self):
        out = self.run_checks(v.automation_ns_regex("nothing-here"))
        for text in out.values():
            self.assertTrue(text.startswith("No VCF Automation namespaces found"), text)
        self.assertEqual(v.KEY_FACTS["Automation pods not Running or not Ready"](text),
                         [("automation_namespaces", "none found")])

    def test_run_catalog_fills_in_the_namespace_pattern(self):
        t = v.Target.__new__(v.Target)
        t.mode, t.clock_offset = "sh", None
        t.sec = {"type": "vcfa", "namespaces_rx": "^(prelude)$"}
        t.kube = {"kubectl": "kubectl", "kubeconfig": None, "sudo": None}
        seen = []
        t.sh = lambda command, timeout, sudo=None: (seen.append(command) or (0, "none\n", False))
        c = v.AUTOMATION_GROUPS[0][2][1]
        t.run_catalog(v.AUTOMATION_GROUPS[0], c)
        self.assertIn("grep -E '^(prelude)$'", seen[0])
        self.assertNotIn("{NSRX}", seen[0])
        self.assertNotIn("{K}", seen[0])

    def test_key_facts(self):
        K = v.KEY_FACTS
        self.assertEqual(K["Automation pods not Running or not Ready"]("none"), [("automation_pods_not_ready", 0)])
        self.assertEqual(K["Errors in Automation pod logs (last 30 min)"]("== prelude/a: 2 error line(s)\n   x\n"),
                         [("automation_pods_with_log_errors", 1)])
        certs = dict(K["Automation ingress hosts and certificates"](
            "== h\n   notAfter=Jan  5 12:00:00 2027 GMT\n   WARNING: the certificate expires within 30 days\n"))
        self.assertEqual(certs["automation_cert_expires_first"], "2027-01-05")
        self.assertEqual(certs["automation_cert_expiring_30d"], 1)


class NoiseSummarizers(unittest.TestCase):
    def test_df_drops_container_and_pod_mounts(self):
        df = ("Filesystem Size Used Avail Use% Mounted on\n/dev/sda3 40G 20G 20G 50% /\n"
              "tmpfs 3.9G 0 3.9G 0% /dev/shm\n"
              "overlay 40G 20G 20G 50% /run/containerd/io.containerd.runtime.v2.task/k8s.io/abc/rootfs\n"
              "shm 64M 0 64M 0% /run/containerd/io.containerd.grpc.v1.cri/sandboxes/abc/shm\n"
              "tmpfs 170M 12K 170M 1% /var/lib/kubelet/pods/0a1b/volumes/kubernetes.io~projected/kube-api-access\n")
        out = v.post_df(df)
        self.assertIn("/dev/sda3", out)
        self.assertIn("tmpfs 3.9G 0 3.9G 0% /dev/shm", out)
        self.assertNotIn("kube-api-access", out)
        self.assertIn("3 container/pod mounts omitted", out)
        self.assertEqual(v.post_df("Filesystem\n/dev/sda1 1G 1G 0 100% /"), "Filesystem\n/dev/sda1 1G 1G 0 100% /")
        self.assertIs(find("vcenter", "Disk usage")["post"], v.post_df)

    def test_log_lines_are_grouped(self):
        lines = ["2026-11-18T10:%02d:00.%03dZ NOTICE vmafdd t@%d: [SQLITE_ERROR:28] - double-quoted string "
                 "literal: \"cdcState\"" % (i, i, 1000 + i) for i in range(50)]
        lines += ["2026-11-18T11:00:0%dZ error wcpsvc opID=ab%dcd Guest operation failed: "
                  "/dev/shm/secret.tmp was not found" % (i, i) for i in range(3)]
        lines += ["2026-11-18T11:05:00Z error vmdird bind failed for user x"]
        out = v.post_sso_errors("\n".join(lines))
        self.assertIn("50 NOTICE/INFO-level line(s) counted but not listed", out)
        self.assertIn("   3 x  2026-11-18T11:00:00Z..2026-11-18T11:00:02Z", out)
        self.assertIn("bind failed", out)
        self.assertLess(len(out.splitlines()), 8)
        capi = "== capi-controller-manager-1\n" + "\n".join(
            'E1118 10:00:%02d.123456       1 controller.go:329] "Reconciler error" err="connection to the workload '
            'cluster is down" reconcileID="%08d-1111-2222-3333-444455556666"' % (i, i) for i in range(40))
        out = v.post_log_dedup(capi)
        self.assertIn("== capi-controller-manager-1", out)
        self.assertIn("  40 x  ", out)
        self.assertEqual(v.post_log_dedup("one\ntwo"), "one\ntwo")     # nothing repeated: unchanged

    def test_kubelet_watchdog_no_lines_are_not_errors(self):
        out = v.post_kubelet_errors(
            "Nov 18 10:00:00 n1 kubelet-watchdog[12]: No image pull failure found\n"
            "Nov 18 10:01:00 n1 kubelet-watchdog[12]: No image pull failure found\n"
            "Nov 18 10:02:00 n1 kubelet[99]: E1118 failed to sync pod x\n")
        self.assertIn("2 line(s) left out", out)
        self.assertNotIn("No image pull", out)
        self.assertIn("failed to sync pod", out)

    def test_warning_events_are_aggregated(self):
        rows = ["NAMESPACE LAST SEEN TYPE REASON OBJECT MESSAGE"]
        rows += ["ns-a  %dm  Warning  Unhealthy  pod/fluentbit-%d  Fluentbit on this pod is unhealthy" % (50 - i, i)
                 for i in range(40)]
        rows += ["ns-b  1m  Warning  BackOff  pod/web-0  Back-off restarting failed container"]
        out = v.post_events("\n".join(rows))
        lines = out.splitlines()
        self.assertIn("41 event(s) -> 2 distinct", lines[0])
        self.assertTrue(lines[2].startswith("   1x  1m  ns-b"))
        self.assertIn("  40x  11m  ns-a  Warning  Unhealthy  pod/fluentbit-0", lines[3])
        self.assertIn("+36 more", lines[3])

    def test_readyz_pv_pods_status_top(self):
        rz = "\n".join("[+]check%d ok" % i for i in range(35)) + "\nreadyz check passed\n"
        self.assertEqual(v.post_readyz(rz), "readyz check passed (35/35 ok)")
        self.assertIn("[-]etcd failed", v.post_readyz(rz.replace("[+]check3 ok", "[-]etcd failed: reason withheld")))
        pv = ("NAME CAPACITY ACCESS MODES RECLAIM POLICY STATUS CLAIM STORAGECLASS AGE\n"
              "pvc-1 10Gi RWO Delete Bound a/b sc 3d\npvc-2 10Gi RWO Retain Released a/c sc 3d\n")
        out = v.post_pv(pv)
        self.assertIn("2 persistent volume(s), 1 Bound (see the claims), 1 not Bound:", out)
        self.assertNotIn("pvc-1", out)
        self.assertIn("pvc-2", out)
        pods = ("NAMESPACE NAME READY STATUS RESTARTS AGE IP NODE\n"
                "ns-a web-7f6d5c4b8f-abcde 1/1 Running 0 3d 10.0.0.1 n1\n"
                "ns-a web-7f6d5c4b8f-fghij 0/1 Running 4 (2h ago) 3d 10.0.0.2 n1\n"
                "ns-a db-0 1/1 Running 0 3d 10.0.0.3 n1\n")
        out = v.post_all_pods(pods)
        self.assertIn("ns-a: 3 pods (3 Running), 1 not ready, restarts 4; workloads: web(2), db(1)", out)
        st = v.post_systemctl_status("CGroup: /system.slice/containerd.service\n"
                                     " |-1 /usr/bin/containerd\n |-2 /usr/bin/containerd-shim-runc-v2 -id a\n")
        self.assertIn("(1 containerd-shim process line(s) omitted)", st)
        self.assertIn("grep -v '^%Cpu[0-9]'", find("vcenter", "Top processes")["cmd"])
        self.assertIn("--lines=0", find("vcfmgmt", "kubelet and containerd")["cmd"])

    def test_raw_output_is_kept_for_the_anonymizer(self):
        t = v.Target.__new__(v.Target)
        t.mode, t.clock_offset, t.sudo, t.sec = "sh", None, None, {"type": "k8s"}
        t.kube = {"kubectl": "kubectl", "kubeconfig": None, "sudo": None}
        pods = ("NAMESPACE NAME READY STATUS RESTARTS AGE IP NODE\n"
                "widgets-ns ledger-api-7f6d5c4b8f-abcde 1/1 Running 0 3d 10.0.0.1 n1\n")
        t.sh = lambda command, timeout, sudo=None: (0, pods, False)
        c = find("k8s", "All pods (per namespace)")
        r = t.run_catalog(("k8s-workloads", "x"), c)
        self.assertEqual(r["raw"], pods)
        self.assertNotIn("ledger-api-7f6d5c4b8f-abcde", r["out"])
        boom = dict(c, post=lambda o: 1 / 0)
        self.assertEqual(t.run_catalog(("k8s-workloads", "x"), boom)["out"], pods)   # never lost
        sc = make()
        t.results, t.identity, t.errmsg = [r], [], ""
        v.learn_from_results([({"sec": {"prefix": "k8snode", "type": "k8s"}}, [t])], sc)
        self.assertTrue(sc.m.lookup("k8sobj", "ledger-api-7f6d5c4b8f-abcde"))
        self.assertTrue(sc.m.lookup("k8sobj", "ledger-api"))       # workload name shown by the summary
        rep = run(sc, v.post_all_pods(pods))
        self.assertNotIn("ledger", rep)
        self.assertNotIn("widgets", rep)

    def test_control_plane_certs_fall_back_when_kubeadm_refuses(self):
        import subprocess
        c = find("supervisor", "Control-plane certificates (kubeadm)")["cmd"]
        refuse = ("[check-expiration] Reading configuration from the \"kubeadm-config\" ConfigMap...\n"
                  "W1119 17:01:02.967756  181247 cluster.go:105] error unmarshaling configuration\n\n"
                  "error: kubeConfig file /etc/kubernetes/scheduler.conf does not have an embedded client certificate\n")
        table = ("[check-expiration] Reading configuration from the cluster...\n"
                 "CERTIFICATE   EXPIRES                  RESIDUAL TIME   CERTIFICATE AUTHORITY\n"
                 "apiserver     Nov 19, 2027 14:19 UTC   364d            ca\n")
        for kubeadm_out, rc in ((refuse, 1), (table, 0)):
            with tempfile.TemporaryDirectory() as d:
                pki, bindir = os.path.join(d, "pki"), os.path.join(d, "bin")
                os.makedirs(os.path.join(pki, "etcd"))
                os.makedirs(bindir)
                for f in ("apiserver.crt", "etcd/server.crt"):
                    open(os.path.join(pki, f), "w").close()
                for name, body in (("kubeadm", "cat <<'EOF'\n%sEOF\nexit %d" % (kubeadm_out, rc)),
                                   ("openssl", "echo 'notAfter=Nov 19 14:19:33 2027 GMT'")):
                    path = os.path.join(bindir, name)
                    with open(path, "w") as fh:
                        fh.write("#!/bin/sh\n" + body + "\n")
                    os.chmod(path, 0o755)
                env = dict(os.environ, PATH=bindir + os.pathsep + os.environ["PATH"])
                out = subprocess.run(["sh", "-c", c.replace("/etc/kubernetes/pki", pki)],
                                     stdout=subprocess.PIPE, env=env).stdout.decode()
            if rc:
                self.assertIn("gave no certificate table: reading the certificate files", out)
                self.assertIn(pki + "/apiserver.crt: notAfter=Nov 19 14:19:33 2027 GMT", out)
                self.assertIn(pki + "/etcd/server.crt: notAfter=", out)
                self.assertNotIn("error:", out)
            else:
                self.assertIn("apiserver     Nov 19, 2027", out)
                self.assertNotIn("[check-expiration]", out)
                self.assertNotIn("reading the certificate files", out)

    def test_tool_caused_failures_are_fixed(self):
        etcd = find("k8s", "etcd health and status (leader, database size)")["cmd"]
        self.assertNotIn("sh -c", etcd)
        self.assertIn('exec "$p" -- etcdctl --endpoints=', etcd)
        self.assertIn("nothing answered with a certificate", find("vcenter", "Certificate on port 443")["cmd"])
        labels = [c["label"] for _, _, cs in v.COMPONENTS["vcfmgmt"]["groups"] for c in cs]
        self.assertNotIn("Certificate on port 443", labels)
        self.assertNotIn("Nodes with roles", labels)
        self.assertEqual(labels.count("Nodes"), 1)
        self.assertIn("not a control-plane node", find("vcfmgmt", "Control-plane certificates (kubeadm)")["cmd"])
        pol = ("== /Security/PasswordMaxDays\n   Path: /Security/PasswordMaxDays\n   Type: integer\n"
               "   Int Value: 90\n   Default Int Value: 99999\n   String Value: \n"
               "== /Security/PasswordQualityControl\n   Path: /Security/PasswordQualityControl\n   Type: string\n"
               "   Int Value: 0\n   String Value: retry=3 min=disabled,disabled,disabled,7,7\n"
               "== /Security/AccountUnlockTime\nError: Unable to find option AccountUnlockTime\n")
        out = v.post_esxi_policy(pol)
        self.assertIn("/Security/PasswordMaxDays = 90", out)
        self.assertIn("/Security/PasswordQualityControl = 0", out)
        self.assertIn("/Security/AccountUnlockTime: not available on this host (Error: Unable to find", out)



def _res(group, label, out, status="ok", rc=None, cmd="c", dur=0.2, note="", **spec):
    return {"group": group, "label": label, "cmd": cmd, "rc": (0 if status == "ok" else 1) if rc is None else rc,
            "out": out, "dur": dur, "status": status, "note": note, "spec": dict({"max_lines": None}, **spec)}


def _tgt(ph, results, mode="sh", clock=None):
    return types.SimpleNamespace(ph=ph, mode=mode, errkind=None, errmsg="", identity=[], user="root", notes=[],
                                 clock_offset=clock, results=results)


CAPI_CLUSTERS = (
    "NAMESPACE   NAME                               CLUSTERCLASS     AVAILABLE   CP DESIRED   CP CURRENT   "
    "CP READY   PHASE         AGE   VERSION\n"
    "ns-0011     cluster.cluster.x-k8s.io/vks-01    builtin-generic  False       4            4            "
    "0          Provisioned   40d   v1.31.4\n"
    "ns-0013     cluster.cluster.x-k8s.io/vks-02    builtin-generic  True        3            3            "
    "2          Provisioned   40d   v1.31.4\n"
    "ns-0014     cluster.cluster.x-k8s.io/vks-03    builtin-generic  True        3            3            "
    "3          Provisioned   40d   v1.31.4\n"
    "\n"
    "NAMESPACE   NAME                                  CLUSTER   AVAILABLE   PHASE\n"
    "ns-0011     machine.cluster.x-k8s.io/vks-01-cp1   vks-01    False       Provisioning\n")


class ReportFindings(unittest.TestCase):
    """Built from the problems found in a real 1.18.0 report."""

    def sample(self):
        G = ("g", "G")
        sup = _tgt("supervisor-01", [
            _res(("k8s-supervisor", "S"), "VKS / Cluster API clusters", CAPI_CLUSTERS),
            _res(("k8s-cluster", "K"), "Nodes", "NAME STATUS ROLES AGE VERSION\ncp1 Ready control-plane 9d v1\n"
                                                "cp2 Ready control-plane 9d v1\n"),
        ])
        vc = _tgt("vcenter-01", [
            _res(("vc-storage", "S"), "Key partitions",
                 "Filesystem Size Used Avail Use% Mounted on\n/dev/mapper/archive_vg-archive 50G 47G 2.5G 95% "
                 "/storage/archive\n/dev/sda3 11G 5G 6G 45% /\n"),
            _res(("os", "O"), "Memory", "              total        used        free      shared  buff/cache   available\n"
                                       "Mem:          32000       20000        1000         100       11000       11500\n"
                                       "Swap:         25000        7987       17013\n"),
        ])
        nsx = _tgt("nsxmgr-01", [_res(("nsx-node", "N"), "Memory",
                                      "total 23.5 GiB, available 2.8 GiB (12%), free 0.7 GiB\nswap: none configured")],
                   mode="nsxcli")
        nsx.sec = {"name": "nsx", "type": "nsx"}
        esx = _tgt("esxi-mgmt-01", [_res(("passwords", "P"), "Password age (days)",
                                         "root                 changed 20 days ago, max age 90 days\n"
                                         "nsx-user             changed 211 days ago, max age 90 days\n")])
        units = "● cap_init.service loaded failed failed Cloud init\n"
        mgmt = [_tgt("vcfmgmt-mgmt-%02d" % i, [_res(G, "Failed units", units)]) for i in (1, 2, 3)]
        return [({"sec": {"name": "supervisor", "type": "supervisor"}}, [sup]),
                ({"sec": {"name": "vcenter", "type": "vcenter"}}, [vc]),
                ({"sec": {"name": "nsx", "type": "nsx"}}, [nsx]),
                ({"sec": {"name": "esxi:mgmt", "type": "esxi"}}, [esx]),
                ({"sec": {"name": "vcfmgmt:mgmt", "type": "vcfmgmt"}}, mgmt)]

    def test_expected_findings(self):
        done = self.sample()
        digest = [(t, v.key_facts(t)) for _, ts in done for t in ts]
        rows = v.report_findings(done, digest)
        got = [(sev, who, text) for sev, who, text, _ in rows]
        self.assertEqual(got[0], ("high", "supervisor-01", "cluster ns-0011/vks-01 AVAILABLE False, CP ready 0/4"))
        self.assertIn(("med", "supervisor-01", "cluster ns-0013/vks-02 CP ready 2/3"), got)
        self.assertIn(("med", "vcenter-01", "filesystem /storage/archive at 95%"), got)
        # NSX Manager keeps most memory in use by design: worth a note, not a "med" finding
        self.assertIn(("info", "nsxmgr-01", "memory available 12% (normal for NSX Manager, whose services keep "
                                            "most memory in use)"), got)
        self.assertIn(("low", "vcenter-01", "swap in use: 7.8 GiB"), got)
        self.assertIn(("low", "esxi-mgmt-01", "password older than its maximum age: nsx-user 211d > 90d"), got)
        self.assertEqual(got[-1], ("info", "all 3 hosts of [vcfmgmt:mgmt]", "failed systemd unit(s): cap_init.service"))
        self.assertFalse(any("vks-03" in t or "machine" in t for _, _, t in got))
        self.assertEqual([r[0] for r in rows], sorted([r[0] for r in rows], key=v.SEVERITIES.index))
        facts = dict(digest[0][1])
        self.assertEqual(facts["nodes_ready"], "2/2")
        self.assertIn("ns-0011/vks-01", facts["capi_clusters_unavailable"])

    def test_findings_section_is_near_the_top(self):
        rep = v.build_report(types.SimpleNamespace(ssh_banner="x"), self.sample(), make(),
                             v.datetime.datetime(2026, 11, 18), 400)
        self.assertLess(rep.index("## How to read this report"), rep.index("## Findings"))
        self.assertLess(rep.index("## Findings"), rep.index("## Summary"))
        self.assertIn("- **high** supervisor-01: cluster ns-0011/vks-01 AVAILABLE False, CP ready 0/4 -> "
                      "VKS / Cluster API clusters", rep)

    def test_more_key_facts(self):
        K = v.KEY_FACTS
        self.assertEqual(K["Nodes"]("NAME STATUS\na Ready x\nb NotReady x\nc Ready,SchedulingDisabled x\n"),
                         [("nodes_ready", "2/3")])
        self.assertEqual(K["Pods with most restarts"]("ns-1 web-0 0/1 CrashLoopBackOff 37 (2m ago) 3d\n"),
                         [("top_restarts", "ns-1/web-0 37")])
        self.assertEqual(K["Failed units"](""), [("failed_units", "none")])
        self.assertEqual(K["Core dumps"]("total 8\n-rw------- 1 root root 4.0K Nov 1 core.vpxd.1\n"), [("core_dumps", 1)])
        self.assertEqual(K["Latest warning events"](v.post_events(
            "NAMESPACE LAST SEEN TYPE REASON OBJECT MESSAGE\na 1m Warning Unhealthy pod/x bad\n"
            "a 1m Warning Unhealthy pod/y bad\nb 2m Warning BackOff pod/z back-off\n")),
            [("warning_events_by_reason", "Unhealthy 2, BackOff 1")])
        old = v._fact_chage("== root\nLast password change : Jan 01, 2020\nPassword expires : Mar 31, 2020\n"
                            "== admin\nPassword expires : never\n")
        self.assertEqual(old, [("passwords_expired", "root expired 2020-03-31")])


LONG_CMD = "kubeadm certs check-expiration 2>&1 | head -n 40; " * 4


class ReportLayout(unittest.TestCase):
    def mgmt(self):
        G = ("os", "OS")
        same = "NAME=Photon\nVERSION=5.0"
        ts = []
        for i in (1, 2, 3):
            ph = "vcfmgmt-mgmt-worker-%02d" % i
            ts.append(_tgt(ph, [
                _res(G, "OS release", same),
                _res(G, "Hostname echo", "I am %s" % ph),
                _res(G, "Uptime and load", "up %d days" % i),
                _res(("node-certs", "C"), "Control-plane certificates (kubeadm)", "x", cmd=LONG_CMD),
            ]))
        ts[2].results.append(_res(G, "Failed thing", "ls: cannot open: Permission denied", status="fail"))
        ts[2].results.append(_res(G, "vSAN", "vSAN Clustering is not enabled on this host", status="fail"))
        ts[2].results.append(_res(G, "Slow", "boom", status="timeout", dur=45.0))
        return [({"sec": {"name": "vcfmgmt:mgmt", "type": "vcfmgmt"}}, ts)]

    def report(self):
        return v.build_report(types.SimpleNamespace(ssh_banner="x"), self.mgmt(), make(),
                              v.datetime.datetime(2026, 11, 18), 400)

    def test_identical_output_is_printed_once(self):
        rep = self.report()
        self.assertIn("### Identical on all 3 hosts (vcfmgmt-mgmt-worker-01, vcfmgmt-mgmt-worker-02, "
                      "vcfmgmt-mgmt-worker-03)", rep)
        self.assertEqual(rep.count("NAME=Photon"), 1)
        self.assertEqual(rep.count("**Hostname echo**"), 1)          # own name normalized
        self.assertIn("I am {host}", rep)
        self.assertIn("`{host}` above stands for each host's own name.", rep)
        self.assertEqual(rep.count("**Uptime and load**"), 3)       # differs: printed per host
        self.assertIn("3 check(s) with the same output as the other hosts", rep)

    def test_failures_are_classified_once(self):
        rep = self.report()
        sec = rep.split("### Collection problems and failed checks", 1)[1].split("### Key facts", 1)[0]
        self.assertIn("- check limitation (permissions, credentials, tool or timeout; not a fault):", sec)
        self.assertIn("vcfmgmt-mgmt-worker-03: Failed thing (ls: cannot open: Permission denied)", sec)
        self.assertIn("vcfmgmt-mgmt-worker-03: Slow (timed out)", sec)
        self.assertIn("- feature not in use (component or tool not present):\n  - vcfmgmt-mgmt-worker-03: vSAN", sec)
        self.assertIn("non-zero exit status is not always a fault", rep)
        self.assertNotIn("Items needing attention", rep)
        self.assertIn("**Slow** (TIMEOUT, 45s)", rep)
        self.assertIn("**Failed thing** (exit 1)", rep)

    def test_long_commands_go_to_the_appendix(self):
        rep = self.report()
        self.assertIn("(full command: **C1** in the appendix)", rep)
        app = rep.split("## Appendix: long commands", 1)[1]
        self.assertIn("**C1** - Control-plane certificates (kubeadm)", app)
        self.assertIn(LONG_CMD, app)
        self.assertEqual(rep.count(LONG_CMD), 1)

    def test_ai_copy_drops_low_value_detail_first(self):
        rep = self.report() + "\n"
        filler = "\n".join("line %d" % i for i in range(3000))
        big = rep.replace("NAME=Photon", "NAME=Photon\n" + filler)
        text, cut = v.report_for_ai(big, len(rep) + 2000)
        self.assertTrue(cut)
        self.assertNotIn("line 2999", text)
        for keep in ("## Findings", "### Collection problems", "**Failed thing** (exit 1)",
                     "Permission denied", "the collector left out 1 check output(s) (OS release)"):
            self.assertIn(keep, text)
        self.assertLessEqual(len(text), len(rep) + 2000)



MISSING_TZ = "1027ca04-24a8-11ef-9e70-06252099f24a"
TZ_OVL = "3c2f6a10-9b1e-4d7a-8f00-aa11bb22cc33"
TZ_VLAN_MP = "7d8e9f00-1111-4222-8333-444455556666"
EP = "/policy/api/v1/infra/sites/default/enforcement-points/default"
PATH = "/infra/sites/default/enforcement-points/default/transport-zones/"
FAKE_HOSTCFG = {
    "/policy/api/v1/infra/sites": {"results": [{"id": "default"}]},
    "/policy/api/v1/infra/sites/default/enforcement-points": {"results": [{"id": "default"}]},
    EP + "/transport-zones": {"results": [
        {"id": TZ_OVL, "display_name": "widgets-overlay-tz", "tz_type": "OVERLAY_BACKED", "path": PATH + TZ_OVL,
         "realization_id": TZ_OVL},
        {"id": "widgets-vlan-tz", "display_name": "widgets-vlan-tz", "tz_type": "VLAN_BACKED",
         "path": PATH + "widgets-vlan-tz", "realization_id": TZ_VLAN_MP}]},
    "/api/v1/transport-zones?page_size=500&include_system_owned=true": {"results": [
        {"id": TZ_OVL, "display_name": "widgets-overlay-tz", "transport_type": "OVERLAY"},
        {"id": TZ_VLAN_MP, "display_name": "widgets-vlan-tz", "transport_type": "VLAN"}]},
    "/api/v1/fabric/compute-collections?page_size=500": {"results": [
        {"external_id": "cm-1:domain-c8", "display_name": "WIDGETS-CL01"}]},
    EP + "/transport-node-collections": {"results": [
        {"id": "tnc-1", "compute_collection_id": "cm-1:domain-c8",
         "transport_node_profile_id": "/infra/host-transport-node-profiles/widgets-cl01-tnp"}]},
    EP + "/transport-node-collections/tnc-1/state": {"state": "SUCCESS"},
    "/policy/api/v1/infra/host-transport-node-profiles": {"results": [
        {"id": "widgets-cl01-tnp", "display_name": "widgets-cl01-tnp",
         "path": "/infra/host-transport-node-profiles/widgets-cl01-tnp",
         "host_switch_spec": {"host_switches": [{"host_switch_name": "widgets-vds01", "transport_zone_endpoints": [
             {"transport_zone_id": PATH + TZ_OVL}, {"transport_zone_id": PATH + MISSING_TZ},
             {"transport_zone_id": PATH + TZ_VLAN_MP}]}]}}]},
    EP + "/host-transport-nodes": {"results": [
        {"id": "h1", "display_name": "esx01.corp.example-widgets.com", "host_switch_spec": {"host_switches": [
            {"host_switch_name": "widgets-vds01", "transport_zone_endpoints": [
                {"transport_zone_id": PATH + MISSING_TZ}]}]}}]},
    "/api/v1/fabric/compute-managers?page_size=100": {"results": [{"id": "cm-1", "server": "vc01.corp.example-widgets.com",
                                                                    "origin_type": "vCenter"}]},
    "/api/v1/fabric/compute-managers/cm-1/status": {"connection_status": "UP", "registration_status": "REGISTERED",
                                                     "version": "9.0.0"},
}

FAKE_SDDC_TASKS = {
    "/v1/tasks?pageSize=500&pageNumber=0": {"elements": [
        {"id": "t-1", "name": "Sync inventory", "status": "Failed", "creationTimestamp": "2099-11-18T09:07:00Z"},
        {"id": "t-2", "name": "Rotate passwords", "status": "Successful", "creationTimestamp": "2099-11-17T09:07:00Z"}],
        "pageMetadata": {"totalPages": 1}},
    "/v1/tasks/t-1": {"id": "t-1", "name": "Sync inventory", "status": "Failed", "type": "INVENTORY_SYNC",
                      "creationTimestamp": "2099-11-18T09:07:00Z", "isRetryable": True,
                      "resources": [{"type": "CLUSTER", "name": "WIDGETS-CL01"}],
                      "subTasks": [{"name": "Generate inputs for Configuring Clusters for NSX", "status": "Failed",
                                    "errors": [{"message": "Error in reading transport node Profile from transport node "
                                                           "collection", "referenceToken": "KR17KQ",
                                                "causes": [{"message": "No transport zone found for given path " + PATH
                                                            + MISSING_TZ}]}]},
                                   {"name": "Validate", "status": "Successful"}]},
    "/v1/nsxt-clusters?pageNumber=0": {"elements": [{"id": "n-1", "vipFqdn": "nsx01.corp.example-widgets.com",
                                                     "version": "9.0.0", "domains": [{"name": "WIDGETS-MGMT"}]}]},
    "/v1/nsxt-clusters/n-1/transport-zones": [{"name": "widgets-overlay-tz", "id": MISSING_TZ, "transportType": "OVERLAY"}],
    "/v1/domains?pageNumber=0": {"elements": [{"id": "d-1", "name": "WIDGETS-MGMT"}]},
    "/v1/clusters?pageNumber=0": {"elements": [{"id": "c-1", "name": "WIDGETS-CL01", "domain": {"id": "d-1"},
                                                "status": "ACTIVE"}]},
    "/v1/clusters/c-1/network/network-profiles": [{"name": "widgets-np01", "isDefault": True, "nsxtHostSwitchConfigs": [
        {"vdsName": "widgets-vds01", "transportZones": [{"name": "widgets-overlay-tz", "transportType": "OVERLAY"},
                                                        {"name": "widgets-edge-vlan", "transportType": "VLAN"}]}]}],
}


class FakeApi:
    def __init__(self, data):
        self.data, self.seen = data, []

    def get(self, path):
        self.seen.append(path)
        return self.data.get(path)

    def paged(self, path, limit=10):
        return (self.get(path) or {}).get("results") or []


class TransportZoneReferences(unittest.TestCase):
    """'Error in reading transport node Profile ... No transport zone found for given path'."""

    def test_missing_and_manager_id_references_are_explained(self):
        out = v.nsx_host_config(FakeApi(FAKE_HOSTCFG))
        self.assertTrue(out.startswith("PROBLEM: profile widgets-cl01-tnp (used by WIDGETS-CL01 (domain-c8)) "
                                       "references transport zone %s%s: MISSING" % (PATH, MISSING_TZ)), out)
        self.assertIn("[MANAGER ID] this is the Manager API id of transport zone widgets-vlan-tz; its Policy path is "
                      + PATH + "widgets-vlan-tz", out)
        self.assertIn("-> %s%s  [OK] widgets-overlay-tz" % (PATH, TZ_OVL), out)
        self.assertIn("cluster: WIDGETS-CL01 (domain-c8)  profile=/infra/host-transport-node-profiles/widgets-cl01-tnp"
                      "  state=SUCCESS", out)
        self.assertIn("PROBLEM: 1 host transport node(s) reference transport zone %s%s" % (PATH, MISSING_TZ), out)
        self.assertEqual(v.KEY_FACTS["Transport zones, node profiles and cluster attachments"](out),
                         [("nsx_tz_reference_problems", 3)])

    def test_clean_configuration(self):
        data = dict(FAKE_HOSTCFG)
        data["/policy/api/v1/infra/host-transport-node-profiles"] = {"results": [
            {"display_name": "p", "path": "/infra/host-transport-node-profiles/widgets-cl01-tnp",
             "host_switch_spec": {"host_switches": [{"host_switch_name": "s", "transport_zone_endpoints": [
                 {"transport_zone_id": PATH + TZ_OVL}]}]}}]}
        data[EP + "/host-transport-nodes"] = {"results": []}
        self.assertTrue(v.nsx_host_config(FakeApi(data)).startswith("Every transport zone reference resolves."))

    def test_sddc_failed_task_and_inventory(self):
        api = FakeApi(FAKE_SDDC_TASKS)
        tasks, inv = v.sddc_failed_tasks(api), v.sddc_nsx_inventory(api)
        self.assertTrue(tasks.startswith("1 failed task(s) in the last 14 days"))
        self.assertIn("FAILED TASK: 2099-11-18T09:07:00  Sync inventory  type=INVENTORY_SYNC", tasks)
        self.assertIn("  failed subtask: Generate inputs for Configuring Clusters for NSX", tasks)
        self.assertIn("error: Error in reading transport node Profile from transport node collection  "
                      "[reference token KR17KQ]", tasks)
        self.assertIn("cause: No transport zone found for given path " + PATH + MISSING_TZ, tasks)
        self.assertNotIn("Rotate passwords", tasks)
        self.assertIn("transport zone known to SDDC Manager: widgets-overlay-tz  id=" + MISSING_TZ, inv)
        self.assertIn("cluster: WIDGETS-CL01  id=c-1  workload domain: WIDGETS-MGMT  status=ACTIVE", inv)
        self.assertIn("network profile widgets-np01 (active): host switch widgets-vds01 -> transport zones: "
                      "widgets-overlay-tz (OVERLAY), widgets-edge-vlan (VLAN)", inv)
        self.assertIn("transport zones: not available", v.sddc_nsx_inventory(FakeApi(
            {k: v_ for k, v_ in FAKE_SDDC_TASKS.items() if "transport-zones" not in k})))

    def test_findings_and_anonymization(self):
        nsx = v.nsx_host_config(FakeApi(FAKE_HOSTCFG)) + "\n" + v.nsx_compute_managers(FakeApi(FAKE_HOSTCFG))
        api = FakeApi(FAKE_SDDC_TASKS)
        sddc = v.sddc_failed_tasks(api) + "\n" + v.sddc_nsx_inventory(api)
        sc = make()
        for typ, key, text in (("nsx", "nsx-api-hostconfig", nsx), ("sddc", "sddc-api-tasks", sddc)):
            group = [g for g in v.COMPONENTS[typ]["groups"] if g[0] == key][0]
            for c in group[2]:
                harvest(sc, c, text)
        problem = "Cause: No transport zone found for given path " + PATH + MISSING_TZ
        out = run(sc, nsx + "\n" + sddc + "\n" + problem)
        for gone in ("widgets", "WIDGETS", "example-widgets", MISSING_TZ):
            self.assertNotIn(gone, out)
        ph = re.search(r"Cause: No transport zone found for given path \S+/(uuid-\d+)", out).group(1)
        self.assertGreaterEqual(out.count(ph), 4)       # same placeholder in NSX, SDDC Manager and the error text
        self.assertIn("KR17KQ", out)
        lab = "Transport zones, node profiles and cluster attachments"
        t = types.SimpleNamespace(ph="nsxmgr-01", errkind=None, clock_offset=None, results=[
            _res(("nsx-api-hostconfig", "H"), lab, v.nsx_host_config(FakeApi(FAKE_HOSTCFG)), api="nsx_host_config"),
            _res(("sddc-api-tasks", "T"), "Failed tasks (last 14 days) with subtask errors and reference tokens",
                 v.sddc_failed_tasks(FakeApi(FAKE_SDDC_TASKS)))])
        rows = v.target_findings(t, v.key_facts(t))
        self.assertEqual(rows[0][0], "high")
        self.assertIn("references transport zone", rows[0][1])
        self.assertTrue(any(r[0] == "med" and "Sync inventory" in r[1] and "KR17KQ" in r[1] and
                            "No transport zone found" in r[1] for r in rows))

    def test_wiring_and_only_reads(self):
        self.assertTrue(v.is_api_group("nsx-api-hostconfig"))
        self.assertTrue(v.is_api_group("sddc-api-tasks"))
        self.assertFalse(v.is_api_group("sddc-logs"))
        api = FakeApi(FAKE_HOSTCFG)
        v.nsx_host_config(api)
        self.assertTrue(all(p.startswith(("/policy/api/v1/", "/api/v1/")) for p in api.seen))
        logs = find("sddc", "NSX transport zone / profile errors in SDDC Manager logs (last 3 days)")
        self.assertIs(logs["post"], v.post_log_dedup)
        self.assertIsNone(v.readonly_problem(logs["cmd"], "sh"))


if __name__ == "__main__":
    unittest.main()


class AnalystReplyChecks(unittest.TestCase):
    """Problems found in a 1.20.0 report and in an AI reply to it (all names invented)."""

    INV = ("[nsx]\nhosts = nsx01.corp.example-widgets.com\n"
           "[sddc]\nhosts = sddc01.corp.example-widgets.com\n")

    def prep(self, reply, extra=()):
        import argparse
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d)
        inv = os.path.join(d, "inventory.ini")
        with open(inv, "w") as fh:
            fh.write(self.INV)
        m = v.Mapping(os.path.join(d, "private", "mapping.json"))
        sc = v.Scrubber(m)
        sc.learn_host("nsx01.corp.example-widgets.com", prefix="nsxmgr")
        sc.learn_host("sddc01.corp.example-widgets.com", prefix="sddcmgr")
        for cat, real in extra:
            m.get(cat, real)
        m.save()
        return v.prepare_plan(argparse.Namespace(inventory=inv, private_dir=os.path.join(d, "private")), reply)

    # --- report side -----------------------------------------------------------------
    def test_ntp_with_a_positive_offset_is_synced(self):
        out = v.post_ntpq_peers(
            "     remote           refid      st t when poll reach   delay   offset  jitter\n"
            "==============================================================================\n"
            "*ntp1.corp.examp .GPS.            1 u  161 1024  377    0.458   +0.501   0.304\n"
            "+ntp2.corp.examp .GPS.            1 u  479 1024  377    0.374   +0.522   0.361\n")
        self.assertEqual(v._fact_ntp(out), [("ntp_synced", "yes, stratum 1"), ("ntp_offset_ms", 0.501)])
        self.assertEqual(v._fact_ntp("remote refid\n=====\n+a .GPS. 1 u 1 64 377 0.1 -0.2 0.1\n"),
                         [("ntp_synced", "no peer selected")])

    def test_stale_quantity_in_the_mapping_is_not_replaced(self):
        m = v.Mapping(None)
        m.get("k8sobj", "10m", prefix="k8sobj")        # written by an older version from a kubectl AGE column
        out = run(make(mapping=m), "/dev/sda2  10M  2.4M  7.6M  24% /boot/efi\npod age 10m")
        self.assertIn("/dev/sda2  10M  2.4M", out)
        self.assertNotIn("k8sobj", out.lower())

    def test_environment_domain_on_its_own_is_a_domain(self):
        sc = make()
        sc.learn_domain("example-widgets.com")
        out = run(sc, "name esx01.corp.example-widgets.com\nsearch corp.example-widgets.com\n"
                      "other app.example-widgets.com")
        dom = re.search(r"esxi-01\.(domain-\d+)", out).group(1)
        self.assertIn("search %s\n" % dom, out)
        self.assertRegex(out, r"other host-\d+\.domain-\d+")

    def test_reference_tokens_are_kept_but_tokens_are_not(self):
        out = run(make(), '{"errorCode":"X","referenceToken":"53TFGG"} reference_token=KR17KQ '
                          '"token":"c2VjcmV0LXZhbHVlLTEyMw" access_token=abc.def.ghi')
        self.assertIn('"referenceToken":"53TFGG"', out)
        self.assertIn("reference_token=KR17KQ", out)
        self.assertNotIn("c2VjcmV0", out)
        self.assertNotIn("abc.def.ghi", out)

    def test_profile_and_host_problems_are_one_finding(self):
        got = v.merge_tz_problems([
            "profile p1 (used by c1) references transport zone /x/tz-9: MISSING - gone",
            "9 host transport node(s) reference transport zone /x/tz-9, which does not resolve",
            "3 host transport node(s) reference transport zone /x/tz-7, which does not resolve"])
        self.assertEqual(got, ["profile p1 (used by c1) references transport zone /x/tz-9: MISSING - gone - "
                               "inherited by 9 host transport node(s)",
                               "3 host transport node(s) reference transport zone /x/tz-7, which does not resolve"])

    def test_sddc_log_check_drops_debug_lines(self):
        c = find("sddc", "NSX transport zone / profile errors in SDDC Manager logs (last 3 days)")
        self.assertIn("(DEBUG|TRACE)", c["cmd"])

    def test_reply_rules_cover_shell_modes_and_credentials(self):
        for text in (v.ANALYST_GUIDE, v.investigator_prompt(5, True)):
            self.assertIn("nsxcli", text)
            self.assertIn("certificate checks", text)
            self.assertIn("no YAML", text)

    # --- plan parsing and translation ----------------------------------------------------
    def test_yaml_block_marker_and_indentation_are_kept(self):
        st = v.parse_plan("```vcf-plan\n[fix] target=nsxmgr-01\nlabel: x\nrun: |\n"
                          "  python3 -c \"\n  try:\n      print(1)\n  except Exception as e:\n      print(e)\n\n"
                          "  print(2)\n  \"\nnote: a\n  b\n```")["steps"][0]
        self.assertEqual(st["run"], 'python3 -c "\ntry:\n    print(1)\nexcept Exception as e:\n    print(e)\n\n'
                                    'print(2)\n"')
        self.assertEqual(st["note"], "a b")
        st = v.parse_plan("```vcf-plan\n[collect] target=a\nrun: grep x f\n  | tail -n 5\n```")["steps"][0]
        self.assertEqual(st["run"], "grep x f\n| tail -n 5")

    def test_decoder_translates_after_a_hyphen_only(self):
        m = v.Mapping(None)
        uid = m.get("uuid", "1027ca04-0000-0000-0000-000000000001")
        m.get("host", "realhost")              # host-0001
        dec = v.Decoder(m)
        self.assertEqual(dec("restored-tz-%s" % uid), "restored-tz-1027ca04-0000-0000-0000-000000000001")
        self.assertEqual(dec("exthost-0001 host-0001"), "exthost-0001 realhost")
        self.assertEqual(dec("ip-%s-2" % uid), "ip-%s-2" % uid)        # followed by -digit: not a placeholder
        self.assertEqual(dec.unknown_placeholders(dec("host-0001 uuid-0999 ip-n9-h9 esxi-01")),
                         ["uuid-0999", "ip-n9-h9"])

    def test_step_credentials(self):
        self.assertTrue(v.step_credential("headers={'Authorization': 'Basic YWRtaW46UGxhY2Vob2xkZXI='}"))
        self.assertIn("base64", v.step_credential("echo YWRtaW46UGxhY2Vob2xkZXI= > /dev/null"))
        self.assertTrue(v.step_credential("curl -u admin:VMware1! https://x/api"))
        self.assertTrue(v.step_credential("python3 x.py --password Secret123"))
        for ok in ("curl -u admin https://x/api", "curl -H \"X-Auth-Token: $TOKEN\" https://x",
                   "grep -i password /var/log/x.log", "chage -l root", "echo password=<your password>",
                   "get cluster status", "grep -c 'referenceToken' /var/log/x"):
            self.assertIsNone(v.step_credential(ok), ok)

    def test_ai_reply_from_the_report(self):
        reply = """```vcf-plan
plan: fix
[collect] target=nsxmgr-01
label: profiles via python
run: python3 -c "import urllib.request; urllib.request.Request('https://localhost/policy/api/v1/infra/host-transport-node-profiles', headers={'Authorization': 'Basic YWRtaW46UGxhY2Vob2xkZXI='})"

[collect] target=nsxmgr-01
label: disk
run: df -h

[fix] target=nsxmgr-01
label: recreate the missing transport zone
run: |
  python3 -c "
  import urllib.request, ssl
  ctx = ssl.create_default_context()
  ctx.verify_mode = ssl.CERT_NONE
  data = {'display_name': 'restored-tz-uuid-0001'}
  req = urllib.request.Request(url, headers={'Authorization': 'Basic YWRtaW46UGxhY2Vob2xkZXI='}, method='PUT')
  try:
      urllib.request.urlopen(req, context=ctx)
  except Exception as e:
      print(e)
  "
note: impact: x

[fix] target=sddcmgr-01
label: Verify SDDC Manager and NSX synchronization
run: systemctl restart domainmanager.service operationsmanager.service
note: rollback: none

[fix] target=sddcmgr-01
label: Verify the services
run: systemctl is-active domainmanager.service
```"""
        p = self.prep(reply, extra=[("uuid", "1027ca04-0000-0000-0000-000000000001")])
        blocked = [e for e in p["manual"] if e["kind"] == "blocked"]
        self.assertEqual(len(blocked), 1)
        self.assertIn("Authorization header", blocked[0]["reason"])
        self.assertTrue(any("nsx login opens the NSX CLI" in pr and "(disk)" in pr for pr in p["problems"]))
        fixes = [e for e in p["manual"] if e["kind"] == "fix"]
        tz, restart, verify = fixes
        self.assertIn("\n    urllib.request.urlopen(req, context=ctx)\n", tz["command"])   # indentation kept
        self.assertNotIn("\n|", "\n" + tz["command"])
        self.assertIn("restored-tz-1027ca04-0000-0000-0000-000000000001", tz["command"])
        w = " ".join(tz["warnings"])
        self.assertIn("Authorization header", w)
        self.assertIn("certificate checking", w)
        self.assertIn("opens the NSX CLI", w)
        self.assertTrue(tz["changes"])
        self.assertEqual(restart["changes"], "it can change a service")
        w = " ".join(restart["warnings"])
        self.assertIn("labelled as a verification, but it changes the system", w)
        self.assertIn("has no sudo: run it as root", w)
        self.assertEqual((verify["changes"], verify["warnings"]), ("", []))
        script = v.plan_as_script(fixes)
        self.assertIn("#    WARNING: It is labelled as a verification", script)
