#!/usr/bin/env python3
"""nsx_tz_check: find, and optionally repair, NSX transport node profiles that point to a
transport zone that no longer exists.

Background: SDDC Manager fails with
    ERROR_IN_GETTING_TNP_FROM_TNC  Error in reading transport node Profile from transport node collection
    Caused by: java.util.NoSuchElementException: No transport zone found for given path
               /infra/sites/default/enforcement-points/default/transport-zones/<id>
when a cluster's transport node collection (TNC) uses a host transport node profile (TNP) whose
host switch lists a transport zone that NSX no longer has.

What this script does
  Check (default, read-only):
    - reads every transport zone, host transport node profile, transport node collection,
      segment and host transport node from each NSX Manager you name
    - reports every reference to a transport zone that does not exist, and every collection
      that points to a profile that does not exist, with the vCenter cluster it affects
    - optionally (--sddc) lists failed SDDC Manager tasks that hit this error
  Fix (--fix, asks before every change):
    - writes a JSON backup of the profile, then removes the dangling transport zone entry from
      the profile, or replaces it with a transport zone you choose (--replace)
    - refuses when that could change networking: a segment still uses the missing zone, NSX's
      manager API still knows the zone, or the host switch would be left without any zone
    - waits for NSX to push the corrected profile to the cluster's hosts
  Retry (--retry-task, asks first): retries the failed SDDC Manager task once NSX is fixed.
  Restore (--restore FILE): puts a profile back exactly as it was in a backup file.

Python 3.9+, standard library only. Run it from any machine that reaches the NSX Manager (and
SDDC Manager) on port 443. Its output contains real names: it is for you, not for sharing.

Examples
  python3 nsx_tz_check.py --nsx nsx01.example.local
  python3 nsx_tz_check.py --nsx nsx01.example.local --nsx nsx-wld01.example.local \
      --sddc sddc01.example.local --sddc-user admin@local
  python3 nsx_tz_check.py --nsx nsx01.example.local --fix
  python3 nsx_tz_check.py --nsx nsx01.example.local --fix --replace <old-tz-id>=<new-tz-name>
  python3 nsx_tz_check.py --sddc sddc01.example.local --retry-task <task-id>
  python3 nsx_tz_check.py --nsx nsx01.example.local --restore tnp-backup-<id>-<time>.json

Passwords are prompted for, or read from NSX_PASSWORD / SDDC_PASSWORD.
Exit status: 0 nothing wrong found, 1 problems found (or a fix was refused), 2 error.
"""

import argparse
import base64
import copy
import datetime as dt
import getpass
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

POLICY = "/policy/api/v1"
DEFAULT_EP = "/infra/sites/default/enforcement-points/default"
SDDC_ERROR_MARKERS = ("ERROR_IN_GETTING_TNP_FROM_TNC", "No transport zone found",
                      "transport node Profile from transport node collection")


# --------------------------------------------------------------------------- HTTP

class ApiError(Exception):
    def __init__(self, status, method, path, body):
        super().__init__(f"{method} {path} -> HTTP {status}: {body}")
        self.status = status


class Api:
    def __init__(self, host, auth_header, ctx, timeout=60):
        self.host = host
        self.base = "https://" + host
        self.auth = auth_header
        self.ctx = ctx
        self.timeout = timeout

    def req(self, method, path, body=None):
        headers = {"Accept": "application/json"}
        if self.auth:
            headers["Authorization"] = self.auth
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, context=self.ctx, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            raise ApiError(e.code, method, path, e.read().decode(errors="replace")[:800]) from None
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise SystemExit(f"error: {self.host}: certificate not trusted ({reason.verify_message}). "
                                 "Use --ca-file with your CA bundle, or --insecure.")
            raise SystemExit(f"error: cannot reach {self.host}: {reason}")
        return json.loads(raw) if raw.strip() else {}

    def get(self, path):
        return self.req("GET", path)

    def list_all(self, path):
        """GET a paged NSX list and return all results."""
        results, cursor = [], None
        for _ in range(1000):
            p = path
            if cursor:
                p += ("&" if "?" in p else "?") + "cursor=" + urllib.parse.quote(cursor)
            page = self.get(p)
            batch = page.get("results") or []
            results.extend(batch)
            cursor = page.get("cursor")
            if not cursor or not batch:
                break
        return results


def basic_auth(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def ssl_context(args):
    if args.insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context(cafile=args.ca_file) if args.ca_file else ssl.create_default_context()


def password_for(env, prompt):
    return os.environ.get(env) or getpass.getpass(prompt)


def confirm(question, expected):
    print()
    answer = input(f"{question}\nType {expected!r} to continue, anything else to skip: ").strip()
    return answer == expected


# --------------------------------------------------------------------------- NSX inventory

def tz_endpoints(obj):
    """Yield (host_switch, endpoint) for every transport zone endpoint in a profile or host."""
    spec = obj.get("host_switch_spec") or {}
    for hs in spec.get("host_switches") or []:
        for ep in hs.get("transport_zone_endpoints") or []:
            yield hs, ep


def hs_name(hs):
    return hs.get("host_switch_name") or hs.get("host_switch_id") or "?"


def last_part(ref):
    return (ref or "").rstrip("/").rsplit("/", 1)[-1]


def collect(nsx, log=print):
    inv = {"host": nsx.host, "notes": []}
    try:
        eps = [ep["path"] for s in nsx.list_all(f"{POLICY}/infra/sites")
               for ep in nsx.list_all(f"{POLICY}{s['path']}/enforcement-points")]
    except ApiError as e:
        inv["notes"].append(f"could not list sites ({e.status}); using the default site only")
        eps = []
    inv["eps"] = eps or [DEFAULT_EP]

    inv["tzs"] = {}
    for ep in inv["eps"]:
        for tz in nsx.list_all(f"{POLICY}{ep}/transport-zones"):
            inv["tzs"][tz["path"]] = tz
    inv["tz_ids"] = {}
    for tz in inv["tzs"].values():
        for key in ("id", "unique_id", "realization_id"):
            if tz.get(key):
                inv["tz_ids"][tz[key]] = tz

    try:
        inv["mp_tzs"] = {t["id"]: t for t in nsx.list_all("/api/v1/transport-zones")}
    except ApiError as e:
        inv["mp_tzs"] = None
        inv["notes"].append(f"manager API transport zone list not available ({e.status}): "
                            "cannot confirm that a missing zone is really gone")

    inv["tnps"] = nsx.list_all(f"{POLICY}/infra/host-transport-node-profiles")
    inv["tncs"] = [t for ep in inv["eps"] for t in nsx.list_all(f"{POLICY}{ep}/transport-node-collections")]

    try:
        inv["segments"] = nsx.list_all(f"{POLICY}/infra/segments")
    except ApiError as e:
        inv["segments"] = []
        inv["notes"].append(f"could not list segments ({e.status})")
    try:
        inv["hosts"] = [h for ep in inv["eps"] for h in nsx.list_all(f"{POLICY}{ep}/host-transport-nodes")]
    except ApiError as e:
        inv["hosts"] = []
        inv["notes"].append(f"could not list host transport nodes ({e.status})")

    names = {}
    for tnc in inv["tncs"]:
        cc = tnc.get("compute_collection_id")
        if cc and cc not in names:
            try:
                names[cc] = nsx.get(f"/api/v1/fabric/compute-collections/{urllib.parse.quote(cc)}").get("display_name") or cc
            except ApiError:
                names[cc] = cc
    inv["cluster_names"] = names
    log(f"  {nsx.host}: {len(inv['tzs'])} transport zones, {len(inv['tnps'])} profiles, "
        f"{len(inv['tncs'])} collections, {len(inv['segments'])} segments, {len(inv['hosts'])} host nodes")
    return inv


def resolve(inv, ref):
    """Return (status, tz). status: ok, path-mismatch, manager-only, gone, missing-unverified."""
    if ref in inv["tzs"]:
        return "ok", inv["tzs"][ref]
    rid = last_part(ref)
    if rid in inv["tz_ids"]:
        tz = inv["tz_ids"][rid]
        return ("ok", tz) if not ref.startswith("/") else ("path-mismatch", tz)
    if inv["mp_tzs"] is None:
        return "missing-unverified", None
    if rid in inv["mp_tzs"]:
        return "manager-only", inv["mp_tzs"][rid]
    return "gone", None


def tnp_lookup(inv, ref):
    for tnp in inv["tnps"]:
        if ref in (tnp.get("path"), tnp.get("id"), tnp.get("unique_id")) or last_part(ref) == tnp.get("id"):
            return tnp
    return None


def clusters_using(inv, tnp):
    out = []
    for tnc in inv["tncs"]:
        ref = tnc.get("transport_node_profile_id")
        if ref and tnp_lookup(inv, ref) is tnp:
            out.append((tnc, inv["cluster_names"].get(tnc.get("compute_collection_id"), "?")))
    return out


def analyze(inv):
    f = {"tnp": [], "tnc": [], "segment": [], "host": []}
    for tnp in inv["tnps"]:
        for hs, ep in tz_endpoints(tnp):
            ref = ep.get("transport_zone_id", "")
            status, tz = resolve(inv, ref)
            if status != "ok":
                f["tnp"].append({"tnp": tnp, "hs": hs_name(hs), "ref": ref, "status": status, "tz": tz})
    for tnc in inv["tncs"]:
        ref = tnc.get("transport_node_profile_id")
        if ref and tnp_lookup(inv, ref) is None:
            f["tnc"].append({"tnc": tnc, "ref": ref,
                             "cluster": inv["cluster_names"].get(tnc.get("compute_collection_id"), "?")})
    for seg in inv["segments"]:
        ref = seg.get("transport_zone_path")
        if ref:
            status, tz = resolve(inv, ref)
            if status != "ok":
                f["segment"].append({"seg": seg, "ref": ref, "status": status})
    for host in inv["hosts"]:
        for hs, ep in tz_endpoints(host):
            ref = ep.get("transport_zone_id", "")
            status, _ = resolve(inv, ref)
            if status != "ok":
                f["host"].append({"host": host, "hs": hs_name(hs), "ref": ref, "status": status})
    return f


STATUS_TEXT = {
    "gone": "does not exist in NSX (policy or manager API)",
    "path-mismatch": "exists, but under a different path",
    "manager-only": "missing in the policy API but the manager API still has it (policy/manager out of sync)",
    "missing-unverified": "missing in the policy API (manager API not checked)",
}


def report(inv, f, search_ids):
    print(f"\n=== {inv['host']}")
    for note in inv["notes"]:
        print(f"  note: {note}")
    if not any(f.values()):
        print("  OK: every profile, collection, segment and host points to objects that exist.")
    for item in f["tnp"]:
        tnp = item["tnp"]
        print(f"\n  PROBLEM profile {tnp.get('display_name')!r} (id {tnp.get('id')})")
        print(f"    host switch {item['hs']!r} lists transport zone {item['ref']}")
        print(f"    -> {STATUS_TEXT[item['status']]}"
              + (f": {item['tz'].get('display_name')!r} {item['tz'].get('path', '')}" if item["tz"] else ""))
        users = clusters_using(inv, tnp)
        print("    used by clusters: " + (", ".join(name for _, name in users) or "none"))
        keep = [ep.get("transport_zone_id") for hs, ep in tz_endpoints(tnp)
                if hs_name(hs) == item["hs"] and ep.get("transport_zone_id") != item["ref"]]
        for ref in keep:
            status, tz = resolve(inv, ref)
            label = f"{tz.get('display_name')!r} ({tz.get('tz_type') or tz.get('transport_type', '')})" if tz else status
            print(f"    other zone on this host switch: {label} {ref}")
    for item in f["tnc"]:
        tnc = item["tnc"]
        label = tnc.get("display_name") or tnc.get("id") or tnc.get("path")
        print(f"\n  PROBLEM collection {label!r} for cluster {item['cluster']!r}")
        print(f"    points to profile {item['ref']}, which does not exist")
        print("    -> not repaired by this script: re-attach a valid profile to the cluster in NSX "
              "(System > Fabric > Hosts > Clusters > Configure NSX), then retry in SDDC Manager")
    for item in f["segment"]:
        seg = item["seg"]
        print(f"\n  PROBLEM segment {seg.get('display_name')!r} uses transport zone {item['ref']} "
              f"-> {STATUS_TEXT[item['status']]}")
    hosts = {}
    for item in f["host"]:
        hosts.setdefault(item["ref"], set()).add(item["host"].get("display_name") or item["host"].get("id"))
    for ref, names in hosts.items():
        print(f"\n  host nodes still listing missing zone {ref}: {len(names)} "
              f"({', '.join(sorted(names)[:8])}{' ...' if len(names) > 8 else ''})")
        print("    (they follow their profile: fixing the profile updates them)")
    for sid in search_ids:
        status, tz = resolve(inv, sid)
        print(f"\n  transport zone {sid}: {'exists: ' + repr(tz.get('display_name')) if status == 'ok' else STATUS_TEXT.get(status, status)}")
        for kind, objs in (("profile", inv["tnps"]), ("collection", inv["tncs"]),
                           ("segment", inv["segments"]), ("host node", inv["hosts"])):
            hits = [o.get("display_name") or o.get("id") for o in objs if sid in json.dumps(o)]
            if hits:
                print(f"    referenced by {kind}(s): {', '.join(map(str, hits[:10]))}")


# --------------------------------------------------------------------------- fix

class Refused(Exception):
    pass


def find_tz(inv, text):
    """Resolve a user-given transport zone (path, id or display name) to a policy object."""
    if text in inv["tzs"]:
        return inv["tzs"][text]
    if text in inv["tz_ids"]:
        return inv["tz_ids"][text]
    named = [tz for tz in inv["tzs"].values() if tz.get("display_name") == text]
    if len(named) == 1:
        return named[0]
    if len(named) > 1:
        raise Refused(f"more than one transport zone is named {text!r}; give its id instead")
    raise Refused(f"transport zone {text!r} not found on {inv['host']}")


def plan_fix(inv, f, tnp, replace, skip_mp_check):
    """Return (new_body, changes) for one profile, or raise Refused."""
    problems = [i for i in f["tnp"] if i["tnp"] is tnp]
    targets = {}
    for item in problems:
        ref, status = item["ref"], item["status"]
        if status == "manager-only":
            raise Refused(f"zone {ref} still exists in the NSX manager API: policy and manager are out of "
                          "sync. Do not edit the profile; open a support case with this output.")
        if status == "missing-unverified" and not skip_mp_check:
            raise Refused(f"cannot confirm zone {ref} is gone (manager API unavailable). "
                          "Re-run with --skip-manager-check only if you are sure it was deleted.")
        if any(s["ref"] == ref or last_part(s["ref"]) == last_part(ref) for s in f["segment"]):
            raise Refused(f"segments still use zone {ref}: removing it from the profile could cut "
                          "their traffic on these hosts. Fix the segments first.")
        new = None
        for old, wanted in replace.items():
            if old in (ref, last_part(ref)):
                new = find_tz(inv, wanted)["path"]
        if new is None and status == "path-mismatch":
            new = item["tz"]["path"]
        targets[ref] = new

    body = copy.deepcopy(tnp)
    changes = []
    for hs in (body.get("host_switch_spec") or {}).get("host_switches") or []:
        eps = hs.get("transport_zone_endpoints") or []
        present = {ep.get("transport_zone_id") for ep in eps}
        kept = []
        for ep in eps:
            ref = ep.get("transport_zone_id")
            if ref not in targets:
                kept.append(ep)
            elif targets[ref] and targets[ref] not in present:
                kept.append(dict(ep, transport_zone_id=targets[ref]))
                present.add(targets[ref])
                changes.append(f"host switch {hs_name(hs)!r}: replace {ref} -> {targets[ref]} "
                               f"({inv['tzs'][targets[ref]].get('display_name')!r})")
            else:
                changes.append(f"host switch {hs_name(hs)!r}: remove {ref}")
        if eps and not kept:
            raise Refused(f"host switch {hs_name(hs)!r} would be left without any transport zone. "
                          "Name the zone it should use: --replace <old-id>=<zone name or id>")
        hs["transport_zone_endpoints"] = kept
    return body, changes


def wait_for_clusters(nsx, inv, tnp, seconds):
    users = clusters_using(inv, tnp)
    if not users or seconds <= 0:
        return
    print(f"\n  Waiting up to {seconds}s for NSX to apply the profile to: {', '.join(n for _, n in users)}")
    deadline = time.time() + seconds
    pending = {tnc["path"]: name for tnc, name in users}
    while pending and time.time() < deadline:
        time.sleep(15)
        for path, name in list(pending.items()):
            try:
                st = nsx.get(f"{POLICY}{path}/state")
            except ApiError as e:
                print(f"    {name}: state not readable ({e.status})")
                pending.pop(path)
                continue
            state = st.get("state", "?")
            pct = st.get("aggregate_progress_percentage")
            print(f"    {name}: {state}" + (f" {pct}%" if pct is not None else ""))
            if state.upper() in ("SUCCESS", "FAILED", "FAILED_TO_REALIZE", "PARTIAL_SUCCESS"):
                pending.pop(path)
                if state.upper() != "SUCCESS":
                    errs = st.get("validation_errors") or st.get("cluster_level_error") or ""
                    print(f"      details: {json.dumps(errs)[:600]}")
    for name in pending.values():
        print(f"    {name}: still in progress; check NSX (System > Fabric > Hosts > Clusters)")


def fix(nsx, inv, f, args, replace):
    done = 0
    for tnp in {id(i["tnp"]): i["tnp"] for i in f["tnp"]}.values():
        name = tnp.get("display_name") or tnp.get("id")
        print(f"\n--- Fix for profile {name!r} on {inv['host']}")
        try:
            body, changes = plan_fix(inv, f, tnp, replace, args.skip_manager_check)
        except Refused as e:
            print(f"  REFUSED: {e}")
            continue
        users = clusters_using(inv, tnp)
        for c in changes:
            print(f"  change: {c}")
        print(f"  affects clusters: {', '.join(n for _, n in users) or 'none'}")
        print("  Impact: NSX re-applies the profile to every host in those clusters. Only the missing "
              "zone is taken out (or swapped), so traffic on existing segments is not expected to change.")
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = os.path.abspath(f"tnp-backup-{tnp.get('id')}-{stamp}.json")
        with open(backup, "w") as fh:
            json.dump({"nsx": inv["host"], "path": tnp["path"], "profile": tnp}, fh, indent=2)
        print(f"  backup written: {backup}")
        print(f"  rollback: python3 {sys.argv[0]} --nsx {inv['host']} --restore {backup}")
        if not confirm(f"Apply this change to profile {name!r}?", tnp.get("id")):
            print("  skipped")
            continue
        try:
            nsx.req("PUT", f"{POLICY}{tnp['path']}", body)
        except ApiError as e:
            print(f"  FAILED: {e}\n  Nothing was changed.")
            continue
        print("  profile updated")
        done += 1
        wait_for_clusters(nsx, inv, tnp, args.wait)
    return done


def restore(nsx, path):
    with open(path) as fh:
        saved = json.load(fh)
    body = saved["profile"]
    current = nsx.get(f"{POLICY}{saved['path']}")
    print(f"Restore profile {body.get('display_name')!r} on {nsx.host} from {path}")
    if not confirm("Put the profile back exactly as in the backup?", body.get("id")):
        return 1
    body = dict(body, _revision=current.get("_revision"))
    nsx.req("PUT", f"{POLICY}{saved['path']}", body)
    print("restored")
    return 0


# --------------------------------------------------------------------------- SDDC Manager

def sddc_login(host, user, ctx):
    api = Api(host, None, ctx)
    try:
        tok = api.req("POST", "/v1/tokens", {"username": user,
                                             "password": password_for("SDDC_PASSWORD", f"Password for {user}@{host}: ")})
    except ApiError as e:
        raise SystemExit(f"error: SDDC Manager login failed for {user} (HTTP {e.status}). "
                         "Use an account with the ADMIN role, e.g. administrator@vsphere.local or admin@local.")
    api.auth = "Bearer " + tok["accessToken"]
    return api


def first_error(task):
    stack = [task]
    while stack:
        t = stack.pop()
        for err in t.get("errors") or []:
            return err
        stack.extend(t.get("subTasks") or [])
    return {}


def sddc_tasks(api, days):
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    found = []
    for page in range(1, 11):
        data = api.get(f"/v1/tasks?pageNumber={page}&pageSize=100")
        elements = data.get("elements") or []
        for t in elements:
            if str(t.get("status", "")).upper() != "FAILED":
                continue
            try:
                created = dt.datetime.fromisoformat(str(t.get("creationTimestamp", "")).replace("Z", "+00:00"))
                if created.tzinfo is None:
                    created = created.replace(tzinfo=dt.timezone.utc)
                if created < cutoff:
                    continue
            except ValueError:
                pass
            detail = api.get(f"/v1/tasks/{t['id']}")
            if any(m in json.dumps(detail) for m in SDDC_ERROR_MARKERS):
                found.append(detail)
        if len(elements) < 100:
            break
    print(f"\n=== SDDC Manager {api.host}: failed tasks in the last {days} days with this error: {len(found)}")
    for t in found:
        err = first_error(t)
        res = ", ".join(f"{r.get('type')} {r.get('name') or r.get('resourceId')}" for r in t.get("resources") or [])
        print(f"  task {t.get('id')}  {t.get('name')!r}  created {t.get('creationTimestamp')}")
        if res:
            print(f"    resources: {res}")
        if err:
            print(f"    error {err.get('errorCode')}: {str(err.get('message'))[:300]}  "
                  f"(reference token {err.get('referenceToken')})")
        print(f"    retry once NSX is fixed: python3 {sys.argv[0]} --sddc {api.host} --retry-task {t.get('id')}")
    return found


def retry_task(api, task_id):
    t = api.get(f"/v1/tasks/{task_id}")
    print(f"Task {task_id}: {t.get('name')!r}, status {t.get('status')}")
    if not confirm("Retry this task in SDDC Manager?", "retry"):
        return 1
    api.req("PATCH", f"/v1/tasks/{task_id}")
    print("retry started; follow it in SDDC Manager (Tasks)")
    return 0


# --------------------------------------------------------------------------- main

def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog="See the top of the script for details and examples.")
    p.add_argument("--nsx", action="append", default=[], metavar="HOST",
                   help="NSX Manager (VIP or node) FQDN; repeat for each NSX instance")
    p.add_argument("--nsx-user", default="admin")
    p.add_argument("--sddc", metavar="HOST", help="SDDC Manager FQDN, to list failed tasks with this error")
    p.add_argument("--sddc-user", default="administrator@vsphere.local")
    p.add_argument("--days", type=int, default=14, help="how far back to look for failed tasks (default 14)")
    p.add_argument("--tz-id", action="append", default=[], metavar="ID",
                   help="also show where this transport zone id is referenced")
    p.add_argument("--fix", action="store_true", help="offer to repair each broken profile (asks first)")
    p.add_argument("--replace", action="append", default=[], metavar="OLD=NEW",
                   help="with --fix: replace missing zone OLD (id or path) with zone NEW (name, id or path)")
    p.add_argument("--skip-manager-check", action="store_true",
                   help="with --fix: allow repair when the NSX manager API cannot be read")
    p.add_argument("--wait", type=int, default=600, help="seconds to wait for NSX after a fix (default 600)")
    p.add_argument("--retry-task", metavar="TASK_ID", help="retry a failed SDDC Manager task (needs --sddc)")
    p.add_argument("--restore", metavar="BACKUP_JSON", help="restore a profile from a backup (needs one --nsx)")
    p.add_argument("--ca-file", help="CA bundle to trust for NSX / SDDC Manager certificates")
    p.add_argument("--insecure", action="store_true", help="do not verify certificates")
    args = p.parse_args(argv)
    if not args.nsx and not args.sddc:
        p.error("give at least one --nsx or --sddc")
    if args.retry_task and not args.sddc:
        p.error("--retry-task needs --sddc")
    if args.restore and len(args.nsx) != 1:
        p.error("--restore needs exactly one --nsx")
    return args


def main(argv=None):
    args = parse_args(argv)
    ctx = ssl_context(args)
    replace = {}
    for item in args.replace:
        if "=" not in item:
            raise SystemExit(f"error: --replace needs OLD=NEW, got {item!r}")
        old, new = item.split("=", 1)
        replace[old.strip()] = new.strip()

    if args.retry_task:
        return retry_task(sddc_login(args.sddc, args.sddc_user, ctx), args.retry_task)

    apis = []
    for host in args.nsx:
        apis.append(Api(host, basic_auth(args.nsx_user, password_for(
            "NSX_PASSWORD", f"Password for {args.nsx_user}@{host}: ")), ctx))
    if args.restore:
        return restore(apis[0], args.restore)

    problems = 0
    if apis:
        print("Reading NSX inventory ...")
    for nsx in apis:
        try:
            inv = collect(nsx)
        except ApiError as e:
            print(f"error: {nsx.host}: {e}", file=sys.stderr)
            if e.status in (401, 403):
                print("  check the user and password (and that the account is not locked)", file=sys.stderr)
            return 2
        f = analyze(inv)
        report(inv, f, args.tz_id)
        problems += sum(len(v) for v in f.values())
        if args.fix and f["tnp"]:
            fixed = fix(nsx, inv, f, args, replace)
            if fixed:
                print("\n  Re-checking ...")
                f2 = analyze(collect(nsx))
                left = len(f2["tnp"]) + len(f2["tnc"])
                print("  OK: no broken profiles or collections left." if not left
                      else f"  {left} problem(s) remain; run the check again for details.")
                problems = problems - sum(len(v) for v in f.values()) + sum(len(v) for v in f2.values())
        elif f["tnp"]:
            print("\n  To repair: run again with --fix (you are asked before anything changes).")

    if args.sddc:
        found = sddc_tasks(sddc_login(args.sddc, args.sddc_user, ctx), args.days)
        if not problems and found:
            print("  NSX looks consistent now: if these tasks ran before the fix, retry them.")

    if apis and not problems:
        print("\nNo dangling references found in NSX. If SDDC Manager still fails, the zone it looks for "
              "may belong to an NSX instance not checked here (add every --nsx), or SDDC Manager's "
              "inventory is stale: open a support case with the task's reference token.")
    return 1 if problems else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
