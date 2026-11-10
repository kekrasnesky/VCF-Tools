# VCF-Tools

## vcf_diag — anonymized diagnostics for VCF 9.x

`vcf_diag.py` lets you get outside help with a VMware Cloud Foundation environment without
revealing what the environment is. It runs where your environment is (it needs no internet),
and everything it writes for sharing uses placeholders instead of hostnames, domains, IP
addresses and other identifiers. The table that maps placeholders back to real names never
leaves your machine.

It is one script with no dependencies beyond what macOS already has. Use it from a simple
window in your browser, or from the terminal.

### How the loop works

1. **Collect.** The tool logs in over SSH, runs read-only health and status checks and writes an
   anonymized Markdown report.
2. **Send.** You carry that file out and share it with the analyst (for example Claude). The
   report itself explains to the analyst how to answer.
3. **Reply.** The analyst answers using the placeholders. The answer can contain a plan with two
   kinds of steps: read-only diagnostics it would like to see next, and fixes it proposes.
4. **Translate.** You paste the answer into the tool. It shows the whole answer with your real
   names, and sorts the plan:
   - **Read-only diagnostics** are listed with the exact commands. If you agree, the tool runs
     them and writes an anonymized follow-up report. Back to step 2.
   - **Fixes are never run by the tool.** They are shown with real names, impact notes and a
     copy button, for you to review and apply by hand.

The tool only ever reads from your systems. Anything that changes them is done by you.

### Requirements

- macOS (or Linux) with Python 3.9 or newer. On a Mac, `python3` comes with the Xcode Command
  Line Tools (`xcode-select --install`) or Homebrew.
- The built-in OpenSSH client (`ssh`).
- SSH reachability from your Mac to the systems you want to check, and SSH enabled on them.

### Quick start (window)

Double-click `start-gui.command` in Finder, or run:

```bash
python3 vcf_diag.py --gui
```

A page opens in your browser:

1. Click **Edit inventory** and list your hosts under the matching sections (first time only).
2. Tick the groups to check and type the SSH username and password for each. Open
   **Choose hosts and checks** to narrow a group down.
3. Click **Run diagnostics** and watch the progress. If a login is rejected you are asked again
   before any other host is contacted.
4. When it finishes you see the privacy check, which real host became which placeholder, and a
   preview of the report, with **Copy report**, **Save a copy…** and **Show file**.

The **Analyst reply** tab is where the answer comes back in: paste it, click **Translate and
read plan**, apply the fixes by hand and, if you want, run the requested read-only diagnostics.
The **Anonymize text** tab scrubs anything else you paste (a log excerpt, an error message) with
the same placeholders.

The page is served by the script to your own Mac only (`127.0.0.1`, behind a random one-time
address). Nothing is uploaded anywhere. Leave the Terminal window that started it open; **Quit**
or Ctrl-C stops it.

### Quick start (terminal)

```bash
python3 vcf_diag.py --init
```

Edit the `inventory.ini` it creates and list your hosts under the matching sections. Then:

```bash
python3 vcf_diag.py
```

The script asks, in order:

1. which component groups to include,
2. which hosts in each group,
3. which diagnostics to run on them,
4. the SSH username and password for each group (hidden input).

It then collects, anonymizes, and prints where the report is. Skim the report, then share
`vcf-diag-output/vcf-report-<timestamp>.md`.

Useful variations:

```bash
python3 vcf_diag.py --dry-run
```

```bash
python3 vcf_diag.py --all
```

```bash
python3 vcf_diag.py --list
```

`--dry-run` shows the plan without contacting anything, `--all` skips the menus (passwords are
still asked), `--list` prints every check and the exact command behind it.

### What it can talk to

| Inventory section | Component | Default user | Notes |
|---|---|---|---|
| `[esxi]` | ESXi hosts | `root` | version, hardware, services, NTP, storage, networking, vSAN, NSX agent |
| `[vcenter]` | vCenter Server | `root` | works with the bash shell or the default appliance shell (the script runs `shell` itself) |
| `[nsx]` | NSX Manager | `admin` | `admin` runs NSX CLI checks; `root` adds OS-level checks |
| `[nsxedge]` | NSX Edge | `admin` | same model as NSX Manager |
| `[sddc]` | SDDC Manager | `vcf` | add `escalate = su` to also run the checks that need root |
| `[k8s]` | Kubernetes control-plane nodes: VCF services runtime, Operations, Automation, Supervisor | `vmware-system-user` | finds a working `kubectl` on its own (plain, `KUBECONFIG=/etc/kubernetes/admin.conf`, with `sudo`) |
| `[linux]` | any other Linux appliance | `root` | generic OS health |

A section name may carry a label, for example `[esxi:mgmt]`, `[esxi:wld01]`, `[k8s:runtime]`,
`[k8s:automation]`. Each labelled section is offered separately in the menu and has its own
credentials. The label shows up in placeholders (`esxi-mgmt-01`), so pick labels you are happy to
share.

You can add your own read-only commands per component type:

```ini
[commands:esxi]
Advanced settings changed from default = esxcli system settings advanced list -d
```

### What is anonymized

| In the report | Stands for |
|---|---|
| `esxi-01`, `vcenter-01`, `nsxmgr-01`, `k8snode-runtime-01` | a host from the inventory |
| `host-0001`, `exthost-0001` | other hosts (inside / outside your DNS domains) |
| `domain-01` | a DNS domain; `esxi-01.domain-01` is an FQDN |
| `ip-n3-h7` | IPv4 address: 7th address seen in the 3rd distinct /24. Hosts in the same subnet keep the same `n` |
| `ip6-0001`, `mac-0001`, `wwn-0001`, `uuid-0001`, `serial-0001`, `thumbprint-0001`, `license-0001`, `naa.device-0001`, `iqn-0001` | addresses and hardware/software identifiers |
| `datastore-0001`, `portgroup-0001`, `dvs-0001`, `lrouter-0001`, `ns-0001`, `k8sobj-0001`, `dn-0001`, `term-0001` | object names, certificate name parts, your own scrub terms |
| `[REDACTED]` | passwords, tokens, keys, certificate bodies |

The same real value always gets the same placeholder, also in later runs, so reports can be
compared over time. Product names that matter for diagnosis stay readable: version numbers,
service and pod names, product namespaces such as `prelude` or `kube-system`, `vsphere.local`,
netmasks, loopback addresses.

Things the tool cannot know by itself go in `[settings]`:

```ini
[settings]
extra_domains   = corp.example.com
scrub_terms     = Example Corp, DAL-01, Project Falcon
keep_literals   = 9.1.1.0
keep_namespaces = my-product-namespace
```

- `scrub_terms`: company name, site codes, project names — any word that identifies you.
- `keep_literals`: four-part version numbers that would otherwise look like an IP address.

After every run the script checks the finished report for every real name and address it knows
and prints a warning if one is still there. It also lists dotted values it left readable as
version numbers so you can confirm none is an address.

Anonymization is pattern based. It is thorough, not infallible: free text can contain an
identifying word the tool has never seen. **Read the report before you send it.**

### Privacy and credentials

- Passwords are typed at a hidden prompt (or a password field in the window) and held in
  memory only. They are passed to `ssh` through a private socket; they are not written to disk,
  to the command line or to environment variables. In the window they travel only between your
  browser and the script on the same Mac, and the fields are cleared when the run starts. If
  your browser offers to save them, decline.
- Each host gets one login attempt. The first host of a group is tried alone, so a mistyped
  password costs one failed login on one host rather than one on every host. If it is rejected
  you are asked again before anything else is contacted.
- Raw command output exists only in memory. Only anonymized text is written.
- `vcf-diag-private/mapping.json` maps placeholders to real names. It is created with owner-only
  permissions. **Never share that directory.** `inventory.ini`, the private directory and the
  output directory are in `.gitignore`.
- Every built-in check is read-only, and so is everything the tool runs from an analyst reply.
  Nothing is restarted or changed on the targets by the tool. Proposed fixes are only displayed. Checks have a time
  limit, enforced on the remote side as well where the appliance supports it.
- Host keys are trusted on first use and written to your normal `~/.ssh/known_hosts`. Use
  `--strict-host-keys` to connect only to hosts you have already accepted.

### Working with the reply

In the window, use the **Analyst reply** tab. In the terminal, save the reply to a file and run:

```bash
python3 vcf_diag.py --plan reply.txt
```

It prints the fixes with your real names (they are not run), lists the read-only diagnostics
that were requested, and asks whether to run those. The result is a
`vcf-diag-output/vcf-followup-<timestamp>.md` to send back.

How requested diagnostics are kept read-only:

- You see every command, with the real host, before anything runs.
- Each command is checked first. One that looks as if it changes something (deleting or writing
  files, restarting services, `esxcli ... set`, `kubectl delete`, and so on) or that would print
  secrets is refused and moved to the by-hand list with the reason.
- That check is a safety net based on patterns, not a guarantee. Your reading of the list is
  the real control.

Follow-up output is usually log text, which is less predictable than status output. Skim a
follow-up report more carefully than a health report before sending it.

To only translate a text, without reading it as a plan:

```bash
python3 vcf_diag.py --decode analysis.txt
```

Anonymize any other text file (a log excerpt, a support message) with the same mapping:

```bash
python3 vcf_diag.py --scrub-file vpxd-excerpt.log
```

### Options

```text
    --gui                open the window in your browser
    --no-browser         with --gui: print the address instead of opening it
-i, --inventory FILE     inventory file (default ./inventory.ini)
-o, --output-dir DIR     where reports go (default ./vcf-diag-output)
    --private-dir DIR    where the private mapping lives (default ./vcf-diag-private)
    --init               write a template inventory
    --list               list all checks
    --all                select everything, no menus
    --dry-run            show the plan only
    --parallel N         hosts contacted at once (default 4)
    --connect-timeout S  SSH connect timeout (default 15)
    --timeout-scale X    multiply all command time limits
    --max-lines N        output lines kept per check (default 200)
    --strict-host-keys   refuse hosts not already in known_hosts
    --plan FILE          read an analyst reply: show fixes (never run), offer read-only follow-ups
    --scrub-file FILE..  anonymize existing text files
    --decode FILE        translate placeholders back (local only)
    --self-test          test the anonymizer
```

### Troubleshooting

| Symptom | What to do |
|---|---|
| `authentication failed` | Wrong user or password, or SSH password login is disabled on the target. |
| `the server asked for a password change` | The account's password has expired on that appliance. |
| `SSH host key not trusted or changed` | The host was rebuilt. Remove its old entry: `ssh-keygen -R <host>`. |
| vCenter: `login shell is not bash` | The script could not start `shell` from the appliance shell. Check that shell access is enabled for the user. |
| `[k8s]`: `kubectl access could not be established` | Set `kubeconfig = /path` and/or `sudo = yes` in the section, or log in as a user who can run `kubectl`. |
| A namespace shows as `ns-0001` but is a product namespace | Add it to `keep_namespaces`. |
| A version shows as `ip-n…` | Add it to `keep_literals`. |
| Hosts behind a jump host | Configure `ProxyJump` with key authentication in `~/.ssh/config`; the script only answers the target's password prompt. |

### Status and limits

- The collection engine, all login paths (plain shell, vCenter appliance shell, NSX CLI, `sudo`,
  `su`), the window and the anonymizer are tested against a local SSH test rig, in a headless
  Chromium browser and by the unit tests in `tests/`. The window has not been tried in Safari
  on a Mac yet. The check commands themselves have not yet been run against a live VCF 9.1.1
  system. Expect a few checks to need adjusting on the first real run; a failing check is
  recorded in the report and never stops the collection.
- The first report covers health and status only. Logs are fetched on request, through the
  read-only diagnostics in an analyst reply. No support bundles.
- A proposed fix is based on anonymized data and can be wrong. Review it like any change to a
  production system before you apply it.

### Tests

```bash
python3 -m unittest discover -s tests -v
```
