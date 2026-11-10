# VCF-Tools

## vcf_diag — anonymized health collector for VCF 9.x

`vcf_diag.py` logs in to the parts of a VMware Cloud Foundation environment over SSH, runs
read-only health and status checks, and writes one Markdown report in which hostnames, domains,
IP addresses and other identifiers are replaced by consistent placeholders. The report is meant
to be shared for analysis; the table that maps placeholders back to real names never leaves
your machine.

It is one script with no dependencies beyond what macOS already has.

### Requirements

- macOS (or Linux) with Python 3.9 or newer. On a Mac, `python3` comes with the Xcode Command
  Line Tools (`xcode-select --install`) or Homebrew.
- The built-in OpenSSH client (`ssh`).
- SSH reachability from your Mac to the systems you want to check, and SSH enabled on them.

### Quick start

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

- Passwords are typed at a hidden prompt and held in memory only. They are passed to `ssh`
  through a private socket; they are not written to disk, to the command line or to environment
  variables.
- Each host gets one login attempt. The first host of a group is tried alone, so a mistyped
  password costs one failed login on one host rather than one on every host. If it is rejected
  you are asked again before anything else is contacted.
- Raw command output exists only in memory. Only anonymized text is written.
- `vcf-diag-private/mapping.json` maps placeholders to real names. It is created with owner-only
  permissions. **Never share that directory.** `inventory.ini`, the private directory and the
  output directory are in `.gitignore`.
- Every check is read-only. Nothing is restarted or changed on the targets. Checks have a time
  limit, enforced on the remote side as well where the appliance supports it.
- Host keys are trusted on first use and written to your normal `~/.ssh/known_hosts`. Use
  `--strict-host-keys` to connect only to hosts you have already accepted.

### Working with the analysis

Translate placeholders in a reply back to real names, locally:

```bash
python3 vcf_diag.py --decode analysis.txt
```

Anonymize any other text file (a log excerpt, a support message) with the same mapping:

```bash
python3 vcf_diag.py --scrub-file vpxd-excerpt.log
```

### Options

```text
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
  `su`) and the anonymizer are tested against a local SSH test rig and by the unit tests in
  `tests/`. The check commands themselves have not yet been run against a live VCF 9.1.1
  system. Expect a few checks to need adjusting on the first real run; a failing check is
  recorded in the report and never stops the collection.
- Scope is health and status. No log collection, no support bundles.

### Tests

```bash
python3 -m unittest discover -s tests -v
```
