# Development operations

## Reproduce safely

Use local Python unit tests for evidence, disk and merge contracts. Use GitHub
Actions `CI` for real Linux probes. Workflow dispatch also runs the lab. Only an
explicit disposable CI runner should set `MANO_DISPOSABLE_CI=1`.

The lab downloads Debian's current genericcloud image via HTTPS, checks its
SHA512 manifest, and stores that manifest in evidence. This detects download
corruption; the manifest is retrieved from the same trusted HTTPS origin and is
not yet a separately signature-verified release provenance chain.
APT security updates remain enabled; installed versions are recorded. Require
bubblewrap >= 0.12.0-1~deb13u1 and xdg-dbus-proxy >= 0.1.6-1+deb13u3 on Debian 13.
Never downgrade these floors for a green test.

The VM has 4 GiB RAM, two vCPUs, 12 GiB sparse bootstrap, 2 GiB btrfs data and 6 GiB btrfs root disks.
After preparation, a second boot uses the installed Debian kernel/initrd and real
btrfs root; the bootstrap disk is read-only and hash-checked.
SSH is key-only, forwarded on runner loopback; keys never leave the runner.
Only `git archive HEAD` enters the guest, not the runner home or CI secrets.
The VM is killed on script exit. Evidence artifacts expire after seven days.
No image or private SSH key is uploaded.

## Storage

`PYTHONPATH=src python3 -m mano_lab.cli disk .` reports disk capacity. Warn when
free space is below 20 GiB or usage is >=90 percent. Refuse new large downloads
below 10 GiB. The VM launcher checks its runner filesystem before downloads.
The assistant also checks the Mac between implementation chunks. These are active
work checks; no background automation or deletion is silently installed.

## Merges

Only main's seed specification was pushed directly to establish the empty repo.
All implementation uses PRs. Run `python3 scripts/merge_checked.py PR_URL` after
checks settle. It requires every check to succeed, all required checks to exist,
an up-to-date mergeable PR, and a matching current head. No admin bypass.

## Rollback

Revert implementation through a new tested PR. The guest is disposable; do not
reuse its disk outside the lab. No runtime services are installed on the Mac.
