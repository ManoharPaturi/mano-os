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

## Prototype human permission command

On an installed Debian prototype, the configured human can use their terminal to
review a workspace profile for a request ID from the prompt UI:

```sh
PYTHONPATH=/usr/lib/mano-os python3 -m mano_prompt.mode PROMPT_ID auto --duration 60 --max-actions 4 --max-timeout 10
PYTHONPATH=/usr/lib/mano-os python3 -m mano_prompt.mode PROMPT_ID --status
```

Review the broker-owned scope before confirming and entering the OS password.
Cancel makes no new profile active. Keep the printed request key after an uncertain
acknowledgement; explicitly retry with --request-key KEY and identical arguments.
The command never retries automatically. Status shows availability for new automatic grants;
a historical approval is insufficient. Issued grants and running work may remain
when a count is exhausted; use independent Stop to revoke them. Full Access remains workspace-only in this
prototype, with no additional host data, network, credentials or privilege. These
commands require the installed Linux human TTY; they are not runnable on this Mac.
See architecture/0083-trusted-mode-selection.md for protocol and acceptance limits.

## Prompt permission management

Once Check request status shows a provisioned task, open Permissions to inspect
availability for new automatic grants and propose a bounded mode. Selecting a mode
or requesting review does not activate it. The pending approval ID and fixed
terminal-review command are shown; review the exact broker-owned terms and complete
PAM only in your trusted human terminal. The window never asks for your password.
Refresh permissions after terminal approval. An old approval does not prove current
authority. Keep the same limits when explicitly retrying an uncertain request.
Closing the window leaves any server-side pending challenge to expire; it does not
approve or revoke it. Independent Stop revokes authority and running work.

## Independent human Stop

On the installed Debian prototype, run `/usr/libexec/mano-stop` from the configured
human account. Super+Shift+Backspace in the human Sway session requests the same fixed
native operation independently of GTK and the Python core. Use the terminal command
to see its acknowledgement; the shortcut's output is logged by the compositor.
A successful reply means new work is latched off and task termination was requested.
It is not a task-completion or independently verified process-exit claim. If no reply
is acknowledged, use the trusted recovery terminal. Rearm still requires separate
protected-terminal PAM authentication, and never revives old grants. Physical key
validation remains deferred while development uses CI VMs.
