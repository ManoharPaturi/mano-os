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

The VM has 4 GiB RAM, two vCPUs, 12 GiB sparse bootstrap, 2 GiB btrfs data and 8 GiB btrfs root disks.
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

## Prototype Debian runtime package

The package targets Debian13 amd64 and Python3.13. Build only in the Linux CI guest
or a matching build environment; the builder refuses this Mac. Build dependencies
include gcc, libc6-dev, libpam0g-dev, libjson-c-dev, libsystemd-dev, libseccomp-dev,
pkg-config, python3-pip and dpkg. Download binary wheels with the committed hashes,
then build offline:

```sh
python3 -m pip download --only-binary=:all: --require-hashes -r packaging/runtime/requirements.lock -d wheelhouse
python3 scripts/build_runtime_deb.py --wheelhouse wheelhouse --output dist
```

On a disposable Debian test installation, install the generated unsigned prototype
with `sudo apt install ./mano-runtime_0.1.0~prototype2_amd64.deb`. Installation creates
locked service accounts and fixed directories; it starts no runtime service, ships
no API key, and leaves provider/model/pricing/controller/egress defaults disabled.
Existing manual runtime files require explicit operator reconciliation first.

From the trusted Root terminal, run `mano-runtime-setup EXISTING_LOGIN --enable`
to enroll the existing human and explicitly enable/start the fixed runtime target.
Use `--start` for this boot only, or omit both flags to enroll without activation.
Log out and back in for group membership. Select the optional "mano prototype"
Wayland session or run `sway -c /usr/share/mano-runtime/human-sway.conf` from a fresh
human session with its own D-Bus/runtime environment. The original desktop default
is not changed. The controller timer and paid model configuration remain separate.

The package includes `mano-prompt`, `mano-mode`, `mano-approve`, Root `mano-task`
and `mano-core-step`, and `/usr/libexec/mano-stop`. Human prompt submission is intent;
it does not itself provision a task or approve execution. Root task provisioning
and trusted human PAM review remain required. The accepted package witness uses an
explicit deterministic mock plan; it is not live AI/provider execution.

Reinstall/upgrade stops the runtime and latches Stop when it is active; it does not
silently restart or rearm. Start explicitly after reviewing the preserved Root
configuration, then use the separate authenticated rearm procedure if appropriate.
Removal disables/stops the runtime and removes its code while retaining generated
human policy, credentials, workspaces and journal data. No package removal script
deletes those data or recycles task identities. Signed distribution, cross-version
migration, full workflow/release and physical installation gates remain unfinished.

## Clean Debian package/reboot CI witness

The additional CI stage boots a separate untouched Debian13 image, installs the
prototype with apt and no recommendations, and enrolls the existing ordinary CI
login. Only the .deb and explicit private test scripts enter that VM. Driver-only
python3-pyatspi is installed separately after runtime dependency resolution.
The packaged Sway config and prompt wrapper run unchanged, without an app observer
or Python-path override. The stage checks actual GUI/PAM/mock task behavior, powers
off, boots again, and requires automatic runtime-target activation and denial of an
old, still-unexpired unused grant while task data persist. It then checks a fresh
postboot workflow and native human Stop. Physical input, login-manager integration,
hardware performance and the full original distribution gates remain separate.
