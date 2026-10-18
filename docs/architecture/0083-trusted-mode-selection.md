# Human terminal mode selection and active authority status

The installed Linux human can request a profile for the request ID shown by the
prompt UI, using the existing protected native adapter. Example from a human TTY:

```sh
PYTHONPATH=/usr/lib/mano-os python3 -m mano_prompt.mode PROMPT_ID auto --duration 60 --max-actions 4 --max-timeout 10
PYTHONPATH=/usr/lib/mano-os python3 -m mano_prompt.mode PROMPT_ID --status
```

These are prototype installed-runtime commands, not Mac commands or evidence of a
packaged release. Mode selection first prints an idempotency request key. If the
acknowledgement is uncertain, reuse it with --request-key and the same arguments;
there is no automatic retry. Changing arguments under the same key denies. An
already approved reply reports historical approval and directs the human to status;
it does not claim the lease is still effective.

Native operation08 is exactly72 bytes: version/op, prompt ID32, request key32,
mode byte, duration u16be, count byte, timeout u16be. The Root adapter authenticates
the configured human's kernel credentials, validates fields/bounds and forwards
only those fixed fields plus its own human UID. Root broker control derives the
task/caller/resource from the human-owned current-boot prompt. An unallocated task,
wrong human/boot, unexpected selector, malformed packet or invalid bound denies.
The request creates only an exact pending policy.set_profile challenge.

The client then retrieves the existing protected approval view. Human UID,
approval ID, task, capability, arguments and compiled scope must match before a
password is requested. The human sees broker-owned terms and explicitly confirms;
only the existing native PAM confirmation activates a lease. Cancel, wrong password
or inability to disable echo activates nothing. Approval/rearm client compatibility
is retained; its reused review function now rejects non-echo fallback. Password
packet bytes are cleared after transport; Python string zeroization is not claimed.
Passwords are never accepted in CLI arguments or environment variables.

Native operation09 is a34-byte read-only permission status query. It returns the
owned prompt/task, recorded mode, whether automatic grants are currently available,
remaining count/time for new grants, timeout and fixed scope. Exhausting a count
does not cancel grants already issued or running work; the CLI states this and
directs the human to independent Stop for revocation. Revoked/expired/exhausted/recovered
leases report automatic=false and zero remaining count/time even if a historical
approval still says approved. It exposes no grant ID, nonce, password or key. It
cannot create, renew, approve or rearm authority. Caller identity, boot and task
selectors cannot be provided by the human packet. Existing operations remain.

Unit tests cover scope/identity rejection, pending-only/idempotent requests,
argument conflicts, read-only effective status/recovery, exact wire/ack binding,
no retry, piped-input rejection, mismatch-before-password, cancel and echo failure.
The guarded VM must exercise the actual CLI under the human UID with a controlling
PTY: cancel, wrong password, same-key retry, successful PAM, no echo and status.
Wrong-role/malformed native requests must deny. This is synthetic terminal input,
not a physical keyboard acceptance claim.

The VM also adds an active lease at the existing broker SIGKILL/restart point.
Before and after restart, lease/grant expiry must still be in the future; the
recovered lease must be exhausted/revoked, old automatic grant denied, new request
pending and old profile approval replay denied. Stop testing now checks a fresh
unused/unrevoked profile grant immediately before Stop, then rejects it after PAM
rearm and checks the revoked record. No authority is silently restored or resource
rebound. Required flags: installed_active_profile_lease_restart_revoked,
human_mode_tty_cancel_wrong_password_retry_and_status,
live_profile_grant_stop_rearm_no_resurrection.

Broader host-data/network scopes, GUI permission management, physical provenance,
live model acceptance, runtime packaging and the original release gates remain.
