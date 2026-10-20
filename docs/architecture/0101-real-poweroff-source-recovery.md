# 0101: Source recovery across actual disposable-VM poweroff

Extend the existing pristine Debian package test around its actual QEMU poweroff
and fresh boot. This adds a release acceptance witness, not a new runtime
privilege. Only the installed package and explicit test drivers enter the stock
guest; the product source tree and lab configuration remain absent.

Before shutdown the existing approved sandboxed RUN creates a small nonsecret
binary/text/executable fixture, owned by its task UID. The unprivileged task uses the Checkpoint
SDK and separate native TTY/PAM consent to capture and export the archive. The
Root observer then changes the live source bytes. A second checkpoint and explicit
restore approval produce an unused preboot restore grant. Only the Root-only,
fsynced private state file holds that grant; evidence contains no grants/passwords.

After the boot ID changes, both old and fresh task callers must be denied direct
old-source reads. The old unused restore grant must be revoked, unused and unable
to create an action. A fresh task with a different Unix UID captures its own
before state. A new protected approval view must identify the old source boot,
task, archive hash and same-human ownership. Cancel must leave approval pending;
new native PAM confirmation grants only that exact restoration. Approval itself
must not change files. The installed Restore SDK executes through the existing
unprivileged descriptor-relative runtime.

Independent observer checks compare every file's bytes/hash/executable bit and
the complete file/directory set, including deletion of the destination's old
file. Mutated original source stays mutated; restoration uses saved custody.
Completed replay must preserve a new post-restore edit. Existing old read-grant
revocation, native Stop, package ownership, disabled-provider and six raw GUI
capture contracts remain required.

The new witness is unaccepted until exact-head CI, the actual uploaded artifact
and all six fresh screenshots pass review. No physical-input/8GB, atomic whole
filesystem rollback, model disclosure, paid model execution or complete-version
claim follows from this bounded recovery test.
