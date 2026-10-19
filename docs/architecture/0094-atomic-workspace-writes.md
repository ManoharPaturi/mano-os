# Approved direct workspace writes

`files.write(path,text)` now executes after an exact bounded grant and durable
executing transition. UTF-8 input is at most32KiB. A retained parent FD fixes the
authorized directory; the leaf comes from the approved canonical relative path.
An absent-at-prepare leaf uses kernel RENAME_NOREPLACE. Existing-at-prepare writes
authorize replacement of that directory slot, including if its entry changes.
They do not authorize modification of the old inode's other aliases.

This deliberately supersedes ADR0017's proposed existing-inode write policy.
In-place truncation would modify hardlinked aliases, and a userspace inode check
plus exchange/rollback cannot provide an atomic inode-conditional rename. Atomic
publication can replace a raced symlink/hardlink entry without following it or
modifying the external linked inode. An initial symlink, hardlink or special file
still fails the original strict preparation. Parent-name replacement cannot
redirect publication away from the retained directory object.

After executing is committed, create/open `.mano-write-staging` within that pinned
parent. Require a real broker-owned0700 directory and matching task primary GID.
Its FD remains bound if the task renames the directory. Stage at a broker-issued
hex action name with fixed O_EXCL/NOFOLLOW/CLOEXEC flags. A native create briefly
sets fixed0007 umask and restores it before returning; the broker must be single-
threaded. This avoids chmod/chown or service-filter exceptions. Source content
is inaccessible to tasks inside the private directory; after publication fixed
0660/task-group ownership lets the task read/edit ordinary project files. Default
workspace ACLs retain the human/broker access contract.

Write/fsync the bounded private inode, observe Stop and grant expiry/profile,
then renameat2 from the private source directory to the pinned parent/leaf.
Fsync both directories. Observe Stop again before saving metadata and done.
Partial staging never truncates the destination. Lost/interrupted publication or
post-publication authority loss remains unknown with no blind retry or rollback.
Old same-key proposals cannot acquire new descriptors or publish again.

The database reserves at most64 lifetime write attempts before allocating staging.
Pending/unknown attempts consume capacity too. Private unpublished staging files
are unlinked only through their private directory FD. Empty reserved directories
are retained because their public name may have been replaced; at most64 new
staging directories can be created by those attempts. READ/WRITE schemas reject
the reserved component. No global account, root path or helper capability is added.

`file_write_result` and SDK return historical publication metadata: approved byte
hash/size, parent-selected path, published inode/device and create/replace-slot
operation. It explicitly leaves current-content and independent effect verification
false. A later file change does not alter this receipt. A separate READ and trusted
verification are needed for current bytes. Typed core write planning/test-fix loops
are subsequent integration; no model disclosure or full Phase2 completion is claimed.

Kernel basis: https://man7.org/linux/man-pages/man2/rename.2.html and
https://man7.org/linux/man-pages/man2/open.2.html. Native/registry tests cover real
pinned-parent rename, staged publication, symlink/hardlink swaps, no-replace races,
Stop before/after effects, historical receipts and caller/boot scope. Installed CI
adds actual PAM/allocated-task SDK create, replace, empty content, task-readable
permissions and unchanged replay canaries. Hardware and signed-release gates remain.
