# 0096: Optional pinned coding delegates in immutable task homes

Antigravity 1.4.2 and Codex 0.163.0 use the existing approved public PTY
capability through a common start/stream/stop/result interface. Fixed argv shapes
exclude configuration overrides and permission bypass flags; prompt/model values
cannot become options. Delegate events and diagnostics are untrusted observations.
Exit zero or a successful model turn never establishes independent verification.
Malformed, partial and duplicate terminal events cannot establish success; recorded
soft-denial fixtures remain denied even when the process exits zero.

The normal unprivileged launcher creates a sealed memfd configuration and mounts
an otherwise read-only synthetic home. Only explicit volatile cache/log directories
are writable. Existing native guard, resource pins, approval, cgroup, Stop, network
and environment boundaries remain in force. Known pinned commands require this
profile for both RUN and PTY. The host's global configuration is never mounted.

Vendor archives are installed only in guarded disposable CI guests, with pinned
SHA512, bounded download/extraction, regular-file-only extraction and root-owned
read-only installation. They are optional and are not shipped in the runtime deb.
No vendor binary executes as Root. No authentication material or paid model calls
are used. Actual version/help, malformed synthetic configuration parsing, kernel
immutability and public native-PAM SDK inspection require real VM evidence.

This change does not establish authenticated coding success, actual authenticated
soft denial, physical input provenance or complete Phase 2 acceptance. Those fields
remain false or null until independently demonstrated.

Primary interface references:
- https://www.antigravity.google/docs/cli/headless/
- https://www.antigravity.google/docs/cli/modes/
- https://developers.openai.com/codex/noninteractive/
- https://developers.openai.com/codex/cli/reference/

Pinned source metadata is recorded in packaging/delegates/linux-amd64.lock.json.

Codex native executable layout is confirmed against the pinned official launcher:
https://github.com/openai/codex/blob/rust-v0.163.0/codex-cli/bin/codex.js
(target vendor subtree uses bin/codex). Initial legacy codex/codex path was
rejected by CI before any vendor execution; no failed head was merged.

Actual Antigravity startup requires singular log and crashes directories plus an
installation_id file. Only these additional volatile directories are writable;
the installation ID is a fresh sealed synthetic UUID, never a host identifier.
The settings file and its parent remain immutable. Codex offline contract passed
in the same failed VM run; overall acceptance still requires a fresh green head.

Antigravity's actual headless startup uses a localhost TCP language-server channel.
Its profile therefore permits TCP streams only within bubblewrap's newly created
network namespace. The native guard compares namespace device/inode with the
trusted compiler's outer identity, requires exactly one active loopback interface,
and still blocks datagram/packet/netlink sockets, namespace changes, mount and
identity changes. Ordinary profiles retain their complete IP socket denial.
Synthetic sealed /etc/hosts resolves only localhost, without exposing host files.
The native guard requires an explicit application separator, so application argv
cannot enable a guard mode. No host network namespace, proxy or external route
is shared. This is internal IPC, not internet/provider access.

Required VM negatives include unreachable actual outer-VM loopback listener,
unroutable external numeric address, denied datagram/netlink/packet sockets,
denied namespace creation, rejection of same-namespace guard admission and
application-argument isolation. A successful in-namespace TCP exchange is required
alongside these denials. Existing default profile security probes remain mandatory.
References: https://github.com/containers/bubblewrap (private loopback namespace),
https://man7.org/linux/man-pages/man7/network_namespaces.7.html.

Actual 1.4.2 authenticates before reporting our malformed JSON settings, so the
initial expectation of a vendor parse error is not an accepted contract. The
adapter now rejects malformed, duplicate-key or unsupported Antigravity settings
before any launch. Default agentMode and empty permission allowlist are mandatory.
An optional private CI configuration may select only the documented gemini
provider; no key is supplied. Actual configuration consumption must be established
by the binary rejecting the missing GEMINI_API_KEY instead of starting OAuth.
This preserves the malformed-config negative requirement at the adapter boundary
and adds a semantic test of real configuration selection. Codex retains its actual
vendor malformed-TOML rejection test. Neither probe establishes authenticated
permission behavior, actual soft denial or live coding success.
Reference: https://antigravity.google/docs/install?tab=cli (Gemini API key provider).

Partial diagnostic reports and independent native-PAM SDK inspection are collected
before rejecting a failed configuration contract. A failed contract still fails CI;
no diagnostic result turns its acceptance flag true or permits a merge.
