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
