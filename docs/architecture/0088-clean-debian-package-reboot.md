# Clean Debian package installation and actual boot-change witness

The prepared lab package witness does not establish stock dependency completeness,
a generic human login, an unmodified packaged GUI, or boot-time activation. Preserve
a read-only copy of the checksum-verified, untouched Debian13 genericcloud image
before lab preparation. A separate overlay boots that pristine image with only the
ordinary cloud-init CI login/key and disposable-guest marker. No lab disks, src tree,
manual service configuration, old virtualenv or external vendor directory enter it.
The pristine backing bytes are hash-checked unchanged after both stock boots.

Transfer only the already-verified prototype2 .deb and whitelisted private test
scripts. Record the absence of mano accounts/config/code/dependencies before install.
Install via apt with --no-install-recommends so the declared runtime dependencies
must resolve; python3-pyatspi is installed afterward as explicit test-driver tooling.
Prototype2 adds explicit pam_unix module and CA-certificate dependencies. Root-TTY
enrollment binds the normal lab login, with no mano-human login account. The fixed
human group alone grants socket access; package administration creates no sudo grant.
Cloud-init's CI sudo/key configuration is a test fixture, not a product feature.

Run the original installed Sway configuration and mano-prompt wrapper without a
PYTHONPATH override, observer subclass or injected transport. A separate human
AT-SPI driver reads visible request/task/approval IDs, drives bounded Auto choices,
and checks pending-only/no-password state. Root independently validates the exact
native view. The private controlling-TTY helper replaces inherited Root groups with the target
account's actual NSS memberships, matching a login where the human socket group is
supplementary. Human-UID TTY cancellation/wrong password leave authority
inactive; actual PAM activates the profile. Capture the real pending/effective
windows only after consecutive identical compositor frames, then visually inspect
them; accessibility text readiness alone does not prove the pixels have settled. An explicit LangGraph mock plan writes a workspace sentinel.

Before shutdown, issue a genuinely unused exact read grant and verify it is currently
unrevoked and unexpired. Keep its ID/proposal in a Root0600 private file that is never
exported. A900-second preboot lease keeps the postboot test independent of expiry;
the postboot new-task lease is120seconds. Power off cleanly and boot the same overlay
again. Require a different kernel boot ID, enabled/active runtime target and Stop
service without any setup/start command after boot. Old prompt/profile access and
exact-grant replay must be denied; the saved unused grant must be revoked while its
recorded deadline is still in the future. Previous workspace data must persist.
A fresh task must complete the same unmodified GUI/PAM/mock workflow, and the
configured generic human must successfully invoke the native Stop client.

This is a fresh Debian VM installation, real kernel boot change and manual headless
human-session launch. It is not physical input, display-manager/autologin validation,
8GB hardware performance, paid provider execution, independent image-signature
verification or a signed mano-OS distribution. The existing complete security suite,
package lifecycle and exact-head merge/artifact requirements remain mandatory.

The95b40fb baseline passed functional/boot checks but consecutive identical PNGs
still contained missing glyphs in pending states. That evidence was rejected. The
headless human harness therefore uses GTK GSK_DEBUG=full-redraw and wlroots
WLR_SCENE_DEBUG_DAMAGE=rerender for its existing Cairo/Pixman software profile.
These documented upstream debugging modes invalidate the full frame instead of
trusting incremental damage. They are test-only environment, not shipped user
configuration or a permission/sandbox bypass. Report the rendering profile and keep
incremental-software-rendering visual acceptance false; no physical/default-renderer
claim follows. Functional/PAM/boot/grant checks and unchanged packaged GUI remain.
References: https://docs.gtk.org/gtk4/running.html and
https://gitlab.freedesktop.org/wlroots/wlroots/-/blob/0.18.2/types/scene/wlr_scene.c
