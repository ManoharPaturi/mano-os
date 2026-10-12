# ADR 0007: verify the system Chromium/Playwright combination inside confinement

Status: implemented for CI acceptance. No production browser/model capability.

Use Playwright Python 1.63.0 (official release published 2026-09-15) with Debian's
system `/usr/bin/chromium`, without downloading Playwright's browser bundle.
The library explicitly warns that arbitrary system browser versions are not
necessarily compatible, so record both actual versions and run this contract
for every update. Chromium sandboxing defaults off in Playwright; explicitly set
`chromium_sandbox=True`, retaining both Chromium and outer bubblewrap boundaries.

The worker receives the validated restricted Wayland listener and fresh workspace.
Require a real local page, named button locator action, exact resulting text,
screenshot and trace. Keep the browser open until the distinct trusted compositor
observer confirms its actual mapped window. Inspect actual process arguments for
pipe debugging transport and no --no-sandbox or debugging-port option, require
renderer seccomp, and verify no TCP listening sockets in the task network namespace.

The fixture uses only local file data. No live provider, credential, human display,
external site/network grant, production broker or synthetic-input approval route
is introduced. LibreOffice, accessibility and actual human focus/approval isolation
remain separate required gates.

Primary sources:
- [Playwright browser launch options](https://playwright.dev/python/docs/api/class-browsertype)
- [Official Playwright Python releases](https://github.com/microsoft/playwright-python/releases)
