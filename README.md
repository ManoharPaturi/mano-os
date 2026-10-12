# mano-OS

> **AI-native, prompt-first Linux — Linux compatibility without a traditional desktop.**  
> **Project specification:** v2.1 · **Updated:** 12 October 2026 · **Status:** architecture / implementation planning; not yet a working distribution.

**This v2.1 README supersedes the earlier v2.0 architecture documents whenever their security or phase ordering differs.**

**mano-OS** is a lightweight Linux-based operating environment where a user describes an outcome and an AI agent plans, executes, and verifies the work using normal Linux programs, development tools, browsers, GUI applications, external APIs, and approved hardware interfaces.

The main interface is **one prompt box**. The system doesn't require GNOME or KDE or a normal icon-and-taskbar desktop. It *does* provide a minimal Wayland compositor and XWayland so graphical Linux applications can still run. The AI should prefer stable application APIs and command-line tools over fragile screen-coordinate clicking.

**Guiding rule:** **The AI proposes. The trusted broker authorizes. Restricted executors act. The broker records. The system verifies.**

---

## 1. Mission, intended experience and boundaries

### 1.1 What we're building

A usable AI-native operating environment with:

- A keyboard-first prompt bar, optional voice later, and a small task/approval viewer.
- Autonomous multi-step tasks (plan → use tools → observe → verify → recover).
- Shell/PTY, Python, Node, Git, package tools, build tools and arbitrary **authorized** Linux CLIs.
- Plug-in coding agents (Antigravity CLI first, plus a second independent adapter).
- Programmatic control of compatible Linux apps: semantic APIs, D-Bus, AT-SPI, browser automation and last-resort vision/input.
- A separate **headless agent desktop** for background GUI work, without stealing the user's keyboard or mouse.
- Permission modes **Supervised**, **Auto** and **Full Access** with kernel-enforced boundaries.
- Device discovery and approved serial/USB/network hardware integrations.
- Durable execution records, capability discovery, resumability, observable results and OS recovery.
- Deployment first as a runtime package on Debian, later as a bootable mano-OS image.

### 1.2 Examples of the experience

**Coding:** “mano, build a Next.js app, test it, run it and show me the results.” The system creates a workspace, invokes a coding agent, builds, tests, opens the application in an agent-controlled browser, verifies the result and reports artifacts.

**GUI:** “mano, open LibreOffice, use these CSV files to make a report, and export the PDF.” The system uses direct data/document libraries where suitable and graphical automation when needed.

**System:** “mano, why is the laptop slow?” The system inspects authorized metrics and proposes remedies; privileged changes require broker authorization.

**Hardware:** “mano, connect to my Arduino, collect sensor readings and plot them.” Device access is mediated through a narrow hardware adapter.

### 1.3 Non-negotiables

1. **8 GB RAM target:** the basic OS, prompt interface and cloud-model workflow must run acceptably on an 8 GB machine. No requirement to host a large model locally.
2. **Real Linux compatibility:** normal Linux packages and supported GUI software remain available. Compatibility is **a target, not a promise that literally every application works**; kernel modules, proprietary drivers, anti-cheat, DRM, root-dependent and compositor-dependent programs require separate validation.
3. **No traditional desktop shell:** the default view is the mano prompt. A minimal compositor is still necessary to run GUI windows.
4. **Easy AI control:** expose typed, semantic system capabilities, not only screenshots and synthetic mouse events.
5. **No trusted LLM:** AI reasoning, tool responses, webpages, repo content, MCP servers and coding delegates are *untrusted*.
6. **Permissions are enforced below the agent:** a prompt or Python `if` statement is not a security boundary.
7. **Independent approval and stop:** agents cannot click their own approvals or disable the emergency stop.
8. **Small, extensible core:** reuse existing workflow frameworks and coding agents; build the novel Linux control plane.
9. **No fabricated results:** a tool reporting success is not equivalent to verified task completion.
10. **User ownership:** the user can see actions, revoke permissions, cancel tasks, export history and uninstall mano-OS without losing access to normal Linux.

### 1.4 Non-goals for v0.x

- Developing a new kernel, Linux filesystem or device-driver stack.
- Implementing a general-purpose LLM model or coding-agent framework from scratch.
- Shipping autonomous financial transactions or safety-critical robotics without specific policy controls.
- Guaranteeing reliable visual control of every third-party application.
- Multi-machine autonomy, always-listening voice, a full app store or heavy local inference.

---

## 2. Reuse vs. build — the core decision

**We reuse an existing agentic workflow harness.** We will **not** invent our own LangGraph replacement.

| Area | Choice | Decision |
|---|---|---|
| Base operating system | **Debian 13 (Trixie) minimal, x86_64** | Reuse Linux kernel, packages, drivers, systemd |
| Local graphical environment | **Sway + XWayland** | Minimal user session and separate headless session, subject to Phase 0 approval |
| Agent workflow engine | **LangGraph** behind a small `AgentRuntime` interface | Existing graph execution, checkpointing, interrupts |
| LLM provider layer | OpenAI, Anthropic, Gemini, OpenAI-compatible endpoints, Ollama | Pluggable; cloud default for 8 GB |
| Coding delegates | **Antigravity CLI + at least one other** (Claude Code or Codex) | Run delegates in mano task sandboxes |
| CLI/process control | Python async subprocess/PTY + Linux process control | Build an adapter around existing OS primitives |
| GUI semantics | D-Bus, AT-SPI, app-native commands | Prefer structured actions over vision |
| Browser | **Playwright launches system Chromium** via `executable_path` | Browser launch uses its local transport, **not** a separately exposed CDP TCP port |
| GUI input / capture | Dedicated headless Sway workspace + controlled input/capture adapter | Keep agent input out of user session |
| Tool interoperability | MCP client/server SDKs | Protocol adapters, not a security policy |
| Sandboxing | bubblewrap + namespaces + Landlock as applicable + seccomp + cgroups | Broker-selected profiles; enforce with kernel boundaries |
| Policy, grants, journal, credentials | **Trusted `mano-broker`** (small, auditable service) | Build; never delegate authority to core |
| Prompt shell | GTK4 or small native Wayland UI | Build a minimal user-facing surface |
| Persistent data | SQLite for agent memory; **separate broker-owned action journal** | Two separate authority domains |
| Disk snapshots | btrfs + Snapper integration | Evaluate in Phase 0; support privileged-change rollback |
| Delivery | `.deb` runtime first, installer ISO later | Validate the product before packaging a distro |

The differentiator is **not** a novel AI model or fancy desktop. It is the **typed Linux control plane plus enforced authority separation**.

---

## 3. Threat model and trust architecture (mandatory reading)

### 3.1 Trust zones

1. **Trusted human interface / login session.** Displays authentic authorization requests; never accepts injected events from the agent compositor. It is not a browser page or text printed by the model.
2. **Trusted `mano-broker`.** The only service allowed to evaluate real policy, issue/revoke grants, write authoritative audit records, coordinate privileged operations or use credentials. Runs under a protected principal, distinct from agent jobs, with narrowly defined IPC.
3. **Untrusted `mano-core`.** Can run an LLM, build plans, keep reasoning state, and *request* capabilities. **It cannot approve its own requests, modify policy, mint grants, read raw secrets, or write authoritative journal entries.**
4. **Untrusted delegates.** Terminal commands, coding-agent CLIs, MCP servers, browsers and third-party GUI apps run with separate sandbox and process limits.
5. **Isolated agent graphical domain.** A separate headless compositor and graphical executor support authorized background UI tasks. Neither agent jobs nor the agent GUI controller receive the **user session** display socket or physical input devices.

> **Compromised-core assumption:** design every policy boundary assuming the LLM, `mano-core`, a coding delegate, or a document it reads may behave maliciously.

### 3.2 Correct authority flow

```text
       USER'S PHYSICAL SESSION                         UNTRUSTED WORK
   ┌───────────────────────────┐                ┌───────────────────────────┐
   │ mano-prompt / approvals   │                │ LLM + mano-core          │
   │ real user login/session   │                │ LangGraph + memory       │
   └─────────────┬─────────────┘                └─────────────┬─────────────┘
                 │ authenticated human approval             │ ACTION REQUEST ONLY
                 │                                           │ (no policy authority)
                 ▼                                           ▼
           ┌───────────────────────────────────────────────────────┐
           │                   TRUSTED mano-broker                 │
           │ policy decisions · protected grants · credentials     │
           │ append-only action journal interface · task limits    │
           │ privileged-operation mediation · emergency stop      │
           └──────────────────────────┬────────────────────────────┘
                                      │ authorized scoped execution
                      ┌───────────────┼──────────────────┐
                      ▼               ▼                  ▼
              ┌────────────┐  ┌────────────────┐  ┌───────────────┐
              │ CLI / code │  │ Headless GUI   │  │ Narrow system │
              │ sandboxes  │  │ per task/domain│  │ / device APIs │
              └────────────┘  └────────────────┘  └───────────────┘
                      └───────────────┼──────────────────┘
                                      ▼
                              Linux kernel + devices
```

**Why the separation matters:** a Python `PolicyEngine` inside `mano-core` is advisory only. Final decisions are made by the broker and enforced by process credentials, kernel sandboxing, restricted sockets and privilege separation.

### 3.3 What `mano-core` is allowed to do

`mano-core` must itself run under a separate unprivileged identity and restrictive service profile. It receives neither the real user home nor the human Wayland/D-Bus sockets, cannot spawn unsandboxed tools on the host, and cannot read broker files. It reaches powerful operations **only through broker IPC**; provider API egress is separately scoped. Restricting delegate subprocesses while leaving `mano-core` with the user's own host privileges would invalidate the threat model.

- Send `ActionRequest` messages to the broker.
- Read redacted, broker-authorized `ActionResult` and sanitized observation data.
- Keep model context, task plans and non-authoritative checkpoints.
- Ask to pause, resume, cancel and verify tasks.
- Provide reasons and requested scopes to the user; **not** grants or signatures.

### 3.4 What `mano-broker` owns

- Authoritative policy evaluation and risk classification.
- User approval records (operation, exact arguments, resource scope, task ID, expiry, grant ID).
- Secure credential store operations and credential-bearing remote requests.
- Broker-owned action journal and execution sequence numbers.
- Creation of sandbox profiles, process ownership, cgroup limits and revocation.
- Narrow privileged Linux operations via a separate root-facing helper when required.
- Routing to user-session approval UI, verifying the trusted channel and stop events.

**Implementation detail:** the broker should run as a different service user and/or root-controlled unit, with policy and journal files outside agent-writable mounts. A separate small privileged helper should do the rare root-required operation; don't make the entire broker a root shell.

### 3.5 Protected paths and persistence prevention

An agent must not gain write access to mano policy or execution infrastructure — **including in Full Access mode**. Protect at least:

```text
/etc/mano/**                        # system policy, broker policy
/var/lib/mano-broker/**             # grants, protected journal, secrets metadata
/run/mano-broker/**                 # broker-only sockets
~/.config/mano/**                   # if user config exists; read-only or mediated
~/.config/systemd/user/**           # persistence via user units
~/.config/sway/**                   # input / shortcut / approval changes
~/.bashrc, ~/.profile, ~/.zshrc     # shell-startup persistence
~/.ssh/**, ~/.gnupg/**              # identity / authentication agents
~/.gemini/antigravity-cli/**        # coding delegate's user-global policy
```

This is a **minimum deny surface**, not an exhaustive list: desktop autostart, shell plugin paths, browser extensions, Git hooks, executable search paths, cron, XDG autostart, dynamic linker configuration, credentials and existing startup entries also require threat modeling. Favor a task-specific synthetic home rather than exposing the real user home. A broad user-space operation can use explicit, mediated mounts; do not promise that write-all `$HOME` is safe.

### 3.6 No inherited privileged IPC

Task sandboxes receive **none** of the following host facilities by default:

```text
DBUS_SESSION_BUS_ADDRESS     # host session bus
WAYLAND_DISPLAY / WAYLAND_SOCKET   # user's compositor
DISPLAY                       # user's X11/XWayland socket
SSH_AUTH_SOCK                 # SSH agent
GNUPGHOME / gpg-agent sockets
PIPEWIRE_REMOTE / PipeWire socket
/dev/input/*, /dev/uinput     # physical input and virtual device creation
/run/user/$UID/**             # generic host-user IPC tree
Docker/Podman host sockets, systemd control sockets, user keyring handles
```

For a legitimate D-Bus call, provide a narrowly filtered, **separate** proxy using `xdg-dbus-proxy`, with exact destinations and methods. A task GUI app gets only its dedicated **agent** Wayland socket, never the human user's socket. Do not expose the user's X11 server, since X11 clients can commonly inspect/interact with other clients.

### 3.7 Sandboxing is a compiled security profile, not a command filter

The broker selects and instantiates a per-task profile using:

- Distinct unprivileged task identity, carefully constructed bubblewrap filesystem mounts, process and network namespaces.
- **Default-deny** filesystem visibility; read-only OS libraries and data; only granted workspace paths are writable.
- Seccomp and Landlock defense in depth where kernel and application compatibility allow.
- Cgroups with `MemoryMax`, `CPUQuota`, process-count limits and timeout/kill policy.
- Explicit network namespaces; outbound traffic only through a broker-controlled proxy with destination, method, redirection, DNS/IP and payload policy. Landlock TCP-port restrictions are **not** a domain allowlist.
- Empty/minimal environment and carefully filtered FDs; no inherited session, desktop or auth sockets.
- Tool-specific restrictions, including not allowing raw privilege escalation, mount, kernel module access, host `systemctl`, or device mutation from sandboxes.

**Security update gate:** Debian 13's bubblewrap package must contain the fix for CVE-2026-87766, provided in `0.12.0-1~deb13u1` (or a later patched Debian package). Phase 0 checks the installed security update and blocks unsafe build images. Bubblewrap is a sandbox construction toolkit; the broker is responsible for defining the actual security policy. Keep `xdg-dbus-proxy` patched as well, including its 2026 message-filtering security updates.

**Full Access does not mean bypassing these boundaries.** It means the user can grant wider *specific data and tool scopes*, with protections around mano internals, root, credentials, physical input and external side effects retained.

### 3.8 Approvals cannot be performed by the agent

**Primary control:** the agent and its GUI-input service exist only in the **headless agent graphical domain**, separate from the user login. No sandbox, model, coding agent, browser or headless compositor has the user's display socket, X11 socket, input devices or trusted-approval IPC.

- A trusted user-interface service receives pending approvals **only from the broker**.
- The approval describes the exact operation, target, risk, expiry and task ID, not text supplied as a UI authority by a webpage or model.
- Approval is authenticated and bound to one request (or to an explicitly stated short-lived grant scope).
- Sensitive changes may require a human OS authentication challenge or second channel, even in Auto/Full Access.
- A compositor device-specific binding can help usability but **is not proof of physical input**; software-created devices can spoof identifiers if `/dev/uinput` or equivalent access is available.
- A physical-only input path must be validated in Phase 0 using a trusted component with controlled access to real evdev/libinput devices; if provenance cannot be validated, use a stronger OS-authenticated / out-of-band confirmation path rather than claiming a physical guarantee.

Foreground desktop control, if added, is an **explicit separate capability**, not an implicit shortcut from headless automation. It must never be able to operate the trusted approval surface.

### 3.9 Emergency stop is independent of Python

Provide a protected `mano-stopd` or broker-hosted watchdog that can kill **every active agent task cgroup/slice**, revoke live grants and disable further automated input. It must be triggerable through trusted input/TTY, continue to work when `mano-core` hangs, and preserve a recovery terminal.

The Sway configuration may expose a convenient key binding, but `bindsym --locked` means “works while locked,” **not** “only a physical keyboard can activate this.” Test the entire trigger path under hostile synthetic input, daemon hang and process storms.

### 3.10 Prompt injection and secret exfiltration

External webpages, repositories, emails, PDFs, logs and MCP outputs are **data**, not privileged instructions. Track untrusted provenance/taint and classify side-effectful requests (email, uploads, network to new destinations, credentials, deployments, deletion, hardware motion). Taint tracking is an extra signal, **not a proof of safety**.

Critical control is destination- and operation-scoped approval, strict data minimization, and credentials which remain in the broker. Do **not** inject raw tokens into an arbitrary sandbox's environment. Instead, the broker or narrowly authorized service performs authenticated API/Git operations or attaches a token only inside an equally protected, trusted operation.

Screenshot vision sent to cloud models is **data leaving the computer**. Prefer cropped task windows, downscaling and redacting known secrets, and require a clear user grant where data leaves the machine; log capture and destination.

---

## 4. Runtime architecture and processes

```text
┌─ Human login / physical graphical session ──────────────────────────┐
│  mano-prompt   mano-approvals   status   human keyboard/mouse        │
│  minimal Sway compositor; no panel, taskbar or full desktop shell   │
└──────────────────────────────────────────────────────────────────────┘
                     │ authenticated UI channel
                     ▼
┌─ Trusted system boundary ───────────────────────────────────────────┐
│ mano-broker: policy + grants + journal + process controls + secrets │
│ mano-privileged-helper: minimal, specifically authorized root ops   │
│ mano-stopd: independent task kill/revoke path                       │
└──────────────────────────────────────────────────────────────────────┘
                     ▲                 │ scoped requests/results
                     │                 ▼
┌─ Untrusted reasoning and task domain ───────────────────────────────┐
│ mano-core + AgentRuntime + LangGraph + model adapters + tool search │
│ Task workers: terminal, coding agents, MCP, browser, GUI adapters   │
│ Each executed with an explicit sandbox profile and task resource ID │
└──────────────────────────────────────────────────────────────────────┘
                                        │ dedicated agent-only socket
                                        ▼
                         ┌──────────────────────────┐
                         │ Headless Sway compositor  │
                         │ Chromium, LibreOffice...  │
                         │ agent-only GUI executor   │
                         └──────────────────────────┘
```

**The headless session** defaults to `WLR_BACKENDS=headless` where supported and a separately owned Wayland runtime directory. Validate proper output creation, accessibility, screenshot capture and XWayland compatibility. Per-task sessions are preferable when GUI tasks are mutually untrusted; sharing one GUI session across unrelated tasks expands the trust surface. Viewing the agent desktop is an optional, authenticated, user-initiated feature (e.g. locally mediated wayvnc), never an unauthenticated network service.

**Foreground mode** is a separate, higher-risk capability where the user can request direct control of a visible app. Implement only after the separate-domain guarantees are proven, and without granting access to approval UI or arbitrary user applications.

### 4.1 Components

| Service | Trust | Responsibilities |
|---|---|---|
| `mano-prompt` | Trusted UI surface | Prompt input, user-initiated status, approvals view |
| `mano-core` | Untrusted | Interpret goals, plan, orchestrate, request tools |
| `mano-broker` | Trusted | Policy, grants, journal, secrets, requests, delegated execution |
| `mano-privileged-helper` | Highly restricted | Allowlisted root-required OS operations |
| `mano-stopd` | Trusted | Independent terminate-all and revoke |
| `mano-sandbox` | Trusted broker component | Build/run sandbox profiles, observe cgroups, control FDs |
| `mano-terminal` | Untrusted worker | Shell/PTY within allocated task rights |
| `mano-code-agent` | Untrusted worker | Antigravity / second coding delegate adapter |
| `mano-gui-executor` | Restricted worker | Input/screen/accessibility **within agent-only session** |
| `mano-browser` | Restricted worker | Playwright + system Chromium in task session |
| `mano-hardware` | Broker-mediated | Device discovery, read telemetry, approved output operations |
| `mano-eval` | Test harness | Verification, trace playback and adversarial tests |

---

## 5. Control API — make Linux easier for the AI

The AI should interact with **semantic operations**. Backends can switch between application-specific APIs, CLI, D-Bus, AT-SPI, browser automation and visual gestures based on capability and reliability.

### 5.1 Preferred control order

1. Application-native/OS structured API or D-Bus method.
2. Well-defined CLI command with verifiable exit and effect.
3. Accessible UI roles, names and actions via AT-SPI.
4. Browser locators via Playwright for browser applications.
5. Screenshot-based click/type/drag fallback, restricted to the agent desktop.

Each route still needs broker-granted authority. Merely changing from mouse automation to a CLI does not bypass a permission.

### 5.2 Proposed public capabilities (not yet implemented)

```text
system.inspect_health()                  # observable system status
terminal.run(argv, cwd, timeout)          # sandboxed, validated task request
terminal.open_pty(profile)                # persistent scoped PTY
files.read(path) / files.write(path, data)
packages.plan_install(names)              # produce plan; broker handles privileged step
apps.list() / apps.launch(app_id)
desktop.observe(session_id)
desktop.click(session_id, target)
desktop.type_text(session_id, text)
browser.open(url) / browser.locate(selector)
coding.run(delegate, workspace, objective)
hardware.discover() / hardware.serial_read(device)
workflow.start(goal) / workflow.pause(id) / workflow.cancel(id)
approvals.request(action_id)              # only broker can mint real request
```

An ordinary GUI action might be executed by AT-SPI; the agent still receives a semantic result such as `window_title`, `target_role`, `changed_state` or `artifact`, not only a screenshot.

### 5.3 Action protocol example

This is a **design sketch**, not a live deployed API:

```json
{
  "schema_version": "1.0",
  "task_id": "task-001",
  "action_id": "act-009",
  "capability": "terminal.run",
  "args": { "argv": ["pytest", "-q"], "cwd": "/workspace/app" },
  "requested_scope": "workspace:app",
  "reason": "Verify the implementation",
  "idempotency_key": "task-001:pytest:1"
}
```

`mano-broker` validates the caller, requested capability, task grant, paths, actual sandbox execution profile and expiry. `action_id`, `idempotency_key` and authorization bindings are not trusted merely because the core supplied them; authoritative IDs/tokens are generated or independently validated by the broker.

Result contract:

```json
{
  "action_id": "act-009",
  "journal_state": "done",
  "execution_state": "exited",
  "exit_code": 0,
  "verified": true,
  "evidence": ["artifact://task-001/test-output.txt"],
  "redactions_applied": true
}
```

A tool exit code of `0` is **not** sufficient to set `verified: true`. Verification is a separate checked outcome.

### 5.4 Capability discovery

On boot or request, collect a signed/validated registry of installed CLIs, versions, applications, APIs, MCP servers, device adapters and current *allowed* capabilities. Re-probe tools when packages change. Unknown adapters are untrusted and execute under restricted profiles.

Expose only the relevant subset of capability schemas to the model to reduce tokens and attack surface.

---

## 6. Agent runtime, state and journal

### 6.1 The agent loop

```text
User request → plan → select capabilities → submit action to broker
      → broker authorization → restricted execution → observation
      → independent outcome verification → continue / recover / report
```

Use **LangGraph** for reasoning-workflow state and checkpoints, behind `AgentRuntime` to permit future replacement. Its checkpoints are **not** the security log or source of truth for external effects.

### 6.2 Broker-owned append-only action journal

Every action becomes a durable sequence of *events*, written only by the broker:

```text
intent  → executing → done
                    ├─ failed
                    └─ unknown
```

- Write and flush an `intent` before beginning an action; use broker-issued action identifiers.
- Record relevant parameters in **redacted** form, caller identity, sandbox profile, grant and external-effect classification.
- Persist `executing`, then a terminal state with outcome evidence.
- On crash or missing acknowledgment, mark the action **unknown**, reconcile external state and **never blindly replay** a non-idempotent effect.
- Keep operator-readable exports, rotations and tamper-evident hash chaining if appropriate. The journal is trusted only up to the OS/broker trust boundary; root compromise is out of scope for journal integrity.
- Test journal behavior under power loss, kill signals, duplicate request IDs and interrupted external API requests.

### 6.3 Task status

`created`, `planning`, `awaiting_grant`, `queued`, `running`, `verifying`, `completed`, `failed`, `cancelled`, `recovering`, `unknown_effect`.

No action should be re-executed merely because the LangGraph step reruns. Before retry, ask the broker whether its effect is complete, failed or uncertain.

### 6.4 Model, context and budget management

- Pluggable model selection by task difficulty, price, latency and cloud/local availability.
- No raw broker credentials in the model context.
- Truncate tool outputs and store full logs as broker-controlled task artifacts.
- Compact long conversational histories with explicit references to original artifacts.
- Token, compute, runtime and cost ceilings per task; require a new grant if a requested limit increases.
- Stable, cache-friendly prompt sections; narrow tool schemas.
- Tool-reported results must be checked; red-team malformed structured output and partial failures.

### 6.5 Coding delegates

The first adapter targets Antigravity CLI headless execution. A second adapter (Claude Code or Codex) should be built in Phase 2 to validate the common interface.

Each delegate must support start, stream, stop, capture outputs, detect denial, accept task-scoped configuration, report errors, and run in a broker-issued sandbox.

**Antigravity-specific controls:**

- Pin and test the supported CLI version. Headless `-p` and JSON streaming behavior must be verified by contract tests.
- Default shell actions may be **soft-denied with exit code `0`** in headless mode. Parse structured events, `stderr` and postconditions; never infer permission or success from exit status alone.
- Antigravity's settings normally live at `~/.gemini/antigravity-cli/settings.json`. **Never expose the host/global copy writable to the delegate.** Use a generated, per-task synthetic home/config, and test that the CLI actually uses it.
- Its `--sandbox` setting is useful defense in depth, not the mano permission boundary. Do not use `--dangerously-skip-permissions` in ordinary operation.
- A delegate's own approval dialog or textual output cannot approve a mano-broker operation.

### 6.6 MCP servers

Treat a local MCP server as **arbitrary untrusted executable code**. Run each under task-scoped limits, restrict filesystem/network/IPC, mediate credentials and inspect tool descriptions as untrusted data. Remote MCP endpoints require explicit connector scopes and destination restrictions.

---

## 7. User, agent desktop and browser

### 7.1 Human-facing default

```text
┌───────────────────────────────────────────────────────────┐
│                           mano-OS                         │
│                                                           │
│         [ ✦ Ask mano anything...                 🎤 ]     │
│                                                           │
│         Active tasks · Approvals · History · Settings     │
└───────────────────────────────────────────────────────────┘
```

No icon grid, dock, panel or heavy background shell. Apps are still launched on demand.

### 7.2 Dedicated agent desktop

- Run a separate compositor using the headless wlroots backend when compatible.
- Use distinct service credentials and `XDG_RUNTIME_DIR` with no cross-session socket sharing.
- The GUI executor may operate **agent session** windows but is never given the **human session** Wayland/X11 sockets.
- For each task, minimize exposure of other task windows, browser cookies and accessibility data; prefer separate desktops when mutual isolation is required.
- Allow optional authenticated read-only user viewing of the agent workspace; bidirectional sharing requires a separate explicit authorization design.
- **Phase 0 challenge:** confirm that untrusted clients in the agent desktop cannot obtain unintended privileged global protocols or circumvent the input broker. A second compositor by itself is *not* sufficient sandboxing.

### 7.3 Wayland and AT-SPI caveats

- Enable the session accessibility service before testing; `org.a11y.Status.IsEnabled` plus Qt/Chromium/Electron accessibility flags are implementation experiments, not guarantees for every application/version.
- AT-SPI screen-space extents may be unreliable on Wayland. Combine accessible-element/window-relative geometry with Sway layout/output scaling, and verify with a screenshot when needed.
- Bound accessibility traversal depth/time and cache results for large applications.
- Disable raw `/dev/uinput` and physical `/dev/input` access for untrusted tasks; do not rely on Wayland virtual-keyboard origin to prove physical input.
- Test Sway privileged-protocol restrictions with the *specific Debian version and actual sandboxed client credentials*. A compositor's security-context filter is not a universal guarantee for every client.

### 7.4 Browser: system Chromium launched by Playwright

Initial choice: **system Chromium**, separate task-owned browser profile, launched under the agent graphical domain with **Playwright's `launch(executable_path=...)`**. This avoids intentionally opening a CDP TCP server and uses Playwright's standard local transport.

Illustrative Python call (only inside the controlled browser worker):

```python
from playwright.async_api import async_playwright

async def open_browser():
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            executable_path="/usr/bin/chromium",
            headless=False,
        )
        context = await browser.new_context()
        page = await context.new_page()
        await page.goto("https://example.org")
        await browser.close()
```

**Known trade-off:** Playwright's maintainers do not guarantee arbitrary system Chromium versions work with every Playwright release. Pin the distro/browser/Playwright combination, run browser launch/locator/navigation/screenshot contracts in CI and evaluate compatibility at every update. Preserve Chromium's sandbox where supported; don't make `--no-sandbox` the normal answer to setup failures.

No general-purpose debugging endpoint is exposed on `127.0.0.1`: loopback access alone is **not** a security boundary. Browser network access is still subject to task policy.

---

## 8. Execution modes and precise boundaries

All modes still use the broker, kernel-enforced task isolation, immutable protected paths, action journal and stop function. A mode is a *grant profile*, not a different AI personality.

| Mode | Automatic authority | Must ask / deny |
|---|---|---|
| **Supervised** | Observe authorized machine status, read allowlisted input data; optional dry runs | Writes, shell changes, installation, network uploads, credentials and external effects generally require explicit grant |
| **Auto** | Read/write the **designated workspace**, run approved development tools, use **approved network destinations** and bounded task budgets | Paths/apps/domains outside scope, privileged system changes, irreversible effects, sensitive data transmission |
| **Full Access** | Broad, explicitly user-granted **ordinary user-space** files/tools/network operations for a task or short session | Still cannot write protected policy/persistence paths, use raw secrets, self-grant privilege, access user session input or unapproved physical hardware; sensitive irreversible external effects remain separately gated |

**Full Access is not root.** This is intentional. A user may elect to run a disposable VM with stronger privileges; the default product never lets model-generated code decide to bypass authentication, root isolation, security policy or physical safety controls.

### 8.1 Grant dimensions

Each grant binds: **human identity, task ID, operation/capability, resource selectors (paths/app/device), network destinations and allowed operations, data classification, duration, maximum count, resource budgets, revocation status and whether external effects are allowed**.

Examples:

```text
/mode supervised
/mode auto
/mode full-access  # trusted manual approval, short expiry
/permissions
/tasks
/pause <task-id>
/resume <task-id>
/stop <task-id>
/emergency-stop
```

The command strings above are a proposed UI, not runnable commands in an implemented OS.

---

## 9. Hardware integration

- Discover GPU, CPU, storage, network, Bluetooth, cameras and USB devices with existing Linux facilities and restricted observability tools.
- Use adapters for Arduino serial, ESP32, MQTT, ROS 2, smart-home APIs and other hardware only as actually supported.
- **Read-only telemetry first.** Sensor collection should be granted per device, baud/configuration, task and time.
- Physical actuator writes require a separate capability, defined movement/energy limits, user authorization, physical safety interlocks and a way to stop actuation independent of the LLM.
- Don't pass raw `/dev` access to the agent just to talk to a serial device; route through a scoped adapter or dedicated device service.

---

## 10. Performance target — 8 GB RAM

The 8 GB requirement is for **cloud-assisted everyday operation**, not concurrent local large-model inference and many open Chromium tabs.

Planned mechanisms:

- Debian minimal, Sway, minimal services; lazy-load model adapters and optional features.
- One on-demand heavy agent task by default; concurrent lightweight tasks only when measured safe.
- zram, `systemd-oomd` and a per-task `MemoryMax` and process limit.
- Separate resource budgets for browser, compiler, coding agent and UI service.
- Process trees killed as cgroups, not by fragile shell PID matching.
- Keep tool logs on disk; stream compact summaries into model context.
- Benchmark idle boot, browser launch, coding job, LibreOffice, serial collection and recovery on **actual 8 GB hardware**.

**Provisional gates (targets, not measured claims):** system remains responsive through normal prompt/terminal tasks; an agent OOM doesn't take down the human session; memory usage and swap pressure are observable; no compulsory on-device foundation-model download.

---

## 11. Storage, updates, recovery and rollback

- **Phase 0:** choose/test a btrfs root partition and Snapper integration at install time. This is easier to validate early than changing filesystems later.
- Snapshot before selected privileged filesystem/package modifications, with space accounting, retention and restore tests.
- Git commits/patches cover source workspace checkpoints; not every file operation is reversible.
- Explicitly classify irreversible or externally visible effects (emails, remote pushes, deployments, payments, actuator motion). A btrfs snapshot **cannot** undo those.
- A stopped or crashed task resumes from the broker journal's verified state, not from guessed agent memory.
- Final distro adds signed packages, pinned/recorded image inputs, package updates, reproducible builds where practical and a rescue terminal.
- Pinned *build provenance* is separate from timely *security updates*: never ship a known-vulnerable snapshot merely for reproducibility.

---

## 12. Development plan — phases, artifacts and acceptance gates

**Project assumption:** initially a solo or very small team using coding agents to accelerate implementation. Time ranges below are **planning estimates, not promised delivery dates**. Each phase yields source, tests, measured results, documentation and a runnable demonstration; a phase is not complete because an AI says it is.

### Phase 0 — Feasibility & security architecture spike (timebox: 2 weeks)

**Goal:** prove the OS foundation is feasible **and** that the agent can be confined away from the user session. Hard go/no-go on Sway architecture.

Build/test:

1. Debian 13 minimal VM (8 GB max), btrfs root and security-update baseline; verify patched bubblewrap.
2. Minimal prompt-only Sway user session; no conventional desktop shell.
3. Separate headless Sway instance, independent runtime dir and service identity; launch Chromium + LibreOffice and validate screenshot and basic input.
4. Explicitly enable accessibility; inspect AT-SPI tree, exercise a named action and verify Wayland coordinate mapping.
5. Restrict compositor privileged protocol access to intended services; test untrusted XWayland and Wayland clients.
6. **Approval spoof attack:** attempt to click/type into human approval from CLI, injected GUI events, virtual-keyboard path and socket abuse. Must fail.
7. **Input/stop test:** physically request stop while core is frozen; tasks must terminate without Python cooperation. Deny `/dev/input` and `/dev/uinput` to untrusted tasks.
8. Check no inherited user D-Bus, Wayland/X11, SSH/gpg, PipeWire or systemd-control sockets.
9. Evaluate Snapper snapshot/restore and terminal rescue on btrfs.
10. Record idle RAM, session memory, app start, process limits, log evidence and compatibility problems; do not invent numbers.

**Gate:** proceed only if user-session isolation, approval protection, trusted stop and headless GUI control are demonstrated. Otherwise revise compositor/session architecture first.

### Phase 1 — Trusted broker, sandbox runner and minimal agent (3–6 weeks estimate)

**Goal:** build an enforceable trust boundary before allowing AI shell execution.

Build/test:

1. Define typed broker request/result/grant schema and distinct user/service identities.
2. Implement broker-owned policy, secure grants and action journal (`intent → executing → done/failed/unknown`).
3. Implement per-task bubblewrap sandbox with filesystem restrictions, no inherited IPC, cgroup and seccomp/Landlock tests.
4. Build supervised, Auto and Full Access policy **profiles** (initial small scope, then expand later).
5. Implement isolated terminal adapter and minimal model adapter / LangGraph `AgentRuntime`.
6. Implement prompt bar and broker-driven approval UI.
7. Build golden-task tests, mock model, recorded traces/replay, malicious shell attempts and CI gating.
8. Implement stop/revoke end-to-end and verify unknown-effect recovery.

**Gate:** agent creates/tests a project in its allowed workspace; attempts to modify protected policy or host configuration **fail at the OS boundary**, not only by LLM instruction.

### Phase 2 — Developer tool workflows and independent coding adapters (3–5 weeks)

**Goal:** autonomous coding with controlled dependencies and verifiable results.

Build/test:

1. PTY and long-running process supervision, logs, environment and package-plan adapters.
2. Antigravity headless adapter with per-task synthetic home/settings; verify soft-denial exit-0 case.
3. Second adapter (Claude Code or Codex) with same contract, version pinning and replayable traces.
4. Git workspace snapshots, test/fix loops and structured artifacts.
5. MCP sandbox runner and minimal tool discovery.
6. Red-team corpus: prompt-injection repos, typosquatted dependencies, malicious MCP servers, malicious scripts.

**Gate:** start coding job → tests → retry or correct failure → verified result; policy and `settings.json` are unchanged even with a malicious delegate.

### Phase 3 — Linux GUI/browser control; ship runtime MVP (4–8 weeks)

**Goal:** useful cross-application control without a traditional desktop.

Build/test:

1. Headless session management and GUI-only sandbox policy.
2. D-Bus/AT-SPI adapters, window geometry and screenshots.
3. Controlled keyboard/mouse input only to agent session; no human focus stealing.
4. Playwright launches system Chromium using local transport; distinct browser profiles.
5. Browser compatibility tests for each pinned version, including security setting checks.
6. LibreOffice tasks (open, edit, save, export) and screenshot/vision privacy controls.
7. Trusted approval surface, synthetic-input attack recheck, independent compositor-level/TTY stop path.
8. Package runnable **`mano-runtime` v0.x `.deb`** for stock Debian + Sway.

**Gate:** “build website → test → open Chromium → verify page → generate summary” succeeds and an attempted approval spoof or user-session control fails. LibreOffice demonstration also passes.

### Phase 4 — Durable multi-app workflows and control SDK (3–6 weeks)

**Goal:** multi-step tasks that recover without redoing external actions.

Build/test:

1. Typed SDK, full capability registry and provider-agnostic tool adapters.
2. Dependency-aware workflow execution, task queues, retries and timeouts.
3. Broker journal reconciliation for `unknown` actions and idempotent replay rules.
4. Searchable artifacts, model context compaction and token/cost budgets.
5. Connector authorization and provenance/taint-aware exfiltration guardrails.

**Gate:** restart core mid-workflow; finished steps aren't repeated, unknown effects are reconciled, and user sees accurate status.

### Phase 5 — Broader autonomy, hardware and OS operations (4–8 weeks)

**Goal:** expand capabilities safely, rather than postponing the security model.

Build/test:

1. Wider, time-bounded Auto and Full Access grants with host data restrictions retained.
2. Broker-performed credentialed Git/API operations; no plain secrets to agents.
3. Narrow package/system helper, btrfs/Snapper actions and documented restore.
4. Device discovery, serial read, GPU/system APIs and safe hardware operation envelopes.
5. VM lab mode for deliberately broad experiments and physical safety stop tests.

**Gate:** a granted sensor read and ordinary system operation work; off-scope credential, device or persistence modifications fail.

### Phase 6 — Optimize for 8 GB, harden and expand compatibility (3–6 weeks)

**Goal:** actual reliability and memory measurements on target hardware.

Build/test:

1. zram and OOM containment tuning; task priority and execution concurrency caps.
2. Cold boot, idle, browser and code-build memory traces on physical 8 GB test systems.
3. Desktop/XWayland/GUI application compatibility matrix and fallback policies.
4. Security fuzzing, IPC-failure, dependency-update and crash recovery tests.
5. CLI/coding-agent/Chromium version contract tests in release pipeline.

**Gate:** normal tasks remain responsive on an 8 GB laptop, and an intentionally OOMing agent cannot take down the user session or trusted broker.

### Phase 7 — Bootable mano-OS distribution (4–8 weeks)

**Goal:** a real installable OS image, after validating the runtime independently.

Build/test:

1. Build custom Debian-based image with `live-build` or `mkosi` (tool decision by experiment).
2. Pin build inputs including base repository snapshot; retain security-update mechanism.
3. Configure prompt-first boot, login, compositor isolation, services and user onboarding.
4. Provide AI API configuration, user policy setup, mode selection and hardware diagnostics.
5. Provide signed packages/image, update/rollback and recovery boot option.
6. Fresh install smoke tests in a VM and on one 8 GB physical machine.

**Gate:** a newly installed mano-OS boots directly to the prompt, launches authorized Linux CLI and GUI workflows, stops agent jobs reliably and survives updates.

### Phase 8 — Optional extensions (after stable baseline)

Voice and wakeword, richer local model selection, robotics/ROS 2, federated tasks, remote access with explicit trust boundaries, compatibility with additional compositors and laptop hardware.

---

## 13. Repo layout (proposed)

```text
mano-os/
├── README.md                         # this living product/build contract
├── docs/
│   ├── architecture/                 # ADRs, diagrams, contracts
│   ├── threat-model.md               # assets, trust zones, adversary tests
│   ├── permissions.md                # grant profiles and approvals
│   ├── phase-0-report.md             # evidence + Sway go/no-go
│   ├── compatibility.md
│   └── operations.md
├── services/
│   ├── mano-core/                   # UNTRUSTED planner/AgentRuntime
│   ├── mano-broker/                 # TRUSTED policy, grants, journal
│   ├── mano-privileged-helper/      # narrow root ops
│   ├── mano-stopd/                  # independent stop
│   ├── mano-sandbox/                # profile constructor/launcher
│   ├── mano-desktop/                # headless compositor integration
│   ├── mano-browser/                # Playwright Chromium worker
│   ├── mano-hardware/               # hardware adapters
│   └── mano-prompt/                 # authenticated human UI
├── integrations/
│   ├── models/
│   ├── coding-agents/
│   │   ├── antigravity/
│   │   └── second-adapter/
│   ├── mcp/
│   ├── dbus/
│   └── atspi/
├── protocols/                       # typed request/grant/journal formats
├── sandbox-profiles/                # supervised / auto / full-access
├── workflows/                       # reusable task graphs
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   ├── desktop/
│   ├── adversarial/
│   ├── recovery/
│   └── golden-tasks/
├── evals/
├── packaging/
│   ├── deb/
│   ├── image/
│   ├── systemd/
│   └── sway/
└── scripts/
```

**Dependency rule:** `mano-core` may import `protocols`, its own model/runtime libraries, and a broker *client*, but never the broker's private implementation, secrets, grant store, desktop-input internals or privileged helper. Coding/MCP adapters must not import LangGraph internals.

---

## 14. Evaluation and success metrics

Define golden tasks from Phase 1, even before the GUI is complete. A claim of success needs independent evidence, not just agent text.

| Test | Verification |
|---|---|
| Basic file/CLI task | Allowed artifact exists with correct content |
| Workspace escape attempt | Sandbox denies writes outside grant |
| Protected policy tampering | Policy/journal/config remain unchanged |
| Malicious MCP / injected prompt | Cannot obtain secrets or elevated capability |
| Approval spoof | Agent cannot operate authentic user approval UI |
| Emergency stop | Independent stop kills task cgroup under hung core |
| Browser behavior | Chromium launches without open CDP port; locators work |
| GUI behavior | LibreOffice output is correct; no user focus hijack |
| Unknown remote side effect | Recovery checks status rather than replaying blindly |
| Memory stress | Agent OOM isolated, user session remains usable |
| Credentialed API request | No raw credential appears in agent env/logs |
| Linux compatibility | Known package & graphical app matrix is reproducible |

Metrics to publish for each phase: **verified task success rate, policy bypass rate (target zero in adversarial suite), user interventions per task, elapsed time, task/model cost, idle/peak RAM, OOM recovery time and regression count.** Record measurements from running tests, not estimates masquerading as evidence.

### First end-to-end MVP demo

> “mano, create a small API and website, run unit tests, launch it in Chromium, verify the primary UI, generate a report and show me what you did.”

Expected evidence: workspace diff, tests and build logs, browser verification trace, report artifact, broker journal actions, cgroup limits and proof that the agent did not touch human-session input.

---

## 15. Phase 0 implementation backlog (first tasks)

- [ ] `P0-01`: Provision Debian 13 minimal VM with btrfs and 8 GB RAM ceiling.
- [ ] `P0-02`: Install security updates; verify bubblewrap security-fix version and record package manifest.
- [ ] `P0-03`: Configure prompt-only Sway human session and rescue TTY.
- [ ] `P0-04`: Start separate `WLR_BACKENDS=headless` Sway under isolated service identity/runtime.
- [ ] `P0-05`: Launch Chromium and LibreOffice in agent session; verify screenshot/input without cross-session focus.
- [ ] `P0-06`: Enable accessibility; inspect app tree; verify coordinate+scale handling.
- [ ] `P0-07`: Restrict privileged Wayland global protocols and test malicious clients.
- [ ] `P0-08`: Construct minimal bwrap sandbox with **no inherited IPC** and filesystem-denial probes.
- [ ] `P0-09`: Prove agent can't operate human-session approval and can't spoof physical input via `uinput`.
- [ ] `P0-10`: Prove independent stop while core is killed/hung; recover cleanly.
- [ ] `P0-11`: Create and restore btrfs/Snapper snapshot.
- [ ] `P0-12`: Publish measured memory/process results, threat observations and **go/no-go** ADR.

**Exit rule:** Do not start unrestricted coding-agent execution until these trust boundaries have passed their tests.

---

## 16. Development workflow for human + AI coding agents

1. Work one phase and one testable issue at a time; do not replace the agreed architecture without an ADR.
2. Add the test and security boundary before wiring a powerful tool to the model.
3. Verify command versions and external APIs against official sources before implementation.
4. Keep input/output schemas in `protocols/`; run contract tests against every adapter version.
5. Every PR includes what changed, tests executed, actual outputs, remaining limitations and rollback instructions.
6. Never hardcode tokens, weaken isolation for a demo, use `--dangerously-skip-permissions` as a fix, or claim a simulation is a production security proof.
7. Untrusted output never becomes a privileged instruction simply because the LLM repeats it.
8. Update the README with verified outcomes after each phase; distinguish **planned** from **implemented** at all times.

### Definition of done per issue

- Implementation compiles/executes in the documented environment.
- Unit and integration tests pass, including the relevant *negative/security* case.
- At least one real end-to-end verification is captured where appropriate.
- Broker-grant and journal behavior are validated for any effectful action.
- Memory and compatibility impacts are recorded.
- A reviewer can reproduce the result without relying on model assertions.

---

## 17. Current status and next action

| Deliverable | Status |
|---|---|
| Product concept and goals | **Specified** |
| Reuse-vs-build choice | **Specified** |
| v2.1 trust/permission architecture | **Specified, not yet verified** |
| Debian + Sway feasibility | **Not tested** |
| Broker/sandbox runtime | **Not implemented** |
| Prompt shell / coding adapters / GUI control | **Not implemented** |
| 8 GB performance measurements | **Not measured** |
| `.deb` or bootable ISO | **Not built** |

**Next engineering action:** start `P0-01` and the Phase 0 go/no-go experiments. Prioritize **isolation of the human session and broker authority**, not flashy agent demos.

---

## 18. Reference documentation (official/primary sources)

- [Debian 13 release and installation documentation](https://www.debian.org/releases/trixie/)
- [Sway compositor](https://github.com/swaywm/sway)
- [wlroots headless backend environment controls](https://github.com/swaywm/wlroots/blob/master/docs/env_vars.md) — verify against the packaged version; this linked tree is historical.
- [Linux kernel Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html)
- [bubblewrap README / security limitations](https://github.com/containers/bubblewrap/blob/main/README.md)
- [Debian bubblewrap security tracker: CVE-2026-87766](https://security-tracker.debian.org/tracker/CVE-2026-87766)
- [Debian security advisory DSA-6472-1 (27 Aug 2026)](https://lists.debian.org/debian-security-announce/2026/msg00383.html)
- [xdg-dbus-proxy policy syntax and call restrictions](https://github.com/flatpak/xdg-dbus-proxy/blob/main/xdg-dbus-proxy.xml)
- [Playwright Python BrowserType launch and executable_path](https://playwright.dev/python/docs/api/class-browsertype)
- [Official Antigravity CLI headless mode](https://antigravity.google/docs/cli/headless/)
- [Official Antigravity CLI settings](https://antigravity.google/docs/cli/using/)
- [Official Antigravity CLI sandbox](https://antigravity.google/docs/cli-sandbox)
- [LangGraph durable execution](https://docs.langchain.com/oss/python/langgraph/durable-execution)
- [LangGraph persistence](https://docs.langchain.com/oss/python/langgraph/persistence)
- [AT-SPI](https://www.freedesktop.org/wiki/Accessibility/AT-SPI2/)
- [Flatpak / xdg-dbus-proxy](https://github.com/flatpak/xdg-dbus-proxy)
- [systemd.resource-control](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)
- [MCP specification](https://modelcontextprotocol.io/specification/)

### Closing engineering contract

**mano-OS is an AI-controlled Linux environment, not an AI with unrestricted permission to impersonate its owner.** The LLM handles intent and planning. The broker holds authority. Sandboxed executors operate normal Linux software. A separate agent desktop prevents unwanted interference with the user. Verified tests — especially negative security tests — decide whether a phase is complete.
