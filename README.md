# mano-OS

**Describe the outcome. Let your computer work toward it.**

mano-OS is an AI-native Linux operating environment built around a simple idea:
you should be able to tell your computer what you want to accomplish, and have an
agent plan the steps, use the right tools, and show you the results.

The main interface is a keyboard-first prompt. Underneath it is Debian Linux,
with familiar command-line tools, development environments, browsers, and graphical
applications. A minimal Wayland environment keeps those applications available
without making a traditional desktop shell the center of the experience.

**Current status:** mano-OS is a working security and runtime prototype under active
development. It has an unsigned Debian runtime package and automated tests in
real Debian virtual machines. The complete everyday assistant experience and a
bootable mano-OS image are still being built.

## What you could ask mano to do

These examples describe the experience we are building; they are not a list of
completed end-to-end features.

- **Build software:** “Create a web app, run its tests, and show me the result.”
- **Work with documents:** “Turn these CSV files into a report and export a PDF.”
- **Understand your system:** “Find out why my laptop is slow and suggest a fix.”
- **Use connected devices:** “Read data from my Arduino and plot the measurements.”

A task should move from a request to a plan, through authorized actions, to a result
you can inspect. When something fails, mano should preserve enough history to
explain what happened and recover where possible.

## What makes mano-OS different

### One prompt, normal Linux tools

mano-OS brings an agent workflow into the operating environment. It aims to combine
coding tools, shell commands, browser automation, document applications, and device
adapters behind one interface. Structured application APIs and command-line tools
are preferred when available; graphical interaction fills the gaps.

### Background work without taking over your desktop

The agent has a separate graphical workspace for supported GUI tasks. Its windows
and automated input are isolated from the human session, so background work can
happen without borrowing your keyboard and mouse.

### An assistant with boundaries

The model proposes actions. A separate trusted service, **mano-broker**, checks
permissions and authorizes specific operations. Restricted executors carry them out,
and the broker records what happened. The model cannot approve its own requests.

The design includes native OS-authenticated approvals, limited task resources,
an independent emergency Stop, and a durable action history. Planned permission
modes—Supervised, Auto, and Full Access—change how much work can proceed without
another prompt; Full Access does not give the model unrestricted Root authority.

### Recovery and visible results

Durable workflow state, action records, and filesystem snapshots support diagnosing
interrupted work and recovering from supported system changes. A command reporting
success is only one piece of evidence: verifying the intended result is a separate
step. Snapshots also cannot undo every external effect.

### A lightweight foundation

The target is an 8 GB RAM machine using a cloud model, without requiring a large
local model. That is a design target; physical-machine performance acceptance is
still pending. Model providers and coding agents are intended to be replaceable
through adapters.

## How it fits together

```text
Your request
    ↓
Prompt interface → Agent core: plan, request tools, observe results
                              ↓
                    Trusted broker: permissions,
                    approvals, grants, action history
                              ↓
                    Restricted task executors
                              ↓
             Linux tools · Browsers · GUI applications
                              ↓
                    Results and verification
```

| Component | Role |
| --- | --- |
| Debian 13, x86_64 | Linux packages, kernel, drivers, and system services |
| Sway / Wayland + XWayland | Minimal graphics and a separate agent desktop |
| Native GTK4 interface | Human prompt and task interaction |
| Agent core with LangGraph | Task orchestration and persistent workflow state |
| mano-broker | Permission checks, scoped grants, approvals, and authoritative history |
| Linux isolation and resource controls | Boundaries around task processes and their access |
| btrfs + Snapper | Snapshots and supported system recovery |

## Where the project stands

The prototype has CI evidence for:

- Isolated task execution, resource limits, broker permissions, and durable action records.
- Native PAM approvals and an independent Stop path, including frozen-service tests.
- Separate human and agent graphical sessions, with selected Chromium and LibreOffice workflows.
- Persistent workflow state and deterministic mock-agent task flows.
- Package planning and review, archive verification, interrupted package-operation handling,
  and btrfs-root recovery boots.
- Installation, reinstallation, and removal of the prototype Debian runtime package,
  including data-preservation checks.

These tests run in disposable Debian VMs. They establish specific prototype
behaviors, not general compatibility with every Linux app or finished-product readiness.
Native approvals currently use synthetic CI input; physical input acceptance is pending.

Work still ahead includes the complete prompt-to-agent experience, accepted live-model
and authenticated coding-agent workflows, broader real-world tasks, physical hardware
and 8 GB performance testing, and release-quality installation and bootable images.
The runtime package is unsigned and remains a development prototype.

## Explore the project

- [Product specification](docs/spec-v2.1.md) — the full v2.1 vision, architecture, and delivery phases.
- [Runtime operations](docs/operations.md) — prototype package setup and operation.
- [Architecture decisions](docs/architecture/) — how the system is designed and why.
- [Development status and handoff](docs/CONTINUATION.md) — detailed implementation progress.
- [Engineering guide](AGENTS.md) — contribution and development workflow.

mano-OS starts as a Debian runtime and grows toward a dedicated operating environment:
a computer organized around the work you want done.
