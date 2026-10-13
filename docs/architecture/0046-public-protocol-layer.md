# Core depends on public protocols

The original specification forbids mano-core from importing broker policy,
private journal implementation, secret stores or privileged helpers. Public
ActionRequest/Capability/Mode types and pure validation now live in mano_protocol.
Generic kernel-authenticated packet reply parsing and Peer/CREDENTIALS also live
there, with no journal, policy or privileged socket paths. Core imports only this
public layer, its own client/runtime and LangGraph libraries.

Existing broker protocol, error and reply exports remain compatibility aliases to
the same public objects. Protected services continue to enforce identity, grants,
filesystem custody and private channels; Python import organization is an
architecture rule rather than an OS security boundary. No permissions, capability
sets, socket exposure or verification guards are relaxed.

An AST dependency test rejects private broker imports in core and public protocol
modules. Identity tests preserve legacy exports. Both disposable-guest installed
code fixtures copy the new root-owned read-only public package. Existing native,
PAM, broker, sandbox, Stop/rearm, agent, verifier and checkpoint tests must still
pass exact-head CI. Acceptance remains pending.
