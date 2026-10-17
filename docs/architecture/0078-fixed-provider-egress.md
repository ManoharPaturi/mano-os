# Fixed-destination TLS egress without exposing the provider key

The provider keeps its Unix-only private-network service. HTTPS now wraps TLS over
one fixed Root-activated Unix stream socket, checking the original Root listener
before TLS. Certificate verification, api.openai.com SNI/Host, POST /v1/responses,
strict request/framing/response limits and no API retry remain unchanged. The
provider performs no DNS or Internet socket creation. No endpoint or proxy choice
is accepted from a caller.

A separate locked mano-egress UID forwards opaque stream bytes. It authenticates
the provider UID/GID, loads only an enabled boolean from its fixed Root credential,
and checks native Stop. Enabled service resolves only the compiled provider host,
validates every returned public/global numeric address, checks Stop again and
connects to the first numeric endpoint on443 exactly once. It does not inspect TLS,
load an API key or accept a host, port, request method or URL from the peer. The
existing provider remains responsible for approved payload/method/path policy and
end-to-end TLS authentication; the relay is a small trusted network component.

Relay limits:64KiB upstream,512KiB downstream,64KiB buffers in each direction and
an absolute maximum30-second deadline. Partial sends and half-close preserve bytes;
excess input, disconnect or timeout cannot trigger another connect/model attempt.
The cap-zero/NNP/seccomp64MiB/4-PID/20%-CPU unit shares the native Stop slice and has
an independent35-second SIGKILL runtime ceiling. It has no home, writable system,
broker journal access or provider key-source access. Startup checks the key cannot
be opened and never reads it, even on an incorrect installation.

Root /etc/mano/egress.json defaults to disabled. Package setup must create the
locked account, install the default Root0600 config only if absent, and install the
socket/template atomically with the new provider template. Never overwrite an
operator's existing config. The provider template requires the egress socket;
activation alone still permits no Internet connection while its policy is disabled.
Pricing and provider generation retain their own independent disabled defaults.

Tests retain actual TLS/SNI/HTTP/wrong-certificate checks using a local Unix server
with explicit test-only CA/listener-auth/path injection. Those do not prove Root
socket activation. Other tests cover counterfeit listeners before TLS, fixed-peer
and disabled policy before DNS, Stop/generation changes, one numeric connect,
actual duplex socketpair/half-close transfer, byte budgets and absolute deadlines.

The guarded Debian VM must prove actual installed disabled-policy rejection and
wrong-UID socket denial. It then explicitly enables ONLY egress in the guest and
uses the production Unix TLS connection code as the provider UID to authenticate
the public provider certificate. This probe sends no HTTP request, model prompt,
Authorization header or API key; it cannot prove paid/API/model execution. Pricing
and provider generation remain disabled and egress is restored disabled afterward.
Required new flags: installed_egress_disabled_policy_denied,
egress_wrong_uid_and_provider_key_source_denied, and
fixed_provider_unix_tls_handshake_without_http. Until final CI these are pending.
Frozen-egress runtime behavior and live paid-provider execution remain unproven.
