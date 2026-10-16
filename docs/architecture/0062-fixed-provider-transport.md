# Fixed protected-provider HTTPS transport

The transport accepts only the exact model.plan argument schema and a credential
supplied by trusted provider code. It rebuilds the fixed narrow Responses body and
sends one POST to api.openai.com:443/v1/responses. No URL, method, header, proxy,
redirect or retry option can be selected by the core's request. There is no CLI,
credential loader, socket service or broker execution activation in this change.

Resolve once, reject any non-global, private, reserved, multicast or scoped address,
and connect to one validated numeric address. TLS retains api.openai.com as SNI
and verifies the certificate chain and hostname using default trust. API keys are
bounded header-safe strings, never placed in the body or logged. Non-200 response
bodies are discarded, redirects are not followed, compression and conflicting
framing are denied, and reads enforce the 256 KiB response ceiling and truncation
checks. Exceptions expose generic uncertainty and do not retry a call.

Socket/handshake/read timeouts use a monotonic deadline. A daemon deadline timer
shuts down the connected stream to interrupt trickled headers/body; response and
socket ownership remain held through bounded reading, including Connection: close.
DNS resolution is synchronous and cannot be forcibly interrupted by this helper;
the future protected service's kernel RuntimeMaxSec/watchdog must supply that hard
outer bound. Native Stop, cost reservation and service cancellation are also still
required before production activation. This module is not a complete egress or
credential boundary by itself. Production Registry still denies model execution.

Mocked tests cover numeric pinning, private/mixed/scoped DNS, certificate-check
configuration, fixed headers, redirects, malformed framing, size/truncation and
single-call uncertainty. Actual local TLS tests generate temporary certificates,
use synthetic credentials and explicitly inject test DNS/CA: correct-host HTTPS
POST succeeds, while a trusted wrong-host certificate fails before credentialed
HTTP reaches the server. Loopback is permitted only by the test injection; the
production address validator rejects it. No OpenAI request, real API key, billing
or live-provider semantic result is claimed.

Sources checked on 2026-10-14:

- [Official OpenAI quickstart and Responses endpoint](https://developers.openai.com/api/docs/quickstart)
- [Python SSL certificate and hostname verification](https://docs.python.org/3/library/ssl.html)
- [Python HTTP client](https://docs.python.org/3/library/http.client.html)
